"""Each call of a tool that reads a rule corpus names the corpus it ran with (T-668).

A manifest's data row is the default corpus as it was when the manifest was
answered; a call may run on another (a model's ``ruleset``), and a long-lived
server or worker may read rules fetched or changed since. So the answer of
every such call carries ``data_used``: per data path its tool declares, the
corpus the call ran with, named by its own name and what named it, with the
count and digest of the files the layer the call used was loaded from. The
rule loaders record that reading (``capabilities.note_data_used``) and keep a
layer only while the files' stat signature is the one it was loaded from, so a
rule edited in place between two calls changes both what the second call
matches and its stamp, and a stamp is never read off the disk after the call.
Written by the wrapper every call goes through — the analysis server's guard,
and the reading layer on whichever side runs a reading — from the tool's
declaration, the same for every tool.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from malspark.tools import capabilities, readers, rules, sidecar_needs
from malspark.tools.capabilities import (
    CHANGED_WHILE_LOADED,
    DATA_USED_KEY,
    NOT_LOADED_STATEMENT,
    NOT_READ_YET,
    ToolNeeds,
    VersionProbe,
    binary,
    data,
    data_used,
    module,
    read_corpus,
    stamped,
)

ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "services" / "analysis-mcp" / "server.py"


def _corpus(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _rewrite_in_place(path: Path, text: str) -> None:
    """Rewrite one rule file, leaving every directory's own modification time as it was."""
    held = [(d, d.stat()) for d in (path.parent, path.parent.parent)]
    path.write_text(text, encoding="utf-8")
    for directory, stat in held:
        os.utime(directory, ns=(stat.st_atime_ns, stat.st_mtime_ns))


@pytest.fixture(autouse=True)
def _fresh() -> Any:
    capabilities.clear_fact_caches()
    rules.reset_rule_caches()
    yield
    capabilities.clear_fact_caches()
    rules.reset_rule_caches()


class TestTheStamp:
    def test_the_default_corpus_is_named_by_what_named_it(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a"})
        need = ToolNeeds("t", (module("json"), data(str(root), pattern="*.yml", argument="rs")))
        (row,) = data_used(need, {"rs": "default"})
        # Outside the project a corpus is named by its base name, never the host's path.
        assert row["name"] == "rules"
        assert row["named_by"] == "the default"
        assert row["files"] == 1
        assert len(row["sha256"]) == 64
        assert str(tmp_path) not in repr(row)

    def test_a_corpus_the_call_names_is_named_by_its_own_name(self, tmp_path: Path) -> None:
        default = _corpus(tmp_path / "default", {"a.yml": "a"})
        other = _corpus(tmp_path / "other", {"x.yml": "x", "y.yml": "y"})
        need = ToolNeeds("t", (data(str(default), pattern="*.yml", argument="ruleset"),))
        (named,) = data_used(need, {"ruleset": str(other)})
        (by_default,) = data_used(need, {})
        assert named["name"] == "other"
        assert named["named_by"] == "the ruleset argument"
        assert named["files"] == 2
        assert named["sha256"] != by_default["sha256"]
        assert str(tmp_path) not in repr(named)

    def test_a_corpus_inside_the_project_is_named_from_its_root(self) -> None:
        need = ToolNeeds("t", (data("data/none-here", pattern="*.yml", argument="ruleset"),))
        (row,) = data_used(need, {"ruleset": "data/yara-x-rules"})
        assert row["name"] == "data/yara-x-rules"
        assert row["named_by"] == "the ruleset argument"

    def test_an_argument_naming_the_default_path_is_the_default(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a"})
        need = ToolNeeds("t", (data("data/x", override="T668_X", pattern="*.yml", argument="rs"),))
        (row,) = data_used(need, {"rs": str(root) + "/"}, {"T668_X": str(root)})
        assert row["named_by"] == "T668_X"
        assert row["name"] == "rules"

    def test_a_tool_declaring_no_data_is_answered_as_it_was(self) -> None:
        need = ToolNeeds("t", (module("json"),))
        assert data_used(need, {}) == []
        assert data_used(None, {}) == []
        answer = {"matches": []}
        assert stamped(answer, []) is answer

    def test_the_stamp_comes_first(self) -> None:
        rows = [{"name": "r", "files": 1}]
        assert list(stamped({"matches": [], "x": 1}, rows)) == [DATA_USED_KEY, "matches", "x"]

    def test_a_call_that_loaded_no_corpus_says_so(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a"})
        need = ToolNeeds("t", (data(str(root), pattern="*.yml"),))
        (row,) = data_used(need, {}, loaded={})
        assert row["digest_statement"] == NOT_LOADED_STATEMENT
        assert "sha256" not in row and "files" not in row


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("MALSPARK_SAMPLE_ROOTS", str(tmp_path))
    spec = importlib.util.spec_from_file_location("analysis_mcp_server_t668", SERVER)
    assert spec and spec.loader
    module_ = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module_
    spec.loader.exec_module(module_)
    return module_


_YARA_RULE = """rules:
  - id: t668_rule
    technique_id: "T1055"
    confidence: 0.9
    description: "t668"
    patterns:
      - "{word}"
"""

_SIGMA_RULE = """title: t668
id: 11111111-1111-1111-1111-111111111111
logsource: {{product: windows, category: process_creation}}
detection:
  sel: {{Image|endswith: '\\\\{word}.exe'}}
  condition: sel
level: high
"""


def _digest(path: Path, need: Any) -> str:
    return str(read_corpus(str(path), need.pattern, need.exclude).facts["sha256"])


def _yara(server: Any, sample: Path) -> tuple[bool, dict[str, Any]]:
    answer = server.yara_scan(path=str(sample))
    (row,) = answer[DATA_USED_KEY]
    return bool(answer["matches"]), row


def _sigma(server: Any, sample: Path) -> tuple[bool, dict[str, Any]]:
    answer = server.sigma_match(events=[{"EventID": 1, "Image": "C:\\x\\good.exe"}])
    (row,) = answer[DATA_USED_KEY]
    return bool(answer["matches"]), row


# Per engine the shared wrapper covers: its override, its declaration, the rule
# text, and one call through the server's own tool.
ENGINES = {
    "yara": (rules.YARA_RULES_ENV, sidecar_needs.YARA_RULES, _YARA_RULE, _yara, "GOODWORD"),
    "sigma": (rules.SIGMA_RULES_ENV, sidecar_needs.SIGMA_RULES, _SIGMA_RULE, _sigma, "good"),
}


class TestARuleEditedInPlace:
    @pytest.mark.parametrize("engine", sorted(ENGINES))
    def test_the_stamp_changes_exactly_when_the_rules_used_change(
        self, engine: str, server: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        env_name, need, rule, call, hit = ENGINES[engine]
        corpus = _corpus(tmp_path / "corpus", {"sub/r.yml": rule.format(word="evil")})
        sample = tmp_path / "sample.bin"
        sample.write_text("xx GOODWORD xx", encoding="utf-8")
        monkeypatch.setenv(env_name, str(corpus))

        matched, first = call(server, sample)
        assert not matched
        old = _digest(corpus, need)
        assert first["sha256"] == old
        # The same rules: the same stamp, and the same answer.
        assert call(server, sample) == (False, first)

        # Edited in place, in a subdirectory: no directory's own time moves.
        _rewrite_in_place(corpus / "sub" / "r.yml", rule.format(word=hit))
        matched, second = call(server, sample)
        assert matched, "the edited rule was not the one the call ran with"
        assert second["sha256"] == _digest(corpus, need) != old
        assert call(server, sample) == (True, second)

    @pytest.mark.parametrize("engine", sorted(ENGINES))
    def test_a_rule_changed_while_it_loads_is_not_stamped_with_either_digest(
        self, engine: str, server: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        env_name, need, rule, call, hit = ENGINES[engine]
        corpus = _corpus(tmp_path / "corpus", {"sub/r.yml": rule.format(word="evil")})
        sample = tmp_path / "sample.bin"
        sample.write_text("xx GOODWORD xx", encoding="utf-8")
        monkeypatch.setenv(env_name, str(corpus))
        loader = "_load_yara" if engine == "yara" else "_load_sigma"
        real = getattr(rules, loader)
        edits = [rule.format(word=hit)]

        def _load_then_edit(path: Path, read: Any) -> Any:
            layer = real(path, read)
            if edits:
                (corpus / "sub" / "r.yml").write_text(edits.pop(), encoding="utf-8")
            return layer

        monkeypatch.setattr(rules, loader, _load_then_edit)
        _matched, row = call(server, sample)
        assert row["digest_statement"] == CHANGED_WHILE_LOADED
        assert "sha256" not in row
        # The next call loads the rules as they now are, and names them.
        matched, row = call(server, sample)
        assert matched
        assert row["sha256"] == _digest(corpus, need)

    def test_both_sigma_tools_name_the_one_layer_they_share(
        self, server: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = _corpus(tmp_path / "corpus", {"r.yml": _SIGMA_RULE.format(word="evil")})
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(corpus))
        (by_events,) = server.sigma_match(events=[])[DATA_USED_KEY]
        (by_report,) = server.sigma_match_sandbox(report={})[DATA_USED_KEY]
        assert by_events == by_report
        assert by_events["sha256"] == _digest(corpus, sidecar_needs.SIGMA_RULES)


def _capa_document(rules_dir: str) -> dict[str, Any]:
    """What a capa run over ``rules_dir`` answers here: one rule per file, read as it runs."""
    return {
        "meta": {},
        "rules": {
            path.read_text(encoding="utf-8"): {"meta": {"name": path.read_text(encoding="utf-8")}}
            for path in sorted(Path(rules_dir).rglob("*.yml"))
            # capa's own loader skips every directory whose path holds ".git".
            if ".git" not in str(path.parent)
        },
    }


class TestCapa:
    @pytest.fixture
    def capa_run(self, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        from malspark.providers.static import capa_yara

        during: list[Any] = []

        def _run(*, rules_dir: str, **kwargs: Any) -> dict[str, Any]:
            document = _capa_document(rules_dir)
            while during:
                during.pop()()
            return document

        monkeypatch.setattr(capa_yara, "run_capa_document", _run)
        return during

    def test_the_stamp_follows_a_rule_edited_in_place(
        self, server: Any, capa_run: list[Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = _corpus(tmp_path / "capa", {"sub/a.yml": "rule-a", ".github/ci.yml": "ci"})
        monkeypatch.setenv(rules.CAPA_RULES_ENV, str(corpus))
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"MZ")

        def _call() -> tuple[list[str], dict[str, Any]]:
            answer = asyncio.run(server.capa(path=str(sample)))
            (row,) = answer[DATA_USED_KEY]
            return [c["rule"] for c in answer["capabilities"]], row

        ran, first = _call()
        assert ran == ["rule-a"]
        assert first["files"] == 1
        assert first["sha256"] == _digest(corpus, sidecar_needs.CAPA_RULES)
        _rewrite_in_place(corpus / "sub" / "a.yml", "rule-b")
        ran, second = _call()
        assert ran == ["rule-b"]
        assert second["sha256"] == _digest(corpus, sidecar_needs.CAPA_RULES) != first["sha256"]

    def test_a_rule_changed_while_capa_runs_is_not_stamped(
        self, server: Any, capa_run: list[Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = _corpus(tmp_path / "capa", {"a.yml": "rule-a"})
        monkeypatch.setenv(rules.CAPA_RULES_ENV, str(corpus))
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"MZ")
        capa_run.append(lambda: (corpus / "a.yml").write_text("rule-changed", encoding="utf-8"))
        (row,) = asyncio.run(server.capa(path=str(sample)))[DATA_USED_KEY]
        assert row["digest_statement"] == CHANGED_WHILE_LOADED
        assert "sha256" not in row

    def test_a_call_that_ends_before_capa_loads_says_it_loaded_none(
        self, server: Any, capa_run: list[Any], tmp_path: Path
    ) -> None:
        (row,) = asyncio.run(server.capa(path=str(tmp_path / "missing.bin")))[DATA_USED_KEY]
        assert row["digest_statement"] == NOT_LOADED_STATEMENT


class TestTheServerGuard:
    def test_a_rule_call_s_answer_names_the_rules_it_ran_with(
        self, server: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        default = _corpus(tmp_path / "sigma", {"r.yml": _SIGMA_RULE.format(word="a")})
        other_root = tmp_path / "operator"
        other = _corpus(
            other_root / "other",
            {"o.yml": _SIGMA_RULE.format(word="o"), "p.yml": _SIGMA_RULE.format(word="p")},
        )
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(default))
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(other_root))

        by_default = server.sigma_match(events=[], ruleset="default")
        named = server.sigma_match(events=[], ruleset=str(other))
        assert list(by_default)[0] == DATA_USED_KEY
        (row,) = by_default[DATA_USED_KEY]
        assert (row["name"], row["named_by"], row["files"]) == ("sigma", rules.SIGMA_RULES_ENV, 1)
        (row,) = named[DATA_USED_KEY]
        assert (row["name"], row["named_by"], row["files"]) == (
            "other",
            "the ruleset argument",
            2,
        )
        assert str(tmp_path) not in repr(named[DATA_USED_KEY])
        # Naming the default corpus by its path is naming the default.
        (row,) = server.sigma_match(events=[], ruleset=str(default))[DATA_USED_KEY]
        assert row["named_by"] == rules.SIGMA_RULES_ENV

    def test_a_tool_without_data_is_answered_without_a_stamp(self, server: Any) -> None:
        answer = server._guard("iocs_from_text", lambda text: {"iocs": []}, text="x")
        assert DATA_USED_KEY not in answer

    def test_the_capabilities_answer_reads_the_data_now(
        self, server: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = tmp_path / "sigma"
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(corpus))
        assert "requirements" not in server.CAPABILITIES

        def _sigma_row(answer: dict[str, Any]) -> dict[str, Any]:
            return next(
                row
                for row in answer["requirements"]
                if row["kind"] == "data" and row["name"] == rules.DEFAULT_SIGMA_RULES
            )

        assert _sigma_row(asyncio.run(server.capabilities()))["files"] == 0
        _corpus(corpus, {"r.yml": "title: r"})
        assert _sigma_row(asyncio.run(server.capabilities()))["files"] == 1


class TestTheCapabilitiesAnswerNeverWaits:
    def test_it_answers_while_a_version_is_read_and_says_it_is_not_read_yet(
        self, server: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        done = tmp_path / "done"
        slow = binary(
            "t668slow",
            version_probe=VersionProbe(
                (
                    sys.executable,
                    "-c",
                    f"import time; time.sleep(2); open({str(done)!r}, 'w'); "
                    "print('t668slow 4.5.6')",
                ),
                timeout_s=10,
            ),
        )
        needs = [ToolNeeds("slow_tool", (slow,))]
        monkeypatch.setattr(server, "TOOL_NEEDS", needs)
        # The server's start: the cells, and the version's reading begun.
        monkeypatch.setattr(
            server, "CAPABILITIES", capabilities.manifest("analysis", needs, requirements=False)
        )
        started = time.monotonic()
        answer = asyncio.run(server.capabilities())
        assert time.monotonic() - started < 1.0
        assert answer["requirements"][0]["version"] == NOT_READ_YET
        assert not done.exists(), "the answer waited for the version"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            version = asyncio.run(server.capabilities())["requirements"][0]["version"]
            if version != NOT_READ_YET:
                break
            time.sleep(0.1)
        assert version == "4.5.6"

    def test_the_data_is_read_off_the_server_s_event_loop(
        self, server: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[Any] = []

        def _answered(held: Any, tools: Any) -> dict[str, Any]:
            seen.append(threading.current_thread())
            return {"server": "analysis", "tools": []}

        monkeypatch.setattr(server, "answered_manifest", _answered)

        async def _go() -> Any:
            await server.capabilities()
            return threading.current_thread()

        loop_thread = asyncio.run(_go())
        assert seen and seen[0] is not loop_thread

    def test_the_attach_keeps_its_manifest_while_a_version_is_read(
        self, server: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import AsyncMock, MagicMock

        from malspark.core.config import MCPServerConfig
        from malspark.providers import servers

        slow = binary(
            "t668slow",
            version_probe=VersionProbe(
                (sys.executable, "-c", "import time; time.sleep(4); print('1.0')"), timeout_s=10
            ),
        )
        needs = [ToolNeeds("slow_tool", (slow,))]
        monkeypatch.setattr(server, "TOOL_NEEDS", needs)
        monkeypatch.setattr(
            server, "CAPABILITIES", capabilities.manifest("analysis", needs, requirements=False)
        )
        # Less than the probe takes: an answer that waited for it would lose the manifest.
        monkeypatch.setattr(servers, "CAPABILITIES_TIMEOUT_SECONDS", 1.5)

        class _Tool:
            def __init__(self, name: str) -> None:
                self.name = name
                self.metadata: dict[str, Any] = {}

            def model_copy(self, *, update: dict[str, Any]) -> Any:
                return _Tool(update.get("name", self.name))

            async def ainvoke(self, _args: dict[str, Any]) -> Any:
                return await server.capabilities()

        def factory(*args: Any, **kwargs: Any) -> Any:
            toolkit = MagicMock()
            toolkit.initialize = AsyncMock(return_value=None)
            toolkit.get_tools = MagicMock(return_value=[_Tool("slow_tool"), _Tool("capabilities")])
            toolkit.cleanup = AsyncMock(return_value=None)
            return toolkit

        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", factory)
        monkeypatch.setattr(servers, "_run_async", lambda coro, label: coro.close())
        handle = servers.ServerHandle("analysis", MCPServerConfig(enabled=True, command="x"))
        started = time.monotonic()
        handle.open("job-t668")
        try:
            assert time.monotonic() - started < 1.5
            assert handle.capabilities is not None
            assert "slow_tool" in handle.capabilities.tools
            assert handle.capabilities.requirements == [
                {
                    "kind": "binary",
                    "name": "t668slow",
                    "version": NOT_READ_YET,
                    "tools": ["slow_tool"],
                }
            ]
        finally:
            handle.close()


class TestTheReadingLayer:
    @pytest.fixture
    def capa_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from malspark.providers.static import capa_yara

        monkeypatch.setattr(
            capa_yara, "run_capa_document", lambda *, rules_dir, **kwargs: _capa_document(rules_dir)
        )

    def _read_capa(self, tmp_path: Path, rules_dir: str) -> dict[str, Any]:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"MZ")
        answer = readers._ran(
            readers.READERS["capa"],
            None,
            {
                "path": str(sample),
                "timeout_s": 5,
                "backend": "auto",
                "rules_dir": rules_dir,
                "signatures_dir": "",
            },
        )
        (row,) = answer[DATA_USED_KEY]
        return dict(row)

    def test_a_reading_run_here_names_the_corpus_it_was_handed(
        self, capa_run: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = _corpus(
            tmp_path / "capa", {"a.yml": "rule", ".github/workflows/ci.yml": "not a rule"}
        )
        monkeypatch.delenv(rules.CAPA_RULES_ENV, raising=False)
        row = self._read_capa(tmp_path, str(corpus))
        assert (row["name"], row["named_by"]) == ("capa", "the rules_dir argument")
        # capa's loader skips the clone's CI files, and so does the count.
        assert row["files"] == 1

    def test_a_reading_handed_the_corpus_the_tool_reads_by_default_names_the_default(
        self, capa_run: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = _corpus(tmp_path / "capa", {"a.yml": "rule"})
        monkeypatch.setenv(rules.CAPA_RULES_ENV, str(corpus))
        row = self._read_capa(tmp_path, str(corpus))
        assert row["named_by"] == rules.CAPA_RULES_ENV
        assert row["files"] == 1

    def test_a_reading_served_for_the_worker_names_the_server_s_corpus(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = tmp_path / "yara.yaml"
        corpus.write_text(_YARA_RULE.format(word="EVIL"), encoding="utf-8")
        sample = tmp_path / "s.bin"
        sample.write_text("nothing", encoding="utf-8")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(corpus))
        answer = readers.serve_reader(
            "yara_scan",
            {"path": str(sample)},
            "",
            offered={"yara_scan"},
            confine=lambda path, job: path,
        )
        (row,) = answer["value"][DATA_USED_KEY]
        assert (row["name"], row["named_by"], row["files"]) == (
            "yara.yaml",
            rules.YARA_RULES_ENV,
            1,
        )
        assert row["sha256"] == _digest(corpus, sidecar_needs.YARA_RULES)
