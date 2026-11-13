"""Each call of a tool that reads a rule corpus names the corpus it ran with (T-668).

A manifest's data row is the default corpus as it was when the manifest was
answered; a call may run on another (a model's ``ruleset``), and a long-lived
server or worker may read rules fetched or changed since. So the answer of
every such call carries ``data_used``: per data path its tool declares, the
corpus the call's own argument named, else the one the tool reads, with its
file count and digest as they were when the call ran. Written by the wrapper
every call goes through — the analysis server's guard, and the reading layer
on whichever side runs a reading — from the tool's declaration, the same for
every tool.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from malspark.tools import capabilities, readers, rules
from malspark.tools.capabilities import (
    DATA_USED_KEY,
    ToolNeeds,
    data,
    data_used,
    module,
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


@pytest.fixture(autouse=True)
def _fresh() -> Any:
    capabilities.clear_fact_caches()
    yield
    capabilities.clear_fact_caches()


class TestTheStamp:
    def test_the_default_corpus_is_named_by_what_named_it(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a"})
        need = ToolNeeds("t", (module("json"), data(str(root), pattern="*.yml", argument="rs")))
        (row,) = data_used(need, {"rs": "default"})
        assert row["name"] == str(root)
        assert row["named_by"] == "the default"
        assert row["files"] == 1
        assert len(row["sha256"]) == 64

    def test_a_corpus_the_call_names_is_the_one_recorded(self, tmp_path: Path) -> None:
        default = _corpus(tmp_path / "default", {"a.yml": "a"})
        other = _corpus(tmp_path / "other", {"x.yml": "x", "y.yml": "y"})
        need = ToolNeeds("t", (data(str(default), pattern="*.yml", argument="ruleset"),))
        (named,) = data_used(need, {"ruleset": str(other)})
        (by_default,) = data_used(need, {})
        assert named["named_by"] == "the ruleset argument"
        assert named["files"] == 2
        assert named["sha256"] != by_default["sha256"]
        # The argument is named, never the path it held.
        assert str(other) not in repr(named)

    def test_a_tool_declaring_no_data_is_answered_as_it_was(self) -> None:
        need = ToolNeeds("t", (module("json"),))
        assert data_used(need, {}) == []
        assert data_used(None, {}) == []
        answer = {"matches": []}
        assert stamped(answer, []) is answer

    def test_the_stamp_comes_first(self) -> None:
        rows = [{"name": "r", "files": 1}]
        assert list(stamped({"matches": [], "x": 1}, rows)) == [DATA_USED_KEY, "matches", "x"]


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setenv("MALSPARK_SAMPLE_ROOTS", str(tmp_path))
    spec = importlib.util.spec_from_file_location("analysis_mcp_server_t668", SERVER)
    assert spec and spec.loader
    module_ = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module_
    spec.loader.exec_module(module_)
    return module_


class TestTheServerGuard:
    def test_a_rule_call_s_answer_names_the_rules_it_ran_with(
        self, server: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        default = _corpus(tmp_path / "sigma", {"r.yml": "title: r"})
        other_root = tmp_path / "operator"
        other = _corpus(other_root / "other", {"o.yml": "title: o", "p.yml": "title: p"})
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(default))
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(other_root))

        def _match(events: list[dict[str, Any]], ruleset: str = "default") -> dict[str, Any]:
            return {"matches": []}

        by_default = server._guard("sigma_match", _match, events=[], ruleset="default")
        named = server._guard("sigma_match", _match, events=[], ruleset=str(other))
        assert list(by_default)[0] == DATA_USED_KEY
        (row,) = by_default[DATA_USED_KEY]
        assert row["named_by"] == rules.SIGMA_RULES_ENV
        assert row["files"] == 1
        (row,) = named[DATA_USED_KEY]
        assert row["named_by"] == "the ruleset argument"
        assert row["files"] == 2

    def test_a_tool_without_data_is_answered_without_a_stamp(self, server: Any) -> None:
        answer = server._guard("iocs_from_text", lambda text: {"iocs": []}, text="x")
        assert DATA_USED_KEY not in answer

    def test_the_capabilities_answer_reads_the_data_now(
        self, server: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = tmp_path / "sigma"
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(corpus))
        assert "requirements" not in server.CAPABILITIES

        def _sigma(answer: dict[str, Any]) -> dict[str, Any]:
            return next(
                row
                for row in answer["requirements"]
                if row["kind"] == "data" and row["name"] == rules.DEFAULT_SIGMA_RULES
            )

        assert _sigma(server.capabilities())["files"] == 0
        _corpus(corpus, {"r.yml": "title: r"})
        assert _sigma(server.capabilities())["files"] == 1


class TestTheReadingLayer:
    def test_a_reading_run_here_names_the_corpus_it_was_handed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = _corpus(
            tmp_path / "capa", {"a.yml": "rule", ".github/workflows/ci.yml": "not a rule"}
        )
        monkeypatch.setattr(rules, "capa", lambda path, **kwargs: {"capabilities": []})
        answer = readers._ran(
            readers.READERS["capa"],
            None,
            {
                "path": "s.bin",
                "timeout_s": 5,
                "backend": "auto",
                "rules_dir": str(corpus),
                "signatures_dir": "",
            },
        )
        (row,) = answer[DATA_USED_KEY]
        assert row["named_by"] == "the rules_dir argument"
        # capa's loader skips the clone's CI files, and so does the count.
        assert row["files"] == 1

    def test_a_reading_served_for_the_worker_names_the_server_s_corpus(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = tmp_path / "yara.yaml"
        corpus.write_text("rules: []\n", encoding="utf-8")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(corpus))
        monkeypatch.setattr(rules, "yara_scan", lambda **kwargs: {"matches": []})
        answer = readers.serve_reader(
            "yara_scan",
            {"path": str(tmp_path / "s.bin")},
            "",
            offered={"yara_scan"},
            confine=lambda path, job: path,
        )
        (row,) = answer["value"][DATA_USED_KEY]
        assert row["named_by"] == rules.YARA_RULES_ENV
        assert row["files"] == 1
