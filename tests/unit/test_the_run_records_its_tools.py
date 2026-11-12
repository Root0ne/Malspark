"""A finished run records the tools it ran (``run_summary.environment.tools``).

Per tool server and provider that served the run: how it served it, the name
and version it gave at its attach, and what each requirement its tools declare
is on its host — a module's installed distribution and version, a data path's
file count and one digest over its files, a binary's version where the tool
declares how to ask it. Read from the declarations every tool makes the same
way; a fact not given is "not reported", and a summary without the part reads
as it always has.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from malspark.analysis import run_environment
from malspark.analysis.run_environment import (
    ENVIRONMENT_VERSION,
    environment_record,
    tools_record,
)
from malspark.analysis.run_summary import RunSummaryBuilder
from malspark.providers.servers import ServerRegistry
from malspark.tools import capabilities
from malspark.tools.capabilities import (
    NOT_INSTALLED,
    NOT_REPORTED,
    ServerCapabilities,
    ToolNeeds,
    VersionProbe,
    binary,
    data,
    env,
    manifest,
    module,
    module_version,
    requirement_facts,
)


def _clear() -> None:
    # Each fact is read once per process; a test reads it afresh. A cache a
    # test patched over is restored by its own fixture.
    for name in ("_probe_version", "_data_digest", "_distributions_of"):
        clear = getattr(getattr(capabilities, name), "cache_clear", None)
        if clear is not None:
            clear()


@pytest.fixture(autouse=True)
def _fresh_caches() -> Any:
    _clear()
    yield
    _clear()


def _python(code: str) -> tuple[str, ...]:
    return (sys.executable, "-c", code)


# ---------------------------------------------------------------------------
# A module: the installed distribution's version


class TestAModule:
    def test_an_installed_module_names_its_distribution_and_version(self) -> None:
        import importlib.metadata

        facts = module("pytest").facts()
        assert facts == {
            "kind": "module",
            "name": "pytest",
            "distribution": "pytest",
            "version": importlib.metadata.version("pytest"),
        }

    def test_a_module_named_by_its_import_reads_the_distribution_that_installed_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            capabilities, "_distributions_of", lambda: {"_pytest": ["not-a-dist", "pytest"]}
        )
        facts = module_version("_pytest.config")
        assert facts["distribution"] == "pytest"

    def test_a_missing_module_is_not_installed(self) -> None:
        assert module_version("no_such_module_t668") == {"version": NOT_INSTALLED}

    def test_a_module_no_distribution_names_is_not_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(capabilities, "_distributions_of", lambda: {})
        version = module_version("pytest")["version"]
        assert version.startswith(f"{NOT_REPORTED}: ")
        assert "pytest" in version

    def test_a_module_is_looked_up_never_imported(self) -> None:
        sys.modules.pop("this", None)
        module("this").facts()
        assert "this" not in sys.modules


# ---------------------------------------------------------------------------
# Data: a count and one digest over the files, name then content


def _corpus(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


class TestData:
    def test_the_files_matching_the_pattern_are_counted_and_digested(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a", "sub/b.yml": "b", "readme.md": "x"})
        facts = data(str(root), pattern="*.yml").facts()
        assert facts is not None
        assert facts["files"] == 2
        assert facts["bytes"] == 2
        assert facts["named_by"] == "the default"
        assert facts["pattern"] == "*.yml"
        assert len(facts["sha256"]) == 64

    def test_the_digest_does_not_depend_on_the_order_files_were_written(
        self, tmp_path: Path
    ) -> None:
        one = _corpus(tmp_path / "one", {"a.yml": "alpha", "z/b.yml": "beta", "c.yml": "gamma"})
        two = _corpus(tmp_path / "two", {"c.yml": "gamma", "z/b.yml": "beta", "a.yml": "alpha"})
        assert data(str(one)).facts()["sha256"] == data(str(two)).facts()["sha256"]  # type: ignore[index]

    def test_a_changed_name_or_content_changes_the_digest(self, tmp_path: Path) -> None:
        base = data(str(_corpus(tmp_path / "base", {"a.yml": "ab", "b.yml": "c"}))).facts()
        renamed = data(str(_corpus(tmp_path / "renamed", {"a.yml": "ab", "c.yml": "c"}))).facts()
        edited = data(str(_corpus(tmp_path / "edited", {"a.yml": "ab", "b.yml": "d"}))).facts()
        # The same bytes split differently between name and content.
        moved = data(str(_corpus(tmp_path / "moved", {"a.yml": "a", "b.yml": "bc"}))).facts()
        digests = {f["sha256"] for f in (base, renamed, edited, moved)}  # type: ignore[index]
        assert len(digests) == 4

    def test_a_single_file_is_one_file(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("rules: []", encoding="utf-8")
        facts = data(str(path)).facts()
        assert facts is not None
        assert facts["files"] == 1
        assert facts["sha256"]

    def test_missing_data_is_counted_as_none(self, tmp_path: Path) -> None:
        facts = data(str(tmp_path / "absent")).facts()
        assert facts is not None
        assert facts["files"] == 0
        assert "sha256" not in facts
        assert facts["digest_statement"] == "no file is there"

    def test_beyond_the_bound_the_files_are_counted_and_no_digest_is_computed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _corpus(tmp_path / "big", {f"r{i}.yml": "x" for i in range(3)})
        monkeypatch.setattr(capabilities, "DATA_DIGEST_MAX_FILES", 2)
        facts = data(str(root)).facts()
        assert facts is not None
        assert facts["files"] == 3
        assert "sha256" not in facts
        assert facts["digest_statement"].startswith("digest not computed: over the bound")

    def test_beyond_the_byte_bound_no_digest_is_computed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _corpus(tmp_path / "big", {"r.yml": "x" * 10})
        monkeypatch.setattr(capabilities, "DATA_DIGEST_MAX_BYTES", 5)
        facts = data(str(root)).facts()
        assert facts is not None
        assert facts["files"] == 1
        assert "sha256" not in facts

    def test_the_digest_is_computed_once_per_process(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a"})
        first = data(str(root)).facts()
        reads: list[Path] = []
        original = Path.read_bytes

        def counted(self: Path) -> bytes:
            reads.append(self)
            return original(self)

        monkeypatch.setattr(Path, "read_bytes", counted)
        assert data(str(root)).facts() == first
        assert reads == []

    def test_the_override_names_the_path_and_the_record_names_only_what_named_it(
        self, tmp_path: Path
    ) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a"})
        req = data("data/none-here", override="T668_RULES", pattern="*.yml")
        facts = req.facts({"T668_RULES": str(root)})
        assert facts is not None
        assert facts["named_by"] == "T668_RULES"
        assert facts["files"] == 1
        assert str(tmp_path) not in repr(facts)

    def test_the_setting_a_caller_hands_the_tool_comes_first(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a", "b.yml": "b"})
        req = data("data/none-here", setting="static.capa.rules_dir", pattern="*.yml")
        settings = {"static": {"capa": {"rules_dir": str(root)}}}
        facts = req.facts(None, settings)
        assert facts is not None
        assert facts["named_by"] == "static.capa.rules_dir"
        assert facts["files"] == 2


# ---------------------------------------------------------------------------
# A binary: not reported unless the tool declares a probe


class TestABinary:
    def test_a_binary_without_a_probe_is_not_reported(self) -> None:
        assert binary("anything").facts() == {
            "kind": "binary",
            "name": "anything",
            "version": NOT_REPORTED,
        }

    def test_a_declared_probe_reads_the_version_the_binary_writes(self) -> None:
        probe = VersionProbe(_python("print('tool v1.2.3 (build 9)')"))
        assert binary("tool", version_probe=probe).facts()["version"] == "1.2.3"  # type: ignore[index]

    def test_a_probe_reads_standard_error_and_its_pattern_s_group(self) -> None:
        probe = VersionProbe(
            _python("import sys; sys.stderr.write('release 7-beta\\n')"),
            pattern=r"release (\S+)",
        )
        assert probe.read() == "7-beta"

    def test_a_probe_that_times_out_is_recorded_not_raised(self) -> None:
        probe = VersionProbe(_python("import time; time.sleep(5)"), timeout_s=0.3)
        assert probe.read() == f"{NOT_REPORTED}: it did not answer within 0.3 s"

    def test_a_probe_that_fails_is_recorded_with_its_status(self) -> None:
        probe = VersionProbe(_python("import sys; print('1.0'); sys.exit(3)"))
        assert probe.read() == f"{NOT_REPORTED}: it exited with status 3"

    def test_a_probe_of_a_program_not_there_names_only_its_name(self) -> None:
        probe = VersionProbe(("/nowhere/t668-no-such-program", "--version"))
        assert probe.read() == f"{NOT_REPORTED}: t668-no-such-program is not on PATH"

    def test_output_naming_no_version_is_not_reported(self) -> None:
        assert VersionProbe(_python("print('hello')")).read() == (
            f"{NOT_REPORTED}: its output named no version"
        )

    def test_a_probe_never_goes_through_a_shell(self) -> None:
        # A shell would expand the variable; the argument reaches the program as written.
        probe = VersionProbe(
            (*_python("import sys; print(sys.argv[1])"), "$HOME 3.4"), pattern=r"\$HOME (\S+)"
        )
        assert probe.read() == "3.4"

    def test_a_probe_s_wall_clock_has_a_ceiling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(capabilities, "VERSION_PROBE_MAX_TIMEOUT_S", 0.3)
        probe = VersionProbe(_python("import time; time.sleep(5)"), timeout_s=600)
        assert probe.read() == f"{NOT_REPORTED}: it did not answer within 0.3 s"

    def test_a_probe_runs_once_per_process(self) -> None:
        probe = VersionProbe(_python("print('2.0')"))
        probe.read()
        probe.read()
        assert capabilities._probe_version.cache_info().hits == 1


# ---------------------------------------------------------------------------
# The manifest carries them, the same way for every tool


class TestTheManifest:
    def test_a_setting_has_no_facts_and_a_tool_needing_nothing_no_row(self) -> None:
        assert env("SOME_KEY").facts() is None
        rows = requirement_facts([ToolNeeds("plain"), ToolNeeds("keyed", (env("SOME_KEY"),))])
        assert rows == []

    def test_a_requirement_two_tools_declare_is_one_row_naming_both(self, tmp_path: Path) -> None:
        shared = data(str(_corpus(tmp_path / "r", {"a.yml": "a"})))
        rows = requirement_facts(
            [
                ToolNeeds("one", (module("pytest"), shared)),
                ToolNeeds("two", (shared,)),
            ]
        )
        assert [(row["kind"], row["tools"]) for row in rows] == [
            ("module", ["one"]),
            ("data", ["one", "two"]),
        ]

    def test_the_manifest_keeps_its_fields_and_adds_the_requirements(self) -> None:
        held = manifest("x", [ToolNeeds("t", (module("pytest"),))], version="1.0")
        assert held["server"] == "x"
        assert held["version"] == "1.0"
        assert [cell["name"] for cell in held["tools"]] == ["t"]
        assert held["requirements"][0]["name"] == "pytest"

    def test_a_manifest_read_back_keeps_its_requirements(self) -> None:
        held = manifest("x", [ToolNeeds("t", (module("pytest"),))])
        parsed = ServerCapabilities.from_payload("x", held)
        assert parsed is not None
        assert parsed.requirements == held["requirements"]
        assert parsed.to_dict()["requirements"] == held["requirements"]

    def test_a_manifest_written_before_them_reads_as_it_did(self) -> None:
        old = {"server": "x", "version": "0.9", "tools": [{"name": "t", "available": True}]}
        parsed = ServerCapabilities.from_payload("x", old)
        assert parsed is not None
        assert parsed.requirements is None
        assert parsed.to_dict() == old

    def test_the_shipped_sidecars_declare_through_the_same_mechanism(self) -> None:
        from malspark.tools import sidecar_needs

        for needs in sidecar_needs.BY_DIRECTORY.values():
            for row in requirement_facts(needs):
                assert row["kind"] in ("module", "data", "binary")
                if row["kind"] == "data":
                    assert "sha256" in row or row.get("digest_statement")
                else:
                    assert row["version"]


# ---------------------------------------------------------------------------
# The run's record: only what served the run


def _tool(server: str) -> Any:
    return SimpleNamespace(name="t", metadata={"malspark_server": server})


class _Registry:
    def __init__(self, versions: dict[str, Any], manifests: dict[str, Any]) -> None:
        self._versions, self._manifests = versions, manifests

    def server_versions(self) -> dict[str, Any]:
        return dict(self._versions)

    def server_manifests(self) -> dict[str, Any]:
        return dict(self._manifests)


class _Container:
    def __init__(
        self,
        tools: dict[str, list[Any]] | None = None,
        versions: dict[str, Any] | None = None,
        manifests: dict[str, Any] | None = None,
    ) -> None:
        self._server_registry_cache = _Registry(versions or {}, manifests or {})
        self._tools = tools or {}
        self.config = None

    def setup_tools(self) -> dict[str, list[Any]]:
        return dict(self._tools)

    def setup_server_versions(self) -> dict[str, Any]:
        return {}


_MANIFEST = {
    "server": "analysis",
    "version": "0.9.0",
    "tools": [{"name": "pe_info", "available": True}],
    "requirements": [
        {
            "kind": "module",
            "name": "pefile",
            "distribution": "pefile",
            "version": "1",
            "tools": ["pe_info"],
        }
    ],
}


class TestServedTheRun:
    def test_a_server_offered_to_an_agent_is_listed_with_its_manifest(self) -> None:
        container = _Container(
            tools={"static": [_tool("analysis")]},
            versions={"analysis": {"name": "AnalysisMCP", "version": "1.2", "extra": "x"}},
            manifests={"analysis": _MANIFEST},
        )
        assert tools_record(container) == {
            "analysis": {
                "served": ["offered"],
                "server_info": {"name": "AnalysisMCP", "version": "1.2"},
                "manifest_version": "0.9.0",
                "requirements": _MANIFEST["requirements"],
            }
        }

    def test_a_server_attached_but_never_offered_or_called_is_not_listed(self) -> None:
        container = _Container(
            versions={"idle": {"name": "Idle", "version": "1"}}, manifests={"idle": _MANIFEST}
        )
        assert tools_record(container) == {}

    def test_a_server_without_a_manifest_gives_its_server_info_only(self) -> None:
        container = _Container(
            tools={"static": [_tool("ghidra")]}, versions={"ghidra": {"name": "G", "version": "11"}}
        )
        assert tools_record(container)["ghidra"] == {
            "served": ["offered"],
            "server_info": {"name": "G", "version": "11"},
            "manifest_version": NOT_REPORTED,
            "requirements": NOT_REPORTED,
        }

    def test_a_server_that_gave_no_server_info_says_so(self) -> None:
        container = _Container(tools={"static": [_tool("bare")]}, versions={"bare": {}})
        assert tools_record(container)["bare"]["server_info"] == NOT_REPORTED

    def test_a_manifest_without_requirements_reports_none(self) -> None:
        old = {k: v for k, v in _MANIFEST.items() if k != "requirements"}
        container = _Container(tools={"s": [_tool("analysis")]}, manifests={"analysis": old})
        row = tools_record(container)["analysis"]
        assert row["manifest_version"] == "0.9.0"
        assert row["requirements"] == NOT_REPORTED

    def test_each_row_says_how_it_served_the_run(self) -> None:
        entries = [
            {"agent": "pipeline", "server": "reputation", "tool": "lookup"},
            {"agent": "static", "server": "analysis", "tool": "pe_info"},
            SimpleNamespace(agent="static", server="r2", tool="afl"),
        ]
        record = tools_record(_Container(tools={"static": [_tool("analysis")]}), entries)
        assert {key: row["served"] for key, row in record.items()} == {
            "analysis": ["called", "offered"],
            "r2": ["called"],
            "reputation": ["pack_step"],
        }

    def test_the_pipeline_s_own_steps_are_read_from_the_shipped_declarations(self) -> None:
        entries = [
            {"agent": "pipeline", "server": "pipeline", "tool": "hashes"},
            {"agent": "pipeline", "server": "pipeline", "tool": "pe_info"},
            {"agent": "pipeline", "server": "pipeline", "tool": "pe_info"},
        ]
        row = tools_record(_Container(), entries)["pipeline"]
        assert row["served"] == ["in_process"]
        assert row["package_version"]
        # ``hashes`` needs nothing beyond the interpreter; ``pe_info`` its library.
        assert [(r["kind"], r["name"], r["tools"]) for r in row["requirements"]] == [
            ("module", "pefile", ["pe_info"])
        ]

    def test_a_record_of_tools_never_raises(self) -> None:
        class _Broken:
            def setup_tools(self) -> Any:
                raise RuntimeError("broken")

        assert tools_record(_Broken(), [{"server": "x"}]) == {}

    def test_the_registry_keeps_each_attached_server_s_manifest(self) -> None:
        import threading

        registry = object.__new__(ServerRegistry)
        registry._lock = threading.RLock()  # type: ignore[attr-defined]
        held = ServerCapabilities.from_payload("analysis", _MANIFEST)
        registry._handles = {  # type: ignore[attr-defined]
            "analysis": SimpleNamespace(name="analysis", capabilities=held),
            "ghidra": SimpleNamespace(name="ghidra", capabilities=None),
        }
        registry._loop_handles = {}  # type: ignore[attr-defined]
        assert registry.server_manifests() == {"analysis": held.to_dict()}  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# The summary block


class TestTheSummary:
    def test_the_environment_carries_the_tools_part(self) -> None:
        container = _Container(
            tools={"static": [_tool("analysis")]}, manifests={"analysis": _MANIFEST}
        )
        record = environment_record(container, [])
        assert record is not None
        assert record["v"] == ENVIRONMENT_VERSION
        assert record["tools"]["analysis"]["manifest_version"] == "0.9.0"
        summary = RunSummaryBuilder(start_time=0.0).set_environment(record).build().to_dict()
        assert summary["environment"]["tools"] == record["tools"]

    def test_a_run_nothing_served_has_no_tools_part(self) -> None:
        record = environment_record(_Container(), [])
        assert record is not None
        assert "tools" not in record

    def test_the_tools_part_alone_is_a_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(run_environment, "host_facts", lambda: {})
        record = environment_record(_Container(tools={"s": [_tool("x")]}))
        assert record is not None
        assert set(record) == {"v", "tools"}

    def test_a_stored_environment_without_the_part_reads_as_before(self) -> None:
        stored = {"v": 1, "host": {"os": "Linux"}}
        summary = RunSummaryBuilder(start_time=0.0).set_environment(stored).build().to_dict()
        assert summary["environment"] == stored
