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
    # Versions are read once per process and digests kept while their files
    # are unchanged; a test reads each afresh.
    capabilities.clear_fact_caches()


@pytest.fixture(autouse=True)
def _fresh_caches() -> Any:
    _clear()
    yield
    _clear()


def _python(code: str) -> tuple[str, ...]:
    return (sys.executable, "-c", code)


def _capa_rule_paths(capa_rules: Any, root: Path) -> list[Any]:
    """The rule files capa's own loader reads from ``root``."""
    collect = getattr(capa_rules, "collect_rule_file_paths", None)
    if collect is None:
        pytest.skip("this capa has no rule-file collector to compare with")
    return list(collect([root]))


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

    def test_the_digest_is_kept_while_no_file_changes(
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

    def test_data_fetched_after_the_first_read_is_read_when_asked_again(
        self, tmp_path: Path
    ) -> None:
        # A server started before its rules were fetched: the first answer
        # finds nothing, a later one the rules a call now runs with.
        root = tmp_path / "rules"
        req = data(str(root), pattern="*.yml")
        assert req.facts()["files"] == 0  # type: ignore[index]
        _corpus(root, {"a.yml": "a", "b.yml": "b"})
        later = req.facts()
        assert later is not None
        assert later["files"] == 2
        assert len(later["sha256"]) == 64

    def test_a_file_rewritten_under_a_long_lived_reader_changes_the_digest(
        self, tmp_path: Path
    ) -> None:
        import os

        root = _corpus(tmp_path / "rules", {"a.yml": "one"})
        req = data(str(root), pattern="*.yml")
        first = req.facts()["sha256"]  # type: ignore[index]
        target = root / "a.yml"
        target.write_text("two", encoding="utf-8")
        # The same size; only the modification time tells the rewrite apart.
        stat = target.stat()
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
        assert req.facts()["sha256"] != first  # type: ignore[index]

    def test_what_the_loader_leaves_out_is_neither_counted_nor_digested(
        self, tmp_path: Path
    ) -> None:
        root = _corpus(
            tmp_path / "rules",
            {"a.yml": "a", ".github/workflows/tests.yml": "ci", ".git/x.yml": "g"},
        )
        req = data(str(root), pattern="*.yml", exclude=("*.git*",))
        facts = req.facts()
        assert facts is not None
        assert facts["files"] == 1
        assert facts["exclude"] == ["*.git*"]
        # A change to the CI files alone leaves the digest as it was.
        (root / ".github" / "workflows" / "tests.yml").write_text("changed", encoding="utf-8")
        assert req.facts()["sha256"] == facts["sha256"]  # type: ignore[index]

    def test_the_row_says_what_its_digest_covers(self, tmp_path: Path) -> None:
        root = _corpus(tmp_path / "rules", {"a.yml": "a"})
        facts = data(str(root), pattern="*.yml", exclude=("*.git*",)).facts()
        assert facts is not None
        assert facts["digest_of"] == (
            "the files matching *.yml, but those under a directory whose path matches "
            "*.git*, at the path the default names, as they were when this was read"
        )

    def test_the_shipped_capa_corpus_leaves_out_what_capa_skips(self) -> None:
        from malspark.tools import sidecar_needs

        assert sidecar_needs.CAPA_RULES.exclude == ("*.git*",)

    @pytest.mark.parametrize(
        ("root_name", "files", "counted"),
        [
            # The clone's own trees, at any depth.
            ("rules", {"a.yml": "a", ".github/w.yml": "c", ".git/x.yml": "g"}, ["a.yml"]),
            # A directory whose name merely holds ".git" is skipped by capa too.
            ("rules", {"a.yml": "a", "x.github/b.yml": "b"}, ["a.yml"]),
            # A corpus kept under a path holding ".git" loads nothing in capa.
            ("capa-rules.git", {"a.yml": "a", "sub/b.yml": "b"}, []),
            # A file whose own name starts with ".git" is a rule file to capa.
            ("rules", {".gitkeep.yml": "k", "a.yml": "a"}, [".gitkeep.yml", "a.yml"]),
        ],
    )
    def test_the_capa_corpus_counts_the_files_capa_s_own_loader_reads(
        self, tmp_path: Path, root_name: str, files: dict[str, str], counted: list[str]
    ) -> None:
        from malspark.tools import sidecar_needs

        root = _corpus(tmp_path / root_name, files)
        need = sidecar_needs.CAPA_RULES
        listed = [name for name, _path in capabilities.data_files(root, need.pattern, need.exclude)]
        assert listed == counted
        capa_rules = pytest.importorskip("capa.rules")
        # capa's own collector, where it is installed, reads the same files.
        read = sorted(
            Path(p).relative_to(root).as_posix() for p in _capa_rule_paths(capa_rules, root)
        )
        assert read == counted

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

    def test_a_flood_of_output_is_read_up_to_the_bound_and_stopped(self) -> None:
        import time

        # Far more than the bound, forever: the probe stops it at the bound.
        probe = VersionProbe(
            _python(
                "import sys\nsys.stdout.write('v9.8.7 ')\nwhile True: sys.stdout.write('x' * 65536)"
            ),
            timeout_s=20,
        )
        started = time.monotonic()
        assert probe.read() == "9.8.7"
        assert time.monotonic() - started < 15
        flood = VersionProbe(
            _python("import sys\nwhile True: sys.stdout.write('x' * 65536)"), timeout_s=20
        )
        assert flood.read() == (
            f"{NOT_REPORTED}: it wrote more than {capabilities._PROBE_OUTPUT_BYTES} bytes "
            "and named no version"
        )

    @pytest.mark.posix
    def test_a_grandchild_holding_the_output_neither_delays_the_answer_nor_outlives_it(
        self, tmp_path: Path
    ) -> None:
        import os
        import time

        marker = tmp_path / "grandchild.pid"
        # The program prints its version and exits at once, leaving a process
        # of its own that holds the output open for a minute.
        code = (
            "import subprocess, sys\n"
            f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            f"open({str(marker)!r}, 'w').write(str(child.pid))\n"
            "print('tool 4.5.6')\n"
        )
        started = time.monotonic()
        assert VersionProbe(_python(code), timeout_s=10).read() == "4.5.6"
        assert time.monotonic() - started < 8
        pid = int(marker.read_text())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            pytest.fail("the probe's grandchild outlived it")

    def test_a_hang_is_stopped_at_its_wall_clock(self) -> None:
        probe = VersionProbe(_python("import time; time.sleep(60)"), timeout_s=0.5)
        assert probe.read() == f"{NOT_REPORTED}: it did not answer within 0.5 s"

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0, 0.0, "soon"])
    def test_a_wall_clock_that_is_no_positive_number_is_the_default(self, bad: Any) -> None:
        assert capabilities.probe_wall_clock(bad) == capabilities.VERSION_PROBE_TIMEOUT_S
        assert VersionProbe(_python("print('1.2')"), timeout_s=bad).read() == "1.2"

    def test_a_relative_path_with_a_separator_is_never_run(self, tmp_path: Path) -> None:
        probe = VersionProbe(("./tool", "--version"))
        assert probe.read() == (
            f"{NOT_REPORTED}: tool is named by a relative path, which a probe never runs"
        )

    @pytest.mark.posix
    def test_a_probe_runs_the_file_the_tool_s_own_lookup_finds(self, tmp_path: Path) -> None:
        pinned = tmp_path / "pinned" / "tool"
        pinned.parent.mkdir()
        pinned.write_text("#!/bin/sh\necho 'tool v2.0.1'\n", encoding="utf-8")
        pinned.chmod(0o755)
        # Another build on PATH answers another version; the probe never asks it.
        req = binary(
            "tool",
            lambda environ=None: None,
            version_probe=VersionProbe(("tool", "--version")),
            resolve=lambda environ=None: pinned,
        )
        assert req.facts()["version"] == "2.0.1"  # type: ignore[index]

    def test_a_tool_whose_lookup_finds_nothing_says_why(self) -> None:
        req = binary(
            "tool",
            lambda environ=None: "tool is not installed: none in the tools directory",
            version_probe=VersionProbe(("tool", "--version")),
            resolve=lambda environ=None: None,
        )
        assert req.facts()["version"] == (  # type: ignore[index]
            f"{NOT_REPORTED}: tool is not installed: none in the tools directory"
        )

    def test_a_probe_runs_once_per_process(self, tmp_path: Path) -> None:
        runs = tmp_path / "runs"
        probe = VersionProbe(_python(f"open({str(runs)!r}, 'a').write('x'); print('2.0')"))
        assert probe.read() == "2.0"
        assert probe.read() == "2.0"
        assert runs.read_text() == "x"

    def test_a_probe_that_failed_is_remembered_with_its_reason_and_asked_again_later(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runs = tmp_path / "runs"
        probe = VersionProbe(
            _python(f"import sys; open({str(runs)!r}, 'a').write('x'); sys.exit(2)")
        )
        said = f"{NOT_REPORTED}: it exited with status 2"
        assert probe.read() == said
        assert probe.read() == said
        assert runs.read_text() == "x"
        # Once the stated time has passed it is asked again.
        monkeypatch.setattr(capabilities, "VERSION_RETRY_S", 0.0)
        assert probe.read() == said
        assert runs.read_text() == "xx"


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

    def test_a_server_leaves_the_requirements_to_each_answer(self) -> None:
        needs = [ToolNeeds("t", (module("pytest"),))]
        held = manifest("x", needs, version="1", requirements=False)
        assert "requirements" not in held
        answered = capabilities.answered_manifest(held, needs)
        assert answered["requirements"][0]["name"] == "pytest"
        answered["tools"][0]["name"] = "changed"
        assert held["tools"][0]["name"] == "t"

    def test_a_third_party_s_requirements_are_reduced_typed_and_capped(self) -> None:
        junk = "j" * 100_000
        payload = {
            "server": "thirdparty",
            "tools": [],
            "requirements": [
                {
                    "kind": "binary",
                    "name": junk,
                    "version": 3,
                    "files": "many",
                    "bytes": -1,
                    "tools": [junk] * 500,
                    "named_by": {"a": "b"},
                    "anything": junk,
                }
            ]
            * 500,
        }
        parsed = ServerCapabilities.from_payload("thirdparty", payload)
        assert parsed is not None and parsed.requirements is not None
        rows = parsed.requirements
        assert len(rows) == capabilities.REQUIREMENT_ROWS
        first = rows[0]
        assert set(first) == {"kind", "name", "version", "tools", "cut"}
        assert first["version"] == "3"
        assert len(first["name"]) == capabilities.REQUIREMENT_TEXT_CHARS
        assert len(first["tools"]) == capabilities.REQUIREMENT_LIST_ITEMS
        assert first["cut"] == (
            "name cut at 200 characters; tools cut at 256 of 500; 1 unknown key(s) left out"
        )
        assert rows[-1]["cut"].endswith("244 more row(s) left out after this one")
        import json

        assert len(json.dumps(rows)) < 20_000_000

    def test_a_shipped_manifest_s_rows_pass_unchanged(self, tmp_path: Path) -> None:
        shared = data(str(_corpus(tmp_path / "r", {"a.yml": "a"})), exclude=(".git*",))
        held = manifest("x", [ToolNeeds("t", (module("pytest"), shared, binary("nowhere")))])
        parsed = ServerCapabilities.from_payload("x", held)
        assert parsed is not None
        assert parsed.requirements == held["requirements"]

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

    def test_a_server_attached_but_never_offered_or_called_is_listed_as_attached(self) -> None:
        container = _Container(
            versions={"idle": {"name": "Idle", "version": "1"}}, manifests={"idle": _MANIFEST}
        )
        assert tools_record(container)["idle"]["served"] == ["attached"]

    def test_a_name_no_attached_server_backs_is_no_tool_server(self) -> None:
        # An agent-to-agent delegation tool carries the server ``team``,
        # which no handle backs: it is not a server that failed to report.
        from malspark.agents.delegation import TEAM_SERVER

        container = _Container(
            tools={"lead": [_tool(TEAM_SERVER), _tool("analysis")]},
            versions={"analysis": {"name": "AnalysisMCP", "version": "1"}},
        )
        entries = [{"agent": "lead", "server": TEAM_SERVER, "tool": "ask_static"}]
        assert set(tools_record(container, entries)) == {"analysis"}

    def test_a_third_party_s_requirements_enter_the_record_capped(self) -> None:
        junk = {"kind": "binary", "name": "x" * 100_000, "named_by": "/home/alice/p", "z": 1}
        held = {"server": "other", "version": "1", "tools": [], "requirements": [junk] * 500}
        container = _Container(tools={"s": [_tool("other")]}, manifests={"other": held})
        rows = tools_record(container)["other"]["requirements"]
        assert len(rows) == capabilities.REQUIREMENT_ROWS
        assert set(rows[0]) == {"kind", "name", "named_by", "cut"}
        assert len(rows[0]["name"]) == capabilities.REQUIREMENT_TEXT_CHARS

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
        container = _Container(
            tools={"static": [_tool("analysis")]},
            versions={"analysis": {}, "r2": {}, "reputation": {}},
        )
        record = tools_record(container, entries)
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

    def test_a_step_in_process_reads_the_environment_of_the_server_it_stands_in_for(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.core.config import Settings
        from malspark.tools import rules

        corpus = _corpus(tmp_path / "sigma", {"a.yml": "a", "b.yml": "b"})
        monkeypatch.delenv(rules.SIGMA_RULES_ENV, raising=False)
        settings = Settings()
        # An override set only on the server's own block, which the step reads.
        settings.mcp.servers["analysis"].env = {rules.SIGMA_RULES_ENV: str(corpus)}
        container = _Container()
        container.config = settings
        entries = [{"agent": "pipeline", "server": "pipeline", "tool": "sigma_match_sandbox"}]
        rows = tools_record(container, entries)["pipeline"]["requirements"]
        (sigma,) = [row for row in rows if row["kind"] == "data"]
        assert sigma["named_by"] == rules.SIGMA_RULES_ENV
        assert sigma["files"] == 2

    def test_a_provider_s_own_server_is_listed_as_the_registry_s_are(self) -> None:
        class _Provider:
            def own_tool_server(self) -> dict[str, Any]:
                return {
                    "server": "r2",
                    "server_info": {"name": "r2mcp", "version": "5.9"},
                    "manifest": None,
                }

        container = _Container(tools={"static": [_tool("r2")]})
        container._static_provider_cache = {"r2": _Provider()}  # type: ignore[attr-defined]
        assert tools_record(container)["r2"] == {
            "served": ["offered"],
            "server_info": {"name": "r2mcp", "version": "5.9"},
            "manifest_version": NOT_REPORTED,
            "requirements": NOT_REPORTED,
        }

    def test_the_registry_s_reading_of_a_server_comes_before_a_provider_s(self) -> None:
        class _Provider:
            def own_tool_server(self) -> dict[str, Any]:
                return {"server": "analysis", "server_info": {"name": "other"}, "manifest": None}

        container = _Container(
            versions={"analysis": {"name": "AnalysisMCP", "version": "1"}},
            manifests={"analysis": _MANIFEST},
        )
        container._sandbox_provider_cache = _Provider()  # type: ignore[attr-defined]
        row = tools_record(container)["analysis"]
        assert row["server_info"] == {"name": "AnalysisMCP", "version": "1"}
        assert row["manifest_version"] == "0.9.0"

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
        record = environment_record(_Container(tools={"s": [_tool("x")]}, versions={"x": {}}))
        assert record is not None
        assert set(record) == {"v", "tools"}

    def test_a_stored_environment_without_the_part_reads_as_before(self) -> None:
        stored = {"v": 1, "host": {"os": "Linux"}}
        summary = RunSummaryBuilder(start_time=0.0).set_environment(stored).build().to_dict()
        assert summary["environment"] == stored


# ---------------------------------------------------------------------------
# The string-extraction tool's binary says its version


class TestTheStringExtractionToolSaysItsVersion:
    @pytest.fixture(autouse=True)
    def _forget(self) -> Any:
        # The lookup's verdicts and the version each build answered are
        # remembered per process; each test reads them afresh.
        from malspark.tools import emulated_strings

        emulated_strings.forget_documents()
        yield
        emulated_strings.forget_documents()

    @pytest.mark.posix
    def test_the_version_is_the_answer_of_the_pinned_build_check_never_a_second_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        from malspark.tools import emulated_strings, sidecar_needs

        stub = tmp_path / "tools" / "floss"
        stub.parent.mkdir()
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
        runs: list[list[str]] = []

        def _run(argv: Any, timeout: Any, pinned: Any = None, scratch: Any = None) -> Any:
            runs.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "floss v3.1.1-0-gabcdef0\n", "")

        monkeypatch.setenv(emulated_strings.FLOSS_PATH_ENV, str(stub))
        monkeypatch.setattr(emulated_strings, "_is_pinned_build", lambda path: True)
        monkeypatch.setattr(emulated_strings, "_run", _run)
        floss = [n for n in sidecar_needs.ANALYSIS if n.name == "floss"]
        # The server's start: the cell's check runs the build once.
        assert manifest("analysis", floss, requirements=False)["tools"][0]["available"]
        rows = requirement_facts(floss)
        assert rows == [{"kind": "binary", "name": "floss", "version": "3.1.1", "tools": ["floss"]}]
        assert runs == [[str(stub), "--version"]]

    def test_a_check_that_timed_out_is_not_run_on_every_answer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        from malspark.tools import emulated_strings, sidecar_needs

        stub = tmp_path / "floss"
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
        runs: list[Any] = []

        def _run(argv: Any, timeout: Any, pinned: Any = None, scratch: Any = None) -> Any:
            runs.append(argv)
            raise subprocess.TimeoutExpired(argv, timeout)

        monkeypatch.setenv(emulated_strings.FLOSS_PATH_ENV, str(stub))
        monkeypatch.setattr(emulated_strings, "_is_pinned_build", lambda path: True)
        monkeypatch.setattr(emulated_strings, "_run", _run)
        floss = [n for n in sidecar_needs.ANALYSIS if n.name == "floss"]
        # The server's start: the cell's check times out once.
        assert not manifest("analysis", floss, requirements=False)["tools"][0]["available"]
        first = requirement_facts(floss)[0]["version"]
        assert first.startswith(f"{NOT_REPORTED}: floss cannot be executed on this host")
        for _ in range(3):
            assert requirement_facts(floss)[0]["version"] == first
        # The record read the check's own answer and never ran the build.
        assert len(runs) == 1

    def test_with_no_pinned_build_the_lookup_s_reason_is_recorded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.tools import emulated_strings, sidecar_needs

        why = "floss is not installed: no floss executable in the user tools directory or on PATH"
        monkeypatch.setattr(emulated_strings, "find_floss", lambda environ=None: (None, why))
        (row,) = requirement_facts([n for n in sidecar_needs.ANALYSIS if n.name == "floss"])
        assert row["version"] == f"{NOT_REPORTED}: {why}"

    def test_the_declaration_calls_the_lookup_that_is_in_place_when_it_is_called(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Bound when the list was built, a lookup a test had replaced while the
        # declarations were first imported stayed in them for every later test.
        from malspark.tools import emulated_strings, sidecar_needs

        (floss,) = [n for n in sidecar_needs.ANALYSIS if n.name == "floss"]
        (req,) = floss.requires
        monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: "here now")
        monkeypatch.setattr(emulated_strings, "floss_version", lambda environ=None: "9.9.9")
        assert req.locate() == "here now"  # type: ignore[misc]
        assert req.facts() == {"kind": "binary", "name": "floss", "version": "9.9.9"}
