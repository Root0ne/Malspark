"""A rule engine that loaded no rule did not run; it never answers "0 hits" (T-556).

haiku8, haiku9 and haiku10 ran the Sigma pass over the sandbox report with no
corpus: the directory is fetched rather than tracked and the run's worktree
had none. The worker logged a warning, the entry held ``rule_count 0``, the
report said "Sigma (0 hits)", the run was not degraded, and the check before
the job named nothing, because the pass runs in the worker by a direct call
that no reading stands in for, and only readings and servers were checked.

Every rule engine now answers an empty corpus as a failure with the code a
missing library has and its declared data path's remedy, the same path capa's
missing rules take: the pack records the step failed, the run is degraded,
the report's scope says what the run went without and why, and the check
before a job looks at the corpus of every in-process step a sidecar declares.
"""

from __future__ import annotations

import importlib.util
import json
import re
from collections.abc import Callable
from functools import partial
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any

import pytest

from app.services.tool_availability import WORKER, as_rows, unavailable_tools
from malspark.agents.evidence_recorder import EvidenceRecorder
from malspark.analysis.run_summary import RunSummaryBuilder
from malspark.core.config import Settings
from malspark.core.paths import (
    OUTSIDE_PROJECT,
    get_project_root,
    host_path_masked,
    host_paths_masked,
)
from malspark.pipeline.operator_choice import SampleFacts, lost_tool_rows
from malspark.pipeline.triage_pack import PIPELINE, run_is_degraded, run_pack
from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST
from malspark.schemas.evidence import EvidenceCounter
from malspark.tools import capabilities, emulated_strings, rules, sidecar_needs
from malspark.tools.errors import BAD_ARGUMENT, MISSING_DEPENDENCY, error_parts
from tests.linear_cost import assert_scales, cpu_seconds
from tests.unit.pipeline.test_triage_pack import SANDBOX_REPORT, _inputs, _write
from tests.unit.tools.test_binary import _pe
from tests.unit.tools.test_rules import SIGMA_RULE

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "reporting"
SIGMA_REASON = (
    "no rule was loaded from data/sigma_rules, which is missing or holds none, so no rule was run"
)

YARA_RULES = """
rules:
  - id: marker_rule
    technique_id: T1059
    patterns: ["MARKER"]
"""


@pytest.fixture(autouse=True)
def fresh_caches() -> Any:
    rules.reset_rule_caches()
    yield
    rules.reset_rule_caches()


@pytest.fixture
def no_sigma(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The Sigma corpus named by its override, and not there."""
    absent = tmp_path / "sigma_rules"
    monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(absent))
    return absent


def _failure(answer: dict[str, Any]) -> tuple[str, str, str | None]:
    parts = error_parts(answer)
    assert parts is not None, answer
    return parts


class TestTheEngineAnswer:
    def test_sigma_over_a_sandbox_report_with_no_corpus_did_not_run(self, no_sigma: Path) -> None:
        answer = rules.sigma_match_sandbox(SANDBOX_REPORT)
        code, message, remedy = _failure(answer)
        assert code == MISSING_DEPENDENCY
        assert message.startswith("no rule was loaded from ")
        assert message.endswith("which is missing or holds none, so no rule was run")
        assert remedy == sidecar_needs.SIGMA_RULES.remedy
        assert answer["tool"] == "sigma_match_sandbox"
        assert answer["event_count"] == 1
        assert "matches" not in answer and "rule_count" not in answer

    def test_a_directory_holding_no_rule_file_did_not_run(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        (tmp_path / "empty").mkdir()
        (tmp_path / "empty" / "README.md").write_text("fetched later\n", encoding="utf-8")
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(tmp_path / "empty"))
        assert _failure(rules.sigma_match([{"Image": "x"}]))[0] == MISSING_DEPENDENCY

    def test_a_ruleset_the_caller_named_is_its_own_argument_to_change(self, tmp_path: Path) -> None:
        code, _message, remedy = _failure(rules.sigma_match([], ruleset=str(tmp_path / "none")))
        assert code == BAD_ARGUMENT
        assert remedy is not None and "'default'" in remedy

    def test_an_empty_corpus_is_not_kept_so_one_put_in_place_later_is_read(
        self, no_sigma: Path
    ) -> None:
        assert "error" in rules.sigma_match_sandbox(SANDBOX_REPORT)
        no_sigma.mkdir()
        (no_sigma / "rundll32.yml").write_text(SIGMA_RULE, encoding="utf-8")
        answer = rules.sigma_match_sandbox(SANDBOX_REPORT)
        assert answer["rule_count"] == 1 and "error" not in answer

    def test_yara_with_no_corpus_did_not_run_and_a_directory_corpus_is_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"xx MARKER yy")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(tmp_path / "yara"))
        code, _message, remedy = _failure(rules.yara_scan(path=str(sample)))
        assert code == MISSING_DEPENDENCY
        assert remedy == sidecar_needs.YARA_RULES.remedy
        assert remedy.startswith("restore data/yara_ttp_rules.yaml from version control")
        (tmp_path / "yara").mkdir()
        (tmp_path / "yara" / "marker.yaml").write_text(YARA_RULES, encoding="utf-8")
        answer = rules.yara_scan(path=str(sample))
        assert answer["rule_count"] == 1
        assert [row["rule"] for row in answer["matches"]] == ["marker_rule"]

    def test_capa_with_no_rules_did_not_run_with_its_declared_remedy(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        code, message, remedy = _failure(rules.capa(str(sample), rules_dir=str(tmp_path / "x")))
        assert code == MISSING_DEPENDENCY
        assert "no rule was loaded from" in message
        assert remedy == sidecar_needs.CAPA_RULES.remedy

    def test_a_path_outside_the_project_is_named_by_what_named_it(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv(rules.SIGMA_RULES_ENV, str(tmp_path / "gone"))
        _code, message, _remedy = _failure(rules.sigma_match([]))
        assert message.startswith(
            "no rule was loaded from the path MALSPARK_SIGMA_RULES_DIR names,"
        )
        assert str(tmp_path) not in message
        _code, message, _remedy = _failure(rules.sigma_match([], ruleset=str(tmp_path / "x")))
        assert message.startswith("no rule was loaded from the ruleset named,")
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")
        _code, message, _remedy = _failure(rules.capa(str(sample), rules_dir=str(tmp_path / "x")))
        assert message.startswith("no rule was loaded from the path static.capa.rules_dir names,")


class TestADirectoryCorpus:
    def test_its_files_are_compiled_once_and_a_bad_one_is_named_and_skipped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        from malspark.analysis import yara_layer

        corpus = tmp_path / "yara"
        corpus.mkdir()
        (corpus / "a.yaml").write_text(YARA_RULES, encoding="utf-8")
        (corpus / "b.yml").write_text(YARA_RULES.replace("marker_rule", "second"), "utf-8")
        (corpus / "broken.yml").write_text("not: [a rule list\n", encoding="utf-8")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(corpus))
        compiled: list[int] = []
        real = yara_layer.YaraLayer.__init__

        def counting(self: Any, rules: list[Any]) -> None:
            compiled.append(len(rules))
            real(self, rules)

        monkeypatch.setattr(yara_layer.YaraLayer, "__init__", counting)
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"xx MARKER yy")

        answer = rules.yara_scan(path=str(sample))

        assert compiled == [2]
        assert answer["rule_count"] == 2
        (skipped,) = answer["files_not_loaded"]
        assert skipped["file"] == "broken.yml"
        assert str(tmp_path) not in skipped["error"]
        assert "broken.yml" in caplog.text


class TestADirectoryCorpusNoneOfWhoseFilesReads:
    def test_it_did_not_run_and_names_each_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = tmp_path / "yara"
        corpus.mkdir()
        (corpus / "a.yml").write_text("not: [a rule list\n", encoding="utf-8")
        (corpus / "b.yaml").write_text("rules\n", encoding="utf-8")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(corpus))
        answer = rules.yara_scan(text="x")
        code, message, _remedy = _failure(answer)
        assert code == MISSING_DEPENDENCY
        assert message == (
            "no rule was loaded from the path MALSPARK_YARA_RULES_DIR names: none of its 2 rule "
            "files could be read, so no rule was run"
        )
        assert [row["file"] for row in answer["files_not_loaded"]] == ["a.yml", "b.yaml"]

    def test_some_unread_and_the_rest_empty_says_so(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        corpus = tmp_path / "yara"
        corpus.mkdir()
        (corpus / "a.yml").write_text("not: [a rule list\n", encoding="utf-8")
        (corpus / "b.yml").write_text("rules: []\n", encoding="utf-8")
        monkeypatch.setenv(rules.YARA_RULES_ENV, str(corpus))
        _code, message, _remedy = _failure(rules.yara_scan(text="x"))
        assert "1 of its 2 rule files could not be read and the rest hold no rule" in message


class TestAnEmptyCorpusIsReadAgainOnlyWhenItChanges:
    def test_the_warning_is_said_once_and_a_corpus_put_in_place_is_read(
        self, no_sigma: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        for _ in range(3):
            assert "error" in rules.sigma_match_sandbox(SANDBOX_REPORT)
        assert caplog.text.count("rules directory not found") == 1
        no_sigma.mkdir()
        (no_sigma / "rundll32.yml").write_text(SIGMA_RULE, encoding="utf-8")
        assert rules.sigma_match_sandbox(SANDBOX_REPORT)["rule_count"] == 1


CAPA_MODULES = (
    "capa",
    "capa.capabilities",
    "capa.capabilities.common",
    "capa.helpers",
    "capa.loader",
    "capa.render",
    "capa.render.result_document",
    "capa.rules",
    "capa.rules.cache",
)


class TestTheEvidenceOnlyProvider:
    """``capa_yara``, for a run with no triage pack: missing rules are a pass not made."""

    def test_missing_capa_rules_are_a_reason_the_bundle_carries(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import sys
        import types

        from malspark.core.config import StaticCapaConfig, StaticYaraConfig
        from malspark.providers.static.capa_yara import CapaYaraStaticProvider

        # capa's modules present, so the rules are what is missing.
        for name in CAPA_MODULES:
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        provider = CapaYaraStaticProvider(
            StaticCapaConfig(rules_dir=str(tmp_path / "capa-rules")),
            StaticYaraConfig(rules_dir=str(tmp_path / "no-yara")),
        )
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")

        bundle = provider.collect_evidence(str(sample))

        assert bundle is not None
        (reason,) = bundle.unavailable
        assert reason.startswith("static provider 'capa_yara' did not run capa: no rule was loaded")
        assert str(tmp_path) not in reason
        assert sidecar_needs.CAPA_RULES.remedy in reason
        assert provider.capabilities.provides_evidence, "rules put in place later are read"
        assert provider.capabilities.degrade_on_failure

    def test_its_rules_directory_is_masked_as_one_path_whatever_its_name_holds(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import sys
        import types

        from malspark.core.config import StaticCapaConfig, StaticYaraConfig
        from malspark.providers.static.capa_yara import CapaYaraStaticProvider

        for name in CAPA_MODULES:
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        provider = CapaYaraStaticProvider(
            StaticCapaConfig(rules_dir=str(tmp_path / "Jane Doe" / "rules (qz)")),
            StaticYaraConfig(rules_dir=str(tmp_path / "no-yara")),
        )
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"MZ")

        (reason,) = provider.collect_evidence(str(sample)).unavailable  # type: ignore[union-attr]

        assert f"no rule was loaded from {OUTSIDE_PROJECT}, which is missing" in reason
        assert "Doe" not in reason and "qz" not in reason


class TestTheRunIsDegraded:
    def test_the_pack_records_the_step_failed_and_the_run_is_degraded(
        self, no_sigma: Path, tmp_path: Path
    ) -> None:
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        path = _write(tmp_path, "s.exe", _pe())
        result = run_pack(recorder, _inputs(path, "pe", sandbox_report=SANDBOX_REPORT))
        (sigma,) = [entry for entry in result.entries if entry.tool == "sigma_match_sandbox"]
        assert sigma.ok is False
        assert "no rule was loaded from" in str(sigma.error)
        assert sigma.remediation == sidecar_needs.SIGMA_RULES.remedy
        assert "triage.sigma_match_sandbox_failed" in result.degradation_reasons
        assert "triage.sigma_match_sandbox_failed" in result.to_state()["degradation_reasons"]
        assert run_is_degraded(["triage.sigma_match_sandbox_failed"])


def _degraded_report(reason: str = SIGMA_REASON) -> MalwareReport:
    return MalwareReport.model_validate(
        {
            "verdict": "Malware",
            "overall_confidence": 0.8,
            "degraded_mode": True,
            "identity": {"hashes": {"sha256": "e" * 64}, "file_type": "pe"},
            "degradation_reasons": ["triage.sigma_match_sandbox_failed"],
            "run_summary": {
                "lost_tools": [{"tool": "sigma_match_sandbox", "reason": reason}],
            },
        }
    )


def _scope(report: MalwareReport) -> str:
    markdown = MarkdownRenderer(layout=ANALYST).render(report)
    return markdown.split("## 2. Introduction and scope", 1)[1].split("\n## ", 1)[0]


class TestTheRunRecordsWhatItWentWithout:
    def test_each_lost_tool_with_its_own_error(self) -> None:
        facts = SampleFacts(
            file_type="pe",
            failures=(
                {"tool": "sigma_match_sandbox", "ok": False, "error": SIGMA_REASON},
                {"tool": "strings", "ok": True, "error": None},
            ),
        )
        rows = lost_tool_rows(["triage.sigma_match_sandbox_failed"], facts)
        assert rows == [{"tool": "sigma_match_sandbox", "reason": SIGMA_REASON}]

    def test_a_servers_tool_with_what_its_reason_brackets(self) -> None:
        reason = (
            "server.analysis.sigma_match_unavailable(data/sigma_rules is missing or empty "
            "(named by the default)); put the data in data/sigma_rules"
        )
        assert lost_tool_rows([reason]) == [
            {
                "tool": "sigma_match",
                "reason": "data/sigma_rules is missing or empty (named by the default)",
            }
        ]

    def test_a_host_path_is_shown_from_the_project_or_masked(self) -> None:
        root = get_project_root()
        error = f"rules at {root}/data/capa-rules and /srv/elsewhere/capa-rules are missing"
        facts = SampleFacts(failures=({"tool": "capa", "ok": False, "error": error},))
        (row,) = lost_tool_rows(["triage.capa_failed"], facts)
        assert row["reason"] == (f"rules at data/capa-rules and {OUTSIDE_PROJECT} are missing")


class TestOnlyAHostPathIsMasked:
    def test_an_http_route_is_kept(self) -> None:
        for text in (
            "GET /api/v1/jobs failed",
            "POST /live/ answered 404",
            "see https://x.test/a/b",
        ):
            assert host_paths_masked(text) == text

    def test_a_path_under_a_host_root_or_the_projects_parents_is_masked(self) -> None:
        parent = get_project_root().parent
        said = host_paths_masked(f"read /tmp/x/rules.yml, /etc/passwd and {parent}/other/r.yml")
        assert said == f"read {OUTSIDE_PROJECT}, {OUTSIDE_PROJECT} and {OUTSIDE_PROJECT}"

    def test_a_path_in_another_hosts_layout_is_masked_on_any_host(self) -> None:
        """macOS's temporary directory resolves under /private, its users under /Users."""
        said = host_paths_masked(
            "read /private/var/folders/2s/xy/T/pytest-0/rules.yml and /Users/someone/r.yml"
        )
        assert said == f"read {OUTSIDE_PROJECT} and {OUTSIDE_PROJECT}"

    def test_the_words_alone_decide_never_the_host(self) -> None:
        # Under a host root, whether or not it is there; elsewhere, kept even
        # where it is there (``/proc`` is on every Linux host).
        assert host_paths_masked("at /opt/no-such-dir-t556") == f"at {OUTSIDE_PROJECT}"
        assert host_paths_masked("read /proc/self/status") == "read /proc/self/status"

    def test_a_file_url_is_a_path(self) -> None:
        root = get_project_root()
        said = host_paths_masked(f"file://{root}/data/sigma_rules and file:///srv/x/r.yml")
        assert said == f"data/sigma_rules and {OUTSIDE_PROJECT}"
        assert host_paths_masked("file://localhost/opt/rules") == OUTSIDE_PROJECT

    def test_a_windows_path_is_masked_on_any_host(self) -> None:
        said = host_paths_masked(
            'in "C:\\Users\\someone\\AppData\\Local\\Temp\\broken.yml", line 1 and D:/x/r.yml'
        )
        assert said == f'in "{OUTSIDE_PROJECT}", line 1 and {OUTSIDE_PROJECT}'
        assert host_paths_masked("file:///C:/rules/r.yml") == OUTSIDE_PROJECT

    def test_an_os_error_s_doubled_backslashes_hide_the_whole_path(self) -> None:
        """How an OSError prints its file name, and how a JSON-escaped message reads."""
        missing = FileNotFoundError(2, "No such file or directory", r"C:\Users\alice\Temp\r.yml")
        said = host_paths_masked(f"{type(missing).__name__}: {missing}")
        assert "alice" not in said and "Temp" not in said
        assert said.endswith(f"No such file or directory: '{OUTSIDE_PROJECT}'")
        assert (
            host_paths_masked(r"at C:\\Users\\alice\\r.yml, then") == f"at {OUTSIDE_PROJECT}, then"
        )
        escaped = r'{"error": "cannot read C:\\\\Users\\\\alice\\\\r.yml"}'
        assert host_paths_masked(escaped) == f'{{"error": "cannot read {OUTSIDE_PROJECT}"}}'

    @pytest.mark.parametrize(
        "written",
        [
            r"\\server\share\me\f",
            r"\\\\server\\share\\me\\f",
            r"\\?\C:\Users\me\f",
            r"\\\\?\\C:\\Users\\me\\f",
            r"\\.\C:\Users\me\f",
            r"\\\\.\\C:\\Users\\me\\f",
            r"\\?\UNC\server\share\me\f",
            r"\\\\?\\UNC\\server\\share\\me\\f",
            r"\\.\pipe\me",
        ],
    )
    def test_a_unc_or_device_path_is_masked(self, written: str) -> None:
        assert host_paths_masked(f"read {written} then") == f"read {OUTSIDE_PROJECT} then"

    def test_a_quoted_windows_path_is_masked_to_its_closing_quote(self) -> None:
        said = host_paths_masked(
            r"""open 'C:\Users\John Smith\AppData\x.yml' and "\\srv\my share\x" failed"""
        )
        assert said == f"""open '{OUTSIDE_PROJECT}' and "{OUTSIDE_PROJECT}" failed"""
        # A quoted POSIX path stops at a space, as it always has.
        assert host_paths_masked("'/home/a b/c'") == f"'{OUTSIDE_PROJECT} b/c'"

    @pytest.mark.parametrize(
        "span",
        [
            r"D:\proj\rules\a.yml and C:\Users\alice\secret.txt",
            r"C:\Users\alice\secret.txt and D:\proj\rules\a.yml",
            r"C:\Users\alice\a.txt and C:\Users\bob\b.txt",
            r"D:\proj\x.yml (copied from \\srv\share\alice\y.yml)",
            r"D:\proj\x.yml (copied from \\\\srv\\share\\alice\\y.yml)",
            r"D:\proj\a then \\?\C:\Users\alice",
            r"D:\proj\x and \\srv\c$\alice",
            r"D:\proj\a then path:C:\Users\alice",
            r"D:\proj\a.C:\Users\alice",
            r"D:\proj\a, file://srv/share/alice",
        ],
    )
    def test_a_quoted_span_holding_another_path_is_masked_whole(self, span: str) -> None:
        root = Path(r"D:\proj")
        for quote in ("'", '"'):
            said = host_paths_masked(f"read {quote}{span}{quote} then", root)
            assert said == f"read {quote}{OUTSIDE_PROJECT}{quote} then"

    def test_a_quoted_project_path_s_words_are_read_again(self) -> None:
        root = Path(r"D:\proj")
        said = host_paths_masked(r"read 'D:\proj\rules\a b.yml, from /home/alice/x' then", root)
        assert said == f"read 'rules/a b.yml, from {OUTSIDE_PROJECT}' then"
        assert host_paths_masked(r"read 'D:\proj\rules\a b.yml' then", root) == (
            "read 'rules/a b.yml' then"
        )

    def test_text_shaped_like_a_windows_path_is_masked_on_any_host_too(self) -> None:
        r"""A decision, not an accident: the words alone decide, never the host.

        ``x:\d+`` reads as a drive path, a doubled backslash before a word as a
        UNC path, a quoted span holding a Windows path is masked up to its
        closing quote, and a ``file://host/`` URL names another machine; so a
        regular expression or a guest's path quoted in a tool's error is masked
        on a Linux host as well.
        """
        assert host_paths_masked(r"pattern x:\d+ matched") == f"pattern {OUTSIDE_PROJECT} matched"
        assert host_paths_masked(r'"\\d+\\s" matched') == f'"{OUTSIDE_PROJECT}" matched'
        assert host_paths_masked(r"ran '\\powershell.exe'") == f"ran '{OUTSIDE_PROJECT}'"
        assert host_paths_masked(r"lost: 'C:\Windows\System32\cmd.exe' is gone") == (
            f"lost: '{OUTSIDE_PROJECT}' is gone"
        )
        assert host_paths_masked(r"'C:\a.yml: bad key, see docs'") == f"'{OUTSIDE_PROJECT}'"
        assert host_paths_masked("from file://host/share/r.yml") == f"from {OUTSIDE_PROJECT}"

    def test_a_drive_after_an_ascii_letter_or_digit_is_a_scheme_not_a_path(self) -> None:
        """``https://`` and an escaped line break (``error:\\n``) are never drives."""
        for text in ("see https://example.com/a", r"error:\nnext", "2C:/x", "wordC:\\x"):
            assert host_paths_masked(text) == text

    @pytest.mark.parametrize("before", ["日本", "é", "path:", "_", "a.", "(", "\\n"])
    def test_a_drive_glued_to_other_words_is_masked(self, before: str) -> None:
        said = host_paths_masked(f"{before}C:\\Users\\alice\\x then")
        assert said == f"{before}{OUTSIDE_PROJECT} then"

    def test_a_drive_inside_a_project_path_starts_another_path(self) -> None:
        said = host_paths_masked(r"read D:\proj\a.C:\Users\alice then", Path(r"D:\proj"))
        assert said == f"read a.{OUTSIDE_PROJECT} then"

    @pytest.mark.parametrize(
        "written",
        [
            r"\\10.0.0.1\c$\Users\alice",
            r"\\?\UNC\10.0.0.5\c$\Users\alice",
            r"\\server\admin$\alice",
            r"C:\$Recycle.Bin\S-1-5-21-123\alice.txt",
            r"\\?\Volume{1234-abcd}\Users\alice",
            r"C:\Users\a(b)\alice",
            r"C:\Users\alice's files\x",
            r"C:\Users\New folder (2)\alice",
            r"C:\(x)\[y]\{z}\a=b;c,d\alice",
            "C:\\Users\\alice\u00a0smith\\x",
            r"C:\Users\John Smith\AppData\x",
            r"C:\\Users\\John Smith\\x",
            r"file://server/share/alice",
            r"file:\\server\share\alice",
            r"file:////server/share/a(b)/alice",
            "C:\\Users\\alice\\OneDrive \u2013 Firma\\x",
            "C:\\Users\\al\u0301ice\\x",
            "C:\\Users\\a\u20acb\\alice",
            "C:\\Users\\R\u00e9sum\u00e9 \u00a92024\\alice",
            "C:\\Users\\alice\\\U0001f600 notes\\x",
            "C:\\Users\\a`b\\alice",
            "C:\\Users\\a\u200bb\\alice",
            "C:\\Users\\alice\u2009smith\\x",
            "C:\\Users\\alice\u2019s files\\x",
            "\\\\server\\€share\\alice",
            r"File://server/share/alice",
            r"FILE:///C:/Users/alice",
            r"File:\\server\share\alice",
        ],
    )
    def test_every_name_a_windows_path_may_hold_is_masked_with_it(self, written: str) -> None:
        for after in (" then", ": denied", ").", ", next"):
            assert host_paths_masked(f"read {written}{after}") == f"read {OUTSIDE_PROJECT}{after}"

    @pytest.mark.parametrize(
        ("opening", "closing"),
        [("`", "`"), ("\u2018", "\u2019"), ("\u201c", "\u201d"), ("\u00ab", "\u00bb")],
    )
    def test_a_path_in_any_quotes_is_masked_to_its_closing_quote(
        self, opening: str, closing: str
    ) -> None:
        said = host_paths_masked(f"open {opening}C:\\Users\\John Smith\\my file.txt{closing} x")
        assert said == f"open {opening}{OUTSIDE_PROJECT}{closing} x"

    @pytest.mark.parametrize(
        ("opening", "closing"),
        [("'", "'"), ('"', '"'), ("`", "`"), ("\u201c", "\u201d")],
    )
    @pytest.mark.parametrize(
        "url",
        [
            "file:///C:/Users/x/My Docs",
            "file:///C:/Users/x/My Docs/y z",
            "file://srv/share/x/My Docs",
            "FILE:\\\\srv\\share\\x\\My Docs",
        ],
    )
    def test_a_quoted_file_url_is_masked_to_its_closing_quote(
        self, url: str, opening: str, closing: str
    ) -> None:
        said = host_paths_masked(f"open {opening}{url}{closing} x")
        assert said == f"open {opening}{OUTSIDE_PROJECT}{closing} x"

    @pytest.mark.parametrize(
        "message",
        [
            "cannot open C:/Users/\u00c9lodie/x now",
            "cannot open file:///C:/Users/\u7530\u4e2d/AppData/x now",
            "cannot open C:/Users/a \u65e5\u672c/x now",
            "cannot open c:\\Users\\p \u011f\\x now",
        ],
    )
    def test_json_written_with_escapes_hides_a_name_that_is_not_ascii(self, message: str) -> None:
        # ``json.dumps`` writes a character that is not ASCII as ``\uXXXX``;
        # after a slash that escape is the name's first character.
        written = json.dumps({"m": message})
        assert "\\u" in written
        said = json.loads(host_paths_masked(written))
        assert said == {"m": f"cannot open {OUTSIDE_PROJECT} now"}

    @pytest.mark.parametrize(
        ("written", "after"),
        [
            ("C:\\Users\\bob\\rules.yml", ". Check the path"),
            ("C:\\Users\\bob\\x", "."),
            ("\\\\srv\\share\\bob\\notes.txt", ". Next"),
            ("C:\\Users\\bob\\a.b.c", "... and so on"),
        ],
    )
    def test_a_full_stop_after_a_windows_path_stays_outside_it(
        self, written: str, after: str
    ) -> None:
        assert host_paths_masked(f"Wrote {written}{after}") == f"Wrote {OUTSIDE_PROJECT}{after}"

    @pytest.mark.parametrize(
        ("written", "after"),
        [
            ("C:\\a\\.(secret", ") end"),
            ("C:\\a\\.,bob", " end"),
            ("C:\\a\\..'bob's", " end"),
            ("C:\\a\\.;bob.txt", ". End"),
            ("\\\\srv\\share\\..(bob", "), then"),
        ],
    )
    def test_a_name_that_starts_with_dots_and_a_mark_is_masked_whole(
        self, written: str, after: str
    ) -> None:
        assert host_paths_masked(f"see {written}{after}") == f"see {OUTSIDE_PROJECT}{after}"

    def test_escaped_json_prose_after_a_path_is_kept(self) -> None:
        # ``json.dumps`` writes each accented letter as an escape; the words
        # after a path are prose however many of them start with one.
        prose = "\u00e9t\u00e9 " + " ".join(["\u00e9l\u00e8ve"] * 50) + " \u00c7al\u0131\u015fma"
        written = json.dumps({"m": f"error C:\\Users\\bob\\a.txt {prose}"})
        assert "\\u00e9" in written
        assert json.loads(host_paths_masked(written)) == {"m": f"error {OUTSIDE_PROJECT} {prose}"}

    @pytest.mark.parametrize(
        "path",
        [
            "C:\\Users\\John \u00e9mile\\x",
            "C:\\Users\\\u00e9mile\\\u00e9t\u00e9\\x",
            "C:/Users/\u00e9 \u00e9/\u00e9x",
            "C:\\ubeef\\ucafe\\x",
        ],
    )
    def test_an_escaped_name_inside_a_path_is_masked_with_it(self, path: str) -> None:
        written = json.dumps({"m": f"open {path}: denied"})
        assert json.loads(host_paths_masked(written)) == {"m": f"open {OUTSIDE_PROJECT}: denied"}

    @pytest.mark.parametrize(
        "path",
        ["\\\\srv\\share\\alice\\x y", "C:\\Users\\alice\\x y", "\\\\?\\C:\\Users\\alice\\x"],
    )
    def test_a_repr_of_an_error_s_words_hides_the_path_too(self, path: str) -> None:
        # An error's words hold its file name's repr; a repr of those words
        # doubles every backslash again.
        error = OSError(2, "No such file or directory", path)
        for written in (repr(str(error)), repr(repr(str(error))), json.dumps(repr(str(error)))):
            said = host_paths_masked(written)
            assert "alice" not in said and "srv" not in said, said

    @pytest.mark.parametrize(
        "written",
        [
            "C:\\Users\\John Smith\\ucafe.txt",
            "C:\\Users\\John Smith\\uabcd1\\notes",
            "\\\\srv\\u1234",
            "\\\\srv\\sh\\a b\\u9575x",
            "\\\\?\\UNC\\srv\\sh\\John Smith\\ud55Ex",
            "\\\\.\\pipe\\a b\\uB1F5x\\ua7ef.txt",
        ],
    )
    def test_a_name_that_reads_like_an_escape_is_a_name_in_a_path_written_as_it_is(
        self, written: str
    ) -> None:
        # One backslash between names: the text is not escaped, so ``\uabcd``
        # is a separator and a name, and the directory before it keeps its space.
        assert host_paths_masked(f"open {written} denied") == f"open {OUTSIDE_PROJECT} denied"

    def test_the_home_directory_before_such_a_name_is_still_one_path(self) -> None:
        home = PureWindowsPath(r"C:\Users\John Smith")
        said = host_paths_masked("open C:\\Users\\John Smith\\u1234 x", Path(r"D:\proj"), home)
        assert said == f"open {OUTSIDE_PROJECT} x"

    @pytest.mark.parametrize(
        "text",
        [
            # a repr of a JSON string, a repr of a repr, JSON in JSON
            repr(json.dumps({"m": "open C:/Users/alice/'b/AppData x"})),
            repr(repr("open file:///C:/Users/alice/'b/c d\u00e9 x")),
            json.dumps({"m": json.dumps({"m": "open C:/d/\u201dx.alice/\u0143\u01ddbob/share x"})}),
            json.dumps({"m": repr("open C:\\Users\\\u00e9 alice\\x: denied")}),
            json.dumps({"e": "cannot open \\\\\\\\srv\\\\share\\\\a \u65e5 b\\\\alice"}),
            json.dumps({"e": "cannot open \\\\\u00e9tage\\share\\alice x"}),
            json.dumps({"e": json.dumps("cannot open \\\\\u00e9tage\\share\\alice x")}),
        ],
    )
    def test_a_path_escaped_more_than_once_is_masked_whole(self, text: str) -> None:
        said = host_paths_masked(text)
        assert "alice" not in said and "bob" not in said, said

    @pytest.mark.parametrize("space", ["\u00a0", "\u2009", "\u202f"])
    def test_a_name_may_start_or_end_with_a_space_that_is_not_ascii(self, space: str) -> None:
        for written in (f"C:/Users/qxa{space}/qxb/x", f"C:\\Users\\{space}qxa\\{space}qxb"):
            assert host_paths_masked(f"see {written} end") == f"see {OUTSIDE_PROJECT} end"

    def test_a_json_document_is_read_as_the_words_it_writes(self) -> None:
        # Each string is read through its escapes and written back the same
        # way: the path is masked whole, the words and lines after it stay,
        # and what the document's other strings write is as it was.
        written = json.dumps(
            {
                "level": 3,
                "msg": (
                    "capa failed reading C:\\work\\John Smith\\s.bin with three words"
                    "\nsecond line\nétage"
                ),
                "joined": "open C:/Users/alice\\John Smith\\Émile.txt failed",
                "note": "café /api/v1/jobs",
            }
        )
        said = host_paths_masked(written)
        assert json.loads(said) == {
            "level": 3,
            "msg": f"capa failed reading {OUTSIDE_PROJECT} with three words\nsecond line\nétage",
            "joined": f"open {OUTSIDE_PROJECT} failed",
            "note": "café /api/v1/jobs",
        }
        assert '"note": "caf\\u00e9 /api/v1/jobs"' in said and '"level": 3' in said

    def test_a_json_document_keeps_how_it_writes_what_is_not_ascii(self) -> None:
        written = json.dumps({"p": "open C:\\Users\\Élodie Martin\\x: refusé"}, ensure_ascii=False)
        assert host_paths_masked(written) == json.dumps(
            {"p": f"open {OUTSIDE_PROJECT}: refusé"}, ensure_ascii=False
        )

    def test_a_json_key_and_a_slash_written_escaped_are_read_too(self) -> None:
        said = host_paths_masked(json.dumps({"C:\\Users\\alice\\x y": 1}))
        assert json.loads(said) == {OUTSIDE_PROJECT: 1}
        escaped = json.dumps({"m": "open C:/Users/alice/AppData/x.txt now"}).replace("/", "\\/")
        assert json.loads(host_paths_masked(escaped)) == {"m": f"open {OUTSIDE_PROJECT} now"}

    def test_half_a_surrogate_pair_a_json_string_writes_stays_escaped(self) -> None:
        # The masked document is stored as UTF-8, which holds no lone half.
        for words in ("é", "e"):
            written = '{"s": "' + words + ' \\ud83d C:\\\\Users\\\\bob"}'
            said = host_paths_masked(written)
            assert said == '{"s": "' + words + f' \\ud83d {OUTSIDE_PROJECT}"' + "}"
            assert said.encode("utf-8")

    def test_a_path_written_as_it_is_beside_an_escaped_one_in_a_json_string(self) -> None:
        # ``D:\new\report.txt`` in a string that escapes its other path: the
        # string writes a line break there, and the words in it are a path.
        for raw in ("D:\\new\\report.txt", "path:D:\\table\\bob.txt", "D:\\u00e9t\\u00e9\\ray.txt"):
            written = '{"m": "x C:\\\\Users\\\\alice and ' + raw + '"}'
            said = host_paths_masked(written)
            assert not re.search(r"alice|report|bob|ray", said), said
            assert json.loads(said)
        # A string that writes every path escaped keeps the other words it writes.
        kept = json.dumps({"m": "open C:\\Users\\alice: see \\d+\\s in the rule"})
        assert json.loads(host_paths_masked(kept)) == {
            "m": f"open {OUTSIDE_PROJECT}: see \\d+\\s in the rule"
        }

    @pytest.mark.parametrize(
        ("written", "said"),
        [
            # a path that ends on the backslash writing a quote; beside an
            # escaped path, a drive before a quote is the words the string writes
            (r'{"m": "set x:\"1\" now"}', {"m": f'set {OUTSIDE_PROJECT}"1" now'}),
            (
                r'{"m": "x C:\\a\\b and D:\"q\" z"}',
                {"m": f'x {OUTSIDE_PROJECT} and D:"q" z'},
            ),
            (
                r'["D:\\", "x:\"", "\\\\srv\\"]',
                [OUTSIDE_PROJECT, f'{OUTSIDE_PROJECT}"', OUTSIDE_PROJECT],
            ),
            (r'"x:\"1\" C:\\Users\\alice"', f'{OUTSIDE_PROJECT}"1" {OUTSIDE_PROJECT}'),
            # a drive named in quotes is no path written as it is
            (
                r'{"m": "drive \"C:\" is full, see D:\\logs\\x.txt"}',
                {"m": f'drive "C:" is full, see {OUTSIDE_PROJECT}'},
            ),
            (r'{"m": "drive \"C:\" is full"}', {"m": f'drive "{OUTSIDE_PROJECT}" is full'}),
        ],
    )
    def test_a_json_string_read_as_it_stands_is_still_that_string(
        self, written: str, said: object
    ) -> None:
        assert json.loads(host_paths_masked(written)) == said

    def test_a_document_written_inside_a_document_is_read_through(self) -> None:
        inner = {"m": "tool failed: \\\\?\\C:\\long\\alice (exit 1) — réessayez plus tard, café"}
        said = host_paths_masked(json.dumps({"m": json.dumps(inner)}))
        assert json.loads(json.loads(said)["m"]) == {
            "m": f"tool failed: {OUTSIDE_PROJECT} (exit 1) — réessayez plus tard, café"
        }
        deep = "open C:\\Users\\alice bob\\x: denied"
        for _ in range(6):
            deep = json.dumps(deep)
        assert "alice" not in host_paths_masked(deep)

    def test_a_repr_is_read_as_the_words_it_writes(self) -> None:
        words = (
            "capa failed reading C:\\work\\John Smith\\s.bin with three words"
            "\nsecond line, it's étage"
        )
        assert host_paths_masked(repr(words)) == repr(
            f"capa failed reading {OUTSIDE_PROJECT} with three words\nsecond line, it's étage"
        )
        # A repr of that repr writes the line break as two backslashes and
        # ``n``, which also read as a path's head; the path itself is gone.
        twice = host_paths_masked(repr(repr(words)))
        assert "work" not in twice and "Smith" not in twice and "s.bin" not in twice

    @pytest.mark.parametrize(
        "written",
        [
            # words in quotes that also parse as an escaped string
            '"open C:\\new\\table.txt now"',
            "'open C:\\new\\table.txt now'",
            '{"error": "open C:\\new\\table.txt now"}',
            '"\\\\srv/share/alice and file:////srv/share/bob"',
            "'\\\\srv\\share\\alice and D:\\x\\bob'",
            "'see C:\\\\real\\\\alice y and C:\\new\\bob z'",
        ],
    )
    def test_words_in_quotes_that_read_as_an_escaped_string_are_read_both_ways(
        self, written: str
    ) -> None:
        said = host_paths_masked(written)
        assert not re.search(r"table|alice|bob|share", said), said

    def test_a_json_document_is_masked_in_linear_time(self) -> None:
        def document(count: int) -> str:
            return json.dumps(
                {
                    **{f"k{n}": "open C:\\Users\\alice b\\x y: no" for n in range(count)},
                    "prose": "C:\\work\\s.bin " + "été crème\n" * count,
                    "inner": json.dumps({"m": "D:\\x\\y " + "word " * count}),
                }
            )

        def brackets(count: int) -> str:
            return "[" * count + '"C:\\\\x"' + "]" * count

        assert "alice" not in host_paths_masked(document(3))
        for text in (document, brackets, lambda count: repr(document(count))):
            # The least count whose text costs a measurable time; only the
            # ratio is asserted.
            count = 200
            while cpu_seconds(partial(host_paths_masked, text(count)), repeats=3) < 0.005:
                count *= 2
            assert_scales(text, count, host_paths_masked, factor=4)

    @pytest.mark.parametrize(
        "text",
        [
            lambda count: "x 'C:" + "\\" * count + "' y",
            lambda count: 'x "C:' + "\\" * count + '" y',
            lambda count: json.dumps({"m": "x 'C:" + "\\" * count + "' y"}),
            lambda count: "x '" + "\\" * count + "srv\\share' y",
            lambda count: "x 'C:" + "\\\\a" * count + "' y",
        ],
    )
    def test_a_quoted_run_of_backslashes_is_masked_in_linear_time(
        self, text: Callable[[int], str]
    ) -> None:
        # The least count whose text costs a measurable time; only the ratio
        # is asserted.
        count = 1_000
        while cpu_seconds(partial(host_paths_masked, text(count)), repeats=3) < 0.005:
            count *= 2
        assert_scales(text, count, host_paths_masked, factor=4)

    @pytest.mark.parametrize(
        "directory",
        [
            "Jane Word1 Word2 Word3 Word4 Word5 Word6 Word7 Word8 Word9",
            "Jane  Doe",
            "Copy of Copy of My Documents backup from old laptop 2019 (2)",
            "a  b   c\u00a0\u00a0d e f g h i j k l m",
        ],
    )
    def test_a_directory_s_name_holds_its_spaces_however_many(self, directory: str) -> None:
        for separator in ("\\", "\\\\", "/"):
            heads = ["C:"] if separator == "/" else ["C:", f"{separator * 2}srv{separator}share"]
            for head in heads:
                written = separator.join((head, "Users", directory, "secret.txt"))
                assert host_paths_masked(f"open {written} failed") == (
                    f"open {OUTSIDE_PROJECT} failed"
                ), written

    @pytest.mark.parametrize(
        "text",
        [
            lambda count: "open C:\\a" + " w" * count,
            lambda count: ("open C:\\a" + " w" * 40 + " ") * count,
            lambda count: ("open C:\\a" + " w" * 40 + "/") * count,
            lambda count: "open \\\\srv\\share\\a" + "  w" * count + " 'C:\\\\a" + " w" * count,
            lambda count: json.dumps({"m": "open C:\\a" + " w" * count}),
        ],
    )
    def test_the_words_after_a_path_are_read_in_linear_time(
        self, text: Callable[[int], str]
    ) -> None:
        # The least count whose text costs a measurable time; only the ratio
        # is asserted.
        count = 1_000
        while cpu_seconds(partial(host_paths_masked, text(count)), repeats=3) < 0.005:
            count *= 2
        assert_scales(text, count, host_paths_masked, factor=4)

    def test_any_space_windows_allows_in_a_name_is_inside_it(self) -> None:
        for space in " \u00a0\u1680\u2009\u3000":
            said = host_paths_masked(f"see C:\\Users\\qxa{space}qxb\\tailqxc end")
            assert said == f"see {OUTSIDE_PROJECT} end", repr(space)

    def test_masked_json_still_reads_as_json(self) -> None:
        for message in (
            'open "C:\\Users\\a b\\x": denied',
            "cannot open C:\\Users\\John Smith\\x",
            "cannot open C:\\Users\\alice\\",
            'open "\\\\srv\\share\\alice\\": denied',
        ):
            said = json.loads(host_paths_masked(json.dumps({"msg": message})))
            assert "alice" not in said["msg"] and "Users" not in said["msg"]
        said = host_paths_masked(json.dumps({"msg": 'open "C:\\Users\\a b\\x": denied'}))
        assert json.loads(said) == {"msg": f'open "{OUTSIDE_PROJECT}": denied'}

    def test_a_path_of_many_parts_is_masked_in_linear_time(self) -> None:
        root = Path(r"D:\proj")

        def text(parts: int) -> str:
            return (
                "/a" * parts
                + " | D:\\proj"
                + "\\a" * parts
                + " | '\\\\s"
                + "\\a b" * parts
                + "' | 'C:\\x"
                + "\\" * parts
                + "x'\n'C:\\x"
                + "\\" * parts
                + "x\n'\\\\a"
                + "\\" * parts
            )

        assert host_paths_masked(text(3), root) == (
            f"/a/a/a | a/a/a | '{OUTSIDE_PROJECT}' | '{OUTSIDE_PROJECT}'\n'{OUTSIDE_PROJECT}"
            "\n'\\\\a\\\\\\"
        )
        assert_scales(text, 5_000, lambda written: host_paths_masked(written, root), factor=4)

    @pytest.mark.parametrize(
        "unit",
        [
            "\\",
            "a ",
            "C:\\a b\\",
            "'",
            '"',
            "`",
            "\u2018",
            "\u2018C:\\a ",
            "'C:\\a ",
            "\\\\s\\a b",
            "C:\\Users\\Jane Doe ",
            "/home/Jane Doe ",
            "\u00e9\u65e5\u2013\u20ac\u00a9\u0301\U0001f600",
            ".",
            ".x",
            "...(",
            "/\\u00e9",
            " \\u00e9",
            "\\u00e9",
            "\\u00e9\\\\",
            "a\u1680",
            "'file:///C:/a b' ",
            "file:///C:/a b/",
        ],
    )
    def test_a_hostile_text_is_masked_in_linear_time(self, unit: str) -> None:
        """Every reader of a path costs time linear in the text, whatever it repeats."""
        root = Path(r"D:\proj")
        homes = (PureWindowsPath(r"C:\Users\Jane Doe"), PurePosixPath("/home/Jane Doe"))

        def text(count: int) -> str:
            return "read C:\\x\\" + unit * count + " then 'C:\\x" + unit * count

        for home in homes:

            def masked(written: str, home: PurePath = home) -> str:
                return host_paths_masked(written, root, home)

            # The least count whose text costs a measurable time; only the
            # ratio is asserted.
            count = 1_000
            while cpu_seconds(partial(masked, text(count)), repeats=3) < 0.005 and count < 1 << 22:
                count *= 2
            assert_scales(text, count, masked, factor=4)

    def test_the_home_directory_is_one_path_whatever_its_name_holds(self) -> None:
        root = Path(r"C:\Users\Jane Doe\proj")
        home = PureWindowsPath(r"C:\Users\Jane Doe")
        for written in (
            r"C:\Users\Jane Doe",
            r"C:\\Users\\Jane Doe",
            "C:/Users/Jane Doe",
            r"c:\users\JANE DOE",
            r"\\?\C:\Users\Jane Doe",
            r"C:\Users\Jane Doe\AppData\Local",
        ):
            for after in ("", " then", ": denied", ")."):
                said = host_paths_masked(f"cwd: {written}{after}", root, home)
                assert said == f"cwd: {OUTSIDE_PROJECT}{after}", written
        said = host_paths_masked(r"at C:\Users\Jane Doe\proj\data\x then", root, home)
        assert said == "at data/x then"
        said = host_paths_masked(
            json.dumps({"cwd": r"C:\Users\Jane Doe", "at": r"C:\Users\Jane Doe\proj\x"}),
            root,
            home,
        )
        assert json.loads(said) == {"cwd": OUTSIDE_PROJECT, "at": "x"}

    def test_a_posix_home_directory_is_one_path_too(self) -> None:
        root = PurePosixPath("/home/Jane Doe/proj")
        home = PurePosixPath("/home/Jane Doe")
        said = host_paths_masked(
            "cwd: /home/Jane Doe, rules at /home/Jane Doe/proj/data/x and /home/Jane Doe/r.yml",
            root,  # type: ignore[arg-type]
            home,
        )
        assert said == f"cwd: {OUTSIDE_PROJECT}, rules at data/x and {OUTSIDE_PROJECT}"
        # The home's name is a whole name: a longer one is another path.
        assert host_paths_masked("/home/Jane Does", root, home) == (  # type: ignore[arg-type]
            host_paths_masked("/home/Jane Does", root, PurePosixPath("/home/other"))  # type: ignore[arg-type]
        )

    def test_the_real_home_directory_is_the_default(self) -> None:
        home = Path.home()
        assert host_paths_masked(f"cwd: {home}") == f"cwd: {OUTSIDE_PROJECT}"

    def test_a_path_a_caller_holds_is_shown_from_the_project_as_one_path(self) -> None:
        root = PurePosixPath("/home/op/proj")
        for path, said in (
            ("/home/op/proj/data/capa rules (old)", "data/capa rules (old)"),
            ("/home/op/proj/data/capa-rules", "data/capa-rules"),
        ):
            assert host_path_masked(path, root) == said, path
        windows = Path(r"D:\a\proj")
        assert host_path_masked(r"D:\a\proj\data\capa rules", windows) == "data/capa rules"
        assert host_path_masked(r"d:\A\PROJ\data\x", windows) == "data/x"
        assert host_path_masked(PureWindowsPath(r"D:\a\proj\data\x"), windows) == "data/x"

    @pytest.mark.parametrize(
        "path",
        [
            "/data/capa-rules",
            "/x",
            "/home/op/proj",
            "/home/Jane Doe",
            "/home/Jane Doe/capa rules",
            "/srv/a(1)/b",
            "~",
            "~/x",
            "~jane/capa-rules",
            r"C:\Users\Jane Doe",
            r"c:\users\jane doe\capa rules",
            r"D:\a\proj",
            r"D:\a\proj2\x",
            "E:/data/x",
            r"\\server\share\Jane Doe",
            r"\\?\C:\Users\Jane Doe\x",
        ],
    )
    def test_any_other_absolute_path_a_caller_holds_is_masked(self, path: str) -> None:
        for root in (PurePosixPath("/home/op/proj"), PureWindowsPath(r"D:\a\proj")):
            assert host_path_masked(path, root) == OUTSIDE_PROJECT

    @pytest.mark.parametrize("path", ["data/capa-rules", "./rules", "rules x/y", "a~b/c"])
    def test_a_relative_path_a_caller_holds_is_kept(self, path: str) -> None:
        assert host_path_masked(path, PurePosixPath("/home/op/proj")) == path

    def test_a_long_path_or_unc_root_is_the_same_root(self) -> None:
        said = host_paths_masked(
            r"at D:\a\Malspark\Malspark\data\x and \\?\D:\\a\\Malspark\\Malspark\\data\\y",
            Path(r"\\?\D:\a\Malspark\Malspark"),
        )
        assert said == "at data/x and data/y"
        unc = Path(r"\\fs\share\Malspark")
        said = host_paths_masked(
            r"at \\fs\share\Malspark\data\x, \\\\fs\\share\\Malspark\\data\\y,"
            r" \\?\UNC\fs\share\Malspark\data\z and \\fs\share\other",
            unc,
        )
        assert said == f"at data/x, data/y, data/z and {OUTSIDE_PROJECT}"

    def test_a_windows_project_s_paths_read_as_a_posix_project_s(self) -> None:
        root = Path("D:\\a\\Malspark\\Malspark")
        said = host_paths_masked(
            "rules at D:\\a\\Malspark\\Malspark/data/capa-rules,"
            " d:\\a\\malspark\\malspark\\data\\x,"
            " file:///D:/a/Malspark/Malspark/data/sigma_rules, D:\\a\\other and /srv/r",
            root,
        )
        assert said == (
            f"rules at data/capa-rules, data/x, data/sigma_rules, {OUTSIDE_PROJECT} and "
            f"{OUTSIDE_PROJECT}"
        )
        assert host_paths_masked("GET /api/v1/jobs failed", root) == "GET /api/v1/jobs failed"

    def test_the_run_summary_keeps_them_and_leaves_them_out_when_none(self) -> None:
        rows = [{"tool": "capa", "reason": "x"}]
        with_rows = RunSummaryBuilder(start_time=0.0).set_lost_tools(rows).build().to_dict()
        assert with_rows["lost_tools"] == rows
        assert "lost_tools" not in RunSummaryBuilder(start_time=0.0).build().to_dict()


class TestTheReportSaysItDidNotRun:
    def test_the_scope_says_what_the_run_went_without_and_why(self) -> None:
        assert (
            "The run went without sigma_match_sandbox (no rule was loaded from "
            "data/sigma_rules, which is missing or holds none, so no rule was run)."
        ) in _scope(_degraded_report())

    def test_a_run_that_is_not_degraded_says_nothing_of_it(self) -> None:
        report = _degraded_report()
        report.degraded_mode = False
        assert "went without" not in _scope(report)

    def test_a_tools_words_are_escaped_and_defanged(self) -> None:
        probe = "[click](http://evil.example/x) <img onerror=alert(1)> **bold**"
        scope = _scope(_degraded_report(probe))
        assert (
            "The run went without sigma_match_sandbox (\\[click\\](hxxp://evil[.]example/x) "
            "\\<img onerror=alert(1)\\> \\*\\*bold\\*\\*)."
        ) in scope
        # Nothing of it reads as a link, a tag or emphasis.
        assert not re.search(r"(?<!\\)\[click(?<!\\)\]\(", scope)
        assert not re.search(r"(?<!\\)<img", scope)
        assert not re.search(r"(?<!\\)\*\*bold", scope)

    def test_a_stored_run_renders_the_same_on_any_host(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The reason was masked when written; rendering reads no host and no project root."""
        from malspark.core import paths

        report = _degraded_report("rules at /srv/run-hk8/data/capa-rules are missing")
        here = MarkdownRenderer(layout=ANALYST).render(report)
        for root in (tmp_path, Path("/srv/run-hk8")):
            monkeypatch.setattr(paths, "get_project_root", lambda root=root: root)
            assert MarkdownRenderer(layout=ANALYST).render(report) == here
        assert "rules at /srv/run-hk8/data/capa-rules are missing" in _scope(report)

    def test_a_stored_run_renders_byte_for_byte_as_it_did(self) -> None:
        """A summary written before ``lost_tools`` says nothing new (haiku8's shape)."""
        stored = json.loads((FIXTURES / "stored_degraded_run.json").read_text(encoding="utf-8"))
        before = json.loads(
            (FIXTURES / "stored_degraded_run.rendered_on_dev.json").read_text(encoding="utf-8")
        )
        report = MalwareReport.model_validate(stored)
        assert MarkdownRenderer(layout=ANALYST).render(report) == before["analyst"]
        assert MarkdownRenderer().render(report) == before["full"]


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Every library and FLOSS present, and every corpus but Sigma's, under a root of its own."""
    monkeypatch.setattr(capabilities, "_data_root", lambda: tmp_path)
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: object())
    monkeypatch.setattr(emulated_strings, "find_floss", lambda environ=None: ("floss", ""))
    monkeypatch.delenv(rules.SIGMA_RULES_ENV, raising=False)
    (tmp_path / "data" / "capa-rules").mkdir(parents=True)
    (tmp_path / "data" / "capa-rules" / "r.yml").write_text("rule:\n", encoding="utf-8")
    (tmp_path / "data" / "yara_ttp_rules.yaml").write_text(YARA_RULES, encoding="utf-8")
    return tmp_path


def _named(settings: Settings) -> list[tuple[str, str]]:
    return [(row["server"], row["tool"]) for row in as_rows(unavailable_tools(settings))]


class TestTheCheckBeforeAJobNamesIt:
    """With the real ``Settings()``: the step runs in the worker whatever the block says."""

    def test_the_in_process_pass_is_named_with_the_server_switched_off(self, host: Path) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        rows = as_rows(unavailable_tools(settings))
        assert [(r["server"], r["tool"]) for r in rows] == [("pipeline", "sigma_match_sandbox")]
        (row,) = rows
        assert row["reason"] == "data/sigma_rules is missing or empty (named by the default)"
        assert row["remediation"] == sidecar_needs.SIGMA_RULES.remedy
        assert row["manifest_code"] == MISSING_DEPENDENCY
        assert row["still_answers"] == ""

    def test_it_is_named_beside_a_server_with_its_own_import_path(self, host: Path) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].env = {"PYTHONPATH": "/opt/libs"}
        assert _named(settings) == [("pipeline", "sigma_match_sandbox")]

    def test_the_server_and_the_worker_are_each_named_where_each_reads(self, host: Path) -> None:
        found = unavailable_tools(Settings())
        assert [(u.server, u.tool) for u in found] == [
            ("analysis", "sigma_match"),
            ("analysis", "sigma_match_sandbox"),
            ("pipeline", "sigma_match_sandbox"),
        ]
        # The same lack and remedy in two places is one row naming both.
        assert _named(Settings()) == [
            ("analysis", "sigma_match"),
            ("analysis, pipeline", "sigma_match_sandbox"),
        ]

    def test_rows_that_differ_stay_apart(self) -> None:
        from malspark.tools.capabilities import Unavailable

        def row(server: str, reason: str, remedy: str = "fetch it") -> Unavailable:
            return Unavailable(server=server, tool="t", reason=reason, remediation=remedy)

        rows = as_rows(
            [row("a", "gone"), row("b", "gone"), row("c", "empty"), row("d", "gone", "x")]
        )
        assert [(r["server"], r["reason"], r["remediation"]) for r in rows] == [
            ("a, b", "gone", "fetch it"),
            ("c", "empty", "fetch it"),
            ("d", "gone", "x"),
        ]
        assert rows[0]["degradation_reason"] == (
            "server.a.t_unavailable(gone); fetch it; server.b.t_unavailable(gone); fetch it"
        )

    def test_the_workers_label_is_the_server_its_entries_are_recorded_under(self) -> None:
        assert WORKER == PIPELINE

    def test_a_corpus_in_place_names_nothing(self, host: Path) -> None:
        (host / "data" / "sigma_rules").mkdir()
        (host / "data" / "sigma_rules" / "r.yml").write_text(SIGMA_RULE, encoding="utf-8")
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        assert _named(settings) == []
        assert _named(Settings()) == []

    def test_the_step_switched_off_is_not_named(self, host: Path) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        settings.triage.steps = [{"id": "sigma_match_sandbox", "enabled": False}]
        assert _named(settings) == []

    def test_a_yara_override_naming_nothing_is_named_and_says_nothing_still_answers(
        self, host: Path
    ) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].env = {rules.YARA_RULES_ENV: "data/none"}
        (host / "data" / "sigma_rules").mkdir()
        (host / "data" / "sigma_rules" / "r.yml").write_text(SIGMA_RULE, encoding="utf-8")
        (row,) = as_rows(unavailable_tools(settings))
        assert (row["server"], row["tool"]) == ("analysis", "yara_scan")
        assert row["reason"] == "data/none is missing or empty (named by MALSPARK_YARA_RULES_DIR)"
        assert row["still_answers"] == ""
