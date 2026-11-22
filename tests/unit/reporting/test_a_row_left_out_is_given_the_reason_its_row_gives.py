"""A row the analyst report leaves out of a table is given the reason its own row gives (T-844).

The analyst report leaves out a table row that carries a finding (the bundle prints it with
the finding's mark) and a row whose text is the text of a sentence a check left a finding on
elsewhere (the bundle prints that row with no mark). The line under the table says a check
left a finding on a row only where the row carries one; a row left out for its text alone is
said to be so, and the bundle is not said to give a reason it does not print.
"""

from __future__ import annotations

import re
from pathlib import Path

from malspark.reporting.models import (
    CliFlag,
    CommandRow,
    ConfigItem,
    FileHashes,
    FlaggedStatement,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.analyst import _left_out_rows
from malspark.reporting.renderers.layout import ANALYST, BUNDLE

ROOT = Path(__file__).resolve().parents[3]


def _report(
    *,
    commands: list[CommandRow] | None = None,
    flags: list[CliFlag] | None = None,
    configuration: list[ConfigItem] | None = None,
    identifiers: list[HostIdentifier] | None = None,
    flagged: list[FlaggedStatement] | None = None,
) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="s.exe"),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            commands=commands or [],
            cli_flags=flags or [],
            configuration=configuration or [],
            host_identifiers=identifiers or [],
        ),
        flagged_statements=flagged or [],
    )


# A finding a check left on a configuration row's value under the ids that row cites: the
# row carries it; another row with the same text under other ids does not.
_ON_CONFIG = FlaggedStatement(
    sentence="--fast [ev_0006]",
    code="report.citation_wrong_entry",
    label='"--fast" was not found whole in ev_0006',
)


def _section(markdown: str, heading: str) -> str:
    return markdown.split(heading, 1)[1].split("\n### ", 1)[0].split("\n## ", 1)[0]


def _left_lines(markdown: str) -> list[str]:
    return re.findall(r"^\d+ further [a-z ]+ rows? (?:is|are) not printed here.*$", markdown, re.M)


class TestTheWordsOfEachForm:
    def test_rows_that_each_carry_a_finding(self) -> None:
        assert _left_out_rows(1, 0, "command row") == (
            "1 further command row is not printed here: a check left a finding on it; the "
            "bundle lists it with the reason."
        )
        assert _left_out_rows(3, 0, "flag row") == (
            "3 further flag rows are not printed here: a check left a finding on each; the "
            "bundle lists each with the reason."
        )

    def test_rows_left_out_for_their_text_alone(self) -> None:
        assert _left_out_rows(0, 1, "command row") == (
            "1 further command row is not printed here: its text is that of a statement a "
            "check left a finding on, and the row itself carries none; the bundle lists it."
        )
        assert _left_out_rows(0, 2, "flag row") == (
            "2 further flag rows are not printed here: the text of each is that of a "
            "statement a check left a finding on, and none of these rows carries one itself; "
            "the bundle lists each."
        )

    def test_rows_of_both_kinds(self) -> None:
        assert _left_out_rows(1, 1, "configuration row") == (
            "2 further configuration rows are not printed here. A check left a finding on 1 "
            "of them, and the bundle lists it with the reason. The other one's text is that "
            "of a statement a check left a finding on, and that row carries none itself; the "
            "bundle lists it."
        )
        assert _left_out_rows(2, 3, "host identifier row") == (
            "5 further host identifier rows are not printed here. A check left a finding on 2 "
            "of them, and the bundle lists each with the reason. The text of each of the "
            "other 3 is that of a statement a check left a finding on, and none of those rows "
            "carries one itself; the bundle lists each."
        )


class TestTheLineIsTrueOfTheRows:
    def test_a_command_and_a_flag_row_matched_by_text_carry_no_finding(self) -> None:
        report = _report(
            configuration=[ConfigItem(key="Mode flag", value="--fast", evidence_refs=["ev_0006"])],
            commands=[
                CommandRow(id="--fast", name="fast", evidence_refs=["ev_0034"]),
                CommandRow(id="--full", name="full", evidence_refs=["ev_0034"]),
            ],
            flags=[
                CliFlag(flag="--fast", description="Sets the ratio.", evidence_ref="ev_0089"),
                CliFlag(flag="--full", description="Full scope.", evidence_ref="ev_0089"),
            ],
            flagged=[_ON_CONFIG],
        )
        analyst = MarkdownRenderer(layout=ANALYST).render(report)
        assert _left_lines(analyst) == [
            "1 further configuration row is not printed here: a check left a finding on it; "
            "the bundle lists it with the reason.",
            "1 further command row is not printed here: its text is that of a statement a "
            "check left a finding on, and the row itself carries none; the bundle lists it.",
            "1 further flag row is not printed here: its text is that of a statement a check "
            "left a finding on, and the row itself carries none; the bundle lists it.",
        ]
        # The bundle prints the configuration row with the finding's mark, and the command
        # and flag rows with none.
        bundle = MarkdownRenderer(layout=BUNDLE).render(report)
        config_row = next(
            ln for ln in _section(bundle, "Configuration").splitlines() if "Mode flag" in ln
        )
        assert "cited to an entry it was not found whole in" in config_row
        commands = _section(bundle, "Commands and capabilities")
        command_row = next(ln for ln in commands.splitlines() if ln.startswith("| --fast"))
        flag_row = next(ln for ln in commands.splitlines() if ln.startswith("| `--fast`"))
        assert "**[" not in command_row and "**[" not in flag_row

    def test_a_row_that_carries_the_finding_under_its_own_citations(self) -> None:
        report = _report(
            commands=[
                CommandRow(id="--fast", name="fast", evidence_refs=["ev_0006"]),
                CommandRow(id="--fast", name="fast", evidence_refs=["ev_0034"]),
                CommandRow(id="--full", name="full", evidence_refs=["ev_0034"]),
            ],
            flagged=[_ON_CONFIG],
        )
        analyst = MarkdownRenderer(layout=ANALYST).render(report)
        assert _left_lines(analyst) == [
            "2 further command rows are not printed here. A check left a finding on 1 of "
            "them, and the bundle lists it with the reason. The other one's text is that of "
            "a statement a check left a finding on, and that row carries none itself; the "
            "bundle lists it."
        ]
        bundle = MarkdownRenderer(layout=BUNDLE).render(report)
        rows = [ln for ln in bundle.splitlines() if ln.startswith("| --fast")]
        assert len(rows) == 2
        assert "**[" in rows[0] and "ev_0006" in rows[0]
        assert "**[" not in rows[1]

    def test_rows_named_by_a_finding_s_number_carry_it(self) -> None:
        report = _report(
            identifiers=[
                HostIdentifier(kind="Mutex", value="gate-one", purpose="a gate"),
                HostIdentifier(
                    kind="Mutex", value="--fast", purpose="a gate", evidence_refs=["ev_0034"]
                ),
            ],
            flagged=[_ON_CONFIG],
        )
        report.run_summary = {
            "validation": {
                "unresolved": [
                    {"code": "report.identifier_uncited", "message": "identifier 1 cites nothing"}
                ]
            }
        }
        analyst = MarkdownRenderer(layout=ANALYST).render(report)
        assert _left_lines(analyst) == [
            "2 further host identifier rows are not printed here. A check left a finding on 1 "
            "of them, and the bundle lists it with the reason. The other one's text is that "
            "of a statement a check left a finding on, and that row carries none itself; the "
            "bundle lists it."
        ]

    def test_a_flagged_sentence_standing_in_a_cell_the_bundle_marks_is_carried(self) -> None:
        report = _report(
            configuration=[
                ConfigItem(key="sleep", value="450 s", evidence_refs=["ev_0003"]),
                ConfigItem(key="jitter", value="10 s", evidence_refs=["ev_0003"]),
            ],
            flagged=[FlaggedStatement(sentence="450 s", code="narrative.claim_doubted")],
        )
        analyst = MarkdownRenderer(layout=ANALYST).render(report)
        assert _left_lines(analyst) == [
            "1 further configuration row is not printed here: a check left a finding on it; "
            "the bundle lists it with the reason."
        ]


def test_no_model_reads_the_line() -> None:
    """The line is written by the analyst report's renderer only: no module of the pipeline,
    the agents, the prompts or the model-facing reporting code names it."""
    readers = sorted(
        str(path.relative_to(ROOT))
        for path in (ROOT / "src").rglob("*.py")
        if "_left_out_rows" in path.read_text(encoding="utf-8")
    )
    assert readers == ["src/malspark/reporting/renderers/analyst.py"]
