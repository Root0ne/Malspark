"""A flagged text is left out only where it stands whole, and each section counts its own (T-706).

A citation check flags a table row whose value its cited entry lacks, and the row's text is
stored as the flagged "sentence" ("--path [ev_0048]"). The analyst report left a flagged
sentence out wherever its text stood, by substring search: the value was cut out of every
sentence naming it ("--shares or." , "the literal 'C:\\Windows\\Prefetch\\*.*'" for
"'del /f /q C:\\...'"), so prose broke and a value the report holds was printed nowhere.
And the line "N sentences of this section were left out" counted each such cut as a
sentence, while the bullets, cells and section 5 sentences the agreement question left out
were counted nowhere, so a summary that lost bullets said nothing.

A flagged text is now left out only where it is a whole sentence or the whole of a field (a
table cell); a sentence that names it stands as written, the row being the bundle's. The
line of each section counts the whole sentences, bullets and cell sentences left out of it
as printed, and nothing else. The values quote one stored run's rows as examples; the
second shape is made up.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from malspark.reporting.models import (
    C2Channel,
    CapabilityBullet,
    CliFlag,
    FileHashes,
    FlaggedStatement,
    KeyFinding,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.renderers.layout import ANALYST
from malspark.reporting.renderers.markdown import MarkdownRenderer

WRONG_ENTRY = "report.citation_wrong_entry"
PROCESS = "The ledger holds no listing of 0x5030."


def _report(**ta: object) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ef" * 32), file_name="sample.exe"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(**ta),
    )


def _analyst(report: MalwareReport) -> str:
    return MarkdownRenderer(layout=ANALYST).render(report)


def _section(markdown: str, heading: str) -> str:
    return markdown.split(heading, 1)[1].split("\n## ", 1)[0]


def _flag(*texts: str, code: str = WRONG_ENTRY) -> list[FlaggedStatement]:
    return [FlaggedStatement(sentence=text, code=code, label="x") for text in texts]


def _dropped(*subjects: str) -> dict[str, object]:
    return {
        "validation": {
            "unresolved": [
                {"code": "agreement.dropped", "message": "left out", "subject": subject}
                for subject in subjects
            ]
        }
    }


# -- Ruling 5: a flagged text is left out only where it stands whole ----------------------


def test_a_flagged_row_value_leaves_the_prose_naming_it_as_written() -> None:
    # One stored run's flag row, cut out of six sentences naming it.
    said = "Its flags are --shares, --full or --path, and none is passed by default [ev_0048]."
    report = _report(
        command_and_control=TechnicalSubsection(title="C2", body=f"It beacons. {said}"),
        cli_flags=[CliFlag(flag="--path", description="the root to walk", evidence_ref="ev_0048")],
    )
    report.flagged_statements = _flag("--path [ev_0048]")
    c2 = _section(_analyst(report), "## 6. Command and control")
    assert "--full or --path, and none is passed by default" in c2
    assert "left out; the bundle lists each" not in c2


def test_a_flagged_value_inside_a_quoted_command_leaves_the_sentence_whole() -> None:
    # A made-up shape: the value opens a quoted command line in the middle of a sentence.
    said = "The note is written by 'regsvc /install UpdateSvc' at the second start [ev_0047]."
    report = _report(
        persistence_detail=TechnicalSubsection(title="Persistence", body=f"It stays. {said}")
    )
    report.flagged_statements = _flag("regsvc /install [ev_0047]")
    functionality = _section(_analyst(report), "## 5. Functionality")
    assert "'regsvc /install UpdateSvc' at the second start" in functionality
    assert "left out; the bundle lists each" not in functionality


def test_a_flagged_whole_sentence_is_still_left_out_and_counted() -> None:
    report = _report(
        packing_obfuscation=TechnicalSubsection(title="Packing", body=f"It packs. {PROCESS}")
    )
    report.flagged_statements = _flag(PROCESS, code="report.process_words")
    functionality = _section(_analyst(report), "## 5. Functionality")
    assert "0x5030" not in functionality
    assert "_1 sentence of this section was left out; the bundle lists each with the reason._" in (
        functionality
    )


def test_a_flagged_whole_cell_prints_as_left_out() -> None:
    report = _report(command_and_control=TechnicalSubsection(title="C2", body="It uses RC4 keys."))
    report.c2_channels = [C2Channel(name="beacon", protocol="HTTP", encryption="RC4 [ev_0009]")]
    report.flagged_statements = _flag("RC4 [ev_0009]")
    c2 = _section(_analyst(report), "## 6. Command and control")
    # The cell holding the flagged text alone is left out; the prose naming it stands.
    assert "| beacon | HTTP | - | - | - |" in c2
    assert "It uses RC4 keys." in c2
    assert "_1 sentence of this section was left out" in c2


# -- Ruling 6: what is left out is counted where it is printed ----------------------------


def test_a_summary_that_lost_bullets_says_so() -> None:
    report = _report(
        capability_summary=[
            CapabilityBullet(text="It encrypts files."),
            CapabilityBullet(text=""),
            CapabilityBullet(text="It deletes shadow copies."),
        ]
    )
    # The second bullet lost its only sentence; the third one of its two.
    report.run_summary = _dropped("capability_summary.2", "capability_summary.3")
    summary = _section(_analyst(report), "## 1. Executive summary")
    assert (
        "_2 sentences of this section were left out; the bundle lists each with the reason._"
        in (summary)
    )


def test_a_cell_and_a_section_5_sentence_left_out_are_counted_where_they_print() -> None:
    report = _report(
        command_and_control=TechnicalSubsection(title="C2", body="It beacons [ev_0009]."),
        string_resolution=TechnicalSubsection(title="Resolution", body="It hashes names."),
    )
    report.c2_channels = [C2Channel(name="beacon", protocol="HTTP", encryption="")]
    report.run_summary = _dropped("communications.1.encryption", "string_resolution")
    markdown = _analyst(report)
    assert "_1 sentence of this section was left out" in _section(
        markdown, "## 6. Command and control"
    )
    assert "_1 sentence of this section was left out" in _section(markdown, "## 5. Functionality")
    # Neither is counted anywhere else.
    assert markdown.count("of this section was left out") == 2


def test_a_key_finding_the_summary_does_not_print_is_not_counted_there() -> None:
    report = _report(capability_summary=[CapabilityBullet(text="It encrypts files.")])
    report.key_findings = [KeyFinding(text="It encrypts files.")]
    report.run_summary = _dropped("key_findings.1")
    summary = _section(_analyst(report), "## 1. Executive summary")
    assert "left out; the bundle lists each" not in summary


def test_a_value_cut_counts_as_no_sentence() -> None:
    report = _report(
        command_and_control=TechnicalSubsection(
            title="C2", body="It takes --shares or --path [ev_0048]."
        )
    )
    report.flagged_statements = _flag("--path [ev_0048]")
    report.run_summary = _dropped("command_and_control")
    c2 = _section(_analyst(report), "## 6. Command and control")
    assert "It takes --shares or --path[[1]]" in c2
    # The one sentence left out of the passage, not the value standing in another.
    assert "_1 sentence of this section was left out" in c2


def test_a_flagged_sentence_before_another_is_left_out_and_counted() -> None:
    report = _report(
        packing_obfuscation=TechnicalSubsection(
            title="Packing", body=f"It packs. {PROCESS} It unpacks in memory."
        )
    )
    report.flagged_statements = _flag(PROCESS, code="report.process_words")
    functionality = _section(_analyst(report), "## 5. Functionality")
    assert "It packs. It unpacks in memory." in functionality
    assert "_1 sentence of this section was left out" in functionality


def test_a_flagged_value_opening_a_sentence_leaves_the_sentence_whole() -> None:
    said = "--path is read before any other flag [ev_0048]."
    report = _report(command_and_control=TechnicalSubsection(title="C2", body=f"It runs. {said}"))
    report.flagged_statements = _flag("--path [ev_0048]")
    c2 = _section(_analyst(report), "## 6. Command and control")
    assert "It runs. --path is read before any other flag" in c2
    assert "left out; the bundle lists each" not in c2


@pytest.mark.parametrize(
    ("subject", "heading"),
    [
        ("execution_flow.1", "## 4. Execution flow"),
        ("procedures.1", "## 10. MITRE ATT&CK mapping"),
        ("host_identifiers.1", "## 8. Detection"),
        ("introduction", "## 2. Introduction and scope"),
    ],
)
def test_a_sentence_left_out_of_any_printed_passage_is_counted_there(
    subject: str, heading: str
) -> None:
    report = _report()
    report.run_summary = _dropped(subject)
    markdown = _analyst(report)
    assert "_1 sentence of this section was left out" in _section(markdown, heading)
    assert markdown.count("of this section was left out") == 1
