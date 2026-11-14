"""A verbatim sentence left standing is marked wherever the bundle prints it.

A sentence of a text printed in its writer's own words that the agreement round dropped naming
no source it is read against is recorded as asked about and left standing. The bundle marks it
at every place it prints, through the one marker every other place uses: the judge's words in
the ATT&CK status cell, the list of claims not published and the run's corroboration table
among them, and an analyst's
statement whose sentence the appendix prints without its claim number. A sentence is the same
sentence whatever the white space between its words and however often its text holds it: the
leaving-out and the mark take every copy, in the analyst report as in the bundle. The mark says
what the round did with it, asked about and left standing; a sentence of a passage the round may
rewrite keeps the words of its own mark and is found once and as copied (T-613).
Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from malspark.reporting.models import FlaggedStatement, MalwareReport
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.section_agreement import (
    CLAIM_LED,
    DROPPED_CODE,
    LISTED_CODE,
    VERBATIM_DEFAULT,
    Passage,
    _cut,
    apply_rows,
    left_out_of,
    passages_of,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

_REASON = "No write into another process is shown [ev_0104]."
_NOTE = "The judge read only the flag check [ev_0103]."
_STATEMENT = "Routine 0x5a10 reads the process list through Process32FirstW [ev_0101]."


def _mark(pid: str) -> str:
    return f"**[asked about and left standing: {pid}]**"


def _dropped(report: MalwareReport, pid: str, sentence: str, **row: Any) -> dict[str, int]:
    counts, _found = apply_rows(
        {"sentences": [{"passage": pid, "sentence": sentence, "decision": "drop", **row}]},
        passages_of(report),
    )
    return counts


def _with_statement(statement: str) -> MalwareReport:
    report = report_of()
    for cell in report.capability_matrix:
        if cell.technique_id == "T1057":
            cell.statements = [statement]
    return report


def _bundle(report: MalwareReport) -> str:
    return MarkdownRenderer(layout=BUNDLE).render(report)


def test_a_judge_reason_left_standing_is_marked_in_every_bundle_line_it_prints_in() -> None:
    report = report_of()
    _dropped(report, "attack_note.T1055", _REASON, sources=[], reason="No.")

    assert [(r.sentence, r.code) for r in report.flagged_statements] == [(_REASON, LISTED_CODE)]
    lines = [line for line in _bundle(report).splitlines() if _REASON in line]
    # The status cell of the ATT&CK table and the list of claims not published.
    assert len(lines) == 2
    assert all(f"{_REASON} {_mark('attack_note.T1055')}" in line for line in lines)


def test_a_judge_note_left_standing_is_marked_in_the_status_cell() -> None:
    report = report_of()
    _dropped(report, "attack_note.T1622", _NOTE, sources=[], reason="No.")

    (row,) = [
        line for line in _bundle(report).splitlines() if "| T1622 | Debugger Evasion |" in line
    ]
    assert f"{_NOTE} {_mark('attack_note.T1622')}" in row


def test_a_drop_naming_a_source_only_passage_and_an_invalid_source_leaves_it_out() -> None:
    report = report_of()
    counts = _dropped(
        report,
        "attack_claim.T1622",
        "Routine 0x5b20 returns -1 when the BeingDebugged byte is set.",
        sources=["attack_claim.T1622.unprinted", "no_such_passage"],
        reason="It disagrees.",
    )

    assert counts["dropped"] == 1
    assert [(r.code, r.left_out) for r in report.flagged_statements] == [
        (DROPPED_CODE, ["attack_claim.T1622"])
    ]


def test_a_statement_s_sentence_is_recorded_as_the_bundle_prints_it() -> None:
    # The appendix prints the sentence without its claim number; the bundle prints it whole.
    stored = "Routine 0x5a10 reads the process list through Process32FirstW [ev_0101] (claim 4)."
    report = _with_statement(f"static: {stored} It compares each name with HOST_MODE [ev_0102].")
    (passage,) = [p for p in passages_of(report) if p.id == "statements.T1057.1"]
    assert passage.text.startswith(_STATEMENT)

    _dropped(report, passage.id, _STATEMENT, sources=[], reason="No.")

    assert [(r.sentence, r.code) for r in report.flagged_statements] == [(stored, LISTED_CODE)]
    (line,) = [line for line in _bundle(report).splitlines() if "(claim 4)" in line]
    assert f"{stored} {_mark(passage.id)}" in line


def test_a_sentence_its_text_holds_twice_is_left_out_each_time() -> None:
    assert left_out_of("S is set. T runs. S is set.", ["S is set."]) == ("T runs.", 2)

    report = _with_statement(
        f"static: {_STATEMENT} It compares each name with HOST_MODE [ev_0102]. {_STATEMENT}"
    )
    counts = _dropped(
        report, "statements.T1057.1", _STATEMENT, sources=["string_resolution"], reason="No."
    )

    assert counts["dropped"] == 1
    assert "reads the process list" not in MarkdownRenderer(layout=ANALYST).render(report)


def test_a_copy_differing_only_in_white_space_is_the_same_sentence() -> None:
    assert left_out_of("S  is\tset. T runs.", ["S is set."]) == ("T runs.", 1)

    report = report_of()
    counts = _dropped(
        report,
        "statements.T1057.1",
        _STATEMENT.replace(" the ", "  the "),
        sources=["string_resolution"],
        reason="No.",
    )

    assert counts["dropped"] == 1
    assert "reads the process list" not in MarkdownRenderer(layout=ANALYST).render(report)


def test_a_sentence_left_standing_is_marked_at_every_copy_whatever_its_white_space() -> None:
    spaced = _STATEMENT.replace(" the ", "  the ")
    report = _with_statement(f"static: {spaced} It compares. {_STATEMENT}")
    report.flagged_statements = [
        FlaggedStatement(sentence=_STATEMENT, code=LISTED_CODE, label="statements.T1057.1")
    ]

    (line,) = [line for line in _bundle(report).splitlines() if "It compares." in line]
    mark = _mark("statements.T1057.1")
    assert f"{spaced} {mark} It compares. {_STATEMENT} {mark}" in line


def test_the_mark_of_a_rewritable_passage_s_sentence_keeps_its_words() -> None:
    report = report_of()
    (passage,) = [p for p in passages_of(report) if p.id == "string_resolution"]
    assert passage.write is not None and not passage.verbatim
    report.flagged_statements = [
        FlaggedStatement(
            sentence=passage.text, code="agreement.rewrite_ungrounded", label=passage.id
        )
    ]

    bundle = _bundle(report)
    assert f"{passage.text} **[asked about and kept: string_resolution]**" in bundle
    assert "asked about and left standing" not in bundle


def test_a_judge_reason_left_standing_is_marked_in_the_run_s_corroboration_table() -> None:
    report = report_of()
    report.run_summary = {
        **(report.run_summary or {}),
        "corroboration": {
            "T1055": {
                "claimed_by": ["static"],
                "not_published": f"the judge dropped it ({_REASON})",
            }
        },
    }
    _dropped(report, "attack_note.T1055", _REASON, sources=[], reason="No.")

    (row,) = [line for line in _bundle(report).splitlines() if line.startswith("| T1055 (")]
    assert f"{_REASON} {_mark('attack_note.T1055')}" in row


def test_a_sentence_left_out_is_left_out_of_a_text_holding_it_twice_and_of_every_other() -> None:
    sentence = "The flag is read at 0x5b20 [ev_0103]."
    report = report_of()
    report.severity.business_impact = f"{sentence} It reaches 0x5c30 first. {sentence}"
    for cell in report.capability_matrix:
        if cell.technique_id == "T1622":
            cell.note = (
                "carried forward: the round-2 revision neither wrote it again nor withdrew it; "
                f"kept by the judge when asked ({sentence} Nothing else is read.)"
            )
    _dropped(report, "attack_note.T1622", sentence, sources=["string_resolution"], reason="No.")

    assert [(r.code, r.left_out) for r in report.flagged_statements] == [
        (DROPPED_CODE, ["judge.business_impact", "attack_note.T1622"])
    ]
    assert "The flag is read" not in MarkdownRenderer(layout=ANALYST).render(report)


def test_the_analyst_report_leaves_out_every_copy_of_a_sentence_left_standing() -> None:
    spaced = _STATEMENT.replace(" the ", "  the ")
    report = _with_statement(f"static: {spaced} It compares each name with HOST_MODE [ev_0102].")
    report.flagged_statements = [
        FlaggedStatement(sentence=_STATEMENT, code=LISTED_CODE, label="statements.T1057.1")
    ]

    assert "reads  the process list" not in MarkdownRenderer(layout=ANALYST).render(report)


def test_a_table_cell_marks_a_sentence_left_standing_whatever_its_white_space() -> None:
    report = report_of()
    for cell in report.capability_matrix:
        if cell.technique_id == "T1057":
            cell.evidence = ["Routine 0x5a10  lists processes [ev_0101]."]
    report.flagged_statements = [
        FlaggedStatement(
            sentence="Routine 0x5a10 lists processes [ev_0101].",
            code=LISTED_CODE,
            label="attack_claim.T1057",
        )
    ]

    (row,) = [
        line for line in _bundle(report).splitlines() if "| T1057 | Process Discovery |" in line
    ]
    assert _mark("attack_claim.T1057") in row


def test_a_passage_the_round_may_rewrite_keeps_the_matcher_it_had() -> None:
    # Only a text printed in its writer's own words finds a sentence by its words at every
    # copy; a rewritable passage's sentence stands once and as copied, and its mark is found
    # as written.
    for text in ("S is set. T runs. S is set.", "S  is set. T runs."):
        rewritable = Passage(id="limitations", label="9.", text=text, kind=CLAIM_LED)
        verbatim = replace(rewritable, verbatim=VERBATIM_DEFAULT)

        assert _cut(rewritable).span("S is set.") is None
        assert _cut(verbatim).span("S is set.") is not None

    report = report_of()
    (passage,) = [p for p in passages_of(report) if p.id == "string_resolution"]
    report.flagged_statements = [
        FlaggedStatement(
            sentence=passage.text.replace(" the ", "  the "),
            code="agreement.rewrite_ungrounded",
            label=passage.id,
        )
    ]
    assert "asked about and kept" not in _bundle(report)
