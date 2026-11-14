"""A sentence printed inside two different verbatim texts is one sentence wherever it prints.

The analyst report can print one sentence inside two texts that differ as wholes: a claim's
first sentence as the ATT&CK table's fallback ("S.") and the same sentence opening an
appendix statement ("S. T."). Each text is its own passage of the agreement round, yet the
sentence is one: every place it prints is indexed by the sentence, an end leaving it out
applies at each of them, and a leaving-out at one passage wins over a keep at the other
(T-613). Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST
from malspark.reporting.section_agreement import DROPPED_CODE, apply_rows, passages_of
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

_S = "Routine 0x5b20 returns -1 when the BeingDebugged byte is set."
_T = "It then reads HOST_FLAG at 0x5c30."
_FALLBACK = "attack_claim.T1622"
_STATEMENT = "statements.T1057.1"


def _both() -> MalwareReport:
    """The report, its appendix statement opening with the fallback's sentence."""
    report = report_of()
    cells = {cell.technique_id: cell for cell in report.capability_matrix}
    cells["T1057"].statements = [f"static: {_S} {_T}"]
    return report


def _drop(pid: str) -> dict[str, Any]:
    return {
        "passage": pid,
        "sentence": _S,
        "decision": "drop",
        "sources": ["string_resolution"],
        "reason": "Section 5 says otherwise.",
    }


_KEEP = {
    "passage": _FALLBACK,
    "sentence": _S,
    "decision": "keep",
    "sources": ["string_resolution"],
    "quote": "Routine 0x5b20 reads the BeingDebugged byte and returns -1 when it is set",
}


def _answered(*rows: dict[str, Any]) -> tuple[MalwareReport, dict[str, int]]:
    report = _both()
    counts, _found = apply_rows({"sentences": list(rows)}, passages_of(report))
    return report, counts


def test_the_two_texts_are_two_passages_sharing_the_sentence() -> None:
    shown = {p.id: p for p in passages_of(_both()) if p.verbatim and not p.source_only}

    assert shown[_FALLBACK].text == _S
    assert shown[_STATEMENT].text == f"{_S} {_T}"


def test_a_drop_at_the_fallback_leaves_the_sentence_out_of_the_statement_too() -> None:
    report, counts = _answered(_drop(_FALLBACK))

    assert counts["dropped"] == 1
    (row,) = [r for r in report.flagged_statements if r.code == DROPPED_CODE]
    assert set(row.left_out) == {_FALLBACK, _STATEMENT}
    for render in (
        MarkdownRenderer(layout=ANALYST).render(report),
        HtmlRenderer(layout=ANALYST).render(report),
    ):
        assert "returns -1 when the BeingDebugged byte is set" not in render
        assert "HOST_FLAG" in render


def test_a_drop_at_the_statement_leaves_the_sentence_out_of_the_fallback_too() -> None:
    report, _counts = _answered(_drop(_STATEMENT))

    (row,) = [r for r in report.flagged_statements if r.code == DROPPED_CODE]
    assert set(row.left_out) == {_FALLBACK, _STATEMENT}
    markdown = MarkdownRenderer(layout=ANALYST).render(report)
    assert "returns -1 when the BeingDebugged byte is set" not in markdown
    assert "| Defense Evasion | T1622 | Debugger Evasion | - _(" in markdown
    assert "HOST_FLAG" in markdown


def test_a_leaving_out_wins_over_a_keep_of_the_same_sentence_elsewhere() -> None:
    report, counts = _answered(_KEEP, _drop(_STATEMENT))

    assert counts["kept"] == 1 and counts["dropped"] == 1
    markdown = MarkdownRenderer(layout=ANALYST).render(report)
    assert "returns -1 when the BeingDebugged byte is set" not in markdown
