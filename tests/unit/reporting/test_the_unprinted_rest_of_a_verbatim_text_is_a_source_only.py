"""What of a verbatim text's writer's whole text the report does not print is a source only.

The analyst report prints some texts in part: the ATT&CK table prints a claim's first
sentence, and a judge's reason as many whole sentences as fit one width. Whatever text takes
an end, where its writer's whole text holds sentences the report does not print, those
sentences are shown to the agreement round as one passage marked (verbatim, a source only):
named as a source, taking no row and no end of its own. What decides is that property, never
a field or a writer: a sentence the report prints elsewhere is not in the rest, and a text
printed whole has none (T-613). Every address, entry and name here is a neutral synthetic
value.
"""

from __future__ import annotations

from malspark.reporting.models import MalwareReport, TechnicalSubsection
from malspark.reporting.section_agreement import agreement_violations, passages_of
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

# A judge's reason longer than the ATT&CK table's width: its first two sentences print.
_REASON = (
    "No write into another process is shown in the routines the run read [ev_0104]. "
    "The only allocation found is a local buffer that the loader frees again at once. "
    "The routine at 0x5e10 that might write elsewhere was never read by any analyst. "
    "A later run could read it and decide the question."
)
_PRINTED = (
    "No write into another process is shown in the routines the run read [ev_0104]. "
    "The only allocation found is a local buffer that the loader frees again at once."
)
_REST = (
    "The routine at 0x5e10 that might write elsewhere was never read by any analyst. "
    "A later run could read it and decide the question."
)


def _shown(report: MalwareReport) -> dict[str, object]:
    return {p.id: p for p in passages_of(report)}


def _long_reason() -> MalwareReport:
    report = report_of()
    cells = {cell.technique_id: cell for cell in report.capability_matrix}
    cells["T1055"].not_published = f"the judge dropped it ({_REASON})"
    return report


def test_a_claim_s_sentences_the_table_does_not_print_are_a_source_only() -> None:
    rest = _shown(report_of())["attack_claim.T1622.unprinted"]

    assert rest.text == "It then exits."  # type: ignore[attr-defined]
    assert rest.source_only and rest.leave_out is None  # type: ignore[attr-defined]
    assert rest.label == (  # type: ignore[attr-defined]
        "ATT&CK table, the claim sentence printed for T1622, not printed in the analyst report"
    )


def test_a_judge_s_reason_cut_to_its_width_leaves_its_rest_a_source_only() -> None:
    shown = _shown(_long_reason())

    assert shown["attack_note.T1055"].text == _PRINTED  # type: ignore[attr-defined]
    rest = shown["attack_note.T1055.unprinted"]
    assert rest.text == _REST  # type: ignore[attr-defined]
    assert rest.source_only  # type: ignore[attr-defined]


def test_a_text_printed_whole_has_no_rest() -> None:
    shown = _shown(report_of())

    assert "statements.T1057.1.unprinted" not in shown
    assert "attack_note.T1055.unprinted" not in shown
    assert "judge.business_impact.unprinted" not in shown


def test_a_sentence_the_report_prints_elsewhere_is_not_in_the_rest() -> None:
    report = report_of()
    cells = {cell.technique_id: cell for cell in report.capability_matrix}
    # The claim's second sentence opens an appendix statement, so the report prints it.
    cells["T1057"].statements = ["static: It then exits. It reads HOST_FLAG at 0x5c30."]

    assert "attack_claim.T1622.unprinted" not in _shown(report)


def test_the_rest_is_a_source_a_verbatim_sentence_is_left_out_on() -> None:
    report = _long_reason()
    row = {
        "passage": "attack_claim.T1622",
        "sentence": "Routine 0x5b20 returns -1 when the BeingDebugged byte is set.",
        "decision": "drop",
        "sources": ["attack_note.T1055.unprinted"],
        "reason": "The judge says the routine was never read.",
    }
    found = agreement_violations({"sentences": [row]}, passages_of(report))

    assert [v for v in found if v.path.startswith("sentences.")] == []


def test_a_judge_s_text_of_which_section_7_prints_nothing_is_a_source_only_whole() -> None:
    report = report_of()
    assert report.severity is not None and report.technical_analysis is not None
    # Beside a composed conclusion, section 7 keeps no judge sentence whose values the
    # report prints elsewhere.
    report.severity.business_impact = "The loader checks for a debugger at 0x5b20 [ev_0103]."
    report.technical_analysis.analyst_conclusion = TechnicalSubsection(
        title="Conclusion", body="The file is a loader that checks for a debugger [ev_0103]."
    )
    shown = _shown(report)

    assert "judge.business_impact" not in shown
    rest = shown["judge.business_impact.unprinted"]
    assert rest.text == "The loader checks for a debugger at 0x5b20 [ev_0103]."  # type: ignore[attr-defined]
    assert rest.source_only  # type: ignore[attr-defined]
