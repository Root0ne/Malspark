"""A text printed in its writer's own words is one passage wherever it prints.

The analyst report can print one verbatim text at several places: a claim sentence under
several technique rows, a statement and a claim fallback alike. The agreement round is shown
each distinct text once, the passage naming every place it prints, and a sentence of it left
out is left out at every one of them. A sentence left out is recorded as left out, a state of
its own beside the places it is left out of, so no reader lists it as standing. Only the
judge's own words are shown as the judge's: the platform's words around a reason ("the judge
dropped it (", "carried forward: …") and a note the platform writes are no passage (T-613).
Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from malspark.pipeline.validation import ValidationTally
from malspark.reporting.models import CapabilityCell, FlaggedStatement, MalwareReport
from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.section_agreement import (
    AGREEMENT_PRODUCER,
    DROPPED_CODE,
    apply_rows,
    passages_of,
    prompt_text,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    CLAIM,
    report_of,
)

_CLAIM_SENTENCE = "Routine 0x5b20 returns -1 when the BeingDebugged byte is set."
_TWICE = ("attack_claim.T1497.001", "attack_claim.T1622")


def _twice() -> MalwareReport:
    """The report, a second published technique printing the same claim sentence."""
    report = report_of()
    report.capability_matrix.append(
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id="T1497.001",
            technique_name="System Checks",
            evidence=[CLAIM],
        )
    )
    return report


def _verbatim(report: MalwareReport) -> dict[str, object]:
    return {p.id: p for p in passages_of(report) if p.verbatim}


def _dropped(report: MalwareReport, pid: str, sentence: str) -> MalwareReport:
    row = {
        "passage": pid,
        "sentence": sentence,
        "decision": "drop",
        "sources": ["string_resolution"],
        "reason": "Section 5 says otherwise.",
    }
    _counts, found = apply_rows({"sentences": [row]}, passages_of(report))
    tally = ValidationTally()
    tally.record_unresolved(AGREEMENT_PRODUCER, found)
    report.run_summary = {
        **(report.run_summary or {}),
        "validation": {"unresolved": tally.unresolved},
    }
    return report


def test_one_text_at_two_places_is_one_passage_naming_both() -> None:
    shown = _verbatim(_twice())

    claims = [pid for pid in shown if pid.startswith("attack_claim.")]
    assert claims == ["attack_claim.T1497.001", "attack_claim.T1057"]
    passage = shown["attack_claim.T1497.001"]
    assert passage.text == _CLAIM_SENTENCE  # type: ignore[attr-defined]
    assert passage.label == (  # type: ignore[attr-defined]
        "ATT&CK table, the claim sentence printed for T1497.001; ATT&CK table, the claim "
        "sentence printed for T1622"
    )
    assert prompt_text(passages_of(_twice())).count(_CLAIM_SENTENCE) == 1


def test_a_sentence_left_out_is_left_out_at_every_place_it_prints() -> None:
    report = _dropped(_twice(), "attack_claim.T1497.001", _CLAIM_SENTENCE)

    assert [(r.code, r.label, r.sentence, r.left_out) for r in report.flagged_statements] == [
        (DROPPED_CODE, "attack_claim.T1497.001", _CLAIM_SENTENCE, list(_TWICE))
    ]
    markdown = MarkdownRenderer(layout=ANALYST).render(report)
    html = HtmlRenderer(layout=ANALYST).render(report)
    assert _CLAIM_SENTENCE not in markdown and _CLAIM_SENTENCE not in html
    assert "| Defense Evasion | T1622 | Debugger Evasion | - _(" in markdown
    assert "| Defense Evasion | T1497.001 | System Checks | - |" in markdown
    assert (
        "_2 sentences of this section were left out; the bundle lists each with the reason._"
        in (markdown)
    )


def test_a_left_out_sentence_is_no_standing_one_on_any_surface() -> None:
    report = _dropped(_twice(), "attack_claim.T1497.001", _CLAIM_SENTENCE)
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    # The bundle prints the claim whole and the round's record of the sentence left out,
    # and no mark calling it kept or standing.
    assert "returns -1 when the BeingDebugged byte is set" in bundle
    assert (
        "(attack_claim.T1497.001) out of the analyst report, which the bundle prints whole"
        in bundle
    )
    assert "asked about and kept" not in bundle
    # A standing row is stored as before: no state of left out on it.
    standing = FlaggedStatement(sentence="A sentence.", code="report.process_words")
    assert "left_out" not in standing.model_dump(mode="json")
    assert report.flagged_statements[0].model_dump(mode="json")["left_out"] == list(_TWICE)


def test_only_the_judge_s_own_words_are_the_judge_s_passage() -> None:
    report = report_of()
    cells = {cell.technique_id: cell for cell in report.capability_matrix}
    cells["T1622"].note = (
        "carried forward: the round-2 revision neither wrote it again nor withdrew it; kept by "
        "the judge when asked (The judge read only the flag check [ev_0103].)"
    )
    cells["T1057"].note = (
        "stated by the judge and claimed by no analyst; a technique the judge states is "
        "published as its own claim"
    )
    shown = _verbatim(report)

    assert shown["attack_note.T1622"].text == "The judge read only the flag check [ev_0103]."  # type: ignore[attr-defined]
    assert shown["attack_note.T1055"].text == "No write into another process is shown [ev_0104]."  # type: ignore[attr-defined]
    assert "attack_note.T1057" not in shown
    assert "the judge dropped it" not in prompt_text(passages_of(report))


def test_a_reason_left_out_keeps_the_platform_s_words_without_the_bracket() -> None:
    report = _dropped(
        report_of(), "attack_note.T1055", "No write into another process is shown [ev_0104]."
    )
    markdown = MarkdownRenderer(layout=ANALYST).render(report)

    assert (
        "- T1055 Process Injection: claimed, not published: the judge dropped it; evidence -"
        in (markdown)
    )
    assert "No write into another process" not in markdown
