"""The judge's words the analyst report does not print are a source of the agreement round.

Beside a composed conclusion, section 7 prints only the judge's sentences that name a value
printed nowhere else; the bundle prints the judge's words whole. What of a judge's text the
analyst report does not print is shown to the round as a passage marked (verbatim, a source
only): it may be named as a source, of a verbatim sentence's drop as of any passage written
without the code, and it takes no row and no end of its own, so nothing is left out of
anything for it (T-613). Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.models import MalwareReport, TechnicalSubsection
from malspark.reporting.section_agreement import (
    UNKNOWN_PASSAGE_CODE,
    agreement_violations,
    apply_rows,
    passages_of,
    prompt_text,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

_SOURCE = "judge.business_impact.unprinted"
_UNPRINTED = "The loader checks for a debugger at 0x5b20 [ev_0103]."


def _composed() -> MalwareReport:
    report = report_of()
    ta = report.technical_analysis
    assert ta is not None
    ta.analyst_conclusion = TechnicalSubsection(
        title="Conclusion", body="The file is a loader that checks for a debugger [ev_0103]."
    )
    return report


def _refusals(report: MalwareReport, row: dict[str, Any]) -> list[Any]:
    found = agreement_violations({"sentences": [row]}, passages_of(report))
    return [v for v in found if v.path.startswith("sentences.")]


def test_the_judge_s_words_not_printed_are_a_source_passage() -> None:
    shown = {p.id: p for p in passages_of(_composed())}

    source = shown[_SOURCE]
    assert source.text == _UNPRINTED
    assert source.label == (
        "7. Conclusion, the judge's severity rationale, not printed in the analyst report"
    )
    assert source.source_only and source.write is None and source.leave_out is None
    # The sentence section 7 prints is a passage of its own, taking its ends.
    assert shown["judge.business_impact"].text == "It reaches 0x5c30 first."
    assert not shown["judge.business_impact"].source_only


def test_the_question_marks_it_a_source_only_and_says_so_once() -> None:
    text = prompt_text(passages_of(_composed()))

    assert (
        "- [judge.business_impact.unprinted] 7. Conclusion, the judge's severity rationale, not "
        "printed in the analyst report (verbatim, a source only) (cites ev_0103): "
    ) in text
    assert text.count("A passage marked (verbatim, a source only)") == 1


def test_a_row_answering_it_is_refused_and_leaves_nothing_out() -> None:
    report = _composed()
    row = {"passage": _SOURCE, "sentence": _UNPRINTED, "decision": "drop", "reason": "No."}

    assert [v.code for v in _refusals(report, row)] == [UNKNOWN_PASSAGE_CODE]
    counts, _found = apply_rows({"sentences": [row]}, passages_of(report))
    assert counts["dropped"] == 0
    assert report.flagged_statements == []


def test_it_is_a_source_a_verbatim_sentence_is_left_out_on() -> None:
    report = _composed()
    row = {
        "passage": "attack_claim.T1622",
        "sentence": "Routine 0x5b20 returns -1 when the BeingDebugged byte is set.",
        "decision": "drop",
        "sources": [_SOURCE],
        "reason": "The judge reads the flag check only.",
    }

    assert _refusals(report, row) == []
    # Where the analyst report prints every judge sentence, no such source is shown.
    assert _refusals(report_of(), row) != []


def test_a_report_printing_every_judge_sentence_shows_no_source_of_them() -> None:
    assert _SOURCE not in {p.id for p in passages_of(report_of())}
