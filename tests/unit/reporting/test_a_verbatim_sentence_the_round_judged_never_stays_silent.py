"""A verbatim sentence the agreement round judged never stays silent.

A listed sentence of a text printed in its writer's own words ends one of three ways. A drop
naming at least one source the round reads verbatim texts against (a fact, a section 5
passage, a debate round, a passage shown as a source only) that fails another check leaves
it out. A drop naming no such source records it as asked about and left standing, the state
the report, the API and the console list: the analyst report treats it as any sentence a
check left standing, the bundle marking it where its copy stands, by its place, and a judge's
words in that state stay printed. A keep no check passes leaves it out. The question says so
in few words (T-613). Every address, entry and name here is a
neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    LISTED_CODE,
    apply_rows,
    passages_of,
    prompt_text,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

_PID = "attack_claim.T1622"
_SENTENCE = "Routine 0x5b20 returns -1 when the BeingDebugged byte is set."
# The same sentence as the claim stores it, its citation in place.
_STORED = "Routine 0x5b20 returns -1 when the BeingDebugged byte is set [ev_0103]."


def _ended(
    pid: str = _PID, sentence: str = _SENTENCE, **row: Any
) -> tuple[MalwareReport, dict[str, int]]:
    report = report_of()
    counts, _found = apply_rows(
        {"sentences": [{"passage": pid, "sentence": sentence, **row}]}, passages_of(report)
    )
    return report, counts


def _printed(report: MalwareReport) -> bool:
    return "returns -1 when the BeingDebugged byte is set" in MarkdownRenderer(
        layout=ANALYST
    ).render(report)


def test_a_drop_naming_a_source_that_fails_another_check_leaves_it_out() -> None:
    # Beside the section 5 passage, one no source of a verbatim sentence: a passage the round
    # may rewrite, and an id shown nowhere.
    for other in ("limitations", "no_such_passage"):
        report, counts = _ended(
            decision="drop", sources=["string_resolution", other], reason="It disagrees."
        )

        assert counts["dropped"] == 1
        assert [(r.code, r.left_out) for r in report.flagged_statements] == [(DROPPED_CODE, [_PID])]
        assert not _printed(report)


def test_a_drop_naming_no_source_is_recorded_as_asked_and_left_standing() -> None:
    for sources in ([], ["limitations"], [_PID], ["no_such_passage"]):
        report, counts = _ended(decision="drop", sources=sources, reason="It disagrees.")

        assert counts["dropped"] == 0
        # The sentence as its place stores it, its citation in place.
        assert [
            (r.sentence, r.code, r.label, r.asked, r.left_out) for r in report.flagged_statements
        ] == [(_STORED, LISTED_CODE, _PID, True, [])]


def test_the_bundle_marks_it_where_its_place_s_copy_stands() -> None:
    report, _counts = _ended(decision="drop", sources=[], reason="It disagrees.")
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    (row,) = [line for line in bundle.splitlines() if "| T1622 | Debugger Evasion |" in line]
    assert f"{_STORED} It then exits. **[asked about and kept: {_PID}]**" in row
    # The analyst report treats it as any sentence a check left standing: the bundle's.
    assert not _printed(report)


def test_a_judge_s_words_in_that_state_stay_printed_and_are_listed_as_standing() -> None:
    reason = "No write into another process is shown [ev_0104]."
    report, counts = _ended(
        pid="attack_note.T1055", sentence=reason, decision="drop", sources=[], reason="No."
    )

    assert counts["dropped"] == 0
    assert [(r.sentence, r.code, r.asked, r.left_out) for r in report.flagged_statements] == [
        (reason, LISTED_CODE, True, [])
    ]
    assert f"the judge dropped it ({reason})" in MarkdownRenderer(layout=ANALYST).render(report)


def test_a_keep_no_check_passes_leaves_it_out() -> None:
    report, counts = _ended(
        decision="keep", sources=["string_resolution"], quote="The second stage is a loader"
    )

    assert counts["kept"] == 0
    assert [(r.code, r.left_out) for r in report.flagged_statements] == [(DROPPED_CODE, [_PID])]
    assert not _printed(report)


def test_the_question_states_the_three_ends_and_the_sources_of_a_drop() -> None:
    text = " ".join(prompt_text(passages_of(report_of())).split())

    assert (
        'or drop it naming in "sources" the source it contradicts (a fact, a section 5 '
        "passage, a debate round or a passage marked (verbatim, a source only)), with "
        '"reason". A keep no check passes, or a refused drop naming such a source, leaves it '
        "out of the analyst report, which the bundle prints whole; a drop naming no such "
        "source is recorded as asked about and left standing."
    ) in text
