"""A verbatim sentence the agreement round judged never stays silent.

A listed sentence of a text printed in its writer's own words ends one of three ways. A drop
naming at least one source the round reads verbatim texts against (a fact, a section 5
passage, a debate round, a passage shown as a source only) that fails another check leaves
it out. A drop naming no such source leaves it as written and records it as asked and left
standing, the state the report, the API and the console list. A keep no check passes leaves
it out. The question says so in few words (T-613). Every address, entry and name here is a
neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST
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


def _ended(**row: Any) -> tuple[MalwareReport, dict[str, int]]:
    report = report_of()
    counts, _found = apply_rows(
        {"sentences": [{"passage": _PID, "sentence": _SENTENCE, **row}]}, passages_of(report)
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


def test_a_drop_naming_no_source_is_left_as_written_and_recorded_as_asked() -> None:
    for sources in ([], ["limitations"], [_PID], ["no_such_passage"]):
        report, counts = _ended(decision="drop", sources=sources, reason="It disagrees.")

        assert counts["dropped"] == 0
        assert [
            (r.sentence, r.code, r.label, r.asked, r.left_out) for r in report.flagged_statements
        ] == [(_SENTENCE, LISTED_CODE, _PID, True, [])]


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
        '"reason". A keep no check passes, or a drop naming such a source that another check '
        "refuses, leaves it out of the analyst report, which the bundle prints whole; a drop "
        "naming no such source leaves it as written, recorded as asked."
    ) in text
