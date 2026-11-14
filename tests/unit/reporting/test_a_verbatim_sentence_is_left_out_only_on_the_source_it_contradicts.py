"""A verbatim sentence is left out only on the source it contradicts; the rewritable side mends.

Where a text printed in its writer's own words and a passage the round may rewrite disagree,
the question says to list and mend the rewritable one. A verbatim sentence is left out only on
a named source it contradicts: a drop naming none is refused, as a keep naming no quote is,
and a drop resting on a passage the round may rewrite is refused too (T-613). Every address,
entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.section_agreement import (
    UNKNOWN_SOURCE_CODE,
    agreement_violations,
    apply_rows,
    passages_of,
    prompt_text,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

_SECOND = "It compares each name with HOST_MODE [ev_0102]."


def _drop(**said: Any) -> dict[str, Any]:
    return {
        "passage": "statements.T1057.1",
        "sentence": _SECOND,
        "decision": "drop",
        "reason": "Section 5 names no such compare.",
        **said,
    }


def _refusals(row: dict[str, Any]) -> list[Any]:
    found = agreement_violations({"sentences": [row]}, passages_of(report_of()))
    return [v for v in found if v.path.startswith("sentences.")]


def test_a_drop_naming_no_source_is_refused_and_leaves_nothing_out() -> None:
    asked = _refusals(_drop())

    assert [v.code for v in asked] == [UNKNOWN_SOURCE_CODE]
    assert asked[0].message.startswith(
        'row 1 drops a sentence of statements.T1057.1 naming no source; name in "sources" the '
        "source it contradicts: only that leaves it out."
    )
    report = report_of()
    counts, _found = apply_rows({"sentences": [_drop()]}, passages_of(report))
    # No source it contradicts is named: the sentence stands as written.
    assert counts["dropped"] == 0 and counts["not_applied"] == 1
    assert report.flagged_statements == []


def test_a_drop_naming_the_source_it_contradicts_passes() -> None:
    assert _refusals(_drop(sources=["string_resolution"])) == []


def test_a_drop_resting_on_a_passage_the_round_may_rewrite_is_refused() -> None:
    asked = _refusals(_drop(sources=["limitations"]))

    assert [v.code for v in asked] == [UNKNOWN_SOURCE_CODE]


def test_the_question_states_the_order_of_ends_once() -> None:
    text = prompt_text(passages_of(report_of()))

    assert text.count("where it and a passage you may rewrite disagree, list and mend that ") == 1
    assert 'or drop it naming in "sources" the source it contradicts, with "reason"' in text
