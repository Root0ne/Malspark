"""A further turn's rows are counted apart from the first answer's and named as the further turn's.

A further turn revises an analyst's first answer before the debate's first
round, and each row it records is marked ``further_turn``
(``pipeline.detonations.mark_further_turn``). Where rows are counted by round,
those are counted apart from round 0, and the sentence names "the further
turn" (T-671 review r2 N2). Offline.
"""

from __future__ import annotations

from typing import Any

from malspark.pipeline.detonations import FURTHER_TURN_KEY
from malspark.pipeline.validation import retry_drop_row, retry_drop_sentences


def _row(round_: int, *, further: bool = False) -> dict[str, Any]:
    row = dict(
        retry_drop_row(
            "dynamic", round_, "claim", "Encrypts files", "", "withdrawn", "no longer seen"
        )
    )
    if further:
        row[FURTHER_TURN_KEY] = "true"
    return row


def test_the_sentence_names_the_further_turn() -> None:
    (alone,) = retry_drop_sentences([_row(0, further=True), _row(0, further=True)])
    assert alone.endswith("from the further turn.")
    (both,) = retry_drop_sentences([_row(0), _row(0, further=True)])
    assert both.endswith("from revision round 0 and the further turn.")


def test_rows_without_the_mark_read_as_before() -> None:
    (first,) = retry_drop_sentences([_row(0), _row(1)])
    assert first.endswith("from revision rounds 0, 1.")
