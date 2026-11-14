"""The platform's cut mark is no part of a judge's words, wherever it stands.

The ATT&CK table prints a judge's reason cut to its width, ending in the platform's cut mark.
Where the cut falls inside a bracket the judge opened, the mark stands before the closing
bracket the platform writes, inside what reads as the judge's bracket: it is still the
platform's, never part of the words the agreement round is shown (T-613). Every address,
entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from malspark.reporting.judge_reasons import CUT_MARK, judge_reason_spans, status_shown

# A reason whose cut falls inside the bracket the judge opened.
_REASON = (
    "the judge dropped it (No write is shown (the routine at 0x5e10 reads a buffer, then "
    "frees it again, then reads a second buffer that it copies into a local array of its "
    "own before it returns to the caller with the count of bytes it read from the file))"
)


def _words(printed: str) -> list[str]:
    return [printed[start:end] for start, end, _close in judge_reason_spans(printed)]


def test_a_cut_inside_the_judge_s_bracket_leaves_the_mark_out_of_the_words() -> None:
    printed = status_shown(_REASON, 120)
    assert CUT_MARK in printed

    (words,) = _words(printed)
    assert CUT_MARK not in words
    assert words.startswith("No write is shown (the routine at 0x5e10")


def test_a_cut_at_the_end_of_the_reason_leaves_the_mark_out_as_well() -> None:
    (words,) = _words(f"the judge dropped it (No write is shown. A second sentence {CUT_MARK})")

    assert words == "No write is shown. A second sentence"
