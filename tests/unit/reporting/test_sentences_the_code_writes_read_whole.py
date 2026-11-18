"""The sentences the code writes read whole and true.

A status cut to its width ends at a word and closes every bracket it opened. The Benign
verdict's reason for a technique refers to nothing a layout may not print.
"""

from __future__ import annotations

from malspark.extractors.capability_matrix import BENIGN_TECHNIQUE_REASON
from malspark.reporting.judge_reasons import status_shown
from malspark.utils.marked_cut import CUT_MARK


def _balanced(text: str) -> bool:
    depth = 0
    for character in text:
        depth += {"(": 1, ")": -1}.get(character, 0)
        if depth < 0:
            return False
    return depth == 0


def test_a_status_cut_to_its_width_ends_at_a_word_and_closes_its_brackets() -> None:
    status = (
        "the verdict is Benign: a capability is not published as the sample's behaviour; the "
        "analyst noted it (the routine at 0x4010 opens a pipe three times and then "
        "CreateProcessW starts the child with the pipe handles as its standard streams)"
    )
    for width in (60, 120, 170, len(status) - 1):
        shown = status_shown(status, width)
        assert len(shown) <= width, width
        assert _balanced(shown), shown
        words = shown.rstrip(")").removesuffix(CUT_MARK)
        assert status.startswith(words), shown
        assert status[len(words)] == " ", shown
    assert status_shown(status, len(status)) == status


def test_the_benign_reason_for_a_technique_names_no_table_a_layout_may_not_print() -> None:
    assert BENIGN_TECHNIQUE_REASON == (
        "the verdict is Benign: a capability named in this run is not published as the "
        "sample's behaviour"
    )
    assert "matrix" not in BENIGN_TECHNIQUE_REASON
