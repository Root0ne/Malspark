"""A dropped file's stated size of zero prints as zero on every surface that prints it.

A written file of no bytes is a fact the record states; "not recorded" said
it was never stated. The report's measured table and the analyst's both read
one helper; a size the record does not state is still "not recorded". A size
that is a number, or text that is a number, prints as bytes; other text prints
as the record states it, with no unit added. Only an empty or blank text and a
value that is no scalar are not recorded: nothing a record states is replaced.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.renderers.markdown import dropped_size_cell


@pytest.mark.parametrize(
    ("size", "printed"),
    [
        (0, "0 bytes"),
        (4096, "4096 bytes"),
        ("2048", "2048 bytes"),
        (" 512 ", "512 bytes"),
        (1.5, "1.5 bytes"),
        (None, "not recorded"),
        ("", "not recorded"),
        ("   ", "not recorded"),
        ("12kB", "12kB"),
        (" 1.2 MB ", "1.2 MB"),
        ("inf", "inf"),
        (float("nan"), "nan"),
        ([4096], "not recorded"),
        ({"bytes": 4096}, "not recorded"),
        (False, "not recorded"),
        (True, "not recorded"),
    ],
)
def test_the_cell_says_what_the_row_states(size: Any, printed: str) -> None:
    assert dropped_size_cell({"size": size}) == printed


def test_a_row_without_a_size_is_not_recorded() -> None:
    assert dropped_size_cell({}) == "not recorded"


def test_both_report_surfaces_read_the_one_helper() -> None:
    from pathlib import Path

    from malspark.reporting.renderers import analyst, markdown

    for module in (markdown, analyst):
        text = Path(module.__file__).read_text(encoding="utf-8")
        assert 'if op.get("size") else "not recorded"' not in text
        assert "dropped_size_cell(op)" in text
