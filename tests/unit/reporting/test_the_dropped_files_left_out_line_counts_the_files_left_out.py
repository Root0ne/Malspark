"""The line under the dropped-files table counts the files the table leaves out.

Two entries of a sandbox task may list the same item of its dropped-files list,
one with the guest path filled in: they are one file. The table prints its
first rows; the line under it counts each file of the rows after them that no
row shown names, once, by the item a row names (the sandbox's name for it, a
row with none by its path), and is not printed where every file is shown
(T-830).
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.models import DynamicBehavior, FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.layout import ANALYST
from malspark.reporting.renderers.markdown import (
    LEFT_OUT_LINE,
    MarkdownRenderer,
    dropped_files_left_out,
)


def _drop(n: int, path: str = "") -> dict[str, Any]:
    return {
        "operation": "write",
        "name": f"files/0x{n:016x}-{n}.dat",
        "path": path,
        "pids": ["4772"],
        "size": 60 + n,
        "type": None,
        "sha256": f"{n:02x}" * 32,
    }


def _ops(listed: int, repeated: list[int]) -> list[dict[str, Any]]:
    """``listed`` items of the list, then the items ``repeated`` names again with a guest path."""
    return [_drop(n) for n in range(listed)] + [
        _drop(n, f"C:\\Users\\Admin\\AppData\\Local\\Temp\\f{n}.ps1") for n in repeated
    ]


def _line(ops: list[dict[str, Any]], layout: Any = None) -> list[str]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        dynamic=DynamicBehavior(file_operations=ops),
    )
    renderer = MarkdownRenderer(layout=layout) if layout is not None else MarkdownRenderer()
    return [ln for ln in renderer.render(report).splitlines() if "dropped files not shown" in ln]


# Thirty items, five of them listed again with their guest path: four of those
# five are among the first twenty rows, one (item 23) is not.
LABELLED = _ops(30, [2, 5, 8, 19, 23])


@pytest.mark.parametrize("layout", [None, ANALYST])
def test_a_repeat_of_an_item_is_not_counted_as_another_file(layout: Any) -> None:
    assert _line(LABELLED, layout) == [LEFT_OUT_LINE.format(rest=10, what="dropped files")]


def test_the_count_is_of_the_files_after_the_rows_shown_that_no_row_shown_names() -> None:
    assert dropped_files_left_out(LABELLED, 20) == 10
    # A repeat of an item shown is shown; one of an item left out is that item.
    assert dropped_files_left_out(_ops(20, [3, 4]), 20) == 0
    assert dropped_files_left_out(_ops(22, [21]), 20) == 2


def test_items_that_differ_are_each_counted() -> None:
    ops = _ops(25, [])
    # The same name with another digest is another file (another detonation's).
    ops.append({**_drop(24), "sha256": "ff" * 32})

    assert dropped_files_left_out(ops, 20) == 6


def test_a_row_with_no_name_is_named_by_its_path() -> None:
    ops = _ops(20, []) + [
        {"operation": "write", "name": "", "path": "C:\\a.dat"},
        {"operation": "write", "name": "", "path": "C:\\b.dat"},
    ]

    assert dropped_files_left_out(ops, 20) == 2


@pytest.mark.parametrize("layout", [None, ANALYST])
def test_no_line_where_every_file_is_shown(layout: Any) -> None:
    assert _line(_ops(20, [1, 2, 3]), layout) == []
