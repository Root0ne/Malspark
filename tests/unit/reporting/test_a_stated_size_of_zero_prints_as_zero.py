"""A dropped file's stated size of zero prints as zero on every surface that prints it.

A written file of no bytes is a fact the record states; "not recorded" said
it was never stated. The report's measured table and the analyst's both read
one helper; a size the record does not state is still "not recorded". A size
that is a number, or text that is a number, prints as bytes; other text prints
as the record states it, with no unit added, as one code span: it is a
sandbox's free text, read as text, never as a link, an image or a tag. Only an
empty or blank text and a value that is no scalar are not recorded: nothing a
record states is replaced.
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
        ("12kB", "`12kB`"),
        (" 1.2 MB ", "`1.2 MB`"),
        ("inf", "`inf`"),
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


# A size text a sandbox wrote, holding what a viewer would read as Markdown.
HOSTILE = (
    "[12kB](https://evil.example/x)",
    "<img src=x onerror=alert(1)>",
    "12`kB",
    "12 | kB",
)


def _rendered(size: str, analyst: bool) -> str:
    from malspark.reporting.models import (
        DynamicBehavior,
        FileHashes,
        MalwareReport,
        SampleIdentity,
    )
    from malspark.reporting.renderers.layout import ANALYST
    from malspark.reporting.renderers.markdown import MarkdownRenderer

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
        verdict="Malware",
        dynamic=DynamicBehavior(
            file_operations=[{"path": "C:\\x\\written.bin", "operation": "write", "size": size}]
        ),
    )
    renderer = MarkdownRenderer(layout=ANALYST) if analyst else MarkdownRenderer()
    return renderer.render(report)


@pytest.mark.parametrize("analyst", [False, True], ids=["report", "analyst"])
@pytest.mark.parametrize("size", HOSTILE)
def test_a_size_text_is_read_as_text_on_both_surfaces(size: str, analyst: bool) -> None:
    from markdown_it import MarkdownIt

    text = _rendered(size, analyst)
    tokens = MarkdownIt("commonmark", {"html": True}).enable("table").parse(text)
    rows: list[list[Any]] = []
    for token in tokens:
        if token.type == "tr_open":
            rows.append([])
        elif token.type == "inline" and rows:
            rows[-1].append(token)
    # The row of the dropped files' table, the one that prints a size.
    (row,) = [
        r
        for r in rows
        if r and "written.bin" in r[0].content and any("dropped" in c.content for c in r)
    ]
    # The size cell, the row's second: one code span holding the text as stated.
    cell = row[1]
    assert [c.type for c in cell.children] == ["code_inline"], cell.content
    # The report defangs an address wherever it prints one, a code span included.
    read = cell.children[0].content.replace("hxxp", "http").replace("[.]", ".")
    assert read == size
