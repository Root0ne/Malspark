"""A carved payload's and a resource's size are printed by the one size reader.

The report's measured payload table, the analyst's payload table and the
report's resource list print a size as the dropped files' cells do
(``dropped_size_cell``): a size of zero is a file of no bytes, a number or
text that is a number prints as bytes, other text prints as stated in one
code span, and only a size that is not stated is "not recorded" (in the
resource list, which states a size only beside a resource, no size at all).
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
)
from malspark.reporting.renderers.layout import ANALYST
from malspark.reporting.renderers.markdown import MarkdownRenderer

CASES = [
    (0, "0 bytes"),
    (1.5, "1.5 bytes"),
    ("2048", "2048 bytes"),
    ("12kB", "`12kB`"),
    (None, "not recorded"),
]


def _report(resources: list[dict[str, Any]]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
        verdict="Malware",
        static=StaticAnalysis(embedded_resources=resources),
    )


def _carved_row(size: Any, analyst: bool) -> list[str]:
    resource = {"id": "payload_1", "carved": True, "size": size, "sha256": "b" * 64}
    renderer = MarkdownRenderer(layout=ANALYST) if analyst else MarkdownRenderer()
    text = renderer.render(_report([resource]))
    (row,) = [line for line in text.splitlines() if line.startswith("| `payload_1`")]
    return [cell.strip() for cell in row.strip("|").split("|")]


@pytest.mark.parametrize("analyst", [False, True], ids=["report", "analyst"])
@pytest.mark.parametrize(("size", "printed"), CASES)
def test_a_carved_payload_s_size_cell_says_what_its_row_states(
    size: Any, printed: str, analyst: bool
) -> None:
    assert _carved_row(size, analyst)[1] == printed


@pytest.mark.parametrize(
    ("size", "item"),
    [
        (0, "- RT_ICON (0 bytes)"),
        (1.5, "- RT_ICON (1.5 bytes)"),
        ("2048", "- RT_ICON (2048 bytes)"),
        ("12kB", "- RT_ICON (`12kB`)"),
        (None, "- RT_ICON"),
        (4096, "- RT_ICON (4096 bytes)"),
    ],
)
def test_a_resource_s_size_says_what_its_row_states(size: Any, item: str) -> None:
    text = MarkdownRenderer().render(_report([{"type": "RT_ICON", "size": size}]))
    lines = text.splitlines()
    heading = next(i for i, line in enumerate(lines) if "Resources" in line and "#" in line)
    items = [line for line in lines[heading + 1 :] if line.startswith("- ")]
    assert items[0] == item
