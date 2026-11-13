"""A later detonation whose share holds not even one marked line is named on one line.

Each later detonation is always named with its launch, even where that
passes the bound: the floor. It is as small as it can be: where not even one
marked line of a detonation fits its share, the trailer alone names it (its
name, its launch and how many of its entries are not shown), so at a bound
too small for anything the later part is exactly one line per later
detonation, each no longer than the launch text's own cut allows
(T-671 review r4 F2). Offline.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from malspark.analysis import sandbox_sections as ss
from malspark.pipeline import detonations as dt
from malspark.pipeline.triage_pack import LAUNCH_SHOWN_ESCAPED, pack_block, pack_entries
from malspark.providers.detonation import DetonationRecord
from malspark.reporting.detonation_marks import LAUNCH_TEXT_CHARS
from malspark.schemas.evidence import LedgerEntry
from tests.unit.pipeline.test_a_later_detonation_is_read_by_the_platform import (
    D2_REPORT,
    container_with_a_pending_request,
)

# One launch text far past the cut, one short.
LAUNCHES = {"d2": "-p " + "A" * (3 * LAUNCH_TEXT_CHARS), "d3": "-p two", "d4": "-p three"}
TRAILER = re.compile(
    r"detonation (\d+), launched with `([^`]*)` (\(.*\)): (\d+) more pack entr(?:y|ies) of this "
    r"detonation not shown here; every entry's full output is reachable by tool call\."
)


def _rows() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    container = container_with_a_pending_request()
    first = LedgerEntry(
        id="ev_0000",
        tool=ss.SECTIONS_TOOL,
        agent="pipeline",
        source="pack",
        structured=ss.section_index({"behavior": {"processes": [{"pid": 84}]}}),
    ).model_dump(mode="json")
    rows = [first]
    for name, arguments in LAUNCHES.items():
        record = DetonationRecord(
            ordinal=int(name[1:]),
            origin="agent",
            arguments=arguments,
            report=D2_REPORT,
            requested_by=[{"agent": "x", "cited_entries": ["ev_0000"]}],
        )
        rows += dt.platform_reads(container, record, "")
    return first, rows


@pytest.mark.parametrize("bound", [1, 50, 300])
def test_each_later_detonation_is_one_line_at_a_bound_too_small_for_its_lines(bound: int) -> None:
    first, rows = _rows()
    alone = pack_block(pack_entries([first]), bound)
    block = pack_block(pack_entries(rows), bound)
    assert block.startswith(alone)
    lines = block[len(alone) :].lstrip("\n").split("\n")
    assert len(lines) == len(LAUNCHES), lines
    for name, line in zip(LAUNCHES, lines, strict=True):
        found = TRAILER.fullmatch(line)
        assert found is not None, line
        number, launch, hint, count = found.groups()
        assert f"d{number}" == name
        assert hint == LAUNCH_SHOWN_ESCAPED.format(name=name)
        # Every entry of the detonation is counted as not shown.
        assert int(count) == sum(row["structured"].get("detonation") == name for row in rows)
        # No longer than the launch text's own cut allows.
        assert len(launch) <= LAUNCH_TEXT_CHARS
        ceiling = (
            f"detonation {number}, launched with `{'x' * LAUNCH_TEXT_CHARS}` {hint}: {count} more "
            "pack entries of this detonation not shown here; every entry's full output is "
            "reachable by tool call."
        )
        assert len(line) <= len(ceiling)
    # The long launch text is the one cut.
    assert len(TRAILER.fullmatch(lines[0]).group(2)) > len(LAUNCHES["d3"])  # type: ignore[union-attr]
