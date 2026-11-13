"""Every later detonation is shown in the pack, the later room shared evenly, each cut named.

With several further detonations, the room after the job's own lines is
divided evenly among them (a detonation that needs less leaves the rest to
the others); each keeps at least one line naming it and its launch, and a
detonation whose entries are not all shown ends with a line naming it and how
many (T-671 review r3 R1). The marks are counted per line before the lines
are fitted, so they neither overfill the room nor leave it under-filled
(R5). Each detonation says once that its launch text is shown escaped and
where the exact text is (R6). Offline.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from malspark.analysis import sandbox_sections as ss
from malspark.pipeline import detonations as dt
from malspark.pipeline.triage_pack import LAUNCH_SHOWN_ESCAPED, pack_block, pack_entries
from malspark.providers.detonation import DetonationRecord
from malspark.schemas.evidence import LedgerEntry
from tests.unit.pipeline.test_a_later_detonation_is_read_by_the_platform import (
    D2_REPORT,
    container_with_a_pending_request,
)

# A detonation that saw much: its lines need more than the others'.
BIG: dict[str, Any] = {
    "behavior": {"processes": [{"pid": n, "process_name": f"p{n}.exe"} for n in range(10, 70)]},
    "network": {"dns": [{"request": f"h{n}.example.net", "type": "A"} for n in range(40)]},
}
LAUNCHES = {"d2": "-p one " + "A" * 40, "d3": "-p two", "d4": "-p a|b`c"}


def _rows(small: str = "") -> tuple[dict[str, Any], list[dict[str, Any]]]:
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
            report=(
                {"behavior": {"processes": []}} if name == small else (BIG if small else D2_REPORT)
            ),
            requested_by=[{"agent": "x", "cited_entries": ["ev_0000"]}],
        )
        rows += dt.platform_reads(container, record, "")
    return first, rows


def _later(bound: int) -> tuple[str, str]:
    first, rows = _rows()
    alone = pack_block(pack_entries([first]), bound)
    block = pack_block(pack_entries(rows), bound)
    assert block.startswith(alone)
    return alone, block[len(alone) :].lstrip("\n")


@pytest.mark.parametrize("bound", [0, 4000, 2000, 900, 300, 60])
def test_every_later_detonation_is_named_with_its_launch(bound: int) -> None:
    _alone, later = _later(bound)
    for name in LAUNCHES:
        number = name[1:]
        assert f"detonation {number}, launched with `" in later, (bound, name)
        # Said once per detonation: the launch text is shown escaped.
        assert later.count(LAUNCH_SHOWN_ESCAPED.format(name=name)) == 1, (bound, name)


@pytest.mark.parametrize("bound", [2000, 900])
def test_a_cut_detonation_has_its_own_trailer(bound: int) -> None:
    _alone, later = _later(bound)
    lines = later.split("\n")
    trailers = [line for line in lines if not line.startswith("[ev_")]
    assert trailers
    for line in trailers:
        assert re.match(r"detonation \d+, launched with `", line), line
        assert re.search(r": \d+ more pack entr(y|ies) of this detonation not shown here", line)
    # Each detonation shows at least one line of its own entries.
    for name in LAUNCHES:
        assert any(
            line.startswith("[ev_") and f"detonation {name[1:]}, launched" in line for line in lines
        ), name


def _by_detonation(later: str) -> dict[str, str]:
    held: dict[str, list[str]] = {}
    for line in later.split("\n"):
        found = re.search(r"detonation (\d+), launched with `", line)
        assert found is not None, line
        held.setdefault(f"d{found.group(1)}", []).append(line)
    return {name: "\n".join(lines) for name, lines in held.items()}


def test_the_room_is_shared_evenly_within_the_bound() -> None:
    _alone, later = _later(2000)
    assert len(later) <= 2000
    share = (2000 - 2) // 3
    parts = _by_detonation(later)
    longest = max(len(line) for line in later.split("\n"))
    for name, text in parts.items():
        # Each takes no more than its share, and is no more than a line short of it.
        assert share - longest <= len(text) <= share, (name, len(text), share)


def test_a_detonation_that_needs_little_leaves_its_share_to_the_others() -> None:
    first, rows = _rows(small="d3")
    alone = pack_block(pack_entries([first]), 0)
    whole = _by_detonation(pack_block(pack_entries(rows), 0)[len(alone) :].lstrip("\n"))
    bound = 3 * (len(whole["d3"]) + 50) + 2
    assert len(whole["d2"]) > (bound - 2) // 3 and len(whole["d4"]) > (bound - 2) // 3
    head = pack_block(pack_entries([first]), bound)
    parts = _by_detonation(pack_block(pack_entries(rows), bound)[len(head) :].lstrip("\n"))
    assert parts["d3"] == whole["d3"]
    # The others share what d3 left, and what d2's long line left of its room
    # passes on to d4: it takes more than an even third.
    assert len(parts["d4"]) > (bound - 2) // 3
    assert len("\n".join(parts.values())) <= bound


def test_the_marks_are_counted_so_the_room_is_filled() -> None:
    _alone, later = _later(2000)
    # Filled to within one more line's worth: no more than the longest marked line short.
    longest = max(len(line) for line in later.split("\n"))
    assert 2000 - len(later) < longest + 3 * 120


def test_the_hint_is_inert_and_the_exact_text_is_in_the_read() -> None:
    _first, rows = _rows()
    _alone, later = _later(0)
    # The escaped launch text names no pipe or back-tick of its own.
    (d4,) = [line for line in later.split("\n") if LAUNCH_SHOWN_ESCAPED.format(name="d4") in line]
    launch = d4[d4.index("`") + 1 : d4.index("`", d4.index("`") + 1)]
    assert "|" not in launch and "\\x7c" in launch
    # The exact text is the launched_with of any read of d4.
    exact = {
        row["structured"]["launched_with"]
        for row in rows
        if row["structured"].get("detonation") == "d4"
    }
    assert exact == {LAUNCHES["d4"]}
