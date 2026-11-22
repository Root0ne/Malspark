"""Where a text a ``strings`` pattern matched inside a run starts names that run's root.

A strings row is one run of printable bytes: its ``offset`` is where the run
starts, and its ``match_offsets`` are where each text the pattern matched
inside the run starts in the file. Both are offsets of the row's text, so a
statement citing either picks the row out and gets the run's root; a number
neither names still picks out no row.
"""

from __future__ import annotations

from typing import Any

from malspark.analysis.evidence_roots import NAMES_NO_ROW, run_roots
from malspark.schemas.evidence import LedgerEntry

SECTIONS = [
    {
        "name": ".text",
        "virtual_address": "0x00001000",
        "virtual_size": 0x4000,
        "raw_offset": 0x400,
        "raw_size": 0x4000,
    },
    {
        "name": ".data",
        "virtual_address": "0x00005000",
        "virtual_size": 0x1000,
        "raw_offset": 0x4400,
        "raw_size": 0x1000,
    },
]
RUN = "alpha beta gamma marker-text one two"
INNER = 0x4410 + RUN.index("marker-text")


def _ledger(*, layout: bool, inner: list[Any] | None) -> list[LedgerEntry]:
    first: dict[str, Any] = {"offset": 0x4410, "enc": "ascii", "text": RUN}
    if inner is not None:
        first = {"offset": 0x4410, "match_offsets": inner, "enc": "ascii", "text": RUN}
    rows = [first, {"offset": 0x4600, "enc": "ascii", "text": "zeta eta theta"}]
    entries = [LedgerEntry(id="ev_0001", tool="hashes", structured={"sha256": "a" * 64})]
    if layout:
        entries.append(LedgerEntry(id="ev_0002", tool="pe_info", structured={"sections": SECTIONS}))
    entries.append(LedgerEntry(id="ev_0003", tool="strings", structured={"strings": rows}))
    return entries


def _read(ledger: list[LedgerEntry], offset: int) -> tuple[list[str], list[str]]:
    return run_roots(ledger).of_statement(
        f"The marker sits at offset {offset:#x} [ev_0003].", ["ev_0003"]
    )


class TestAMatchOffsetNamesItsRun:
    def test_a_match_offset_gives_the_root_the_run_s_start_gives(self) -> None:
        ledger = _ledger(layout=True, inner=[INNER])

        assert _read(ledger, INNER) == _read(ledger, 0x4410) == (["0x5010 in .data"], [])

    def test_a_file_with_no_layout_gives_the_run_s_file_offset(self) -> None:
        ledger = _ledger(layout=False, inner=[INNER])

        assert _read(ledger, INNER) == (["file offset 0x4410"], [])

    def test_the_cited_source_is_read_as_the_run_s_start_is(self) -> None:
        roots = run_roots(_ledger(layout=True, inner=[INNER]))

        inner = roots.sources_of_statement(f"At offset {INNER:#x} [ev_0003].", ["ev_0003"])
        start = roots.sources_of_statement(f"At offset {0x4410:#x} [ev_0003].", ["ev_0003"])

        assert inner == start


class TestNothingElseMoves:
    def test_a_row_without_match_offsets_is_read_as_before(self) -> None:
        roots, reasons = _read(_ledger(layout=True, inner=None), INNER)

        assert roots == []
        assert reasons == ["ev_0003: " + NAMES_NO_ROW.format(entry="ev_0003")]

    def test_an_offset_no_row_names_picks_out_none(self) -> None:
        roots, reasons = _read(_ledger(layout=True, inner=[INNER]), INNER + 1)

        assert roots == []
        assert reasons == ["ev_0003: " + NAMES_NO_ROW.format(entry="ev_0003")]

    def test_a_value_that_is_no_number_is_left_unread(self) -> None:
        ledger = _ledger(layout=True, inner=["not a number", None])

        assert _read(ledger, 0x4410) == (["0x5010 in .data"], [])
        assert run_roots(ledger).of_entry("ev_0003").roots == ["0x5010 in .data", "0x5200 in .data"]
