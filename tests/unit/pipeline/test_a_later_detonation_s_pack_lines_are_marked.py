"""A later detonation's pack lines say which detonation they are of, and its item ids are qualified.

The platform's reads of a further detonation are the pack's entries, so every
agent after it and the reporter are shown them in the pack. Each such line
names the detonation and the arguments it was launched with, and every item
id it shows carries the detonation's qualifier (``d2/proc:9``), the form the
citation checks know. The job's own lines keep their room: a later
detonation's lines come after them, in a room of their own bounded as the
pack is. A job with one detonation renders as it did. Offline.
"""

from __future__ import annotations

import re
from typing import Any

from malspark.analysis import sandbox_sections as ss
from malspark.pipeline.triage_pack import PIPELINE, pack_block, pack_entries, pack_row_heads
from malspark.schemas.evidence import LedgerEntry
from tests.unit.pipeline.test_a_later_detonation_is_read_by_the_platform import (
    ARGS,
    _entered_update,
    container_with_a_pending_request,
)

D1_REPORT: dict[str, Any] = {
    "behavior": {"processes": [{"pid": 4, "process_name": "first.exe"}]},
    "network": {"dns": [{"request": "a.example.net", "type": "A"}]},
}


def _first_entries(start: int = 1) -> list[dict[str, Any]]:
    """The job's own detonation's pack entries: its processes and its section index."""
    from malspark.providers import sandbox_tools

    def _entry(n: int, tool: str, value: dict[str, Any]) -> dict[str, Any]:
        return LedgerEntry(
            id=f"ev_{n:04d}",
            seq=n,
            tool=tool,
            agent=PIPELINE,
            source="pack",
            structured=value,
            output="x",
        ).model_dump(mode="json")

    return [
        _entry(start, "sandbox_processes", sandbox_tools.sandbox_processes(D1_REPORT)),
        _entry(start + 1, ss.SECTIONS_TOOL, ss.section_index(D1_REPORT)),
    ]


def _rows() -> list[dict[str, Any]]:
    """The first detonation's entries, then the platform's reads of d2 (issued after them)."""
    container = container_with_a_pending_request()
    first = _first_entries(1)
    counter = container.get_evidence_counter()
    counter.next_id()
    counter.next_id()
    later = _entered_update(container, {"evidence_ledger": []})["evidence_ledger"]
    return [*first, *later]


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("[ev_")]


class TestThePackMarksALaterDetonation:
    def test_every_later_line_names_its_detonation_and_launch(self) -> None:
        block = pack_block(pack_entries(_rows()), 0)
        lines = _lines(block)
        first, later = lines[:2], lines[2:]
        assert all("detonation 2" not in line for line in first)
        assert len(later) == 6
        for line in later:
            assert f"detonation 2, launched with `{ARGS}`" in line

    def test_every_item_id_a_later_line_shows_is_qualified(self) -> None:
        block = pack_block(pack_entries(_rows()), 0)
        later = _lines(block)[2:]
        shown = [i for line in later for i in ss.item_ids_in(line)]
        assert "d2/proc:9" in shown
        assert shown and all(i.startswith("d2/") for i in shown)
        # The first detonation's ids stay as they were.
        first_ids = [i for line in _lines(block)[:2] for i in ss.item_ids_in(line)]
        assert "proc:4" in first_ids and not any("/" in i for i in first_ids)

    def test_the_first_detonation_s_lines_keep_their_room(self) -> None:
        rows = _rows()
        alone = pack_block(pack_entries(rows[:2]), 0)
        bound = len(alone) - len(alone.splitlines()[0]) - 1
        block = pack_block(pack_entries(rows), bound)
        assert block.startswith(alone)
        # The later lines come after, in a room bounded as the pack is.
        later = block[len(alone) :]
        assert later.strip() and len(later) <= bound + 1

    def test_the_row_heads_mark_a_later_entry_too(self) -> None:
        rows = _rows()
        heads = pack_row_heads(rows)
        later_ids = [str(row["id"]).lower() for row in rows[2:]]
        for entry_id in later_ids:
            assert f"detonation 2, launched with `{ARGS}`" in heads[entry_id]
        assert "detonation 2" not in heads["ev_0001"]
        sections = heads[later_ids[-1]]
        assert all(i.startswith("d2/") for i in ss.item_ids_in(sections))

    def test_a_job_with_one_detonation_renders_as_it_did(self) -> None:
        rows = _first_entries(1)
        block = pack_block(pack_entries(rows), 0)
        assert "detonation" not in block
        assert re.search(r"\(proc:4\)", block)


class TestAnIdCitedAsThePackShowsIt:
    def test_passes_the_citation_and_value_checks(self) -> None:
        from malspark.pipeline.nodes import sandbox_item_citations, with_item_texts
        from malspark.pipeline.validation import EntryTexts, citation_violations

        container = container_with_a_pending_request()
        rows = _first_entries(1)
        counter = container.get_evidence_counter()
        counter.next_id()
        counter.next_id()
        rows += _entered_update(container, {"evidence_ledger": []})["evidence_ledger"]
        block = pack_block(pack_entries(rows), 0)
        shown = [i for line in _lines(block)[2:] for i in ss.item_ids_in(line)]
        (process,) = [i for i in shown if i.startswith("d2/proc:")]
        container.sandbox_normalised = None
        state = {"evidence_ledger": rows, "sandbox_report": D1_REPORT}
        items = sandbox_item_citations(state, container)
        assert items is not None
        ids = [str(row["id"]) for row in rows]
        assert citation_violations({"body": f"runs [{process}]"}, ids, items=items) == []
        entries = with_item_texts(EntryTexts.from_ledger(rows), items)
        assert entries is not None and "x.exe" in (entries.items.text(process) or "")
