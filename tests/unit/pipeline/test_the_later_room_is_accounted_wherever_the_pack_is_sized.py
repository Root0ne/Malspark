"""The later detonations' room is accounted for wherever the pack is sized or fitted.

The job's own lines keep the pack's bound; a further detonation's lines take
a room of the same size of their own. Where an earlier run's block shares the
bound (``nodes.pack_text``) it is taken off the job's own room only. Where an
analyst's prompt is fitted to its model's window, the pack is measured as it
is, the later room included: the input the room leaves is shortened, and says
so, exactly as it is for a long pack of one detonation; no pack line is cut
mid-line (T-671 review r3 R2). Offline.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.llm import context_window as cw
from malspark.pipeline import nodes
from malspark.pipeline.triage_pack import PACK_HEADING, pack_block, pack_entries
from tests.unit.pipeline.test_every_later_detonation_is_shown_in_the_pack import _rows
from tests.unit.test_an_input_that_fits_its_window_runs_one_loop import _Analyst


def test_the_earlier_run_s_block_is_taken_off_the_job_s_own_room_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, rows = _rows()
    bound = 2000
    earlier = "AN EARLIER RUN ON THIS SAMPLE: " + "e" * 300
    monkeypatch.setattr(nodes, "upstream_chars", lambda container, reporter=False: bound)
    monkeypatch.setattr(nodes, "earlier_run_text", lambda container, sha: earlier)
    text = nodes.pack_text({"evidence_ledger": rows, "file_hash": "x"}, SimpleNamespace())
    pack, _, tail = text.rpartition("\n\n")
    assert tail == earlier
    own_room = bound - len(earlier) - 2
    assert pack.startswith(pack_block(pack_entries([first]), own_room))
    later = pack[len(pack_block(pack_entries([first]), own_room)) :].lstrip("\n")
    # The later lines have the whole bound, not the bound less the earlier block.
    assert later == pack_block(pack_entries(rows), bound)[
        len(pack_block(pack_entries([first]), bound)) :
    ].lstrip("\n")


def _framed(window: int, facts_block: str) -> Any:
    agent = _Analyst(llm=None, name="dynamic")  # type: ignore[arg-type]
    budget = cw.ContextBudget(cw.WindowFact(window, cw.DECLARED, "test"))
    agent._context_budget = lambda: budget  # type: ignore[method-assign]
    agent._system_prompt = lambda *a, **k: "s" * 2000  # type: ignore[method-assign]
    agent.tools = []
    agent.facts_block = facts_block
    return agent


def test_a_small_window_measures_the_pack_with_its_later_room() -> None:
    first, rows = _rows()
    bound = 4000
    one = pack_block(pack_entries([first]), bound)
    several = pack_block(pack_entries(rows), bound)
    assert len(several) > len(one)
    window = 16_384
    alone, with_later = _framed(window, one), _framed(window, several)
    text = "x" * 200_000
    # The input's room is taken off by the pack as it is, later lines included.
    assert alone._input_room_chars(text) - with_later._input_room_chars(text) == len(several) - len(
        one
    )
    # And the input is shortened, and says so, as it is for a long pack.
    shortened = with_later._truncate_input(text)
    assert len(shortened) < len(text)
    assert shortened != text[: len(shortened)]


def test_no_pack_line_is_cut_mid_line() -> None:
    _first, rows = _rows()
    block = pack_block(pack_entries(rows), 900)
    for line in block.split("\n")[1:]:
        assert line.startswith("[ev_") or line.startswith("detonation "), line
        assert not line.endswith("…") or "not shown" not in line
    assert block.startswith(PACK_HEADING)
