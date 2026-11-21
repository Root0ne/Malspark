"""The words a pack line gains never cost an entry or a cut the pack would not make without them.

The capture line says what the sandbox's flow rows say of each conversation's
address, and the code-links line what the publish rule says of a value's
process and where the sandbox started the file from. Those words are laid out
last: the pack is laid out at the sizes its lines have without them (the
capture line bare, the code-links line with "process not attributed" in place
of the rule's words): the entries shown, the trailer's count and every cut are
that layout's at every room. A line the layout shows whole then takes its
words, in pack order, while the block stays within the room (the capture
line's conversation by conversation); a line whose words do not fit, and a
line the layout cut, stays as laid out. With no room limit every line takes
every word.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from malspark.analysis import behaviour_code as bc
from malspark.pipeline import triage_pack
from malspark.reporting import ledger_projection
from malspark.schemas.sandbox_report import STAGED_KEY, STAGED_WORDS
from tests.unit.analysis.test_a_behaviour_link_says_what_the_rows_say_of_its_process import (
    UNLISTED_ONLY,
    UNLISTED_ROW,
    _network,
    _strings_of,
)
from tests.unit.pipeline.test_the_capture_line_says_what_the_sandbox_rows_say_of_each_address import (  # noqa: E501
    SILENT_WORDS,
    _capture,
    _entry,
    _flows,
)

READER = ("box", "box")
ADDRESS = "192.0.2.7"
# Many conversations, one of which no flow row holds: a capture line whose
# words are long, beside a view and a code-links answer.
CONVERSATIONS = (
    "198.51.100.1",
    "198.51.100.2",
    "198.51.100.3",
    "198.51.100.4",
    *(f"203.0.113.{n}" for n in range(1, 25)),
)
UNLISTED_WORDS = UNLISTED_ONLY
# Every word this branch adds to a line, as written after its "; ".
WORDS = (
    ledger_projection.SAMPLE_TREE_FLOW,
    ledger_projection.NO_FLOW_ROW,
    SILENT_WORDS,
    UNLISTED_WORDS,
)


def _links() -> dict[str, Any]:
    """A code-links answer: one value put on an unlisted process, one value at a started row."""
    report = _network(tcp=[{"dst": ADDRESS, **UNLISTED_ROW}])
    answer = bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS))
    assert any(row.get("attribution") == UNLISTED_WORDS for row in answer["links"])
    for row in answer["links"]:
        if row["value"] != ADDRESS:
            row[STAGED_KEY] = True
    return answer


def _bare_links(answer: dict[str, Any]) -> dict[str, Any]:
    """The answer as the line is laid out: "process not attributed" in place of the rule's words."""
    bare = copy.deepcopy(answer)
    for row in bare["links"]:
        row.pop(STAGED_KEY, None)
        if bc.attribution_words(row):
            row["attribution"] = bc.NOT_ATTRIBUTED
    return bare


def _entries(links: dict[str, Any]) -> list[Any]:
    return triage_pack.pack_entries(
        [
            _entry("sandbox_network", _flows(), 13),
            _entry(bc.TOOL, links, 15),
            _entry("pcap_summary", _capture(*CONVERSATIONS), 17),
        ]
    )


def _below_heading(block: str) -> str:
    """The pack's lines, which the room bounds: the block below its heading."""
    heading, _, lines = block.partition("\n")
    assert heading == triage_pack.PACK_HEADING
    return lines


def _worded(room: int) -> str:
    return _below_heading(triage_pack.pack_block(_entries(_links()), room, normalised_by=READER))


def _laid_out(room: int) -> str:
    """The pack at the sizes its lines have without the words."""
    return _below_heading(triage_pack.pack_block(_entries(_bare_links(_links())), room))


def _unworded(line: str) -> str:
    """``line`` with every word this branch adds taken off, the code-links label put back."""
    if line.startswith("[ev_0015] "):
        line = line.replace(f"; {UNLISTED_WORDS}", f"; {bc.NOT_ATTRIBUTED}")
        line = line.replace(f"({UNLISTED_WORDS}", f"({bc.NOT_ATTRIBUTED}")
    for said in (STAGED_WORDS, *WORDS):
        line = line.replace(f"; {said}", "")
    return line


def _same_layout(worded: str, laid: str, room: int) -> None:
    got, want = worded.split("\n"), laid.split("\n")
    assert len(got) == len(want)
    for line, base in zip(got, want, strict=True):
        assert line == base or _unworded(line) == base, (room, line[:120], base[:120])
    assert len(worded) <= room


ROOMS = list(range(300, len(_worded(0)) + 400, 37))


class TestTheLayoutIsTheLayoutWithoutTheWords:
    @pytest.mark.parametrize("room", ROOMS)
    def test_at_every_room_the_entries_trailer_and_cuts_are_the_bare_layout_s(
        self, room: int
    ) -> None:
        _same_layout(_worded(room), _laid_out(room), room)

    def test_a_room_of_the_bare_whole_pack_shows_every_entry_whole(self) -> None:
        room = len(_laid_out(0))
        assert _worded(room) == _laid_out(room) == _laid_out(0)


class TestTheWordsTakeWhatRoomIsLeft:
    def test_with_no_limit_every_line_takes_every_word(self) -> None:
        block = _worded(0)
        assert f"; {ledger_projection.NO_FLOW_ROW}" in block
        assert UNLISTED_WORDS in block and STAGED_WORDS in block

    def test_in_pack_order_while_the_block_stays_within_the_room(self) -> None:
        bare = _laid_out(0)
        links_line = next(line for line in _worded(0).split("\n") if line.startswith("[ev_0015]"))
        bare_links = next(line for line in bare.split("\n") if line.startswith("[ev_0015]"))
        room = len(bare) + len(links_line) - len(bare_links)
        block = _worded(room)
        # The code-links line, first in the pack, takes its words; the capture
        # line, after it, has no room left for one.
        assert UNLISTED_WORDS in block and STAGED_WORDS in block
        assert ledger_projection.NO_FLOW_ROW not in block
        assert len(block) <= room

    def test_a_line_whose_words_do_not_fit_stays_as_laid_out(self) -> None:
        bare = _laid_out(0)
        links_line = next(line for line in _worded(0).split("\n") if line.startswith("[ev_0015]"))
        bare_links = next(line for line in bare.split("\n") if line.startswith("[ev_0015]"))
        room = len(bare) + len(links_line) - len(bare_links) - 1
        block = _worded(room)
        assert bare_links in block.split("\n")
        # The capture line after it takes what the room holds.
        assert f"; {ledger_projection.SAMPLE_TREE_FLOW}" in block
        assert len(block) <= room

    def test_the_capture_line_takes_its_words_conversation_by_conversation(self) -> None:
        whole = _worded(0)
        room = len(whole) - 40
        block = _worded(room)
        capture = next(line for line in block.split("\n") if line.startswith("[ev_0017]"))
        assert f"; {ledger_projection.SAMPLE_TREE_FLOW}" in capture
        assert capture != next(line for line in whole.split("\n") if line.startswith("[ev_0017]"))
        assert len(block) <= room

    def test_a_line_the_layout_cut_takes_no_words(self) -> None:
        laid = _laid_out(0)
        capture = next(line for line in laid.split("\n") if line.startswith("[ev_0017]"))
        # A room the capture line is cut in, with room left in the block.
        room = len(laid) - len(capture) // 2
        block = _worded(room)
        cut = next(line for line in block.split("\n") if line.startswith("[ev_0017]"))
        assert "the rest are in the entry" in cut
        assert ledger_projection.NO_FLOW_ROW not in cut
        assert ledger_projection.SAMPLE_TREE_FLOW not in cut
        _same_layout(block, _laid_out(room), room)


class TestThePackRecordReadsTheLayout:
    def test_the_pass_entries_unsaid_are_those_of_the_bare_layout(self) -> None:
        from tests.unit.pipeline.test_deobfuscation_passes_in_the_pack import _synthetic_pack

        def _pack(links: dict[str, Any]) -> list[Any]:
            rows = [*_synthetic_pack(), _entry(bc.TOOL, links, 15)]
            return triage_pack.pack_entries([row.model_dump(mode="json") for row in rows])

        worded, bare = _pack(_links()), _pack(_bare_links(_links()))
        differs = 0
        for room in range(3_000, 40_000, 997):
            want = [e.id for e in triage_pack.pack_unsaid(bare, room)]
            assert [e.id for e in triage_pack.pack_unsaid(worded, room)] == want, room
            # The record is of the pack as rendered: what it shows or counts
            # and what it records cover every pass entry alike.
            differs += want != [e.id for e in triage_pack.pack_unsaid(worded, 0)]
        assert differs


def _later(payload: dict[str, Any], number: int) -> Any:
    """``payload`` as the platform's read of a further detonation (``d2``)."""
    return _entry("pcap_summary" if "conversations" in payload else bc.TOOL, payload, number)


def _with_later(links: dict[str, Any]) -> list[Any]:
    """The job's own entries, then a further detonation's capture and code-links answers."""
    mark = {"detonation": "d2", "launched_with": "-x"}
    rows = [
        _entry("sandbox_network", _flows(), 13),
        _entry(bc.TOOL, _links(), 15),
        _entry("pcap_summary", _capture(*CONVERSATIONS), 17),
        _later({**links, **mark}, 21),
        _later({**_capture(*CONVERSATIONS), **mark}, 23),
    ]
    return triage_pack.pack_entries(rows)


def _later_lines(block: str) -> list[str]:
    return [line for line in block.split("\n") if "detonation 2" in line]


class TestALaterDetonationsLinesCarryNoWords:
    @pytest.mark.parametrize("room", [0, *range(1_500, 16_000, 450)])
    def test_its_lines_are_those_of_its_answers_without_the_words(self, room: int) -> None:
        worded = triage_pack.pack_block(_with_later(_links()), room, normalised_by=READER)
        bare = triage_pack.pack_block(
            _with_later(_bare_links(_links())), room, normalised_by=READER
        )
        lines = _later_lines(worded)
        assert lines and lines == _later_lines(bare)
        for line in lines:
            assert UNLISTED_WORDS not in line and STAGED_WORDS not in line
            assert all(f"; {said}" not in line for said in WORDS)
