"""On a small window the upstream questions never cut a claim or move it out of the first chunk.

The hand-off goes into the agent's first chunk, and the head source is sized
for it. A block that grows by its questions makes the first piece of a split
head source smaller; the claims stay at the head of the first chunk. Where the
head is not split — a JSON head that is the agent's only source and fits its
room with the claims — the questions would take the one chunk past the room,
where the prompt shortens it from its end, the hand-off's end: there the
questions are fitted line by line to the room the chunk leaves, and with none
fitting the chunk is the one sent before.
"""

from __future__ import annotations

import json
import re
from typing import Any

from malspark.core.config import ProfileDefinition, StageDefinition
from malspark.pipeline.nodes import (
    UPSTREAM_QUESTIONS_HEADING,
    make_stage_agent_node,
)
from tests.unit.pipeline import handoff_isrs as h
from tests.unit.pipeline.test_the_hand_off_shows_the_upstream_questions_after_every_claim import (
    CLAIMS,
    QUESTION_LINES,
)
from tests.unit.test_an_input_that_fits_its_window_runs_one_loop import (
    _agent,
    _chunks_shown,
    _container,
    _no_overlap,
    _state,
)

FULL = "\n".join([CLAIMS, "", UPSTREAM_QUESTIONS_HEADING, *QUESTION_LINES])
LEFT_OUT = re.compile(r"^- (\d+) more open question\(s\) are not shown here")
PARSED = "".join(f"- flow {i:05d} to a host of the test network\n" for i in range(600))
TARGET = {f"field_{i:03d}": f"an invented value {i}" for i in range(60)}


def _shown(role: str, sets: dict, room: int, **state: Any) -> list[str]:
    """What a ``role`` analyst at ``room`` characters is handed after the ``first`` stage."""
    name = {"network": "network", "static": "static"}[role]
    agent = _agent(room=room)
    container = _container(agent, role=role, settings=_no_overlap())
    stage = StageDefinition(
        key="later",
        kind="analysis",
        agents=[name],
        depends_on=["first"],
        inject_upstream="findings",
    )
    container.active_profile.return_value = ProfileDefinition(
        label="test",
        stages=[
            StageDefinition(key="first", kind="analysis", agents=["reader", "lister"]),
            stage,
            StageDefinition(key="verdict", kind="verdict", agents=["judge"], depends_on=["later"]),
        ],
    )
    container.config.reporting.upstream_findings_max_chars = 50_000
    if role == "network":
        container.parser_registry.create.side_effect = None
        container.parser_registry.create.return_value.parse.return_value = PARSED
    make_stage_agent_node(stage, name, container)(
        _state(isr_reports=sets, reports={}, **state)  # type: ignore[arg-type]
    )
    return _chunks_shown(agent)


def _claims_chunk(shown: list[str]) -> list[int]:
    return [
        i for i, chunk in enumerate(shown) if CLAIMS in chunk or json.dumps(CLAIMS)[1:-1] in chunk
    ]


class TestASplitHead:
    ROOM = 4_000

    def test_the_claims_head_the_first_chunk_and_the_questions_follow_them(self) -> None:
        report = {"network": {"hosts": ["192.0.2.10"]}}
        before = _shown(
            "network", h.without_questions(h.with_questions()), self.ROOM, sandbox_report=report
        )
        after = _shown("network", h.with_questions(), self.ROOM, sandbox_report=report)

        assert len(before) > 2
        assert _claims_chunk(before) == _claims_chunk(after) == [0]
        assert before[0].startswith(CLAIMS + "\n\n")
        assert after[0].startswith(FULL + "\n\n")
        assert all(len(chunk) <= self.ROOM for chunk in after)
        # Nothing of the input is lost: the head piece is smaller by the questions.
        assert after[0][len(FULL) + 2 :] + "".join(after[1:]) == PARSED
        assert len(after[0]) - len(FULL) < len(before[0]) - len(CLAIMS)


class TestAJsonHeadThatIsTheOnlySource:
    REPORT = {"target": TARGET}

    def _length(self, sets: dict) -> int:
        (only,) = _shown("static", sets, 1_000_000, sandbox_report=self.REPORT)
        return len(only)

    def test_every_room_the_claims_fit_keeps_them_whole_and_the_chunk_inside_it(self) -> None:
        sets = h.with_questions()
        before = self._length(h.without_questions(sets))
        whole = self._length(sets)
        assert whole > before
        seen: set[int] = set()
        for room in [*range(before, whole, 9), whole]:
            (only,) = _shown("static", sets, room, sandbox_report=self.REPORT)
            # Never past the room, where the prompt would shorten it.
            assert len(only) <= room, room
            handed = json.loads(only)["upstream_findings"]
            assert handed.startswith(CLAIMS), room
            if handed == CLAIMS:
                (dev,) = _shown(
                    "static", h.without_questions(sets), room, sandbox_report=self.REPORT
                )
                assert only == dev, room
                seen.add(0)
                continue
            lines = handed[len(CLAIMS) + 2 :].split("\n")
            assert lines[0] == UPSTREAM_QUESTIONS_HEADING, room
            tail = LEFT_OUT.match(lines[-1])
            questions = lines[1:-1] if tail else lines[1:]
            assert questions == QUESTION_LINES[: len(questions)], room
            if tail:
                assert int(tail.group(1)) == len(QUESTION_LINES) - len(questions), room
            seen.add(len(questions))
        assert 0 in seen and len(QUESTION_LINES) in seen and len(seen) > 2

    def test_at_the_room_the_claims_alone_fill_the_chunk_is_the_one_sent_before(self) -> None:
        sets = h.with_questions()
        before = self._length(h.without_questions(sets))
        (dev,) = _shown("static", h.without_questions(sets), before, sandbox_report=self.REPORT)
        (now,) = _shown("static", sets, before, sandbox_report=self.REPORT)
        assert now == dev
        assert json.loads(now)["upstream_findings"] == CLAIMS
