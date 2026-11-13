"""The request tool's answer is true for every team shape.

Where a request can still be carried out is reachability in the graph, read
from the step the request was filed in, held per context so steps running at
once never read each other's; a first negotiation that will still give the
further turns carries a request out for them; and the sentence promising a
further turn is said only where that turn is still ahead. Offline.
"""

from __future__ import annotations

import asyncio
import contextvars
from types import SimpleNamespace
from typing import Any

import pytest

from malspark.core.config import ProfileDefinition, Settings, StageDefinition
from malspark.pipeline import detonations as dt
from malspark.providers import detonation_requests as dr
from malspark.providers.detonation import DetonationRecord
from malspark.schemas.evidence import EvidenceCounter


def _team(stages: list[StageDefinition], *, judge_reads: bool = True) -> Any:
    settings = Settings()
    profile = ProfileDefinition(stages=stages)
    if not judge_reads:
        judge = settings.agents.definitions["judge"]
        settings.agents.definitions["judge"] = judge.model_copy(
            update={"tools": [ref for ref in judge.tools if ref.kind != "sandbox"]}
        )
    counter = EvidenceCounter()
    counter.next_id()
    return SimpleNamespace(
        config=settings,
        active_profile=lambda: profile,
        _agent_cache={},
        event_sink=None,
        detonations=[DetonationRecord(report={})],
        detonation_requests=[],
        detonator=None,
        detonations_seen={},
        further_turns=[],
        current_step="",
        get_evidence_counter=lambda: counter,
    )


TRIAGE = StageDefinition(key="triage_pack", kind="triage")
ANALYSIS = StageDefinition(
    key="analysis", kind="analysis", agents=["static", "dynamic"], mode="sequential"
)
DEBATE = StageDefinition(key="debate", kind="debate", depends_on=["analysis"])
VERDICT_AFTER_DEBATE = StageDefinition(
    key="verdict", kind="verdict", agents=["judge"], depends_on=["debate"]
)
VERDICT_AFTER_ANALYSIS = StageDefinition(
    key="verdict", kind="verdict", agents=["judge"], depends_on=["analysis"]
)


def _file(container: Any, agent: str = "dynamic") -> dr.DetonationRequest:
    return dr.file_request(
        container, agent=agent, arguments="-p x", reason="found", cited_entries=["ev_0001"]
    )


@pytest.fixture(autouse=True)
def _can_detonate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dr, "_cannot_detonate", lambda container, arguments: "")


class TestATeamWithoutDebate:
    def test_the_answer_promises_no_further_turn(self) -> None:
        container = _team([TRIAGE, ANALYSIS, VERDICT_AFTER_ANALYSIS])
        token = dt._CURRENT_STEP.set("dynamic_analyst")
        try:
            request = _file(container)
        finally:
            dt._CURRENT_STEP.reset(token)
        assert request.state == dr.ACCEPTED
        assert "on entry of the next step of the run that has an agent reading the sandbox " in (
            request.answer
        )
        assert "(judge)" in request.answer
        assert dr.FURTHER_TURN_PROMISE.strip() not in request.answer


class TestAJudgeThatHoldsNoSandboxSource:
    STAGES = [TRIAGE, ANALYSIS, DEBATE, VERDICT_AFTER_DEBATE]

    def test_the_last_analyst_s_request_is_accepted_for_the_further_turn(self) -> None:
        container = _team(self.STAGES, judge_reads=False)
        assert dt.later_reading_step(container, "dynamic_analyst") == "negotiation"
        token = dt._CURRENT_STEP.set("dynamic_analyst")
        try:
            request = _file(container)
        finally:
            dt._CURRENT_STEP.reset(token)
        assert request.state == dr.ACCEPTED
        assert "(negotiation)" in request.answer
        assert dr.FURTHER_TURN_PROMISE in request.answer

    def test_the_first_negotiation_carries_it_out_though_its_mediator_reads_nothing(
        self,
    ) -> None:
        container = _team(self.STAGES, judge_reads=False)
        carried: list[str] = []

        async def _detonate(record: DetonationRecord) -> None:
            carried.append(record.name)

        container.detonator = _detonate
        token = dt._CURRENT_STEP.set("dynamic_analyst")
        try:
            _file(container)
        finally:
            dt._CURRENT_STEP.reset(token)

        async def negotiation(state: Any) -> dict[str, Any]:
            return {}

        entered = dt.on_entry(
            container, "negotiation", negotiation, reading_agents=("judge",), first_negotiation=True
        )
        asyncio.run(entered({}))
        assert carried == ["d2"]

    def test_after_the_turns_were_given_a_request_is_too_late_and_promises_nothing(
        self,
    ) -> None:
        container = _team(self.STAGES, judge_reads=False)
        container._further_turns_given = True
        token = dt._CURRENT_STEP.set("negotiation")
        try:
            request = _file(container)
        finally:
            dt._CURRENT_STEP.reset(token)
        assert request.state == dr.REFUSED and request.answer == dr.NO_LATER_STEP

    def test_a_request_in_a_further_turn_promises_no_second_one(self) -> None:
        container = _team(self.STAGES)
        container._further_turns_given = True
        token = dt._CURRENT_STEP.set("negotiation")
        try:
            request = _file(container)
        finally:
            dt._CURRENT_STEP.reset(token)
        assert request.state == dr.ACCEPTED and "(judge)" in request.answer
        assert dr.FURTHER_TURN_PROMISE.strip() not in request.answer


class TestTwoParallelStages:
    """Two stages that both depend only on the triage step: neither is after the other."""

    STAGES = [
        TRIAGE,
        StageDefinition(key="first", kind="analysis", agents=["static"]),
        StageDefinition(key="second", kind="analysis", agents=["dynamic"]),
        StageDefinition(
            key="verdict", kind="verdict", agents=["judge"], depends_on=["first", "second"]
        ),
    ]

    def test_a_stage_running_beside_is_not_later(self) -> None:
        container = _team(self.STAGES)
        # ``dynamic`` reads the sandbox and runs beside ``static``, not after it.
        assert dt.later_reading_step(container, "static_analyst") == "judge"
        assert dt.later_reading_step(container, "triage_pack") == "dynamic_analyst"

    def test_each_step_running_at_once_reads_its_own_step(self) -> None:
        container = _team(self.STAGES)
        seen: dict[str, str] = {}
        both = asyncio.Event()

        def _node(label: str) -> Any:
            async def node(state: Any) -> dict[str, Any]:
                seen[f"{label}:before"] = dt.current_step(container)
                if len(seen) >= 2:
                    both.set()
                await asyncio.wait_for(both.wait(), 5)
                # A tool call runs on a thread with the step's context copied.
                ctx = contextvars.copy_context()
                seen[label] = await asyncio.to_thread(ctx.run, dt.current_step, container)
                return {}

            return node

        first = dt.on_entry(container, "static_analyst", _node("static"))
        second = dt.on_entry(container, "dynamic_analyst", _node("dynamic"))

        async def main() -> None:
            await asyncio.gather(first({}), second({}))

        asyncio.run(main())
        assert seen["static"] == "static_analyst"
        assert seen["dynamic"] == "dynamic_analyst"
        assert seen["static:before"] == "static_analyst"
        assert seen["dynamic:before"] == "dynamic_analyst"
