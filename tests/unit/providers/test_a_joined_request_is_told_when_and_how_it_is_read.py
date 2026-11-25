"""A request joined to an accepted one is told when and how that detonation is read.

In the accepted answer's own clauses: it is carried out on entry of the next
step of the run that has an agent reading the sandbox, with no step named
(on a team whose steps branch, the step the joining agent would reach is not
always the one that carries it out); the further turn only where one is
ahead for the joining agent (an analysis agent that reads the sandbox, while
the debate's first negotiation is still ahead); and how to read it with the
sandbox tools. Read from the team's shape. Every value is made up.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.core.config import ProfileDefinition, Settings, StageDefinition
from malspark.pipeline import detonations as dt
from malspark.providers.detonation import DetonationRecord
from malspark.providers.detonation_requests import (
    ACCEPTED,
    FURTHER_TURN_PROMISE,
    JOINED,
    file_request,
)
from malspark.providers.submission import LaunchArgumentsAnswer

READ = "Read it with the sandbox tools' detonation argument (d2)."
CARRIED = (
    "it is carried out on entry of the next step of the run that has an agent reading the sandbox. "
)


class _Provider:
    id = "sbx-any"
    capabilities = SimpleNamespace(can_submit=True, can_pass_launch_arguments=True)

    def launch_arguments_answer(self, arguments: str, sample_path: Any = None) -> Any:
        return LaunchArgumentsAnswer(honoured=True, via="arguments=")


def _job(step: str, profile: Any = None) -> Any:
    settings = Settings()
    profile = profile or settings.agents.profiles[settings.agents.profile]
    return SimpleNamespace(
        config=settings,
        active_profile=lambda: profile,
        _agent_cache={},
        is_mock=False,
        sample_path="/samples/given.bin",
        get_sandbox_provider=_Provider,
        get_evidence_counter=lambda: SimpleNamespace(issued=10),
        detonations=[DetonationRecord(report={})],
        detonation_requests=[],
        current_step=step,
    )


def _reads_the_sandbox(job: Any, agent: str) -> None:
    """``agent`` built with a tool of the sandbox source, as an agent holding the tool is."""
    from langchain_core.tools import StructuredTool

    from malspark.agents.prompt_fragments import SANDBOX_FAMILY, stamp_source

    tool = StructuredTool.from_function(func=lambda: {}, name="sandbox_items", description="x")
    job._agent_cache[agent] = SimpleNamespace(
        tools=stamp_source([tool], SANDBOX_FAMILY, declared="sandbox")
    )


def _ask(job: Any, agent: str) -> Any:
    return file_request(
        job,
        agent=agent,
        arguments="--key k1",
        reason="the routine compares its first argument with a stored word",
        cited_entries=["ev_0004"],
    )


def _joined(job: Any, agent: str) -> Any:
    first = _ask(job, "dynamic")
    assert first.state == ACCEPTED and first.detonation == "d2"
    assert FURTHER_TURN_PROMISE in first.answer
    second = _ask(job, agent)
    assert second.state == JOINED and second.detonation == "d2"
    return second


def test_an_analyst_reading_the_sandbox_is_told_when_its_further_turn_and_the_read() -> None:
    job = _job("network_analyst")
    _reads_the_sandbox(job, "network")
    assert _joined(job, "network").answer == (
        "joined to d2, already accepted with exactly these arguments (asked for by dynamic, "
        f"r1); it is one detonation, and its record names every agent that asked; {CARRIED}"
        f"{FURTHER_TURN_PROMISE}{READ}"
    )


def test_on_a_branching_team_the_joined_answer_names_no_step_and_holds() -> None:
    """Triage feeds two parallel steps; a third depends on the first; the debate on both.

    The detonation is carried out on entry of the third step, which the
    joining agent of the second never reaches: its answer names no step, and
    each of its sentences is true of the run.
    """
    profile = ProfileDefinition(
        stages=[
            StageDefinition(key="triage_pack", kind="triage"),
            StageDefinition(key="first", kind="analysis", agents=["dynamic"]),
            StageDefinition(key="second", kind="analysis", agents=["network"]),
            StageDefinition(key="third", kind="analysis", agents=["static"], depends_on=["first"]),
            StageDefinition(key="debate", kind="debate", depends_on=["third", "second"]),
            StageDefinition(key="verdict", kind="verdict", agents=["judge"], depends_on=["debate"]),
        ]
    )
    job = _job("dynamic_analyst", profile)
    for agent in ("dynamic", "network", "static"):
        _reads_the_sandbox(job, agent)
    first = _ask(job, "dynamic")
    assert first.state == ACCEPTED and "(static_analyst)" in first.answer
    job.current_step = "network_analyst"
    joined = _ask(job, "network")
    assert joined.state == JOINED and joined.detonation == "d2"
    assert joined.answer.endswith(f"asked; {CARRIED}{FURTHER_TURN_PROMISE}{READ}")
    for step in dt.steps_of(job):
        assert f"({step.name})" not in joined.answer
    # The next step of the run with a sandbox reader is the third, entered
    # before the debate, and it carries out every pending detonation ...
    assert [s.name for s in dt.carrying_steps(job, "dynamic_analyst")][0] == "static_analyst"
    assert "static_analyst" not in [s.name for s in dt.carrying_steps(job, "network_analyst")]
    # ... the joining analyst reads the sandbox and the debate is still ahead ...
    assert dt.given_further_turns(job, "network") and dt.further_turn_ahead(job, "network_analyst")
    # ... and the read names the detonation, not the joining request.
    assert "(r2)" not in joined.answer


@pytest.mark.parametrize(
    ("agent", "why"),
    [
        ("network", "an analysis agent that reads no sandbox"),
        ("judge", "an agent of no analysis step"),
    ],
)
def test_no_further_turn_is_promised_to_an_agent_that_is_given_none(agent: str, why: str) -> None:
    job = _job("network_analyst")
    if agent == "judge":
        _reads_the_sandbox(job, agent)
    answer = _joined(job, agent).answer
    assert FURTHER_TURN_PROMISE not in answer, why
    assert answer.endswith(f"{CARRIED}{READ}"), why


def test_no_further_turn_is_promised_once_the_further_turns_were_given() -> None:
    job = _job("revision")
    _reads_the_sandbox(job, "network")
    first = _ask(job, "dynamic")
    job._further_turns_given = True
    second = _ask(job, "network")
    assert first.state == ACCEPTED and second.state == JOINED
    assert FURTHER_TURN_PROMISE not in second.answer
    assert second.answer.endswith(f"{CARRIED}{READ}")


def test_an_agent_whose_further_turn_cannot_be_read_is_answered_without_the_promise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Where reading whether the joining agent is given a further turn fails, the answer
    promises none, and the request is still answered and joined."""
    from malspark.providers.detonation_requests import request_tool

    def _unreadable(container: Any, agent: str) -> bool:
        raise RuntimeError("the team cannot be read")

    job = _job("network_analyst")
    _reads_the_sandbox(job, "network")
    first = _ask(job, "dynamic")
    assert first.state == ACCEPTED and FURTHER_TURN_PROMISE in first.answer
    monkeypatch.setattr(dt, "given_further_turns", _unreadable)
    second = _ask(job, "network")
    assert second.state == JOINED and second.detonation == "d2"
    assert FURTHER_TURN_PROMISE not in second.answer
    assert second.answer.endswith(f"asked; {CARRIED}{READ}")
    # Through the tool as an agent calls it: answered, not failed.
    said = request_tool(job).invoke(
        {
            "arguments": "--key k1",
            "reason": "the routine compares its first argument with a stored word",
            "cited_entries": ["ev_0004"],
        }
    )
    assert job.detonation_requests[-1].state == JOINED
    assert FURTHER_TURN_PROMISE not in str(said) and "joined to d2" in str(said)
