"""A request joined to an accepted one is told when and how that detonation is read.

In the accepted answer's own clauses: the step it is carried out on entry
of, the further turn only where one is ahead for the joining agent (an
analysis agent that reads the sandbox, while the debate's first negotiation
is still ahead), and how to read it with the sandbox tools. Read from the
team's shape, on the default team. Every value is made up.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.core.config import Settings
from malspark.providers.detonation import DetonationRecord
from malspark.providers.detonation_requests import (
    ACCEPTED,
    FURTHER_TURN_PROMISE,
    JOINED,
    file_request,
)
from malspark.providers.submission import LaunchArgumentsAnswer

READ = "Read it with the sandbox tools' detonation argument (d2)."


class _Provider:
    id = "sbx-any"
    capabilities = SimpleNamespace(can_submit=True, can_pass_launch_arguments=True)

    def launch_arguments_answer(self, arguments: str, sample_path: Any = None) -> Any:
        return LaunchArgumentsAnswer(honoured=True, via="arguments=")


def _job(step: str) -> Any:
    settings = Settings()
    profile = settings.agents.profiles[settings.agents.profile]
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


def test_an_analyst_reading_the_sandbox_is_told_the_step_its_further_turn_and_the_read() -> None:
    job = _job("network_analyst")
    _reads_the_sandbox(job, "network")
    assert _joined(job, "network").answer == (
        "joined to d2, already accepted with exactly these arguments (asked for by dynamic, "
        "r1); it is one detonation, and its record names every agent that asked; it is "
        "carried out on entry of the next step of the run that has an agent reading the "
        f"sandbox (negotiation). {FURTHER_TURN_PROMISE}{READ}"
    )


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
    assert answer.endswith(f"sandbox (negotiation). {READ}"), why


def test_no_further_turn_is_promised_once_the_further_turns_were_given() -> None:
    job = _job("revision")
    _reads_the_sandbox(job, "network")
    first = _ask(job, "dynamic")
    job._further_turns_given = True
    second = _ask(job, "network")
    assert first.state == ACCEPTED and second.state == JOINED
    assert FURTHER_TURN_PROMISE not in second.answer
    assert second.answer.endswith(f"sandbox (negotiation). {READ}")
