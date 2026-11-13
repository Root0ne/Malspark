"""An agent asks for a further detonation, and the tool answers what will happen.

The ``request_detonation`` tool detonates nothing: it checks the request in
code and records it on the container, answered accepted (as which
detonation), joined to an identical pending one, or refused with the reason.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.llm.context_window import answering_for
from malspark.providers.detonation import AGENT_ORIGIN, DetonationRecord
from malspark.providers.detonation_requests import (
    ACCEPTED,
    JOINED,
    REFUSED,
    REQUEST_TOOL,
    file_request,
    request_tool,
)
from malspark.providers.submission import LaunchArgumentsAnswer, cannot_pass


class _Provider:
    id = "cape2"

    def __init__(self, *, passes: bool = True, submits: bool = True) -> None:
        self.passes = passes
        self.capabilities = SimpleNamespace(can_submit=submits, can_pass_launch_arguments=passes)

    def launch_arguments_answer(self, arguments: str, sample_path: Any = None) -> Any:
        if not self.passes:
            return cannot_pass(self.id)
        return LaunchArgumentsAnswer(honoured=True, via="arguments=")


def _container(
    *,
    provider: Any = None,
    issued: int = 10,
    ceiling: int = 4,
    mock: bool = False,
    first: DetonationRecord | None = None,
) -> Any:
    stages = [
        SimpleNamespace(key="reversing", agents=["reverser"]),
        SimpleNamespace(key="dynamic", agents=["dynamic", "network"]),
    ]
    return SimpleNamespace(
        config=SimpleNamespace(
            sandbox=SimpleNamespace(
                provider="cape2",
                max_detonations_per_job=ceiling,
                cape2=SimpleNamespace(timeout_seconds=600),
            )
        ),
        is_mock=mock,
        sample_path="/samples/locker.exe",
        get_sandbox_provider=lambda: provider or _Provider(),
        get_evidence_counter=lambda: SimpleNamespace(issued=issued),
        active_profile=lambda: SimpleNamespace(stages=stages),
        detonations=[first or DetonationRecord(report={})],
        detonation_requests=[],
    )


def _ask(container: Any, arguments: str = "--password x", **kwargs: Any) -> Any:
    return file_request(
        container,
        agent=kwargs.pop("agent", "reverser"),
        arguments=arguments,
        reason=kwargs.pop("reason", "the binary compares its first argument with x"),
        cited_entries=kwargs.pop("cited_entries", ["ev_0004"]),
    )


class TestAccepted:
    def test_a_request_is_accepted_as_the_next_detonation_and_recorded(self) -> None:
        container = _container()
        request = _ask(container)
        assert request.state == ACCEPTED
        assert request.detonation == "d2"
        assert request.stage == "reversing"
        assert container.detonation_requests == [request]
        assert "d2" in request.answer and "before the next stage" in request.answer
        assert request.asker()["cited_entries"] == ["ev_0004"]

    def test_each_distinct_request_is_its_own_detonation(self) -> None:
        container = _container()
        names = [_ask(container, f"--password {n}").detonation for n in "abc"]
        assert names == ["d2", "d3", "d4"]

    def test_cited_entries_may_be_one_text(self) -> None:
        request = _ask(_container(), cited_entries="ev_0002, EV_0003")
        assert request.state == ACCEPTED
        assert request.cited_entries == ["ev_0002", "ev_0003"]


class TestRefused:
    @pytest.mark.parametrize(
        ("arguments", "words"),
        [("a\nb", "not one command line"), ("   ", "not one command line")],
    )
    def test_a_value_that_is_not_one_command_line(self, arguments: str, words: str) -> None:
        request = _ask(_container(), arguments)
        assert request.state == REFUSED and words in request.answer

    def test_without_a_reason(self) -> None:
        request = _ask(_container(), reason=" ")
        assert request.state == REFUSED and "reason" in request.answer

    def test_without_cited_entries(self) -> None:
        request = _ask(_container(), cited_entries=[])
        assert request.state == REFUSED and "cited_entries" in request.answer

    def test_cited_entries_the_run_never_issued_are_named(self) -> None:
        request = _ask(_container(issued=5), cited_entries=["ev_0004", "ev_0099"])
        assert request.state == REFUSED
        assert request.answer.endswith("ev_0099")
        assert "ev_0004" not in request.answer

    def test_a_provider_that_cannot_pass_arguments(self) -> None:
        request = _ask(_container(provider=_Provider(passes=False)))
        assert request.state == REFUSED
        assert "cannot pass launch arguments" in request.answer
        assert request.detonation == ""

    def test_a_provider_that_detonates_nothing(self) -> None:
        request = _ask(_container(provider=_Provider(submits=False)))
        assert request.state == REFUSED and "detonates nothing" in request.answer

    def test_a_run_in_mock_mode(self) -> None:
        request = _ask(_container(mock=True))
        assert request.state == REFUSED and "mock mode" in request.answer

    def test_the_ceiling_counts_the_job_s_own_detonation(self) -> None:
        container = _container(ceiling=2)
        assert _ask(container, "-a").state == ACCEPTED
        refused = _ask(container, "-b")
        assert refused.state == REFUSED
        assert "ceiling of 2 detonations" in refused.answer
        assert "d1 (without arguments), d2 (with '-a')" in refused.answer

    def test_an_identical_detonation_already_made_is_named(self) -> None:
        container = _container()
        container.detonations.append(
            DetonationRecord(
                ordinal=2,
                origin=AGENT_ORIGIN,
                arguments="--password x",
                launch={"honoured": True},
                report={},
            )
        )
        request = _ask(container)
        assert request.state == REFUSED
        assert request.detonation == "d2"
        assert "already launched with exactly these arguments" in request.answer

    def test_the_job_s_own_arguments_name_the_first_detonation(self) -> None:
        first = DetonationRecord(arguments="--password x", launch={"honoured": True}, report={})
        request = _ask(_container(first=first))
        assert request.state == REFUSED and request.detonation == "d1"

    def test_the_job_s_own_arguments_not_passed_are_no_detonation_with_them(self) -> None:
        first = DetonationRecord(arguments="--password x", launch={"honoured": False})
        assert _ask(_container(first=first)).state == ACCEPTED


class TestJoined:
    def test_an_identical_pending_request_is_one_detonation(self) -> None:
        container = _container()
        first = _ask(container, agent="reverser")
        second = _ask(container, agent="judge")
        assert second.state == JOINED
        assert second.detonation == first.detonation == "d2"
        assert "reverser" in second.answer and "r1" in second.answer
        # A joined request takes no place under the ceiling.
        assert _ask(container, "-other").detonation == "d3"


class TestTheTool:
    def test_it_answers_and_names_the_agent_whose_call_it_is(self) -> None:
        container = _container()
        tool = request_tool(container)
        assert tool.name == REQUEST_TOOL
        with answering_for("network"):
            answer = tool.invoke(
                {"arguments": "-x", "reason": "a switch", "cited_entries": ["ev_0001"]}
            )
        assert answer["state"] == ACCEPTED and answer["detonation"] == "d2"
        assert container.detonation_requests[0].agent == "network"
        assert container.detonation_requests[0].stage == "dynamic"

    def test_its_description_states_the_sandbox_s_limits(self) -> None:
        description = request_tool(_container(ceiling=3)).description
        assert "at most 3 detonations per job, the job's own included" in description
        assert "600 seconds of the cape2 sandbox's time" in description
        assert "may be public" in description
        assert "never run on this machine" in description
