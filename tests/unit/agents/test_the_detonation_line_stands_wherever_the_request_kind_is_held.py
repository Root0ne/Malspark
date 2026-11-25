"""The job's detonations stand in the run state of every agent holding a tool of the request kind.

Read through each held tool's declared kind, never its name: a tool of the
kind under another name carries the line, a tool named like it that nothing
declared does not, and an agent holding none reads the run state exactly as
before. The line is built again at every turn, so a request accepted in one
turn shows from the next. Every value is made up.
"""

from __future__ import annotations

from types import SimpleNamespace

from malspark.agents.base_agent import current_run_state
from malspark.providers.detonation_requests import REQUEST_TOOL, detonations_line, file_request
from malspark.providers.sandbox_tools import _request_tools

from .holder_shapes import BRIEFED, Holder, Scripted, a_tool_named, container, held_tool


def _agent(tools: list[object], job: object) -> Holder:
    return Holder(Scripted(script=[], seen=[]), tools, job)


def test_a_holder_reads_the_line_after_its_run_state() -> None:
    job = container()
    agent = _agent([a_tool_named("read_any"), held_tool(job)], job)
    assert current_run_state(agent) == f"{BRIEFED}\n{detonations_line(job)}"


def test_a_tool_of_the_kind_under_another_name_carries_it() -> None:
    job = container()
    agent = _agent([held_tool(job, name="ask_for_another_run")], job)
    assert current_run_state(agent).endswith(detonations_line(job))


def test_an_agent_holding_no_tool_of_the_kind_reads_its_run_state_as_before() -> None:
    job = container()
    for tools in ([], [a_tool_named("read_any")], [a_tool_named(REQUEST_TOOL)]):
        assert current_run_state(_agent(tools, job)) == BRIEFED


def test_a_job_that_offers_no_request_gives_no_tool_and_so_no_line() -> None:
    for job in (container(mock=True), container(ceiling=1)):
        tools = _request_tools(job)
        assert tools == []
        assert current_run_state(_agent(tools, job)) == BRIEFED


def test_a_provider_nobody_declared_takes_part_through_the_kind() -> None:
    from .holder_shapes import Provider

    job = container(provider=Provider("sbx-never-declared"))
    tools = _request_tools(job)
    assert [t.name for t in tools] == [REQUEST_TOOL]
    from malspark.agents.prompt_fragments import SANDBOX_FAMILY, stamp_source

    agent = _agent(stamp_source(tools, SANDBOX_FAMILY, declared="sandbox"), job)
    assert current_run_state(agent).endswith(detonations_line(job))


def test_a_request_accepted_shows_from_the_next_turn(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from malspark.pipeline import detonations

    monkeypatch.setattr(detonations, "later_reading_step", lambda c, s: "negotiation")
    job = container()
    agent = _agent([held_tool(job)], job)
    before = current_run_state(agent)
    file_request(
        job, agent="dynamic", arguments="--key k1", reason="found", cited_entries=["ev_0002"]
    )
    after = current_run_state(agent)
    assert "accepted, not carried out yet" not in before
    assert after.endswith(
        "d2, asked for by dynamic (r1) with `--key k1`: accepted, not carried out yet"
    )
    assert "can accept 2 more" in after


def test_a_line_that_cannot_be_built_is_left_out() -> None:
    job = container()
    agent = _agent([held_tool(job)], job)
    agent._container = SimpleNamespace(detonations=None, detonation_requests=[object()])
    assert current_run_state(agent) == BRIEFED
