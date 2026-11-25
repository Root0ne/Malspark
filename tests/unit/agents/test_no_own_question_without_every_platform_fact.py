"""The own question opens on platform facts alone, and not when any one of them is missing.

Where the agent's own marked question, a held tool of the related kind, the
absence of a request of its own, a claim or a written answer, or the stage
answer itself is missing, nothing is asked and nothing is recorded. Where
those hold and the ceiling, the job's time, the tools' binding, the loop's
steps or its time does not, nothing is asked and the loop's record says why.
Every value is made up.
"""

from __future__ import annotations

import re
import time
from typing import Any
from unittest.mock import patch

import pytest

from malspark.agents.base_agent import BaseAnalyst
from malspark.agents.own_question import OWN_QUESTION_RECORD
from malspark.providers.detonation_requests import ACCEPTED, REFUSED, DetonationRequest
from malspark.providers.sandbox_tools import _request_tools
from malspark.schemas.isr_models import OpenQuestion

from .holder_shapes import (
    CannotBind,
    Holder,
    Provider,
    Scripted,
    a_tool_named,
    answer,
    container,
    held_tool,
    marked,
)


@pytest.fixture(autouse=True)
def _a_negotiation_is_ahead(monkeypatch: pytest.MonkeyPatch) -> None:
    from malspark.pipeline import detonations

    monkeypatch.setattr(detonations, "later_reading_step", lambda c, s: "negotiation")
    monkeypatch.setattr(detonations, "further_turn_ahead", lambda c, s: True)


@pytest.fixture(autouse=True)
def _the_window_holds_it() -> Any:
    with patch.object(BaseAnalyst, "_fits_the_window", lambda *_a: True):
        yield


def _request(job: Any, agent: str, state: str, name: str = "") -> None:
    job.detonation_requests.append(
        DetonationRequest(
            number=len(job.detonation_requests) + 1,
            agent=agent,
            stage="dynamic",
            arguments=f"--key {len(job.detonation_requests)}",
            reason="found",
            cited_entries=["ev_0002"],
            state=state,
            detonation=name,
        )
    )


def _run(agent: Holder, checked: Any) -> Any:
    before = [dict(r) for r in agent._budget_records]
    returned = BaseAnalyst._with_own_question(agent, checked, "the raw data")
    assert returned is checked
    return before


def _holder(job: Any = None, tools: Any = None, model: type[Scripted] = Scripted) -> Holder:
    job = job or container()
    llm = model(script=["No."], seen=[])
    return Holder(llm, [held_tool(job)] if tools is None else tools(job), job)


class TestNothingAskedNothingRecorded:
    @pytest.mark.parametrize(
        "shape",
        [
            "no marked question",
            "a callee's marked question",
            "no held tool of the kind",
            "an undeclared tool named like it",
            "a request of its own, refused",
            "a request of its own, accepted",
            "no claim and no written answer",
            "no container",
        ],
    )
    def test_the_shape_asks_nothing(self, shape: str) -> None:
        job = container()
        agent = _holder(job)
        checked = answer(marked())
        if shape == "no marked question":
            checked = answer(OpenQuestion(question="Which key?", why_open="obfuscated"))
        elif shape == "a callee's marked question":
            question = marked()
            question.source = "reverser"
            checked = answer(question)
        elif shape == "no held tool of the kind":
            agent.tools = [a_tool_named("read_any")]
        elif shape == "an undeclared tool named like it":
            agent.tools = [a_tool_named("request_detonation")]
        elif shape == "a request of its own, refused":
            _request(job, "dynamic", REFUSED)
        elif shape == "a request of its own, accepted":
            _request(job, "dynamic", ACCEPTED, "d2")
        elif shape == "no claim and no written answer":
            checked = answer(marked(), claims=False)
        elif shape == "no container":
            agent._container = None

        before = _run(agent, checked)

        assert agent.llm.seen == []
        assert agent._budget_records == before
        assert not hasattr(agent, "_own_question_asked_job")

    def test_a_question_the_buffer_still_holds_is_the_agent_s_own_too(self) -> None:
        agent = _holder()
        agent._open_questions_buffer = [marked()]
        _run(agent, answer())
        assert len(agent.llm.seen) == 1

    @pytest.mark.parametrize("job", ["mock", "ceiling one", "no provider", "cannot submit"])
    def test_a_job_that_hands_no_request_tool_asks_nothing(self, job: str) -> None:
        shapes = {
            "mock": lambda: container(mock=True),
            "ceiling one": lambda: container(ceiling=1),
            "no provider": lambda: _no_provider(),
            "cannot submit": lambda: container(provider=Provider(submits=False)),
        }
        built = shapes[job]()
        agent = _holder(built, tools=lambda j: _request_tools(j))
        assert agent.tools == []
        _run(agent, answer(marked()))
        assert agent.llm.seen == []

    def test_a_provider_nobody_declared_takes_part(self) -> None:
        from malspark.agents.prompt_fragments import SANDBOX_FAMILY, stamp_source

        built = container(provider=Provider("sbx-never-declared"))
        agent = _holder(
            built,
            tools=lambda j: stamp_source(_request_tools(j), SANDBOX_FAMILY, declared="sandbox"),
        )
        _run(agent, answer(marked()))
        assert len(agent.llm.seen) == 1


def _no_provider() -> Any:
    job = container()

    def _none() -> Any:
        raise RuntimeError("no sandbox provider is configured")

    job.get_sandbox_provider = _none
    return job


class TestNotAskedAndSaidWhy:
    def _said(self, agent: Holder) -> str:
        (row,) = [r for r in agent._budget_records if OWN_QUESTION_RECORD in r]
        record = row[OWN_QUESTION_RECORD]
        assert record["asked"] is False and agent.llm.seen == []
        assert not hasattr(agent, "_own_question_asked_job")
        return str(record["outcome"])

    def test_the_ceiling_reached(self) -> None:
        job = container()
        for name in ("d2", "d3", "d4"):
            _request(job, "reverser", ACCEPTED, name)
        agent = _holder(job)
        _run(agent, answer(marked()))
        assert self._said(agent) == "not asked: the job's ceiling of 4 detonations is reached"

    def test_the_job_s_time_cannot_hold_a_detonation(self) -> None:
        job = container(job_timeout=900)
        agent = _holder(job)
        agent.run_state_source = {"run_started_at": time.time() - 600}
        _run(agent, answer(marked()))
        assert re.fullmatch(
            r"not asked: the job's time limit leaves (299|300) seconds, and a detonation "
            r"may take 600",
            self._said(agent),
        )

    def test_a_model_that_cannot_bind_tools(self) -> None:
        agent = _holder(model=CannotBind)
        _run(agent, answer(marked()))
        assert self._said(agent) == "not asked: its model could not bind its tools"

    def test_too_few_steps_left(self) -> None:
        agent = _holder()
        agent._last_loop_steps_known, agent._last_loop_steps_left = True, 2
        _run(agent, answer(marked()))
        assert self._said(agent) == (
            "not asked: 2 step(s) of its loop were left, and a turn that may call a tool "
            "needs three"
        )

    def test_too_little_of_the_loop_s_time_left(self) -> None:
        agent = _holder()
        agent._last_loop_deadline = time.monotonic() + 5.0
        with patch.object(BaseAnalyst, "seconds_an_answer_needs", lambda _s: 60.0):
            _run(agent, answer(marked()))
        said = self._said(agent)
        assert said.startswith("not asked: ") and said.endswith(
            "s of the loop's time were left, and an answer needs 60s"
        )

    def test_a_conversation_the_window_cannot_hold(self) -> None:
        agent = _holder()
        with patch.object(BaseAnalyst, "_fits_the_window", lambda *_a: False):
            _run(agent, answer(marked()))
        assert "do not fit this model's window" in self._said(agent)


class TestOnlyTheStageAnswer:
    def test_a_revision_puts_no_own_question(self) -> None:
        agent = _holder()
        with (
            patch.object(BaseAnalyst, "_own_question_turn") as own,
            patch.object(Holder, "revise_isr", lambda self, *a: ("CLAIM: x", answer(marked()))),
            patch.object(BaseAnalyst, "_validate_isr", lambda self, isr, evidence: isr),
        ):
            agent.safe_revise_isr("raw", "own", {}, "feedback", 1)
        own.assert_not_called()

    def test_a_delegated_ask_puts_no_own_question(self) -> None:
        agent = _holder()
        with (
            patch.object(BaseAnalyst, "_own_question_turn") as own,
            patch.object(Holder, "execute_tool_loop", lambda self, *a, **k: "CLAIM: x"),
            patch.object(BaseAnalyst, "_validate_isr", lambda self, isr, evidence: isr),
        ):
            agent.answer_task("Read the routine at 0x1000.")
        own.assert_not_called()

    def test_a_salvaged_answer_puts_no_own_question(self) -> None:
        agent = _holder()
        with (
            patch.object(BaseAnalyst, "_own_question_turn") as own,
            patch.object(Holder, "_synthesise_from_answered_asks", lambda self: answer(marked())),
            patch.object(BaseAnalyst, "_validate_isr", lambda self, isr, evidence: isr),
        ):
            agent._salvaged_isr("the raw data")
        own.assert_not_called()

    def test_the_stage_answer_and_the_merged_chunked_answer_put_it(self) -> None:
        import ast
        from pathlib import Path

        import malspark.agents.base_agent as module

        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        callers = sorted(
            function.name
            for function in ast.walk(tree)
            if isinstance(function, ast.FunctionDef)
            and function.name != "_with_own_question"
            and any(
                isinstance(node, ast.Attribute) and node.attr == "_with_own_question"
                for node in ast.walk(function)
            )
        )
        assert callers == ["_analyze_chunks", "_analyze_isr_guarded"]
