"""An analyst holding the request tool is asked once about the questions it marked as needing a run.

After its stage answer is validated and settled, over its own conversation
with its tools: its own marked questions as it filed them, the tool it holds
by name, how many more detonations the job can accept and the tool's own
limits sentence. The reply is recorded and never read as the answer; a
request filed in it is on the job's record and takes the route every request
takes; nothing the turn raises loses the validated answer. Every value is
made up.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any
from unittest.mock import patch

import pytest

from malspark.agents.base_agent import BaseAnalyst
from malspark.agents.own_question import OWN_QUESTION_CALL, OWN_QUESTION_RECORD
from malspark.core.cancellation import JobCancelled
from malspark.providers.detonation_requests import ACCEPTED, FURTHER_TURN_PROMISE, REQUEST_TOOL

from .holder_shapes import (
    LIMITS,
    Holder,
    Scripted,
    a_tool_named,
    answer,
    call,
    container,
    held_tool,
    last_question,
    marked,
)

OTHER = marked("Which child process writes the second file?")
EXPECTED = (
    "One more question, about your own answer; it is asked once.\n"
    "Your answer leaves 2 question(s) open that you marked as needing a sandbox run:\n"
    "- Does the sample write its note when started with an argument? | Why open: "
    "needs_sandbox_run | Detail: the run made had no argument | Would answer it: a sandbox "
    "run with the argument\n"
    "- Which child process writes the second file? | Why open: needs_sandbox_run | Detail: "
    "the run made had no argument | Would answer it: a sandbox run with the argument\n"
    "You hold request_detonation, which asks the platform for a further detonation of the "
    "sample with launch arguments; the job's record holds no request of yours. The job can "
    f"accept 3 more detonation(s). {LIMITS} The run state lists the job's detonations.\n"
    "Whether any of these questions calls for a further detonation, and with which "
    "arguments, is yours to decide; the platform makes no further detonation of its own. "
    "This reply is recorded and is not read as your answer: you need not write your answer "
    "again. The tool's answer says when and how a detonation you request is read. Your tools "
    "are attached to this turn."
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


def _holder(script: list[Any], job: Any = None, **kw: Any) -> tuple[Holder, Scripted, Any]:
    job = job or container()
    llm = Scripted(script=list(script), seen=[])
    tools = [a_tool_named("read_any"), held_tool(job)]
    return Holder(llm, tools, job, **kw), llm, job


def _ask(agent: Holder, checked: Any) -> Any:
    return BaseAnalyst._with_own_question(agent, checked, "the raw data")


def _record(agent: Holder) -> dict[str, Any]:
    (row,) = [r for r in agent._budget_records if OWN_QUESTION_RECORD in r]
    return row[OWN_QUESTION_RECORD]


class TestAsked:
    def test_exactly_one_request_with_the_words_built_from_the_record(self) -> None:
        agent, llm, _job = _holder(["I leave them open."])
        checked = answer(marked(), OTHER)

        assert _ask(agent, checked) is checked
        assert len(llm.seen) == 1
        assert last_question(llm.seen) == EXPECTED
        assert llm.seen[0]["tools"] == ["read_any", REQUEST_TOOL]
        assert agent.token_ledger.by_call()["dynamic"][OWN_QUESTION_CALL]["calls"] == 1
        assert _record(agent) == {
            "asked": True,
            "questions": 2,
            "tools": [REQUEST_TOOL],
            "left": 3,
            "outcome": "asked; it filed no request",
            "requests": [],
            "calls": 0,
            "reply": "I leave them open.",
        }

    def test_its_run_state_lists_the_job_s_detonations(self) -> None:
        agent, llm, _job = _holder(["No."])
        _ask(agent, answer(marked()))
        humans = [m for m in llm.seen[0]["messages"] if m.type == "human"]
        assert "detonations: the job can accept 3 more" in str(humans[-1].content)

    def test_the_run_summary_carries_the_record_with_the_loop_s_others(self) -> None:
        from malspark.analysis.run_summary import RunSummaryBuilder

        agent, _llm, _job = _holder(["No."])
        _ask(agent, answer(marked()))
        budget = (
            RunSummaryBuilder(start_time=0.0)
            .set_budget({"dynamic": agent.drain_budget_records()})
            .build()
            .to_dict()["budget"]
        )
        (record,) = budget["dynamic"]["own_question"]
        assert record["outcome"] == "asked; it filed no request"

    def test_a_tool_of_the_kind_under_another_name_is_named_by_that_name(self) -> None:
        job = container()
        llm = Scripted(script=["No."], seen=[])
        agent = Holder(llm, [held_tool(job, name="ask_for_another_run")], job)
        _ask(agent, answer(marked()))
        assert "You hold ask_for_another_run, which asks" in last_question(llm.seen)

    def test_it_is_asked_once_per_agent_and_job(self) -> None:
        agent, llm, _job = _holder(["No.", "No."])
        _ask(agent, answer(marked()))
        _ask(agent, answer(marked()))
        assert len(llm.seen) == 1

    def test_two_holders_are_each_asked_their_own_once(self) -> None:
        job = container()
        first, first_llm, _ = _holder(["No."], job)
        second, second_llm, _ = _holder(["No."], job, name="network")
        _ask(first, answer(marked()))
        _ask(second, answer(marked("Does the traffic change with an argument?")))
        _ask(first, answer(marked()))
        assert len(first_llm.seen) == len(second_llm.seen) == 1
        assert "Does the traffic change" in last_question(second_llm.seen)

    def test_it_opens_on_the_stage_answer_path(self) -> None:
        agent, llm, _job = _holder(["No."])
        checked = answer(marked())
        with (
            patch.object(Holder, "analyze_isr", lambda self, data: checked),
            patch.object(BaseAnalyst, "_validate_isr", lambda self, isr, evidence: isr),
        ):
            assert agent._analyze_isr_guarded("the raw data") is checked
        assert len(llm.seen) == 1

    def test_an_answer_salvaged_inside_the_loop_is_the_stage_answer_and_is_asked(self) -> None:
        from malspark.schemas.isr_models import AgentISR

        agent, llm, _job = _holder(["No."])
        salvaged = answer(marked())
        empty = AgentISR(agent_id="dynamic", domain="dynamic", claims=[])
        with (
            patch.object(Holder, "analyze_isr", lambda self, data: empty),
            patch.object(Holder, "_synthesise_from_answered_asks", lambda self: salvaged),
            patch.object(BaseAnalyst, "_validate_isr", lambda self, isr, evidence: isr),
        ):
            assert agent._analyze_isr_guarded("the raw data") is salvaged
        assert len(llm.seen) == 1
        assert _record(agent)["outcome"] == "asked; it filed no request"


class TestTheJobIsMarkedAsked:
    @pytest.mark.parametrize("files", [False, True])
    def test_once_the_question_reached_the_model_filed_or_not(self, files: bool) -> None:
        script: list[Any] = [call(REQUEST_TOOL, "--key k1"), "Filed."] if files else ["No."]
        agent, _llm, job = _holder(script)
        _ask(agent, answer(marked()))
        assert len(job.detonation_requests) == (1 if files else 0)
        assert agent._own_question_asked_job == "job-1"

    def test_a_question_that_never_reached_the_model_is_asked_with_a_later_stage_answer(
        self,
    ) -> None:
        agent, llm, _job = _holder(["No."])
        with patch.object(BaseAnalyst, "_answer_after_loop", side_effect=TimeoutError("cap")):
            _ask(agent, answer(marked()))
        assert llm.seen == [] and not hasattr(agent, "_own_question_asked_job")
        _ask(agent, answer(marked()))
        assert len(llm.seen) == 1
        assert agent._own_question_asked_job == "job-1"


class TestTheAnswerInForceStands:
    def test_a_reply_with_another_answer_changes_nothing(self) -> None:
        reply = (
            "CLAIM 1: the sample deletes itself\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.9\n"
            "TECHNIQUE: NONE\n---\nWITHDRAW 1\n```json\n"
            '{"findings": [{"claim": "x"}], "open_questions": [{"question": "y", '
            '"why_open": "other"}]}\n```'
        )
        agent, _llm, _job = _holder([reply])
        checked = answer(marked())
        before = copy.deepcopy(checked)
        buffers = (
            list(agent._findings_buffer),
            list(agent._artifacts_buffer),
            list(agent._open_questions_buffer),
        )

        assert _ask(agent, checked) is checked
        assert checked == before
        assert (
            agent._findings_buffer,
            agent._artifacts_buffer,
            agent._open_questions_buffer,
        ) == buffers

    def test_what_a_tool_of_the_turn_writes_to_the_buffers_and_the_cut_note_is_undone(
        self,
    ) -> None:
        from langchain_core.tools import StructuredTool

        job = container()
        llm = Scripted(script=[{"name": "scribble", "args": {}, "id": "s1"}, "Done."], seen=[])
        ran: list[str] = []
        agent = Holder(llm, [], job)

        def _scribble() -> str:
            ran.append("scribble")
            agent._findings_buffer.append({"claim": "written in the turn"})
            agent._artifacts_buffer.append({"artifact": "written in the turn"})
            agent._open_questions_buffer.append(marked("Written in the turn?"))
            agent._last_answer_cut = None
            agent._last_answer_ended = False
            return "written"

        scribble = StructuredTool.from_function(
            func=_scribble, name="scribble", description="Any tool."
        )
        agent.tools = [scribble, held_tool(job)]
        agent._findings_buffer = [{"claim": "the stage's"}]
        agent._artifacts_buffer = [{"artifact": "the stage's"}]
        agent._open_questions_buffer = [marked()]
        agent._last_answer_cut = (512, "the stage answer's cut text")
        agent._last_answer_ended = True
        checked = answer(marked())

        assert _ask(agent, checked) is checked
        assert ran == ["scribble"]
        assert agent._findings_buffer == [{"claim": "the stage's"}]
        assert agent._artifacts_buffer == [{"artifact": "the stage's"}]
        assert agent._open_questions_buffer == [marked()]
        assert agent._last_answer_cut == (512, "the stage answer's cut text")
        assert agent._last_answer_ended is True

    def test_a_failure_while_the_question_is_built_returns_the_same_answer(self) -> None:
        from malspark.providers import detonation_requests

        agent, llm, _job = _holder(["No."])
        checked = answer(marked())
        before = copy.deepcopy(checked)
        with patch.object(
            detonation_requests, "limits_sentence", side_effect=RuntimeError("unreadable")
        ):
            assert _ask(agent, checked) is checked
        assert checked == before
        assert llm.seen == []

    @pytest.mark.parametrize(
        "failure", [TimeoutError("the hard cap"), RuntimeError("the transport closed")]
    )
    def test_a_failure_in_the_turn_leaves_the_validated_answer_and_is_recorded(
        self, failure: BaseException
    ) -> None:
        agent, _llm, _job = _holder([failure])
        checked = answer(marked())
        before = copy.deepcopy(checked)

        assert _ask(agent, checked) is checked
        assert checked == before
        record = _record(agent)
        assert record["asked"] is True
        assert record["outcome"].startswith("asked; no answer came (")

    def test_a_failure_before_any_request_is_recorded_as_not_asked(self) -> None:
        agent, llm, _job = _holder([])
        checked = answer(marked())
        with patch.object(BaseAnalyst, "_answer_after_loop", side_effect=TimeoutError("cap")):
            assert _ask(agent, checked) is checked
        assert llm.seen == []
        assert _record(agent)["outcome"].startswith("not asked: TimeoutError")

    def test_the_job_s_cancellation_goes_on(self) -> None:
        agent, _llm, _job = _holder([])
        with (
            patch.object(BaseAnalyst, "_answer_after_loop", side_effect=JobCancelled("stop")),
            pytest.raises(JobCancelled),
        ):
            _ask(agent, answer(marked()))


class TestARequestFiledInIt:
    def test_it_is_recorded_and_takes_the_route_a_stage_request_takes(self) -> None:
        from malspark.pipeline import detonations as dt

        agent, _llm, job = _holder([call(REQUEST_TOOL, "--key k1"), "Filed."])
        checked = answer(marked())

        assert _ask(agent, checked) is checked
        (request,) = job.detonation_requests
        assert (request.name, request.agent, request.stage) == ("r1", "dynamic", "dynamic")
        assert request.state == ACCEPTED and request.detonation == "d2"
        assert "(negotiation)" in request.answer and FURTHER_TURN_PROMISE in request.answer
        record = _record(agent)
        assert record["outcome"] == "asked; it filed request r1 (accepted as d2)"
        assert record["requests"] == ["r1"] and record["calls"] == 1
        assert [e.tool for e in agent._evidence_entries] == [REQUEST_TOOL]

        # Carried out on the negotiation's entry, as a request of the stage loop is.
        async def _detonate(record: Any) -> None:
            record.report = {"behavior": {"processes": []}}
            record.submit_returned = True
            record.launch = {"honoured": True}

        job.detonator = _detonate
        job.event_sink = lambda kind, data: None
        (made,) = asyncio.run(dt.carry_out(job, {}, "negotiation"))
        assert made.name == "d2" and made.reported
        assert [a["agent"] for a in made.requested_by] == ["dynamic"]

    def test_a_request_with_no_reply_text_after_it_is_recorded_as_filed(self) -> None:
        agent, _llm, job = _holder([call(REQUEST_TOOL, "--key k1"), ""])
        checked = answer(marked())

        assert _ask(agent, checked) is checked
        assert [r.name for r in job.detonation_requests] == ["r1"]
        outcome = _record(agent)["outcome"]
        assert outcome.startswith(
            "asked; it filed request r1 (accepted as d2); no answer text came ("
        )
