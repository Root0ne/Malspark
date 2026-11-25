"""The request for a further detonation says, of the entries it cites, exactly what it checks.

``cited_entries`` names the ledger entries the arguments rest on, whichever
call filed them; the tool checks that at least one is given and that each was
issued earlier in the run, and nothing else about them. Its description, its
schema and its refusal for a request that cites none say that one rule, and
no text says the arguments must be the asking agent's own finding. Every
value is made up.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.utils.function_calling import convert_to_openai_tool

from malspark.llm.context_window import answering_for
from malspark.providers.detonation import DetonationRecord
from malspark.providers.detonation_requests import (
    ACCEPTED,
    REFUSED,
    REFUSED_NO_CITATIONS,
    REFUSED_UNISSUED,
    file_request,
    request_tool,
)
from malspark.providers.submission import LaunchArgumentsAnswer

DESCRIPTION = (
    "Ask for a further detonation of the sample, started with launch arguments (a password "
    "the sample checks, an installer switch). ``arguments`` is one command line as typed after "
    "the program's name; ``reason`` says why; ``cited_entries`` are the ledger entries (ev_…) "
    "the arguments rest on, whichever call filed them (yours, another agent's or the "
    "platform's): the platform checks that at least one is given and that each was issued "
    "earlier in this run, and nothing else about them. The tool detonates nothing itself: it "
    "answers whether the request is accepted, as which detonation (d2, d3…) and when it will "
    "be run, joined to an identical pending one, or refused and why. A request is carried out "
    "on entry of the next step of the run that has an agent reading the sandbox, so it can be "
    "made while such a step is still ahead (during the analysis and the debate); one made "
    "after the last of them began is refused as too late. A detonation already made is "
    "compared on its exact launch text: the pack shows a later detonation's launch text "
    "escaped, and the exact text is the launched_with of any read of that detonation. Limits "
    "of the sandbox: at most 4 detonations per job, the job's own included; each one takes up "
    "to 600 seconds of the sbx-any sandbox's time and its quota. Each submission sends the "
    "sample to the sandbox, is disclosed in the run's record, and may be public on that "
    "service. The arguments are handed to the sandbox verbatim as the program's command line "
    "and are never run on this machine."
)
NO_CITATIONS = (
    "cite as cited_entries the ledger entries (ev_…) these arguments rest on, whichever call "
    "filed them (yours, another agent's or the platform's): at least one, each issued earlier "
    "in this run"
)
# Words that would state a condition on the cited entries the checking code does not hold:
# whose finding the arguments are, what led to them, what the asker read or was shown.
UNCHECKED = (
    "your own analysis",
    "found by",
    "you found",
    "led you",
    "that led",
    "you read",
    "you were shown",
    "you have seen",
    "hold the arguments",
)


@pytest.fixture(autouse=True)
def _a_later_step_reads_the_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    from malspark.pipeline import detonations

    monkeypatch.setattr(detonations, "later_reading_step", lambda container, current: "judge")
    monkeypatch.setattr(detonations, "further_turn_ahead", lambda container, current: False)


class _Provider:
    id = "sbx-any"
    capabilities = SimpleNamespace(can_submit=True, can_pass_launch_arguments=True)

    def launch_arguments_answer(self, arguments: str, sample_path: Any = None) -> Any:
        return LaunchArgumentsAnswer(honoured=True, via="arguments=")


def _container(issued: int = 10) -> Any:
    stages = [
        SimpleNamespace(key="reversing", agents=["reverser"]),
        SimpleNamespace(key="dynamic", agents=["dynamic"]),
    ]
    return SimpleNamespace(
        config=SimpleNamespace(
            sandbox=SimpleNamespace(
                provider="sbx-any",
                max_detonations_per_job=4,
                **{"sbx-any": SimpleNamespace(timeout_seconds=600)},
            )
        ),
        is_mock=False,
        sample_path="/samples/given.bin",
        get_sandbox_provider=_Provider,
        get_evidence_counter=lambda: SimpleNamespace(issued=issued),
        active_profile=lambda: SimpleNamespace(stages=stages),
        detonations=[DetonationRecord(report={})],
        detonation_requests=[],
    )


def _call(job: Any, args: dict[str, Any], agent: str = "dynamic") -> dict[str, Any]:
    """One call of the tool as a model makes it, under ``agent``."""
    with answering_for(agent):
        return request_tool(job).invoke(args)


def _parameters(tool: Any) -> dict[str, Any]:
    return convert_to_openai_tool(tool)["function"]["parameters"]


class TestTheSchema:
    def test_cited_entries_is_required_with_no_null_and_no_default(self) -> None:
        parameters = _parameters(request_tool(_container()))
        assert parameters["required"] == ["arguments", "reason", "cited_entries"]
        assert parameters["properties"]["cited_entries"] == {
            "anyOf": [{"items": {"type": "string"}, "type": "array"}, {"type": "string"}]
        }
        assert "null" not in json.dumps(parameters)

    def test_the_tool_an_agent_holds_under_another_name_keeps_it_required(self) -> None:
        from tests.unit.agents.holder_shapes import held_tool

        held = held_tool(_container(), name="ask_for_another_run")
        assert "cited_entries" in _parameters(held)["required"]

    def test_a_tool_a_loop_records_keeps_it_required(self) -> None:
        from malspark.agents.evidence_recorder import (
            ArgumentRepairs,
            EvidenceRecorder,
            RepeatGuard,
            record_tools,
        )
        from malspark.schemas.evidence import EvidenceCounter

        (recorded,) = record_tools(
            [request_tool(_container())],
            EvidenceRecorder("dynamic", counter=EvidenceCounter()),
            RepeatGuard(),
            ArgumentRepairs(),
            None,
        )
        assert "cited_entries" in _parameters(recorded)["required"]


class TestTheTexts:
    def test_the_description_states_the_rule_whole(self) -> None:
        assert request_tool(_container()).description == DESCRIPTION

    def test_the_refusal_for_no_citation_states_the_rule(self) -> None:
        assert REFUSED_NO_CITATIONS == NO_CITATIONS

    def test_the_refusal_for_an_unissued_id_keeps_its_words(self) -> None:
        assert REFUSED_UNISSUED == "these cited entries were not issued earlier in this run: {ids}"

    @pytest.mark.parametrize("which", ["description", "refusal"])
    def test_no_text_states_a_condition_the_check_does_not_hold(self, which: str) -> None:
        text = (
            request_tool(_container()).description
            if which == "description"
            else (REFUSED_NO_CITATIONS)
        )
        said = [words for words in UNCHECKED if words in text.lower()]
        assert said == []


class TestWhatTheCheckHolds:
    def test_another_agent_s_entry_of_the_job_is_accepted(self) -> None:
        answer = _call(
            _container(),
            {"arguments": "--key k1", "reason": "the compare", "cited_entries": ["ev_0004"]},
            agent="dynamic",
        )
        assert answer["state"] == ACCEPTED and answer["detonation"] == "d2"
        assert "whichever call filed them (yours, another agent's" in (
            request_tool(_container()).description
        )

    def test_an_entry_the_asker_never_read_or_wrote_is_accepted(self) -> None:
        job = _container(issued=3)
        request = file_request(
            job, agent="dynamic", arguments="--key k1", reason="r", cited_entries="ev_0001"
        )
        assert request.state == ACCEPTED and request.cited_entries == ["ev_0001"]

    @pytest.mark.parametrize(
        "args",
        [
            {"arguments": "--key k1", "reason": "r"},
            {"arguments": "--key k1", "reason": "r", "cited_entries": None},
            {"arguments": "--key k1", "reason": "r", "cited_entries": []},
            {"arguments": "--key k1", "reason": "r", "cited_entries": "no id here"},
        ],
    )
    def test_a_request_citing_none_is_refused_in_the_new_words_and_filed(
        self, args: dict[str, Any]
    ) -> None:
        job = _container()
        answer = _call(job, args)
        assert answer == {"request": "r1", "state": REFUSED, "answer": NO_CITATIONS}
        (request,) = job.detonation_requests
        assert request.state == REFUSED and request.answer == NO_CITATIONS

    def test_an_id_the_job_did_not_issue_is_refused_as_before(self) -> None:
        answer = _call(
            _container(issued=5),
            {"arguments": "--key k1", "reason": "r", "cited_entries": ["ev_0004", "ev_0099"]},
        )
        assert answer["state"] == REFUSED
        assert (
            answer["answer"] == "these cited entries were not issued earlier in this run: ev_0099"
        )
