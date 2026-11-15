"""A check that raises is recorded under the name it had before its place was recorded.

A round runs each check as one validator, and a validator that raises is named in
the run's record: the finding's subject and wording, the summary row, the
appendix line "checks that could not run". Wiring a round's checks to its schema
keeps each check where the round builds it, so those names are the ones a run
recorded before: the narrative's checks are lambdas of ``NarrativeAgent.generate``,
the question round's of ``answer_questions``. The expected texts are what the tree
before the wiring recorded.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import malspark.reporting.narrative_agent as narrative_agent
import malspark.reporting.question_round as question_round
from malspark.pipeline import validation
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity, TTPMapping

NARRATIVE_NAME = "NarrativeAgent.generate.<locals>.<lambda>"
QUESTION_NAME = "answer_questions.<locals>.<lambda>"
NARRATIVE_NAMES = [NARRATIVE_NAME] * 7 + ["technique_name_violations"] + [NARRATIVE_NAME] * 2
QUESTION_NAMES = [QUESTION_NAME] * 5


def _recommendation() -> dict[str, str]:
    return {
        "category": "firewall",
        "action": "Block it.",
        "rationale": "Seen.",
        "priority": "P0",
        "technique_id": "",
        "detection": "Alert.",
    }


ANSWER = json.dumps(
    {
        "executive_summary": "The sample is a loader that reaches its server over HTTPS and should "
        "be contained on every host it reached, with its domain blocked.",
        "key_findings": [
            {"text": "It resolves its imports at run time.", "evidence_ids": []},
            {"text": "It reaches its server over HTTPS.", "evidence_ids": []},
        ],
        "defensive_recommendations": [_recommendation()] * 3,
    }
)


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_type="pe"),
        ttp_mappings=[TTPMapping(technique_id="T1071.001", technique_name="n")],
    )


def _boom(*_a: Any, **_k: Any) -> Any:
    raise ValueError("secret answer text")


def _spy(module: Any, names: list[str]) -> None:
    real = module.retry_with_feedback

    async def spy(run: Any, messages: Any, validators: Any, **kw: Any) -> Any:
        names.extend(validation._validator_name(v) for v in validators)
        return await real(run, messages, validators, **kw)

    module.retry_with_feedback = spy


@pytest.mark.asyncio
async def test_the_narrative_loop_records_its_checks_under_the_names_they_had(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(narrative_agent, "narrative_capability_violations", _boom)
    names: list[str] = []
    _spy(narrative_agent, names)
    llm = MagicMock()
    structured = MagicMock()
    structured.ainvoke = AsyncMock(side_effect=Exception("no schema"))
    llm.with_structured_output.return_value = structured
    llm.ainvoke = AsyncMock(side_effect=[MagicMock(content=ANSWER), MagicMock(content=ANSWER)])
    agent = narrative_agent.NarrativeAgent(llm=llm)

    await agent.generate(_report())

    rows = [
        r for r in agent.validation_tally.unresolved if r["code"] == validation.CHECK_FAILED_CODE
    ]
    assert names == NARRATIVE_NAMES
    assert rows == [
        {
            "advisory": "true",
            "agent": "narrative",
            "asked": "false",
            "code": "validation.check_failed",
            "message": f"The check {NARRATIVE_NAME} could not run on this answer (ValueError); "
            "what it checks was not checked.",
            "subject": NARRATIVE_NAME,
        }
    ]


@pytest.mark.asyncio
async def test_the_question_round_records_its_checks_under_the_names_they_had(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from langchain_core.messages import AIMessage

    monkeypatch.setattr(question_round, "citation_violations", _boom)
    names: list[str] = []
    _spy(question_round, names)

    class Reporter:
        async def ask(self, turns: Any, *, call: str, what: str) -> Any:
            reply = {
                "question": 1,
                "outcome": "not_determinable",
                "answer": "Said.",
                "evidence_ids": [],
            }
            return AIMessage(content=json.dumps({"answers": [reply]}))

    out = await question_round.answer_questions(Reporter(), _report(), ["What is it?"])

    rows = [r for r in out.tally.unresolved if r["code"] == validation.CHECK_FAILED_CODE]
    assert names == QUESTION_NAMES
    assert rows == [
        {
            "advisory": "true",
            "agent": "questions",
            "asked": "false",
            "code": "validation.check_failed",
            "message": f"The check {QUESTION_NAME} could not run on this answer (ValueError); "
            "what it checks was not checked.",
            "subject": QUESTION_NAME,
        }
    ]
