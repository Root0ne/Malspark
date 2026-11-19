"""A check that raises is recorded under the name it had before its place was recorded.

A round runs each check as one validator, and a validator that raises is named in
the run's record: the finding's subject and wording, the summary row, the
appendix line "checks that could not run". Wiring a round's checks to its schema
keeps each check where the round builds it, so those names are the ones a run
recorded before: the narrative's checks are lambdas of ``NarrativeAgent.generate``,
the question round's of ``answer_questions``, and a composer section's checks run
in its one validator, ``_validate`` of ``ReportComposer._invoke``. The expected
texts are what the tree before the wiring recorded.
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
NARRATIVE_NAMES = [NARRATIVE_NAME] * 8 + ["technique_name_violations"] + [NARRATIVE_NAME] * 2
QUESTION_NAMES = [QUESTION_NAME] * 6


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


# A check made to raise in each round, and the name the run records it under: a
# check a round wraps in a lambda (or the composer in its one section validator)
# is named by the wrapper, a check the round passes as it is by the function that
# stands in for it.
COMPOSER_NAME = "ReportComposer._invoke.<locals>._validate"
NARRATIVE_RAISES = [
    pytest.param("narrative_capability_violations", NARRATIVE_NAME, id="capability"),
    pytest.param("citation_violations", NARRATIVE_NAME, id="citation"),
    pytest.param("key_finding_citation_violations", NARRATIVE_NAME, id="key-finding"),
    pytest.param("wrong_entry_citations", NARRATIVE_NAME, id="wrong-entry"),
    pytest.param("technique_name_violations", "_boom", id="technique-name"),
]
COMPOSER_RAISES = [
    "section_capability_violations",
    "citation_violations",
    "wrong_entry_citations",
    "technique_name_violations",
    "repeated_item_violations",
]


def _failed(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in rows if r["code"] == validation.CHECK_FAILED_CODE]


def _said(name: str) -> str:
    """The row's words; a row first raised by a retry's answer says so after them."""
    return (
        f"The check {name} could not run on this answer (ValueError); "
        "what it checks was not checked."
    )


class _Structured:
    def __init__(self, llm: _Model, schema: Any) -> None:
        self.llm = llm
        self.schema = schema

    async def ainvoke(self, turns: list[Any], **_: Any) -> dict[str, Any]:
        from langchain_core.messages import AIMessage

        self.llm.asked.append("structured")
        text = self.llm.text(turns)
        parsed = None
        if self.llm.parses:
            payload = json.loads(text)
            fields = self.schema.model_fields
            parsed = self.schema.model_validate({k: v for k, v in payload.items() if k in fields})
        return {"raw": AIMessage(content=text), "parsed": parsed, "parsing_error": None}


class _Model:
    """A provider with a structured path: its answer parsed, or kept as text for the loop."""

    def __init__(self, text: Any, *, parses: bool) -> None:
        self.text = text
        self.parses = parses
        self.asked: list[str] = []

    def with_structured_output(self, schema: Any, **_: Any) -> _Structured:
        return _Structured(self, schema)

    async def ainvoke(self, turns: list[Any], **_: Any) -> Any:
        from langchain_core.messages import AIMessage

        self.asked.append("plain")
        return AIMessage(content=self.text(turns))


class TestTheNarrativeRecordsARaisingCheckUnderItsName:
    """The validation loop, reached three ways.

    With no structured path the loop is the round. A structured answer kept as
    text is the loop's first answer, with no call made again. A structured answer
    the schema parsed is checked where it came back; a check that raises there
    ends that path, and the round is asked again through the loop, which records
    it: a raise is never recorded on the parsed path itself.
    """

    @staticmethod
    async def _run(llm: Any, monkeypatch: pytest.MonkeyPatch, structured: bool) -> Any:
        monkeypatch.setattr(
            narrative_agent, "structured_output_supported_for_llm", lambda _llm: structured
        )
        agent = narrative_agent.NarrativeAgent(llm=llm)
        assert await agent.generate(_report()) is not None
        return agent

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("check", "name"), NARRATIVE_RAISES)
    async def test_the_loop(self, check: str, name: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(narrative_agent, check, _boom)
        llm = _Model(lambda _turns: ANSWER, parses=False)

        agent = await self._run(llm, monkeypatch, structured=False)

        assert set(llm.asked) == {"plain"}
        (row,) = _failed(agent.validation_tally.unresolved)
        assert row["subject"] == name
        assert row["message"].startswith(_said(name))

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("check", "name"), NARRATIVE_RAISES)
    async def test_a_kept_structured_answer(
        self, check: str, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(narrative_agent, check, _boom)
        llm = _Model(lambda _turns: ANSWER, parses=False)

        agent = await self._run(llm, monkeypatch, structured=True)

        assert set(llm.asked) == {"structured"}, "the structured path is not left"
        (row,) = _failed(agent.validation_tally.unresolved)
        assert row["subject"] == name
        assert row["message"].startswith(_said(name))

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("check", "name"), NARRATIVE_RAISES)
    async def test_a_parsed_structured_answer(
        self, check: str, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(narrative_agent, check, _boom)
        llm = _Model(lambda _turns: ANSWER, parses=True)

        agent = await self._run(llm, monkeypatch, structured=True)

        assert llm.asked[0] == "structured" and "plain" in llm.asked
        (row,) = _failed(agent.validation_tally.unresolved)
        assert row["subject"] == name
        assert row["message"].startswith(_said(name))


class TestTheComposerRecordsARaisingCheckUnderItsName:
    """Every section's one validator, with the structured setting off and on.

    Off, each section is asked by the manual path. On, a structured answer kept as
    text is the loop's first answer, with no call made again; a parsed one is
    checked where it came back, and a check that raises there ends that path and
    the section is asked again by the manual path, which records it.
    """

    @staticmethod
    def _compose(llm: Any, check: str, structured: bool) -> list[dict[str, str]]:
        import asyncio
        from unittest.mock import patch

        from malspark.reporting import composer
        from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
            _isr,
        )
        from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
            _report as _composed_report,
        )

        with (
            patch.object(composer, check, _boom),
            patch.object(composer, "structured_output_supported_for_llm", return_value=structured),
        ):
            writer = composer.ReportComposer(llm=llm, per_section_timeout=30)
            asyncio.run(writer.compose(_composed_report(), _isr(), concurrent=False))
        rows: list[dict[str, str]] = writer.validation_tally.unresolved
        return rows

    @staticmethod
    def _model(parses: bool) -> _Model:
        from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
            _answer,
            _section_of,
        )

        return _Model(lambda turns: json.dumps(_answer(_section_of(turns))), parses=parses)

    @staticmethod
    def _named(rows: list[dict[str, str]]) -> None:
        failed = _failed(rows)
        assert len(failed) == 20
        assert len({r["agent"] for r in failed}) == len(failed), "one row per section"
        assert {(r["subject"], r["message"]) for r in failed} == {
            (COMPOSER_NAME, _said(COMPOSER_NAME))
        }

    @pytest.mark.parametrize("check", COMPOSER_RAISES)
    def test_the_manual_path(self, check: str) -> None:
        llm = self._model(parses=False)

        self._named(self._compose(llm, check, structured=False))
        assert set(llm.asked) == {"plain"}

    @pytest.mark.parametrize("check", COMPOSER_RAISES)
    def test_a_kept_structured_answer(self, check: str) -> None:
        llm = self._model(parses=False)

        self._named(self._compose(llm, check, structured=True))
        assert set(llm.asked) == {"structured"}, "the structured path is not left"

    @pytest.mark.parametrize("check", COMPOSER_RAISES)
    def test_a_parsed_structured_answer(self, check: str) -> None:
        llm = self._model(parses=True)

        self._named(self._compose(llm, check, structured=True))
        assert llm.asked[0] == "structured" and "plain" in llm.asked
