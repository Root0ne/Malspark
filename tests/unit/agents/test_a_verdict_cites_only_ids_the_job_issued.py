"""Every entry id the judge's verdict names is one the job issued.

The job's evidence counter issues ``ev_0001`` up to its count, to every agent.
An id the verdict's bundle names past that count, in its assessment or in any
object, names no entry; the judge is asked once (``verdict.unissued_evidence``),
on every way the round can end, and the finding follows ``validation.feedback``.
An indicator's pattern compares values the sample wrote, not citations, and a
code span is quoted text: neither is read.

Every sentence, address and id here is made up for the test.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from malspark.agents.judge_agent import JudgeAgent, VerdictCheckInputs, verdict_checks
from malspark.pipeline.validation import (
    UNISSUED_VERDICT_EVIDENCE_CODE,
    unissued_verdict_citations,
)
from malspark.schemas.evidence import EvidenceCounter
from malspark.schemas.stix_models import Bundle


def _bundle(rationale: str = "injects code", **extra: Any) -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--1",
        "x_malspark_assessment": {
            "verdict": "Malware",
            "confidence": 0.9,
            "severity": {"rating": "High", "rationale": rationale},
            "malware_category": "loader",
        },
        "objects": [
            {
                "type": "malware",
                "id": "malware--1",
                "name": "x",
                "is_family": False,
                "malware_types": ["dropper"],
                **extra,
            }
        ],
    }


def _asked(answer: dict[str, Any], issued: int | None = 10) -> list[Any]:
    return unissued_verdict_citations(Bundle.model_validate(answer), issued)


class TestTheVerdictCheck:
    def test_an_unissued_id_in_the_assessment_is_asked(self) -> None:
        (found,) = _asked(_bundle("injects code [ev_0099]"))

        assert found.code == UNISSUED_VERDICT_EVIDENCE_CODE
        assert found.subject == "ev_0099"
        assert "ev_0001 to ev_0010" in found.message

    def test_an_unissued_id_in_an_object_is_asked(self) -> None:
        (found,) = _asked(_bundle(description="seen in ev_0042"))

        assert found.subject == "ev_0042"

    def test_an_issued_id_of_any_agent_is_not_asked(self) -> None:
        assert _asked(_bundle("injects code [ev_0007]")) == []

    def test_an_indicator_s_pattern_is_not_read(self) -> None:
        answer = _bundle()
        answer["objects"].append(
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[file:name = 'ev_0099.exe']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
            }
        )

        assert _asked(answer) == []

    def test_an_id_in_a_code_span_is_not_read(self) -> None:
        assert _asked(_bundle("prints `ev_0099` to its log")) == []

    def test_each_end_of_a_range_is_read(self) -> None:
        (found,) = _asked(_bundle("injects code [ev_0005-ev_0012]"))

        assert found.subject == "ev_0012"

    def test_a_malformed_id_is_not_read(self) -> None:
        assert _asked(_bundle("ev_99 and ev_0005x")) == []

    def test_no_count_asks_nothing(self) -> None:
        assert _asked(_bundle("injects code [ev_0099]"), issued=None) == []

    def test_a_job_that_issued_nothing_names_every_id(self) -> None:
        (found,) = _asked(_bundle("injects code [ev_0001]"), issued=0)

        assert "issued none" in found.message

    def test_it_is_one_of_the_checks_every_ending_runs(self) -> None:
        inputs = VerdictCheckInputs(
            evidence_corpus=None,
            attck=None,
            sample=None,
            shortened_tools=(),
            searched=(),
            corpus_state=None,
            technique_sources=None,
            sandbox_facts=None,
            analyst_claims=1,
            ledger_ids=["ev_0001"],
            issued=3,
        )
        found = verdict_checks(Bundle.model_validate(_bundle("[ev_0099]")), inputs)

        assert [v.code for v in found] == [UNISSUED_VERDICT_EVIDENCE_CODE]


# ---------------------------------------------------------------------------
# Through the judge's verdict round
# ---------------------------------------------------------------------------


def _settings(mode: str) -> Any:
    from malspark.core.settings_overrides import build_settings

    return build_settings({"validation": {"feedback": mode}})


@pytest.fixture(params=["feed_back", "record_only"])
def mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    built = _settings(request.param)
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)
    return str(request.param)


class _Llm:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any], **_: Any) -> Any:
        self.calls.append(list(messages))
        return AIMessage(content=self._answers.pop(0) if self._answers else "")


@pytest.mark.asyncio
async def test_the_round_asks_about_an_id_the_job_never_issued(mode: str) -> None:
    llm = _Llm(json.dumps(_bundle("injects code [ev_0099]")), json.dumps(_bundle("[ev_0002]")))
    judge = JudgeAgent(llm)  # type: ignore[arg-type]
    judge.evidence_counter = EvidenceCounter()
    for _ in range(3):
        judge.evidence_counter.next_id()

    verdict = await judge.give_verdict(
        {"static": "loader injecting"}, [], evidence_corpus={"nothing"}, ledger_ids=["ev_0001"]
    )

    found = [v for v in verdict.violations if v.code == UNISSUED_VERDICT_EVIDENCE_CODE]
    if mode == "feed_back":
        assert len(llm.calls) == 2
        assert verdict.fed_back.get(UNISSUED_VERDICT_EVIDENCE_CODE) == 1
        assert found == []
    else:
        assert len(llm.calls) == 1
        assert found and all(v.asked is False for v in found)


@pytest.mark.asyncio
async def test_a_judge_without_a_counter_is_not_asked() -> None:
    llm = _Llm(json.dumps(_bundle("injects code [ev_0099]")))

    verdict = await JudgeAgent(llm).give_verdict(  # type: ignore[arg-type]
        {"static": "loader injecting"}, [], evidence_corpus={"nothing"}, ledger_ids=["ev_0001"]
    )

    assert not [v for v in verdict.violations if v.code == UNISSUED_VERDICT_EVIDENCE_CODE]


class _IssuingLlm(_Llm):
    """A judge model during whose answer the job's counter issues more ids."""

    def __init__(self, counter: EvidenceCounter, more: int, *answers: str) -> None:
        super().__init__(*answers)
        self._counter = counter
        self._more = more

    async def ainvoke(self, messages: list[Any], **_: Any) -> Any:
        for _ in range(self._more):
            self._counter.next_id()
        self._more = 0
        return await super().ainvoke(messages)


@pytest.mark.asyncio
async def test_the_count_is_read_when_the_verdict_is_checked(mode: str) -> None:
    counter = EvidenceCounter()
    for _ in range(3):
        counter.next_id()
    llm = _IssuingLlm(counter, 3, json.dumps(_bundle("injects code [ev_0005]")))
    judge = JudgeAgent(llm)  # type: ignore[arg-type]
    judge.evidence_counter = counter

    verdict = await judge.give_verdict(
        {"static": "loader injecting"},
        [],
        evidence_corpus={"nothing"},
        ledger_ids=["ev_0001", "ev_0005"],
    )

    assert len(llm.calls) == 1
    assert not [v for v in verdict.violations if v.code == UNISSUED_VERDICT_EVIDENCE_CODE]


def test_the_judge_and_the_analysts_read_the_count_through_one_helper() -> None:
    import inspect

    from malspark.agents import base_agent, judge_agent
    from malspark.schemas.evidence import issued_by

    counter = EvidenceCounter()
    counter.next_id()
    assert (issued_by(counter), issued_by(None)) == (1, None)
    assert "issued_by(" in inspect.getsource(judge_agent)
    assert "issued_by(" in inspect.getsource(base_agent)
    assert not hasattr(judge_agent, "_issued_by")
