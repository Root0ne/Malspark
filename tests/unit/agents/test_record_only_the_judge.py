"""The judge's verdict and its technique question in both ``validation.feedback`` modes (T-672).

``feed_back``: a finding on the verdict opens the one retry, and the describe
check's finding asks the judge about the technique. ``record_only``: no retry
is sent for a finding, every finding is recorded not asked, and an ungrounded
indicator is still kept out of the bundle; the describe check asks nothing,
and the technique is recorded as not asked with the mode as the reason. An
answer that is not JSON is asked again in both.

Every sentence, address and id here is made up for the test.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from malspark.agents.judge_agent import JudgeAgent, JudgeVerdict
from malspark.extractors.capability_matrix import judge_questions
from malspark.pipeline.feedback_mode import NOT_ASKED_IN_RECORD_ONLY
from malspark.schemas.isr_models import AgentISR, ClaimEvidence
from malspark.schemas.stix_models import Bundle
from malspark.tools import knowledge

UNDESCRIBED = "T1003"  # OS Credential Dumping: the sentence below shares no term with it
CLAIMED = "T1112"  # a technique the bundle does not carry
WINDOW = "The sample opens a window on the desktop."

# A whole bundle whose one indicator no evidence grounds.
FIRST = {
    "type": "bundle",
    "id": "bundle--1",
    "x_malspark_assessment": {
        "verdict": "Malware",
        "confidence": 0.9,
        "severity": {"rating": "High", "rationale": "injects"},
        "malware_category": "loader",
    },
    "objects": [
        {
            "type": "malware",
            "id": "malware--1",
            "name": "x",
            "is_family": False,
            "malware_types": ["dropper"],
        },
        {
            "type": "indicator",
            "id": "indicator--1",
            "pattern": "[domain-name:value='evil.example']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
        },
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "indicates",
            "source_ref": "indicator--1",
            "target_ref": "malware--1",
        },
    ],
}
# The same bundle without the indicator: what a judge told about it answers.
FIXED = {
    **FIRST,
    "objects": [FIRST["objects"][0]],
}


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


async def _verdict(judge: JudgeAgent) -> JudgeVerdict:
    return await judge.give_verdict(
        {"static": "loader injecting"}, [], evidence_corpus={"nothing"}, ledger_ids=["ev_0001"]
    )


def _indicators(verdict: JudgeVerdict) -> list[Any]:
    return [o for o in verdict.bundle.objects if o.type == "indicator"]


@pytest.mark.asyncio
async def test_a_finding_on_the_verdict_opens_the_retry_only_in_feed_back(mode: str) -> None:
    llm = _Llm(json.dumps(FIRST), json.dumps(FIXED))

    verdict = await _verdict(JudgeAgent(llm))  # type: ignore[arg-type]

    ungrounded = [v for v in verdict.violations if v.code == "stix.ungrounded_indicator"]
    if mode == "feed_back":
        assert len(llm.calls) == 2
        assert verdict.retries == 1
        assert "stix.ungrounded_indicator" in verdict.fed_back
        assert ungrounded == []
    else:
        assert len(llm.calls) == 1
        assert verdict.retries == 0
        assert verdict.fed_back == {}
        assert ungrounded and all(v.asked is False for v in ungrounded)
        assert all(v.asked is False for v in verdict.violations)
        # The assessment stands as written, and the integrity guard still holds:
        # the ungrounded indicator is kept out of the bundle.
        assessment = verdict.bundle.x_malspark_assessment
        assert assessment is not None and assessment.verdict == "Malware"
    assert _indicators(verdict) == []


@pytest.mark.asyncio
async def test_an_answer_that_is_not_json_is_asked_again_in_both_modes(mode: str) -> None:
    llm = _Llm("I think it is a loader.", json.dumps(FIXED))

    verdict = await _verdict(JudgeAgent(llm))  # type: ignore[arg-type]

    assert len(llm.calls) == 2
    assert verdict.retries == 1
    assert verdict.fed_back.get("verdict.not_json") == 1
    assert verdict.bundle.x_malspark_fallback_verdict is None


def _unreadable(case: str) -> dict[str, Any]:
    """FIXED with one part the bundle cannot read: what ``case`` names."""
    bundle = json.loads(json.dumps(FIXED))
    assessment = bundle["x_malspark_assessment"]
    if case == "verdict.unrecognised":
        assessment["verdict"] = "Probably malware (loader)"
    elif case == "verdict.severity_enum":
        assessment["severity"]["rating"] = "Severe"
    elif case == "verdict.assessment_unreadable":
        assessment["confidence"] = "very sure"
    elif case == "verdict.assessment_missing":
        del bundle["x_malspark_assessment"]
    elif case == "stix.unknown_object":
        bundle["objects"].append({"type": "x-loader-note", "id": "x-loader-note--1"})
    elif case == "stix.duplicate_label":
        bundle["objects"].append({**bundle["objects"][0], "name": "y"})
    return bundle


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "verdict.unrecognised",
        "verdict.severity_enum",
        "verdict.assessment_unreadable",
        "verdict.assessment_missing",
        "stix.unknown_object",
        "stix.duplicate_label",
    ],
)
async def test_a_part_of_the_verdict_that_cannot_be_read_is_asked_in_both_modes(
    mode: str, case: str
) -> None:
    llm = _Llm(json.dumps(_unreadable(case)), json.dumps(FIXED))

    verdict = await _verdict(JudgeAgent(llm))  # type: ignore[arg-type]

    assert len(llm.calls) == 2
    assert verdict.retries == 1
    assert verdict.fed_back.get(case) == 1
    assessment = verdict.bundle.x_malspark_assessment
    assert assessment is not None and assessment.verdict == "Malware"
    assert assessment.severity is not None and assessment.severity.rating == "High"


def _isrs() -> dict[str, AgentISR]:
    claims = [
        ClaimEvidence(
            claim=WINDOW, evidence_ref="[ev_0003]", confidence=0.6, technique_id=UNDESCRIBED
        ),
    ]
    return {"static": AgentISR(agent_id="static", domain="static", claims=claims)}


def _bundle_with(tid: str) -> dict[str, Any]:
    return {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332211",
                "name": "OS Credential Dumping",
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            }
        ]
    }


class TestTheTechniqueQuestion:
    def test_the_describe_finding_asks_only_when_told_to(self) -> None:
        asked, left_out = judge_questions(_bundle_with(UNDESCRIBED), _isrs(), attck=knowledge)
        assert [(q.technique_id, q.kind) for q in asked] == [(UNDESCRIBED, "undescribed")]
        assert left_out == {}

        asked, left_out = judge_questions(
            _bundle_with(UNDESCRIBED), _isrs(), attck=knowledge, ask_undescribed=False
        )
        assert asked == []
        assert left_out == {UNDESCRIBED: NOT_ASKED_IN_RECORD_ONLY}

    def test_a_claimed_question_is_asked_without_the_finding(self) -> None:
        bundle = _bundle_with(CLAIMED)

        (with_check,), _ = judge_questions(bundle, _isrs(), attck=knowledge)
        (without,), left_out = judge_questions(
            bundle, _isrs(), attck=knowledge, ask_undescribed=False
        )

        assert (with_check.technique_id, with_check.kind) == (UNDESCRIBED, "claimed")
        assert with_check.check
        assert (without.technique_id, without.kind, without.check) == (UNDESCRIBED, "claimed", "")
        assert left_out == {}

    def test_the_judge_is_asked_only_in_feed_back(self, mode: str) -> None:
        llm = _Llm("[]")
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]

        review = asyncio.run(
            judge.decide_techniques(
                Bundle.model_validate(_bundle_with(UNDESCRIBED)),
                _isrs(),
                reports={"static": "r"},
                evidence_texts={},
                routed={"platform": "windows", "file_type": "pe"},
            )
        )

        assert review is not None
        if mode == "feed_back":
            assert len(llm.calls) == 1
            assert review.asked == [UNDESCRIBED]
            assert set(review.undescribed) == {UNDESCRIBED}
            assert review.not_asked == {}
        else:
            assert llm.calls == []
            assert review.asked == []
            assert review.undescribed == {}
            assert review.not_asked == {UNDESCRIBED: NOT_ASKED_IN_RECORD_ONLY}


def test_the_reason_names_the_setting_and_its_value() -> None:
    assert "validation.feedback" in NOT_ASKED_IN_RECORD_ONLY
    assert "record_only" in NOT_ASKED_IN_RECORD_ONLY
