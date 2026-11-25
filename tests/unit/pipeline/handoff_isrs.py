"""Upstream answers the stage hand-off tests build on: invented claims and open questions.

A two-stage team: ``first`` (two agents) and ``later``, which depends on it and
is handed its findings. Each set is a state's ``isr_reports``; every value is
invented for these tests.
"""

from __future__ import annotations

from typing import Any

from malspark.core.config import Settings
from malspark.core.container import ServiceContainer
from malspark.schemas.isr_models import AgentISR, ClaimEvidence, OpenQuestion

TEAM = [
    {"key": "first", "kind": "analysis", "agents": ["reader", "lister"]},
    {
        "key": "later",
        "kind": "analysis",
        "agents": ["follower"],
        "depends_on": ["first"],
        "inject_upstream": "findings",
    },
    {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["later"]},
]


def settings(**over: Any) -> Settings:
    definitions = {
        "reader": {"role": "generic", "prompt": "read it"},
        "lister": {"role": "generic", "prompt": "list it"},
        "follower": {"role": "generic", "prompt": "follow it"},
    }
    stages = over.pop("stages", TEAM)
    return Settings(
        _env_file=None,
        agents={
            "definitions": definitions,
            "profiles": {"team": {"label": "Team", "stages": stages}},
            "profile": "team",
        },
        **over,
    )


def container(**over: Any) -> ServiceContainer:
    return ServiceContainer(settings(**over), mock=True)


def later_stage(built: ServiceContainer, mode: str = "findings") -> Any:
    stage = built.active_profile().stage("later")
    return stage.model_copy(update={"inject_upstream": mode})


def claim(text: str, ref: str, confidence: float = 0.7) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=confidence)


def question(text: str, why: str, **fields: Any) -> OpenQuestion:
    return OpenQuestion.model_validate({"question": text, "why_open": why, **fields})


def isr(agent: str, claims: list[ClaimEvidence], questions: list[OpenQuestion]) -> AgentISR:
    return AgentISR(
        agent_id=agent,
        domain="static",
        claims=claims,
        dissent_items=[],
        open_questions=questions,
    )


READER_CLAIMS = [
    claim("the loader reads its settings from an embedded resource", "ev_0003", 0.8),
    claim("the settings name a second file  written\nbeside the loader", "ev_0005"),
]
LISTER_CLAIMS = [claim("the file lists one exported routine", "ev_0002", 0.6)]

READER_QUESTIONS = [
    question(
        "Which value does the loader expect as its first argument?",
        "needs_sandbox_run",
        detail="the argument check returns early\nwithout one",
        would_answer="a run with an argument",
        tool_kind="detonation_request",
        evidence_ids=["ev_0003"],
    ),
    question("Which routine decodes the stored settings?", "obfuscated", agent="follower"),
]
LISTER_QUESTIONS = [
    question(
        "Does the exported routine take a callback?", "tool_failed", detail="the read timed out"
    ),
    question(
        "What does the second resource hold?",
        "a word of its own",
        source="helper",
    ),
]


def with_questions() -> dict[str, AgentISR]:
    """Both agents with claims; each with questions of two reasons."""
    return {
        "reader": isr("reader", READER_CLAIMS, READER_QUESTIONS),
        "lister": isr("lister", LISTER_CLAIMS, LISTER_QUESTIONS),
    }


def claims_on_one_side() -> dict[str, AgentISR]:
    """One agent with claims and no question, the other with questions and no claim."""
    return {
        "reader": isr("reader", READER_CLAIMS, []),
        "lister": isr("lister", [], LISTER_QUESTIONS),
    }


def questions_only() -> dict[str, AgentISR]:
    """No upstream claim at all, and questions."""
    return {
        "reader": isr("reader", [], READER_QUESTIONS),
        "lister": isr("lister", [], []),
    }


def without_questions(sets: dict[str, AgentISR]) -> dict[str, AgentISR]:
    """``sets`` with every open question taken out: the hand-off before it carried them."""
    return {name: answer.model_copy(update={"open_questions": []}) for name, answer in sets.items()}


def state(sets: dict[str, AgentISR]) -> dict[str, Any]:
    return {"file_hash": "abc", "isr_reports": sets, "reports": {}}
