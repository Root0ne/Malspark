"""A debate's first mediation is asked for every contradiction the answers and the ledger establish.

A point the mediator first raises in a later mediation costs the debate a
revision round, and only the first mediation is told so: its question carries
one declared sentence (``FIRST_MEDIATION_QUESTION``) before the closing line.
A later mediation, which the negotiation node names by the revision round held
before it (``last_revision_round``), is asked as before. The sentence asks; it
restricts nothing the mediator may decide.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

from malspark.agents.judge_agent import (
    FIRST_MEDIATION_QUESTION,
    MEDIATOR_HUMAN_CLOSING,
    JudgeAgent,
)


def _judge(seen: list[list[Any]]) -> JudgeAgent:
    judge = JudgeAgent.__new__(JudgeAgent)
    judge.logger = MagicMock()
    judge.tools = []
    judge.token_ledger = None
    judge.truncation_ledger = None
    judge._config = None
    judge.evidence_counter = None
    judge._evidence_entries = []
    judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]

    class _Model:
        async def ainvoke(self, messages: Any, **_k: Any) -> Any:
            seen.append(list(messages))
            return MagicMock(content="CONTRADICTIONS: NONE\nagreement_confidence: 0.9")

    judge.llm = _Model()
    return judge


def _messages(**extra: Any) -> tuple[str, str]:
    """The system turn and the question of one mediation."""
    seen: list[list[Any]] = []
    with (
        patch.object(JudgeAgent, "_question_room", return_value=None),
        patch.object(JudgeAgent, "_context_budget", return_value=None),
        patch.object(JudgeAgent, "_built_cap_tokens", return_value=0),
    ):
        asyncio.run(
            _judge(seen).mediate(
                reports={"static": "text"},
                history=[],
                isr_reports={},
                reputation_asked=True,
                **extra,
            )
        )
    system, human = seen[0][0], seen[0][1]
    return str(getattr(system, "content", system)), str(getattr(human, "content", human))


class TestTheFirstMediation:
    def test_its_question_asks_for_every_contradiction_now(self) -> None:
        _system, question = _messages()

        assert FIRST_MEDIATION_QUESTION in question
        # Before the closing line, which stays the question's last words.
        assert question.index(FIRST_MEDIATION_QUESTION) < question.index(MEDIATOR_HUMAN_CLOSING)
        assert question.endswith(MEDIATOR_HUMAN_CLOSING)

    def test_the_sentence_is_said_once_and_only_in_the_question(self) -> None:
        system, question = _messages()

        assert question.count(FIRST_MEDIATION_QUESTION) == 1
        assert FIRST_MEDIATION_QUESTION not in system


class TestALaterMediation:
    def test_its_question_does_not_carry_the_sentence(self) -> None:
        _system, question = _messages(last_revision_round=1)

        assert FIRST_MEDIATION_QUESTION not in question
        assert question.endswith(MEDIATOR_HUMAN_CLOSING)

    def test_the_system_turn_is_the_first_mediation_s(self) -> None:
        first, _q = _messages()
        later, _q = _messages(last_revision_round=3)

        assert later == first


class TestTheSentence:
    def test_it_names_the_round_a_late_point_costs(self) -> None:
        said = FIRST_MEDIATION_QUESTION.lower()

        assert "every contradiction" in said
        assert "ledger" in said
        assert "later mediation" in said and "round" in said
