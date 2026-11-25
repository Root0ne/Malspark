"""The turn in which a further detonation is read is told it is the platform's, not a negotiation.

Every revise implementation it reaches sends the platform's text under its
own heading, with no negotiation framing, no peer-reports line and no
disputes section; the debate's own revision prompts are sent as before, byte
for byte. Every value is made up.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage

from malspark.agents.base_agent import (
    _REVISION_ISR_FORMAT,
    _REVISION_ISR_FRAMING,
    BaseAnalyst,
    further_turn_messages,
    revision_messages,
)
from malspark.agents.composition import ResolvedAgent
from malspark.agents.configurable_analyst import ConfigurableAnalyst
from malspark.agents.dynamic_analyst import DynamicAnalyst
from malspark.agents.network_analyst import NetworkAnalyst
from malspark.agents.static_analyst import StaticAnalyst

PLATFORM = "Further detonations of the sample were made after your turn."
ANSWER = "CLAIM 1: the sample writes a file\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.6\n"
NEGOTIATION_WORDS = ("negotiation", "PEER REPORTS", "MEDIATOR FEEDBACK", "DISPUTES", "peer")


def _configurable() -> ConfigurableAnalyst:
    llm = FakeMessagesListChatModel(responses=[AIMessage(content=ANSWER)] * 2)
    resolved = ResolvedAgent(
        key="checker",
        role="generic",
        prompt="PROMPT-MARKER",
        tools=[],
        static_provider_id="ghidra",
        llm=llm,
        attck_techniques=True,
    )
    return ConfigurableAnalyst("checker", resolved, llm)


BUILT = {
    "dynamic": lambda: DynamicAnalyst(llm=MagicMock(), name="dynamic"),
    "static": lambda: StaticAnalyst(llm=MagicMock(), name="static"),
    "network": lambda: NetworkAnalyst(llm=MagicMock(), name="network"),
}


def _sent(agent: Any, *, further: bool) -> list[Any]:
    """The messages ``agent``'s revise implementation sends, in a further turn or a debate round."""
    sent: list[Any] = []

    def _answer(self: Any, messages: list[Any], what: str = "revision") -> str:
        sent.append(list(messages))
        return ANSWER

    agent._further_turn = further
    with patch.object(BaseAnalyst, "revision_answer", _answer):
        agent.revise_isr("RAW", "OWN", {} if further else {"peer": "P"}, PLATFORM, 0)
    return sent[-1]


def _configurable_sent(further: bool) -> list[Any]:
    agent = _configurable()
    agent._further_turn = further
    seen: list[Any] = []
    original = agent._run

    def _run(messages: Any, what: str) -> Any:
        seen.append(messages)
        return original(messages, what)

    agent._run = _run  # type: ignore[method-assign]
    agent.revise_isr("RAW", "OWN", {} if further else {"peer": "P"}, PLATFORM, 0)
    return seen[-1]


@pytest.mark.parametrize("role", sorted(BUILT))
def test_a_built_in_analyst_s_further_turn_heads_the_platform_s_text(role: str) -> None:
    system, human = (str(m.content) for m in _sent(BUILT[role](), further=True))
    assert f"FROM THE PLATFORM:\n{PLATFORM}\n\n" in human
    assert human.startswith("YOUR ORIGINAL REPORT:\nOWN\n\nFROM THE PLATFORM:")
    for word in NEGOTIATION_WORDS:
        assert word not in system and word not in human, word


def test_the_configurable_analyst_s_further_turn_heads_the_platform_s_text() -> None:
    (_system, system_text), (_human, human) = _configurable_sent(further=True)
    assert f"FROM THE PLATFORM:\n{PLATFORM}\n\n" in human
    for word in NEGOTIATION_WORDS:
        assert word not in system_text and word not in human, word


@pytest.mark.parametrize("role", sorted(BUILT))
def test_a_debate_round_keeps_its_negotiation_prompt(role: str) -> None:
    system, human = (str(m.content) for m in _sent(BUILT[role](), further=False))
    assert system.endswith(_REVISION_ISR_FRAMING)
    assert "PEER REPORTS:\nPEER REPORT:\nP\n\n" in human
    assert f"MEDIATOR FEEDBACK:\n{PLATFORM}\n\n" in human
    assert "FROM THE PLATFORM" not in human


def test_the_debate_s_shared_revision_prompt_is_byte_for_byte_as_before() -> None:
    assert revision_messages("SYS", "DATA", "OWN", {"peer": "P"}, "FB", isr=True) == [
        ("system", "SYS\n\n" + _REVISION_ISR_FRAMING),
        (
            "human",
            "YOUR ORIGINAL REPORT:\nOWN\n\nPEER REPORTS:\nPEER REPORT:\nP\n\n"
            "MEDIATOR FEEDBACK:\nFB\n\nRAW DATA:\nDATA\n\n" + _REVISION_ISR_FORMAT,
        ),
    ]


def test_the_further_turn_prompt_in_full() -> None:
    assert revision_messages("SYS", "DATA", "OWN", {}, PLATFORM, isr=True, further_turn=True) == (
        further_turn_messages("SYS", "DATA", "OWN", PLATFORM)
    )
    (role, system), (_role, human) = further_turn_messages("SYS", "DATA", "OWN", PLATFORM)
    assert (role, system) == ("system", "SYS")
    assert human == (
        f"YOUR ORIGINAL REPORT:\nOWN\n\nFROM THE PLATFORM:\n{PLATFORM}\n\nRAW DATA:\nDATA\n\n"
        "Format your response as structured claims (CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE).\n"
        "Write each claim's technique ids alone, several separated by commas, or NONE when "
        "it claims none. An id the claim does not assert (negated, absent, not supported) is "
        "left off the line, and the claim sentence says so; a doubt about an id the claim "
        "does assert is said in the claim and in its CONFIDENCE.\n"
        "Example:\nCLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1071\n---\n"
    )
    without = further_turn_messages("SYS", "DATA", "OWN", PLATFORM, techniques=False)[1][1]
    assert "TECHNIQUE" not in without


def test_the_flag_is_set_for_the_turn_alone() -> None:
    agent = DynamicAnalyst(llm=MagicMock(), name="dynamic")
    seen: list[bool] = []

    def _revise(self: Any, *args: Any) -> Any:
        seen.append(self._further_turn)
        return ANSWER, self._text_to_isr(ANSWER, 0)

    with (
        patch.object(DynamicAnalyst, "revise_isr", _revise),
        patch.object(BaseAnalyst, "_validate_isr", lambda self, isr, evidence: isr),
    ):
        agent.safe_revise_isr("RAW", "OWN", {}, PLATFORM, 0, further_turn=True)
        agent.safe_revise_isr("RAW", "OWN", {"peer": "P"}, "FB", 1)
    assert seen == [True, False]
    assert agent._further_turn is False


def test_the_further_turn_asks_its_revision_as_a_further_turn(monkeypatch: Any) -> None:
    from malspark.pipeline import detonations as dt
    from malspark.pipeline import nodes
    from malspark.providers.detonation import DetonationRecord

    asked: list[dict[str, Any]] = []

    class _Agent:
        def safe_revise_isr(self, *args: Any, **kwargs: Any) -> Any:
            asked.append(kwargs)
            return "revised", SimpleNamespace(claims=["c"])

        def drain_evidence_entries(self) -> list[Any]:
            return []

    record = DetonationRecord(ordinal=2, origin="agent", arguments="--key k1", report={})
    job = SimpleNamespace(
        detonations=[DetonationRecord(report={}), record],
        detonations_seen={"dynamic": {"d1"}},
        further_turns=[],
        event_sink=lambda kind, data: None,
        get_agent=lambda name: _Agent(),
    )
    monkeypatch.setattr(dt, "_readers_owed", lambda c, s: {"dynamic": [record]})
    monkeypatch.setattr(nodes, "_revision_input", lambda s, c, n: nodes.RevisionInput(text="raw"))
    monkeypatch.setattr(nodes, "brief_agent", lambda *a: None)
    monkeypatch.setattr(nodes, "_budget_update", lambda *a: {})
    monkeypatch.setattr(nodes, "_validation_update", lambda *a: {})
    monkeypatch.setattr(nodes, "_nudge_mode", lambda *a: "")
    monkeypatch.setattr(nodes, "revision_decided_nothing", lambda isr: False)
    asyncio.run(dt.further_turns(job, {"reports": {"dynamic": "own"}}, "negotiation"))
    assert asked == [{"further_turn": True}]
