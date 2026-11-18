"""The TECHNIQUE line's rule is stated with the format, and a retry shows the line it asks about.

The rule (ids alone, or NONE; an id the claim does not assert is left off the
line) was stated only in the question an unread line earns, so analysts wrote
"T1055 (candidate only, not asserted)" in every new answer and were asked
again each time. And the question quotes a line the analyst could not see:
an answer the strict parser read was shown back as its claims summary, which
prints only the ids that were read.
"""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import MagicMock

import pytest

from malspark.agents.base_agent import _REVISION_ISR_FORMAT, BaseAnalyst
from malspark.agents.prompt_fragments import CLAIM_FORMAT_FRAGMENT, TECHNIQUE_LINE_RULE
from malspark.pipeline.retry_merge import numbering_unsettled
from malspark.pipeline.validation import technique_line_violation
from malspark.schemas.isr_models import AgentISR

_UNREAD = "T1055 (candidate only, not asserted)"

_ANSWER = (
    "CLAIM: The loader writes into another process's memory.\n"
    "EVIDENCE: [ev_0004] WriteProcessMemory import\n"
    "CONFIDENCE: 0.6\n"
    f"TECHNIQUE: {_UNREAD}\n"
)

_FIXED = _ANSWER.replace(f"TECHNIQUE: {_UNREAD}", "TECHNIQUE: NONE")


class _Attck:
    """``tools.knowledge`` without the catalogue behind it."""

    def attck_validate(self, ids: list[str]) -> dict[str, Any]:
        return {"invalid": [], "checked": len(ids)}

    def resolve_technique(self, text: str, k: int = 5) -> dict[str, Any]:
        return {"candidates": []}


@pytest.fixture(autouse=True)
def _offline_knowledge(monkeypatch: pytest.MonkeyPatch) -> None:
    import malspark.tools.knowledge as knowledge

    stub = _Attck()
    monkeypatch.setattr(knowledge, "attck_validate", stub.attck_validate, raising=False)
    monkeypatch.setattr(knowledge, "resolve_technique", stub.resolve_technique, raising=False)


class _StrictAnalyst(BaseAnalyst):
    """An analyst whose first answer the strict parser reads, as the built-in roles' is."""

    def __init__(self, written: str, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self._written = written
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def analyze_isr(self, data: str) -> AgentISR:
        content = self._capture_findings(self._written)
        return self._parsed_isr(self._read_claims(content), content, "static")

    def _invoke_llm_with_timeout(self, messages: list, timeout: int, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        return self._replies.pop(0)


def _shown(analyst: _StrictAnalyst) -> list[str]:
    """The analyst's own turns in the retry's conversation."""
    return [
        str(turn.content) for turn in analyst.seen_turns[0] if getattr(turn, "type", "") == "ai"
    ]


def test_the_claim_format_states_the_technique_line_rule() -> None:
    assert TECHNIQUE_LINE_RULE in CLAIM_FORMAT_FRAGMENT
    assert "left off the line" in TECHNIQUE_LINE_RULE


def test_the_revision_format_states_the_technique_line_rule() -> None:
    assert TECHNIQUE_LINE_RULE in _REVISION_ISR_FORMAT


@pytest.mark.parametrize(
    ("module", "cls"),
    [
        ("malspark.agents.static_analyst", "StaticAnalyst"),
        ("malspark.agents.dynamic_analyst", "DynamicAnalyst"),
        ("malspark.agents.network_analyst", "NetworkAnalyst"),
    ],
)
def test_every_built_in_revision_states_the_technique_line_rule(module: str, cls: str) -> None:
    analyst: Any = getattr(importlib.import_module(module), cls)(llm=MagicMock(), name=cls)
    sent: list[str] = []

    def _answer(messages: list[Any]) -> str:
        sent.extend(str(m.content) for m in messages)
        return _FIXED

    analyst.revision_answer = _answer
    analyst.revise_isr("{}", "own", {"peer": "theirs"}, "feedback", 1)

    assert any(TECHNIQUE_LINE_RULE in text for text in sent)


def test_the_question_about_an_unread_line_states_the_same_rule() -> None:
    assert TECHNIQUE_LINE_RULE in technique_line_violation([_UNREAD]).message


def test_a_strictly_read_answer_is_shown_back_with_the_unread_line_as_written() -> None:
    analyst = _StrictAnalyst(_ANSWER, [_FIXED])

    analyst.safe_analyze_isr("raw data")

    [shown] = _shown(analyst)
    assert f"TECHNIQUE: {_UNREAD}" in shown


def test_an_answer_shown_as_its_summary_carries_the_unread_line_as_written() -> None:
    analyst = _StrictAnalyst(_ANSWER, [_FIXED])
    content = analyst._capture_findings(_ANSWER)
    # A merge of chunks: no single answer holds its claims, so none is recorded.
    merged = AgentISR(agent_id="static", domain="static", claims=analyst._read_claims(content))
    analyst.analyze_isr = lambda data: merged  # type: ignore[method-assign]

    analyst.safe_analyze_isr("raw data")

    [shown] = _shown(analyst)
    assert _UNREAD in shown


_MUTEX = "The loader creates the mutex Global\\qx7 before anything else."
_INJECT = "The loader writes into another process's memory."


def _numbered(number: int, sentence: str, technique: str) -> str:
    return (
        f"CLAIM {number}: {sentence}\n"
        "EVIDENCE: [ev_0004] WriteProcessMemory import\n"
        "CONFIDENCE: 0.6\n"
        f"TECHNIQUE: {technique}\n"
        "---\n"
    )


def test_a_strictly_read_answer_keeps_its_written_text_and_its_retry_merges_by_number() -> None:
    """The strict parser's answer records the text it was read from, so a retry
    that writes only the claim asked about replaces that claim by its number and
    keeps the rest."""
    first = _numbered(1, _MUTEX, "NONE") + _numbered(2, _INJECT, _UNREAD)
    analyst = _StrictAnalyst(first, [_numbered(2, _INJECT, "NONE")])
    parsed = analyst.analyze_isr("raw data")
    assert parsed.answer_text.strip() == first.strip()
    assert numbering_unsettled(parsed) == ""
    analyst = _StrictAnalyst(first, [_numbered(2, _INJECT, "NONE")])

    isr = analyst.safe_analyze_isr("raw data")

    # A whole-answer retry would leave claim 2 alone; the merge keeps claim 1.
    assert [c.claim for c in isr.claims] == [_MUTEX, _INJECT]
    assert [c.technique_line for c in isr.claims] == [None, None]
