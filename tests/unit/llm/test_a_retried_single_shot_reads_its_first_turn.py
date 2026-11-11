"""On Claude, a single shot a validation retry may follow caches its first turn for the retry.

A report section is asked once and, where its answer breaks a rule, asked
again: the retry sends the first pass's whole first turn again, then the
answer and the question. The first pass marked only the head the sections
share, so the retry read the head and wrote the rest of the turn again. A user
turn noted as one a later request may send again
(``anthropic_history.SENT_AGAIN``, with its length) now carries a breakpoint
at its end on the single shot too, where no other breakpoint is placed at it
or after it: the first pass writes the turn, and the retry, whose request is
the first pass's byte for byte through that block, reads it. Only cache
markers and a string turn's one-block shape differ; the text is the same.

A turn a question was later added to is not marked by its note, a request no
later one sends again carries the mark only where an earlier request wrote
it, no request carries more than four breakpoints, every call kind without the
note sends the body it sent before (``anthropic_cache_bodies``), and the
other providers send the same body with the note or without it.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from malspark.core.config import Settings
from malspark.llm import anthropic_history
from malspark.llm.anthropic_history import LAST_REQUEST, SENT_AGAIN, SHARED_HEAD
from malspark.llm.anthropic_provider import AnthropicProvider
from malspark.reporting.composer import COMPOSED_SECTIONS, ReportComposer
from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
    _answer,
    _isr,
    _report,
)

from .anthropic_cache_bodies import bodies
from .anthropic_wire import MODEL, Wire, install, message

FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "anthropic_bodies_before_sent_again.json"
)
USAGE = {"input_tokens": 10, "output_tokens": 5}
MARK = {"type": "ephemeral"}
SYSTEM = "You are a report writer."
HEAD = "DETERMINISTIC FACTS (complete list):\n- file_type: PE32 executable\n\n"
TASK = "Write the introduction.\n\nThe evidence follows.\n" + "evidence line\n" * 20
ANSWER = '{"introduction": "It reads a file."}'
QUESTION = "Your previous answer had these problems: claim 1 cites no entry. Fix it."
FACTS = "DETERMINISTIC FACTS (complete list):\n- file_type: PE32 executable"
_LEAD = "The evidence for the "


def _thinking(turn: int) -> dict[str, Any]:
    return {"type": "thinking", "thinking": "", "signature": f"EoBsig{turn}/+=" * 8}


def _reply(body: dict[str, Any]) -> dict[str, Any]:
    turn = len(body["messages"])
    return message(
        [_thinking(turn), {"type": "text", "text": ANSWER}], stop="end_turn", usage=USAGE
    )


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch) -> Wire:
    found = Wire(_reply)
    install(monkeypatch, found)
    return found


def _model(**anthropic: Any) -> Any:
    settings = Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key", **anthropic}},
    )
    return AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096)


def _noted(text: str, head: int = 0) -> HumanMessage:
    notes: dict[str, Any] = {SENT_AGAIN: len(text)}
    if head:
        notes[SHARED_HEAD] = head
    return HumanMessage(content=text, response_metadata=notes)


def _answered(turn: int) -> AIMessage:
    return AIMessage(content=[_thinking(turn), {"type": "text", "text": ANSWER}])


def _through_first_turn(body: dict[str, Any]) -> str:
    """The body's tools, system prompt and first turn, serialised as sent (markers kept)."""
    return json.dumps([body.get("tools"), body.get("system"), body["messages"][0]])


def _markers(body: dict[str, Any]) -> int:
    return json.dumps([body.get("tools"), body.get("system"), body["messages"]]).count(
        '"cache_control"'
    )


class TestTheFirstPass:
    def test_a_noted_turn_is_marked_at_its_end(self, wire: Wire) -> None:
        _model().invoke([SystemMessage(content=SYSTEM), _noted(TASK)])
        (body,) = wire.bodies
        assert body["messages"] == [
            {"role": "user", "content": [{"type": "text", "text": TASK, "cache_control": MARK}]}
        ]

    def test_with_a_shared_head_the_head_and_the_end_are_marked(self, wire: Wire) -> None:
        _model().invoke([SystemMessage(content=SYSTEM), _noted(HEAD + TASK, len(HEAD))])
        (body,) = wire.bodies
        assert body["messages"][0]["content"] == [
            {"type": "text", "text": HEAD, "cache_control": MARK},
            {"type": "text", "text": TASK, "cache_control": MARK},
        ]

    def test_the_note_never_reaches_a_request_body(self, wire: Wire) -> None:
        _model().invoke([SystemMessage(content=SYSTEM), _noted(TASK)])
        assert SENT_AGAIN not in json.dumps(wire.bodies[-1])


class TestTheRetryReadsIt:
    @pytest.mark.parametrize("head", [0, len(HEAD)], ids=["whole turn", "shared head"])
    def test_a_retry_after_the_answer_sends_the_first_pass_through_its_mark(
        self, wire: Wire, head: int
    ) -> None:
        text = HEAD + TASK if head else TASK
        model = _model()
        model.invoke([SystemMessage(content=SYSTEM), _noted(text, head)])
        model.invoke(
            [
                SystemMessage(content=SYSTEM),
                _noted(text, head),
                _answered(2),
                HumanMessage(content=QUESTION),
            ]
        )
        first, retry = wire.bodies
        assert wire.refused == []
        assert _through_first_turn(retry) == _through_first_turn(first)
        assert retry["messages"][0]["content"][-1]["cache_control"] == MARK

    def test_a_retry_in_its_call_s_reply_reads_the_first_turn(self, wire: Wire) -> None:
        from langchain_core.tools import StructuredTool

        from .anthropic_cache_bodies import _What

        tool = StructuredTool.from_function(
            func=lambda what="": what, name="lookup", description="Look.", args_schema=_What
        )
        call = AIMessage(
            content=[
                _thinking(2),
                {"type": "tool_use", "id": "call_0", "name": "lookup", "input": {"what": "a"}},
            ],
            tool_calls=[{"name": "lookup", "args": {"what": "a"}, "id": "call_0"}],
        )
        reply = ToolMessage(
            content=QUESTION,
            tool_call_id="call_0",
            status="error",
            response_metadata={LAST_REQUEST: True},
        )
        bound = _model().bind_tools([tool])
        turn = _noted(HEAD + TASK, len(HEAD))
        bound.invoke([SystemMessage(content=SYSTEM), turn])
        bound.invoke([SystemMessage(content=SYSTEM), turn, call, reply])
        first, retry = wire.bodies
        assert wire.refused == []
        assert _through_first_turn(retry) == _through_first_turn(first)
        assert _markers(retry) == 2, "the head and the turn's end; the last reply writes nothing"

    def test_a_last_request_nothing_wrote_before_marks_only_the_head(self, wire: Wire) -> None:
        reply = HumanMessage(content=QUESTION, response_metadata={LAST_REQUEST: True})
        _model().invoke(
            [SystemMessage(content=SYSTEM), _noted(HEAD + TASK, len(HEAD)), _answered(2), reply]
        )
        (body,) = wire.bodies
        assert body["messages"][0]["content"][0]["cache_control"] == MARK
        assert "cache_control" not in body["messages"][0]["content"][1]
        assert _markers(body) == 1

    def test_a_turn_a_question_was_added_to_is_not_marked_by_its_note(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.pipeline.turns import with_question

        sent: list[list[dict[str, Any]]] = []
        for notes in ({SENT_AGAIN: len(TASK)}, {}):
            found = Wire(_reply)
            install(monkeypatch, found)
            turns = [
                SystemMessage(content=SYSTEM),
                HumanMessage(content=TASK, response_metadata=notes),
            ]
            # A cut answer's question is asked at the end of the first turn.
            _model().invoke(with_question(turns, QUESTION))
            sent.append(found.bodies)
        noted, plain = sent
        assert noted == plain
        assert isinstance(noted[0]["messages"][0]["content"], str)


class TestTheComposer:
    """Every section's first pass marks its turn's end, and its retry reads it."""

    @staticmethod
    def _text_of(body: dict[str, Any]) -> str:
        content = body["messages"][0]["content"]
        if isinstance(content, str):
            return content
        return "".join(block["text"] for block in content)

    def _section(self, body: dict[str, Any]) -> str:
        text = self._text_of(body)
        start = text.index(_LEAD) + len(_LEAD)
        return text[start : text.index(" section follows.", start)]

    def _compose(self, monkeypatch: pytest.MonkeyPatch, structured: bool) -> list[dict[str, Any]]:
        def reply(body: dict[str, Any]) -> dict[str, Any]:
            answer = _answer(self._section(body)) if _LEAD in self._text_of(body) else {}
            if body.get("tools"):
                name = body["tools"][0]["name"]
                use = {"type": "tool_use", "id": "toolu_1", "name": name, "input": answer}
                return message([use], stop="tool_use", usage=USAGE)
            text = {"type": "text", "text": json.dumps(answer)}
            return message([text], stop="end_turn", usage=USAGE)

        found = Wire(reply)
        install(monkeypatch, found)
        composer = ReportComposer(llm=_model(), per_section_timeout=60)
        with patch(
            "malspark.reporting.composer.structured_output_supported_for_llm",
            return_value=structured,
        ):
            asyncio.run(composer.compose(_report(), _isr(), facts_block=FACTS, concurrent=True))
        assert found.refused == []
        return found.bodies

    @pytest.mark.parametrize("structured", [False, True], ids=["manual", "structured"])
    def test_each_retry_sends_its_first_pass_through_the_marked_turn(
        self, monkeypatch: pytest.MonkeyPatch, structured: bool
    ) -> None:
        sent = self._compose(monkeypatch, structured)
        firsts = {
            (self._section(b), json.dumps(b.get("tools"))): b
            for b in sent
            if len(b["messages"]) == 1
        }
        assert {section for section, _tools in firsts} == set(COMPOSED_SECTIONS)
        for body in firsts.values():
            assert body["messages"][0]["content"][-1]["cache_control"] == MARK
        retries = [b for b in sent if len(b["messages"]) > 1]
        # On the manual path the stand-in answers break a rule, so sections
        # are asked again; a parsed structured answer here is not, and the
        # retry in its call's reply is checked on its own above.
        assert retries or structured
        for retry in retries:
            first = firsts[(self._section(retry), json.dumps(retry.get("tools")))]
            assert _through_first_turn(retry) == _through_first_turn(first)


class TestNeverAFifthBreakpoint:
    def test_no_composer_request_carries_more_than_four(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        composer = TestTheComposer()
        for structured in (False, True):
            for body in composer._compose(monkeypatch, structured):
                assert _markers(body) <= anthropic_history.MAX_BREAKPOINTS

    def test_no_request_reading_the_ledger_carries_more_than_four(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.agents.ledger_reads import LedgerReads

        from .test_a_structured_answer_in_text_is_kept import _in_text
        from .test_the_report_calls_may_read_the_ledger import LEDGER

        found = Wire(_in_text)
        install(monkeypatch, found)
        composer = ReportComposer(llm=_model(), per_section_timeout=60)
        composer.ledger_reads = LedgerReads(LEDGER)
        with patch(
            "malspark.reporting.composer.structured_output_supported_for_llm", return_value=True
        ):
            asyncio.run(composer.compose(_report(), _isr(), facts_block=FACTS, concurrent=True))
        assert found.bodies
        for body in found.bodies:
            assert _markers(body) <= anthropic_history.MAX_BREAKPOINTS

    def test_standing_facts_a_head_and_a_loop_stay_within_four(self, wire: Wire) -> None:
        from malspark.agents.technique_facts import STANDING_FACTS_CHARS
        from malspark.llm.anthropic_history import TOOL_LOOP_TURN

        pack = "TRIAGE PACK\n" + "standing fact\n" * 30
        text = pack + HEAD + TASK
        notes = {
            STANDING_FACTS_CHARS: len(pack),
            SHARED_HEAD: len(pack + HEAD),
            SENT_AGAIN: len(text),
            TOOL_LOOP_TURN: True,
        }
        first = HumanMessage(content=text, response_metadata=notes)
        model = _model(pack_cache_ttl="1h")
        system = SystemMessage(content=SYSTEM)
        turns: list[Any] = [system, first]
        for turn in range(2, 8, 2):
            model.invoke(turns)
            turns = [
                *turns,
                _answered(turn),
                HumanMessage(
                    content=f"{QUESTION} {turn}", response_metadata={TOOL_LOOP_TURN: True}
                ),
            ]
        model.invoke(turns)
        assert wire.refused == []
        for body in wire.bodies:
            assert _markers(body) <= anthropic_history.MAX_BREAKPOINTS


class TestEveryOtherCallKind:
    def test_every_body_is_the_one_built_before(self) -> None:
        before = json.loads(FIXTURE.read_text(encoding="utf-8"))
        now = bodies()
        assert list(now) == list(before)
        for kind in before:
            assert now[kind] == before[kind], kind


class TestOtherProviders:
    def test_the_note_changes_no_other_provider_s_body(self) -> None:
        from .provider_bodies import _ollama, _openai, _payload

        builders = {
            "deepseek": lambda: _openai("https://api.deepseek.com", "deepseek"),
            "llama": lambda: _openai("http://127.0.0.1:8080/v1", "auto"),
            "standard": lambda: _openai(None, "auto"),
            "ollama": _ollama,
        }
        system = SystemMessage(content=SYSTEM)
        for name, build in builders.items():
            model = build()
            noted = _payload(model, [system, _noted(HEAD + TASK, len(HEAD))])
            plain = _payload(model, [system, HumanMessage(content=HEAD + TASK)])
            assert json.dumps(noted, default=str) == json.dumps(plain, default=str), name
