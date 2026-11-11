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
other providers send the same body with the note or without it. The mark
asks for five minutes whatever lifetime the other breakpoints ask for: its
only reader is the retry of the same call, and it is the request's last.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
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

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
FIXTURE = FIXTURES / "anthropic_bodies_before_sent_again.json"
BY_LIFETIME = FIXTURES / "anthropic_bodies_before_sent_again_by_lifetime.json"
USAGE = {"input_tokens": 10, "output_tokens": 5}
MARK = {"type": "ephemeral"}
HOUR = {"type": "ephemeral", "ttl": "1h"}
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


def _marks(body: dict[str, Any]) -> list[tuple[int, int, dict[str, str]]]:
    """Each breakpoint of the body's turns, in order: turn, block and marker."""
    return [
        (i, j, block["cache_control"])
        for i, turn in enumerate(body["messages"])
        if isinstance(turn["content"], list)
        for j, block in enumerate(turn["content"])
        if "cache_control" in block
    ]


def _lifetimes(body: dict[str, Any]) -> list[str]:
    """Each breakpoint's lifetime in the order the body holds them: tools, system, turns."""
    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("cache_control"), dict):
                found.append(value["cache_control"].get("ttl", "5m"))
            for inner in value.values():
                walk(inner)
        elif isinstance(value, list):
            for inner in value:
                walk(inner)

    walk([body.get("tools"), body.get("system"), body["messages"]])
    return found


def _in_order(body: dict[str, Any]) -> bool:
    """Whether no hour-long breakpoint follows a five-minute one, and at most four are set."""
    lifetimes = _lifetimes(body)
    after = lifetimes[lifetimes.index("5m") :] if "5m" in lifetimes else []
    return len(lifetimes) <= 4 and "1h" not in after


def _clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """The clock the provider reads its cache entries' age by, set by the test."""
    now = [1000.0]
    monkeypatch.setattr(anthropic_history, "time", SimpleNamespace(monotonic=lambda: now[0]))
    return now


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
    @pytest.mark.parametrize("ttl", ["5m", "1h"])
    @pytest.mark.parametrize("head", [0, len(HEAD)], ids=["whole turn", "shared head"])
    def test_a_retry_after_the_answer_sends_the_first_pass_through_its_mark(
        self, wire: Wire, head: int, ttl: str
    ) -> None:
        text = HEAD + TASK if head else TASK
        model = _model(prompt_cache_ttl=ttl)
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
        assert _in_order(first) and _in_order(retry)

    @pytest.mark.parametrize("ttl", ["5m", "1h"])
    @pytest.mark.parametrize("last", [True, False], ids=["kept answer", "not last"])
    def test_a_retry_in_its_call_s_reply_reads_the_first_turn(
        self, wire: Wire, ttl: str, last: bool
    ) -> None:
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
            response_metadata={LAST_REQUEST: True} if last else {},
        )
        bound = _model(prompt_cache_ttl=ttl).bind_tools([tool])
        turn = _noted(HEAD + TASK, len(HEAD))
        bound.invoke([SystemMessage(content=SYSTEM), turn])
        bound.invoke([SystemMessage(content=SYSTEM), turn, call, reply])
        first, retry = wire.bodies
        assert wire.refused == []
        assert _through_first_turn(retry) == _through_first_turn(first)
        assert _in_order(first) and _in_order(retry)
        if last:
            assert _markers(retry) == 2, (
                "the head and the turn's end; the last reply writes nothing"
            )
        else:
            # The reply's own breakpoint follows the turn's end, five minutes too.
            assert _lifetimes(retry)[1:] == ["5m", "5m"]

    def test_a_last_request_nothing_wrote_before_marks_only_the_head(self, wire: Wire) -> None:
        reply = HumanMessage(content=QUESTION, response_metadata={LAST_REQUEST: True})
        _model().invoke(
            [SystemMessage(content=SYSTEM), _noted(HEAD + TASK, len(HEAD)), _answered(2), reply]
        )
        (body,) = wire.bodies
        assert body["messages"][0]["content"][0]["cache_control"] == MARK
        assert "cache_control" not in body["messages"][0]["content"][1]
        assert _markers(body) == 1

    @pytest.mark.parametrize("ttl", ["5m", "1h"])
    @pytest.mark.parametrize("after", [299, 301, 1800])
    def test_a_last_request_reads_the_end_mark_within_its_five_minutes_only(
        self, wire: Wire, monkeypatch: pytest.MonkeyPatch, ttl: str, after: int
    ) -> None:
        now = _clock(monkeypatch)
        model = _model(prompt_cache_ttl=ttl)
        model.invoke([SystemMessage(content=SYSTEM), _noted(TASK)])
        now[0] += after
        reply = HumanMessage(content=QUESTION, response_metadata={LAST_REQUEST: True})
        model.invoke([SystemMessage(content=SYSTEM), _noted(TASK), _answered(2), reply])
        first, late = wire.bodies
        assert first["messages"][0]["content"][-1]["cache_control"] == MARK
        if after < 300:
            assert _marks(late) == [(0, 0, MARK)], "the entry the first pass wrote is read"
            assert _through_first_turn(late) == _through_first_turn(first)
        else:
            assert _markers(late) == 0, "the entry the first pass wrote has expired"

    def test_a_read_refreshes_the_end_mark_s_five_minutes(
        self, wire: Wire, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = _clock(monkeypatch)
        model = _model()
        model.invoke([SystemMessage(content=SYSTEM), _noted(TASK)])
        reply = HumanMessage(content=QUESTION, response_metadata={LAST_REQUEST: True})
        for after in (200, 250):
            now[0] += after
            model.invoke([SystemMessage(content=SYSTEM), _noted(TASK), _answered(2), reply])
        first, read, again = wire.bodies
        assert _marks(read) == _marks(again) == [(0, 0, MARK)], "450 s on, 250 s after a read"

    def test_a_retry_s_mark_on_the_turn_counts_for_five_minutes_under_the_hour(
        self, wire: Wire, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = _clock(monkeypatch)
        model = _model(prompt_cache_ttl="1h")
        model.invoke([SystemMessage(content=SYSTEM), _noted(TASK)])
        now[0] += 1
        retry = [SystemMessage(content=SYSTEM), _noted(TASK), _answered(2)]
        model.invoke([*retry, HumanMessage(content=QUESTION)])
        now[0] += 1800
        reply = HumanMessage(content=QUESTION, response_metadata={LAST_REQUEST: True})
        model.invoke([*retry, reply])
        _first, again, late = wire.bodies
        assert _marks(again)[0] == (0, 0, MARK)
        assert _markers(late) == 0, "the entry the retry read has expired"

    def test_an_hour_long_entry_of_the_prefix_is_kept_after_its_end_mark(
        self, wire: Wire, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.llm.anthropic_history import TOOL_LOOP_TURN

        # A loop's request, which keeps the setting's hour, writes the prefix
        # first; a single shot marks its end ten seconds later.
        now = _clock(monkeypatch)
        model = _model(prompt_cache_ttl="1h")
        looped = HumanMessage(
            content=TASK, response_metadata={SENT_AGAIN: len(TASK), TOOL_LOOP_TURN: True}
        )
        model.invoke([SystemMessage(content=SYSTEM), looped])
        now[0] += 10
        model.invoke([SystemMessage(content=SYSTEM), _noted(TASK)])
        now[0] += 990
        reply = HumanMessage(content=QUESTION, response_metadata={LAST_REQUEST: True})
        model.invoke([SystemMessage(content=SYSTEM), _noted(TASK), _answered(2), reply])
        loop, single, late = wire.bodies
        assert _marks(loop) == [(0, 0, HOUR)]
        assert _marks(single) == [(0, 0, MARK)]
        assert _marks(late) == [(0, 0, MARK)], "the hour's entry still holds the prefix"

    def test_a_loop_marks_its_later_turns_and_not_the_noted_turn_s_end(self, wire: Wire) -> None:
        from malspark.llm.anthropic_history import TOOL_LOOP_TURN

        loop = {TOOL_LOOP_TURN: True}
        first = HumanMessage(content=TASK, response_metadata={SENT_AGAIN: len(TASK), **loop})
        turns: list[Any] = [SystemMessage(content=SYSTEM), first]
        for turn in (2, 4):
            # Sent as a block list, which carries a breakpoint as it is.
            question = [{"type": "text", "text": f"{QUESTION} {turn}"}]
            turns += [_answered(turn), HumanMessage(content=question, response_metadata=loop)]
        _model().invoke(turns)
        (body,) = wire.bodies
        marked = [i for i, _j, _marker in _marks(body)]
        assert marked and 0 not in marked, "a later breakpoint reads the noted turn on its own"
        assert marked[-1] == len(body["messages"]) - 1

    def test_a_noted_turn_after_every_placed_breakpoint_carries_its_end_mark(
        self, wire: Wire
    ) -> None:
        from malspark.llm.anthropic_history import TOOL_LOOP_TURN

        # The opening turn, written by an earlier request of the model.
        opening = HumanMessage(content=[{"type": "text", "text": HEAD}])
        model = _model()
        model.invoke(
            [
                SystemMessage(content=SYSTEM),
                opening.model_copy(update={"response_metadata": {TOOL_LOOP_TURN: True}}),
            ]
        )
        # A noted turn sent as one text block, then two string turns, which
        # carry no breakpoint as sent: theirs fall back to the opening turn.
        noted = HumanMessage(
            content=[{"type": "text", "text": TASK}], response_metadata={SENT_AGAIN: len(TASK)}
        )
        model.invoke(
            [
                SystemMessage(content=SYSTEM),
                opening,
                _answered(2),
                noted,
                _answered(4),
                HumanMessage(content=f"{QUESTION} 4"),
                _answered(6),
                HumanMessage(content=f"{QUESTION} 6"),
            ]
        )
        body = wire.bodies[-1]
        assert wire.refused == []
        assert _marks(body) == [(0, 0, MARK), (2, 0, MARK)]
        assert _markers(body) <= 4

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

    def _compose(
        self, monkeypatch: pytest.MonkeyPatch, structured: bool, ttl: str = "5m"
    ) -> list[dict[str, Any]]:
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
        composer = ReportComposer(llm=_model(prompt_cache_ttl=ttl), per_section_timeout=60)
        with patch(
            "malspark.reporting.composer.structured_output_supported_for_llm",
            return_value=structured,
        ):
            asyncio.run(composer.compose(_report(), _isr(), facts_block=FACTS, concurrent=True))
        assert found.refused == []
        return found.bodies

    @pytest.mark.parametrize("ttl", ["5m", "1h"])
    @pytest.mark.parametrize("structured", [False, True], ids=["manual", "structured"])
    def test_each_retry_sends_its_first_pass_through_the_marked_turn(
        self, monkeypatch: pytest.MonkeyPatch, structured: bool, ttl: str
    ) -> None:
        sent = self._compose(monkeypatch, structured, ttl)
        assert all(_in_order(body) for body in sent)
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


class TestTheMarkAsksForFiveMinutes:
    """Under an hour's cache setting the turn's end asks for five minutes, after every hour."""

    def test_the_end_is_the_last_mark_and_the_only_short_one(self, wire: Wire) -> None:
        _model(prompt_cache_ttl="1h").invoke(
            [SystemMessage(content=SYSTEM), _noted(HEAD + TASK, len(HEAD))]
        )
        (body,) = wire.bodies
        assert wire.refused == []
        assert _marks(body) == [(0, 0, HOUR), (0, 1, MARK)]

    def test_with_standing_facts_every_hour_comes_before_it(self, wire: Wire) -> None:
        from malspark.agents.technique_facts import STANDING_FACTS_CHARS

        pack = "TRIAGE PACK\n" + "standing fact\n" * 30
        text = pack + HEAD + TASK
        notes = {
            STANDING_FACTS_CHARS: len(pack),
            SHARED_HEAD: len(pack + HEAD),
            SENT_AGAIN: len(text),
        }
        _model(prompt_cache_ttl="1h", pack_cache_ttl="1h").invoke(
            [SystemMessage(content=SYSTEM), HumanMessage(content=text, response_metadata=notes)]
        )
        (body,) = wire.bodies
        lifetimes = [marker for _i, _j, marker in _marks(body)]
        assert lifetimes[-1] == MARK and MARK not in lifetimes[:-1]
        assert body["messages"][0]["content"][-1]["cache_control"] == MARK

    def test_a_later_turn_s_head_leaves_the_end_unmarked(self, wire: Wire) -> None:
        model = _model(prompt_cache_ttl="1h")
        model.invoke([SystemMessage(content=SYSTEM), _noted(TASK)])
        later = HumanMessage(
            content=HEAD + QUESTION,
            response_metadata={SHARED_HEAD: len(HEAD), LAST_REQUEST: True},
        )
        model.invoke([SystemMessage(content=SYSTEM), _noted(TASK), _answered(2), later])
        body = wire.bodies[-1]
        assert _marks(body) == [(2, 0, HOUR)], "the head keeps its hour"
        assert "cache_control" not in body["messages"][0]["content"][-1], "the end is unmarked"

    @pytest.mark.parametrize("ttl", ["5m", "1h"])
    @pytest.mark.parametrize("last", [False, True], ids=["not last", "last"])
    def test_a_later_turn_s_head_keeps_the_body_a_call_without_the_note_sends(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        ttl: str,
        last: bool,
    ) -> None:
        marker = HOUR if ttl == "1h" else MARK
        notes: dict[str, Any] = {SHARED_HEAD: len(HEAD)}
        if last:
            notes[LAST_REQUEST] = True
        later = HumanMessage(content=HEAD + QUESTION, response_metadata=notes)
        sent: list[dict[str, Any]] = []
        for first in (_noted(TASK), HumanMessage(content=[{"type": "text", "text": TASK}])):
            found = Wire(_reply)
            install(monkeypatch, found)
            model = _model(prompt_cache_ttl=ttl)
            with caplog.at_level("WARNING", logger="malspark"):
                model.invoke([SystemMessage(content=SYSTEM), first])
                model.invoke([SystemMessage(content=SYSTEM), first, _answered(2), later])
            assert found.refused == []
            sent.append(found.bodies[-1])
        noted, plain = sent
        if last:
            assert _marks(noted) == [(2, 0, marker)], "the head only; the end is unmarked"
        else:
            assert _marks(noted) == [(0, 0, marker), (2, 0, marker), (2, 1, marker)]
        assert noted["messages"] == plain["messages"]
        assert not [r for r in caplog.records if "asking for an hour followed" in r.getMessage()]

    @pytest.mark.parametrize("ttl", ["5m", "1h"])
    def test_a_breakpoint_before_a_noted_later_turn_keeps_the_setting(
        self, wire: Wire, caplog: pytest.LogCaptureFixture, ttl: str
    ) -> None:
        # The opening turn, sent as one text block, carries the breakpoint
        # before the newest answer; the noted turn is the newest user turn.
        opening = HumanMessage(content=[{"type": "text", "text": TASK}])
        with caplog.at_level("WARNING", logger="malspark"):
            _model(prompt_cache_ttl=ttl).invoke(
                [SystemMessage(content=SYSTEM), opening, _answered(2), _noted(QUESTION)]
            )
        (body,) = wire.bodies
        assert wire.refused == []
        before = HOUR if ttl == "1h" else MARK
        assert _marks(body) == [(0, 0, before), (2, 0, MARK)]
        assert _in_order(body)
        assert not [r for r in caplog.records if "asking for an hour followed" in r.getMessage()]

    @pytest.mark.parametrize("ttl", ["5m", "1h"])
    def test_no_noted_call_s_request_is_shortened_after_it_is_built(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, ttl: str
    ) -> None:
        from langchain_core.tools import StructuredTool

        from malspark.agents.technique_facts import STANDING_FACTS_CHARS
        from malspark.llm.anthropic_history import TOOL_LOOP_TURN

        from .anthropic_cache_bodies import _What

        system = SystemMessage(content=SYSTEM)
        pack = "TRIAGE PACK\n" + "standing fact\n" * 30
        loop = {TOOL_LOOP_TURN: True}
        kept = {LAST_REQUEST: True}
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
        standing = HumanMessage(
            content=pack + HEAD + TASK,
            response_metadata={
                STANDING_FACTS_CHARS: len(pack),
                SHARED_HEAD: len(pack + HEAD),
                SENT_AGAIN: len(pack + HEAD + TASK),
            },
        )
        looped = HumanMessage(content=TASK, response_metadata={SENT_AGAIN: len(TASK), **loop})
        reply = HumanMessage(content=QUESTION, response_metadata=kept)
        shapes: list[tuple[bool, list[list[Any]]]] = []
        for head in (0, len(HEAD)):
            turn = _noted(HEAD + TASK if head else TASK, head)
            question = HumanMessage(content=QUESTION)
            shapes.append((False, [[system, turn], [system, turn, _answered(2), question]]))
            shapes.append((False, [[system, turn], [system, turn, _answered(2), reply]]))
            shapes.append((False, [[system, turn, _answered(2), reply]]))
            for meta in ({}, kept):
                answer = ToolMessage(
                    content=QUESTION, tool_call_id="call_0", status="error", response_metadata=meta
                )
                shapes.append((True, [[system, turn], [system, turn, call, answer]]))
        for meta in ({}, kept):
            later = HumanMessage(
                content=HEAD + QUESTION, response_metadata={SHARED_HEAD: len(HEAD), **meta}
            )
            shapes.append(
                (False, [[system, _noted(TASK)], [system, _noted(TASK), _answered(2), later]])
            )
        shapes.append((False, [[system, standing], [system, standing, _answered(2), reply]]))
        tail = [
            _answered(2),
            HumanMessage(content=[{"type": "text", "text": QUESTION}], response_metadata=loop),
        ]
        shapes.append((False, [[system, looped], [system, looped, *tail]]))
        for bound, requests in shapes:
            found = Wire(_reply)
            install(monkeypatch, found)
            model = _model(prompt_cache_ttl=ttl, pack_cache_ttl=ttl)
            runnable = model.bind_tools([tool]) if bound else model
            with caplog.at_level("WARNING", logger="malspark"):
                for turns in requests:
                    runnable.invoke(turns)
            assert found.refused == []
            assert all(_in_order(body) for body in found.bodies)
        composer = TestTheComposer()
        with caplog.at_level("WARNING", logger="malspark"):
            for structured in (False, True):
                composer._compose(monkeypatch, structured, ttl)
        assert not [r for r in caplog.records if "asking for an hour followed" in r.getMessage()]

    @pytest.mark.parametrize("head", [0, len(HEAD)], ids=["whole turn", "shared head"])
    def test_the_retry_sends_the_first_pass_through_its_mark(self, wire: Wire, head: int) -> None:
        text = HEAD + TASK if head else TASK
        model = _model(prompt_cache_ttl="1h")
        model.invoke([SystemMessage(content=SYSTEM), _noted(text, head)])
        reply = HumanMessage(content=QUESTION, response_metadata={LAST_REQUEST: True})
        model.invoke([SystemMessage(content=SYSTEM), _noted(text, head), _answered(2), reply])
        first, retry = wire.bodies
        assert wire.refused == []
        assert _through_first_turn(retry) == _through_first_turn(first)
        assert _marks(retry)[-1] == (0, len(retry["messages"][0]["content"]) - 1, MARK)


class TestNeverAFifthBreakpoint:
    def test_no_composer_request_carries_more_than_four(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        composer = TestTheComposer()
        for structured in (False, True):
            for ttl in ("5m", "1h"):
                for body in composer._compose(monkeypatch, structured, ttl):
                    assert _markers(body) <= 4

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
            assert _markers(body) <= 4

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
            assert _markers(body) <= 4

    def test_more_than_four_are_cut_to_four_keeping_the_first(self, wire: Wire) -> None:
        # Breakpoints a caller set on an earlier turn, beside the provider's own;
        # with no standing facts' breakpoint, the note alone has them counted.
        given = [{"type": "text", "text": f"part {n}\n", "cache_control": MARK} for n in range(4)]
        _model(pack_cache_ttl="off").invoke(
            [
                SystemMessage(content=SYSTEM),
                HumanMessage(content=given),
                _answered(2),
                _noted(TASK),
            ]
        )
        (body,) = wire.bodies
        marks = [(i, j) for i, j, _marker in _marks(body)]
        assert len(marks) == 4
        assert marks[0] == (0, 0), "the first, the longest-lived, is kept"
        assert marks[-1] == (2, 0)


class TestEveryOtherCallKind:
    def test_every_body_is_the_one_built_before(self) -> None:
        before = json.loads(FIXTURE.read_text(encoding="utf-8"))
        now = bodies()
        assert list(now) == list(before)
        for kind in before:
            assert now[kind] == before[kind], kind

    @pytest.mark.parametrize("prompt", ["5m", "1h"])
    @pytest.mark.parametrize("pack", ["off", "5m", "1h"])
    def test_under_every_lifetime_every_body_is_the_one_built_before(
        self, prompt: str, pack: str
    ) -> None:
        before = json.loads(BY_LIFETIME.read_text(encoding="utf-8"))[f"{prompt},{pack}"]
        now = bodies(prompt, pack)
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
