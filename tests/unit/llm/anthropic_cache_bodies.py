"""The request bodies the Anthropic provider sends for call kinds noted as no turn sent again.

A single shot, a single shot with a shared head and with standing facts, a
tools-free validation retry and the questions after it, a tool loop and the
question at its end, and a retry answered in its call's reply noted as the
conversation's last. None of them carries a ``SENT_AGAIN`` note
(``anthropic_history.SENT_AGAIN``), so each body must be the one built before
that note existed: ``python -m tests.unit.llm.anthropic_cache_bodies PATH``
writes them, and the fixture holds what it wrote on the branch the note was
added to. With ``--lifetimes`` it writes them under every combination of
``prompt_cache_ttl`` and ``pack_cache_ttl`` (:data:`LIFETIMES`), keyed
``"<prompt>,<pack>"``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from .anthropic_wire import MODEL, Wire, install, message

USAGE = {"input_tokens": 10, "output_tokens": 5}
SYSTEM = "You are a static analyst."
HEAD = "DETERMINISTIC FACTS (complete list):\n- file_type: PE32 executable\n\n"
TASK = "Write the introduction.\n\nThe evidence follows.\n" + "evidence line\n" * 20
PACK = "TRIAGE PACK\n" + "standing fact\n" * 30
ANSWER = "CLAIM: it reads a file\nEVIDENCE: [ev_0001]\n"
QUESTION = "Your previous answer had these problems: claim 1 cites no entry. Fix it."
LIFETIMES = [(prompt, pack) for prompt in ("5m", "1h") for pack in ("off", "5m", "1h")]


class _What(BaseModel):
    what: str = ""


def _lookup() -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda what="": f"answer for {what}",
        name="lookup",
        description="Look it up.",
        args_schema=_What,
    )


def _thinking(turn: int) -> dict[str, Any]:
    return {"type": "thinking", "thinking": "", "signature": f"EoBsig{turn}/+=" * 8}


def _reply(body: dict[str, Any]) -> dict[str, Any]:
    turn = len(body["messages"])
    return message(
        [_thinking(turn), {"type": "text", "text": ANSWER}], stop="end_turn", usage=USAGE
    )


def _model(**anthropic: Any) -> Any:
    from malspark.core.config import Settings
    from malspark.llm.anthropic_provider import AnthropicProvider

    settings = Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key", **anthropic}},
    )
    return AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096)


def _answered(turn: int) -> AIMessage:
    return AIMessage(content=[_thinking(turn), {"type": "text", "text": ANSWER}])


def _called(turn: int, call: str) -> AIMessage:
    return AIMessage(
        content=[
            _thinking(turn),
            {"type": "tool_use", "id": call, "name": "lookup", "input": {"what": call}},
        ],
        tool_calls=[{"name": "lookup", "args": {"what": call}, "id": call}],
    )


def _sequences() -> dict[str, list[tuple[str, list[Any]]]]:
    """Each call kind: the requests one model sends, in order, with what each binds."""
    from malspark.agents.technique_facts import STANDING_FACTS_CHARS
    from malspark.llm.anthropic_history import LAST_REQUEST, SHARED_HEAD, TOOL_LOOP_TURN

    headed = HumanMessage(content=HEAD + TASK, response_metadata={SHARED_HEAD: len(HEAD)})
    standing = HumanMessage(
        content=PACK + TASK, response_metadata={STANDING_FACTS_CHARS: len(PACK)}
    )
    first = HumanMessage(content=TASK)
    loop_first = HumanMessage(content=TASK, response_metadata={TOOL_LOOP_TURN: True})
    loop_reply = ToolMessage(
        content="answer for call_0", tool_call_id="call_0", response_metadata={TOOL_LOOP_TURN: True}
    )
    last_reply = ToolMessage(
        content=QUESTION,
        tool_call_id="call_0",
        status="error",
        response_metadata={LAST_REQUEST: True},
    )
    system = SystemMessage(content=SYSTEM)
    return {
        "single shot": [("plain", [system, first])],
        "single shot, shared head": [("plain", [system, headed])],
        "single shot, standing facts": [("pack", [system, standing])],
        "tools-free retry and its questions": [
            ("plain", [system, first]),
            ("plain", [system, first, _answered(2), HumanMessage(content=QUESTION)]),
            (
                "plain",
                [
                    system,
                    first,
                    _answered(2),
                    HumanMessage(content=QUESTION),
                    _answered(4),
                    HumanMessage(content="Write your whole corrected answer."),
                ],
            ),
        ],
        "shared head, retry": [
            ("plain", [system, headed]),
            ("plain", [system, headed, _answered(2), HumanMessage(content=QUESTION)]),
        ],
        "tool loop and the question at its end": [
            ("tools", [system, loop_first]),
            ("tools", [system, loop_first, _called(2, "call_0"), loop_reply]),
            (
                "tools",
                [
                    system,
                    loop_first,
                    _called(2, "call_0"),
                    loop_reply,
                    _answered(4),
                    HumanMessage(content=QUESTION, response_metadata={LAST_REQUEST: True}),
                ],
            ),
        ],
        "retry in its call's reply, the last request": [
            ("tools", [system, headed]),
            ("tools", [system, headed, _called(2, "call_0"), last_reply]),
        ],
        "standing facts, tool loop": [
            ("pack-tools", [system, standing]),
            ("pack-tools", [system, standing, _called(2, "call_0"), loop_reply]),
        ],
    }


def bodies(
    prompt: str | None = None, pack_ttl: str | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Every body, keyed by the call kind that sent it, in the order sent.

    With ``prompt`` and ``pack_ttl``, every model is built with those
    lifetimes; else with the defaults, the standing facts' an hour.
    """
    lifetimes = (
        {"prompt_cache_ttl": prompt, "pack_cache_ttl": pack_ttl}
        if prompt is not None and pack_ttl is not None
        else None
    )
    out: dict[str, list[dict[str, Any]]] = {}
    with pytest.MonkeyPatch.context() as monkeypatch:
        for kind, requests in _sequences().items():
            wire = Wire(_reply)
            install(monkeypatch, wire)
            plain = _model(**(lifetimes or {}))
            pack = _model(**(lifetimes or {"pack_cache_ttl": "1h"}))
            for how, turns in requests:
                if how == "plain":
                    plain.invoke(turns)
                elif how == "pack":
                    pack.invoke(turns)
                elif how == "tools":
                    plain.bind_tools([_lookup()]).invoke(turns)
                else:
                    pack.bind_tools([_lookup()]).invoke(turns)
            out[kind] = wire.bodies
    return json.loads(json.dumps(out))


if __name__ == "__main__":
    import sys
    from pathlib import Path

    if "--lifetimes" in sys.argv[1:]:
        found: Any = {f"{prompt},{pack}": bodies(prompt, pack) for prompt, pack in LIFETIMES}
    else:
        found = bodies()
    path = next(arg for arg in sys.argv[1:] if not arg.startswith("--"))
    Path(path).write_text(json.dumps(found, indent=1) + "\n", encoding="utf-8")
