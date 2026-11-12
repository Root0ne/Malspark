"""The sampling a run records for a model is the sampling its requests carry on the wire.

The run summary's environment block says, per agent, which sampling
parameters each model sent (``llm.sent_request``), read off the model each
provider adapter built. That reading is only worth recording if it is what
leaves the process, so every shipped adapter is driven here against a stub
HTTP server on the loopback interface: the request body the client library
sends is captured as the server received it, and the sampling parameters in
it are compared with the record, the empty case included (a model documented
to refuse sampling parameters is sent none). The model identifier the stub's
answer names is the one the token ledger reads off the answer. No request
leaves the machine.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from malspark.core.config import Settings
from malspark.core.token_ledger import response_model_of
from malspark.llm.sent_request import (
    SAMPLING_PARAMETERS,
    SentRequest,
    carry_sent_request,
    record_sent_request,
    sampling_sent,
    sent_request_of,
)

# The model identifier each stub answer names, apart from the model asked for.
ANSWERED_AS = "wire-answered-model-1"


def _sse(answer: dict[str, Any]) -> bytes:
    """A chat completion as an OpenAI-compatible server streams it."""
    head = {**answer, "object": "chat.completion.chunk"}
    parts = [
        {**head, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "ok"}}]},
        {**head, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        {**head, "choices": [], "usage": answer["usage"]},
    ]
    return ("".join(f"data: {json.dumps(p)}\n\n" for p in parts) + "data: [DONE]\n\n").encode()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # noqa: D102 — quiet
        return

    def _answer(self, path: str, body: dict[str, Any]) -> tuple[int, str, bytes]:
        if path.endswith("/messages"):
            answer = {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": ANSWERED_AS,
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
            return 200, "application/json", json.dumps(answer).encode()
        if path.endswith("/chat/completions"):
            refuse = self.server.refuse  # type: ignore[attr-defined]
            if refuse and refuse in body:
                error = {"error": {"message": f"Unsupported parameter: {refuse}"}}
                return 400, "application/json", json.dumps(error).encode()
            answer = {
                "id": "c1",
                "object": "chat.completion",
                "created": 1,
                "model": ANSWERED_AS,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
            if body.get("stream"):
                return 200, "text/event-stream", _sse(answer)
            return 200, "application/json", json.dumps(answer).encode()
        if path.endswith("/api/chat"):
            line = {
                "model": ANSWERED_AS,
                "created_at": "2026-01-01T00:00:00Z",
                "message": {"role": "assistant", "content": "ok"},
                "done": True,
                "done_reason": "stop",
                "prompt_eval_count": 1,
                "eval_count": 1,
            }
            return 200, "application/x-ndjson", (json.dumps(line) + "\n").encode()
        if ":generateContent" in path:
            answer = {
                "candidates": [
                    {
                        "content": {"role": "model", "parts": [{"text": "ok"}]},
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 1,
                    "candidatesTokenCount": 1,
                    "totalTokenCount": 2,
                },
                "modelVersion": ANSWERED_AS,
            }
            return 200, "application/json", json.dumps(answer).encode()
        return 404, "application/json", b"{}"

    def do_POST(self) -> None:  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("content-length") or 0))
        body = json.loads(raw) if raw else {}
        path = self.path.split("?", 1)[0]
        self.server.bodies.append((path, body))  # type: ignore[attr-defined]
        status, kind, data = self._answer(path, body if isinstance(body, dict) else {})
        self.send_response(status)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST  # noqa: N815


@pytest.fixture
def server() -> Iterator[ThreadingHTTPServer]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    httpd.bodies = []  # type: ignore[attr-defined]
    httpd.refuse = ""  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(10)


def _url(httpd: ThreadingHTTPServer) -> str:
    host, port = httpd.server_address[:2]
    return f"http://{host}:{port}"


def _recorded(model: Any, provider: str) -> dict[str, Any]:
    """The record the registry keeps for ``model``: the same call it makes once built."""
    record_sent_request(model, SentRequest(agent="a", position=0, provider=provider, model="m"))
    held = sent_request_of(model)
    assert held is not None
    return dict(held.sampling)


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _sent(path: str, body: dict[str, Any]) -> dict[str, Any]:
    """The sampling parameters in one captured request body, where its API carries them."""
    if path.endswith("/api/chat"):
        held = dict(body.get("options") or {})
    elif ":generateContent" in path:
        held = {_snake(k): v for k, v in (body.get("generationConfig") or {}).items()}
    else:
        held = dict(body)
    return {name: held[name] for name in SAMPLING_PARAMETERS if name in held}


def _model_bodies(httpd: ThreadingHTTPServer) -> list[tuple[str, dict[str, Any]]]:
    paths = ("/messages", "/chat/completions", "/api/chat")
    return [
        (path, body)
        for path, body in httpd.bodies  # type: ignore[attr-defined]
        if path.endswith(paths) or ":generateContent" in path
    ]


def _anthropic(httpd: ThreadingHTTPServer, model: str, temperature: float) -> Any:
    from malspark.llm.anthropic_provider import AnthropicProvider

    settings = Settings(_env_file=None, llm={"anthropic": {"api_key": "test-value"}})
    return AnthropicProvider(settings).build_model(
        model, temperature, base_url=_url(httpd), max_retries=0, max_tokens=64
    )


def _openai(httpd: ThreadingHTTPServer, compat: str, temperature: float, **extra: Any) -> Any:
    from malspark.llm.openai_provider import OpenAIProvider, forget_standard_only

    forget_standard_only()
    settings = Settings(
        _env_file=None,
        llm={
            "openai": {
                "api_key": "test-value",
                "base_url": f"{_url(httpd)}/v1",
                "compat": compat,
                **extra,
            }
        },
    )
    return OpenAIProvider(settings).build_model("m", temperature, max_tokens=64)


def _ollama(httpd: ThreadingHTTPServer, temperature: float) -> Any:
    from malspark.llm.ollama_provider import OllamaProvider

    settings = Settings(_env_file=None, llm={"ollama": {"base_url": _url(httpd)}})
    return OllamaProvider(settings).build_model("m", temperature)


def _gemini(httpd: ThreadingHTTPServer, temperature: float) -> Any:
    from malspark.llm.gemini_provider import GeminiProvider

    settings = Settings(_env_file=None, llm={"gemini": {"api_key": "test-value"}})
    return GeminiProvider(settings).build_model("gemini-test", temperature, base_url=_url(httpd))


CASES = [
    pytest.param(lambda s: _anthropic(s, "claude-sonnet-4-6", 0.1), "anthropic", id="anthropic"),
    pytest.param(
        lambda s: _anthropic(s, "claude-haiku-5-5", 0.1), "anthropic", id="anthropic-fixed-sampling"
    ),
    pytest.param(lambda s: _openai(s, "standard", 0.1), "openai", id="openai-standard"),
    pytest.param(lambda s: _openai(s, "standard", 0.0), "openai", id="openai-temperature-zero"),
    pytest.param(
        lambda s: _openai(s, "llama_cpp", 0.2, repetition_penalty=1.1, dry_multiplier=0.8),
        "openai",
        id="openai-llama-cpp-samplers",
    ),
    pytest.param(lambda s: _ollama(s, 0.1), "ollama", id="ollama"),
    pytest.param(lambda s: _gemini(s, 0.1), "gemini", id="gemini"),
]


@pytest.mark.parametrize(("build", "provider"), CASES)
def test_the_recorded_sampling_is_what_the_request_body_carries(
    server: ThreadingHTTPServer, build: Any, provider: str
) -> None:
    model = build(server)
    recorded = _recorded(model, provider)
    answer = model.invoke("hello")
    bodies = _model_bodies(server)
    assert bodies, "no request reached the stub"
    for path, body in bodies:
        assert _sent(path, body) == recorded, (path, body)
    # The model the answer named, read as the token ledger reads it.
    assert response_model_of(answer) == ANSWERED_AS


def test_a_model_documented_to_refuse_sampling_records_and_sends_none(
    server: ThreadingHTTPServer,
) -> None:
    model = _anthropic(server, "claude-haiku-5-5", 0.7)
    assert _recorded(model, "anthropic") == {}
    model.invoke("hello")
    ((_path, body),) = _model_bodies(server)
    assert not set(body) & set(SAMPLING_PARAMETERS)


def test_the_llama_cpp_samplers_are_recorded_as_sent(server: ThreadingHTTPServer) -> None:
    model = _openai(server, "llama_cpp", 0.2, repetition_penalty=1.1, dry_multiplier=0.8)
    assert _recorded(model, "openai") == {
        "temperature": 0.2,
        "repeat_penalty": 1.1,
        "repetition_penalty": 1.1,
        "dry_multiplier": 0.8,
    }


def test_a_model_rebuilt_without_the_extras_records_what_it_now_sends(
    server: ThreadingHTTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The endpoint refuses the llama.cpp extras: the self-heal rebuilds the
    # model without them, and the record follows the rebuilt model.
    server.refuse = "repeat_penalty"  # type: ignore[attr-defined]
    model = _openai(server, "llama_cpp", 0.2, repetition_penalty=1.1)
    _recorded(model, "openai")
    healed: list[Any] = []
    from malspark.llm import openai_provider

    monkeypatch.setattr(openai_provider, "_HEAL_LISTENERS", [])
    openai_provider.on_model_healed(lambda _old, new: healed.append(new))
    # Awaited: the heal closes the replaced model's sync client, which the
    # async path does not use.
    asyncio.run(model.ainvoke("hello"))
    assert healed
    record = sent_request_of(model)
    assert record is not None and sent_request_of(healed[-1]) is record
    path, last = _model_bodies(server)[-1]
    assert "repeat_penalty" not in last
    assert _sent(path, last) == record.sampling == {"temperature": 0.2}


def test_carry_reads_the_replacement() -> None:
    class _Model:
        def __init__(self, **fields: Any) -> None:
            self.__dict__.update(fields)

    old, new = _Model(temperature=0.3, top_p=0.9), _Model(temperature=0.3)
    record_sent_request(old, SentRequest(agent="a", position=0, provider="p", model="m"))
    carry_sent_request(old, new)
    assert sent_request_of(new) is sent_request_of(old)
    assert sampling_sent(new) == sent_request_of(new).sampling == {"temperature": 0.3}  # type: ignore[union-attr]
