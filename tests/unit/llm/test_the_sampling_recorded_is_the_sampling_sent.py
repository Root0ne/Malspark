"""The sampling a run records for a model is the sampling its requests carry on the wire.

The run summary's environment block says, per agent, which sampling
parameters and thinking switches each model sent (``llm.sent_request``), read
by the provider adapter off the request body its client would send
(``LLMProvider.sent_parameters``). That reading is only worth recording if it
is what leaves the process, so every shipped adapter is driven here against a
stub HTTP server on the loopback interface: the request body the client
library sends is captured as the server received it and compared with the
record. The comparison runs over the body's own keys: every key is either a
known non-sampling field of its API or a recorded sampling parameter with the
value sent, so a sampling key the record does not know fails the test. The
models are driven directly, and through the registry and the container with
``bind_tools`` and ``with_structured_output`` awaited, as a run drives them.
The model identifier the stub's answer names is the one the token ledger reads
off the answer. No request leaves the machine.
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
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.tools import tool
from pydantic import BaseModel

from malspark.core.config import Settings
from malspark.core.token_ledger import response_model_of
from malspark.llm.sent_request import (
    NO_SAMPLING_SENT,
    NOT_REPORTED,
    SentRequest,
    carry_sent_request,
    parameters_sent,
    record_sent_request,
    sent_request_of,
)

# The model identifier each stub answer names, apart from the model asked for.
ANSWERED_AS = "wire-answered-model-1"
# The text each stub answer carries: JSON that fits the schema a structured
# call asks for, so a client that parses it as it arrives reads it.
ANSWER_TEXT = '{"answer": "ok"}'

# Per API, the body keys that are not sampling parameters, written out here
# rather than derived from the record's own list: a body key in neither this
# list nor the record fails the comparison.
NOT_SAMPLING: dict[str, frozenset[str]] = {
    "chat": frozenset(
        {
            "model",
            "messages",
            "stream",
            "stream_options",
            "max_completion_tokens",
            "max_tokens",
            "n_predict",
            "n",
            "tools",
            "tool_choice",
            "parallel_tool_calls",
            "response_format",
            "reasoning_effort",
            "chat_template_kwargs",
            "thinking",
            "stop",
        }
    ),
    "responses": frozenset(
        {
            "model",
            "input",
            "stream",
            "max_output_tokens",
            "reasoning",
            "include",
            "tools",
            "tool_choice",
            "text",
            "store",
            "parallel_tool_calls",
            "instructions",
        }
    ),
    "messages": frozenset(
        {
            "model",
            "messages",
            "system",
            "max_tokens",
            "stream",
            "tools",
            "tool_choice",
            "output_config",
            "thinking",
            "metadata",
        }
    ),
    "ollama": frozenset(
        {
            "model",
            "messages",
            "stream",
            "options",
            "format",
            "keep_alive",
            "tools",
            "think",
            "logprobs",
            "top_logprobs",
        }
    ),
    "ollama.options": frozenset({"num_ctx", "num_predict", "stop"}),
    "gemini": frozenset(
        {
            "contents",
            "systemInstruction",
            "tools",
            "toolConfig",
            "safetySettings",
            "generationConfig",
            "labels",
        }
    ),
    "gemini.generationConfig": frozenset(
        {
            "maxOutputTokens",
            "candidateCount",
            "stopSequences",
            "thinkingConfig",
            "responseMimeType",
            "responseJsonSchema",
            "responseSchema",
        }
    ),
}

# Per API, where a body carries a thinking switch, as dotted paths of the body.
THINKING_AT: dict[str, tuple[str, ...]] = {
    "chat": ("chat_template_kwargs.enable_thinking", "thinking"),
    "responses": (),
    "messages": ("thinking",),
    "ollama": ("think",),
    "gemini": ("generationConfig.thinkingConfig",),
}


def _sse(answer: dict[str, Any]) -> bytes:
    """A chat completion as an OpenAI-compatible server streams it."""
    head = {**answer, "object": "chat.completion.chunk"}
    parts = [
        {**head, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ANSWER_TEXT}}]},
        {**head, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        {**head, "choices": [], "usage": answer["usage"]},
    ]
    return ("".join(f"data: {json.dumps(p)}\n\n" for p in parts) + "data: [DONE]\n\n").encode()


def _anthropic_sse() -> bytes:
    """A Messages API answer as the server streams it."""
    events = [
        (
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "model": ANSWERED_AS,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            },
        ),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": ANSWER_TEXT},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 1},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    ]
    return "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events).encode()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # noqa: D102 — quiet
        return

    def _answer(self, path: str, body: dict[str, Any]) -> tuple[int, str, bytes]:
        if path.endswith("/messages"):
            if body.get("stream"):
                return 200, "text/event-stream", _anthropic_sse()
            answer = {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": ANSWERED_AS,
                "content": [{"type": "text", "text": ANSWER_TEXT}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
            return 200, "application/json", json.dumps(answer).encode()
        if path.endswith("/responses"):
            answer = {
                "id": "resp_1",
                "object": "response",
                "created_at": 1,
                "status": "completed",
                "model": ANSWERED_AS,
                "output": [
                    {
                        "type": "message",
                        "id": "msg_1",
                        "status": "completed",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": ANSWER_TEXT, "annotations": []}
                        ],
                    }
                ],
                "parallel_tool_calls": True,
                "tool_choice": "auto",
                "tools": [],
                "usage": {
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "total_tokens": 2,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens_details": {"reasoning_tokens": 0},
                },
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
                        "message": {"role": "assistant", "content": ANSWER_TEXT},
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
                "message": {"role": "assistant", "content": ANSWER_TEXT},
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
                        "content": {"role": "model", "parts": [{"text": ANSWER_TEXT}]},
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


def _recorded(model: Any, provider: str) -> SentRequest:
    """The record the registry keeps for ``model``: the same call it makes once built."""
    record_sent_request(model, SentRequest(agent="a", position=0, provider=provider, model="m"))
    held = sent_request_of(model)
    assert held is not None
    return held


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _api(path: str) -> str:
    if path.endswith("/api/chat"):
        return "ollama"
    if ":generateContent" in path:
        return "gemini"
    if path.endswith("/responses"):
        return "responses"
    if path.endswith("/messages"):
        return "messages"
    return "chat"


def _at(body: Any, path: str) -> Any:
    for part in path.split("."):
        body = body.get(part) if isinstance(body, dict) else None
    return body


def _leaves(value: Any, path: str) -> dict[str, Any]:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, held in value.items():
            out.update(_leaves(held, f"{path}.{key}"))
        return out
    return {} if value is None else {path: value}


def _unaccounted(path: str, body: dict[str, Any], record: SentRequest) -> list[str]:
    """Every way ``body`` differs from ``record``; empty when the record is what was sent."""
    api = _api(path)
    sampling = dict(record.sampling or {})
    problems: list[str] = []
    # Where the API carries its sampling, and the keys around it.
    if api == "ollama":
        layers = [("ollama", body), ("ollama.options", body.get("options") or {})]
        carrier = body.get("options") or {}
    elif api == "gemini":
        config = body.get("generationConfig") or {}
        layers = [("gemini", body), ("gemini.generationConfig", config)]
        carrier = {_snake(k): v for k, v in config.items()}
    else:
        layers = [(api, body)]
        carrier = body
    for name, layer in layers:
        for key in layer:
            snake = _snake(key) if api == "gemini" else key
            if key in NOT_SAMPLING[name]:
                continue
            if name in ("gemini", "ollama"):
                # Those APIs carry no sampling at the top of the body.
                problems.append(f"{key} is no known field of {name}'s request")
                continue
            if snake not in sampling:
                problems.append(f"{key}={layer[key]!r} was sent and is not recorded")
            elif sampling[snake] != layer[key]:
                problems.append(f"{key} sent {layer[key]!r}, recorded {sampling[snake]!r}")
    for name, value in sampling.items():
        if name not in carrier:
            problems.append(f"{name}={value!r} is recorded and was not sent")
    # The thinking switches, compared leaf by leaf.
    sent_thinking: dict[str, Any] = {}
    for where in THINKING_AT[api]:
        sent_thinking.update(_leaves(_at(body, where), where))
    if api == "gemini":
        sent_thinking = {
            ".".join(_snake(p) for p in k.split(".")[1:]): v for k, v in sent_thinking.items()
        }
    if sent_thinking != dict(record.thinking or {}):
        problems.append(f"thinking sent {sent_thinking!r}, recorded {record.thinking!r}")
    return problems


def _model_bodies(httpd: ThreadingHTTPServer) -> list[tuple[str, dict[str, Any]]]:
    paths = ("/messages", "/chat/completions", "/api/chat", "/responses")
    return [
        (path, body)
        for path, body in httpd.bodies  # type: ignore[attr-defined]
        if path.endswith(paths) or ":generateContent" in path
    ]


def _anthropic(httpd: ThreadingHTTPServer, model: str, temperature: float, **extra: Any) -> Any:
    from malspark.llm.anthropic_provider import AnthropicProvider

    settings = Settings(_env_file=None, llm={"anthropic": {"api_key": "test-value"}})
    return AnthropicProvider(settings).build_model(
        model, temperature, base_url=_url(httpd), max_retries=0, **{"max_tokens": 64, **extra}
    )


def _openai(
    httpd: ThreadingHTTPServer, compat: str, temperature: float, model: str = "m", **extra: Any
) -> Any:
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
    return OpenAIProvider(settings).build_model(model, temperature, max_tokens=64)


def _ollama(httpd: ThreadingHTTPServer, temperature: float, **extra: Any) -> Any:
    from malspark.llm.ollama_provider import OllamaProvider

    settings = Settings(_env_file=None, llm={"ollama": {"base_url": _url(httpd), **extra}})
    return OllamaProvider(settings).build_model("m", temperature)


def _gemini(httpd: ThreadingHTTPServer, temperature: float, model: str = "gemini-test") -> Any:
    from malspark.llm.gemini_provider import GeminiProvider

    settings = Settings(_env_file=None, llm={"gemini": {"api_key": "test-value"}})
    return GeminiProvider(settings).build_model(model, temperature, base_url=_url(httpd))


CASES = [
    pytest.param(lambda s: _anthropic(s, "claude-sonnet-4-6", 0.1), "anthropic", id="anthropic"),
    pytest.param(
        lambda s: _anthropic(s, "claude-haiku-5-5", 0.1), "anthropic", id="anthropic-fixed-sampling"
    ),
    pytest.param(
        lambda s: _anthropic(s, "claude-sonnet-4-6", 0.1, streaming=True, stream_usage=True),
        "anthropic",
        id="anthropic-streaming",
    ),
    pytest.param(lambda s: _openai(s, "standard", 0.1), "openai", id="openai-standard"),
    pytest.param(lambda s: _openai(s, "standard", 0.0), "openai", id="openai-temperature-zero"),
    pytest.param(
        lambda s: _openai(s, "standard", 1.0, model="gpt-5-pro"),
        "openai",
        id="openai-responses-api",
    ),
    pytest.param(
        lambda s: _openai(
            s, "llama_cpp", 0.2, repetition_penalty=1.1, dry_multiplier=0.8, disable_thinking=True
        ),
        "openai",
        id="openai-llama-cpp-samplers-streaming",
    ),
    pytest.param(
        lambda s: _openai(s, "deepseek", 0.3, model="deepseek-chat", disable_thinking=True),
        "openai",
        id="openai-deepseek-thinking-off",
    ),
    pytest.param(lambda s: _ollama(s, 0.1), "ollama", id="ollama"),
    pytest.param(
        lambda s: _ollama(s, 0.1, disable_thinking=True), "ollama", id="ollama-thinking-off"
    ),
    pytest.param(lambda s: _gemini(s, 0.1), "gemini", id="gemini"),
    pytest.param(
        lambda s: _gemini(s, 0.1, model="gemini-3.6-flash"), "gemini", id="gemini-3.6-flash-fixed"
    ),
    pytest.param(
        lambda s: _gemini(s, 0.1, model="gemini-3.5-flash-lite"),
        "gemini",
        id="gemini-3.5-flash-lite-fixed",
    ),
]


@pytest.mark.filterwarnings("ignore:Model 'gemini:UserWarning")
@pytest.mark.parametrize(("build", "provider"), CASES)
def test_the_recorded_parameters_are_what_the_request_body_carries(
    server: ThreadingHTTPServer, build: Any, provider: str
) -> None:
    model = build(server)
    record = _recorded(model, provider)
    assert record.sampling is not None and record.thinking is not None
    answer = model.invoke("hello")
    bodies = _model_bodies(server)
    assert bodies, "no request reached the stub"
    for path, body in bodies:
        assert _unaccounted(path, body, record) == [], (path, body)
    # The model the answer named, read as the token ledger reads it, on the
    # streaming paths too.
    assert response_model_of(answer) == ANSWERED_AS


@pytest.mark.filterwarnings("ignore:Model 'gemini:UserWarning")
@pytest.mark.parametrize(
    ("build", "provider"),
    [
        pytest.param(lambda s: _anthropic(s, "claude-haiku-5-5", 0.7), "anthropic", id="anthropic"),
        pytest.param(
            lambda s: _openai(s, "standard", 1.0, model="gpt-5-pro"), "openai", id="openai"
        ),
        pytest.param(lambda s: _gemini(s, 0.7, model="gemini-3.6-flash"), "gemini", id="gemini"),
    ],
)
def test_a_model_sent_no_sampling_records_none_sent(
    server: ThreadingHTTPServer, build: Any, provider: str
) -> None:
    record = _recorded(build(server), provider)
    assert record.sampling == {}
    assert record.as_dict()["sampling_statement"] == NO_SAMPLING_SENT


def test_the_llama_cpp_samplers_and_switch_are_recorded_as_sent(
    server: ThreadingHTTPServer,
) -> None:
    model = _openai(
        server, "llama_cpp", 0.2, repetition_penalty=1.1, dry_multiplier=0.8, disable_thinking=True
    )
    record = _recorded(model, "openai")
    assert record.sampling == {
        "temperature": 0.2,
        "repeat_penalty": 1.1,
        "repetition_penalty": 1.1,
        "dry_multiplier": 0.8,
    }
    assert record.thinking == {"chat_template_kwargs.enable_thinking": False}


def test_ollama_s_thinking_switch_is_recorded(server: ThreadingHTTPServer) -> None:
    record = _recorded(_ollama(server, 0.1, disable_thinking=True), "ollama")
    assert record.thinking == {"think": False}


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
    assert _unaccounted(path, last, record) == []
    assert record.sampling == {"temperature": 0.2}


def test_carry_reads_the_replacement(server: ThreadingHTTPServer) -> None:
    old = _openai(server, "standard", 0.3)
    new = _openai(server, "standard", 0.5)
    record_sent_request(old, SentRequest(agent="a", position=0, provider="openai", model="m"))
    carry_sent_request(old, new)
    assert sent_request_of(new) is sent_request_of(old)
    assert sent_request_of(new).sampling == {"temperature": 0.5}  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# What no hook can read is not reported, never "none sent"


class _PlugIn(FakeListChatModel):
    # Sent as "temperature" by its own request builder, under a field name of its own.
    temp: float = 0.7


def test_a_plug_in_model_with_no_hook_is_not_reported() -> None:
    model = _PlugIn(responses=["x"])
    record = SentRequest(agent="a", position=0, provider="plug", model="m")
    record_sent_request(model, record)
    row = record.as_dict()
    assert row["sampling"] is None and row["thinking"] is None
    assert row["sampling_statement"] == NOT_REPORTED


def test_a_model_of_another_kind_is_not_read_by_an_adapter(server: ThreadingHTTPServer) -> None:
    assert parameters_sent("openai", _PlugIn(responses=["x"])) is None
    assert parameters_sent("anthropic", _openai(server, "standard", 0.1)) is None


def test_a_hook_that_fails_reports_nothing() -> None:
    class _Broken:
        @classmethod
        def sent_parameters(cls, llm: Any) -> Any:
            raise RuntimeError("broken")

    assert parameters_sent(_Broken, object()) is None


def test_a_binding_is_read_through_to_its_bound_arguments(server: ThreadingHTTPServer) -> None:
    from langchain_openai import ChatOpenAI

    bound = ChatOpenAI(
        model="m", api_key="test-value", base_url=f"{_url(server)}/v1", temperature=0.1
    ).bind(temperature=0.9, top_p=0.5)
    record = SentRequest(agent="a", position=0, provider="openai", model="m")
    record_sent_request(bound, record)
    assert record.sampling == {"temperature": 0.9, "top_p": 0.5}
    bound.invoke("hello")
    ((path, body),) = _model_bodies(server)
    assert _unaccounted(path, body, record) == []


# ---------------------------------------------------------------------------
# Through the registry and the container, as a run drives a model


class _Verdict(BaseModel):
    answer: str


@tool
def read_evidence(entry: str) -> str:
    """Read one evidence entry."""
    return entry


def _container(settings: Settings) -> Any:
    from malspark.core.container import ServiceContainer
    from malspark.llm.registry import LLMProviderRegistry

    container = ServiceContainer(config=settings, mock=True)
    container._llm_registry = LLMProviderRegistry(settings)
    return container


def _settings(provider: str, httpd: ThreadingHTTPServer) -> Settings:
    blocks: dict[str, dict[str, Any]] = {
        "openai": {
            "api_key": "test-value",
            "base_url": f"{_url(httpd)}/v1",
            "compat": "standard",
            "expert_model": "m",
        },
        "anthropic": {
            "api_key": "test-value",
            "base_url": _url(httpd),
            "expert_model": "claude-sonnet-4-6",
            "effort": "high",
        },
        "ollama": {"base_url": _url(httpd), "expert_model": "m"},
        "gemini": {"api_key": "test-value", "expert_model": "gemini-test"},
    }
    return Settings(
        _env_file=None,
        llm={"provider": provider, provider: blocks[provider], "expert_max_tokens": 64},
    )


@pytest.mark.parametrize("provider", ["openai", "anthropic", "ollama", "gemini"])
def test_through_the_container_with_tools_and_a_schema_awaited(
    server: ThreadingHTTPServer, provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if provider == "gemini":
        # Gemini has no address setting; the stub is handed to its build.
        from malspark.llm.gemini_provider import GeminiProvider

        built = GeminiProvider.build_model
        monkeypatch.setattr(
            GeminiProvider,
            "build_model",
            lambda self, model, temperature, **kw: built(
                self, model, temperature, base_url=_url(server), **kw
            ),
        )
    container = _container(_settings(provider, server))
    llm = container.get_agent_llm("static")
    (record,) = container._llm_registry.sent_requests()
    assert record.agent == "static" and record.sampling is not None

    async def drive() -> None:
        await llm.bind_tools([read_evidence]).ainvoke("hello")
        await llm.with_structured_output(_Verdict, include_raw=True).ainvoke("hello")

    asyncio.run(drive())
    bodies = _model_bodies(server)
    assert len(bodies) == 2
    for path, body in bodies:
        assert _unaccounted(path, body, record) == [], (path, body)
    if provider == "anthropic":
        # The effort the record names is the effort on the wire.
        assert record.effort == "high"
        assert record.effort_setting == "llm.anthropic.effort"
        assert all(body["output_config"]["effort"] == record.effort for _p, body in bodies)


def test_a_sampling_key_the_record_does_not_know_fails_the_comparison() -> None:
    record = SentRequest(
        agent="a", position=0, provider="openai", model="m", sampling={"temperature": 0.1}
    )
    body = {"model": "m", "messages": [], "temperature": 0.1, "xtc_probability": 0.5}
    assert _unaccounted("/v1/chat/completions", body, record) == [
        "xtc_probability=0.5 was sent and is not recorded"
    ]
