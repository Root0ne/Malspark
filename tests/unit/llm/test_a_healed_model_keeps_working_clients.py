"""A self-healed model, and every other model on its endpoint, keeps clients that work.

The self-heal rebuilds a local model without the llama.cpp extras an endpoint
rejected. It used to close the replaced model's synchronous httpx client, but
``langchain_openai`` hands every model for one endpoint and timeout the same
cached client, so the rebuilt model was given the very client just closed: the
next ``invoke`` on it — and on every other model for that endpoint in the
process — failed with "Cannot send a request, as the client has been closed".
An analyst's tool loop calls ``invoke``, so a local run lost its analysts.

These run the real provider against a stub endpoint on the loopback interface
that refuses ``repeat_penalty`` as an endpoint without the llama.cpp fields
does, and answers anything else.
"""

from __future__ import annotations

import gc
import json
import threading
import weakref
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest

from malspark.core.config import Settings
from malspark.llm import openai_provider
from malspark.llm.openai_provider import (
    OpenAIProvider,
    clear_shared_httpx_clients,
    forget_standard_only,
)

_ANSWER = {
    "id": "c",
    "object": "chat.completion",
    "created": 1,
    "model": "m",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}


class _Endpoint:
    """What the stub endpoint was asked: one entry per chat request."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.base_url = ""

    @property
    def rejected(self) -> int:
        return sum(1 for body in self.requests if "repeat_penalty" in body)


def _handler(endpoint: _Endpoint) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            return

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self._send(404, b"{}", "application/json")

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            if not self.path.endswith("/chat/completions"):
                self._send(404, b"{}", "application/json")
                return
            endpoint.requests.append(body)
            if "repeat_penalty" in body:
                error = {"error": {"message": "Unsupported parameter: repeat_penalty"}}
                self._send(400, json.dumps(error).encode(), "application/json")
                return
            if not body.get("stream"):
                self._send(200, json.dumps(_ANSWER).encode(), "application/json")
                return
            head = {**_ANSWER, "object": "chat.completion.chunk"}
            chunks = [
                {
                    **head,
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": "ok"}}],
                },
                {**head, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
                {**head, "choices": [], "usage": _ANSWER["usage"]},
            ]
            stream = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks)
            self._send(200, (stream + "data: [DONE]\n\n").encode(), "text/event-stream")

    return _Handler


@pytest.fixture
def endpoint() -> Iterator[_Endpoint]:
    seen = _Endpoint()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(seen))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    seen.base_url = f"http://127.0.0.1:{server.server_address[1]}/v1"
    try:
        yield seen
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[Any, Any]]]:
    """No endpoint memory, no cached client and no listener crosses tests."""
    swaps: list[tuple[Any, Any]] = []
    forget_standard_only()
    clear_shared_httpx_clients()
    monkeypatch.setattr(
        openai_provider, "_HEAL_LISTENERS", [lambda old, new: swaps.append((old, new))]
    )
    yield swaps
    forget_standard_only()
    clear_shared_httpx_clients()


def _provider(base_url: str, compat: str = "llama_cpp") -> OpenAIProvider:
    return OpenAIProvider(
        Settings(
            _env_file=None,
            llm={
                "openai": {
                    "api_key": "sk-test",
                    "base_url": base_url,
                    "compat": compat,
                    "repetition_penalty": 1.1,
                }
            },
        )
    )


def _sync_client(model: Any) -> Any:
    return model.root_client._client


def _assert_answers(model: Any) -> None:
    assert model.invoke("hi").content == "ok"


async def _assert_answers_async(model: Any) -> None:
    assert (await model.ainvoke("hi")).content == "ok"


class TestAfterASyncHeal:
    def test_the_healed_model_answers_sync_again(self, endpoint: _Endpoint) -> None:
        model = _provider(endpoint.base_url).build_model("m", 0.2, max_tokens=64)

        _assert_answers(model)
        _assert_answers(model)

        assert endpoint.rejected == 1, "the heal happened, once"

    @pytest.mark.asyncio
    async def test_the_healed_model_answers_async_too(
        self, endpoint: _Endpoint, _fresh_state: list[tuple[Any, Any]]
    ) -> None:
        model = _provider(endpoint.base_url).build_model("m", 0.2, max_tokens=64)
        _assert_answers(model)

        await _assert_answers_async(model)
        healed = _fresh_state[0][1]
        _assert_answers(healed)
        await _assert_answers_async(healed)

    @pytest.mark.asyncio
    async def test_a_model_built_earlier_on_the_endpoint_still_answers(
        self, endpoint: _Endpoint
    ) -> None:
        earlier = _provider(endpoint.base_url).build_model("m", 0.2, max_tokens=64)
        standard = _provider(endpoint.base_url, "standard").build_model("m", 0.2, max_tokens=64)
        healing = _provider(endpoint.base_url).build_model("m", 0.2, max_tokens=64)
        assert _sync_client(earlier) is _sync_client(healing), "one client for the endpoint"

        _assert_answers(healing)

        # The model built earlier still carries the extras: it heals on its own
        # first request, through the client it was built with.
        _assert_answers(earlier)
        await _assert_answers_async(earlier)
        _assert_answers(standard)
        await _assert_answers_async(standard)
        assert endpoint.rejected == 2, "each wrapped model healed once, the standard one never"


class TestAfterAnAsyncHeal:
    @pytest.mark.asyncio
    async def test_sync_and_async_answer_on_the_healed_model_and_an_earlier_one(
        self, endpoint: _Endpoint, _fresh_state: list[tuple[Any, Any]]
    ) -> None:
        earlier = _provider(endpoint.base_url, "standard").build_model("m", 0.2, max_tokens=64)
        model = _provider(endpoint.base_url).build_model("m", 0.2, max_tokens=64)

        await _assert_answers_async(model)
        healed = _fresh_state[0][1]

        _assert_answers(model)
        _assert_answers(healed)
        await _assert_answers_async(healed)
        _assert_answers(earlier)
        await _assert_answers_async(earlier)
        assert endpoint.rejected == 1


class TestWhoOwnsTheClients:
    def test_the_replacement_inherits_both_clients_and_none_is_closed(
        self, endpoint: _Endpoint, _fresh_state: list[tuple[Any, Any]]
    ) -> None:
        model = _provider(endpoint.base_url).build_model("m", 0.2, max_tokens=64)
        sync_before, async_before = _sync_client(model), model.http_async_client

        _assert_answers(model)
        (replaced, healed) = _fresh_state[0]

        assert replaced is model
        assert _sync_client(healed) is sync_before, "no second sync client per heal"
        assert healed.http_async_client is async_before, "no second async pool per heal"
        assert not sync_before.is_closed
        assert not async_before.is_closed

    def test_a_client_of_the_model_s_own_is_inherited_and_closed_with_it(
        self,
        endpoint: _Endpoint,
        _fresh_state: list[tuple[Any, Any]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A timeout langchain cannot hash gives the model a client nobody else holds.

        That one is the model's alone. The heal hands it to the replacement
        rather than opening another, and once neither model is held any more
        it is collected and closed: langchain's client wrapper closes itself
        when collected (``_SyncHttpxClientWrapper.__del__``).
        """
        from langchain_openai.chat_models._client_utils import _SyncHttpxClientWrapper

        closed: list[int] = []
        original_close = _SyncHttpxClientWrapper.close

        def recording_close(self: Any) -> None:
            closed.append(id(self))
            original_close(self)

        monkeypatch.setattr(_SyncHttpxClientWrapper, "close", recording_close)
        model = _provider(endpoint.base_url).build_model(
            "m", 0.2, max_tokens=64, request_timeout=httpx.Timeout(30.0)
        )
        other = _provider(endpoint.base_url).build_model(
            "m", 0.2, max_tokens=64, request_timeout=httpx.Timeout(30.0)
        )
        own = _sync_client(model)
        assert own is not _sync_client(other), "an unhashable timeout is not cached"

        _assert_answers(model)
        healed = _fresh_state[0][1]
        assert _sync_client(healed) is own
        assert not own.is_closed
        assert closed == [], "the heal closes nothing"

        own_id = id(own)
        freed = weakref.ref(own)
        del model, healed, own
        _fresh_state.clear()
        gc.collect()
        assert freed() is None, "nothing holds the client once its models are gone"
        assert own_id in closed, "and it was closed as it was collected"
        _assert_answers(other)

    @pytest.mark.asyncio
    async def test_a_model_whose_sync_client_cannot_be_found_still_heals(
        self, endpoint: _Endpoint, _fresh_state: list[tuple[Any, Any]]
    ) -> None:
        """No ``root_client._client`` to hand on: the rebuild takes langchain's own.

        Where the openai SDK keeps its client elsewhere the helper finds none,
        the replacement is built with whatever langchain gives it, and still
        nothing is closed.
        """
        model = _provider(endpoint.base_url).build_model("m", 0.2, max_tokens=64)
        cached = _sync_client(model)
        # ``invoke`` sends through ``model.client``; only the lookup is hidden.
        object.__setattr__(model, "root_client", object())
        assert openai_provider._sync_http_client_of(model) is None

        _assert_answers(model)
        healed = _fresh_state[0][1]

        await _assert_answers_async(model)
        _assert_answers(healed)
        await _assert_answers_async(healed)
        assert not cached.is_closed
        assert not model.http_async_client.is_closed
        assert endpoint.rejected == 1
