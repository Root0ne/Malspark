"""No platform path streams or batches a provider-built chat model directly.

A local OpenAI-compatible model that answers HTTP 400 is healed: rebuilt with
adjusted parameters and retried. The heal is installed on the model's
``invoke`` and ``ainvoke`` only. ``batch`` and ``abatch`` reach it because the
base class runs them through ``invoke`` and ``ainvoke``; ``stream``,
``astream`` and ``astream_events`` on the model object do not, so a 400 raised
there is not healed.

The platform stays inside the healed calls: a model, or a runnable bound from
it (``bind_tools``, ``with_structured_output``, ``bind``), is only ever invoked,
and a LangGraph loop that is streamed (``graph.astream``) calls its model
through ``ainvoke`` at every step. This test pins both halves:

* it reads every Python module of the core, the API, the services and the
  scripts with ``ast`` and fails, naming file and line, where a
  ``stream`` / ``astream`` / ``astream_events`` / ``batch`` / ``abatch`` (or
  their ``*_as_completed`` forms) is called on an expression that names a
  model: a name or attribute made of the words ``llm`` or ``model``, a
  ``build_model`` result, a chain of ``bind*`` / ``with_*`` calls on one, or a
  variable assigned from any of these. Streams of httpx responses and of
  compiled graphs are not model expressions and are not flagged;
* it runs a healed model through a binding and through a streamed ReAct graph
  against an in-process transport, which is what makes the graph exemption
  true: every step that reached the model after the 400 was the healed call.

A new call form that reaches the model without ``invoke`` or ``ainvoke`` has to
be covered by the heal itself before this test is changed.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

import httpx
import pytest

from malspark.core.config import Settings
from malspark.llm.openai_provider import (
    OpenAIProvider,
    clear_shared_httpx_clients,
    forget_standard_only,
)

ROOT = Path(__file__).resolve().parents[3]
SOURCES = (
    ROOT / "src" / "malspark",
    ROOT / "apps" / "api",
    ROOT / "services",
    ROOT / "scripts",
)
SKIPPED_DIRS = frozenset({"node_modules", ".venv", "__pycache__", ".next"})

# The call forms the heal on ``invoke`` / ``ainvoke`` does not cover directly.
UNHEALED_FORMS = frozenset(
    {
        "stream",
        "astream",
        "astream_events",
        "astream_log",
        "batch",
        "abatch",
        "batch_as_completed",
        "abatch_as_completed",
        "transform",
        "atransform",
    }
)
# Calls that return a runnable made from the model they are called on.
DERIVING_CALLS = frozenset(
    {
        "bind",
        "bind_tools",
        "bind_functions",
        "with_structured_output",
        "with_config",
        "with_retry",
        "with_fallbacks",
        "with_types",
        "with_listeners",
        "pipe",
    }
)
# Calls that build a model.
BUILDING_CALLS = frozenset({"build_model", "init_chat_model"})
MODEL_WORDS = frozenset({"llm", "llms", "model", "models"})


def _words(identifier: str) -> set[str]:
    return {part for part in re.split(r"_+", identifier.lower()) if part}


def _names_a_model(identifier: str) -> bool:
    return bool(_words(identifier) & MODEL_WORDS)


def _is_model_expression(node: ast.AST, tainted: set[str]) -> bool:
    """Whether ``node`` names a chat model, or a runnable derived from one."""
    if isinstance(node, ast.Name):
        return node.id in tainted or _names_a_model(node.id)
    if isinstance(node, ast.Attribute):
        return _names_a_model(node.attr) or node.attr in tainted
    if isinstance(node, ast.Subscript):
        return _is_model_expression(node.value, tainted)
    if isinstance(node, ast.Await):
        return _is_model_expression(node.value, tainted)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in BUILDING_CALLS:
                return True
            if func.attr in DERIVING_CALLS:
                return _is_model_expression(func.value, tainted)
        if isinstance(func, ast.Name) and func.id in BUILDING_CALLS:
            return True
    return False


def _assigned_names(target: ast.AST) -> Iterator[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Attribute):
        yield target.attr
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            yield from _assigned_names(element)


def _tainted_names(tree: ast.AST) -> set[str]:
    """Names assigned, anywhere in the module, from a model expression."""
    tainted: set[str] = set()
    grew = True
    while grew:
        grew = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if not _is_model_expression(value, tainted):
                continue
            for target in targets:
                for name in _assigned_names(target):
                    if name not in tainted:
                        tainted.add(name)
                        grew = True
    return tainted


def unhealed_calls(source: str) -> list[tuple[int, str]]:
    """``(line, form)`` of each stream or batch call made on a model expression."""
    tree = ast.parse(source)
    tainted = _tainted_names(tree)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in UNHEALED_FORMS
            and _is_model_expression(func.value, tainted)
        ):
            found.append((node.lineno, func.attr))
        # ``getattr(model, "astream")`` reaches the same method.
        elif (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in UNHEALED_FORMS
            and _is_model_expression(node.args[0], tainted)
        ):
            found.append((node.lineno, str(node.args[1].value)))
    return sorted(found)


def _python_files() -> Iterator[Path]:
    for root in SOURCES:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            if not SKIPPED_DIRS.intersection(path.relative_to(ROOT).parts):
                yield path


class TestTheDetector:
    @pytest.mark.parametrize(
        "line",
        [
            "self.llm.astream(messages)",
            "llm.stream(messages)",
            "model.batch(items)",
            "await self._model.abatch(items)",
            "self.llm.bind_tools(tools).astream(messages)",
            "self.llm.with_structured_output(Schema).astream(messages)",
            "provider.build_model('m', 0.0).stream(messages)",
            "chat = self.llm.bind(max_tokens=3)\nchat.astream_events(messages)",
            "getattr(self.llm, 'astream')(messages)",
        ],
    )
    def test_a_streamed_or_batched_model_is_found(self, line: str) -> None:
        assert unhealed_calls(line), line

    @pytest.mark.parametrize(
        "line",
        [
            "self.llm.invoke(messages)",
            "await self.llm.bind_tools(tools).ainvoke(messages)",
            "http.stream('GET', url)",
            "self._http.stream('GET', url)",
            "response.stream(CHUNK)",
            "request.stream()",
            "graph['executor'].astream(state, stream_mode='values')",
            "self.graph.astream(state)",
        ],
    )
    def test_an_unrelated_stream_is_not(self, line: str) -> None:
        assert not unhealed_calls(line), line


def test_no_platform_path_streams_or_batches_a_provider_model() -> None:
    found: list[str] = []
    scanned = 0
    for path in _python_files():
        scanned += 1
        try:
            hits = unhealed_calls(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        found.extend(f"{path.relative_to(ROOT)}:{line}: .{form}()" for line, form in hits)
    assert scanned > 100, "the walk found the source tree"
    assert not found, (
        "a provider model is streamed or batched where the 400 heal does not reach "
        "(it is installed on invoke and ainvoke only):\n" + "\n".join(found)
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


def _transport(requests: list[dict[str, Any]]) -> httpx.MockTransport:
    """An endpoint that refuses ``repeat_penalty`` and answers anything else."""

    def answer(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        if "repeat_penalty" in body:
            error = {"error": {"message": "Unsupported parameter: repeat_penalty"}}
            return httpx.Response(400, json=error)
        if not body.get("stream"):
            return httpx.Response(200, json=_ANSWER)
        head = {**_ANSWER, "object": "chat.completion.chunk"}
        chunks = [
            {**head, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "ok"}}]},
            {**head, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
            {**head, "choices": [], "usage": _ANSWER["usage"]},
        ]
        stream = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=(stream + "data: [DONE]\n\n").encode(),
        )

    return httpx.MockTransport(answer)


@pytest.fixture(autouse=True)
def _fresh_endpoint_memory() -> Iterator[None]:
    forget_standard_only()
    clear_shared_httpx_clients()
    yield
    forget_standard_only()
    clear_shared_httpx_clients()


def _model(requests: list[dict[str, Any]]) -> Any:
    provider = OpenAIProvider(
        Settings(
            _env_file=None,
            llm={
                "openai": {
                    "api_key": "sk-test",
                    "base_url": "http://127.0.0.1:9/v1",
                    "compat": "llama_cpp",
                    "repetition_penalty": 1.1,
                }
            },
        )
    )
    return provider.build_model(
        "m",
        0.2,
        max_tokens=64,
        http_client=httpx.Client(transport=_transport(requests)),
        http_async_client=httpx.AsyncClient(transport=_transport(requests)),
    )


def _tool() -> Any:
    from langchain_core.tools import tool

    @tool
    def echo(text: str) -> str:
        """Return the text."""
        return text

    return echo


class TestTheHealSurvivesWhatIsBuiltOnTheModel:
    def test_a_bound_model_calls_the_healed_invoke(self) -> None:
        requests: list[dict[str, Any]] = []
        bound = _model(requests).bind_tools([_tool()])

        assert bound.invoke("hi").content == "ok"

        assert ["repeat_penalty" in body for body in requests] == [True, False]

    @pytest.mark.asyncio
    async def test_a_bound_model_calls_the_healed_ainvoke(self) -> None:
        requests: list[dict[str, Any]] = []
        bound = _model(requests).bind_tools([_tool()])

        assert (await bound.ainvoke("hi")).content == "ok"

        assert ["repeat_penalty" in body for body in requests] == [True, False]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", ["values", "messages"])
    async def test_a_streamed_react_graph_reaches_the_model_through_the_heal(
        self, mode: Literal["values", "messages"]
    ) -> None:
        from langgraph.prebuilt import create_react_agent

        requests: list[dict[str, Any]] = []
        tool = _tool()
        graph = create_react_agent(_model(requests).bind_tools([tool]), [tool])

        seen = [
            step async for step in graph.astream({"messages": [("user", "hi")]}, stream_mode=mode)
        ]

        assert seen
        assert ["repeat_penalty" in body for body in requests] == [True, False]
