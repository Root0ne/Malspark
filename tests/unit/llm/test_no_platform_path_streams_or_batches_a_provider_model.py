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
  their ``*_as_completed`` forms) is called on a model expression. A model
  expression is a name or attribute whose last word is ``llm`` or ``model``
  (or their plurals, for containers), a ``build_model`` result, a
  ``bind*`` / ``with_*`` / ``pipe`` call on one or taking one as an argument,
  a pipe (``a | b``) with one on either side, an element of a container
  named so, or a variable assigned from or looping over any of these.
  Streams of httpx responses and of compiled graphs are not model
  expressions and are not flagged;
* it runs a healed model through a binding and through a streamed ReAct graph
  against an in-process transport, which is what makes the graph exemption
  true: every step that reached the model after the 400 was the healed call.

What the walk does not see: a model held under a name without those words, one
received as a parameter, or one kept in a container the walk cannot follow. It
claims no completeness; a new call form that reaches the model without
``invoke`` or ``ainvoke`` has to be covered by the heal itself.

A line that the walk flags although its receiver is not a model carries a
trailing comment of one form, with a reason::

    something.batch(rows)  # unhealed-ok: a database batch, not a chat model

A waiver without a reason fails the test. The test prints how many waivers the
tree holds.
"""

from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal, NamedTuple

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
# Calls that return a runnable made from the model they are called on, or
# from a model they are given.
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
# A name is a model's by its last word.
MODEL_WORDS = frozenset({"llm", "llms", "model", "models"})
# Calls that hand back the elements of the container they are called on.
ELEMENT_CALLS = frozenset({"values"})
ELEMENT_WRAPPERS = frozenset({"list", "tuple", "sorted", "reversed", "enumerate", "set"})

WAIVER = re.compile(r"#\s*unhealed-ok:(?P<reason>.*)$")


def _names_a_model(identifier: str) -> bool:
    words = [part for part in re.split(r"_+", identifier.lower()) if part]
    return bool(words) and words[-1] in MODEL_WORDS


def _is_model_expression(node: ast.AST, tainted: set[str]) -> bool:
    """Whether ``node`` names a chat model, or a runnable derived from one."""
    if isinstance(node, ast.Name):
        return node.id in tainted or _names_a_model(node.id)
    if isinstance(node, ast.Attribute):
        return _names_a_model(node.attr) or node.attr in tainted
    if isinstance(node, ast.Subscript | ast.Await | ast.Starred):
        return _is_model_expression(node.value, tainted)
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, ast.BitOr) and (
            _is_model_expression(node.left, tainted) or _is_model_expression(node.right, tainted)
        )
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_model_expression(element, tainted) for element in node.elts)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in BUILDING_CALLS:
                return True
            if func.attr in DERIVING_CALLS:
                arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
                return _is_model_expression(func.value, tainted) or any(
                    _is_model_expression(argument, tainted) for argument in arguments
                )
        if isinstance(func, ast.Name) and func.id in BUILDING_CALLS:
            return True
    return False


def _elements_of(node: ast.AST, tainted: set[str]) -> bool:
    """Whether iterating ``node`` yields models."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ELEMENT_CALLS and not node.args:
            return _is_model_expression(func.value, tainted)
        if isinstance(func, ast.Name) and func.id in ELEMENT_WRAPPERS and node.args:
            return _elements_of(node.args[0], tainted)
    return _is_model_expression(node, tainted)


def _assigned_names(target: ast.AST) -> Iterator[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Attribute):
        yield target.attr
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            yield from _assigned_names(element)


def _bindings(tree: ast.AST) -> Iterator[tuple[list[ast.AST], ast.AST, bool]]:
    """``(targets, value, iterated)`` for each assignment, loop and comprehension."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            yield list(node.targets), node.value, False
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            yield [node.target], node.value, False
        elif isinstance(node, ast.NamedExpr):
            yield [node.target], node.value, False
        elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            yield [node.target], node.iter, True


def _tainted_names(tree: ast.AST) -> set[str]:
    """Names bound, anywhere in the module, from a model expression."""
    tainted: set[str] = set()
    bindings = list(_bindings(tree))
    grew = True
    while grew:
        grew = False
        for targets, value, iterated in bindings:
            if not (
                _elements_of(value, tainted) if iterated else _is_model_expression(value, tainted)
            ):
                continue
            for target in targets:
                for name in _assigned_names(target):
                    if name not in tainted:
                        tainted.add(name)
                        grew = True
    return tainted


class Scan(NamedTuple):
    found: list[tuple[int, str]]
    waived: int


def _waivers(source: str) -> dict[int, str]:
    """The reason of each ``unhealed-ok`` comment, by line."""
    reasons: dict[int, str] = {}
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            match = WAIVER.search(token.string)
            if match:
                reasons[token.start[0]] = match.group("reason").strip()
    return reasons


def scan(source: str) -> Scan:
    """Each stream or batch call made on a model expression, and the waivers used."""
    tree = ast.parse(source)
    tainted = _tainted_names(tree)
    waivers = _waivers(source)
    found: list[tuple[int, str]] = []
    waived = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        form: str | None = None
        if (
            isinstance(func, ast.Attribute)
            and func.attr in UNHEALED_FORMS
            and _is_model_expression(func.value, tainted)
        ):
            form = func.attr
            line = func.end_lineno or node.lineno
        # ``getattr(model, "astream")`` reaches the same method.
        elif (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in UNHEALED_FORMS
            and _is_model_expression(node.args[0], tainted)
        ):
            form = str(node.args[1].value)
            line = node.lineno
        if form is None:
            continue
        if line in waivers:
            if waivers[line]:
                waived += 1
            else:
                found.append((line, f"{form} (an unhealed-ok waiver without a reason)"))
            continue
        found.append((line, form))
    return Scan(sorted(found), waived)


def unhealed_calls(source: str) -> list[tuple[int, str]]:
    """``(line, form)`` of each stream or batch call made on a model expression."""
    return scan(source).found


def _python_files(root: Path) -> Iterator[Path]:
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
            "self.chat_model.astream(messages)",
            "self.llm.bind_tools(tools).astream(messages)",
            "self.llm.with_structured_output(Schema).astream(messages)",
            "self.llm.with_fallbacks([other]).astream(messages)",
            "provider.build_model('m', 0.0).stream(messages)",
            "chat = self.llm.bind(max_tokens=3)\nchat.astream_events(messages)",
            "getattr(self.llm, 'astream')(messages)",
            "(prompt | self.llm).astream(x)",
            "(self.llm | parser).stream(x)",
            "chain = prompt | self.llm\nchain.astream(x)",
            "chain = prompt | self.llm | parser\nchain.stream(x)",
            "prompt.pipe(self.llm).astream(x)",
            "chain = prompt.pipe(self.llm)\nchain.abatch(x)",
            "base.with_fallbacks([self.llm]).astream(x)",
            "for m in self.models:\n    m.batch(x)",
            "for m in models.values():\n    m.stream(x)",
            "[m.batch(x) for m in self.llms]",
            "for _, m in enumerate(models):\n    m.stream(x)",
            "self.models['a'].astream(x)",
        ],
    )
    def test_a_streamed_or_batched_model_is_found(self, line: str) -> None:
        assert unhealed_calls(line), line

    @pytest.mark.parametrize(
        "line",
        [
            "self.llm.invoke(messages)",
            "await self.llm.bind_tools(tools).ainvoke(messages)",
            "(prompt | self.llm).ainvoke(x)",
            "http.stream('GET', url)",
            "self._http.stream('GET', url)",
            "response.stream(CHUNK)",
            "request.stream()",
            "graph['executor'].astream(state, stream_mode='values')",
            "self.graph.astream(state)",
            "self.model_name.stream(x)",
            "model_response.stream(8)",
            "llm_cache.batch(1)",
            "model_graph.astream(s)",
            "(a | b).stream(x)",
            "for r in responses:\n    r.stream(x)",
        ],
    )
    def test_an_unrelated_stream_is_not(self, line: str) -> None:
        assert not unhealed_calls(line), line

    def test_a_waiver_with_a_reason_is_honoured_and_counted(self) -> None:
        found = scan("model.batch(rows)  # unhealed-ok: a database batch, not a chat model\n")

        assert found == Scan([], 1)

    def test_a_waiver_without_a_reason_is_refused(self) -> None:
        for comment in ("# unhealed-ok:", "# unhealed-ok:   "):
            found = scan(f"model.batch(rows)  {comment}\n")

            assert found.found
            assert found.waived == 0

    def test_a_waiver_covers_its_own_line_only(self) -> None:
        source = "model.batch(a)  # unhealed-ok: not a chat model\nmodel.batch(b)\n"

        assert scan(source) == Scan([(2, "batch")], 1)

    def test_a_waiver_inside_a_string_is_no_waiver(self) -> None:
        assert unhealed_calls("model.batch('# unhealed-ok: reason')\n")


def test_no_platform_path_streams_or_batches_a_provider_model() -> None:
    found: list[str] = []
    waived = 0
    for root in SOURCES:
        scanned = 0
        for path in _python_files(root) if root.is_dir() else ():
            scanned += 1
            try:
                result = scan(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            waived += result.waived
            found.extend(
                f"{path.relative_to(ROOT)}:{line}: .{form}()" for line, form in result.found
            )
        assert scanned, f"the walk found no Python file under {root.relative_to(ROOT)}"
    print(f"unhealed-ok waivers in the tree: {waived}")
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
