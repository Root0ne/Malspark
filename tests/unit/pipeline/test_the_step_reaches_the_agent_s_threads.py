"""The step a request is filed in reaches every thread and loop the agent layer runs agent work on.

An agent's tool loop runs on the shared agent loop (``_submit_to_agent_loop``),
whose task is scheduled from the caller's thread and so runs in a copy of the
caller's context; a multi-view analysis runs its views on a thread pool, whose
threads run in none until the caller's context is carried to each. Two stages
running at once each read their own step (``detonations.current_step``) in
both places, never the container's last note (T-671 review r2 N3). Offline.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from malspark.agents.base_agent import BaseAnalyst, _submit_to_agent_loop
from malspark.pipeline import detonations as dt


def _agent_loop() -> asyncio.AbstractEventLoop:
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    return loop


def test_two_stages_at_once_each_read_their_own_step_on_the_agent_loop() -> None:
    container = SimpleNamespace(current_step="")
    loop = _agent_loop()
    seen: dict[str, str] = {}
    both = threading.Barrier(2)

    def _node(label: str) -> Any:
        def node(state: Any) -> dict[str, Any]:
            both.wait(5)
            # The container's note is whichever step was entered last.
            container.current_step = "someone_else"

            async def tool_call() -> str:
                return dt.current_step(container)

            future, _running = _submit_to_agent_loop(tool_call(), loop)
            seen[label] = future.result(5)
            return {}

        return node

    first = dt.on_entry(container, "static_analyst", _node("static"))
    second = dt.on_entry(container, "dynamic_analyst", _node("dynamic"))

    async def main() -> None:
        running = asyncio.get_running_loop()
        await asyncio.gather(
            running.run_in_executor(None, first, {}), running.run_in_executor(None, second, {})
        )

    asyncio.run(main())
    loop.call_soon_threadsafe(loop.stop)
    assert seen == {"static": "static_analyst", "dynamic": "dynamic_analyst"}


class _Viewer(BaseAnalyst):
    def __init__(self, container: Any) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self.read_steps: list[str] = []
        self._step_container = container

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_view(self, prompt: str, data: str, budget: Any) -> str:
        self.read_steps.append(dt.current_step(self._step_container))
        return "CLAIM 1: x.\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5\nTECHNIQUE: NONE\n---\n"


def test_a_multi_view_analysis_reads_its_step_in_every_view() -> None:
    container = SimpleNamespace(current_step="someone_else")
    viewer = _Viewer(container)

    def node(state: Any) -> dict[str, Any]:
        container.current_step = "someone_else"
        viewer.analyze_isr_views("data", 2)
        return {}

    dt.on_entry(container, "static_analyst", node)({})
    assert viewer.read_steps == ["static_analyst", "static_analyst"]
