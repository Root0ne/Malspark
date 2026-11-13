"""Each platform server answers its capabilities tool off its event loop.

A slow read of a binary's version, or of a data path, must not stop the server
answering other calls, whichever server it is.
"""

from __future__ import annotations

import asyncio
import importlib.util
import threading
from pathlib import Path
from typing import Any

import pytest

from malspark.tools import capabilities
from malspark.tools.capabilities import ToolNeeds, binary

ROOT = Path(__file__).resolve().parents[3]


# How long the version probe waits for the event loop to release it. Reached
# only when the loop is blocked; a slow machine does not get near it.
RELEASE_TIMEOUT_S = 30.0


@pytest.mark.parametrize("server", ["knowledge", "network", "threatintel", "analysis"])
def test_the_loop_keeps_running_while_a_version_is_read(
    server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = ROOT / "services" / f"{server}-mcp" / "server.py"
    spec = importlib.util.spec_from_file_location(f"{server}_capabilities_loop", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    released = threading.Event()
    events: list[str] = []

    def _version_after_the_loop_runs() -> str:
        # Blocks in its worker thread until a task on the server's own loop has run.
        assert released.wait(RELEASE_TIMEOUT_S), (
            "the event loop never ran while the version was read"
        )
        return "3.1"

    needs = [
        ToolNeeds(
            "t", (binary("t668loop", lambda *a: None, version_of=_version_after_the_loop_runs),)
        )
    ]
    monkeypatch.setattr(module, "TOOL_NEEDS", needs)
    monkeypatch.setattr(
        module, "CAPABILITIES", capabilities.manifest(server, needs, requirements=False)
    )
    capabilities.clear_fact_caches()

    async def _release() -> None:
        events.append("loop ran")
        released.set()

    async def _run() -> Any:
        task = asyncio.create_task(_release())
        try:
            held = await module.capabilities()
            events.append("answered")
            return held
        finally:
            await task

    try:
        held = asyncio.run(_run())
    finally:
        released.set()
        capabilities.clear_fact_caches()
    assert events == ["loop ran", "answered"]
    assert held["requirements"][0]["version"] == "3.1"
