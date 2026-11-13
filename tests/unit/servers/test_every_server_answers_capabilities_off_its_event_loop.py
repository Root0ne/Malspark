"""Each platform server answers its capabilities tool off its event loop.

A slow read of a binary's version, or of a data path, must not stop the server
answering other calls, whichever server it is.
"""

from __future__ import annotations

import asyncio
import importlib.util
import time
from pathlib import Path
from typing import Any

import pytest

from malspark.tools import capabilities
from malspark.tools.capabilities import ToolNeeds, binary

ROOT = Path(__file__).resolve().parents[3]


def _slow_version() -> str:
    time.sleep(0.5)
    return "3.1"


@pytest.mark.parametrize("server", ["knowledge", "network", "threatintel", "analysis"])
def test_the_loop_keeps_running_while_a_version_is_read(
    server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = ROOT / "services" / f"{server}-mcp" / "server.py"
    spec = importlib.util.spec_from_file_location(f"{server}_capabilities_loop", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    needs = [ToolNeeds("t", (binary("t668loop", lambda *a: None, version_of=_slow_version),))]
    monkeypatch.setattr(module, "TOOL_NEEDS", needs)
    monkeypatch.setattr(
        module, "CAPABILITIES", capabilities.manifest(server, needs, requirements=False)
    )
    capabilities.clear_fact_caches()
    ticks: list[float] = []

    async def _tick() -> None:
        while True:
            ticks.append(time.monotonic())
            await asyncio.sleep(0.02)

    async def _run() -> Any:
        ticker = asyncio.create_task(_tick())
        try:
            return await module.capabilities()
        finally:
            ticker.cancel()

    try:
        held = asyncio.run(_run())
    finally:
        capabilities.clear_fact_caches()
    assert held["requirements"][0]["version"] == "3.1"
    assert len(ticks) > 10
