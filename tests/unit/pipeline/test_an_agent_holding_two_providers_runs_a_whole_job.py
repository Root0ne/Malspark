"""A whole job in which one agent holds two static providers, against the rehearsal's stub model.

The real pipeline runs in this process (``scripts.rehearsal.inprocess``): the
default team with one ``generic`` agent added to its analysis stage, the
mock sandbox, the repository's own tool sidecars, every model call answered
by the loopback stub. The agent names two made-up static providers
(``tests.stub_static_providers``) through ``provider`` references, so the
second provider's one tool is offered under a prefixed name, and the stub
calls each tool once. Each provider has its own mirror of the sample.

What the job must show: the second provider's tool was given the second
provider's mirror, each call is in the evidence ledger under its own
provider's source, and the run summary's environment names both providers
for that agent. No model, no network beyond 127.0.0.1, no decompiler.
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("starlette", reason="the stub model is served with starlette")
pytest.importorskip("uvicorn", reason="the stub model is served with uvicorn")
pytest.importorskip("mcp", reason="the tool sidecars speak the mcp package's protocol")

from scripts.rehearsal.inprocess import Rehearsal, rehearse  # noqa: E402
from scripts.rehearsal.sample import write_sample  # noqa: E402

from tests.stub_static_providers import TOOL, registered  # noqa: E402


def _loopback_binds() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not _loopback_binds(), reason="no loopback port to bind the stub on"),
]

FIRST, SECOND = "stub_first_provider", "stub_second_provider"
AGENT = "two_provider_reader"
JOB_DEADLINE_S = 600.0


def _team() -> dict[str, Any]:
    """The default team with ``AGENT`` in its analysis stage, holding both providers."""
    from malspark.core.settings_overrides import build_settings

    stages = build_settings({}).agents.profiles["default"].model_dump(mode="json")["stages"]
    for stage in stages:
        if stage["key"] == "analysis":
            stage["agents"] = [*stage["agents"], AGENT]
    return {
        "agents.definitions": {
            AGENT: {
                "role": "generic",
                "label": "Two-provider reader",
                "prompt": "Read the sample with the tools you are given and report what they show.",
                "tools": [
                    {"kind": "provider", "provider": FIRST},
                    {"kind": "provider", "provider": SECOND},
                ],
            }
        },
        "agents.profiles": {"two_providers": {"label": "Two providers", "stages": stages}},
        "agents.profile": "two_providers",
    }


def test_each_provider_s_tool_reads_its_own_mirror_and_the_run_records_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from malspark.app import MalsparkApp

    results: list[dict[str, Any]] = []
    real_arun = MalsparkApp.arun

    async def _kept(self: Any, *args: Any, **kwargs: Any) -> Any:
        result = await real_arun(self, *args, **kwargs)
        results.append(result)
        return result

    monkeypatch.setattr(MalsparkApp, "arun", _kept)
    mirrors = {
        FIRST: str(write_sample(tmp_path / "mirror-first")[0]),
        SECOND: str(write_sample(tmp_path / "mirror-second")[0]),
    }
    with registered(FIRST, SECOND) as providers:
        record = asyncio.run(
            rehearse(
                Rehearsal(
                    scenario="normal",
                    provider="openai",
                    work_dir=tmp_path / "run",
                    job_timeout_s=JOB_DEADLINE_S,
                    extra=_team(),
                    static_sample_paths=mirrors,
                )
            )
        )
    assert record.job_status == "completed", record.job_error
    (result,) = results

    # Each provider's tool was given that provider's own mirror, and each
    # opened the sample on it before the loop.
    for provider_id in (FIRST, SECOND):
        assert providers[provider_id].read_paths
        assert set(providers[provider_id].read_paths) == {mirrors[provider_id]}
        assert providers[provider_id].opened_paths
        assert set(providers[provider_id].opened_paths) == {mirrors[provider_id]}

    # Both calls are in the ledger, each under its own provider's source.
    calls = {
        entry["tool"]: entry
        for entry in result["evidence_ledger"]
        if entry.get("agent") == AGENT and entry.get("tool") in (TOOL, f"{SECOND}__{TOOL}")
    }
    assert calls[TOOL]["source"] == f"provider:{FIRST}"
    assert calls[f"{SECOND}__{TOOL}"]["source"] == f"provider:{SECOND}"
    assert all(entry["ok"] for entry in calls.values())

    # The run summary's environment names both providers for the agent.
    agents = record.run_summary["environment"]["agents"]
    assert agents[AGENT]["static_providers"] == [FIRST, SECOND]
    assert not any("static_providers" in block for key, block in agents.items() if key != AGENT)
