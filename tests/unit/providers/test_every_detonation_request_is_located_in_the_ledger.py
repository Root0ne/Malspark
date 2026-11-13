"""Every request's ledger entry is located when the summary is built, and the CLI records it.

A request refused or too late keeps the ledger entry of the call that filed
it, as an accepted one does, located when the run summary is built; and the
command line's summary carries the record of the further detonations as the
worker's does (T-671 review B8). Offline.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.core.config import ProfileDefinition, Settings, StageDefinition
from malspark.pipeline import detonations as dt
from malspark.providers import detonation_requests as dr
from malspark.providers.detonation import DetonationRecord
from malspark.providers.detonation_requests import REQUEST_KIND, REQUEST_TOOL
from malspark.schemas.evidence import EvidenceCounter


def a_job(stages: list[StageDefinition] | None = None, **sandbox: Any) -> Any:
    """A job's container that can submit, with three entry ids issued; ``sandbox`` settings set."""
    settings = Settings()
    for key, value in sandbox.items():
        setattr(settings.sandbox, key, value)
    profile = (
        ProfileDefinition(stages=stages)
        if stages
        else settings.agents.profiles[settings.agents.profile]
    )
    counter = EvidenceCounter()
    for _ in range(3):
        counter.next_id()
    return SimpleNamespace(
        config=settings,
        active_profile=lambda: profile,
        _agent_cache={},
        event_sink=None,
        detonations=[DetonationRecord(report={})],
        detonation_requests=[],
        detonator=None,
        detonations_seen={},
        further_turns=[],
        current_step="",
        get_evidence_counter=lambda: counter,
        is_mock=False,
        sample_path="/x/sample.exe",
    )


def filed(container: Any, arguments: str = "-p x", agent: str = "dynamic") -> Any:
    """One request filed from the dynamic analyst's step."""
    token = dt._CURRENT_STEP.set("dynamic_analyst")
    try:
        return dr.file_request(
            container, agent=agent, arguments=arguments, reason="r", cited_entries=["ev_0001"]
        )
    finally:
        dt._CURRENT_STEP.reset(token)


def test_refused_and_too_late_requests_have_their_entry_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dr, "_cannot_detonate", lambda container, arguments: "")
    container = a_job()
    refused = filed(container, "")  # not one command line
    monkeypatch.setattr(dr, "_later_step", lambda container: ("", False))
    too_late = filed(container, "-q")
    assert refused.state == dr.REFUSED and too_late.answer == dr.NO_LATER_STEP
    state = {
        "evidence_ledger": [
            {
                "id": f"ev_000{n}",
                "tool": REQUEST_TOOL,
                "source": "sandbox",
                "facts": {"v": 1, "kind": REQUEST_KIND},
                "structured": {"request": name},
            }
            for n, name in ((5, "r1"), (6, "r2"))
        ]
    }
    record = dt.recorded_detonations(container, state)
    assert [r["entry_id"] for r in record["detonation_requests"]] == ["ev_0005", "ev_0006"]


def test_the_command_line_summary_carries_the_record(monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from malspark import cli

    container = a_job()
    filed(container, "")
    printed: list[dict[str, Any]] = []

    class _App:
        def __init__(self, **_kwargs: Any) -> None:
            self.container = container

        def run(self, **_kwargs: Any) -> dict[str, Any]:
            return {"stix_output": {}, "run_summary": {"negotiation": {}}}

        def remember_the_run(self) -> bool:
            return False

    monkeypatch.setattr(cli, "MalsparkApp", _App)
    monkeypatch.setattr(cli, "_release", lambda _app: None)
    monkeypatch.setattr(cli, "_print_run_summary_inline", printed.append)
    result = CliRunner().invoke(cli.app, ["analyze", "sample_1", "--mock"])
    assert result.exit_code == 0, result.output
    (summary,) = printed
    assert [r["request"] for r in summary["detonation_requests"]] == ["r1"]
    assert summary["detonations"][0]["detonation"] == "d1"
