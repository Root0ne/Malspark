"""Every job in a workflow carries a time limit, so a hung step cannot hold a run.

Without ``timeout-minutes`` GitHub lets a job run for six hours, and a pull
request waits on it the whole time. A job that calls a reusable workflow
(``uses:``) cannot carry one; the jobs inside the called workflow do. The
browser install of the E2E job is cut short and retried once, and the job
fails only if both attempts do.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FILES = sorted(WORKFLOWS.glob("*.yml"))


def _jobs(path: Path) -> dict[str, dict[str, Any]]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]


def test_the_workflow_files_are_found() -> None:
    assert len(FILES) >= 12


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_job_has_a_time_limit_or_calls_a_reusable_workflow(path: Path) -> None:
    missing = [
        name
        for name, job in _jobs(path).items()
        if "uses" not in job and not isinstance(job.get("timeout-minutes"), int)
    ]
    assert not missing, f"{path.name}: jobs without timeout-minutes: {missing}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_time_limit_is_below_ten_minutes_or_above_three_hours(path: Path) -> None:
    for name, job in _jobs(path).items():
        if "timeout-minutes" in job:
            assert 10 <= job["timeout-minutes"] <= 180, f"{path.name}: {name}"


def test_the_browser_install_is_cut_short_and_retried_once() -> None:
    steps = _jobs(WORKFLOWS / "ci.yml")["e2e"]["steps"]
    installs = [s for s in steps if "playwright install" in s.get("run", "")]
    assert len(installs) == 2
    first, second = installs
    assert first["continue-on-error"] is True
    assert isinstance(first["timeout-minutes"], int)
    assert second["if"] == f"steps.{first['id']}.outcome == 'failure'"
    assert isinstance(second["timeout-minutes"], int)
    assert "continue-on-error" not in second
    assert steps.index(second) == steps.index(first) + 1
    assert first["timeout-minutes"] <= 15
    assert second["timeout-minutes"] <= 15
    assert first["run"] == second["run"]
    assert first["id"] == "browsers"
