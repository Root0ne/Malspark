"""docker/docker-compose.dev-polling.yml makes the development stack poll, and changes nothing else.

The overlay restates the API's development command to narrow its reload to
the source trees, so it is held here to the development overlay's command
plus those trees, and the trees to the ones the worker's supervisor watches.
Read from the YAML files alone (no docker), so it runs on every OS.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
DEV = ROOT / "docker" / "docker-compose.dev.yml"
POLLING = ROOT / "docker" / "docker-compose.dev-polling.yml"

WATCHFILES = {"WATCHFILES_FORCE_POLLING": "true", "WATCHFILES_POLL_DELAY_MS": "1000"}


def _services(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict) and set(loaded) == {"services"}
    services = loaded["services"]
    assert isinstance(services, dict)
    return services


def test_the_api_reloads_as_in_development_but_watches_the_source_trees_only() -> None:
    dev, polling = _services(DEV), _services(POLLING)
    base = dev["backend-api"]["command"].split()
    narrowed = polling["backend-api"]["command"].split()
    assert narrowed[: len(base)] == base and "--reload" in base
    added = narrowed[len(base) :]
    assert added[::2] == ["--reload-dir"] * (len(added) // 2) and len(added) % 2 == 0
    # The trees the worker's watchfiles supervisor restarts it for.
    assert set(added[1::2]) == set(dev["backend-worker"]["command"].split()[-2:])


def test_each_watcher_polls_once_a_second_and_nothing_else_changes() -> None:
    polling = _services(POLLING)
    assert set(polling) == {"backend-api", "backend-worker", "frontend"}
    assert polling["backend-api"]["environment"] == WATCHFILES
    assert polling["backend-worker"] == {"environment": WATCHFILES}
    assert polling["frontend"] == {"environment": {"MALSPARK_WATCH_POLL_MS": "1000"}}
    assert set(polling["backend-api"]) == {"command", "environment"}


def test_the_frontend_reads_the_interval_it_is_given() -> None:
    config = (ROOT / "apps" / "web" / "next.config.ts").read_text(encoding="utf-8")
    assert "process.env.MALSPARK_WATCH_POLL_MS" in config
    assert "watchOptions: { pollIntervalMs: POLL_MS }" in config
