"""The Makefile's stack targets are one-line calls to the setup entry point.

Each target the entry point covers runs ``$(DEV) <command>`` and nothing else,
so make and a host without it (native Windows) run the same commands. The dev
targets append the compose files COMPOSE_FILE_EXTRA names: compose reads
``docker-compose.override.yml`` on its own only when it is given no ``-f``;
``make dev-up`` gives it two (the shipped file and the dev overlay), so a
host's own overrides reach the dev stack only through COMPOSE_FILE_EXTRA, from
the environment and from the make command line alike. Run through make with a
``docker`` on PATH that writes down what it is given. A host that is not Linux
adds its overlays after the shipped files, so what is expected there holds them
too: the entry point's own tests say which host adds which.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEV = f"DEV={sys.executable} scripts/dev/malspark_dev.py"
HOST_CHOICES = ("COMPOSE_FILE_EXTRA", "MALSPARK_DATA_VOLUMES", "VIRTUAL_ENV")


def _entry() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "malspark_dev_for_the_make_targets", ROOT / "scripts" / "dev" / "malspark_dev.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


entry = _entry()
SHIPPED = [arg for path in entry.SHIPPED_COMPOSE for arg in ("-f", path)]
# What this host adds by itself, with nothing in the environment choosing.
HOST = [
    arg
    for path in (*entry.host_overlays(ROOT, None, {}), *entry.dev_overlays(ROOT))
    for arg in ("-f", path)
]

needs_make = pytest.mark.skipif(shutil.which("make") is None, reason="needs make")

TARGETS = {
    "dev-up": ["up", "-d"],
    "dev-down": ["--profile", "*", "down"],
    "dev-logs": ["logs", "-f"],
}

WRAPPERS = {
    "setup": "setup --dev",
    "external": "external",
    "migrate": "migrate",
    "doctor": "doctor",
    "env-init": "env init",
    "docker-build": "docker-build",
    "docker-up": "docker-up",
    "docker-down": "docker-down",
    "docker-logs": "docker-logs",
    "dev-up": "up",
    "dev-down": "down",
    "dev-logs": "logs",
    "fe-rebuild": "fe-rebuild",
    "worker-restart": "worker-restart",
}


def _recipe(target: str) -> list[str]:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    body = re.search(rf"^{re.escape(target)}:\n((?:\t.*\n)+)", text, re.M)
    assert body, target
    return [line.strip() for line in body.group(1).splitlines()]


@pytest.mark.parametrize("target", sorted(WRAPPERS))
def test_each_target_is_one_call_to_the_entry_point(target: str) -> None:
    assert _recipe(target) == [f"$(DEV) {WRAPPERS[target]}"]


def test_the_entry_point_is_run_without_the_project_s_environment() -> None:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "\nDEV = uv run --no-project python scripts/dev/malspark_dev.py\n" in text


def _calls(tmp_path: Path, target: str, *args: str, extra: str | None = None) -> list[list[str]]:
    log = tmp_path / "calls.jsonl"
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    docker = shims / "docker"
    docker.write_text(
        f"#!{sys.executable}\nimport json, sys\n"
        f"open({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    docker.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in HOST_CHOICES}
    env["PATH"] = f"{shims}{os.pathsep}{env.get('PATH', '')}"
    if extra is not None:
        env["COMPOSE_FILE_EXTRA"] = extra
    done = subprocess.run(
        ["make", "-s", target, *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return [json.loads(line) for line in log.read_text().splitlines()]


@pytest.mark.posix
@needs_make
@pytest.mark.parametrize("target", sorted(TARGETS))
def test_without_extra_files_the_two_shipped_files_are_passed(tmp_path: Path, target: str) -> None:
    assert _calls(tmp_path, target, DEV) == [["compose", *SHIPPED, *HOST, *TARGETS[target]]]


@pytest.mark.posix
@needs_make
@pytest.mark.parametrize("target", sorted(TARGETS))
def test_each_extra_file_is_appended_after_the_shipped_ones_in_order(
    tmp_path: Path, target: str
) -> None:
    calls = _calls(tmp_path, target, DEV, extra="docker/local.yml  /srv/gpu.yml")
    extra = ["-f", "docker/local.yml", "-f", "/srv/gpu.yml"]
    assert calls == [["compose", *SHIPPED, *HOST, *extra, *TARGETS[target]]]


@pytest.mark.posix
@needs_make
def test_the_extra_files_may_be_given_on_the_command_line(tmp_path: Path) -> None:
    calls = _calls(tmp_path, "dev-up", DEV, "COMPOSE_FILE_EXTRA=docker/local.yml")
    assert calls == [["compose", *SHIPPED, *HOST, "-f", "docker/local.yml", "up", "-d"]]


@pytest.mark.posix
@needs_make
@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_the_shipped_wrapper_runs_the_entry_point_through_uv(tmp_path: Path) -> None:
    files = entry._production_files(ROOT, None, {})
    assert _calls(tmp_path, "docker-down") == [["compose", *files, "--profile", "*", "down"]]
