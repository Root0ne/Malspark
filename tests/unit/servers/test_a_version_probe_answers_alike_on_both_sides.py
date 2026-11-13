"""A program's version is asked the same way by the platform and by a CLI sidecar (T-668).

The CLI sidecar base imports nothing of the platform, so it keeps its own copy
of the platform's version probe (``malspark.tools.capabilities``). One table
runs against both: no shell, a relative path with a separator never run, a
wall clock held to its ceiling and a bad one read as the default, each stream
read up to a bound and a flood stopped there, the program's process group
killed whole once it has answered, so a process it left holding the output
neither delays the answer nor outlives it, and none of the asking process's
environment reaching the program but ``PATH``: it runs with a temporary
directory of its own as its home, temporary directory and working directory.

A sidecar's manifest then answers ``requirements`` for its program: the
version its image pins and, where the program declares how to ask it, the
version it says it is.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from malspark.tools import capabilities

ROOT = Path(__file__).resolve().parents[3]
SERVICES = ROOT / "services"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sidecar = _load("cli_sidecar", SERVICES / "cli-sidecar" / "cli_sidecar.py")
NOT_REPORTED = capabilities.NOT_REPORTED
DEFAULT = capabilities.VersionProbe(()).pattern


def _platform(command: tuple[str, ...], pattern: str = DEFAULT, timeout_s: Any = None) -> str:
    # Past the once-per-process memory, so every row asks afresh.
    return str(capabilities._read_version(command, pattern, timeout_s))


def _sidecar(command: tuple[str, ...], pattern: str = DEFAULT, timeout_s: Any = None) -> str:
    return str(sidecar.probe_version(command, pattern, timeout_s))


SIDES: dict[str, Callable[..., str]] = {"platform": _platform, "sidecar": _sidecar}


def _python(code: str) -> tuple[str, ...]:
    return (sys.executable, "-c", code)


def test_the_two_copies_share_their_bounds() -> None:
    for name in (
        "VERSION_PROBE_TIMEOUT_S",
        "VERSION_PROBE_MAX_TIMEOUT_S",
        "_PROBE_OUTPUT_BYTES",
        "_PUMP_JOIN_S",
    ):
        assert getattr(sidecar, name) == getattr(capabilities, name)
    assert sidecar.VERSION_PATTERN == DEFAULT
    assert sidecar.NOT_REPORTED == NOT_REPORTED


FLOOD = "import sys\nwhile True: sys.stdout.write('x' * 65536)"
TABLE: list[tuple[str, tuple[str, ...], str, Any, str]] = [
    ("stdout", _python("print('tool v1.2.3 (build 9)')"), DEFAULT, None, "1.2.3"),
    (
        "stderr and a group",
        _python("import sys; sys.stderr.write('release 7-beta\\n')"),
        r"release (\S+)",
        None,
        "7-beta",
    ),
    (
        "an exit status",
        _python("import sys; print('1.0'); sys.exit(3)"),
        DEFAULT,
        None,
        f"{NOT_REPORTED}: it exited with status 3",
    ),
    (
        "a hang",
        _python("import time; time.sleep(60)"),
        DEFAULT,
        0.5,
        f"{NOT_REPORTED}: it did not answer within 0.5 s",
    ),
    (
        "a flood after the version",
        _python(f"import sys\nsys.stdout.write('v9.8.7 ')\n{FLOOD.split(chr(10), 1)[1]}"),
        DEFAULT,
        20,
        "9.8.7",
    ),
    (
        "a flood naming none",
        _python(FLOOD),
        DEFAULT,
        20,
        f"{NOT_REPORTED}: it wrote more than {64 * 1024} bytes and named no version",
    ),
    ("a NaN wall clock", _python("print('2.5')"), DEFAULT, float("nan"), "2.5"),
    ("a negative wall clock", _python("print('2.6')"), DEFAULT, -3, "2.6"),
    ("a wall clock that is no number", _python("print('2.7')"), DEFAULT, "soon", "2.7"),
    (
        "a relative path",
        ("./tool", "--version"),
        DEFAULT,
        None,
        f"{NOT_REPORTED}: tool is named by a relative path, which a probe never runs",
    ),
    (
        "a program not there",
        ("/nowhere/t668-no-such-program", "--version"),
        DEFAULT,
        None,
        f"{NOT_REPORTED}: t668-no-such-program is not on PATH",
    ),
    (
        "no shell",
        (*_python("import sys; print(sys.argv[1])"), "$HOME 3.4"),
        r"\$HOME (\S+)",
        None,
        "3.4",
    ),
    ("an empty command", (), DEFAULT, None, f"{NOT_REPORTED}: the probe names no command"),
]


@pytest.mark.parametrize("side", sorted(SIDES))
@pytest.mark.parametrize(("case", "command", "pattern", "timeout_s", "expected"), TABLE)
def test_each_case_is_answered_alike(
    side: str, case: str, command: tuple[str, ...], pattern: str, timeout_s: Any, expected: str
) -> None:
    started = time.monotonic()
    assert SIDES[side](command, pattern, timeout_s) == expected
    assert time.monotonic() - started < 15


@pytest.mark.posix
@pytest.mark.parametrize("side", sorted(SIDES))
def test_a_grandchild_holding_the_output_is_killed_with_the_group(
    side: str, tmp_path: Path
) -> None:
    marker = tmp_path / "grandchild.pid"
    code = (
        "import subprocess, sys\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(marker)!r}, 'w').write(str(child.pid))\n"
        "print('tool 4.5.6')\n"
    )
    started = time.monotonic()
    assert SIDES[side](_python(code), DEFAULT, 10) == "4.5.6"
    assert time.monotonic() - started < 8
    pid = int(marker.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    pytest.fail("the probe's grandchild outlived it")


@pytest.mark.posix
@pytest.mark.parametrize("side", sorted(SIDES))
def test_a_grandchild_in_a_session_of_its_own_delays_the_answer_by_one_short_deadline(
    side: str,
) -> None:
    # It escapes the group kill and holds the output open: both readers are
    # waited for together, once, not each for a deadline of its own.
    code = (
        "import subprocess, sys\n"
        "subprocess.Popen([sys.executable, '-c', 'import os, time; os.setsid(); time.sleep(6)'])\n"
        "print('2.3.4')\n"
    )
    started = time.monotonic()
    assert SIDES[side](_python(code), DEFAULT, 3) == "2.3.4"
    assert time.monotonic() - started < 1.5


def _added_to_an_empty_environment(scratch: Path) -> set[str]:
    """The variables a child gets with none given: what the system itself adds."""
    import subprocess

    done = subprocess.run(  # noqa: S603 — the test's own interpreter
        [sys.executable, "-c", "import os; print('\\n'.join(os.environ))"],
        env={},
        cwd=scratch,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return set(done.stdout.split())


@pytest.mark.posix
@pytest.mark.parametrize("side", sorted(SIDES))
def test_the_program_sees_only_path_lang_and_a_home_of_its_own(
    side: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    seen = tmp_path / "seen.json"
    monkeypatch.setenv("T668_PROVIDER_API_KEY", "sk-must-not-reach-the-program")
    code = (
        "import json, os\n"
        f"json.dump({{'env': dict(os.environ), 'cwd': os.getcwd()}}, open({str(seen)!r}, 'w'))\n"
        "print('1.0')\n"
    )
    assert SIDES[side](_python(code), DEFAULT, 10) == "1.0"
    held = json.loads(seen.read_text())
    env, cwd = held["env"], held["cwd"]
    assert "T668_PROVIDER_API_KEY" not in env
    assert "sk-must-not-reach-the-program" not in json.dumps(env)
    # Within the stated variables and what the system and the interpreter add to
    # every process of their own, measured: a child started with an empty
    # environment through the same spawning call.
    stated = {"PATH", "LANG", "HOME", "TMPDIR"}
    assert stated <= set(env) <= stated | _added_to_an_empty_environment(tmp_path)
    # The marker set in this process's environment is no part of the program's.
    assert not any(name.startswith("T668_") for name in env)
    assert env["PATH"] == os.environ["PATH"]
    assert env["LANG"] == "C.UTF-8"
    assert env["HOME"] == env["TMPDIR"] == cwd
    assert Path(cwd).name.startswith("version-probe-")
    # The temporary directory goes with the probe.
    assert not Path(cwd).exists()


# ---------------------------------------------------------------------------
# The sidecar's manifest answers its program's requirement


@pytest.fixture
def bin_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    held = tmp_path / "bin"
    held.mkdir()
    monkeypatch.setenv("PATH", f"{held}{os.pathsep}/usr/bin{os.pathsep}/bin")
    sidecar._VERSIONS.clear()
    yield held
    sidecar._VERSIONS.clear()


def _stub(bin_dir: Path, name: str, answer: str) -> None:
    path = bin_dir / name
    path.write_text(f'#!/bin/sh\n[ "$1" = "--version" ] && echo "{answer}"\nexit 0\n')
    path.chmod(0o755)


@pytest.mark.posix
class TestTheSidecarsManifest:
    def test_a_program_with_a_version_argument_says_its_version_beside_the_pin(
        self, bin_dir: Path
    ) -> None:
        _stub(bin_dir, "t668tool", "t668tool 1.21.0")
        program = sidecar.Program(
            name="t668tool", command=("t668tool",), install="x", version_argv=("--version",)
        )
        held = sidecar.capabilities("t", program, ("scan",), version="1.21.0")
        assert held["requirements"] == [
            {
                "kind": "binary",
                "name": "t668tool",
                "pinned": "1.21.0",
                "version": "1.21.0",
                "tools": ["scan"],
            }
        ]
        parsed = capabilities.ServerCapabilities.from_payload("t", held)
        assert parsed is not None and parsed.requirements == held["requirements"]

    def test_a_program_without_one_is_its_pinned_version_alone(self, bin_dir: Path) -> None:
        _stub(bin_dir, "t668tool", "t668tool 9.9")
        program = sidecar.Program(name="t668tool", command=("t668tool",), install="x")
        (row,) = sidecar.capabilities("t", program, ("scan",), version="3.21")["requirements"]
        assert row["pinned"] == "3.21"
        assert row["version"] == f"{NOT_REPORTED}: the program declares no version argument"

    def test_a_program_not_installed_says_why(self, bin_dir: Path) -> None:
        program = sidecar.Program(
            name="t668tool", command=("t668tool",), install="x", version_argv=("--version",)
        )
        (row,) = sidecar.capabilities("t", program, ("scan",), version="1")["requirements"]
        assert row["version"] == f"{NOT_REPORTED}: t668tool is not on PATH"

    def test_the_capabilities_answer_does_not_probe_on_the_event_loop(self, bin_dir: Path) -> None:
        path = bin_dir / "t668tool"
        path.write_text('#!/bin/sh\nsleep 0.5\necho "t668tool 2.5"\n')
        path.chmod(0o755)
        program = sidecar.Program(
            name="t668tool", command=("t668tool",), install="x", version_argv=("--version",)
        )
        ticks: list[float] = []

        async def _loop_is_free() -> None:
            while True:
                ticks.append(time.monotonic())
                await asyncio.sleep(0.02)

        async def _run() -> dict[str, Any]:
            ticker = asyncio.create_task(_loop_is_free())
            try:
                return await sidecar.answer_capabilities("t", program, ("scan",), version="2.5")
            finally:
                ticker.cancel()

        held = asyncio.run(_run())
        assert held["requirements"][0]["version"] == "2.5"
        # The loop kept running through the half second the probe took.
        assert len(ticks) > 10

    def test_the_program_is_asked_once_per_process(self, bin_dir: Path) -> None:
        _stub(bin_dir, "t668tool", "t668tool 1.0")
        program = sidecar.Program(
            name="t668tool", command=("t668tool",), install="x", version_argv=("--version",)
        )
        assert sidecar.program_version(program) == "1.0"
        _stub(bin_dir, "t668tool", "t668tool 2.0")
        assert sidecar.program_version(program) == "1.0"


# Each image whose program's documentation gives a version argument declares
# it; the others answer the version their image pins.
DECLARES_A_VERSION_ARGUMENT = {"ilspy-mcp", "jadx-mcp", "yarax-mcp"}
IMAGES = (
    "die-mcp",
    "goresym-mcp",
    "ilspy-mcp",
    "jadx-mcp",
    "oletools-mcp",
    "unblob-mcp",
    "webcrack-mcp",
    "yarax-mcp",
)


@pytest.mark.parametrize("image", IMAGES)
def test_each_image_declares_a_version_argument_only_where_its_program_documents_one(
    image: str,
) -> None:
    server = _load(f"{image.replace('-', '_')}_t668", SERVICES / image / "server.py")
    expected = ("--version",) if image in DECLARES_A_VERSION_ARGUMENT else ()
    assert server.PROGRAM.version_argv == expected
