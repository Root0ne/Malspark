"""One command-line analysis program, served over MCP from a container of its own.

Shared by the sidecars that each wrap one program (``die-mcp``, ``ilspy-mcp``,
``goresym-mcp``, ``yarax-mcp``, ``oletools-mcp``, ``webcrack-mcp``,
``unblob-mcp``, ``jadx-mcp``). It imports
nothing of the platform: each image holds this module, its server and the
program, and nothing else, so a sidecar holds no platform code, credential or
setting beyond its own token.

What every such server does the same way:

* **The sample is read where the deployment put it.** A path argument is
  resolved with ``realpath`` and must name a regular file under one of the
  directories ``MALSPARK_SAMPLE_ROOTS`` lists (the container's read-only sample
  mount); anything else is refused, and the refusal names no host path.
* **The program reads the file; nothing runs it.** The program is started
  with the path as an argument, its standard input closed, a scratch working
  directory of its own (or one its server made for the call, where the
  program writes files the server reads back), only the variables it needs
  and any resource limit its server sets (a machine-safety bound, such as the
  largest file it may write). Nothing here writes, copies or changes the mode
  of a sample.
* **A failure is an answer in one shape.** ``{"error": {"code", "message",
  "remediation"}, "tool"}``, with the codes the platform's own tool servers
  use: a program that is not installed is ``missing_dependency`` with the
  install hint, a program that ran past ``TOOL_TIMEOUT_SECONDS`` is
  ``timeout``, a path outside the roots is ``path_outside_roots``.
* **No bound of its own on the answer.** The program's whole output is read
  and parsed in one pass; the time bound is the operator's
  (``TOOL_TIMEOUT_SECONDS``, unset for none) and the caller's call timeout.
* **The capabilities tool says what the host can run**, in the shape the
  platform's registry reads: each tool with whether its program is present
  and, when it is not, why and how to install it.
* **Each tool declares itself** when the server lists it (``reading_tool``):
  MCP annotations, and under its ``_meta`` the facts the platform reads it
  by, which the client reads for any server alike.

``serve`` runs the server over streamable HTTP (``MCP_BIND_ADDRESS``,
``MCP_PORT``, ``MCP_AUTH_TOKEN``; a bind beyond loopback is refused without a
token) or, with ``--stdio``, over standard input and output for an operator
who installs the program on the worker's host instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import resource
except ImportError:  # not POSIX: the sidecar runs in its Linux container
    resource = None  # type: ignore[assignment]

logger = logging.getLogger("cli_sidecar")

# The codes, as the platform's tool servers write them (``malspark.tools.errors``).
MISSING_DEPENDENCY = "missing_dependency"
TIMEOUT = "timeout"
BAD_ARGUMENT = "bad_argument"
NO_SUCH_FILE = "no_such_file"
PATH_OUTSIDE_ROOTS = "path_outside_roots"
UNSUPPORTED_FORMAT = "unsupported_format"
TOOL_FAILED = "tool_failed"

REMEDIATIONS: dict[str, str] = {
    TIMEOUT: (
        "raise TOOL_TIMEOUT_SECONDS on this server, or the call timeout of its block, or ask "
        "for less"
    ),
    BAD_ARGUMENT: (
        "check the argument names and types against the tool's manifest and call it again"
    ),
    NO_SUCH_FILE: (
        "the file this call named is not there; leave the path argument out to read the file "
        "this call was given"
    ),
    PATH_OUTSIDE_ROOTS: (
        "this server reads the files under the sample directories it was given; leave the "
        "path argument out to read the file this call was given"
    ),
    UNSUPPORTED_FORMAT: "this tool reads another format; use a tool for the format the file is",
    TOOL_FAILED: (
        "read the message; if it names nothing you can change, report it with the server log"
    ),
}

# The variables a sidecar reads.
SAMPLE_ROOTS_ENV = "MALSPARK_SAMPLE_ROOTS"
TIMEOUT_ENV = "TOOL_TIMEOUT_SECONDS"
BIND_ENV = "MCP_BIND_ADDRESS"
PORT_ENV = "MCP_PORT"
TOKEN_ENV = "MCP_AUTH_TOKEN"

# What the refusal of a path says. No path in it: the argument it is about is
# the one part of the answer the sample's author may have written.
OUTSIDE_ROOTS_MESSAGE = "the path argument is outside the directories this server may read"

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})


def tool_error(
    code: str, message: str, *, tool: str, remediation: str | None = None
) -> dict[str, Any]:
    """The structured failure for ``code``, with its remediation."""
    hint = remediation or REMEDIATIONS.get(code, REMEDIATIONS[TOOL_FAILED])
    return {"error": {"code": code, "message": message, "remediation": hint}, "tool": tool}


class ToolFailure(Exception):
    """A tool's answer is a failure: raised inside a tool, answered by :func:`answering`."""

    def __init__(self, code: str, message: str, remediation: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = remediation


# ---------------------------------------------------------------------------
# The program
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Program:
    """The command-line program a sidecar serves, and how it is found and installed.

    ``command`` is what is started before the tool's own arguments: the
    program's name on ``PATH``, or an interpreter and the file it runs.
    ``files`` are files the command needs besides its first word (a .NET
    tool's assembly). ``install`` is the sentence a missing program's answer
    and the capabilities tool give as the remedy.
    """

    name: str
    command: tuple[str, ...]
    install: str
    files: tuple[str, ...] = ()
    # Variables the program needs, by value; nothing else of this process's
    # environment reaches it but ``PATH``.
    env: Mapping[str, str] = field(default_factory=dict)
    # The arguments after ``command`` that make the program print its own
    # version, where its documentation gives them; empty for none, and its
    # version is then the one its image pins alone (``capabilities``).
    version_argv: tuple[str, ...] = ()

    def absent(self) -> str | None:
        """``None`` when the program can be started, else why it cannot."""
        if not shutil.which(self.command[0]):
            return f"{self.command[0]} is not on PATH"
        for name in self.files:
            if not Path(name).is_file():
                return f"{Path(name).name} is not installed"
        return None


@dataclass(frozen=True)
class Ran:
    """What one run of the program left: its exit status and both streams, whole."""

    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def said(self) -> str:
        """The program's own words about a failure: its standard error, else its output."""
        text = self.stderr.decode("utf-8", "replace").strip()
        return text or self.stdout.decode("utf-8", "replace").strip()


def timeout_seconds() -> float | None:
    """The operator's bound on one run, from ``TOOL_TIMEOUT_SECONDS``; ``None`` for none."""
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number of seconds; runs have no bound.", TIMEOUT_ENV, raw)
        return None
    return value if value > 0 else None


async def run(
    program: Program,
    arguments: Sequence[str],
    *,
    workdir: str | None = None,
    limits: Mapping[int, int] | None = None,
) -> Ran:
    """Run ``program`` with ``arguments`` and wait for it; raises :class:`ToolFailure`.

    Missing, it is ``missing_dependency`` with the install hint; past the
    operator's bound, ``timeout``. A caller that gives up (a cancelled call)
    kills it, so no run outlives the call that started it. ``workdir`` is a
    directory the caller made for this call and removes itself (where the
    program writes files the caller reads after the run); without one, the run
    gets a scratch directory that goes with it. ``limits`` are resource
    limits the run (and every process it starts) is held to, each a
    ``resource.RLIMIT_*`` and its value: a machine-safety bound its server
    sets, such as the largest file it may write. They are set by util-linux's
    ``prlimit``, which the command is started under (:func:`limited`), so
    nothing runs in this process between the fork and the program.
    """
    absent = program.absent()
    if absent:
        raise ToolFailure(MISSING_DEPENDENCY, absent, program.install)
    command = limited(program.command, limits)
    if limits and not shutil.which(command[0]):
        raise ToolFailure(MISSING_DEPENDENCY, f"{command[0]} is not on PATH", PRLIMIT_INSTALL)
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        **program.env,
    }
    held = (
        contextlib.nullcontext(workdir)
        if workdir
        else tempfile.TemporaryDirectory(prefix=f"{program.name}-")
    )
    with held as scratch:
        env.setdefault("HOME", scratch)
        env.setdefault("TMPDIR", scratch)
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=scratch,
                env=env,
                # A process group of its own, so stopping the run stops every
                # process the program started, and none keeps its output open.
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise ToolFailure(
                MISSING_DEPENDENCY, f"{program.command[0]} could not be started", program.install
            ) from exc
        bound = timeout_seconds()
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), bound)
        except TimeoutError as exc:
            await _stop(process)
            raise ToolFailure(
                TIMEOUT, f"{program.name} did not finish within {bound:g} s ({TIMEOUT_ENV})"
            ) from exc
        except asyncio.CancelledError:
            await _stop(process)
            raise
    return Ran(int(process.returncode or 0), stdout, stderr)


async def _stop(process: asyncio.subprocess.Process) -> None:
    """Kill the run's whole process group and reap the program."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        process.kill()
    with contextlib.suppress(Exception):
        await process.wait()


# The resource limits a run may be held to, by the ``prlimit`` option that sets
# each (soft and hard alike).
# Empty where ``resource`` is missing: a run asked to be limited there is
# refused (``limited``), never run without its limits.
PRLIMIT_OPTIONS: dict[int, str] = (
    {}
    if resource is None
    else {
        resource.RLIMIT_FSIZE: "--fsize",
        resource.RLIMIT_NOFILE: "--nofile",
        resource.RLIMIT_AS: "--as",
        resource.RLIMIT_CPU: "--cpu",
    }
)
PRLIMIT_INSTALL = "install util-linux, whose prlimit sets a run's resource limits"


def limited(command: Sequence[str], limits: Mapping[int, int] | None) -> tuple[str, ...]:
    """``command`` started under ``prlimit`` with ``limits``; as it is without any."""
    if not limits:
        return tuple(command)
    options = []
    for which, value in sorted(limits.items()):
        if which not in PRLIMIT_OPTIONS:
            raise ValueError(f"no prlimit option sets resource limit {which}")
        options.append(f"{PRLIMIT_OPTIONS[which]}={int(value)}")
    return ("prlimit", *options, "--", *command)


async def run_ok(program: Program, arguments: Sequence[str], *, workdir: str | None = None) -> Ran:
    """:func:`run`, with a non-zero exit status a ``tool_failed`` naming the program's words."""
    ran = await run(program, arguments, workdir=workdir)
    if ran.returncode != 0:
        said = ran.said or "no output"
        raise ToolFailure(TOOL_FAILED, f"{program.name} exited with {ran.returncode}: {said}")
    return ran


def option_value(name: str, value: str) -> str:
    """``value`` for a program option, refused where the program would read it as an option."""
    text = str(value or "").strip()
    if not text:
        raise ToolFailure(BAD_ARGUMENT, f"{name} is empty")
    if "\0" in text:
        raise ToolFailure(BAD_ARGUMENT, f"{name} holds a NUL character")
    if text.startswith("-"):
        raise ToolFailure(BAD_ARGUMENT, f"{name} may not start with '-'")
    return text


def json_document(text: str, program: str) -> Any:
    """The JSON document ``text`` holds, read from its first ``{`` or else its first ``[``.

    A program that writes a line of its own before its document (a banner, a
    warning, even one with a bracket in it) still answers; one that wrote none
    is a ``tool_failed``. At most two reads, each in one pass.
    """
    starts = sorted(at for at in (text.find("{"), text.find("[")) if at >= 0)
    if not starts:
        raise ToolFailure(TOOL_FAILED, f"{program} wrote no JSON document")
    said = ""
    for at in starts:
        try:
            value, _end = json.JSONDecoder().raw_decode(text, at)
        except ValueError as exc:
            said = said or str(exc)
            continue
        return value
    raise ToolFailure(TOOL_FAILED, f"{program} wrote JSON that does not parse: {said}")


# ---------------------------------------------------------------------------
# What the program says its version is
# ---------------------------------------------------------------------------

# A copy of the platform's version probe (``malspark.tools.capabilities``:
# ``VersionProbe``, ``run_bounded`` and the helpers below), kept here because
# this module imports nothing of the platform. The two must behave alike, and
# one test table runs against both
# (``tests/unit/servers/test_a_version_probe_answers_alike_on_both_sides.py``).
VERSION_PROBE_TIMEOUT_S = 5.0
VERSION_PROBE_MAX_TIMEOUT_S = 30.0
_PROBE_OUTPUT_BYTES = 64 * 1024
VERSION_PATTERN = r"\d+(?:\.\d+)+"
NOT_REPORTED = "not reported"
_PUMP_JOIN_S = 0.5


def probe_wall_clock(timeout_s: Any) -> float:
    """The wall clock a probe is given: the declared one held to the ceiling, else the default."""
    try:
        wall = float(timeout_s) if timeout_s is not None else VERSION_PROBE_TIMEOUT_S
    except (TypeError, ValueError):
        wall = VERSION_PROBE_TIMEOUT_S
    if not math.isfinite(wall) or wall <= 0:
        wall = VERSION_PROBE_TIMEOUT_S
    return min(max(wall, 0.1), VERSION_PROBE_MAX_TIMEOUT_S)


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    """Kill ``process``'s whole group, and it; whatever is already gone is left."""
    killpg = getattr(os, "killpg", None)
    if killpg is not None:
        with contextlib.suppress(OSError):
            killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        process.kill()


def run_bounded(
    argv: list[str],
    wall: float,
    *,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[int | None, bytes, bytes, str]:
    """Run ``argv`` for at most ``wall`` seconds, reading each stream up to the bound.

    Answers the exit status (``None`` when it did not exit in time), both
    streams as far as they were read, and ``""``, ``"timeout"`` or
    ``"flood"`` (it wrote past the bound and was stopped). The program gets a
    session and process group of its own, closed standard input, and its
    group is killed once it has exited or been stopped: a process it started
    that holds the output open is gone with it, and the read ends there.
    ``env`` and ``cwd`` are the program's environment and working directory
    (this process's when ``None``). Both readers are waited for against one
    short deadline once the program has exited (``_PUMP_JOIN_S``).
    """
    process = subprocess.Popen(  # noqa: S603 — a declared argument list, no shell
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=None if env is None else dict(env),
        cwd=cwd,
    )
    held = {"out": bytearray(), "err": bytearray()}
    flooded = threading.Event()

    def _pump(stream: Any, into: bytearray) -> None:
        try:
            while True:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    return
                room = _PROBE_OUTPUT_BYTES - len(into)
                into.extend(chunk[: max(room, 0)])
                if len(chunk) > room:
                    flooded.set()
                    _kill_group(process)
                    return
        except (OSError, ValueError):
            return

    pumps = [
        threading.Thread(target=_pump, args=(process.stdout, held["out"]), daemon=True),
        threading.Thread(target=_pump, args=(process.stderr, held["err"]), daemon=True),
    ]
    for pump in pumps:
        pump.start()
    ended = ""
    status: int | None
    try:
        status = process.wait(timeout=wall)
    except subprocess.TimeoutExpired:
        status, ended = None, "timeout"
    _kill_group(process)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=2.0)
    # One deadline for both readers: a process the program started in a
    # session of its own may hold the output open, and is not waited for.
    deadline = time.monotonic() + _PUMP_JOIN_S
    for pump in pumps:
        pump.join(timeout=max(0.0, deadline - time.monotonic()))
    for stream in (process.stdout, process.stderr):
        with contextlib.suppress(OSError):
            if stream is not None:
                stream.close()
    if flooded.is_set():
        ended = "flood"
    return status, bytes(held["out"]), bytes(held["err"]), ended


def _probed_executable(word: str, search: str | None = None) -> tuple[str | None, str]:
    """The file a probe's first word names, or ``None`` and why it is not run.

    A bare name is looked up on ``search`` (this process's ``PATH`` when ``None``).
    """
    if not word.strip():
        return None, "the probe names no command"
    named = Path(word)
    if named.is_absolute():
        if named.is_file() and os.access(named, os.X_OK):
            return str(named), ""
        return None, f"{named.name} is not on PATH"
    if os.sep in word or (os.altsep and os.altsep in word):
        return None, f"{named.name} is named by a relative path, which a probe never runs"
    found = shutil.which(word, path=search)
    if found is None:
        return None, f"{named.name} is not on PATH"
    return found, ""


def probe_environment(scratch: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """The whole environment a probed program gets: ``PATH``, ``LANG``, ``extra``, a home.

    ``PATH`` is this process's, so a bare name runs what it names here, and
    nothing else of this process's environment reaches the program: a
    worker's or server's variables (provider keys among them) are not the
    program's to read. ``HOME`` and ``TMPDIR`` are ``scratch``, a temporary
    directory the probe also runs in, unless ``extra`` names them. A copy of
    the platform's (``capabilities.probe_environment``).
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        **dict(extra or {}),
    }
    env.setdefault("HOME", scratch)
    env.setdefault("TMPDIR", scratch)
    return env


def probe_version(
    command: tuple[str, ...],
    pattern: str = VERSION_PATTERN,
    timeout_s: float | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    """The version ``command`` reports, else ``"not reported: <reason>"``. Never raises.

    The rules of the platform's version probe (``VersionProbe``): no shell,
    an absolute path or a bare name looked up on ``PATH``, never a relative
    path with a separator, a wall clock held to the ceiling, each stream read
    up to the bound, the program's process group killed whole once it has
    answered or run out of time, and none of this process's environment but
    ``PATH``: the program gets ``probe_environment`` with ``env``'s variables,
    and a temporary directory of its own as its home, temporary directory and
    working directory.
    """
    if not command:
        return f"{NOT_REPORTED}: the probe names no command"
    found, why = _probed_executable(str(command[0]), (env or {}).get("PATH"))
    if found is None:
        return f"{NOT_REPORTED}: {why}"
    try:
        compiled = re.compile(pattern)
    except re.error:
        return f"{NOT_REPORTED}: the probe's pattern is not a regular expression"
    wall = probe_wall_clock(timeout_s)
    try:
        with tempfile.TemporaryDirectory(prefix="version-probe-") as scratch:
            status, out, err, ended = run_bounded(
                [found, *command[1:]], wall, env=probe_environment(scratch, env), cwd=scratch
            )
    except Exception as exc:  # noqa: BLE001 — a version is a label, never a failure
        # The type alone: an exception's words may carry the host's paths.
        return f"{NOT_REPORTED}: it could not be run ({type(exc).__name__})"
    if ended == "timeout":
        return f"{NOT_REPORTED}: it did not answer within {wall:g} s"
    if ended != "flood" and status != 0:
        return f"{NOT_REPORTED}: it exited with status {status}"
    for said in (out, err):
        match = compiled.search(said.decode("utf-8", "replace"))
        if match:
            value = match.group(1) if compiled.groups else match.group(0)
            if value and value.strip():
                return value.strip()[:120]
    if ended == "flood":
        return (
            f"{NOT_REPORTED}: it wrote more than {_PROBE_OUTPUT_BYTES} bytes and named no version"
        )
    return f"{NOT_REPORTED}: its output named no version"


# ---------------------------------------------------------------------------
# The sample
# ---------------------------------------------------------------------------


def sample_roots() -> list[Path]:
    """The directories a path argument may be under, from ``MALSPARK_SAMPLE_ROOTS``.

    Empty when the variable is unset: such a server reads nothing.
    """
    raw = os.environ.get(SAMPLE_ROOTS_ENV, "")
    return [Path(os.path.realpath(part)) for part in raw.split(os.pathsep) if part.strip()]


def sample_file(path: str) -> str:
    """``path`` resolved, when it names a regular file under a sample root; else a failure."""
    if not isinstance(path, str) or not path.strip():
        raise ToolFailure(BAD_ARGUMENT, "path names no file")
    if "\0" in path:
        raise ToolFailure(BAD_ARGUMENT, "path holds a NUL character")
    resolved = Path(os.path.realpath(path))
    if not any(resolved == root or root in resolved.parents for root in sample_roots()):
        raise ToolFailure(PATH_OUTSIDE_ROOTS, OUTSIDE_ROOTS_MESSAGE)
    if not resolved.is_file():
        raise ToolFailure(NO_SUCH_FILE, "the file the path argument names is not there")
    return str(resolved)


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------


async def answering(tool: str, work: Callable[[], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
    """``work``'s answer, or its failure in the one shape; a tool server answers, never raises."""
    try:
        return await work()
    except ToolFailure as failure:
        return tool_error(failure.code, failure.message, tool=tool, remediation=failure.remediation)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 — a tool server answers, it does not raise
        logger.exception("%s failed", tool)
        return tool_error(TOOL_FAILED, f"{type(exc).__name__}: {exc}", tool=tool)


# Each program's version as it answered, by the command that asked it: asked
# once per process, since the program does not change under a running server.
_VERSIONS: dict[tuple[str, ...], str] = {}


def program_version(program: Program) -> str:
    """What ``program`` says its version is, else ``"not reported: <reason>"``. Never raises.

    Asked with its ``version_argv`` through :func:`probe_version`, with the
    variables a run of it gets (``Program.env``); a program that declares no
    version argument, or that is not installed, says so.
    """
    if not program.version_argv:
        return f"{NOT_REPORTED}: the program declares no version argument"
    # The program's own presence, not what a server adds to it (its rules).
    absent = Program.absent(program)
    if absent:
        return f"{NOT_REPORTED}: {absent}"
    command = (*program.command, *program.version_argv)
    if command not in _VERSIONS:
        _VERSIONS[command] = probe_version(command, env=program.env)
    return _VERSIONS[command]


def capabilities(
    server: str, program: Program, tools: Iterable[str], version: str = "unknown"
) -> dict[str, Any]:
    """The capability manifest the platform's registry reads (``capabilities`` tool).

    Probed now: each of ``tools`` needs ``program``, so each is available
    exactly when the program can be started, and says why not and how to
    install it when it cannot. ``requirements`` is the one requirement they
    share, in the shape the platform's own servers write it: the program, the
    version its image pins (``pinned``: ``version``, which is what the server
    was built for) and the version it says it is (``program_version``).
    ``version`` is also the manifest's own ``version``: for these servers the
    program's pinned version, where the platform's own servers give the
    platform's.
    """
    absent = program.absent()
    names = list(tools)
    requirement: dict[str, Any] = {"kind": "binary", "name": program.name}
    if version and version != "unknown":
        requirement["pinned"] = version
    requirement["version"] = program_version(program)
    requirement["tools"] = names
    cells = []
    for name in names:
        cell: dict[str, Any] = {
            "name": name,
            "optional_dependency": program.name,
            "available": absent is None,
            "reason": absent,
            "timeout_s": timeout_seconds(),
        }
        if absent:
            cell["remediation"] = program.install
        cells.append(cell)
    return {"server": server, "version": version, "tools": cells, "requirements": [requirement]}


# ---------------------------------------------------------------------------
# What each tool declares of itself
# ---------------------------------------------------------------------------

# The key of a tool definition's ``_meta`` under which its server declares it,
# in the vocabulary of the platform's tool declarations; the platform's own
# helper (``malspark.tools.declared_facts``) writes the same, and the client
# reads it for every server alike.
FACTS_META_KEY = "malspark/tool_facts"


async def answer_capabilities(
    server: str, program: Program, tools: Iterable[str], version: str = "unknown"
) -> dict[str, Any]:
    """:func:`capabilities`, with the version probe run off the event loop.

    The probe starts a process and may take seconds; a server answers other
    calls meanwhile. The answer is the same, and complete.
    """
    return await asyncio.to_thread(capabilities, server, program, list(tools), version)


# The capabilities tool's declaration, the same on every server.
CAPABILITIES_FACTS: dict[str, Any] = {"kind": "capabilities"}
# A call runs nothing of the sample, reaches nothing beyond this server and
# sends nothing of the sample to a third party.
NO_EFFECT: dict[str, Any] = {"executes": "no", "network": False, "third_party": "no"}


def reading_tool(title: str, facts: Mapping[str, Any]) -> dict[str, Any]:
    """The keyword arguments of FastMCP's ``tool`` decorator that declare one tool here.

    Every tool of such a server reads the file its path names and changes
    nothing, so an identical call answers the same: it is declared read-only
    (the declaration's ``read_only``, and the MCP hints ``readOnlyHint`` and
    ``idempotentHint``), with no effect beyond answering, under ``title``.
    """
    from mcp.types import ToolAnnotations

    held = json.loads(json.dumps(dict(facts)))
    held.update(read_only=True, effects=dict(NO_EFFECT))
    return {
        "annotations": ToolAnnotations(
            title=title,
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
        "meta": {FACTS_META_KEY: held},
    }


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


class BearerGate:
    """An ASGI wrapper that answers 401 to an HTTP request without the server's token."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            given = dict(scope.get("headers") or ()).get(b"authorization", b"")
            if not hmac.compare_digest(given, self._expected):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"text/plain")],
                    }
                )
                await send({"type": "http.response.body", "body": b"unauthorized\n"})
                return
        await self.app(scope, receive, send)


def bind_refusal(bind: str, token: str) -> str:
    """Why the server may not listen on ``bind`` with ``token``; ``""`` when it may."""
    if bind not in _LOOPBACK and not token:
        return (
            f"{BIND_ENV}={bind} listens beyond loopback, and {TOKEN_ENV} is empty: set the "
            "token (and the same token as this server's auth_token in the console)"
        )
    return ""


def serve(mcp: Any, argv: Sequence[str] | None = None) -> None:
    """Run ``mcp`` over streamable HTTP, or over stdio when ``--stdio`` is given."""
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    args = list(sys.argv[1:] if argv is None else argv)
    if "--stdio" in args:
        mcp.run(transport="stdio")
        return
    import uvicorn

    bind = os.environ.get(BIND_ENV, "127.0.0.1").strip() or "127.0.0.1"
    token = os.environ.get(TOKEN_ENV, "").strip()
    refused = bind_refusal(bind, token)
    if refused:
        logger.error("%s", refused)
        raise SystemExit(1)
    port = int(os.environ.get(PORT_ENV, "8080"))
    app = mcp.streamable_http_app()
    uvicorn.run(BearerGate(app, token) if token else app, host=bind, port=port, log_level="info")
