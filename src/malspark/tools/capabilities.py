"""What a tool server can do on the host it runs on, computed rather than claimed.

A sidecar's manifest lists every tool whether or not its optional library is
installed, so a model learns why an answer is empty instead of never seeing
the capability. That leaves the operator learning the same thing one failed
call at a time, mid-run. The capability manifest says it up front::

    {"server": "analysis", "version": "0.9.0",
     "tools": [{"name": "document_info", "optional_dependency": "olefile",
                "available": false, "reason": "olefile is not installed",
                "timeout_s": null}, ...]}

Each sidecar declares which tool needs which optional module, binary,
setting or data path, and ``manifest`` probes each of them on the server's own interpreter
and host — an import, a ``which``, an environment variable — when the server
starts. Nothing is hard-coded as present: a manifest that drifted from the
host would be worse than none. The registry reads it once per job through the
sidecar's ``capabilities`` tool, the settings probe returns it to the console,
and a stage that binds a tool the manifest marks unavailable records the
degradation when it starts, with the reason and the remedy.

The same declarations say what the server ran with: the manifest's
``requirements`` give each declared module's installed distribution and
version, each data path's file count and one digest over its files, and each
binary's version where the tool declares how to ask it (``VersionProbe``), so
a run's record states the tool versions and rule sets it used
(``analysis.run_environment``). They are read each time the manifest is
answered (``answered_manifest``), and a data row is the default path as it was
then; the corpus a call ran with is in that call's own answer
(``data_used``), which the wrapper every tool call goes through writes from
what the call's own rule loader recorded of the corpus it loaded
(``recording_data_used``). A binary's version is read once, in the background
from the server's start, and an answer never waits for it.
"""

from __future__ import annotations

import contextlib
import contextvars
import copy
import fnmatch
import functools
import hashlib
import importlib
import importlib.metadata
import importlib.util
import math
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from malspark.tools.errors import MISSING_DEPENDENCY, NOT_CONFIGURED, REMEDIATIONS

# The tool a server answers this with. Named once, so the registry and the
# probe look for the same thing every sidecar offers.
CAPABILITIES_TOOL = "capabilities"


# What reading what a requirement is at may cost (``Requirement.facts``). A
# probe of a binary's version is given this long when its declaration names no
# wall clock (or names one that is not a positive number), and never more than
# the ceiling. It runs once per process for each executable: a server starts
# reading its binaries' versions in the background when it builds its manifest,
# and the capabilities answer never waits for it (``NOT_READ_YET``).
VERSION_PROBE_TIMEOUT_S = 5.0
VERSION_PROBE_MAX_TIMEOUT_S = 30.0
# How long a version that could not be read (a probe that timed out, failed or
# found no program) is remembered with its reason before it is asked again, so
# a slow or broken program is not run again on every answer. A version read is
# kept for the life of the process.
VERSION_RETRY_S = 600.0
# How long the two readers of a probe's output are waited for, together, once
# the program has exited: a process it started in a session of its own can
# hold the output open past the program's own end.
_PUMP_JOIN_S = 0.5
# How much of a probe's output is read for the version, per stream: a program
# that writes more is stopped there, and what it wrote up to the bound is read.
_PROBE_OUTPUT_BYTES = 64 * 1024
# The most a data path's digest reads: beyond either bound its files are
# counted and no digest is computed, so a corpus copied in whole by mistake
# costs a count, not a read of it.
DATA_DIGEST_MAX_FILES = 20_000
DATA_DIGEST_MAX_BYTES = 64 * 1024 * 1024
# What a fact that was not read is recorded as. ``NOT_REPORTED`` is the one
# phrase every part of a run's environment record says it with
# (``analysis.run_environment``, ``llm.sent_request``), a reason following it
# after a colon where one is known.
NOT_INSTALLED = "not installed"
NOT_REPORTED = "not reported"
# A binary's version the server's background reading has not read yet.
NOT_READ_YET = f"{NOT_REPORTED}: not read yet"


@dataclass(frozen=True)
class VersionProbe:
    """How a binary says its own version, for a tool that declares it.

    ``command`` is run as given, never through a shell. Its first word is the
    executable: an absolute path, or a bare name looked up on ``PATH``; a
    relative path with a separator in it (``./tool``) is never run, since it
    would name whatever the working directory holds. A requirement that
    declares where its tool finds the executable (``Requirement.resolve``)
    runs the probe on that file instead, so the probe asks the binary the tool
    runs. The version is the first match of ``pattern`` in what the command
    writes (its standard output, then its standard error, each read up to
    ``_PROBE_OUTPUT_BYTES``): the pattern's first group when it has one, else
    the whole match. ``timeout_s`` bounds the run (``VERSION_PROBE_TIMEOUT_S``
    when ``None`` or not a positive number, never more than
    ``VERSION_PROBE_MAX_TIMEOUT_S``). The program runs in a process group of
    its own, which is killed whole once it has answered or run out of time,
    so no process it started outlives the probe or holds its output open. It
    gets none of this process's environment but ``PATH`` (``probe_environment``)
    and a temporary directory of its own as its home, temporary directory and
    working directory.
    """

    command: tuple[str, ...]
    pattern: str = r"\d+(?:\.\d+)+"
    timeout_s: float | None = None

    def read(self, executable: str | None = None) -> str:
        """The version the command reports, else ``"not reported: <reason>"``. Never raises.

        ``executable`` replaces the command's first word where the caller
        found the file the tool runs (``Requirement.resolve``).
        """
        command = self.command if executable is None else (executable, *self.command[1:])
        return _probe_version(tuple(str(word) for word in command), self.pattern, self.timeout_s)


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
    short deadline once the program has exited (``_PUMP_JOIN_S``). The CLI
    sidecar base keeps a copy of this (``services/cli-sidecar/cli_sidecar.py``),
    and both answer one test table.
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
    directory the probe also runs in, unless ``extra`` names them. The CLI
    sidecar base keeps a copy, and both answer one test table.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        **dict(extra or {}),
    }
    env.setdefault("HOME", scratch)
    env.setdefault("TMPDIR", scratch)
    return env


def _probe_version(command: tuple[str, ...], pattern: str, timeout_s: float | None) -> str:
    # Once per process for each probe of each executable: a version does not
    # change while a server runs, and the probe is a process start. One that
    # was not read is asked again only after ``VERSION_RETRY_S``.
    return remembered_version(
        ("probe", command, pattern, timeout_s),
        lambda: _read_version(command, pattern, timeout_s),
    )


def _read_version(command: tuple[str, ...], pattern: str, timeout_s: float | None) -> str:
    """The version ``command`` reports now, else ``"not reported: <reason>"``. Never raises."""
    if not command:
        return f"{NOT_REPORTED}: the probe names no command"
    found, why = _probed_executable(str(command[0]))
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
                [found, *command[1:]], wall, env=probe_environment(scratch), cwd=scratch
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


# Each version read, by what read it, with when (``time.monotonic``): a version
# read is kept for the life of the process, one not read (``NOT_REPORTED``)
# for ``VERSION_RETRY_S``. The readings under way in the background, by key.
_VERSIONS: dict[Any, tuple[str, float]] = {}
_VERSIONS_PENDING: set[Any] = set()
_VERSIONS_LOCK = threading.Lock()
_MAX_VERSIONS = 256


def _kept_version(key: Any) -> tuple[str, bool] | None:
    """The version kept under ``key`` and whether it still stands, or ``None``."""
    with _VERSIONS_LOCK:
        held = _VERSIONS.get(key)
    if held is None:
        return None
    value, at = held
    return value, not value.startswith(NOT_REPORTED) or time.monotonic() - at < VERSION_RETRY_S


def _keep_version(key: Any, read: Callable[[], str]) -> str:
    try:
        value = str(read())
    except Exception as exc:  # noqa: BLE001 — a version is a label, never a failure
        value = f"{NOT_REPORTED}: it could not be read ({type(exc).__name__})"
    with _VERSIONS_LOCK:
        if len(_VERSIONS) >= _MAX_VERSIONS:
            _VERSIONS.clear()
        _VERSIONS[key] = (value, time.monotonic())
    return value


def remembered_version(key: Any, read: Callable[[], str]) -> str:
    """The version kept under ``key``, else what ``read`` answers now, kept (``_VERSIONS``)."""
    kept = _kept_version(key)
    if kept is not None and kept[1]:
        return kept[0]
    return _keep_version(key, read)


def version_in_background(key: Any, read: Callable[[], str]) -> str:
    """The version kept under ``key``, never waiting for it to be read.

    When none stands, ``read`` is started in a thread of its own (once per
    key at a time) and the answer is what was kept before, a reason for a
    version not read, or ``NOT_READ_YET``.
    """
    kept = _kept_version(key)
    if kept is not None and kept[1]:
        return kept[0]
    with _VERSIONS_LOCK:
        start = key not in _VERSIONS_PENDING
        _VERSIONS_PENDING.add(key)
    if start:

        def _read() -> None:
            try:
                _keep_version(key, read)
            finally:
                with _VERSIONS_LOCK:
                    _VERSIONS_PENDING.discard(key)

        threading.Thread(target=_read, name="version-reading", daemon=True).start()
    return kept[0] if kept is not None else NOT_READ_YET


@functools.cache
def _distributions_of() -> dict[str, list[str]]:
    """Each top-level module and the distributions that provide it, read once per process."""
    try:
        return {k: list(v) for k, v in importlib.metadata.packages_distributions().items()}
    except Exception:  # noqa: BLE001 — a version is a label, never a failure
        return {}


def module_version(name: str) -> dict[str, str]:
    """``{"distribution", "version"}`` of the distribution that provides module ``name``.

    Looked up, never imported: the module's top-level package is found on the
    import path and the distribution that installed it is read from its
    metadata. ``version`` is ``"not installed"`` when the module is not on the
    import path, and ``"not reported: …"`` when it is there but no installed
    distribution names it (a module vendored or copied in). Never raises.
    """
    top = name.split(".", 1)[0]
    try:
        found = importlib.util.find_spec(top)
    except (ImportError, ValueError):
        found = None
    if found is None:
        return {"version": NOT_INSTALLED}
    for distribution in sorted(_distributions_of().get(top, ())):
        try:
            return {
                "distribution": distribution,
                "version": str(importlib.metadata.version(distribution)),
            }
        except Exception:  # noqa: BLE001, S112 — the next distribution may answer
            continue
    return {"version": f"{NOT_REPORTED}: no installed distribution provides {top}"}


def data_files(target: Path, pattern: str, exclude: tuple[str, ...] = ()) -> list[tuple[str, Path]]:
    """The files that make up the data at ``target``, as ``(name, path)`` in name order.

    A file is itself, under its own name; a directory is every file under it
    matching ``pattern``, each named by its path relative to the directory,
    but for a file whose directory, written out whole as this host names it
    (the directory ``target`` itself included), matches one of ``exclude``.
    That is how a rule loader that skips directories by their path reads
    them: ``*.git*`` is capa's own rule, which skips every directory whose
    path holds ``.git`` (a clone's ``.git`` and ``.github`` trees, and every
    file of a corpus kept under a path such as ``rules.git``). Empty when
    nothing is there.
    """
    if target.is_file():
        return [(target.name, target)]
    if not target.is_dir():
        return []
    held = []
    for entry in target.rglob(pattern):
        if exclude and any(fnmatch.fnmatchcase(str(entry.parent), rule) for rule in exclude):
            continue
        if entry.is_file():
            held.append((entry.relative_to(target).as_posix(), entry))
    return sorted(held, key=lambda item: item[0])


# Each data path's last digest, by path, pattern and exclusions, with the stat
# signature of the files it was computed over: the digest is computed again
# only when a file is added, removed, renamed, resized or rewritten.
_DIGESTS: dict[tuple[str, str, tuple[str, ...]], tuple[Any, dict[str, Any]]] = {}
_DIGESTS_LOCK = threading.Lock()
_MAX_DIGESTS = 32


@dataclass(frozen=True)
class CorpusRead:
    """The data at a path as it was listed once: its files, their stat signature, its facts.

    ``signature`` is every file's name, size and modification time, ``None``
    when they could not be read; ``facts`` the count and digest
    (``Requirement.data_facts``). A rule loader keeps the layer it loaded
    from these files with this reading, and loads again when the signature
    it reads before a call differs (``corpus_signature``).
    """

    files: tuple[tuple[str, Path], ...]
    signature: tuple[tuple[str, int, int], ...] | None
    facts: dict[str, Any]


def corpus_signature(
    target: str, pattern: str, exclude: tuple[str, ...] = ()
) -> tuple[tuple[str, int, int], ...] | None:
    """The stat signature of the data at ``target`` now (``CorpusRead``), ``None`` unread."""
    try:
        files = data_files(Path(target), pattern, exclude)
        return tuple((name, st.st_size, st.st_mtime_ns) for name, st in _stats(files))
    except OSError:
        return None


def _stats(files: list[tuple[str, Path]]) -> list[tuple[str, os.stat_result]]:
    return [(name, path.stat()) for name, path in files]


def read_corpus(target: str, pattern: str, exclude: tuple[str, ...] = ()) -> CorpusRead:
    """The data at ``target`` listed once, its signature and its count and digest. Never raises."""
    try:
        files = data_files(Path(target), pattern, exclude)
    except OSError as exc:
        return CorpusRead(
            (), None, {"files": 0, "digest_statement": f"not read ({type(exc).__name__})"}
        )
    return _read_listed(target, pattern, exclude, files)


def _data_digest(target: str, pattern: str, exclude: tuple[str, ...] = ()) -> dict[str, Any]:
    # Read as the data is now: a server started before its corpus was fetched,
    # or a worker whose operator updated it, digests what is there when asked.
    return read_corpus(target, pattern, exclude).facts


def _read_listed(
    target: str, pattern: str, exclude: tuple[str, ...], files: list[tuple[str, Path]]
) -> CorpusRead:
    # The files are listed and their sizes and modification times read every
    # time; their contents only when that signature changed.
    listed = tuple(files)
    out: dict[str, Any] = {"files": len(files)}
    if not files:
        out["digest_statement"] = "no file is there"
        return CorpusRead(listed, (), out)
    try:
        stats = _stats(files)
    except OSError as exc:
        out["digest_statement"] = f"digest not computed ({type(exc).__name__})"
        return CorpusRead(listed, None, out)
    signature = tuple((name, st.st_size, st.st_mtime_ns) for name, st in stats)
    key = (target, pattern, exclude)
    with _DIGESTS_LOCK:
        kept = _DIGESTS.get(key)
    if kept is not None and kept[0] == signature:
        return CorpusRead(listed, signature, dict(kept[1]))
    total = sum(st.st_size for _name, st in stats)
    out["bytes"] = total
    if len(files) > DATA_DIGEST_MAX_FILES or total > DATA_DIGEST_MAX_BYTES:
        out["digest_statement"] = (
            f"digest not computed: over the bound ({DATA_DIGEST_MAX_FILES} files, "
            f"{DATA_DIGEST_MAX_BYTES} bytes)"
        )
        return CorpusRead(listed, signature, out)
    digest = hashlib.sha256()
    try:
        for name, path in files:
            content = path.read_bytes()
            encoded = name.encode("utf-8", "surrogateescape")
            # Each part is length-prefixed, so no two different sets of names
            # and contents feed the hash the same bytes.
            digest.update(len(encoded).to_bytes(8, "big") + encoded)
            digest.update(len(content).to_bytes(8, "big") + content)
    except OSError as exc:
        out["digest_statement"] = f"digest not computed ({type(exc).__name__})"
        return CorpusRead(listed, None, out)
    out["sha256"] = digest.hexdigest()
    with _DIGESTS_LOCK:
        if len(_DIGESTS) >= _MAX_DIGESTS:
            _DIGESTS.clear()
        _DIGESTS[key] = (signature, dict(out))
    return CorpusRead(listed, signature, out)


def clear_fact_caches() -> None:
    """Forget every digest and version read. For tests."""
    with _DIGESTS_LOCK:
        _DIGESTS.clear()
    with _VERSIONS_LOCK:
        _VERSIONS.clear()
        _VERSIONS_PENDING.clear()
    # Read off the module: a test may have put a plain function in its place.
    clear = getattr(_distributions_of, "cache_clear", None)
    if clear is not None:
        clear()


@dataclass(frozen=True)
class Requirement:
    """One thing a tool needs on the host: a module, a binary, a setting or data."""

    kind: str  # "module" | "binary" | "env" | "data"
    name: str
    # For a binary found somewhere other than ``PATH`` alone: the lookup that
    # answers ``None`` when it is present, else the reason it is not. Called
    # with no argument inside the server, and with the server's environment
    # when the check is made from outside it (``installed``).
    locate: Callable[..., str | None] | None = field(default=None, compare=False)
    # For data (a rule corpus, a signature set): the core setting whose value
    # is the path a caller hands the tool, as a dotted path
    # (``static.capa.rules_dir``), and the server environment variable that
    # overrides ``name``, the default path, where the tool reads one instead.
    # Either may be empty. ``pattern`` is what a file in a directory must match
    # for the directory to hold the data. ``fetched`` is data kept out of
    # version control, which a fresh clone or worktree lacks until it is
    # fetched; otherwise the default is tracked and only an override can miss.
    setting: str = ""
    override: str = ""
    pattern: str = "*"
    fetched: bool = True
    # For a binary: how it says its own version (``VersionProbe``), where the
    # tool declares one. Without it a binary's version is not reported.
    version_probe: VersionProbe | None = field(default=None, compare=False)
    # For a binary found by ``locate``: the file the tool runs, as the same
    # lookup finds it (called as ``locate`` is), or ``None`` when there is
    # none. A version probe runs on that file, not on what ``PATH`` names.
    resolve: Callable[..., str | os.PathLike[str] | None] | None = field(
        default=None, compare=False
    )
    # For a binary whose tool already asks it its version, as a check of its
    # pinned build (``emulated_strings._does_not_run``): the version that check
    # read, or ``"not reported: <reason>"``, called as ``locate`` is. Read in
    # place of ``version_probe``, so the binary is never run a second time.
    version_of: Callable[..., str] | None = field(default=None, compare=False)
    # For data: what of the directory the tool's loader leaves out
    # (``data_files``), so the count and the digest cover what it loads; and
    # the call argument that names another corpus in place of this one (any
    # value but ``CORPUS_DEFAULT_WORDS``), so a call's answer names the data
    # it ran with (``data_used``).
    exclude: tuple[str, ...] = ()
    argument: str = ""

    def facts(
        self,
        environ: Mapping[str, str] | None = None,
        settings: Any = None,
        *,
        wait: bool = True,
    ) -> dict[str, Any] | None:
        """What this requirement is on this host, for the record of a run. Never raises.

        A module: the distribution that provides it and its installed version
        (``module_version``). Data: the path's files matching ``pattern`` (but
        ``exclude``) counted and one SHA-256 over them, name then content in
        name order, within ``DATA_DIGEST_MAX_FILES`` and
        ``DATA_DIGEST_MAX_BYTES``, as they are when this is read; the path is
        read as ``installed`` reads it and named only by what named it, and
        ``digest_of`` says in words what the digest covers. A binary: the
        version its tool's own check read (``version_of``), else the one its
        declared probe reads, on the file ``resolve`` finds where it is
        declared, else ``"not reported"``. A setting is no install and has no
        facts (``None``): its value is the operator's, not the host's. A
        module's version and a binary's are read once per process (a binary's
        not read is asked again after ``VERSION_RETRY_S``); with ``wait``
        false a binary's version not read yet is ``NOT_READ_YET`` and is read
        in the background (``version_in_background``). Data is listed each
        time and read again only when a file of it changed.
        """
        try:
            out: dict[str, Any] = {"kind": self.kind, "name": self.name}
            if self.kind == "module":
                out.update(module_version(self.name))
            elif self.kind == "binary":
                out["version"] = self._version(environ, wait=wait)
            elif self.kind == "data":
                value, named_by = self._data_path(environ, settings)
                out.update(self.data_facts(value, named_by))
            else:
                return None
            return out
        except Exception as exc:  # noqa: BLE001 — a fact unread is recorded, never raised
            return {"kind": self.kind, "name": self.name, "statement": type(exc).__name__}

    def _version(self, environ: Mapping[str, str] | None, *, wait: bool = True) -> str:
        key = (
            "requirement",
            self,
            self.version_probe,
            self.version_of,
            self.resolve,
            None if environ is None else frozenset(environ.items()),
        )

        def _read() -> str:
            return self._read_version(environ)

        return remembered_version(key, _read) if wait else version_in_background(key, _read)

    def _read_version(self, environ: Mapping[str, str] | None) -> str:
        if self.version_of is not None:
            said = self.version_of() if environ is None else self.version_of(environ)
            return str(said) if said else f"{NOT_REPORTED}: its tool's check read no version"
        if self.version_probe is None:
            return NOT_REPORTED
        if self.resolve is None:
            return self.version_probe.read()
        found = self.resolve() if environ is None else self.resolve(environ)
        if found is None:
            why = None
            if self.locate is not None:
                why = self.locate() if environ is None else self.locate(environ)
            return f"{NOT_REPORTED}: {why or f'{self.name} is not where its tool looks'}"
        return self.version_probe.read(os.fspath(found))

    def data_facts(self, value: str, named_by: str) -> dict[str, Any]:
        """The count and digest of the data at ``value``, named by ``named_by``. Never raises."""
        out = self._data_head(named_by)
        if not value.strip():
            out.update({"files": 0, "digest_statement": f"{named_by} names no path"})
            return out
        out.update(_data_digest(str(_resolved(value)), self.pattern, self.exclude))
        left_out = (
            f", but those under a directory whose path matches {' or '.join(self.exclude)},"
            if self.exclude
            else ""
        )
        out["digest_of"] = (
            f"the files matching {self.pattern}{left_out} at the path {named_by} names, "
            "as they were when this was read"
        )
        return out

    def _data_head(self, named_by: str) -> dict[str, Any]:
        out: dict[str, Any] = {"named_by": named_by, "pattern": self.pattern}
        if self.exclude:
            out["exclude"] = list(self.exclude)
        return out

    def corpus(
        self,
        argument: Any = None,
        environ: Mapping[str, str] | None = None,
        settings: Any = None,
    ) -> tuple[Path, str]:
        """The absolute path of the data a call with ``argument`` reads, and what named it.

        ``argument`` is the value of the call's corpus argument
        (``Requirement.argument``). One that names no corpus
        (``CORPUS_DEFAULT_WORDS``), or that names the path the tool reads by
        default, is that path, named by what names it (``installed``: the
        setting, the override in ``environ``, the default); any other is the
        path it names, named by the argument. The tool's own rule loader
        reads its corpus through this (``tools.rules``), so the path it loads
        and the one its call's answer names are one.
        """
        value, named_by = self._data_path(environ, settings)
        default = _resolved(value.strip())
        if isinstance(argument, str) and argument.strip() not in CORPUS_DEFAULT_WORDS:
            given = _resolved(argument.strip())
            if given != default:
                return given, f"the {self.argument or 'corpus'} argument"
        return default, named_by

    def probe(self) -> str | None:
        """``None`` when present, else the reason it is not.

        A missing module says so in the import's own words, which name the
        module and nothing else. Anything further — a broken install, a shared
        library that will not load — is reported by exception type alone: those
        messages carry absolute paths off the host, and this reason travels to
        a probe response, the console, the run summary and the judge's prompt.
        The type is what a reader acts on; the path is what they must not be
        handed.
        """
        if self.kind == "module":
            try:
                importlib.import_module(self.name)
            except ModuleNotFoundError as exc:
                detail = str(exc).strip()
                return f"{self.name} is not installed" + (f" ({detail})" if detail else "")
            except Exception as exc:  # noqa: BLE001 — a broken import is as absent as a missing one
                return f"{self.name} is not installed ({type(exc).__name__})"
            return None
        if self.kind == "binary":
            if self.locate is not None:
                return self.locate()
            return None if shutil.which(self.name) else f"{self.name} is not on PATH"
        if self.kind == "env":
            return None if os.environ.get(self.name) else f"{self.name} is not configured"
        if self.kind == "data":
            # The path a tool is handed is the caller's setting, which the
            # server does not read: the check before a job does (``installed``).
            return None
        return f"unknown requirement kind {self.kind!r}"

    def installed(
        self, environ: Mapping[str, str] | None = None, settings: Any = None
    ) -> str | None:
        """``None`` when the module, binary or data is on this host, else the reason.

        The check made before a job, from outside the server: nothing is
        imported and nothing is run. A module is looked up on the import path
        (a library uninstalled under a running process is noticed, where a
        module that process imported once would still answer), and a binary is
        looked for as ``probe`` looks for it, in ``environ`` (the environment
        the server is started with) rather than this process's. A setting is
        no install: an ``env`` requirement answers ``None`` here, since the
        value is handed to the server by its own settings, which this
        process's environment does not show.

        A data path is read where the tool reads it. ``settings`` is given
        only by a caller that hands the tool the declared setting's value (the
        worker's own reading): the setting is then the path. Otherwise, as for
        a tool a server runs with its own defaults, the path is the override
        in ``environ`` (this process's environment when ``None``), else the
        default. It is missing when nothing is there, a file is empty or a
        directory holds no file matching ``pattern``. The reason names what
        named the path, and the path itself only relative to the project root:
        the answer is read by any signed-in user, and a path outside the
        project is the host's, not theirs.

        The import path looked on is this process's: a server started with a
        ``PYTHONPATH`` of its own can import what this answers is missing, so
        a caller leaves a module of such a server unchecked.
        """
        if self.kind == "module":
            try:
                found = importlib.util.find_spec(self.name)
            except (ImportError, ValueError):
                found = None
            if found is None:
                return f"{self.name} is not installed (No module named '{self.name}')"
            return None
        if self.kind == "binary":
            if self.locate is not None:
                return self.locate(environ)
            path = None if environ is None else environ.get("PATH")
            return None if shutil.which(self.name, path=path) else f"{self.name} is not on PATH"
        if self.kind == "data":
            return self._data_missing(environ, settings)
        return None

    def _data_path(self, environ: Mapping[str, str] | None, settings: Any) -> tuple[str, str]:
        """The data path the tool reads, and what named it (``installed``)."""
        value, named_by = self.name, "the default"
        held = _setting_value(settings, self.setting) if self.setting else None
        if held is not None:
            value, named_by = str(held), self.setting
        elif self.override:
            given = (os.environ if environ is None else environ).get(self.override, "")
            if given.strip():
                value, named_by = given, self.override
        return value, named_by

    def _data_missing(self, environ: Mapping[str, str] | None, settings: Any) -> str | None:
        value, named_by = self._data_path(environ, settings)
        if not value.strip():
            return f"{named_by} names no path"
        base = _data_root()
        target = Path(value)
        target = target if target.is_absolute() else base / target
        if data_held(target, self.pattern):
            return None
        try:
            shown = target.relative_to(base).as_posix()
        except ValueError:
            return f"the path {named_by} names is missing or empty"
        return f"{shown} is missing or empty (named by {named_by})"

    def handed(self, settings: Any) -> dict[str, str]:
        """The server environment that hands the tool this data path's setting.

        ``{override: value}`` for data declaring both a core setting and a
        server override, when ``settings`` names a path other than the
        default: the server's tool then reads the path a caller handing the
        setting reads. Empty otherwise, so a launch under the defaults is
        given nothing it was not given before.
        """
        if self.kind != "data" or not self.setting or not self.override:
            return {}
        held = _setting_value(settings, self.setting)
        value = "" if held is None else str(held).strip()
        if not value:
            return {}
        from malspark.core.paths import resolve_data

        # Absolute, as the caller's own reading resolves it: a server started
        # in another working directory or tree reads the same path.
        path = resolve_data(value)
        if path == resolve_data(self.name):
            return {}
        return {self.override: str(path)}

    @property
    def remedy(self) -> str:
        """What puts a missing data path in place, in words naming no one tool."""
        named = " or ".join(name for name in (self.setting, self.override) if name)
        point = f", or point {named} at a populated copy" if named else ""
        if not self.fetched:
            return f"restore {self.name} from version control{point}"
        return (
            f"put the data in {self.name}{point}: it is not in version control, so a "
            "fresh clone or git worktree has it only once make external has fetched it "
            "or the main checkout's copy is linked in"
        )


def _setting_value(settings: Any, dotted: str) -> Any:
    """The value at ``dotted`` in ``settings``, or ``None`` when there is none to read."""
    node = settings
    for part in dotted.split("."):
        if node is None:
            return None
        node = node.get(part) if isinstance(node, Mapping) else getattr(node, part, None)
    return node


def _data_root() -> Path:
    """The directory a relative data path is read against (``core.paths.resolve_data``)."""
    from malspark.core.paths import get_project_root

    return get_project_root()


def _resolved(value: str) -> Path:
    """``value`` as an absolute path, a relative one read against ``_data_root``, normalised."""
    target = Path(value)
    return Path(os.path.normpath(target if target.is_absolute() else _data_root() / target))


def shown_data_name(path: Path) -> str:
    """How a data path is named in a record: from the project root inside it, else its base name.

    Never the host's layout: a path outside the project is the host's, not
    the reader's.
    """
    try:
        return path.relative_to(Path(os.path.normpath(_data_root()))).as_posix() or "."
    except ValueError:
        return path.name


def data_held(path: str | os.PathLike[str], pattern: str = "*") -> bool:
    """Whether ``path`` holds data: a non-empty file, or a directory with a file of ``pattern``.

    A look, not a load: nothing is parsed, so it stays cheap enough for every
    submit and status read. A file that is there and holds no rule (a YARA
    corpus of ``rules: []``) passes it; the engine that reads it answers that
    it did not run (``tools.rules._not_loaded``), and the run is degraded then.
    """
    target = Path(path)
    try:
        if target.is_file():
            return target.stat().st_size > 0
        return target.is_dir() and any(entry.is_file() for entry in target.rglob(pattern))
    except OSError:
        return False


def module(name: str) -> Requirement:
    return Requirement("module", name)


def binary(
    name: str,
    locate: Callable[..., str | None] | None = None,
    *,
    version_probe: VersionProbe | None = None,
    resolve: Callable[..., str | os.PathLike[str] | None] | None = None,
    version_of: Callable[..., str] | None = None,
) -> Requirement:
    """A tool that shells out to an executable.

    Found on ``PATH`` by default. ``locate`` is for an executable looked for in
    more places than that, or checked for more than presence — the analysis
    server's ``floss`` looks at a configured path and a user tools directory
    and runs only the pinned build — and answers the reason it is absent.
    ``version_probe`` is how the executable says its version, for a run's
    record of what it ran (``Requirement.facts``); without one its version is
    not reported. ``resolve`` is the file ``locate``'s lookup finds, which the
    probe then runs, so it asks the build the tool runs. ``version_of`` is the
    version the tool's own check of its build already read, for a tool that
    makes one: it is the version, and the binary is not run again to ask.
    """
    return Requirement(
        "binary",
        name,
        locate,
        version_probe=version_probe,
        resolve=resolve,
        version_of=version_of,
    )


def env(name: str) -> Requirement:
    return Requirement("env", name)


def data(
    default: str,
    *,
    setting: str = "",
    override: str = "",
    pattern: str = "*",
    fetched: bool = True,
    exclude: tuple[str, ...] = (),
    argument: str = "",
) -> Requirement:
    """A file or directory the tool reads its rules or signatures from.

    ``default`` is the path the tool reads when nothing names another;
    ``setting`` the core setting whose value a caller that reads it hands the
    tool instead (a server running the tool with its own defaults does not,
    unless ``override`` is declared too: its launch is then handed the
    setting's value under it, ``handed``),
    ``override`` the server environment variable that replaces the default,
    and ``pattern`` what a file of a directory must match to count. A path
    that is missing or holds nothing is named before a job (``installed``)
    with what named it: a tool reading an empty corpus answers nothing, and
    says so only once the run has paid for it. ``fetched`` is ``False`` for a
    default that version control keeps (``Requirement.remedy``). ``exclude``
    is what of a directory the tool's loader leaves out, and ``argument`` the
    call argument that names another corpus in place of this one
    (``data_used``).
    """
    return Requirement(
        "data",
        default,
        setting=setting,
        override=override,
        pattern=pattern,
        fetched=fetched,
        exclude=tuple(exclude),
        argument=argument,
    )


@dataclass(frozen=True)
class ToolNeeds:
    """A tool and what it needs. No requirement means it always answers."""

    name: str
    requires: tuple[Requirement, ...] = ()
    timeout_s: float | None = None
    # What the tool still does without the requirement, when it does
    # something: ``apk_info`` answers the zip-level facts without androguard.
    without: str = ""
    # The routed formats only the missing requirement reads, for a tool that
    # still answers without it: a sample of another known format loses
    # nothing (``archive_list`` without py7zr on a zip), and one of these
    # formats loses what it would have read. Empty when that cannot be said,
    # and the partial answer is then a loss for every sample.
    without_reads: tuple[str, ...] = ()
    # The remedy when the requirement is missing, where the code's general one
    # names the wrong thing: an executable is not installed by ``uv sync``.
    remediation: str = ""
    # A tool whose work grows with the sample and has no wall clock of its own
    # (capa, FLOSS): a caller waits for it with no deadline unless its operator
    # set one, and its caller giving up is not the server failing.
    long_running: bool = False
    # What the tool takes and does, in plain facts, for a tool whose arguments
    # its name does not say (the operations of ``transform_bytes``).
    facts: str = ""


def _cell(tool: ToolNeeds) -> dict[str, Any]:
    # Probed once per requirement. The reason and the code both need the
    # answer, and probing twice re-runs an import, a ``which`` and a read of
    # the environment for every cell of every manifest.
    probed = [(req, req.probe()) for req in tool.requires]
    missing = [(req, reason) for req, reason in probed if reason]
    # A data path is never probed here (``Requirement.probe``), so not listed.
    dependency = ", ".join(req.name for req in tool.requires if req.kind != "data") or None
    cell: dict[str, Any] = {
        "name": tool.name,
        "optional_dependency": dependency,
        "available": not missing,
        "reason": "; ".join(reason for _req, reason in missing) if missing else None,
        "timeout_s": tool.timeout_s,
    }
    if tool.long_running:
        cell["long_running"] = True
    if tool.facts:
        cell["facts"] = tool.facts
    if missing:
        kinds = {req.kind for req, _reason in missing}
        code = NOT_CONFIGURED if kinds == {"env"} else MISSING_DEPENDENCY
        # Kept on the cell: a setting left unset is the operator's choice and a
        # library missing is a loss, and the code, not the reason's words, is
        # what tells them apart (``pipeline.operator_choice``).
        cell["code"] = code
        cell["remediation"] = remedy_for(tool, [req for req, _reason in missing])
        if tool.without:
            cell["without"] = tool.without
            if tool.without_reads:
                cell["without_reads"] = list(tool.without_reads)
    return cell


def package_version(distribution: str = "malspark") -> str:
    """The installed version of ``distribution``, or ``"unknown"``."""
    try:
        return str(importlib.metadata.version(distribution))
    except Exception:  # noqa: BLE001 — a version is a label, never a failure
        return "unknown"


def requirement_facts(
    tools: list[ToolNeeds],
    environ: Mapping[str, str] | None = None,
    settings: Any = None,
    *,
    wait: bool = True,
) -> list[dict[str, Any]]:
    """What each requirement of ``tools`` is on this host, once each, with the tools needing it.

    One row per requirement (``Requirement.facts``), in the order the tools
    first declare them, each listing the tools that declare it. A setting is
    not listed. ``wait`` false never waits for a binary's version not read
    yet. Never raises.
    """
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for tool in tools:
        for req in tool.requires:
            key = (req.kind, req.name)
            if key not in rows:
                facts = req.facts(environ, settings, wait=wait)
                if facts is None:
                    continue
                rows[key] = {**facts, "tools": []}
            if tool.name not in rows[key]["tools"]:
                rows[key]["tools"].append(tool.name)
    return list(rows.values())


def manifest(
    server: str,
    tools: list[ToolNeeds],
    *,
    version: str | None = None,
    requirements: bool = True,
) -> dict[str, Any]:
    """The capability manifest for ``server``, probed now on this host.

    ``requirements`` is what each declared module, binary and data path is
    here (``requirement_facts``). A server builds its manifest's cells once
    when it starts and leaves them out there (``requirements=False``), then
    reads them each time its ``capabilities`` tool is answered
    (``answered_manifest``): data fetched after the start, or changed under a
    running server, is what the answer describes. Building it so also starts
    reading each declared binary's version in the background
    (``read_versions_in_background``), which no answer waits for.
    """
    held: dict[str, Any] = {
        "server": server,
        "version": version if version is not None else package_version(),
        "tools": [_cell(tool) for tool in tools],
    }
    if requirements:
        held["requirements"] = requirement_facts(tools)
    else:
        read_versions_in_background(tools)
    return held


def read_versions_in_background(tools: list[ToolNeeds]) -> None:
    """Start reading the version of each binary ``tools`` declare, in a thread of its own each."""
    for tool in tools:
        for req in tool.requires:
            if req.kind == "binary":
                req._version(None, wait=False)


def answered_manifest(held: Mapping[str, Any], tools: list[ToolNeeds]) -> dict[str, Any]:
    """A copy of the manifest ``held`` with its ``requirements`` read now (``manifest``).

    Deep, so a caller cannot reach in and change what the server says. A
    binary's version is the one read in the background, ``NOT_READ_YET``
    until it has been: this never waits for a program to answer. The data's
    count and digest are read here, so a server calls this off its event
    loop.
    """
    out = copy.deepcopy(dict(held))
    out["requirements"] = requirement_facts(tools, wait=False)
    return out


# The values of a corpus argument (``Requirement.argument``) that name the
# default corpus rather than a path.
CORPUS_DEFAULT_WORDS = ("", "default")
# The key a tool's answer names the data it ran with under (``data_used``).
DATA_USED_KEY = "data_used"


# What a call's rule loaders recorded of the data they loaded, while the
# wrapper the call goes through records it (``recording_data_used``).
_LOADED: contextvars.ContextVar[dict[Requirement, dict[str, Any]] | None] = contextvars.ContextVar(
    "malspark_data_loaded", default=None
)
# What a call's row says of data its loader recorded no load of.
NOT_LOADED_STATEMENT = "not loaded: the call ended before it loaded this data"
# What a row says in place of a digest when the data changed while it loaded.
CHANGED_WHILE_LOADED = "digest not taken: the data changed while it was loaded"


@contextlib.contextmanager
def recording_data_used() -> Iterator[dict[Requirement, dict[str, Any]]]:
    """Record, for the call made inside, the data each declared corpus was loaded from.

    The rule loaders call ``note_data_used`` with the reading the layer they
    used was loaded from; what they noted is handed to ``data_used``.
    """
    held: dict[Requirement, dict[str, Any]] = {}
    token = _LOADED.set(held)
    try:
        yield held
    finally:
        _LOADED.reset(token)


def note_data_used(
    req: Requirement, path: Path, named_by: str, read: CorpusRead, *, changed: bool = False
) -> None:
    """Record that the call under way ran with the data at ``path`` as ``read`` read it.

    ``read`` is the reading the loader's layer was loaded from (or, for a
    loader that loads in a process of its own, the one made just before it
    started). ``changed`` is a signature read again after the load that
    differs from it: the digest is then not stated. Nothing is recorded
    outside ``recording_data_used``.
    """
    held = _LOADED.get()
    if held is None:
        return
    facts = dict(read.facts)
    if changed:
        facts.pop("sha256", None)
        facts["digest_statement"] = CHANGED_WHILE_LOADED
    held[req] = {"name": shown_data_name(path), **req._data_head(named_by), **facts}


def data_used(
    needs: ToolNeeds | None,
    arguments: Mapping[str, Any],
    environ: Mapping[str, str] | None = None,
    settings: Any = None,
    loaded: Mapping[Requirement, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Per data path ``needs`` declares, the data a call with ``arguments`` ran with. Never raises.

    ``loaded`` is what the call's rule loaders recorded (``recording_data_used``):
    a corpus there is named by its own name (``shown_data_name``) and what
    named it, with the count and digest of the files the layer the call used
    was loaded from. A declared corpus the call recorded no load of says so
    (``NOT_LOADED_STATEMENT``). Without ``loaded`` (a caller that records no
    load), the corpus the call's argument names, else the one the tool reads
    by default (``Requirement.corpus``), is read as it is now. ``environ`` is
    the environment of the process that runs the tool. Empty for a tool that
    declares no data. Read by the wrapper every tool call goes through, the
    same for every tool.
    """
    rows: list[dict[str, Any]] = []
    for req in needs.requires if needs is not None else ():
        if req.kind != "data":
            continue
        noted = loaded.get(req) if loaded is not None else None
        if noted is not None:
            rows.append(dict(noted))
            continue
        given = arguments.get(req.argument) if req.argument else None
        try:
            path, named_by = req.corpus(given, environ, settings)
            if loaded is not None:
                facts = {**req._data_head(named_by), "digest_statement": NOT_LOADED_STATEMENT}
            else:
                facts = req.data_facts(str(path), named_by)
            row = {"name": shown_data_name(path), **facts}
        except Exception as exc:  # noqa: BLE001 — a fact unread is recorded, never raised
            row = {"name": req.name, "statement": type(exc).__name__}
        row.pop("digest_of", None)
        rows.append(row)
    return rows


def stamped(answer: Any, rows: list[dict[str, Any]]) -> Any:
    """``answer`` with ``rows`` (``data_used``) first, where it is a dict and there are any.

    First, as a carved file's ``read_path`` is: an answer wider than the
    caller's output bound is cut from the end before anything records it.
    """
    if not rows or not isinstance(answer, dict):
        return answer
    return {DATA_USED_KEY: rows, **{k: v for k, v in answer.items() if k != DATA_USED_KEY}}


def remedy_for(tool: ToolNeeds, missing: list[Requirement]) -> str:
    """The remedy for ``missing``: the tool's for what is not data, each data path's own."""
    remedies = []
    other = {req.kind for req in missing if req.kind != "data"}
    if other or not missing:
        code = NOT_CONFIGURED if other == {"env"} else MISSING_DEPENDENCY
        remedies.append(tool.remediation or REMEDIATIONS[code])
    remedies.extend(req.remedy for req in missing if req.kind == "data")
    return "; ".join(dict.fromkeys(remedies))


@dataclass
class Unavailable:
    """One tool a manifest marks unavailable, as a degradation reason reads it."""

    server: str
    tool: str
    reason: str
    remediation: str | None = None
    without: str = ""
    # The manifest's code for why (``not_configured``, ``missing_dependency``),
    # ``None`` for a manifest written before cells carried one.
    code: str | None = None
    # What the tool needs, by name, as its cell lists it (``optional_dependency``).
    requires: tuple[str, ...] = ()

    @property
    def degradation_reason(self) -> str:
        """``server.<key>.<tool>_unavailable(<reason>)``, with what it still does and the remedy.

        A tool that answers less is not a tool that does not answer, and the
        difference is what a reader of the degraded block needs: ``apk_info``
        without androguard still reads the zip, and saying only that it is
        unavailable overstates what was lost.
        """
        text = f"server.{self.server}.{self.tool}_unavailable({self.reason})"
        if self.without:
            text += f"; still answers {self.without}"
        if self.remediation:
            text += f"; {self.remediation}"
        return text


# What a manifest's ``requirements`` may hold once read (``reported_requirements``):
# the keys ``requirement_facts`` and the CLI sidecars write, each of one type,
# a string cut at ``REQUIREMENT_TEXT_CHARS``, at most ``REQUIREMENT_ROWS`` rows
# and ``REQUIREMENT_LIST_ITEMS`` items in a row's list. A manifest comes from
# any server a run attaches, a third party's among them, and what it says is
# stored with every run summary.
_REQUIREMENT_TEXT_KEYS = (
    "kind",
    "name",
    "distribution",
    "version",
    "pinned",
    "named_by",
    "pattern",
    "sha256",
    "digest_statement",
    "digest_of",
    "statement",
)
_REQUIREMENT_COUNT_KEYS = ("files", "bytes")
_REQUIREMENT_LIST_KEYS = ("tools", "exclude")
REQUIREMENT_TEXT_CHARS = 200
REQUIREMENT_ROWS = 256
REQUIREMENT_LIST_ITEMS = 256
# The key a row or the list's last row says what was cut under.
REQUIREMENT_CUT_KEY = "cut"


def _clipped(value: Any) -> tuple[str, bool]:
    text = str(value)
    return text[:REQUIREMENT_TEXT_CHARS], len(text) > REQUIREMENT_TEXT_CHARS


def _requirement_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """One row reduced to the known keys, typed and capped; what was cut is said."""
    out: dict[str, Any] = {}
    cut: list[str] = []
    for key in _REQUIREMENT_TEXT_KEYS:
        value = row.get(key)
        if value is None or isinstance(value, dict | list):
            continue
        out[key], clipped = _clipped(value)
        if clipped:
            cut.append(f"{key} cut at {REQUIREMENT_TEXT_CHARS} characters")
    for key in _REQUIREMENT_COUNT_KEYS:
        value = row.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            continue
        out[key] = value
    for key in _REQUIREMENT_LIST_KEYS:
        value = row.get(key)
        if not isinstance(value, list):
            continue
        items = [_clipped(item)[0] for item in value if isinstance(item, str | int | float)]
        if len(items) > REQUIREMENT_LIST_ITEMS:
            cut.append(f"{key} cut at {REQUIREMENT_LIST_ITEMS} of {len(items)}")
        out[key] = items[:REQUIREMENT_LIST_ITEMS]
    dropped = sorted(
        str(key)[:40]
        for key in row
        if key not in (*_REQUIREMENT_TEXT_KEYS, *_REQUIREMENT_COUNT_KEYS, *_REQUIREMENT_LIST_KEYS)
    )
    if dropped:
        cut.append(f"{len(dropped)} unknown key(s) left out")
    if cut:
        out[REQUIREMENT_CUT_KEY] = "; ".join(cut)
    return out


def reported_requirements(held: Any) -> list[dict[str, Any]] | None:
    """A manifest's ``requirements`` as a run keeps them: known keys, typed, capped.

    ``None`` when the manifest carries no list. Rows that are not objects are
    left out; beyond ``REQUIREMENT_ROWS`` the rest are, and the last row kept
    says how many were (``cut``), as a row says what of it was cut.
    """
    if not isinstance(held, list):
        return None
    rows = [_requirement_row(row) for row in held if isinstance(row, Mapping)]
    if len(rows) > REQUIREMENT_ROWS:
        dropped = len(rows) - REQUIREMENT_ROWS
        rows = rows[:REQUIREMENT_ROWS]
        said = rows[-1].get(REQUIREMENT_CUT_KEY)
        note = f"{dropped} more row(s) left out after this one"
        rows[-1][REQUIREMENT_CUT_KEY] = f"{said}; {note}" if said else note
    return rows


@dataclass
class ServerCapabilities:
    """A manifest as the registry keeps it, indexed by tool."""

    server: str
    version: str = "unknown"
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    # What the server's declared requirements are on its host
    # (``requirement_facts``); ``None`` for a manifest that carries none.
    requirements: list[dict[str, Any]] | None = None

    @classmethod
    def from_payload(cls, server: str, payload: Any) -> ServerCapabilities | None:
        """Read a ``capabilities()`` answer; ``None`` for anything that is not one."""
        if isinstance(payload, str):
            import json

            try:
                payload = json.loads(payload)
            except (ValueError, TypeError):
                return None
        if not isinstance(payload, dict) or not isinstance(payload.get("tools"), list):
            return None
        tools: dict[str, dict[str, Any]] = {}
        for cell in payload["tools"]:
            if isinstance(cell, dict) and cell.get("name"):
                tools[str(cell["name"])] = dict(cell)
        requirements = reported_requirements(payload.get("requirements"))
        return cls(
            server=str(payload.get("server") or server),
            version=str(payload.get("version") or "unknown"),
            tools=tools,
            requirements=requirements,
        )

    def unavailable(self, names: list[str] | None = None) -> list[Unavailable]:
        """The tools marked unavailable, all of them or only ``names``."""
        wanted = set(names) if names is not None else set(self.tools)
        out: list[Unavailable] = []
        for name in sorted(wanted):
            cell = self.tools.get(name)
            if cell is None or cell.get("available", True):
                continue
            out.append(
                Unavailable(
                    server=self.server,
                    tool=name,
                    reason=str(cell.get("reason") or "unavailable"),
                    remediation=(str(cell["remediation"]) if cell.get("remediation") else None),
                    without=str(cell.get("without") or ""),
                    code=str(cell["code"]) if cell.get("code") else None,
                    requires=tuple(
                        name.strip()
                        for name in str(cell.get("optional_dependency") or "").split(",")
                        if name.strip()
                    ),
                )
            )
        return out

    def unusable(self) -> frozenset[str]:
        """The tools this host cannot run, and which answer nothing without it.

        A tool the model is offered is a tool the model will spend a step on.
        One run was handed four of them, got four failures back, and the
        degradation that explained why went to the log and the run summary
        rather than to the agent holding the tool. So these are kept off the
        list the model is given — they stay in the manifest, with the reason
        and the remedy, which is what an operator needs and what the degraded
        block prints.

        A tool that declares what it still answers is not one of them:
        ``archive_list`` without py7zr still lists a zip, and withholding it
        would cost a whole archive analysis to save a 7z failure.
        """
        return frozenset(
            name
            for name, cell in self.tools.items()
            if not cell.get("available", True) and not cell.get("without")
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "server": self.server,
            "version": self.version,
            "tools": [dict(cell) for cell in self.tools.values()],
        }
        if self.requirements is not None:
            out["requirements"] = [dict(row) for row in self.requirements]
        return out
