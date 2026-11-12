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
(``analysis.run_environment``).
"""

from __future__ import annotations

import functools
import hashlib
import importlib
import importlib.metadata
import importlib.util
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from malspark.tools.errors import MISSING_DEPENDENCY, NOT_CONFIGURED, REMEDIATIONS

# The tool a server answers this with. Named once, so the registry and the
# probe look for the same thing every sidecar offers.
CAPABILITIES_TOOL = "capabilities"


# What reading what a requirement is at may cost (``Requirement.facts``). A
# probe of a binary's version is given this long when its declaration names no
# wall clock, and never more than the ceiling: it runs once per process, when
# the manifest is built, and a server's start waits for it.
VERSION_PROBE_TIMEOUT_S = 5.0
VERSION_PROBE_MAX_TIMEOUT_S = 30.0
# How much of a probe's output is read for the version.
_PROBE_OUTPUT_CHARS = 64 * 1024
# The most a data path's digest reads: beyond either bound its files are
# counted and no digest is computed, so a corpus copied in whole by mistake
# costs a server's start a count, not a read of it.
DATA_DIGEST_MAX_FILES = 20_000
DATA_DIGEST_MAX_BYTES = 64 * 1024 * 1024
# What a fact that was not read is recorded as. ``NOT_REPORTED`` is the one
# phrase every part of a run's environment record says it with
# (``analysis.run_environment``, ``llm.sent_request``), a reason following it
# after a colon where one is known.
NOT_INSTALLED = "not installed"
NOT_REPORTED = "not reported"


@dataclass(frozen=True)
class VersionProbe:
    """How a binary says its own version, for a tool that declares it.

    ``command`` is run as given, never through a shell: its first word is
    looked up on ``PATH``. The version is the first match of ``pattern`` in
    what the command writes (its standard output, then its standard error):
    the pattern's first group when it has one, else the whole match.
    ``timeout_s`` bounds the run (``VERSION_PROBE_TIMEOUT_S`` when ``None``,
    never more than ``VERSION_PROBE_MAX_TIMEOUT_S``).
    """

    command: tuple[str, ...]
    pattern: str = r"\d+(?:\.\d+)+"
    timeout_s: float | None = None

    def read(self) -> str:
        """The version the command reports, else ``"not reported: <reason>"``. Never raises."""
        return _probe_version(self.command, self.pattern, self.timeout_s)


@functools.lru_cache(maxsize=64)
def _probe_version(command: tuple[str, ...], pattern: str, timeout_s: float | None) -> str:
    # Once per process for each probe: a version does not change while a
    # server runs, and the probe is a process start.
    if not command or not str(command[0]).strip():
        return f"{NOT_REPORTED}: the probe names no command"
    word = str(command[0])
    found = shutil.which(word)
    if found is None:
        return f"{NOT_REPORTED}: {Path(word).name} is not on PATH"
    wall = min(
        VERSION_PROBE_TIMEOUT_S if timeout_s is None else max(float(timeout_s), 0.1),
        VERSION_PROBE_MAX_TIMEOUT_S,
    )
    try:
        done = subprocess.run(  # noqa: S603 — a declared argument list, no shell
            [found, *(str(arg) for arg in command[1:])],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            errors="replace",
            timeout=wall,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"{NOT_REPORTED}: it did not answer within {wall:g} s"
    except Exception as exc:  # noqa: BLE001 — a version is a label, never a failure
        # The type alone: an exception's words may carry the host's paths.
        return f"{NOT_REPORTED}: it could not be run ({type(exc).__name__})"
    if done.returncode != 0:
        return f"{NOT_REPORTED}: it exited with status {done.returncode}"
    try:
        compiled = re.compile(pattern)
    except re.error:
        return f"{NOT_REPORTED}: the probe's pattern is not a regular expression"
    for said in (done.stdout, done.stderr):
        match = compiled.search((said or "")[:_PROBE_OUTPUT_CHARS])
        if match:
            value = match.group(1) if compiled.groups else match.group(0)
            if value and value.strip():
                return value.strip()[:120]
    return f"{NOT_REPORTED}: its output named no version"


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


def data_files(target: Path, pattern: str) -> list[tuple[str, Path]]:
    """The files that make up the data at ``target``, as ``(name, path)`` in name order.

    A file is itself, under its own name; a directory is every file under it
    matching ``pattern``, each named by its path relative to the directory.
    Empty when nothing is there.
    """
    if target.is_file():
        return [(target.name, target)]
    if not target.is_dir():
        return []
    held = [
        (entry.relative_to(target).as_posix(), entry)
        for entry in target.rglob(pattern)
        if entry.is_file()
    ]
    return sorted(held, key=lambda item: item[0])


@functools.lru_cache(maxsize=32)
def _data_digest(target: str, pattern: str) -> dict[str, Any]:
    # Once per process for each path: a server's corpus is what it loaded at
    # start, and the worker's does not change under a run.
    try:
        files = data_files(Path(target), pattern)
    except OSError as exc:
        return {"files": 0, "digest_statement": f"not read ({type(exc).__name__})"}
    out: dict[str, Any] = {"files": len(files)}
    if not files:
        out["digest_statement"] = "no file is there"
        return out
    try:
        total = sum(path.stat().st_size for _name, path in files)
    except OSError as exc:
        out["digest_statement"] = f"digest not computed ({type(exc).__name__})"
        return out
    out["bytes"] = total
    if len(files) > DATA_DIGEST_MAX_FILES or total > DATA_DIGEST_MAX_BYTES:
        out["digest_statement"] = (
            f"digest not computed: over the bound ({DATA_DIGEST_MAX_FILES} files, "
            f"{DATA_DIGEST_MAX_BYTES} bytes)"
        )
        return out
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
        return out
    out["sha256"] = digest.hexdigest()
    return out


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

    def facts(
        self, environ: Mapping[str, str] | None = None, settings: Any = None
    ) -> dict[str, Any] | None:
        """What this requirement is on this host, for the record of a run. Never raises.

        A module: the distribution that provides it and its installed version
        (``module_version``). Data: the path's files matching ``pattern``
        counted and one SHA-256 over them, name then content in name order,
        within ``DATA_DIGEST_MAX_FILES`` and ``DATA_DIGEST_MAX_BYTES``; the
        path is read as ``installed`` reads it and named only by what named
        it. A binary: the version its declared probe reads, else
        ``"not reported"``. A setting is no install and has no facts
        (``None``): its value is the operator's, not the host's. Each is read
        once per process.
        """
        try:
            out: dict[str, Any] = {"kind": self.kind, "name": self.name}
            if self.kind == "module":
                out.update(module_version(self.name))
            elif self.kind == "binary":
                out["version"] = (
                    self.version_probe.read() if self.version_probe is not None else NOT_REPORTED
                )
            elif self.kind == "data":
                value, named_by = self._data_path(environ, settings)
                out["named_by"] = named_by
                out["pattern"] = self.pattern
                if not value.strip():
                    out.update({"files": 0, "digest_statement": f"{named_by} names no path"})
                else:
                    target = Path(value)
                    target = target if target.is_absolute() else _data_root() / target
                    out.update(_data_digest(str(target), self.pattern))
            else:
                return None
            return out
        except Exception as exc:  # noqa: BLE001 — a fact unread is recorded, never raised
            return {"kind": self.kind, "name": self.name, "statement": type(exc).__name__}

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
) -> Requirement:
    """A tool that shells out to an executable.

    Found on ``PATH`` by default. ``locate`` is for an executable looked for in
    more places than that, or checked for more than presence — the analysis
    server's ``floss`` looks at a configured path and a user tools directory
    and runs only the pinned build — and answers the reason it is absent.
    ``version_probe`` is how the executable says its version, for a run's
    record of what it ran (``Requirement.facts``); without one its version is
    not reported.
    """
    return Requirement("binary", name, locate, version_probe=version_probe)


def env(name: str) -> Requirement:
    return Requirement("env", name)


def data(
    default: str,
    *,
    setting: str = "",
    override: str = "",
    pattern: str = "*",
    fetched: bool = True,
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
    default that version control keeps (``Requirement.remedy``).
    """
    return Requirement(
        "data", default, setting=setting, override=override, pattern=pattern, fetched=fetched
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
) -> list[dict[str, Any]]:
    """What each requirement of ``tools`` is on this host, once each, with the tools needing it.

    One row per requirement (``Requirement.facts``), in the order the tools
    first declare them, each listing the tools that declare it. A setting is
    not listed. Never raises.
    """
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for tool in tools:
        for req in tool.requires:
            key = (req.kind, req.name)
            if key not in rows:
                facts = req.facts(environ, settings)
                if facts is None:
                    continue
                rows[key] = {**facts, "tools": []}
            if tool.name not in rows[key]["tools"]:
                rows[key]["tools"].append(tool.name)
    return list(rows.values())


def manifest(server: str, tools: list[ToolNeeds], *, version: str | None = None) -> dict[str, Any]:
    """The capability manifest for ``server``, probed now on this host.

    ``requirements`` is what each declared module, binary and data path is
    here (``requirement_facts``): built with the manifest, which a server
    builds once when it starts, so no tool call pays for it.
    """
    return {
        "server": server,
        "version": version if version is not None else package_version(),
        "tools": [_cell(tool) for tool in tools],
        "requirements": requirement_facts(tools),
    }


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
        held = payload.get("requirements")
        requirements = (
            [dict(row) for row in held if isinstance(row, dict)] if isinstance(held, list) else None
        )
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
