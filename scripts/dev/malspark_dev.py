#!/usr/bin/env python3
"""Set up Malspark and drive its compose stack, the same way on Windows, macOS and Linux.

Standard library only, so a host needs no dependency of the project to install
the stack: uv provides the interpreter and nothing else.

    uv run --no-project python scripts/dev/malspark_dev.py <command>

    setup [--dev]          fetch the pinned third-party trees and data; --dev also
                           syncs the host environment and installs pre-commit
    external [NAME ...]    the pinned trees (ghidra-mcp; ik_llama.cpp only when
                           named), the Sigma rules and capa's data
    env init [--force]     docker/.env and bootstrap.env from their examples, with
                           generated secrets; an existing file is left as it is
    doctor                 what this host has and lacks for the stack (informative)
    up / down / logs       the development stack (live frontend and worker)
    docker-up / docker-down / docker-logs / docker-build
                           the production stack
    migrate                the API's Alembic migrations against DATABASE_URL
    create-admin EMAIL     the first admin account, in the running stack
    fe-rebuild             rebuild and restart the production frontend
    worker-restart         restart the production worker

The Makefile's targets of the same names call this file, so ``make`` keeps
working where make is installed. ``--dry-run`` on a stack command prints the
commands instead of running them; no secret value is ever printed.

On a host that is not Linux, samples and uploads are on named volumes
(docker/docker-compose.named-data.yml) and the development stack's reloads
poll (docker/docker-compose.dev-polling.yml). MALSPARK_DATA_VOLUMES=1 (or
true, yes, on) puts them on named volumes on any host, MALSPARK_DATA_VOLUMES=0
(or false, no, off) keeps them under data/ on any host.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import platform
import re
import secrets
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

if sys.version_info < (3, 11):  # noqa: UP036 - read by an interpreter older than the project's
    sys.exit("malspark_dev.py needs Python 3.11 or later (uv run --python 3.11 ...)")

REPO_ROOT = Path(__file__).resolve().parents[2]

# ── Environment files ────────────────────────────────────────────────────────

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DOUBLE_QUOTED_ESCAPE = re.compile(r'\\(["\\$`])')


def _env_value(text: str) -> str:
    """One value as a shell assignment or compose's .env reads it, without its quotes."""
    if text[:1] == "'":
        end = text.find("'", 1)
        return text[1:end] if end != -1 else text[1:]
    if text[:1] == '"':
        # The first quote no backslash escapes closes it.
        closing = re.search(r'(?<!\\)(?:\\\\)*"', text[1:])
        inner = text[1 : closing.end()] if closing else text[1:]
        return _DOUBLE_QUOTED_ESCAPE.sub(r"\1", inner)
    # Unquoted, a # after white space starts a comment, as in the shell.
    comment = re.search(r"\s#", text)
    return (text[: comment.start()] if comment else text).strip()


def parse_env(text: str) -> dict[str, str]:
    """``KEY=value`` lines of an env file: CRLF, quotes, comments and ``export`` tolerated.

    A later line wins over an earlier one, as sourcing the file does. A line
    that is no assignment is skipped. No ``$VAR`` in a value is expanded.
    """
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[len("export") :].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and _NAME.fullmatch(key):
            values[key] = _env_value(value.strip())
    return values


def _read_text(path: Path, required: bool = False) -> str | None:
    """The file's text, None when it is not there; a file that cannot be read stops the run.

    A ``required`` file that is not there raises the FileNotFoundError a plain
    read gives.

    One stat says what the path is, and only a regular file is opened (a FIFO
    would block the read). The one line names the path and what is wrong, never
    any of the content.
    """
    try:
        mode = os.stat(path).st_mode
    except (FileNotFoundError, NotADirectoryError):
        if required:
            raise
        return None
    except OSError:
        raise _fail(f"  FAIL     {path} cannot be read") from None
    if stat.S_ISDIR(mode):
        raise _fail(f"  FAIL     {path} is a directory, not a file")
    if not stat.S_ISREG(mode):
        raise _fail(f"  FAIL     {path} is not a regular file")
    try:
        return path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        if required:
            raise
        return None
    except UnicodeDecodeError:
        problem = "is not UTF-8 text"
    except OSError:
        problem = "cannot be read"
    raise _fail(f"  FAIL     {path} {problem}")


ABSENT, FILE, DIRECTORY, OTHER, DENIED = "absent", "file", "directory", "other", "denied"


def _examine(path: Path) -> str:
    """What stands at ``path``, and never raises: ABSENT (nothing there, a dangling link
    too), FILE, DIRECTORY, OTHER (a FIFO, a socket, a device) or DENIED (it cannot be
    examined: a folder on the way is not searchable, a link loops, the file system fails).
    """
    try:
        mode = os.stat(path).st_mode
    except (FileNotFoundError, NotADirectoryError):
        return ABSENT
    except OSError:
        return DENIED
    if stat.S_ISREG(mode):
        return FILE
    return DIRECTORY if stat.S_ISDIR(mode) else OTHER


def _is(path: Path, *kinds: str) -> bool:
    """Whether ``path`` is one of ``kinds``; a path that cannot be examined stops the run.

    The one line names the path, as the reader's do: a command that decides on
    a file or a folder never takes "cannot tell" for "not there".
    """
    kind = _examine(path)
    if kind == DENIED:
        raise _fail(f"  FAIL     {path} cannot be examined")
    return kind in kinds


def _is_file(path: Path) -> bool:
    return _is(path, FILE)


def _is_dir(path: Path) -> bool:
    return _is(path, DIRECTORY)


def _present(path: Path) -> bool:
    """Whether anything stands at ``path``, whatever it is."""
    return _is(path, FILE, DIRECTORY, OTHER)


def _matching(directory: Path, pattern: str) -> list[Path]:
    """The directory's entries matching ``pattern``, sorted; a listing that fails stops the run."""
    try:
        return sorted(directory.glob(pattern))
    except OSError:
        raise _fail(f"  FAIL     {directory} cannot be listed") from None


def read_env(path: Path) -> dict[str, str]:
    """The file's assignments, or none when it is not there."""
    return parse_env(_read_text(path) or "")


# ── The stack's compose commands ─────────────────────────────────────────────

SHIPPED_COMPOSE = ("docker/docker-compose.yml", "docker/docker-compose.dev.yml")
IMAGE_DEFAULT_ID = "10001"

# Samples and uploads go on named volumes on a host that is not Linux, where a
# bind mount from the host's file system carries no Linux owner; Linux keeps
# the bind mount. MALSPARK_DATA_VOLUMES set to one of DATA_VOLUMES_ON adds the
# overlay on any host and one of DATA_VOLUMES_OFF leaves it out on any host: a
# worker run on the host writes its sample copies to data/samples, where only
# a bind mount shows them to the sidecars.
NAMED_DATA_OVERLAY = "docker/docker-compose.named-data.yml"
DATA_VOLUMES_ON = ("1", "true", "yes", "on")
DATA_VOLUMES_OFF = ("0", "false", "no", "off")
# The volumes the overlay declares, named under the compose project as compose
# names them (<project>_samples), and the project the shipped file names.
DATA_VOLUMES = ("samples", "uploads")
COMPOSE_PROJECT = "malspark"
# The development stack's reloads poll on a host that is not Linux, whose
# shared files raise no change notification in the containers.
DEV_POLLING_OVERLAY = "docker/docker-compose.dev-polling.yml"
# Where the named volumes mount under the read-only ../data mount. Docker
# cannot create a mount point there, so each must exist on the host.
DATA_MOUNT_POINTS = ("data/samples", "data/uploads")

CORPORA = ("data/sigma_rules", "data/capa-rules", "data/capa-signatures")


@dataclass(frozen=True)
class Step:
    """One command: its arguments, where it runs, and the variables it is given."""

    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str] = field(default_factory=dict)


def compose_ids(
    environ: Mapping[str, str],
    docker_env: Mapping[str, str],
    getuid: Callable[[], int] | None,
    getgid: Callable[[], int] | None,
) -> dict[str, str]:
    """MALSPARK_UID and MALSPARK_GID for a command that starts the stack.

    The environment's value first, then docker/.env's (its digits only), then
    the invoking user's ids (the user behind sudo, not root); an id that comes
    out 0 is the image's own 10001. A host without user ids (Windows) sets
    neither, and the image's 10001 applies.
    """
    if getuid is None or getgid is None:
        return {}

    def own(sudo: str, real: Callable[[], int]) -> str:
        value = environ.get(sudo) or str(real())
        return IMAGE_DEFAULT_ID if value == "0" else value

    ids = {}
    for name, sudo, real in (
        ("MALSPARK_UID", "SUDO_UID", getuid),
        ("MALSPARK_GID", "SUDO_GID", getgid),
    ):
        from_file = re.sub(r"\D", "", docker_env.get(name, ""))
        ids[name] = environ.get(name) or from_file or own(sudo, real)
    return ids


def _linux(system: str | None) -> bool:
    return (system or platform.system()) == "Linux"


def data_volumes_choice(environ: Mapping[str, str]) -> bool | None:
    """MALSPARK_DATA_VOLUMES as on, off or neither (any case); neither leaves it to the host."""
    value = environ.get("MALSPARK_DATA_VOLUMES", "").strip().lower()
    if value in DATA_VOLUMES_ON:
        return True
    if value in DATA_VOLUMES_OFF:
        return False
    return None


def warn_data_volumes_value(environ: Mapping[str, str]) -> None:
    """A value of MALSPARK_DATA_VOLUMES that is neither on nor off is named, not ignored."""
    value = environ.get("MALSPARK_DATA_VOLUMES", "").strip()
    if value and data_volumes_choice(environ) is None:
        print(
            f"warning: MALSPARK_DATA_VOLUMES={value} is not read; it takes"
            f" {', '.join(DATA_VOLUMES_ON)} (named volumes) or {', '.join(DATA_VOLUMES_OFF)}"
            " (bind mounts), so this host's own choice stands",
            file=sys.stderr,
        )


def host_overlays(
    root: Path, system: str | None = None, environ: Mapping[str, str] | None = None
) -> list[str]:
    """The compose files this host adds after the shipped ones (see NAMED_DATA_OVERLAY)."""
    choice = data_volumes_choice(environ or {})
    wanted = not _linux(system) if choice is None else choice
    if not wanted or not _is_file(root / NAMED_DATA_OVERLAY):
        return []
    return [NAMED_DATA_OVERLAY]


def data_volumes_note(
    root: Path, environ: Mapping[str, str], docker_env: Mapping[str, str] | None = None
) -> str:
    """Where samples and uploads are, when the named-data overlay puts them on volumes."""
    project = (
        environ.get("COMPOSE_PROJECT_NAME")
        or (read_env(root / "docker" / ".env") if docker_env is None else docker_env).get(
            "COMPOSE_PROJECT_NAME"
        )
        or COMPOSE_PROJECT
    )
    names = " and ".join(f"{project}_{volume}" for volume in DATA_VOLUMES)
    return (
        f"samples and uploads are on the named volumes {names}: the containers do not see"
        " a file put in data/samples or data/uploads, the tracked fixtures apart for the"
        " API and the worker (MALSPARK_DATA_VOLUMES=0 keeps the bind mounts)"
    )


def dev_overlays(root: Path, system: str | None = None) -> list[str]:
    """The files the development stack adds on this host (see DEV_POLLING_OVERLAY)."""
    if _linux(system) or not _is_file(root / DEV_POLLING_OVERLAY):
        return []
    return [DEV_POLLING_OVERLAY]


def make_mount_points(root: Path) -> None:
    """Each named data volume's mount point under data/ (see DATA_MOUNT_POINTS).

    Something other than a directory standing at one stops the start here,
    named, before Docker fails on it.
    """
    for path in DATA_MOUNT_POINTS:
        try:
            (root / path).mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise _fail(
                f"  FAIL     {path} cannot be the mount point of a named volume: {error};"
                " move what stands there and run this again"
            ) from None


def split_extra_files(value: str, windows: bool | None = None) -> list[str]:
    """COMPOSE_FILE_EXTRA's files, one ``-f`` each.

    On Windows (this host's, unless ``windows`` says) the value is split on
    ``;``, as compose splits its own COMPOSE_FILE there, so a path may hold a
    space; elsewhere on white space.
    """
    if windows is None:
        windows = os.name == "nt"
    parts = value.split(";") if windows else value.split()
    return [part.strip() for part in parts if part.strip()]


def _production_files(root: Path, system: str | None, environ: Mapping[str, str]) -> list[str]:
    """The production stack's ``-f`` arguments, run from docker/.

    None at all, so compose reads docker-compose.override.yml on its own; with
    a host overlay, the files compose would have read are named before it.
    """
    overlays = host_overlays(root, system, environ)
    if not overlays:
        return []
    files = ["docker-compose.yml"]
    if _is_file(root / "docker" / "docker-compose.override.yml"):
        files.append("docker-compose.override.yml")
    files += [str(PurePosixPath(path).relative_to("docker")) for path in overlays]
    return [arg for path in files for arg in ("-f", path)]


def _dev_files(
    root: Path, extra: Sequence[str], system: str | None, environ: Mapping[str, str]
) -> list[str]:
    """The development stack's ``-f`` arguments, run from the repository root.

    COMPOSE_FILE_EXTRA's files come last, each one more ``-f``, so they win
    over the shipped file and the overlays.
    """
    files = [
        *SHIPPED_COMPOSE,
        *host_overlays(root, system, environ),
        *dev_overlays(root, system),
        *extra,
    ]
    return [arg for path in files for arg in ("-f", path)]


@dataclass(frozen=True)
class Context:
    """What a stack command is built from: the checkout, the environment, the host."""

    root: Path
    environ: Mapping[str, str]
    extra_files: tuple[str, ...] = ()
    system: str | None = None
    getuid: Callable[[], int] | None = None
    getgid: Callable[[], int] | None = None

    @classmethod
    def here(cls, root: Path = REPO_ROOT, extra: Sequence[str] = ()) -> Context:
        environ = dict(os.environ)
        return cls(
            root=root,
            environ=environ,
            extra_files=(*split_extra_files(environ.get("COMPOSE_FILE_EXTRA", "")), *extra),
            getuid=getattr(os, "getuid", None),
            getgid=getattr(os, "getgid", None),
        )

    def bootstrap(self) -> dict[str, str]:
        """bootstrap.env over the environment, as ``set -a; . ./bootstrap.env`` leaves it."""
        return read_env(self.root / "bootstrap.env")

    def ids(self, environ: Mapping[str, str]) -> dict[str, str]:
        docker_env = read_env(self.root / "docker" / ".env")
        return compose_ids(environ, docker_env, self.getuid, self.getgid)


def _with(ctx: Context, *, bootstrap: bool = False, ids: bool = False) -> dict[str, str]:
    """The variables a command is given beyond the environment it starts from."""
    added: dict[str, str] = {}
    if bootstrap:
        added.update(ctx.bootstrap())
    if ids:
        added.update(ctx.ids({**ctx.environ, **added}))
    return added


def stack_plan(command: str, ctx: Context, email: str | None = None) -> list[Step]:
    """The commands one stack command runs, in order; each runs only if the one before passed."""
    docker_dir = ctx.root / "docker"
    prod = ["docker", "compose", *_production_files(ctx.root, ctx.system, ctx.environ)]
    dev = ["docker", "compose", *_dev_files(ctx.root, ctx.extra_files, ctx.system, ctx.environ)]
    root = ctx.root
    plans: dict[str, Callable[[], list[Step]]] = {
        "docker-build": lambda: [Step((*prod, "build"), docker_dir)],
        "docker-up": lambda: [Step((*prod, "up", "-d"), docker_dir, _with(ctx, ids=True))],
        # `--profile *` so a down also stops the optional services (ghidra,
        # qdrant) whatever COMPOSE_PROFILES says now.
        "docker-down": lambda: [Step((*prod, "--profile", "*", "down"), docker_dir)],
        "docker-logs": lambda: [Step((*prod, "logs", "-f"), docker_dir)],
        "up": lambda: [Step((*dev, "up", "-d"), root, _with(ctx, bootstrap=True, ids=True))],
        "down": lambda: [Step((*dev, "--profile", "*", "down"), root, _with(ctx, bootstrap=True))],
        "logs": lambda: [Step((*dev, "logs", "-f"), root, _with(ctx, bootstrap=True))],
        "migrate": lambda: [
            Step(
                ("uv", "run", "--directory", "apps/api", "alembic", "upgrade", "head"),
                root,
                _with(ctx, bootstrap=True),
            )
        ],
        # exec reaches the service by the compose project's name, whichever
        # files started it. `--` keeps an address that starts with `-` an argument.
        "create-admin": lambda: [
            Step(
                (*prod, "exec", "backend-api", "malspark", "create-admin", "--", email or ""),
                docker_dir,
            )
        ],
        "fe-rebuild": lambda: [
            Step((*prod, "build", "frontend"), docker_dir, _with(ctx, ids=True)),
            Step((*prod, "up", "-d", "--no-deps", "frontend"), docker_dir, _with(ctx, ids=True)),
        ],
        "worker-restart": lambda: [Step(("docker", "restart", "malspark-worker"), root)],
    }
    return plans[command]()


# Shown with their values in a dry run; every other variable is named only.
_SHOWN = frozenset({"MALSPARK_UID", "MALSPARK_GID", "COMPOSE_PROFILES"})


def describe(step: Step, root: Path) -> str:
    """A step as one line, every variable it adds named and no secret value shown."""
    try:
        where = step.cwd.relative_to(root).as_posix() or "."
    except ValueError:
        where = str(step.cwd)
    names = " ".join(
        f"{key}={value}" if key in _SHOWN else key for key, value in sorted(step.env.items())
    )
    env = f" [{names}]" if names else ""
    return f"({where}){env} {shlex.join(step.argv)}"


def run_steps(steps: Sequence[Step], environ: Mapping[str, str], root: Path) -> int:
    """Run each step in turn; the first that fails ends the run with its status."""
    for step in steps:
        program = shutil.which(step.argv[0], path=environ.get("PATH"))
        if program is None:
            print(
                f"  FAIL     {step.argv[0]} is not on PATH{_install_hint(step.argv[0])}",
                file=sys.stderr,
            )
            return 127
        try:
            done = subprocess.run(
                [program, *step.argv[1:]],
                cwd=step.cwd,
                env={**environ, **step.env},
                check=False,
            )
        except KeyboardInterrupt:
            return 130
        if done.returncode != 0:
            return done.returncode
    return 0


def _install_hint(program: str) -> str:
    if program == "docker":
        return (
            ": install Docker Desktop (Windows, macOS) or Docker Engine with the compose"
            " plugin (Linux)"
        )
    if program == "uv":
        return ": install uv (https://docs.astral.sh/uv/)"
    return ""


def warn_missing_corpora(root: Path) -> None:
    """The stack mounts ./data over the image's copy, so a corpus missing here is missing there."""
    for corpus in CORPORA:
        if not _is_dir(root / corpus):
            print(
                f"warning: {corpus} is missing; the stack mounts ./data over the image's copy,"
                " so run the external command first (make external, or"
                " uv run --no-project python scripts/dev/malspark_dev.py external)",
                file=sys.stderr,
            )


# ── The pinned third-party trees ─────────────────────────────────────────────
#
# external/ is not in version control and is not ours to redistribute: each of
# these is someone else's project under its own licence. What the repository
# carries instead is the exact ref each was used at, so a clone can reconstruct
# the tree rather than receive a copy of it.
#
# CAPE is deliberately absent. It is somebody else's platform, wants a Linux
# host of its own with KVM and registered Windows guest images, and is a
# deployment rather than a dependency. This project talks to one over its REST
# API; it does not install, build or package it.
#
# A pinned tag that does not build or start as released carries a patch,
# scripts/dev/patches/<name>-<ref>.patch, applied after the checkout. A tree that
# already carries it is left as it is; one where it neither applies nor is in
# place stops the fetch, since the image built from it would not be the one
# the pin describes. MALSPARK_EXTERNAL_DIR puts the trees somewhere other than
# external/.


@dataclass(frozen=True)
class Target:
    """A pinned tree: the ref is what the project was built and measured against."""

    name: str
    url: str
    ref: str
    # Fetched by a run that names no tree; otherwise only when named.
    default: bool = True


TARGETS: tuple[Target, ...] = (
    Target("ghidra-mcp", "https://github.com/bethington/ghidra-mcp.git", "v5.6.0"),
    # The commit the paper pins as the inference engine. Only a host that builds
    # the local model server needs it, so it is fetched when named.
    Target("ik_llama.cpp", "https://github.com/ikawrakow/ik_llama.cpp", "eb570eb9", default=False),
)

# The Sigma corpus is SigmaHQ's work, not ours, and it lands outside external/
# because the layer reads it from data/sigma_rules by default. It used to be
# committed here: 2,651 rule files by Florian Roth, Nasreddine Bencherchali,
# frack113 and the rest of SigmaHQ, carrying no licence and no attribution, in a
# repository that calls itself MIT. Their rules are under the Detection Rule
# License. Fetching beats vendoring for the same reason it does above.
SIGMA_URL = "https://github.com/SigmaHQ/sigma.git"
SIGMA_REF = "r2026-07-01"

# capa's rules and its library-identification signatures, for the flare-capa
# version uv.lock pins; the flare-capa wheel carries neither. They land where
# static.capa.rules_dir and static.capa.signatures_dir point by default, which
# is also what the compose stack mounts over the image's own copies. The rules
# are capa-rules' tag of that version, without its CI folder (.github), so a
# rule count equals what capa loads. The signatures are the sigs/ directory of
# flare-capa's own sdist on PyPI. Each archive is checked against the sha256
# recorded when it was pinned (the sdist's is uv.lock's own), and each
# directory keeps its licence file and a PINNED.txt line naming what it holds.
# Keep the three values in step with uv.lock and docker/Dockerfile.backend; a
# test holds them together. A directory that is already there is never
# touched: it is said to be the pinned version or not, and left as it is.
CAPA_VERSION = "9.4.0"
CAPA_RULES_SHA256 = "273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669"
CAPA_SDIST_SHA256 = "c4f421abac566e23657241e4ddc66119beb0caf5f082ee42d68b7c879ebb7fc6"


@dataclass(frozen=True)
class Capa:
    """capa's pinned version, its two archives and what each directory's PINNED.txt says."""

    version: str = CAPA_VERSION
    rules_sha256: str = CAPA_RULES_SHA256
    sdist_sha256: str = CAPA_SDIST_SHA256
    rules_url: str = (
        f"https://github.com/mandiant/capa-rules/archive/refs/tags/v{CAPA_VERSION}.tar.gz"
    )
    sdist_url: str = (
        "https://files.pythonhosted.org/packages/source/f/flare-capa/"
        f"flare_capa-{CAPA_VERSION}.tar.gz"
    )

    @property
    def rules_pin(self) -> str:
        return f"capa-rules v{self.version} sha256:{self.rules_sha256}"

    @property
    def signatures_pin(self) -> str:
        return f"flare-capa {self.version} sigs sha256:{self.sdist_sha256}"


@dataclass(frozen=True)
class Layout:
    """Where the fetched trees and corpora go."""

    root: Path
    external: Path

    @classmethod
    def of(cls, root: Path, environ: Mapping[str, str]) -> Layout:
        return cls(root, Path(environ.get("MALSPARK_EXTERNAL_DIR") or root / "external"))

    @property
    def patches(self) -> Path:
        return self.root / "scripts" / "dev" / "patches"

    @property
    def sigma(self) -> Path:
        return self.root / "data" / "sigma_rules"

    @property
    def capa_rules(self) -> Path:
        return self.root / "data" / "capa-rules"

    @property
    def capa_signatures(self) -> Path:
        return self.root / "data" / "capa-signatures"


class Stop(Exception):
    """The fetch stops here with this exit status; its reason is already said."""

    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


def _say(text: str) -> None:
    print(text, flush=True)


def _fail(text: str, status: int = 1) -> Stop:
    print(text, file=sys.stderr, flush=True)
    return Stop(status)


# A pinned tree is the same bytes on every host: no line ending is rewritten on
# checkout or patch, whatever the host's git config (Git for Windows turns
# core.autocrlf on), and a file whose attributes leave its ending to the host
# gets LF, the ending of the Linux images it is built into. Windows' 260-character
# path limit stops a checkout of a deep tree unless git is told to use long
# paths. Each setting holds for the command, not the tree.
GIT = (
    "git",
    "-c",
    "core.autocrlf=false",
    "-c",
    "core.eol=lf",
    *(("-c", "core.longpaths=true") if os.name == "nt" else ()),
)


def _git(dest: Path, *args: str, quiet: bool = False) -> subprocess.CompletedProcess[str]:
    """``git -C dest args``, its output read; quiet keeps its standard error off the terminal."""
    return subprocess.run(
        [*GIT, "-C", str(dest), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE if quiet else None,
        text=True,
        check=False,
    )


def _runs(*argv: str) -> int:
    """A git step's exit status, its messages on the terminal."""
    return subprocess.run(argv, check=False).returncode


def _passes(dest: Path, *args: str) -> bool:
    """Whether a git check passes, its messages kept off the terminal."""
    return _git(dest, *args, quiet=True).returncode == 0


def _git_ok(dest: Path, *args: str) -> None:
    """A git step that must pass; its own message is shown when it does not."""
    status = _runs(*GIT, "-C", str(dest), *args)
    if status != 0:
        raise Stop(status)


def _commit(dest: Path, ref: str) -> str:
    """The commit ``ref`` names in ``dest``, or empty when it names none there."""
    done = _git(dest, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", quiet=True)
    return done.stdout.strip() if done.returncode == 0 else ""


def _head(dest: Path, *flags: str) -> str:
    done = _git(dest, "rev-parse", *flags, "HEAD", quiet=True)
    if done.returncode != 0:
        print(done.stderr, end="", file=sys.stderr)
        raise Stop(done.returncode)
    return done.stdout.strip()


def _unpatch(layout: Layout, target: Target, dest: Path) -> None:
    """The patch this fetch applied for the earlier pin comes off first.

    So it does not stand in the checkout's way: only one whose ref (its file
    name, <name>-<ref>.patch) is the tree's HEAD and that comes off cleanly,
    and nothing else in the tree is touched.
    """
    prefix = f"{target.name}-"
    patches = _matching(layout.patches, "*.patch") if _is_dir(layout.patches) else []
    for applied in patches:
        if not applied.name.startswith(prefix) or not _is_file(applied):
            continue
        from_ref = applied.name[len(prefix) : -len(".patch")]
        at = _commit(dest, from_ref)
        if not at or at != _head(dest):
            continue
        reverse = ("apply", "--ignore-whitespace", "--reverse")
        if not _passes(dest, *reverse, "--check", str(applied)):
            continue
        _git_ok(dest, *reverse, str(applied))
        # The lines it puts back carry the patch's line endings; a file that
        # then differs from the checkout in those alone is the checkout's again.
        numstat = _git(dest, "apply", "--numstat", str(applied), quiet=True).stdout
        for line in numstat.splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3 and _passes(
                dest, "diff", "--quiet", "--ignore-cr-at-eol", "--", parts[2]
            ):
                _git_ok(dest, "checkout", "--quiet", "--", parts[2])
        _say(f"  unpatch  {target.name} {applied.name}")


def _fetch_tree(layout: Layout, target: Target) -> None:
    dest = layout.external / target.name
    name, ref = target.name, target.ref
    if _is_dir(dest / ".git"):
        have = _head(dest, "--short")
        # The pin is an exact ref: a tree merely ahead of it was not built or
        # measured against it, so only HEAD == ref counts as in place.
        want = _commit(dest, ref)
        if (want and _head(dest) == want) or have == ref[: len(have)]:
            _say(f"  ok       {name} at {have}")
        else:
            _say(f"  checkout {name} -> {ref}")
            _unpatch(layout, target, dest)
            _git_ok(dest, "fetch", "--quiet", "--tags", "origin")
            if _runs(*GIT, "-C", str(dest), "checkout", "--quiet", ref) != 0:
                raise _fail(
                    f"  FAIL     {name}: cannot check out {ref}; local changes in {dest} are"
                    f" in the way (see git -C {dest} status), or the ref is not there"
                )
    elif _present(dest):
        print(f"  SKIP     {name} exists and is not a git checkout: {dest}", file=sys.stderr)
        return
    else:
        _say(f"  clone    {name} {ref}")
        # No default-branch checkout: its .gitattributes line-ending rules can make the
        # pinned ref's files look locally modified and block the checkout below.
        status = _runs(*GIT, "clone", "--quiet", "--no-checkout", target.url, str(dest))
        if status != 0:
            raise Stop(status)
        _git_ok(dest, "checkout", "--quiet", ref)

    # The tag's own files differ in line endings by checkout (CRLF as released,
    # LF once an editor has touched them), so whitespace is not compared.
    patch = layout.patches / f"{name}-{ref}.patch"
    if _is_file(patch):
        apply = ("apply", "--ignore-whitespace")
        if _passes(dest, *apply, "--check", str(patch)):
            _git_ok(dest, *apply, str(patch))
            _say(f"  patch    {name} {patch.name}")
        elif _passes(dest, *apply, "--reverse", "--check", str(patch)):
            _say(f"  ok       {name} carries {patch.name}")
        else:
            print(
                f"  FAIL     {name}: {patch.name} neither applies to {dest} nor is in place",
                file=sys.stderr,
            )
            _runs(*GIT, "-C", str(dest), *apply, "--check", str(patch))
            raise Stop(1)


def fetch_sigma(dest: Path, url: str = SIGMA_URL, ref: str = SIGMA_REF) -> None:
    """The Sigma corpus at its exact pin.

    A tree ahead of (or behind) the ref is not the corpus measured, and a ref
    that is not there never falls back to the default branch.
    """
    if _is_dir(dest / ".git"):
        want = _commit(dest, ref)
        if want and _head(dest) == want:
            _say(f"  ok       sigma rules at {_head(dest, '--short')}")
            return
        _say(f"  checkout sigma rules -> {ref}")
        tag = f"refs/tags/{ref}:refs/tags/{ref}"
        git = (*GIT, "-C", str(dest))
        if (
            _runs(*git, "fetch", "--quiet", "--depth", "1", "origin", tag) != 0
            and _runs(*git, "fetch", "--quiet", "--tags", "origin") != 0
        ):
            raise _fail(f"  FAIL     cannot fetch sigma rules {ref}")
        if _runs(*git, "checkout", "--quiet", ref) != 0:
            raise _fail(f"  FAIL     sigma rules {ref} not available")
    elif _present(dest):
        print(f"  SKIP     {dest} exists and is not a git checkout", file=sys.stderr)
    else:
        _say(f"  clone    sigma rules {ref}")
        if _runs(*GIT, "clone", "--quiet", "--depth", "1", "--branch", ref, url, str(dest)):
            raise _fail(f"  FAIL     cannot clone sigma rules at {ref}")


def _download_checked(url: str, sha256: str, out: Path) -> None:
    """The archive at ``url`` into ``out``, refused unless its sha256 is the pinned one."""
    digest = hashlib.sha256()
    try:
        # nosemgrep: dynamic-urllib-use-detected — a pinned URL from this file, digest checked
        with urllib.request.urlopen(url, timeout=120) as answer, out.open("wb") as sink:
            for chunk in iter(lambda: answer.read(1 << 16), b""):
                digest.update(chunk)
                sink.write(chunk)
    except OSError as error:
        raise _fail(f"  FAIL     cannot fetch {url}: {error}") from None
    if digest.hexdigest() != sha256:
        raise _fail(f"  FAIL     {url}: sha256 {digest.hexdigest()} is not the pinned {sha256}")


def _extract(
    archive: Path, into: Path, strip: int, wanted: Callable[[tuple[str, ...]], bool]
) -> int:
    """The members ``wanted`` picks, their first ``strip`` path parts taken off.

    As ``tar --strip-components`` does, under tarfile's ``data`` filter: no
    absolute path, no path out of ``into``, no device, no link out of it.
    """
    if not hasattr(tarfile, "data_filter"):
        raise _fail("  FAIL     unpacking safely needs Python 3.11.4 or later")
    count = 0
    try:
        tar = tarfile.open(archive, "r:*")
    except (tarfile.TarError, OSError) as error:
        raise _fail(f"  FAIL     {archive.name}: {error}") from None
    with tar:
        for member in tar.getmembers():
            parts = PurePosixPath(member.name).parts
            if not wanted(parts) or len(parts) <= strip:
                continue
            changes = {"name": "/".join(parts[strip:])}
            if member.islnk():
                link = PurePosixPath(member.linkname).parts[strip:]
                if not link:
                    continue
                changes["linkname"] = "/".join(link)
            try:
                tar.extract(member.replace(**changes, deep=False), into, filter="data")  # type: ignore[arg-type]
            except (tarfile.TarError, OSError) as error:
                raise _fail(f"  FAIL     {archive.name}: {member.name}: {error}") from None
            count += 1
    return count


def _is_pinned(directory: Path, pin: str, tag: str | None = None) -> bool:
    """It says so in its PINNED.txt, or, for the rules, it is a checkout of the pinned tag."""
    pinned = directory / "PINNED.txt"
    if _is_file(pinned):
        lines = pinned.read_text(encoding="utf-8", errors="replace").splitlines()
        if lines and lines[0].rstrip("\r") == pin:
            return True
    if tag and _present(directory / ".git") and shutil.which("git"):
        at = _git(directory, "rev-parse", "-q", "--verify", "HEAD", quiet=True).stdout.strip()
        tagged = _commit(directory, f"refs/tags/{tag}")
        return bool(at) and at == tagged
    return False


def fetch_capa(layout: Layout, capa: Capa | None = None) -> None:
    """capa's rules and signatures into data/, each only when its directory is not there."""
    capa = capa or Capa()
    # Unpacked beside its destination and renamed into place, so a failed fetch or
    # a digest that does not match leaves no directory a later run would skip.
    work: Path | None = None

    def work_dir() -> Path:
        nonlocal work
        if work is None:
            (layout.root / "data").mkdir(parents=True, exist_ok=True)
            work = Path(tempfile.mkdtemp(prefix=".capa-fetch.", dir=layout.root / "data"))
        return work

    def say_present(directory: Path, pin: str, label: str, tag: str | None = None) -> None:
        if _is_pinned(directory, pin, tag):
            _say(f"  ok       {label} v{capa.version}")
        else:
            _say(
                f"  present  {label} in data/, but not the pinned v{capa.version}: left as they are"
            )

    try:
        if _present(layout.capa_rules):
            say_present(layout.capa_rules, capa.rules_pin, "capa rules", f"v{capa.version}")
        else:
            _say(f"  fetch    capa rules v{capa.version}")
            archive = work_dir() / "rules.tar.gz"
            _download_checked(capa.rules_url, capa.rules_sha256, archive)
            rules = work_dir() / "rules"
            rules.mkdir()
            # capa skips the rules' .github workflows; a rule count would not.
            _extract(archive, rules, 1, lambda parts: ".github" not in parts)
            _write_text(rules / "PINNED.txt", capa.rules_pin + "\n")
            rules.rename(layout.capa_rules)

        if _present(layout.capa_signatures):
            say_present(layout.capa_signatures, capa.signatures_pin, "capa signatures")
        else:
            _say(f"  fetch    capa signatures from flare-capa {capa.version}")
            archive = work_dir() / "sdist.tar.gz"
            _download_checked(capa.sdist_url, capa.sdist_sha256, archive)
            signatures = work_dir() / "signatures"
            signatures.mkdir()
            top = f"flare_capa-{capa.version}"
            sigs = _extract(archive, signatures, 2, lambda parts: parts[:2] == (top, "sigs"))
            licence = _extract(archive, signatures, 1, lambda parts: parts == (top, "LICENSE.txt"))
            if not sigs or not licence:
                raise _fail(f"  FAIL     {capa.sdist_url} holds no {top}/sigs or {top}/LICENSE.txt")
            _write_text(signatures / "PINNED.txt", capa.signatures_pin + "\n")
            signatures.rename(layout.capa_signatures)
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)


def fetch_external(
    names: Sequence[str],
    layout: Layout,
    targets: Sequence[Target] = TARGETS,
    sigma: tuple[str, str] = (SIGMA_URL, SIGMA_REF),
    capa: Capa | None = None,
) -> int:
    """Every default tree, the Sigma rules and capa's data; or only the named trees."""
    # A name that is no target is a typo, and fetching nothing for it would pass for success.
    known = [t.name for t in targets]
    for wanted in names:
        if wanted not in known:
            print(
                f"  FAIL     no target named {wanted}; the targets are: {' '.join(known)}",
                file=sys.stderr,
            )
            return 2
    if shutil.which("git") is None:
        print("  FAIL     git is not on PATH; install git first", file=sys.stderr)
        return 1
    try:
        layout.external.mkdir(parents=True, exist_ok=True)
        for target in targets:
            if names and target.name not in names:
                continue
            if not names and not target.default:
                _say(f"  opt-in   {target.name}: fetched only when named (external {target.name})")
                continue
            _fetch_tree(layout, target)
        # Named trees only: the rule corpora below are fetched by a run without names.
        if names:
            return 0
        fetch_sigma(layout.sigma, *sigma)
        fetch_capa(layout, capa)
    except Stop as stop:
        return stop.status
    _say("")
    _say(
        "external/, data/sigma_rules, data/capa-rules and data/capa-signatures are ignored by git."
    )
    _say("Re-run this after a fresh clone.")
    return 0


# ── docker/.env and bootstrap.env ────────────────────────────────────────────


def _fernet_key() -> str:
    """A key the settings store's Fernet accepts: 32 random bytes, URL-safe base64."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


DOCKER_GENERATED: dict[str, Callable[[], str]] = {
    "GHIDRA_MCP_AUTH_TOKEN": lambda: secrets.token_urlsafe(32),
    "REDIS_PASSWORD": lambda: secrets.token_urlsafe(32),
    "QDRANT_API_KEY": lambda: secrets.token_urlsafe(32),
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(32),
    "MINIO_ROOT_USER": lambda: "malspark",
    "MINIO_ROOT_PASSWORD": lambda: secrets.token_urlsafe(32),
    "SETTINGS_ENCRYPTION_KEY": _fernet_key,
    "JWT_SECRET_KEY": lambda: secrets.token_hex(32),
}

_PUBLISHED = re.compile(r"\$\{(?P<var>[A-Z0-9_]+_PORT):-(?P<port>\d+)\}")
_ASSIGNMENT = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)=")


def published_ports(root: Path) -> dict[str, int]:
    """Each ``${NAME_PORT:-N}`` the compose file publishes, with its default."""
    text = _read_text(root / "docker" / "docker-compose.yml", required=True) or ""
    return {m["var"]: int(m["port"]) for m in _PUBLISHED.finditer(text)}


def port_of(
    name: str,
    root: Path,
    environ: Mapping[str, str],
    docker_env: Mapping[str, str],
    defaults: Mapping[str, int] | None = None,
) -> int:
    """The host port compose publishes for ``name``: the environment, docker/.env, the default."""
    value = environ.get(name) or docker_env.get(name)
    if value and value.isdigit():
        return int(value)
    return (published_ports(root) if defaults is None else defaults)[name]


LOOPBACK = "127.0.0.1"


def bind_address(environ: Mapping[str, str], docker_env: Mapping[str, str]) -> str:
    """The address a host process reaches the published ports on; never empty.

    Resolved as compose resolves ``${BIND_ADDRESS:-127.0.0.1}``: the
    environment's value when it is set, else docker/.env's, and an empty one is
    unset, so the default stands. A wildcard (0.0.0.0, ::) publishes on every
    interface, and a host process reaches that on loopback, which is also where
    a port taken by anything listening on those addresses is seen.
    """
    given = environ["BIND_ADDRESS"] if "BIND_ADDRESS" in environ else docker_env.get("BIND_ADDRESS")
    address = (given or "").strip().strip("[]").strip()
    if not address or address in ("0.0.0.0", "::"):
        return LOOPBACK
    return address


def _host(environ: Mapping[str, str], docker_env: Mapping[str, str]) -> str:
    """The bind address as a URL's host part."""
    address = bind_address(environ, docker_env)
    return f"[{address}]" if ":" in address else address


_PLAIN_VALUE = re.compile(r"[A-Za-z0-9_./:@%+=,-]*")
_PLACEHOLDER = re.compile(r"<[^<>]*>")


def env_quote(value: str) -> str:
    """``value`` as parse_env and a POSIX shell read it back unchanged.

    Bare when it holds nothing those read specially; single-quoted, which both
    take literally, unless it holds a single quote; double-quoted with the
    shell's escapes otherwise. A value holding both a single quote and a
    backquote is refused: no quoting reads the same everywhere it is read.
    """
    if "'" in value and "`" in value:
        raise ValueError("a value holding both ' and ` cannot be written to an env file")
    if _PLAIN_VALUE.fullmatch(value):
        return value
    if "'" not in value:
        return f"'{value}'"
    return '"' + re.sub(r'(["\\$`])', r"\\\1", value) + '"'


def _fill(template: str, values: Mapping[str, str], kept_lines: Mapping[str, str]) -> str:
    """The example with each uncommented ``KEY=`` line given its value.

    A key the earlier file set keeps that file's line as it was written; one
    the example does not have is added at the end.
    """
    out = []
    seen = set()
    for line in template.splitlines():
        match = _ASSIGNMENT.match(line)
        key = match["key"] if match else None
        if key is not None and key in kept_lines:
            out.append(kept_lines[key])
            seen.add(key)
        elif key is not None and key in values:
            out.append(f"{key}={env_quote(values[key])}")
            seen.add(key)
        else:
            out.append(line)
    rest = [line for key, line in kept_lines.items() if key not in seen]
    if rest:
        out += ["", "# Kept from the file this one replaced.", *rest]
    return "\n".join(out) + "\n"


def _set_lines(path: Path) -> dict[str, str]:
    """The last uncommented line of each key the file assigns, as written, an empty one too."""
    lines: dict[str, str] = {}
    for line in (_read_text(path) or "").splitlines():
        match = _ASSIGNMENT.match(line.strip())
        if match:
            lines[match["key"]] = line.strip()
    return lines


def _umask() -> int:
    """The process umask, read without changing it for longer than the call."""
    mask = os.umask(0o077)
    os.umask(mask)
    return mask


def _write_text(path: Path, text: str, private: bool = False) -> None:
    """Written whole, with LF line ends; private files readable by their owner only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as out:
            out.write(text)
        if os.name == "posix" and not private:
            # mkstemp makes the file owner-only; a shared one gets the mode a
            # plain open would have given it under the user's umask.
            os.chmod(temporary, 0o666 & ~_umask())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


# Each bootstrap.env value derived from docker/.env, with the docker/.env
# values it carries: a new one of those makes the derived value stale.
DERIVED_FROM = {
    "DATABASE_URL": ("POSTGRES_PASSWORD",),
    "REDIS_URL": ("REDIS_PASSWORD",),
    "MINIO_ENDPOINT": (),
    "MINIO_ACCESS_KEY": ("MINIO_ROOT_USER",),
    "MINIO_SECRET_KEY": ("MINIO_ROOT_PASSWORD",),
    # The same keys as the containers', so a host process reads the same settings store.
    "SETTINGS_ENCRYPTION_KEY": ("SETTINGS_ENCRYPTION_KEY",),
    "JWT_SECRET_KEY": ("JWT_SECRET_KEY",),
}


def _derived(
    root: Path, environ: Mapping[str, str], docker_env: Mapping[str, str]
) -> dict[str, str]:
    """bootstrap.env's values as docker/.env and the published ports give them."""
    host = _host(environ, docker_env)
    quote = urllib.parse.quote
    user = docker_env.get("POSTGRES_USER") or "malspark"
    database = docker_env.get("POSTGRES_DB") or "malspark"
    postgres = port_of("POSTGRES_PORT", root, environ, docker_env)
    redis = port_of("REDIS_PORT", root, environ, docker_env)
    minio = port_of("MINIO_API_PORT", root, environ, docker_env)
    return {
        "DATABASE_URL": (
            f"postgresql+asyncpg://{quote(user, safe='')}"
            f":{quote(docker_env['POSTGRES_PASSWORD'], safe='')}"
            f"@{host}:{postgres}/{quote(database, safe='')}"
        ),
        "REDIS_URL": f"redis://:{quote(docker_env['REDIS_PASSWORD'], safe='')}@{host}:{redis}/0",
        "MINIO_ENDPOINT": f"{host}:{minio}",
        "MINIO_ACCESS_KEY": docker_env["MINIO_ROOT_USER"],
        "MINIO_SECRET_KEY": docker_env["MINIO_ROOT_PASSWORD"],
        "SETTINGS_ENCRYPTION_KEY": docker_env["SETTINGS_ENCRYPTION_KEY"],
        "JWT_SECRET_KEY": docker_env["JWT_SECRET_KEY"],
    }


GENERATED_NAMES = tuple(DOCKER_GENERATED)


def filled_names(env: Mapping[str, str]) -> frozenset[str]:
    """The names an env mapping gives a value; the values stay with the caller."""
    return frozenset(name for name, held in env.items() if held)


def unset_names(filled: Collection[str]) -> list[str]:
    """The names ``env init`` generates that docker/.env leaves empty or does not set.

    ``env init --force`` fills them; only names go in and come out.
    """
    return [name for name in GENERATED_NAMES if name not in filled]


def stale_derived(
    bootstrap_env: Mapping[str, str], docker_env: Mapping[str, str]
) -> list[tuple[str, str]]:
    """Each bootstrap.env value, with the docker/.env key, that no longer carries its source."""
    found = []
    for key, sources in DERIVED_FROM.items():
        text = bootstrap_env.get(key, "")
        if not text or _PLACEHOLDER.search(text):
            continue
        for source in sources:
            held = docker_env.get(source, "")
            if not held:
                continue
            carried = (
                urllib.parse.quote(held, safe="") in text if key.endswith("_URL") else text == held
            )
            if not carried:
                found.append((key, source))
    return found


def _unset_line(name: str) -> str:
    return f"  warn     docker/.env {name} is empty or not set; run env init --force to generate it"


def _stale_line(key: str, source: str, rewritten: bool = False) -> str:
    what = (
        "kept as written"
        if rewritten
        else "remove it from bootstrap.env and run env init --force to derive it again"
    )
    return f"  warn     bootstrap.env {key} does not carry docker/.env's {source}; {what}"


def env_init(root: Path, environ: Mapping[str, str], force: bool = False) -> int:
    try:
        return _env_init(root, environ, force)
    except Stop as stop:
        return stop.status


def _env_init(root: Path, environ: Mapping[str, str], force: bool) -> int:
    """docker/.env and bootstrap.env from their examples; no secret value is printed.

    A file already there is left as it is unless ``force``; rewritten, it
    keeps every assignment it had, empty ones included, and only an empty
    secret is generated. When docker/.env gets a new secret, every
    bootstrap.env value that carries it is derived again, so the two files
    never disagree; a bootstrap.env value is otherwise kept unless it is
    empty or still the example's placeholder.
    """
    docker_env_path = root / "docker" / ".env"
    bootstrap_path = root / "bootstrap.env"
    needed = dict.fromkeys(source for sources in DERIVED_FROM.values() for source in sources)

    # Compose expands $ in a value that is not single-quoted; parse_env does
    # not, so the two would disagree on the secret. Refused before anything
    # is written.
    expanded = []
    for key, line in _set_lines(docker_env_path).items():
        raw = line.partition("=")[2].strip()
        if key in needed and "$" in parse_env(line).get(key, "") and not raw.startswith("'"):
            expanded.append(key)
    if expanded:
        print(
            f"  FAIL     docker/.env: {', '.join(expanded)} holds a $ that compose would expand;"
            " single-quote the value ('...') and run env init again",
            file=sys.stderr,
        )
        return 1

    # Both files are built in memory and checked first; nothing is written
    # unless both can be, so a refusal leaves the two as they were.
    generated: dict[str, str] = {}
    docker_text: str | None = None
    if not (_present(docker_env_path) and not force):
        kept = _set_lines(docker_env_path)
        generated = {
            key: make()
            for key, make in DOCKER_GENERATED.items()
            if not parse_env(kept.get(key, "")).get(key)
        }
        kept = {key: line for key, line in kept.items() if key not in generated}
        template = _read_text(root / "docker" / ".env.example", required=True) or ""
        docker_text = _fill(template, generated, kept)
    docker_env = parse_env(docker_text) if docker_text is not None else read_env(docker_env_path)

    stale = sorted(k for k, sources in DERIVED_FROM.items() if set(sources) & set(generated))
    bootstrap_text: str | None = None
    old = read_env(bootstrap_path)
    # Kept as written: say so when it no longer carries what docker/.env holds.
    drifted = [pair for pair in stale_derived(old, docker_env) if pair[0] not in stale]
    if not (_present(bootstrap_path) and not force and not stale):
        empty = [key for key in needed if not docker_env.get(key)]
        if empty:
            print(
                f"  FAIL     nothing written: docker/.env sets no {', '.join(empty)}",
                file=sys.stderr,
            )
            return 1
        derived = _derived(root, environ, docker_env)
        kept = _set_lines(bootstrap_path)
        for key in derived:
            value = old.get(key, "")
            if key in stale or not value or _PLACEHOLDER.search(value):
                kept.pop(key, None)
                continue
        template = _read_text(root / "bootstrap.env.example", required=True) or ""
        try:
            bootstrap_text = _fill(template, derived, kept)
        except ValueError as error:
            print(f"  FAIL     nothing written: {error}", file=sys.stderr)
            return 1

    if docker_text is None:
        _say("  ok       docker/.env is there: left as it is (--force rewrites it, values kept)")
        for name in unset_names(filled_names(docker_env)):
            _say(_unset_line(name))
    else:
        _write_text(docker_env_path, docker_text, private=True)
        made = ", ".join(sorted(generated)) or "none"
        _say(f"  wrote    docker/.env (generated: {made})")
    if bootstrap_text is None:
        _say("  ok       bootstrap.env is there: left as it is (--force fills only what is empty)")
        for key, source in drifted:
            _say(_stale_line(key, source))
        return 0
    _write_text(bootstrap_path, bootstrap_text, private=True)
    url = urllib.parse.urlsplit(parse_env(bootstrap_text).get("DATABASE_URL", ""))
    try:
        where = f"database on {url.hostname}:{url.port}"
    except ValueError:
        where = "database URL kept as written"
    _say(f"  wrote    bootstrap.env ({where})")
    for key, source in drifted:
        _say(_stale_line(key, source, rewritten=True))
    if stale and old:
        _say(f"  note     bootstrap.env derived again from the new docker/.env: {', '.join(stale)}")
    return 0


# ── doctor ───────────────────────────────────────────────────────────────────


def _probe(argv: Sequence[str], timeout: float = 20) -> str | None:
    """A read-only command's output, or None when it fails or is not there."""
    try:
        done = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def port_in_use(host: str, port: int) -> bool:
    """Whether something already listens where compose would publish ``port``."""
    address = host.strip("[]") or LOOPBACK
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        # On Windows a bind can share a port another socket opened for reuse;
        # an exclusive bind is refused wherever anything holds it.
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            probe.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        try:
            probe.bind((address, port))
        except OSError:
            return True
    return False


def windows_filesystem(path: Path) -> str | None:
    """The file system the drive holding ``path`` is formatted with (Windows only)."""
    if os.name != "nt":
        return None
    import ctypes

    drive = os.path.splitdrive(str(path.resolve()))[0] + "\\"
    name = ctypes.create_unicode_buffer(64)
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None
    ok = windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(drive), None, 0, None, None, None, name, len(name)
    )
    return name.value if ok else None


# Beyond this many characters a checkout's path leaves the deepest files of the
# fetched trees little room under Windows' 260-character limit.
LONG_CHECKOUT = 60


def _state(directory: Path, unreadable: list[str]) -> str:
    """A tree's or corpus's line; one that cannot be examined is said so, once, on stderr."""
    kind = _examine(directory)
    if kind == DENIED:
        unreadable.append(str(directory))
        print(f"  FAIL     {directory} cannot be examined", file=sys.stderr)
        return "not checked: cannot be examined"
    return "present" if kind == DIRECTORY else "missing  (run external)"


def doctor_report(
    root: Path,
    environ: Mapping[str, str],
    probe: Callable[[Sequence[str]], str | None] = _probe,
    in_use: Callable[[str, int], bool] = port_in_use,
    filesystem: Callable[[Path], str | None] = windows_filesystem,
    windows: bool = os.name == "nt",
    system: str | None = None,
) -> Iterator[str]:
    """What this host has and lacks for the stack, one line each.

    A file that cannot be read is said once on stderr; a check that depends on
    it is not run and says so in one line, and the checks that do not need it
    go on. The report then ends with the stop, so the exit is non-zero.
    What each check reads: volumes, ports (the bind address and the port
    variables) and the secrets check read docker/.env; ports also reads
    docker/docker-compose.yml for the published defaults; the derived-values
    check reads docker/.env and bootstrap.env; the machine, file system, path
    length, docker, engine, compose, tree and data checks read neither.
    """
    unreadable: list[str] = []

    def tolerant(path: Path, label: str) -> dict[str, str] | None:
        try:
            return read_env(path)
        except Stop:
            unreadable.append(label)
            return None

    docker_read = tolerant(root / "docker" / ".env", "docker/.env")
    bootstrap_read = tolerant(root / "bootstrap.env", "bootstrap.env")
    docker_env = docker_read or {}
    bits = struct.calcsize("P") * 8
    emulated = environ.get("PROCESSOR_ARCHITEW6432")
    yield (
        f"  machine  {platform.system()} {platform.machine()}"
        + (f" (an {emulated} host)" if emulated else "")
        + f", Python {platform.python_version()} {bits}-bit"
    )
    overlay_seen = True
    try:
        named_data = bool(host_overlays(root, system, environ))
    except Stop:
        named_data, overlay_seen = False, False
        unreadable.append(NAMED_DATA_OVERLAY)
    if not overlay_seen:
        yield f"  volumes  not checked: {NAMED_DATA_OVERLAY} could not be examined"
    elif named_data and docker_read is None:
        yield "  volumes  not checked: docker/.env could not be read"
    elif named_data:
        yield f"  volumes  {data_volumes_note(root, environ, docker_env)}"
    if (fs := filesystem(root)) and fs.upper() == "NTFS":
        yield (
            f"  warn     the checkout is on NTFS ({root}): a bind mount from it carries no"
            " Linux owner or mode"
            + (
                ", and whether the stack keeps samples and uploads on named volumes was not checked"
                if not overlay_seen
                else ", so the stack keeps samples and uploads on named volumes"
                if named_data
                else ", so files the containers write under data/samples and data/uploads do not"
                " keep the ownership a Linux host gives them"
            )
        )
    if windows and len(str(root)) > LONG_CHECKOUT:
        yield (
            f"  warn     the checkout's path is {len(str(root))} characters long: a deep file"
            " under it can pass Windows' 260-character limit; a shorter one (C:\\src\\malspark)"
            " avoids it"
        )
    docker = shutil.which("docker", path=environ.get("PATH"))
    if docker is None:
        yield "  missing  docker" + _install_hint("docker")
    else:
        yield f"  docker   {docker}"
        engine = probe(["docker", "version", "--format", "{{.Server.Os}} {{.Server.Version}}"])
        if engine is None:
            yield (
                "  warn     the Docker engine does not answer:"
                " start Docker Desktop or the docker service"
            )
        else:
            server_os, _, version = engine.partition(" ")
            if server_os == "linux":
                yield f"  engine   Linux containers, server {version}"
            else:
                yield (
                    f"  warn     the engine runs {server_os} containers:"
                    " switch Docker Desktop to Linux containers"
                )
        compose = probe(["docker", "compose", "version", "--short"])
        if compose is None:
            yield "  missing  the docker compose plugin (compose v2)"
        else:
            major = compose.lstrip("v").split(".", 1)[0]
            note = "" if major.isdigit() and int(major) >= 2 else ": compose v2 or later is needed"
            yield f"  compose  {compose}{note}"
    if docker_read is None:
        yield "  secrets  not checked: docker/.env could not be read"
    elif not _is_file(root / "docker" / ".env"):
        yield "  missing  docker/.env: run env init"
    else:
        for name in unset_names(filled_names(docker_env)):
            yield (
                f"  missing  docker/.env {name} is empty or not set;"
                " run env init --force to generate it"
            )
    if docker_read is None or bootstrap_read is None:
        names = " and ".join(n for n in unreadable if n.endswith(".env"))
        yield f"  derived  not checked: {names} could not be read"
    elif _is_file(root / "docker" / ".env"):
        for key, source in stale_derived(bootstrap_read, docker_env):
            yield _stale_line(key, source)
    host = bind_address(environ, docker_env)
    defaults: dict[str, int] | None = None
    if docker_read is not None:
        try:
            defaults = published_ports(root)
        except Stop:
            unreadable.append("docker/docker-compose.yml")
        except OSError:
            unreadable.append("docker/docker-compose.yml")
            print(
                f"  FAIL     {root / 'docker' / 'docker-compose.yml'} cannot be read",
                file=sys.stderr,
            )
    taken = []
    if defaults is not None:
        for name in sorted(defaults):
            port = port_of(name, root, environ, docker_env, defaults)
            if in_use(host, port):
                taken.append((port, name))
    if docker_read is None:
        yield "  ports    not checked: docker/.env could not be read"
    elif defaults is None:
        yield "  ports    not checked: docker/docker-compose.yml could not be read"
    elif taken:
        listed = ", ".join(f"{port} ({name})" for port, name in taken)
        yield f"  in use   {listed} on {host}: the stack's own, or another program's"
        # A port another program holds is moved by its variable; a host process
        # then needs Postgres's new port in bootstrap.env's DATABASE_URL too.
        names = " or ".join(name for _, name in taken)
        yield (
            f"  hint     to publish elsewhere, set {names} in docker/.env"
            + (
                ", and the same port in bootstrap.env's DATABASE_URL"
                if any(n == "POSTGRES_PORT" for _, n in taken)
                else ""
            )
        )
    else:
        yield f"  ports    every published port is free on {host}"
    for tree in [root / "external" / t.name for t in TARGETS if t.default]:
        yield f"  tree     {tree.relative_to(root).as_posix()} {_state(tree, unreadable)}"
    for corpus in CORPORA:
        yield f"  data     {corpus} {_state(root / corpus, unreadable)}"
    if unreadable:
        raise Stop(1)


# ── setup ────────────────────────────────────────────────────────────────────


def setup_plan(root: Path, dev: bool) -> list[Step]:
    """The host environment a developer works in; a stack user needs none of it."""
    if not dev:
        return []
    return [
        Step(("uv", "sync", "--all-extras", "--all-packages"), root),
        Step(("uv", "run", "pre-commit", "install"), root),
    ]


# ── Command line ─────────────────────────────────────────────────────────────

STACK_COMMANDS = {
    "up": ("dev-up", "start the development stack"),
    "down": ("dev-down", "stop the development stack, optional services included"),
    "logs": ("dev-logs", "follow the development stack's logs"),
    "docker-up": (None, "start the production stack"),
    "docker-down": (None, "stop the production stack, optional services included"),
    "docker-logs": (None, "follow the production stack's logs"),
    "docker-build": (None, "build the production images"),
    "migrate": (None, "apply the API's migrations to bootstrap.env's DATABASE_URL"),
    "fe-rebuild": (None, "rebuild and restart the production frontend"),
    "worker-restart": (None, "restart the production worker"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malspark_dev.py", description=__doc__.split("\n\n", 1)[0]
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    setup = commands.add_parser(
        "setup", help="fetch what the stack needs; --dev adds the host environment"
    )
    setup.add_argument(
        "--dev",
        action="store_true",
        help="also uv sync --all-extras --all-packages and pre-commit install",
    )

    external = commands.add_parser("external", help="fetch the pinned third-party trees and data")
    external.add_argument("names", nargs="*", metavar="NAME", help="only these trees")

    env = commands.add_parser("env", help="the stack's env files")
    env_commands = env.add_subparsers(dest="env_command", required=True, metavar="init")
    init = env_commands.add_parser(
        "init", help="docker/.env and bootstrap.env with generated secrets"
    )
    init.add_argument(
        "--force", action="store_true", help="rewrite existing files, keeping the values they set"
    )

    commands.add_parser("doctor", help="what this host has and lacks (informative)")

    for name, (alias, text) in STACK_COMMANDS.items():
        sub = commands.add_parser(name, help=text, aliases=[alias] if alias else [])
        sub.set_defaults(command=name)
        sub.add_argument("--dry-run", action="store_true", help="print the commands, run nothing")
        if name in ("up", "down", "logs"):
            sub.add_argument(
                "-f", "--file", action="append", default=[], metavar="FILE",
                help="one more compose file after COMPOSE_FILE_EXTRA's (repeatable)",
            )  # fmt: skip

    admin = commands.add_parser(
        "create-admin", help="the first admin account, in the running stack"
    )
    admin.add_argument("email", metavar="EMAIL")
    admin.add_argument("--dry-run", action="store_true", help="print the command, run nothing")
    return parser


def _console_takes_any_text() -> None:
    """A character the console's encoding lacks is written escaped, never raised.

    A Windows console redirected to a pipe or a file encodes in the host's code
    page (cp1252, say), and a path or a git message holding a character outside
    it would stop the run with UnicodeEncodeError; UTF-8 has every character,
    so Linux and macOS print the same as before.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(errors="backslashreplace")


def main(argv: Sequence[str] | None = None, root: Path = REPO_ROOT) -> int:
    try:
        return _main(argv, root)
    except Stop as stop:
        return stop.status


def _main(argv: Sequence[str] | None, root: Path) -> int:
    _console_takes_any_text()
    args = build_parser().parse_args(argv)
    environ = dict(os.environ)

    if args.command == "external":
        return fetch_external(args.names, Layout.of(root, environ))
    if args.command == "setup":
        status = run_steps(setup_plan(root, args.dev), environ, root)
        if status:
            return status
        status = fetch_external([], Layout.of(root, environ))
        if status == 0 and not _present(root / "docker" / ".env"):
            _say("")
            _say("Next: uv run --no-project python scripts/dev/malspark_dev.py env init")
        return status
    if args.command == "env":
        return env_init(root, environ, force=args.force)
    if args.command == "doctor":
        warn_data_volumes_value(environ)
        for line in doctor_report(root, environ):
            _say(line)
        return 0

    if args.command == "create-admin" and not args.email:
        print("usage: malspark_dev.py create-admin EMAIL", file=sys.stderr)
        return 2
    ctx = Context.here(root, getattr(args, "file", ()))
    steps = stack_plan(args.command, ctx, getattr(args, "email", None))
    warn_data_volumes_value(environ)
    if args.command == "docker-up":
        warn_missing_corpora(root)
    starts_named_data = args.command in ("up", "docker-up") and bool(
        host_overlays(root, ctx.system, ctx.environ)
    )
    if starts_named_data:
        print(f"note: {data_volumes_note(root, environ)}", file=sys.stderr)
    if args.dry_run:
        for step in steps:
            _say(describe(step, root))
        return 0
    if starts_named_data:
        try:
            make_mount_points(root)
        except Stop as stop:
            return stop.status
    return run_steps(steps, environ, root)


if __name__ == "__main__":
    sys.exit(main())
