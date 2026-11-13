"""Where one job's staged bytes live, and who takes them away again.

A tool sidecar writes two kinds of file: the uploads ``put_sample`` receives
and the payloads ``carve_payloads`` writes out of a sample. Both used to land
in one directory per server *process*, which is one directory for every job the
host ever ran — so an operator's uploaded document stayed readable by the next
job the moment any read surface widened, and a stale tree from an old run of
the same sample was reachable until the TTL took it.

The boundary is the job's own directory:

* ``MALSPARK_STAGING_DIR`` is the **base**, and it stays what the operator set.
  A server nobody configured uses ``default_base()``.
* ``MALSPARK_STAGING_JOB`` is the **leaf**, one directory name composed by
  whoever spawns the sidecar and never read from the parent environment. The
  sidecar joins the two itself, which is why the spawn does not have to know
  the base a sidecar would have defaulted to.

Two variables rather than one because the spawn cannot compose one:
``agents.subprocess_env.child_env`` applies the server's own ``mcp.<server>.env``
mapping last, so a composed absolute path written before it would be overridden
by an operator's value, and one written after it would overwrite theirs.

Who creates what, and who removes it:

* the sidecar creates ``<base>/<leaf>`` 0o700, on its first write, and the
  worker creates it only for work of its own there — a sandbox capture, the
  triage pack's FLOSS run — so a job that stages nothing has no directory;
* the spawn composes the name and records it here, so the process that started
  the sidecars knows exactly which directories that job may have created;
* the job's owner removes them on every way out of the run, beside the owner
  heartbeat it drops in the same place;
* whatever a removal missed — a worker that was killed, a directory another
  user's process holds open — is left to the sidecar's own TTL sweep, which
  prunes a whole job directory by the newest mtime inside it.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import sys
import tempfile
import threading
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

from malspark.core.previous_name import PREVIOUS_NAME

# The base directory, the per-job leaf inside it, and how long anything in
# either is kept. Named here so the sidecars, the spawn and the worker read
# one spelling of each.
STAGING_DIR_ENV = "MALSPARK_STAGING_DIR"
STAGING_JOB_ENV = "MALSPARK_STAGING_JOB"
STAGING_TTL_ENV = "MALSPARK_STAGING_TTL_HOURS"
# How long a staged file is kept when ``MALSPARK_STAGING_TTL_HOURS`` is unset.
DEFAULT_STAGING_TTL_HOURS = 24.0

# The base a sidecar uses when nothing configured one. Shared rather than
# written out in each server, because the remover has to reach the same
# directory the writer did.
DEFAULT_BASE_NAME = "malspark-analysis-mcp"
# The default base a release before the product's rename (T-576) used, under
# its previous name: no sidecar writes there now, and the sweep still reaches
# it, because what a killed worker left there is live malware.
LEGACY_BASE_NAME = f"{PREVIOUS_NAME}-analysis-mcp"

# What a job directory is called. The prefix is what tells the sweep which
# entries under the base are job directories and which are the flat files of
# an older release, and it keeps the name away from ``carved``.
JOB_DIRECTORY_PREFIX = "job-"

# The child of a job directory a sandbox capture is fetched into. A capture is
# the one file the platform writes into staging without going through
# ``put_sample``, and until it moved here it went to a directory shared by
# every job on the host, named as a permanent sample root, and removed by
# nothing — so a sample carrying one instruction could have a later job read
# an earlier job's whole network capture.
CAPTURES_DIRECTORY = "captures"

# The child of a job directory every file written out of a sample lands in,
# under the sample's SHA-256: the analysis server's ``carve_payloads`` and
# ``unpack_upx``, and the triage pack's unpacking, write there, and the
# server's ``carved_path`` reads only there.
CARVED_DIRECTORY = "carved"

# The child of a job directory each capa run has a directory of its own in,
# its home, temporary and working directory, removed when the run ends: the
# triage pack's step and the capa_yara provider open it in the worker, and an
# analysis server started for the job joins it to its own job directory.
CAPA_DIRECTORY = "capa"

# The child of a job directory the job's artefact store keeps its files in
# (``pipeline.artefacts``), each under its SHA-256: a file one tool server
# wrote, the sandbox capture and the sandbox report, for another server's tool
# to read. A server on this host is handed its file under its own job
# directory's child of this name.
ARTEFACTS_DIRECTORY = "artefacts"

# Where the release before this fetched captures. Written by nothing now; the
# sweep still reaches it, because it is this project's directory and what is
# in it is somebody's traffic. It carries the product's previous name
# (``malspark.core.previous_name``), as that release wrote it.
LEGACY_CAPTURE_DIR_NAME = f"{PREVIOUS_NAME}-cape-pcap"

# A job id is a uuid in every deployment, but it arrives as a string and a
# directory name is not a place to find out otherwise. Anything outside this
# set becomes a hyphen and the original is named by a digest suffix, so two ids
# that differ only in what was replaced still get two directories.
_UNSAFE_IN_A_NAME = re.compile(r"[^A-Za-z0-9._-]")
_MAX_ID_CHARS = 64
_DIGEST_CHARS = 12

# The job directories this process composed a name for, by job id. The spawn
# writes here and the job's teardown reads it: the exact paths, rather than a
# base re-derived at removal time from settings that may since have been
# reloaded. Reached from the agent loop's thread and the graph loop's thread.
_COMPOSED: dict[str, set[Path]] = {}
_COMPOSED_LOCK = threading.Lock()


def default_base() -> Path:
    """The staging base a sidecar uses when ``MALSPARK_STAGING_DIR`` is unset."""
    return Path(tempfile.gettempdir()) / DEFAULT_BASE_NAME


def staging_base(environ: Mapping[str, str] | None = None) -> Path:
    """The configured base, created or not. Never the per-job directory.

    Made absolute here, at the one place both sides read it. A relative
    ``MALSPARK_STAGING_DIR`` otherwise means two directories: the worker resolves
    it against its own working directory and a built-in sidecar against
    ``services/<name>-mcp``, which is the cwd it is spawned with — so the
    remover would look somewhere the writer never wrote.
    """
    source = os.environ if environ is None else environ
    configured = str(source.get(STAGING_DIR_ENV, "")).strip()
    base = Path(configured) if configured else default_base()
    return base if base.is_absolute() else Path(os.path.abspath(base))


def job_directory_name(job_id: str) -> str:
    """The one directory name that stands for ``job_id``.

    Deterministic, so the spawn, the sidecar and the remover name the same
    directory without passing a path between them, and a single path segment
    whatever the id was: a value carrying a separator or a ``..`` is replaced
    character by character and then distinguished by a digest of the original.

    Written in lower case, because a staging base may sit on a mount that does
    not distinguish case (macOS, CIFS) and two ids differing only in case would
    then be one directory. A job id is a uuid in every deployment here, so this
    changes nothing in practice and closes the case that is not a deployment
    here. The digest suffix keeps two ids apart when the folding — or the
    character replacement — made them equal.
    """
    raw = str(job_id or "")
    safe = _UNSAFE_IN_A_NAME.sub("-", raw)[:_MAX_ID_CHARS].lower()
    if safe != raw:
        digest = sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:_DIGEST_CHARS]
        safe = f"{safe}-{digest}" if safe else digest
    return f"{JOB_DIRECTORY_PREFIX}{safe}"


def is_job_directory_name(name: str) -> bool:
    """Whether ``name`` is one segment this module would have composed.

    Asked of the leaf a sidecar is handed before it is joined to the base: the
    value comes from the process that spawned the server rather than from a
    model, and it is still not joined to a path unchecked.
    """
    return (
        bool(name)
        and name.startswith(JOB_DIRECTORY_PREFIX)
        and "/" not in name
        and os.sep not in name
        and name not in (".", "..")
        and Path(name).name == name
    )


def job_staging_dir(base: Path, job_id: str) -> Path:
    """Where everything ``job_id`` stages lands, under ``base``."""
    return base / job_directory_name(job_id)


def job_capture_dir(job_id: str, environ: Mapping[str, str] | None = None) -> Path:
    """Where this job's sandbox captures land, created or not.

    A child of the job's own staging directory, which is what makes a capture
    obey every rule the rest of this job's bytes obey: removed with the job,
    swept by the same TTL, and refused to another job by ``confined_to_this_job``
    without a rule of its own.
    """
    return job_staging_dir(staging_base(environ), job_id) / CAPTURES_DIRECTORY


def job_captures(job_dir: Path) -> list[str]:
    """The captures in one job's directory, named relative to it, in name order.

    ``captures/<file>``: the form a model is shown a capture in and passes one
    back in. Never a host path — a name that travels to a prompt, a refusal or
    the event feed says nothing about where this host keeps its staging.
    """
    directory = Path(job_dir) / CAPTURES_DIRECTORY
    try:
        files = sorted(entry.name for entry in directory.iterdir() if entry.is_file())
    except OSError:  # no capture directory: this job fetched no capture
        return []
    return [f"{CAPTURES_DIRECTORY}/{name}" for name in files]


def job_relative(path: str | Path, environ: Mapping[str, str] | None = None) -> str:
    """``path`` named relative to the job directory it is in, or by its file name.

    For a file the platform staged for a job — a capture — and is about to
    name to a model: the job directory's own part (``captures/<file>``) is what
    the job's sidecars resolve, and anything above it is this host's layout.
    """
    target = Path(path)
    base = Path(os.path.realpath(staging_base(environ)))
    real = Path(os.path.realpath(target))
    for parent in real.parents:
        if parent.parent == base and is_job_directory_name(parent.name):
            return real.relative_to(parent).as_posix()
    return target.name


def is_link(path: Path) -> bool:
    """Whether ``path`` is a link: a symbolic link, or on Windows a junction too.

    A junction is a directory link ``is_symlink`` does not report and
    ``lstat`` shows as a directory; whatever walks or removes a tree treats it
    as the link it is.
    """
    return path.is_symlink() or path.is_junction()


def is_reparse_point(path: Path, info: os.stat_result) -> bool:
    """Whether ``path``, whose ``lstat`` is ``info``, is a link or any other reparse point.

    A link (:func:`is_link`), and on Windows every entry that carries
    ``FILE_ATTRIBUTE_REPARSE_POINT``: a junction, a mount point, and a
    reparse point that is no link at all, such as a cloud file placeholder
    (OneDrive), whose content the system fetches from somewhere else when it
    is opened. Whatever asks this refuses all of them alike: what such an
    entry leads to cannot be told from the entry.
    """
    return is_link(path) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def owned_by_this_user(path: str | os.PathLike[str], info: os.stat_result) -> bool:
    """Whether ``path``, whose ``lstat`` is ``info``, is owned by this process's user.

    POSIX compares user ids (:func:`st_owned_by_this_user`). Windows has none
    (``st_uid`` is always 0), so there the owner the file's own security
    descriptor names is compared with this process's
    (:func:`_windows_owner_is_ours`). A reparse point is never this user's
    there: a junction or a symbolic link, whose owner says nothing about the
    directory it leads to, and a reparse point that is no link, such as a
    OneDrive placeholder, are refused alike (fail closed). Any failure to read
    either owner answers ``False``: a file whose owner cannot be told is not
    taken for this user's.
    """
    if sys.platform == "win32":
        if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            return False
        try:
            return _windows_owner_is_ours(path)
        except (OSError, AttributeError, ValueError):
            return False
    return st_owned_by_this_user(info)


def st_owned_by_this_user(info: os.stat_result) -> bool:
    """Whether the file ``info`` was read from is owned by this process's user, from ``info`` alone.

    For a caller that holds a stat result and no path to name the file by,
    such as one read with ``fstat`` from a descriptor opened relative to a
    directory. POSIX compares user ids. On Windows a stat result names no
    owner (``st_uid`` is always 0), so there the answer is ``False``: a file
    whose owner cannot be told is not taken for this user's; ask
    :func:`owned_by_this_user` with the file's path instead.
    """
    if sys.platform == "win32":
        return False
    getuid = getattr(os, "getuid", None)
    return False if getuid is None else info.st_uid == getuid()


# Why a name is refused where no flag of the system refuses a link at it.
NOT_FOLLOWED = "it is a link or another reparse point, which is never followed"
# Why a name is refused when the file opened at it is somewhere else.
OPENED_ELSEWHERE = "the file opened at it is somewhere else, so a link stood on its way"
# Why a name is refused where the system cannot say where an open file is.
NO_DESCRIPTOR_PATH = (
    "this system cannot say where an open file is, so a file opened without following "
    "links cannot be checked; unavailable on this platform"
)


def open_no_follow(
    path: str | os.PathLike[str], flags: int, mode: int = 0o600, *, at: str | None = None
) -> int:
    """``os.open(path, flags, mode)`` that follows no link at ``path``'s last part, or ``OSError``.

    Where the system has ``O_NOFOLLOW`` (POSIX) it is added to ``flags``: the
    one call it always was. On Windows, which has no such flag, what holds is:

    1. The file is opened by ``CreateFileW`` with
       ``FILE_FLAG_OPEN_REPARSE_POINT`` (:func:`_windows_open`): a link, a
       junction or any other reparse point at the last part, a OneDrive
       placeholder among them, is opened as itself, never followed, and then
       refused on the open handle's own attributes (``ELOOP``), before
       anything is written. ``O_CREAT``, ``O_EXCL`` and ``O_TRUNC`` are mapped
       to the creation disposition the C runtime's ``open`` uses, except that
       ``O_TRUNC`` never truncates at the open; the handle is not inherited and
       carries ``SECURITY_IDENTIFICATION``, so a named pipe server reached
       through the name cannot act as this process. It becomes a descriptor in
       binary (``O_BINARY``, without which a write turns each newline byte
       into two).
    2. The path of the file actually open, asked of the system by its handle
       (:func:`descriptor_path`), must be ``at``: by default the real path of
       ``path``'s directory as it was before the open, joined with its name.
       So a junction or link at any directory above the last part, put there
       at any moment before the open, is caught on the file that is open.
    3. Only then is the file truncated, where ``O_TRUNC`` was asked.

    A POSIX system without ``O_NOFOLLOW`` (no real one; ``tests/without_posix.py``
    makes one) refuses a link found at the name, opens with ``os.open`` and
    holds the open file to steps 2 and 3.

    ``at`` is for a caller that has checked more of the path than its last
    part (``pipeline.artefacts.open_beneath``). A refusal raises ``OSError``
    with ``ELOOP``, as ``O_NOFOLLOW`` does, naming why; a Win32 failure to
    open raises the ``OSError`` its error stands for (``ENOENT``, ``EEXIST``,
    ``EACCES``).
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is not None:
        return os.open(path, flags | nofollow, mode)
    where = os.path.abspath(os.fspath(path))
    expected = at or os.path.join(os.path.realpath(os.path.dirname(where)), os.path.basename(where))
    truncate = bool(flags & os.O_TRUNC)
    if sys.platform == "win32":
        fd = _windows_open(where, flags & ~os.O_TRUNC, mode)
    else:
        fd = _open_unless_a_link(where, flags & ~os.O_TRUNC, mode)
    try:
        opened = descriptor_path(fd)
        if os.path.normcase(opened) != os.path.normcase(expected):
            raise OSError(errno.ELOOP, OPENED_ELSEWHERE, where)
        if truncate:
            os.ftruncate(fd, 0)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_unless_a_link(where: str, flags: int, mode: int) -> int:
    """``os.open`` of ``where`` unless a link or another reparse point stands there now."""
    try:
        info = os.lstat(where)
    except FileNotFoundError:
        pass
    else:
        if is_reparse_point(Path(where), info):
            raise OSError(errno.ELOOP, NOT_FOLLOWED, where)
    return os.open(where, flags | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0), mode)


# The Win32 constants the open passes (winnt.h, winbase.h, fileapi.h).
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_READ_ATTRIBUTES = 0x80
_FILE_SHARE_READ_WRITE = 0x3  # what the C runtime's open shares: read and write
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_OPEN_ALWAYS = 4
_FILE_ATTRIBUTE_READONLY = 0x1
_FILE_ATTRIBUTE_NORMAL = 0x80
_SECURITY_IDENTIFICATION = 0x00010000
_SECURITY_SQOS_PRESENT = 0x00100000
_INVALID_HANDLE = -1
# A Win32 error, as the errno the C runtime gives it.
_WIN32_ERRNO = {
    2: errno.ENOENT,  # ERROR_FILE_NOT_FOUND
    3: errno.ENOENT,  # ERROR_PATH_NOT_FOUND
    4: errno.EMFILE,  # ERROR_TOO_MANY_OPEN_FILES
    5: errno.EACCES,  # ERROR_ACCESS_DENIED
    32: errno.EACCES,  # ERROR_SHARING_VIOLATION
    33: errno.EACCES,  # ERROR_LOCK_VIOLATION
    53: errno.ENOENT,  # ERROR_BAD_NETPATH
    67: errno.ENOENT,  # ERROR_BAD_NET_NAME
    80: errno.EEXIST,  # ERROR_FILE_EXISTS
    123: errno.ENOENT,  # ERROR_INVALID_NAME
    161: errno.ENOENT,  # ERROR_BAD_PATHNAME
    183: errno.EEXIST,  # ERROR_ALREADY_EXISTS
    206: errno.ENOENT,  # ERROR_FILENAME_EXCED_RANGE
}


def creation_disposition(flags: int) -> int:
    """The ``CreateFileW`` disposition for ``O_CREAT`` and ``O_EXCL``; ``O_TRUNC`` is applied later.

    As the C runtime maps them, with truncation left out: ``O_CREAT|O_EXCL``
    creates a new file or fails, ``O_CREAT`` opens or creates, and without
    ``O_CREAT`` only an existing file opens.
    """
    if flags & os.O_CREAT:
        return _CREATE_NEW if flags & os.O_EXCL else _OPEN_ALWAYS
    return _OPEN_EXISTING


def _windows_access(flags: int) -> int:
    """The access a handle opened for ``flags`` asks for, its attributes always among it."""
    asked = flags & 0x3  # O_RDONLY 0, O_WRONLY 1, O_RDWR 2
    access = {0: _GENERIC_READ, 1: _GENERIC_WRITE}.get(asked, _GENERIC_READ | _GENERIC_WRITE)
    return access | _FILE_READ_ATTRIBUTES


def _win32_error(code: int, call: str, where: str) -> OSError:
    return OSError(
        _WIN32_ERRNO.get(code, errno.EINVAL), f"{call} failed (Windows error {code})", where
    )


def _windows_open(where: str, flags: int, mode: int) -> int:
    """``where`` opened as itself by ``CreateFileW``, as a descriptor; a reparse point refused.

    ``flags`` carries no ``O_TRUNC`` (:func:`open_no_follow` truncates later).
    A flag this does not map is refused rather than dropped.
    """
    import ctypes

    known = 0x3 | os.O_CREAT | os.O_EXCL
    known |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    if flags & ~known:
        raise ValueError(f"open_no_follow cannot open with the flags {flags & ~known:#x} here")
    kernel32, msvcrt = _win32_files()
    created = flags & os.O_CREAT and not mode & stat.S_IWRITE
    handle = kernel32.CreateFileW(
        where,
        _windows_access(flags),
        _FILE_SHARE_READ_WRITE,
        None,
        creation_disposition(flags),
        (_FILE_ATTRIBUTE_READONLY if created else _FILE_ATTRIBUTE_NORMAL)
        | _FILE_FLAG_OPEN_REPARSE_POINT
        | _SECURITY_SQOS_PRESENT
        | _SECURITY_IDENTIFICATION,
        None,
    )
    if handle is None or handle == _INVALID_HANDLE:
        raise _win32_error(_last_error(), "CreateFileW", where)
    try:
        info = _by_handle_file_information()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise _win32_error(_last_error(), "GetFileInformationByHandle", where)
        if info.dwFileAttributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(errno.ELOOP, NOT_FOLLOWED, where)
        return int(
            msvcrt.open_osfhandle(
                handle, getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
            )
        )
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def _by_handle_file_information() -> Any:
    """An empty ``BY_HANDLE_FILE_INFORMATION``: its attributes are what the open reads.

    Built where it is used, so that importing this module needs no ``ctypes``
    on a system that never takes the Windows branch.
    """
    import ctypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", ctypes.c_uint32),
            # the times, the volume, the size, the links, the index
            ("rest", ctypes.c_uint32 * 12),
        ]

    return _ByHandleFileInformation()


def _win32_files() -> tuple[Any, Any]:
    """kernel32 typed for the open, and ``msvcrt`` that makes a descriptor of its handle."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = ctypes.c_ssize_t  # INVALID_HANDLE_VALUE reads as -1
    kernel32.GetFileInformationByHandle.argtypes = [ctypes.c_ssize_t, ctypes.c_void_p]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.c_ssize_t]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32, msvcrt


def descriptor_path(fd: int) -> str:
    """The path the file open as ``fd`` is at, every link on the way to it resolved.

    Asked of the system by the open file, never of a path: on Windows
    ``GetFinalPathNameByHandleW`` names the file the handle holds, and where
    the system keeps a ``/proc/self/fd`` table its link names the same.
    Raises ``OSError`` (:data:`NO_DESCRIPTOR_PATH`) where neither is there.
    """
    if sys.platform == "win32":
        try:
            return _windows_final_path(fd)
        except (AttributeError, ImportError) as exc:
            raise OSError(errno.ENOTSUP, NO_DESCRIPTOR_PATH) from exc
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError as exc:
        raise OSError(errno.ENOTSUP, NO_DESCRIPTOR_PATH) from exc


def _windows_final_path(fd: int) -> str:
    """``GetFinalPathNameByHandleW`` of ``fd``'s handle, as a drive or UNC path."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    handle = msvcrt.get_osfhandle(fd)  # type: ignore[attr-defined,unused-ignore]
    size = 512
    while True:
        buffer = ctypes.create_unicode_buffer(size)
        # FILE_NAME_NORMALIZED | VOLUME_NAME_DOS: the long name, under its drive.
        length = kernel32.GetFinalPathNameByHandleW(handle, buffer, size, 0)
        if not length:
            raise OSError(_last_error(), "GetFinalPathNameByHandleW failed")
        if length < size:
            return _without_dos_prefix(buffer.value)
        size = length  # the size it needs, its terminating null counted


def _without_dos_prefix(name: str) -> str:
    r"""``\\?\C:\x`` as ``C:\x``, ``\\?\UNC\host\share`` as ``\\host\share``: as ``realpath``."""
    if name.startswith("\\\\?\\UNC\\"):
        return "\\\\" + name[len("\\\\?\\UNC\\") :]
    if name.startswith("\\\\?\\"):
        return name[len("\\\\?\\") :]
    return name


# The Win32 constants the owner check passes (winnt.h, winbase.h, accctrl.h).
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x1
_READ_CONTROL = 0x20000
_FILE_SHARE_ALL = 0x7  # read, write and delete
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # needed to open a directory
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000  # the link itself, never its target
_TOKEN_QUERY = 0x8
_TOKEN_USER = 1
_TOKEN_OWNER = 4
_TOKEN_ELEVATION = 20


def _windows_owner_is_ours(path: str | os.PathLike[str]) -> bool:
    """Whether the owner SID of ``path`` is one this process owns what it creates by.

    That is the token's user and, only while the token is elevated, its
    default owner as well: an elevated process makes its files owned by the
    Administrators group rather than by its user, so a directory it created is
    still its own. An unelevated process never takes a file the Administrators
    own for its own. Raises ``OSError`` when the system refuses to answer.
    """
    return _owner_sid(path) in _process_sids()


def _win32() -> tuple[Any, Any]:
    """advapi32 and kernel32, loaded with the argument and result types the check uses."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    pointer = ctypes.POINTER(ctypes.c_void_p)
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        pointer,
        pointer,
        pointer,
        pointer,
        pointer,
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
    advapi32.IsValidSid.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return advapi32, kernel32


def _last_error() -> int:
    import ctypes

    return int(getattr(ctypes, "get_last_error", lambda: 0)())


def _sid_bytes(advapi32: Any, sid: Any) -> bytes:
    """A SID's bytes, compared as ``EqualSid`` compares them: whole and exactly."""
    import ctypes

    if not sid or not advapi32.IsValidSid(sid):
        raise OSError("the security descriptor holds no valid SID")
    return ctypes.string_at(sid, advapi32.GetLengthSid(sid))


def _owner_sid(path: str | os.PathLike[str]) -> bytes:
    """The SID of the owner ``path``'s own security descriptor names.

    The file is opened with ``FILE_FLAG_OPEN_REPARSE_POINT``, so a junction or
    a symbolic link is examined itself and never the directory it leads to.
    """
    import ctypes
    from ctypes import wintypes

    advapi32, kernel32 = _win32()
    handle = kernel32.CreateFileW(
        os.fspath(path),
        _READ_CONTROL,
        _FILE_SHARE_ALL,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle is None or handle == wintypes.HANDLE(-1).value:
        raise OSError(_last_error(), "CreateFileW failed")
    try:
        owner = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        status = advapi32.GetSecurityInfo(
            handle,
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if status != 0:
            raise OSError(status, "GetSecurityInfo failed")
        try:
            return _sid_bytes(advapi32, owner)
        finally:
            kernel32.LocalFree(descriptor)
    finally:
        kernel32.CloseHandle(handle)


def _token_information(advapi32: Any, token: Any, kind: int) -> Any:
    """One class of the token's information, in a buffer of the size it asks for."""
    import ctypes
    from ctypes import wintypes

    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
    buffer = ctypes.create_string_buffer(size.value)
    if not size.value or not advapi32.GetTokenInformation(
        token, kind, buffer, size, ctypes.byref(size)
    ):
        raise OSError(_last_error(), "GetTokenInformation failed")
    return buffer


def _token_sid(advapi32: Any, token: Any, kind: int) -> bytes:
    """The SID ``TOKEN_USER`` or ``TOKEN_OWNER`` names: both begin with its pointer."""
    import ctypes

    buffer = _token_information(advapi32, token, kind)
    return _sid_bytes(advapi32, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0])


def _token_elevated(advapi32: Any, token: Any) -> bool:
    """Whether the token is elevated (``TOKEN_ELEVATION.TokenIsElevated``)."""
    import ctypes

    buffer = _token_information(advapi32, token, _TOKEN_ELEVATION)
    return bool(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint32))[0])


def _process_sids() -> frozenset[bytes]:
    """The SIDs this process owns what it creates by (:func:`_windows_owner_is_ours`)."""
    import ctypes
    from ctypes import wintypes

    advapi32, kernel32 = _win32()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise OSError(_last_error(), "OpenProcessToken failed")
    try:
        sids = {_token_sid(advapi32, token, _TOKEN_USER)}
        if _token_elevated(advapi32, token):
            sids.add(_token_sid(advapi32, token, _TOKEN_OWNER))
        return frozenset(sids)
    finally:
        kernel32.CloseHandle(token)


def private_dir(path: Path, *, what: str = "staging path") -> Path:
    """``path`` as a directory only this user may enter, or an error.

    Created with ``mkdir(mode=0o700)`` rather than created-then-chmodded, and
    refused if what is already there is a symlink or belongs to somebody else.
    These names are predictable and the system temp directory is shared, so
    without those checks another local user could plant a directory or a link
    at one of them and receive live malware into a location of their choosing —
    and the chmod would then be applied to their target.

    One function for every directory this project creates under the base, so
    the capture directory the worker opens is held to exactly what the sidecar
    holds its own staging directory to.

    On Windows the mode is not what keeps the directory private: a directory
    CPython creates with mode 0o700 gets a DACL that admits only its owner,
    SYSTEM and the Administrators, and that is the privacy there. The DACL of
    a directory that already exists is not verified; its owner is
    (:func:`owned_by_this_user`), and a junction or any other reparse point
    is refused (:func:`is_reparse_point`).
    """
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except FileExistsError as exc:  # a non-directory already sits at that path
        raise RuntimeError(f"{what} {path} is not a directory") from exc
    if is_link(path):
        raise RuntimeError(f"{what} {path} is a symlink")
    info = path.lstat()
    if is_reparse_point(path, info):
        raise RuntimeError(f"{what} {path} is a reparse point, which is never followed")
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{what} {path} is not a directory")
    if not owned_by_this_user(path, info):
        raise RuntimeError(f"{what} {path} is owned by another user")
    if info.st_mode & 0o077:
        path.chmod(0o700)
    return path


def open_capture_dir(job_id: str) -> Path:
    """This job's capture directory, created 0o700, readable by this job's sidecars.

    The directory is named as a sample root because a capture is not staged
    through ``put_sample`` — the sandbox provider writes it and the network
    analyst is told the path — and a root is how a sidecar learns it may read
    a directory the platform filled. The root is this job's own and is dropped
    when the job ends, so no later job inherits it; the shared, permanent root
    of the release before this is what let one job read another's capture.

    Every level is opened through ``private_dir``, so a base or a job directory
    somebody else owns, or a symlink planted at one of them, is refused with a
    sentence saying which rather than ending in a ``PermissionError`` from a
    chmod that happened to fail.
    """
    from malspark.tools.roots import add_sample_root

    captures = job_capture_dir(job_id)
    for directory in (captures.parent.parent, captures.parent, captures):
        private_dir(directory, what="capture path")
    note_job_directory(job_id, captures.parent)
    add_sample_root(captures)
    return captures


def open_job_directory(job_id: str, child: str, environ: Mapping[str, str] | None = None) -> Path:
    """``<base>/<job>/<child>``, created 0o700 level by level, recorded for the teardown.

    For work the platform itself does in a job's staging directory, as
    ``open_capture_dir`` is for a capture, and held to the same checks: every
    level goes through ``private_dir``, and the job directory is recorded so
    the job's teardown removes it with everything else the job staged. No
    sample root is named, because nothing but the platform reads it.
    """
    job_dir = job_staging_dir(staging_base(environ), job_id)
    target = job_dir / child
    for directory in (job_dir.parent, job_dir, target):
        private_dir(directory)
    note_job_directory(job_id, job_dir)
    return target


def staging_ttl_seconds(environ: Mapping[str, str] | None = None) -> float:
    """``MALSPARK_STAGING_TTL_HOURS``, or a day. Zero or less disables pruning.

    One reading for every sweep: the analysis server's of its staging base,
    and a capa run's of the temporary directories runs with no job left.
    """
    source = os.environ if environ is None else environ
    raw = str(source.get(STAGING_TTL_ENV, "")).strip()
    try:
        hours = float(raw) if raw else DEFAULT_STAGING_TTL_HOURS
    except ValueError:
        hours = DEFAULT_STAGING_TTL_HOURS
    return hours * 3600.0


def newest_mtime(root: Path) -> float:
    """The most recent mtime in this tree, the directory itself included.

    Read with ``lstat`` throughout: a symlink's own timestamp is what counts,
    never the timestamp of whatever it points at, which may be a file somebody
    else is still writing.
    """
    try:
        newest = root.lstat().st_mtime
    except OSError:
        return 0.0
    for entry in root.rglob("*"):
        try:
            newest = max(newest, entry.lstat().st_mtime)
        except OSError:  # an entry another call removed while this walked
            continue
    return newest


def staging_root(environ: Mapping[str, str] | None = None) -> Path:
    """The directory the server reading ``environ`` may write and read.

    The job directory when a leaf was composed for this child, and the base
    itself when none was — a sidecar started by hand, a settings probe, or a
    deployment that runs the server outside a job.
    """
    source = os.environ if environ is None else environ
    base = staging_base(source)
    leaf = str(source.get(STAGING_JOB_ENV, "")).strip()
    return base / leaf if is_job_directory_name(leaf) else base


def _touch_not_through_a_link(directory: Path | str) -> None:
    """Set the directory's own mtime to now, never the mtime of what a link names.

    Where ``os.utime`` takes ``follow_symlinks`` it is passed ``False``. Where it
    does not (Windows), a link is left alone by looking first: the answer is the
    same one, a link is not touched, and the window between the look and the
    touch is the one a directory this project made itself leaves open.
    """
    if os.utime in os.supports_follow_symlinks:
        os.utime(directory, None, follow_symlinks=False)
    elif not os.path.islink(directory):
        os.utime(directory, None)


def touch_job_staging(job_id: str) -> bool:
    """Say this job is still running, where another process's sweep can read it.

    The sweep prunes a job directory whole once the newest mtime inside it is
    past the TTL, and it runs inside a sidecar — a child with no database, no
    queue and no way to ask whether a job is alive. So the job says so on disk,
    by keeping its own directory's mtime current: the owner that refreshes the
    heartbeat refreshes this beside it, twice inside the claim's own TTL.

    Without it, a job that has been running longer than
    ``MALSPARK_STAGING_TTL_HOURS`` without staging anything new — a long static
    pass, a slow sandbox — could have its directory, carved payloads and all,
    removed under it by a *second* worker's sidecar sharing the base.

    The directories touched are the ones this process *recorded* — what the
    spawn composed from the child's own environment, and what the capture fetch
    opened — rather than one re-derived here from the worker's environment.
    Where an operator sets ``MALSPARK_STAGING_DIR`` in a server's own ``env`` map
    alone, those two are different directories, and the one that matters is the
    one the sidecar will sweep. It is the same list the removal walks.

    Returns whether there was a directory to touch. Nothing recorded means no
    sidecar was ever pointed anywhere, so there is nothing to protect.
    """
    touched = False
    for directory in job_directories(job_id):
        try:
            _touch_not_through_a_link(directory)
        except OSError:  # nothing staged yet, or a directory somebody else owns
            continue
        touched = True
    return touched


def make_private(path: Path) -> None:
    """Take everyone but this user off a file the platform just wrote.

    For a file a provider streamed in rather than one this project opened:
    ``put_sample`` creates its own at 0o600 through :func:`open_no_follow`, while a
    capture arrives through an HTTP client that writes at the process umask —
    0o664 on this host, which on a shared machine is every local user.
    """
    try:
        if not path.is_symlink() and path.is_file():
            path.chmod(0o600)
    except OSError:  # a file the provider removed again, or a foreign mount
        pass


def confined_to_this_job(resolved: Path, environ: Mapping[str, str] | None = None) -> Path:
    """``resolved``, unless it is staged bytes belonging to a different job.

    A sample root is a deployment's own directory and a staging base may be
    configured inside one — and then a path argument that lands in a sibling
    job's directory answers the roots question truthfully and would be read.
    The job directory is the boundary whatever the roots are, so the staging
    base is the one place where being inside a root is not enough.

    Raises:
        PathOutsideRoots: for anything staged that this job did not stage.
    """
    from malspark.tools.roots import PathOutsideRoots

    source = os.environ if environ is None else environ
    base = staging_base(source)
    root = staging_root(source)
    if root == base:
        return resolved
    real_base = Path(os.path.realpath(base))
    real_root = Path(os.path.realpath(root))
    if real_base in resolved.parents and not (
        resolved == real_root or real_root in resolved.parents
    ):
        raise PathOutsideRoots()
    return resolved


def note_job_directory(job_id: str, path: Path) -> None:
    """Record that ``job_id``'s sidecars were pointed at ``path``."""
    with _COMPOSED_LOCK:
        _COMPOSED.setdefault(str(job_id), set()).add(Path(path))


def job_directories(job_id: str) -> list[Path]:
    """Every directory this process composed for ``job_id``, in a stable order."""
    with _COMPOSED_LOCK:
        return sorted(_COMPOSED.get(str(job_id), ()))


def forget_job_directories(job_id: str) -> list[Path]:
    """Drop what was recorded for ``job_id`` and hand it back."""
    with _COMPOSED_LOCK:
        return sorted(_COMPOSED.pop(str(job_id), ()))


def remove_job_staging(job_id: str) -> list[Path]:
    """Remove every staging directory this process composed for ``job_id``.

    Returns the ones that were there and are gone. A directory that was never
    created — a job whose sidecars staged nothing — is not in that list and is
    not a failure either; the caller tells the two apart by asking what is left
    on disk rather than by counting. Never raises: a removal that fails is the
    caller's to log, and what is left behind is swept by the sidecar's TTL.

    The tree holds live malware, so it is walked rather than handed to a
    library: nothing is followed through a symlink, and each directory is made
    private again before it is descended into, so a partial removal cannot
    leave a readable directory behind.

    The job's capture directory goes with it, and so does the sample root that
    named it: a root left behind would be inherited by every sidecar this
    process starts afterwards, which is the shape of the leak this replaces.
    """
    from malspark.tools.roots import remove_sample_root

    remove_sample_root(job_capture_dir(job_id))
    removed: list[Path] = []
    for path in forget_job_directories(job_id):
        if not path.exists() and not path.is_symlink():
            continue
        if remove_tree(path):
            removed.append(path)
    return removed


class NotThisJob(ValueError):
    """A release asked of a server started for one job, for another job."""


def release_job_directory(job_id: str, environ: Mapping[str, str] | None = None) -> bool:
    """Remove ``<base>/<job_id's directory>`` on this side, for a job that ended. True when gone.

    For a server that serves many jobs from one process (a container of its
    own, ``tools.readers.RELEASE_JOB``), asked by the worker at the job's
    end, so the job's scratch and carves go then rather than at the TTL.

    Only that job's directory: its name is :func:`job_directory_name`, a
    single segment whatever the id holds (a ``..``, a separator, an absolute
    path are replaced and told apart by a digest), joined to the base and
    checked to sit directly in it. A link standing there is unlinked and its
    target left alone (:func:`remove_tree`). A server whose environment names
    one job's leaf releases only that job.

    Raises:
        NotThisJob: when this server was started for another job.
        ValueError: when the id is empty or the name lands anywhere but in the base.
    """
    if not str(job_id or "").strip():
        raise ValueError("no job to release")
    source = os.environ if environ is None else environ
    base = staging_base(source)
    name = job_directory_name(job_id)
    root = staging_root(source)
    if root != base and root.name != name:
        raise NotThisJob("this server stages for another job")
    target = base / name
    if not is_job_directory_name(name) or target.parent != base:
        raise ValueError("the job's directory name is not one segment of the staging base")
    return remove_tree(target)


def remove_tree(root: Path) -> bool:
    """Delete ``root`` and everything under it. True when nothing is there.

    A link at ``root`` is removed rather than followed, and so is every link
    inside it: a directory of staged malware is exactly the place a link
    planted into it must not turn a cleanup into a delete somewhere else. A
    link is a symbolic link or, on Windows, a junction too (:func:`is_link`),
    which ``os.walk`` would otherwise descend into.
    """
    try:
        info = root.lstat()
    except OSError:
        return True  # nothing there, which is the state this asks for
    if is_link(root) or not stat.S_ISDIR(info.st_mode):
        try:
            root.unlink()
        except OSError:
            return False
        return True
    ok = True
    # Walked from the top so a link to a directory is taken out of the walk
    # before it could be entered, then emptied from the bottom.
    visited: list[tuple[Path, list[str], list[str]]] = []
    for directory, subdirectories, files in os.walk(root, topdown=True, followlinks=False):
        here = Path(directory)
        links = [name for name in subdirectories if is_link(here / name)]
        subdirectories[:] = [name for name in subdirectories if name not in links]
        visited.append((here, files, links))
    for here, files, links in reversed(visited):
        try:
            here.chmod(0o700)
        except OSError:
            ok = False
        for name in files:
            try:
                (here / name).unlink()
            except OSError:
                ok = False
        # The target of a link is somebody else's: the link alone goes. On
        # Windows ``unlink`` removes a directory link, a junction among them,
        # as the link it is.
        for name in links:
            try:
                (here / name).unlink()
            except OSError:
                ok = False
        try:
            here.rmdir()
        except OSError:
            ok = False
    return ok and not root.exists()
