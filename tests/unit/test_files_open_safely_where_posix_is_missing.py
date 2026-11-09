"""A file the host code opens is held to the same rule where POSIX's flags are missing.

Windows has no ``O_NOFOLLOW``, no ``O_DIRECTORY`` and no ``openat``. There a
file is opened through ``tools.staging.open_no_follow``: a link or any other
reparse point at its name is refused, it is opened in binary, and the path of
the file actually open, asked of the system by its handle, must be the one
that was checked, before anything is truncated or read. These tests take the
flags away on this host and run that branch for real: the path of an open
file is read from ``/proc/self/fd`` here and from ``GetFinalPathNameByHandleW``
on Windows. Where nothing of a process can be measured, the isolation part
says it is not available on this platform rather than reading as measured.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib.util
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from malspark.agents import sample_staging
from malspark.analysis import sample_integrity
from malspark.loaders.cape2_client import CAPEv2Client
from malspark.pipeline.artefacts import open_beneath
from malspark.providers.sandbox.limits import stream_to_file_capped
from malspark.tools import staging

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = b"line one\nline two\r\n\x1a\x00\xff"

# The branch is run here with the open file's path read from /proc.
needs_proc = pytest.mark.skipif(
    not os.path.isdir("/proc/self/fd"), reason="this host names no open file's path in /proc"
)


@pytest.fixture
def no_posix_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    """This process without ``O_NOFOLLOW`` and ``O_DIRECTORY``, as on Windows."""
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(os, "O_DIRECTORY", raising=False)


class _Chunks:
    """A streamed response of the chunks given."""

    def __init__(self, *chunks: bytes) -> None:
        self._chunks = chunks

    def iter_bytes(self, _size: int) -> Any:
        return iter(self._chunks)


def test_a_plain_file_is_opened_and_read_whole_on_every_system(tmp_path: Path) -> None:
    """Unmarked: on Windows this is the handle's own path checked by the real API."""
    target = tmp_path / "plain.bin"
    target.write_bytes(PAYLOAD)
    fd = staging.open_no_follow(target, os.O_RDONLY)
    with os.fdopen(fd, "rb") as handle:
        assert handle.read() == PAYLOAD


def test_where_the_flag_exists_it_is_the_one_call_it_was(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(os, "O_NOFOLLOW", 0x20000, raising=False)
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(os, "open", lambda *args: calls.append(args) or 7)
    assert staging.open_no_follow(tmp_path / "x", os.O_RDONLY, 0o600) == 7
    assert calls == [(tmp_path / "x", os.O_RDONLY | 0x20000, 0o600)]


@needs_proc
@pytest.mark.usefixtures("no_posix_flags")
class TestOpeningWithoutTheFlag:
    def test_a_file_in_place_is_opened_in_binary_and_not_inherited(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        target = tmp_path / "f"
        target.write_bytes(PAYLOAD)
        monkeypatch.setattr(os, "O_BINARY", 1 << 28, raising=False)
        monkeypatch.setattr(os, "O_NOINHERIT", 1 << 29, raising=False)
        real_open, flags = os.open, []

        def spying(path: Any, given: int, mode: int = 0o777) -> int:
            flags.append(given)
            return real_open(path, given & ~((1 << 28) | (1 << 29)), mode)

        monkeypatch.setattr(os, "open", spying)
        fd = staging.open_no_follow(target, os.O_RDONLY)
        os.close(fd)
        assert flags == [os.O_RDONLY | (1 << 28) | (1 << 29)]

    @pytest.mark.posix
    def test_a_link_at_the_name_is_refused(self, tmp_path: Path) -> None:
        victim = tmp_path / "victim"
        victim.write_bytes(b"keep")
        (tmp_path / "link").symlink_to(victim)
        with pytest.raises(OSError, match="never followed") as caught:
            staging.open_no_follow(tmp_path / "link", os.O_WRONLY | os.O_TRUNC)
        assert caught.value.errno == errno.ELOOP
        assert victim.read_bytes() == b"keep"

    def test_a_reparse_point_that_is_no_link_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A OneDrive placeholder: no link, and still never opened (fail closed)."""
        target = tmp_path / "placeholder"
        target.write_bytes(b"x")
        real_lstat = os.lstat
        placeholder = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
        )

        def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
            return placeholder if Path(path) == target else real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", lstat)
        with pytest.raises(OSError, match="never followed"):
            staging.open_no_follow(target, os.O_RDONLY)

    def test_a_file_found_elsewhere_once_open_is_refused_and_never_truncated(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A link put in place between the check and the open is caught on the open file."""
        target = tmp_path / "f"
        target.write_bytes(b"somebody's bytes")
        monkeypatch.setattr(staging, "descriptor_path", lambda _fd: str(tmp_path / "other"))
        opened: list[int] = []
        real_open = os.open
        monkeypatch.setattr(os, "open", lambda *a: opened.append(real_open(*a)) or opened[-1])
        with pytest.raises(OSError, match="somewhere else") as caught:
            staging.open_no_follow(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        assert caught.value.errno == errno.ELOOP
        assert target.read_bytes() == b"somebody's bytes"
        with pytest.raises(OSError):
            os.fstat(opened[0])  # closed

    def test_a_file_in_place_is_truncated_once_checked(self, tmp_path: Path) -> None:
        target = tmp_path / "f"
        target.write_bytes(b"old and longer")
        fd = staging.open_no_follow(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.write(fd, b"new")
        os.close(fd)
        assert target.read_bytes() == b"new"

    def test_a_system_that_cannot_name_an_open_file_refuses(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        target = tmp_path / "f"
        target.write_bytes(b"x")

        def no_table(_path: Any) -> str:
            raise FileNotFoundError

        monkeypatch.setattr(os, "readlink", no_table)
        with pytest.raises(OSError, match="unavailable on this platform") as caught:
            staging.open_no_follow(target, os.O_RDONLY)
        assert caught.value.errno == errno.ENOTSUP


class _Function:
    """A foreign function as ``ctypes`` gives one: typed by attributes, then called."""

    def __init__(self, body: Any) -> None:
        self.argtypes: Any = None
        self.restype: Any = None
        self._body = body

    def __call__(self, *args: Any) -> Any:
        return self._body(*args)


class TestTheOpenFilesPathOnWindows:
    @pytest.fixture(autouse=True)
    def _windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")

    def _kernel32(self, monkeypatch: pytest.MonkeyPatch, final: str) -> list[int]:
        sizes: list[int] = []

        def final_path(_handle: Any, buffer: Any, size: int, flags: int) -> int:
            sizes.append(size)
            assert flags == 0  # the normalised name, under its drive letter
            if size <= len(final):
                return len(final) + 1
            buffer.value = final
            return len(final)

        kernel32 = SimpleNamespace(GetFinalPathNameByHandleW=_Function(final_path))
        monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: kernel32, raising=False)
        monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=lambda fd: fd))
        return sizes

    @pytest.mark.parametrize(
        ("final", "said"),
        [
            ("\\\\?\\C:\\staging\\job-x\\f", "C:\\staging\\job-x\\f"),
            ("\\\\?\\UNC\\host\\share\\f", "\\\\host\\share\\f"),
        ],
    )
    def test_the_handle_names_its_file_as_realpath_would(
        self, monkeypatch: pytest.MonkeyPatch, final: str, said: str
    ) -> None:
        self._kernel32(monkeypatch, final)
        assert staging.descriptor_path(3) == said

    def test_a_long_name_is_asked_again_with_room_for_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        final = "\\\\?\\C:\\" + "d" * 700
        sizes = self._kernel32(monkeypatch, final)
        assert staging.descriptor_path(3) == "C:\\" + "d" * 700
        assert sizes == [512, len(final) + 1]

    def test_a_refusal_of_the_system_is_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._kernel32(monkeypatch, "")
        monkeypatch.setattr(ctypes, "get_last_error", lambda: 6, raising=False)
        with pytest.raises(OSError, match="GetFinalPathNameByHandleW"):
            staging.descriptor_path(3)

    def test_no_win32_api_is_unavailable_on_this_platform(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delattr(ctypes, "WinDLL", raising=False)
        monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=lambda fd: fd))
        with pytest.raises(OSError, match="unavailable on this platform"):
            staging.descriptor_path(3)


class _Win32Files:
    """kernel32 and msvcrt as the Windows open calls them, over this host's own files.

    ``CreateFileW`` records what it was asked and answers a handle, or fails
    with ``error``; ``open_osfhandle`` makes a real descriptor of the path the
    handle was opened for, so what the open writes lands in a real file.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, attributes: int = 0, error: int = 0):
        self.created: list[tuple[Any, ...]] = []
        self.closed: list[int] = []
        self.made: list[int] = []
        self.paths: dict[int, str] = {}
        self._attributes, self._error, self._next = attributes, error, 100
        self.info_fails = False
        kernel32 = SimpleNamespace(
            CreateFileW=self.create,
            GetFileInformationByHandle=self.information,
            CloseHandle=self.closed.append,
        )
        msvcrt = SimpleNamespace(open_osfhandle=self.descriptor)
        self._handles: dict[int, str] = {}
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
        monkeypatch.setattr(staging, "_win32_files", lambda: (kernel32, msvcrt))
        monkeypatch.setattr(staging, "descriptor_path", lambda fd: self.paths[fd])
        monkeypatch.setattr(ctypes, "get_last_error", lambda: self._error, raising=False)

    def create(self, path: str, *args: Any) -> int:
        self.created.append((path, *args))
        if self._error:
            return -1
        self._next += 1
        self._handles[self._next] = path
        return self._next

    def information(self, _handle: int, info: Any) -> int:
        if self.info_fails:
            return 0
        info._obj.dwFileAttributes = self._attributes
        return 1

    def descriptor(self, handle: int, flags: int) -> int:
        self.made.append(flags)
        fd = os.open(self._handles[handle], os.O_RDWR | os.O_CREAT, 0o600)
        self.paths[fd] = os.path.realpath(self._handles[handle])
        return fd


class TestTheWin32Open:
    """The open on Windows: the link itself, refused by its attributes, nothing written first."""

    @pytest.mark.parametrize(
        ("flags", "disposition"),
        [
            (os.O_RDONLY, staging._OPEN_EXISTING),
            (os.O_WRONLY | os.O_TRUNC, staging._OPEN_EXISTING),
            (os.O_WRONLY | os.O_CREAT, staging._OPEN_ALWAYS),
            (os.O_WRONLY | os.O_CREAT | os.O_TRUNC, staging._OPEN_ALWAYS),
            (os.O_WRONLY | os.O_CREAT | os.O_EXCL, staging._CREATE_NEW),
            (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC, staging._CREATE_NEW),
        ],
    )
    def test_the_disposition_is_the_c_runtime_s_without_truncating(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, flags: int, disposition: int
    ) -> None:
        assert staging.creation_disposition(flags) == disposition
        files = _Win32Files(monkeypatch)
        target = tmp_path / "f"
        target.write_bytes(b"x")
        os.close(staging.open_no_follow(target, flags))
        assert files.created[0][4] == disposition

    def test_the_link_itself_is_opened_unshared_for_delete_and_not_impersonable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        files = _Win32Files(monkeypatch)
        target = tmp_path / "f"
        target.write_bytes(PAYLOAD)
        fd = staging.open_no_follow(target, os.O_RDONLY)
        with os.fdopen(fd, "rb") as handle:
            assert handle.read() == PAYLOAD
        path, access, share, security, _disposition, attributes, template = files.created[0]
        assert path == str(target) and security is None and template is None
        assert access == staging._GENERIC_READ | staging._FILE_READ_ATTRIBUTES
        assert share == staging._FILE_SHARE_READ_WRITE
        assert attributes & staging._FILE_FLAG_OPEN_REPARSE_POINT
        assert attributes & staging._SECURITY_SQOS_PRESENT
        assert attributes & staging._SECURITY_IDENTIFICATION
        assert not attributes & staging._FILE_FLAG_BACKUP_SEMANTICS
        assert files.made == [getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)]

    def test_writing_asks_for_write_and_a_file_created_without_write_is_read_only(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        files = _Win32Files(monkeypatch)
        os.close(staging.open_no_follow(tmp_path / "w", os.O_WRONLY | os.O_CREAT, 0o600))
        os.close(staging.open_no_follow(tmp_path / "r", os.O_WRONLY | os.O_CREAT, 0o400))
        (_, written, *_, normal, _), (_, _, *_, read_only, _) = files.created
        assert written == staging._GENERIC_WRITE | staging._FILE_READ_ATTRIBUTES
        assert normal & staging._FILE_ATTRIBUTE_NORMAL
        assert read_only & staging._FILE_ATTRIBUTE_READONLY

    def test_a_reparse_point_is_refused_on_its_handle_before_anything_is_written(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        files = _Win32Files(monkeypatch, attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        target = tmp_path / "placeholder"
        target.write_bytes(b"somebody's bytes")
        with pytest.raises(OSError, match="never followed") as caught:
            staging.open_no_follow(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        assert caught.value.errno == errno.ELOOP
        assert target.read_bytes() == b"somebody's bytes"
        assert files.closed == [101] and files.made == []

    @pytest.mark.parametrize(
        ("error", "kind", "number"),
        [
            (80, FileExistsError, errno.EEXIST),
            (183, FileExistsError, errno.EEXIST),
            (2, FileNotFoundError, errno.ENOENT),
            (3, FileNotFoundError, errno.ENOENT),
            (5, PermissionError, errno.EACCES),
            (32, PermissionError, errno.EACCES),
            (33, PermissionError, errno.EACCES),
            (4, OSError, errno.EMFILE),
            (53, FileNotFoundError, errno.ENOENT),
            (67, FileNotFoundError, errno.ENOENT),
            (123, FileNotFoundError, errno.ENOENT),
            (161, FileNotFoundError, errno.ENOENT),
            (206, FileNotFoundError, errno.ENOENT),
            (87, OSError, errno.EINVAL),
        ],
    )
    def test_a_win32_failure_is_the_oserror_it_stands_for(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        error: int,
        kind: type[OSError],
        number: int,
    ) -> None:
        files = _Win32Files(monkeypatch, error=error)
        with pytest.raises(kind) as caught:
            staging.open_no_follow(tmp_path / "f", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        assert caught.value.errno == number
        assert files.closed == [] and files.made == []

    def test_a_handle_whose_attributes_cannot_be_read_is_closed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        files = _Win32Files(monkeypatch, error=5)
        files._error = 0
        files.info_fails = True
        with pytest.raises(OSError, match="GetFileInformationByHandle"):
            staging.open_no_follow(tmp_path / "f", os.O_WRONLY | os.O_CREAT)
        assert files.closed == [101] and files.made == []

    def test_a_handle_no_descriptor_is_made_of_is_closed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        files = _Win32Files(monkeypatch)

        def refusing(_handle: int, _flags: int) -> int:
            raise OSError(errno.EMFILE, "too many open files")

        kernel32 = SimpleNamespace(
            CreateFileW=files.create,
            GetFileInformationByHandle=files.information,
            CloseHandle=files.closed.append,
        )
        monkeypatch.setattr(
            staging, "_win32_files", lambda: (kernel32, SimpleNamespace(open_osfhandle=refusing))
        )
        with pytest.raises(OSError, match="too many open files"):
            staging.open_no_follow(tmp_path / "f", os.O_WRONLY | os.O_CREAT)
        assert files.closed == [101]

    def test_a_file_found_elsewhere_once_open_is_closed_and_never_truncated(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        files = _Win32Files(monkeypatch)
        target = tmp_path / "f"
        target.write_bytes(b"somebody's bytes")
        monkeypatch.setattr(staging, "descriptor_path", lambda _fd: str(tmp_path / "elsewhere"))
        real_close, closed = os.close, []
        monkeypatch.setattr(os, "close", lambda fd: closed.append(fd) or real_close(fd))
        with pytest.raises(OSError, match="somewhere else"):
            staging.open_no_follow(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        assert target.read_bytes() == b"somebody's bytes"
        assert len(closed) == 1 and files.made

    def test_a_file_in_place_is_truncated_once_checked(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _Win32Files(monkeypatch)
        target = tmp_path / "f"
        target.write_bytes(b"old and longer")
        fd = staging.open_no_follow(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.write(fd, b"new")
        os.close(fd)
        assert target.read_bytes() == b"new"

    def test_a_flag_it_does_not_map_is_refused_before_any_open(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        files = _Win32Files(monkeypatch)
        with pytest.raises(ValueError, match="cannot open with the flags"):
            staging.open_no_follow(tmp_path / "f", os.O_WRONLY | os.O_APPEND)
        assert files.created == []


class TestOwnershipFromAStatResult:
    @pytest.mark.skipif(not hasattr(os, "getuid"), reason="no user ids on this host")
    def test_posix_compares_user_ids(self) -> None:
        mine = SimpleNamespace(st_uid=os.getuid())
        theirs = SimpleNamespace(st_uid=os.getuid() + 1)
        assert staging.st_owned_by_this_user(mine)  # type: ignore[arg-type]
        assert not staging.st_owned_by_this_user(theirs)  # type: ignore[arg-type]

    def test_windows_tells_no_owner_from_a_stat_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        assert not staging.st_owned_by_this_user(SimpleNamespace(st_uid=0))  # type: ignore[arg-type]


def test_a_reparse_point_is_refused_as_a_private_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A OneDrive placeholder is no link and still never taken for a staging directory."""
    target = tmp_path / "placeholder"
    target.mkdir()
    real_lstat = Path.lstat
    placeholder = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
    )
    monkeypatch.setattr(
        Path, "lstat", lambda self: placeholder if self == target else real_lstat(self)
    )
    with pytest.raises(RuntimeError, match="is a reparse point"):
        staging.private_dir(target)


@needs_proc
@pytest.mark.posix
@pytest.mark.usefixtures("no_posix_flags")
def test_a_file_is_opened_beneath_its_root_with_no_link_followed_without_openat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    opened: list[str] = []
    real = staging._open_unless_a_link
    monkeypatch.setattr(
        staging,
        "_open_unless_a_link",
        lambda where, flags, mode: opened.append(where) or real(where, flags, mode),
    )
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "a" / "f").write_bytes(PAYLOAD)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f").write_bytes(b"not the job's")
    (root / "dirlink").symlink_to(outside, target_is_directory=True)
    (root / "a" / "filelink").symlink_to(outside / "f")
    os.link(outside / "f", root / "a" / "hard")
    for good in ("a/f", str(root / "a" / "f"), "./a/f"):
        fd = open_beneath(root, good, "the root")
        try:
            assert os.read(fd, 100) == PAYLOAD
        finally:
            os.close(fd)
    # Every open above went the way a system without O_NOFOLLOW goes.
    assert opened == [str(root / "a" / "f")] * 3
    for bad, said in (
        ("dirlink/f", "not inside the root"),
        ("a/filelink", "cannot be opened as a file"),
        ("../outside/f", "not inside the root"),
        ("a/../../outside/f", "not inside the root"),
        (str(outside / "f"), "not inside the root"),
        ("a", "not a regular file|cannot be opened as a file"),
        ("a/missing", "cannot be opened as a file"),
        ("a/hard", "2 hard links"),
    ):
        with pytest.raises(ValueError, match=said):
            open_beneath(root, bad, "the root")


@needs_proc
@pytest.mark.usefixtures("no_posix_flags")
def test_a_directory_swapped_below_the_root_after_the_walk_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "a" / "f").write_bytes(PAYLOAD)
    monkeypatch.setattr(staging, "descriptor_path", lambda _fd: str(tmp_path / "elsewhere" / "f"))
    with pytest.raises(ValueError, match="cannot be opened as a file inside the root"):
        open_beneath(root, "a/f", "the root")


@needs_proc
@pytest.mark.usefixtures("no_posix_flags")
class TestACopyIsHashedWithoutOpenat:
    def test_a_copy_in_place_is_hashed_and_never_set_blocking(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        copy = tmp_path / "copy"
        copy.write_bytes(PAYLOAD)
        monkeypatch.setattr(os, "set_blocking", lambda *_a: pytest.fail("a file is no pipe"))
        assert sample_integrity.file_sha256(copy, len(PAYLOAD)) == (
            hashlib.sha256(PAYLOAD).hexdigest(),
            "",
        )

    @pytest.mark.posix
    def test_a_link_at_the_copy_or_its_directory_is_a_failed_reading(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        (real / "copy").write_bytes(PAYLOAD)
        (tmp_path / "dirlink").symlink_to(real, target_is_directory=True)
        (real / "link").symlink_to(real / "copy")
        assert sample_integrity.file_sha256(tmp_path / "dirlink" / "copy") == ("", "OSError")
        assert sample_integrity.file_sha256(real / "link") == ("", "OSError")


@needs_proc
@pytest.mark.posix
@pytest.mark.usefixtures("no_posix_flags")
def test_a_copy_s_directory_swapped_for_a_link_after_its_check_is_a_failed_reading(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The path the copy must be at is fixed before the check, so a swap after it is caught."""
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "copy").write_bytes(b"real")
    (tmp_path / "evil").mkdir()
    (tmp_path / "evil" / "copy").write_bytes(b"evil bytes")
    real = staging.is_reparse_point

    def swapping(path: Path, info: os.stat_result) -> bool:
        answer = real(path, info)
        if path == tmp_path / "dir":
            os.rename(tmp_path / "dir", tmp_path / "dir.old")
            os.symlink(tmp_path / "evil", tmp_path / "dir")
        return answer

    monkeypatch.setattr(staging, "is_reparse_point", swapping)
    assert sample_integrity.file_sha256(tmp_path / "dir" / "copy") == ("", "OSError")


@needs_proc
@pytest.mark.posix
@pytest.mark.usefixtures("no_posix_flags")
class TestACaptureIsWrittenWithoutTheFlag:
    def test_the_cape_capture_is_written_and_a_link_refused(self, tmp_path: Path) -> None:
        out = tmp_path / "capture.pcap"
        CAPEv2Client._write_capture(_Chunks(PAYLOAD[:5], PAYLOAD[5:]), out)
        assert out.read_bytes() == PAYLOAD
        victim = tmp_path / "victim"
        victim.write_bytes(b"keep")
        (tmp_path / "link").symlink_to(victim)
        with pytest.raises(OSError, match="never followed"):
            CAPEv2Client._write_capture(_Chunks(b"x"), tmp_path / "link")
        assert victim.read_bytes() == b"keep"

    def test_the_capped_capture_is_written_and_a_link_refused(self, tmp_path: Path) -> None:
        out = tmp_path / "capture.pcap"
        stream_to_file_capped(_Chunks(PAYLOAD), out, what="The capture")
        assert out.read_bytes() == PAYLOAD
        victim = tmp_path / "victim"
        victim.write_bytes(b"keep")
        (tmp_path / "link").symlink_to(victim)
        with pytest.raises(OSError, match="never followed"):
            stream_to_file_capped(_Chunks(b"x"), tmp_path / "link", what="The capture")
        assert victim.read_bytes() == b"keep"

    def test_an_upload_is_read_as_its_bytes_and_a_link_refused(self, tmp_path: Path) -> None:
        source = tmp_path / "sample"
        source.write_bytes(PAYLOAD)
        with sample_staging._open_regular(source) as handle:
            assert handle.read() == PAYLOAD
        (tmp_path / "link").symlink_to(source)
        with pytest.raises(OSError, match="never followed"):
            sample_staging._open_regular(tmp_path / "link")


@pytest.fixture
def analysis_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """The analysis sidecar, staging under the test's own directory."""
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
    monkeypatch.delenv(staging.STAGING_JOB_ENV, raising=False)
    path = ROOT / "services" / "analysis-mcp" / "server.py"
    spec = importlib.util.spec_from_file_location("analysis_mcp_server_np", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


@needs_proc
@pytest.mark.posix
@pytest.mark.usefixtures("no_posix_flags")
def test_put_sample_writes_its_bytes_and_refuses_a_link_without_the_flag(
    analysis_server: Any, tmp_path: Path
) -> None:
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    written = analysis_server._write_sample("s.bin", PAYLOAD, digest)
    assert Path(written["path"]).read_bytes() == PAYLOAD
    Path(written["path"]).unlink()
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep")
    Path(written["path"]).symlink_to(victim)
    with pytest.raises(OSError, match="never followed"):
        analysis_server._write_sample("s.bin", PAYLOAD, digest)
    assert victim.read_bytes() == b"keep"
