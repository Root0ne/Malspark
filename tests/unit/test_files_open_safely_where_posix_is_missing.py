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
    tmp_path: Path,
) -> None:
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
