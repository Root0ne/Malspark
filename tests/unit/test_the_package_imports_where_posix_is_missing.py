"""The package imports, and says what it cannot do, on a host without POSIX.

Windows has no ``resource`` or ``fcntl``, no ``O_NOFOLLOW``, no ``SIGKILL``,
no process groups and no user ids. A Linux run takes them away
(``tests/without_posix.py``) and the entry points still import and the locale
pin still runs. What needs one of them answers with a reason saying it is
unavailable on this platform, as a tool error, instead of failing at import
or running without the bound it is held to.
"""

from __future__ import annotations

import ctypes
import os
import signal
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.worker import sample_files
from malspark.core import ctype_locale
from malspark.providers.static import capa_yara
from malspark.tools import children, emulated_strings, staging

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"

# Every module of both packages, every server under services/ and the locale
# pin. A package's ``__main__`` runs its program rather than defining it.
_IMPORTS = """
import importlib, importlib.util, pkgutil, sys
from pathlib import Path
import app, malspark
for package in (malspark, app):
    for found in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        if not found.name.endswith(".__main__"):
            importlib.import_module(found.name)
servers = sorted(Path("services").glob("*/server.py"))
for path in [Path("services/cli-sidecar/cli_sidecar.py"), *servers]:
    name = "cli_sidecar" if path.stem == "cli_sidecar" else path.parent.name.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
from malspark.core.ctype_locale import pin_character_classification
pin_character_classification(lambda level, text: None)
print("imported")
"""


def _without_posix(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter and a script of this repository
        [sys.executable, str(ROOT / "tests" / "without_posix.py"), *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
        check=False,
    )


def test_every_module_and_server_imports_and_the_locale_pins_without_posix() -> None:
    finished = _without_posix("-c", _IMPORTS)
    assert finished.returncode == 0, finished.stderr[-4000:]
    assert finished.stdout.strip().endswith("imported")


@pytest.mark.slow
def test_the_suite_collects_without_posix() -> None:
    finished = _without_posix(
        "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "tests"
    )
    assert finished.returncode == 0, (finished.stdout[-4000:], finished.stderr[-4000:])


class TestFlossWithoutProcessGroups:
    def test_a_run_is_refused_with_the_reason(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delattr(os, "killpg", raising=False)
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ")
        answer = emulated_strings._emulate("floss", sample, 4, 5, emulated_strings._run)
        assert answer == f"FLOSS could not be started: {emulated_strings.NO_PROCESS_GROUPS}"
        assert "unavailable on this platform" in answer

    def test_the_probe_says_floss_cannot_run_here(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delattr(os, "setsid", raising=False)
        monkeypatch.setattr(emulated_strings, "_RUNS", {})
        build = tmp_path / "floss"
        build.write_bytes(b"\x7fELF")
        reason = emulated_strings._does_not_run(build)
        assert reason == (
            f"floss cannot be executed on this host: {emulated_strings.NO_PROCESS_GROUPS}"
        )
        assert list(emulated_strings._RUNS.values()) == [reason]

    def test_without_resource_a_run_is_uncapped_and_says_so(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(emulated_strings, "resource", None)
        assert emulated_strings._limit_address_space(os.getpid()) is False


class TestKillingWithoutProcessGroups:
    def test_the_process_alone_is_killed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delattr(os, "killpg", raising=False)
        monkeypatch.delattr(os, "getpgrp", raising=False)
        killed: list[tuple[int, int]] = []
        monkeypatch.setattr(os, "kill", lambda pid, number: killed.append((pid, number)))
        children.kill_process_group(424242)
        assert killed == [(424242, children._KILL)]

    def test_this_process_is_still_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delattr(os, "killpg", raising=False)
        monkeypatch.delattr(os, "getpgrp", raising=False)
        killed: list[Any] = []
        monkeypatch.setattr(os, "kill", lambda *args: killed.append(args))
        for pid in (0, 1, os.getpid()):
            children.kill_process_group(pid)
        assert killed == []

    def test_the_handlers_skip_a_signal_the_host_lacks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delattr(signal, "SIGHUP", raising=False)
        installed: list[int] = []
        monkeypatch.setattr(signal, "signal", lambda number, _handler: installed.append(number))
        children.kill_all_on_exit()
        assert installed == [signal.SIGTERM, signal.SIGINT]


class TestCapaWithoutWait4:
    def _child(self, code: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen(  # noqa: S603 - this interpreter
            [sys.executable, "-c", code], stdout=subprocess.PIPE
        )

    def test_an_ended_child_is_reaped_without_usage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delattr(os, "wait4", raising=False)
        process = self._child("pass")
        assert capa_yara._ended(process, 60, capa_yara.time.monotonic()) == (0, None)

    def test_a_stopped_child_is_killed_without_usage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delattr(os, "wait4", raising=False)
        monkeypatch.setattr(capa_yara, "_GRACE_SECONDS", 0.05)
        process = self._child(
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)"
        )
        assert process.stdout is not None
        assert process.stdout.readline().strip() == b"ready"  # the SIGTERM is ignored
        assert capa_yara._stop(process) is None
        assert process.returncode is not None


class TestOwnership:
    @pytest.mark.skipif(not hasattr(os, "getuid"), reason="no user ids on this host")
    def test_posix_compares_user_ids(self, tmp_path: Path) -> None:
        mine = SimpleNamespace(st_uid=os.getuid())
        theirs = SimpleNamespace(st_uid=os.getuid() + 1)
        assert staging.owned_by_this_user(tmp_path, mine)  # type: ignore[arg-type]
        assert not staging.owned_by_this_user(tmp_path, theirs)  # type: ignore[arg-type]

    def test_a_posix_host_without_user_ids_answers_no(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delattr(os, "getuid", raising=False)
        assert not staging.owned_by_this_user(tmp_path, SimpleNamespace(st_uid=0))  # type: ignore[arg-type]


class TestOwnershipOnWindows:
    """The owner SID of the file against the user, or the default owner, of this process."""

    @pytest.fixture(autouse=True)
    def _windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")

    def _owned(self, tmp_path: Path) -> bool:
        return staging.owned_by_this_user(tmp_path, SimpleNamespace(st_uid=0))  # type: ignore[arg-type]

    def _sids(self, monkeypatch: pytest.MonkeyPatch, owner: bytes) -> None:
        monkeypatch.setattr(staging, "_owner_sid", lambda _path: owner)
        monkeypatch.setattr(staging, "_process_sids", lambda: frozenset({b"user", b"admins"}))

    def test_the_user_s_own_sid_is_this_user(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._sids(monkeypatch, b"user")
        assert self._owned(tmp_path)

    def test_the_owner_an_elevated_token_gives_is_this_user(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._sids(monkeypatch, b"admins")
        assert self._owned(tmp_path)

    def test_another_sid_is_not(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self._sids(monkeypatch, b"someone else")
        assert not self._owned(tmp_path)

    def test_a_reparse_point_is_never_this_user_s(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._sids(monkeypatch, b"user")
        junction = SimpleNamespace(st_uid=0, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        assert not staging.owned_by_this_user(tmp_path, junction)  # type: ignore[arg-type]

    def test_a_file_the_system_will_not_open_is_not(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from ctypes import wintypes

        opened: list[tuple[Any, ...]] = []

        def create(*args: Any) -> Any:
            opened.append(args)
            return wintypes.HANDLE(-1).value  # INVALID_HANDLE_VALUE

        kernel32 = SimpleNamespace(CreateFileW=create)
        monkeypatch.setattr(staging, "_win32", lambda: (SimpleNamespace(), kernel32))
        assert not self._owned(tmp_path)
        # The link itself is opened, never the directory it leads to.
        flags = opened[0][5]
        assert flags & staging._FILE_FLAG_OPEN_REPARSE_POINT
        assert flags & staging._FILE_FLAG_BACKUP_SEMANTICS

    def test_a_descriptor_the_system_refuses_is_not_and_the_handle_is_closed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        closed: list[Any] = []
        advapi32 = SimpleNamespace(GetSecurityInfo=lambda *_args: 5)  # access denied
        kernel32 = SimpleNamespace(CreateFileW=lambda *_args: 42, CloseHandle=closed.append)
        monkeypatch.setattr(staging, "_win32", lambda: (advapi32, kernel32))
        assert not self._owned(tmp_path)
        assert closed == [42]

    @pytest.mark.parametrize(("elevated", "expected"), [(False, {b"u"}), (True, {b"u", b"o"})])
    def test_the_token_s_owner_counts_only_while_it_is_elevated(
        self, monkeypatch: pytest.MonkeyPatch, elevated: bool, expected: set[bytes]
    ) -> None:
        closed: list[Any] = []
        advapi32 = SimpleNamespace(OpenProcessToken=lambda *_args: 1)
        kernel32 = SimpleNamespace(GetCurrentProcess=lambda: -1, CloseHandle=closed.append)
        monkeypatch.setattr(staging, "_win32", lambda: (advapi32, kernel32))
        sids = {staging._TOKEN_USER: b"u", staging._TOKEN_OWNER: b"o"}
        monkeypatch.setattr(staging, "_token_sid", lambda _api, _token, kind: sids[kind])
        monkeypatch.setattr(staging, "_token_elevated", lambda _api, _token: elevated)
        assert staging._process_sids() == expected
        assert len(closed) == 1

    def test_a_token_the_system_refuses_is_not(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(staging, "_owner_sid", lambda _path: b"user")
        advapi32 = SimpleNamespace(OpenProcessToken=lambda *_args: 0)
        kernel32 = SimpleNamespace(GetCurrentProcess=lambda: -1)
        monkeypatch.setattr(staging, "_win32", lambda: (advapi32, kernel32))
        monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
        assert not self._owned(tmp_path)

    def test_no_win32_api_is_not(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.delattr(ctypes, "WinDLL", raising=False)
        assert not self._owned(tmp_path)


@pytest.mark.skipif(sys.platform != "win32", reason="the owner SID is read on Windows only")
def test_a_directory_this_process_made_is_its_own_on_windows(tmp_path: Path) -> None:
    made = tmp_path / "mine"
    made.mkdir()
    assert staging.owned_by_this_user(made, made.lstat())
    assert staging.private_dir(made) == made


class TestAJunctionIsALink:
    """A junction is not reported by ``is_symlink``; staging treats it as the link it is."""

    def _junction(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        monkeypatch.setattr(Path, "is_junction", lambda self: self.name == name)

    def test_removing_a_tree_never_enters_a_junction_inside_it(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        root = tmp_path / "job"
        (root / "junction").mkdir(parents=True)
        precious = root / "junction" / "precious"
        precious.write_bytes(b"keep")
        (root / "payload").write_bytes(b"x")
        self._junction(monkeypatch, "junction")
        staging.remove_tree(root)
        # Only the link is removed (here a real directory, which unlink refuses).
        assert precious.read_bytes() == b"keep"
        assert not (root / "payload").exists()

    def test_a_junction_at_the_root_is_not_emptied(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        root = tmp_path / "junction"
        root.mkdir()
        (root / "precious").write_bytes(b"keep")
        self._junction(monkeypatch, "junction")
        assert staging.remove_tree(root) is False
        assert (root / "precious").read_bytes() == b"keep"

    def test_a_junction_is_refused_as_a_private_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        (tmp_path / "junction").mkdir()
        self._junction(monkeypatch, "junction")
        with pytest.raises(RuntimeError, match="is a symlink"):
            staging.private_dir(tmp_path / "junction")


class TestSampleCopiesWithoutPosix:
    @pytest.mark.parametrize(
        ("missing", "present"), [("O_NOFOLLOW", "O_DIRECTORY"), ("O_DIRECTORY", "O_NOFOLLOW")]
    )
    def test_a_missing_flag_is_named(
        self, monkeypatch: pytest.MonkeyPatch, missing: str, present: str
    ) -> None:
        # The other flag is there, so this one is the one named (Windows has neither).
        monkeypatch.setattr(os, present, getattr(os, present, 0o400000), raising=False)
        monkeypatch.delattr(os, missing, raising=False)
        with pytest.raises(sample_files.NotPosix, match=f"os.{missing}, which is unavailable"):
            sample_files._dir_flags()

    def test_a_missing_lock_is_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sample_files, "fcntl", None)
        with (
            pytest.raises(sample_files.NotPosix, match="fcntl.flock, which is unavailable"),
            sample_files._locked(0),
        ):
            pass


class TestTheLocalePinOnWindows:
    def test_the_universal_c_runtime_is_asked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        asked: list[Any] = []
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(ctypes, "CDLL", lambda name: asked.append(name) or name)
        assert ctype_locale._libc() == "ucrtbase"
        assert asked == ["ucrtbase"]

    def test_msvcrt_where_it_is_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def load(name: Any) -> Any:
            if name == "ucrtbase":
                raise OSError(name)
            return name

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(ctypes, "CDLL", load)
        assert ctype_locale._libc() == "msvcrt"
