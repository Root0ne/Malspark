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

_IMPORTS = """
import importlib.util, sys
for name in ("malspark.cli", "malspark.app", "app.main", "app.worker.analysis_worker"):
    __import__(name)
for name, path in (
    ("cli_sidecar", "services/cli-sidecar/cli_sidecar.py"),
    ("unblob_mcp_server", "services/unblob-mcp/server.py"),
):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
from malspark.core.ctype_locale import pin_character_classification
pin_character_classification(lambda level, text: None)
print("imported")
"""


def test_the_entry_points_import_and_pin_the_locale_without_posix() -> None:
    finished = subprocess.run(  # noqa: S603 - this interpreter and a script of this repository
        [sys.executable, str(ROOT / "tests" / "without_posix.py"), "-c", _IMPORTS],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr[-4000:]
    assert finished.stdout.strip().endswith("imported")


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


class TestOwnershipWithoutUserIds:
    @pytest.mark.skipif(not hasattr(os, "getuid"), reason="no user ids on this host")
    def test_posix_compares_user_ids(self) -> None:
        mine = SimpleNamespace(st_uid=os.getuid())
        theirs = SimpleNamespace(st_uid=os.getuid() + 1)
        assert staging.owned_by_this_user(mine)  # type: ignore[arg-type]
        assert not staging.owned_by_this_user(theirs)  # type: ignore[arg-type]

    def test_a_host_without_user_ids_answers_yes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delattr(os, "getuid", raising=False)
        assert staging.owned_by_this_user(SimpleNamespace(st_uid=0))  # type: ignore[arg-type]


class TestSampleCopiesWithoutPosix:
    def test_a_missing_flag_is_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
        with pytest.raises(sample_files.NotPosix, match="os.O_NOFOLLOW, which is unavailable"):
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
