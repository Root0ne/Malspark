"""An env file that cannot be read ends the command with one line, never a traceback.

docker/.env that is unreadable, a directory or not UTF-8 text stops ``doctor``,
``up``, ``docker-up`` and ``env init`` with one line naming the path and what is
wrong, and a non-zero exit; none of the file's bytes reach the output. A file
that is not there keeps its old behaviour.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]
# Joined at call time: a whole KEY=value line is a credential to a secret scanner.
_MARK = "".join(("sentinel", "-", "bytes"))
COMMANDS = (["doctor"], ["up", "--dry-run"], ["docker-up", "--dry-run"], ["env", "init"])


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "malspark_dev_unreadable_under_test", ROOT / "scripts" / "dev" / "malspark_dev.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dev = _load()


@pytest.fixture
def checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for path in ("docker/.env.example", "docker/docker-compose.yml", "bootstrap.env.example"):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / path, tmp_path / path)
    # No docker on the path: doctor probes nothing.
    monkeypatch.setenv("PATH", "")
    return tmp_path


def _unreadable(path: Path) -> None:
    path.write_text(f"X_KEY={_MARK}\n", encoding="utf-8")
    path.chmod(0)


def _directory(path: Path) -> None:
    path.mkdir()
    (path / "inner").write_text(_MARK, encoding="utf-8")


def _not_utf8(path: Path) -> None:
    path.write_bytes(b"X_KEY=" + _MARK.encode() + b"\xff\xfe\x80\n")


def _skip_unless_modes_apply() -> None:
    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("a mode that denies reading binds neither Windows nor root")


CASES: list[tuple[str, Callable[[Path], None], str]] = [
    ("unreadable", _unreadable, "cannot be read"),
    ("directory", _directory, "is a directory"),
    ("not-utf8", _not_utf8, "is not UTF-8 text"),
]


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: " ".join(c))
@pytest.mark.parametrize(("name", "make", "said"), CASES, ids=[c[0] for c in CASES])
def test_the_command_ends_in_one_clean_line(
    checkout: Path,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
    name: str,
    make: Callable[[Path], None],
    said: str,
) -> None:
    if name == "unreadable":
        _skip_unless_modes_apply()
    target = checkout / "docker" / ".env"
    make(target)
    try:
        status = dev.main(command, root=checkout)
    finally:
        if name == "unreadable":
            target.chmod(0o600)
    shown = capsys.readouterr()
    text = shown.out + shown.err

    assert status != 0
    assert "Traceback" not in text
    assert _MARK not in text and "\\xff" not in text
    failing = [line for line in text.splitlines() if "FAIL" in line]
    assert len(failing) == 1
    assert str(target) in failing[0] and said in failing[0]


@pytest.mark.parametrize("command", [["doctor"], ["up", "--dry-run"]], ids=" ".join)
def test_a_file_that_is_not_there_keeps_its_old_behaviour(
    checkout: Path, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    assert dev.main(command, root=checkout) == 0
    shown = capsys.readouterr()
    assert "FAIL" not in shown.out + shown.err


def test_env_init_called_on_its_own_returns_the_status_instead_of_raising(
    checkout: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _directory(checkout / "docker" / ".env")

    assert dev.env_init(checkout, {}) != 0
    assert "is a directory" in capsys.readouterr().err


def _search_denied(root: Path) -> Path:
    """A valid docker/.env in a folder that can be read but not searched."""
    target = root / "docker" / ".env"
    target.write_text("X_KEY=value\n", encoding="utf-8")
    target.parent.chmod(0o600)
    return target


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: " ".join(c))
def test_a_folder_that_cannot_be_searched_gives_the_clean_line(
    checkout: Path, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    _skip_unless_modes_apply()
    target = _search_denied(checkout)
    try:
        status = dev.main(command, root=checkout)
    finally:
        target.parent.chmod(0o700)
    shown = capsys.readouterr()
    text = shown.out + shown.err

    assert status != 0
    assert "Traceback" not in text
    failing = [line for line in text.splitlines() if "FAIL" in line]
    assert any(str(target) in line for line in failing)
    assert all("cannot be read" in line for line in failing)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="a FIFO needs POSIX")
@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: " ".join(c))
def test_a_fifo_at_the_path_is_named_and_never_opened(
    checkout: Path, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    target = checkout / "docker" / ".env"
    os.mkfifo(target)
    # An open for reading would block here: a watchdog turns a hang into a failure.
    opened: list[object] = []
    real_open = Path.read_text

    def refuse(self: Path, *args: object, **kwargs: object) -> str:
        if self == target:
            opened.append(self)
            raise AssertionError("the FIFO was opened")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    mp = pytest.MonkeyPatch()
    mp.setattr(Path, "read_text", refuse)
    try:
        status = dev.main(command, root=checkout)
    finally:
        mp.undo()
    shown = capsys.readouterr()
    text = shown.out + shown.err

    assert not opened
    assert status != 0
    assert "Traceback" not in text
    failing = [line for line in text.splitlines() if "FAIL" in line]
    assert len(failing) == 1
    assert str(target) in failing[0] and "is not a regular file" in failing[0]


def test_doctor_goes_on_past_an_unreadable_file_and_still_fails(
    checkout: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _directory(checkout / "bootstrap.env")

    status = dev.main(["doctor"], root=checkout)
    shown = capsys.readouterr()

    assert status != 0
    assert "bootstrap.env is a directory" in shown.err
    assert "  ports    " in shown.out or "  in use   " in shown.out
    assert "  tree     " in shown.out and "  data     " in shown.out


def test_doctor_goes_on_past_an_unreadable_docker_env_too(
    checkout: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _directory(checkout / "docker" / ".env")

    status = dev.main(["doctor"], root=checkout)
    shown = capsys.readouterr()

    assert status != 0
    assert shown.err.count("FAIL") == 1
    assert "  tree     " in shown.out and "  data     " in shown.out
    assert "missing  docker/.env" not in shown.out
