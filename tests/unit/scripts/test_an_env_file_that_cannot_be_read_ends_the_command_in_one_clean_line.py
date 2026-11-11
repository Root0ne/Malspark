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
    assert "FAIL" not in capsys.readouterr().out


def test_env_init_called_on_its_own_returns_the_status_instead_of_raising(
    checkout: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _directory(checkout / "docker" / ".env")

    assert dev.env_init(checkout, {}) != 0
    assert "is a directory" in capsys.readouterr().err
