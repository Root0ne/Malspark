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


@pytest.mark.parametrize("system", ["Linux", "Darwin", "Windows"])
@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: " ".join(c))
def test_a_folder_that_cannot_be_searched_gives_the_clean_line(
    checkout: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    command: list[str],
    system: str,
) -> None:
    _skip_unless_modes_apply()
    # The files a command probes depend on the host: Darwin and Windows take branches Linux skips.
    monkeypatch.setattr(dev.platform, "system", lambda: system)
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
    assert any(str(target.parent) in line for line in failing)
    assert all("cannot be read" in line or "cannot be examined" in line for line in failing)


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


def _report(
    root: Path,
    in_use: Callable[[str, int], bool],
    system: str | None = None,
    environ: dict[str, str] | None = None,
    filesystem: Callable[[Path], str | None] = lambda path: None,
) -> list[str]:
    """Doctor's lines, up to the stop an unreadable file ends it with."""
    lines: list[str] = []
    try:
        for line in dev.doctor_report(
            root,
            {"PATH": "", **(environ or {})},
            probe=lambda argv: None,
            in_use=in_use,
            filesystem=filesystem,
            system=system,
        ):
            lines.append(line)
    except dev.Stop:
        pass
    return lines


def test_doctor_does_not_state_what_it_cannot_know_without_docker_env(checkout: Path) -> None:
    shutil.copy(ROOT / "docker" / "docker-compose.named-data.yml", checkout / "docker")
    _directory(checkout / "docker" / ".env")
    probed: list[tuple[str, int]] = []

    def in_use(host: str, port: int) -> bool:
        probed.append((host, port))
        return False

    text = "\n".join(_report(checkout, in_use, system="Darwin"))

    assert probed == []
    assert "  ports    not checked: docker/.env could not be read" in text
    assert "  volumes  not checked: docker/.env could not be read" in text
    assert "  secrets  not checked: docker/.env could not be read" in text
    assert "  derived  not checked: docker/.env could not be read" in text
    assert "every published port is free" not in text and "malspark_samples" not in text
    assert "  tree     " in text and "  data     " in text and "  machine  " in text


def test_doctor_does_not_check_derived_values_without_bootstrap_env(checkout: Path) -> None:
    (checkout / "docker" / ".env").write_text("X_KEY=value\n", encoding="utf-8")
    _directory(checkout / "bootstrap.env")

    text = "\n".join(_report(checkout, lambda host, port: False))

    assert "  derived  not checked: bootstrap.env could not be read" in text
    assert "  ports    every published port is free" in text
    assert "  secrets  " not in text


def test_doctor_does_not_check_ports_without_the_compose_file(checkout: Path) -> None:
    _skip_unless_modes_apply()
    (checkout / "docker" / ".env").write_text("X_KEY=value\n", encoding="utf-8")
    compose = checkout / "docker" / "docker-compose.yml"
    compose.chmod(0)
    try:
        text = "\n".join(_report(checkout, lambda host, port: False))
    finally:
        compose.chmod(0o600)

    assert "  ports    not checked: docker/docker-compose.yml could not be read" in text
    assert "  tree     " in text


def test_a_port_probe_error_is_never_reported_as_an_unreadable_file(
    checkout: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(host: str, port: int) -> bool:
        raise OSError("probe failed")

    with pytest.raises(OSError, match="probe failed"):
        _report(checkout, broken)

    assert "FAIL" not in capsys.readouterr().err


def _compose_not_utf8(path: Path) -> None:
    path.unlink()
    path.write_bytes(b"services: " + _MARK.encode() + b"\xff\xfe\n")


def _compose_fifo(path: Path) -> None:
    path.unlink()
    os.mkfifo(path)


COMPOSE_CASES = [
    pytest.param(_compose_not_utf8, "is not UTF-8 text", id="not-utf8"),
    pytest.param(
        _compose_fifo,
        "is not a regular file",
        id="fifo",
        marks=pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="a FIFO needs POSIX"),
    ),
]


@pytest.mark.parametrize(("make", "said"), COMPOSE_CASES)
def test_doctor_names_a_compose_file_that_cannot_be_read(
    checkout: Path, capsys: pytest.CaptureFixture[str], make: Callable[[Path], None], said: str
) -> None:
    target = checkout / "docker" / "docker-compose.yml"
    make(target)

    status = dev.main(["doctor"], root=checkout)
    shown = capsys.readouterr()
    text = shown.out + shown.err

    assert status != 0
    assert "Traceback" not in text and _MARK not in text
    assert [line for line in shown.err.splitlines() if str(target) in line and said in line]
    assert "  ports    not checked: docker/docker-compose.yml could not be read" in shown.out
    assert "  tree     " in shown.out


@pytest.mark.parametrize("command", [["up", "--dry-run"], ["docker-up", "--dry-run"]], ids=" ".join)
@pytest.mark.parametrize(("make", "said"), COMPOSE_CASES)
def test_the_stack_commands_do_not_read_the_compose_file_themselves(
    checkout: Path,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
    make: Callable[[Path], None],
    said: str,
) -> None:
    make(checkout / "docker" / "docker-compose.yml")

    assert dev.main(command, root=checkout) == 0
    shown = capsys.readouterr()
    assert "Traceback" not in shown.out + shown.err


@pytest.mark.parametrize("example", ["docker/.env.example", "bootstrap.env.example"])
def test_env_init_names_an_example_file_that_is_not_utf8(
    checkout: Path, capsys: pytest.CaptureFixture[str], example: str
) -> None:
    target = checkout / example
    target.write_bytes(b"X_KEY=" + _MARK.encode() + b"\xff\n")

    status = dev.main(["env", "init"], root=checkout)
    shown = capsys.readouterr()
    text = shown.out + shown.err

    assert status != 0
    assert "Traceback" not in text and _MARK not in text
    assert [
        line for line in text.splitlines() if str(target) in line and "is not UTF-8 text" in line
    ]


def test_a_missing_example_file_keeps_its_old_error(checkout: Path) -> None:
    (checkout / "docker" / ".env.example").unlink()

    with pytest.raises(FileNotFoundError, match=r"\.env\.example"):
        dev.main(["env", "init"], root=checkout)


def test_what_stands_at_a_path_is_told_apart_without_raising(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("x", encoding="utf-8")
    (tmp_path / "folder").mkdir()
    assert dev._examine(tmp_path / "missing") == dev.ABSENT
    assert dev._examine(tmp_path / "file" / "below") == dev.ABSENT
    assert dev._examine(tmp_path / "file") == dev.FILE
    assert dev._examine(tmp_path / "folder") == dev.DIRECTORY
    if hasattr(os, "symlink"):
        os.symlink(tmp_path / "nowhere", tmp_path / "dangling")
        assert dev._examine(tmp_path / "dangling") == dev.ABSENT
    if hasattr(os, "mkfifo"):
        os.mkfifo(tmp_path / "pipe")
        assert dev._examine(tmp_path / "pipe") == dev.OTHER


def test_a_path_that_cannot_be_examined_is_not_taken_for_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _skip_unless_modes_apply()
    (tmp_path / "folder").mkdir()
    (tmp_path / "folder" / "file").write_text("x", encoding="utf-8")
    (tmp_path / "folder").chmod(0o600)
    try:
        assert dev._examine(tmp_path / "folder" / "file") == dev.DENIED
        with pytest.raises(dev.Stop):
            dev._is_file(tmp_path / "folder" / "file")
    finally:
        (tmp_path / "folder").chmod(0o700)
    assert "cannot be examined" in capsys.readouterr().err


def test_doctor_says_what_it_could_not_examine_and_goes_on(checkout: Path) -> None:
    _skip_unless_modes_apply()
    shutil.copy(ROOT / "docker" / "docker-compose.named-data.yml", checkout / "docker")
    (checkout / "external").mkdir()
    (checkout / "external" / "x").mkdir()
    (checkout / "external").chmod(0o600)
    try:
        text = "\n".join(_report(checkout, lambda host, port: False, system="Darwin"))
    finally:
        (checkout / "external").chmod(0o700)

    assert "  tree     external/" in text and "not checked: cannot be examined" in text
    assert "  ports    every published port is free" in text
    assert "  machine  " in text


def test_doctor_says_the_overlay_could_not_be_examined(checkout: Path) -> None:
    _skip_unless_modes_apply()
    (checkout / "docker").chmod(0o600)
    try:
        text = "\n".join(_report(checkout, lambda host, port: False, system="Darwin"))
    finally:
        (checkout / "docker").chmod(0o700)

    assert (
        "  volumes  not checked: docker/docker-compose.named-data.yml could not be examined" in text
    )
    assert "  tree     " in text


@pytest.mark.parametrize("given", ["", "   ", "[]"])
def test_an_empty_bind_address_probes_the_compose_default(checkout: Path, given: str) -> None:
    (checkout / "docker" / ".env").write_text("BIND_ADDRESS=10.9.9.9\n", encoding="utf-8")
    probed: list[str] = []

    def in_use(host: str, port: int) -> bool:
        probed.append(host)
        return False

    _report(checkout, in_use, environ={"BIND_ADDRESS": given})

    assert probed and set(probed) == {dev.LOOPBACK}


def test_a_bind_address_is_resolved_as_compose_does(checkout: Path) -> None:
    (checkout / "docker" / ".env").write_text("BIND_ADDRESS=10.9.9.9\n", encoding="utf-8")
    probed: list[str] = []

    def in_use(host: str, port: int) -> bool:
        probed.append(host)
        return False

    _report(checkout, in_use)
    assert set(probed) == {"10.9.9.9"}
    probed.clear()
    _report(checkout, in_use, environ={"BIND_ADDRESS": "0.0.0.0"})
    assert set(probed) == {dev.LOOPBACK}


@pytest.mark.parametrize("host", ["", "[]"])
def test_the_port_probe_never_binds_an_empty_address(
    monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    bound: list[tuple[str, int]] = []

    class Probe:
        def __init__(self, *args: object) -> None:
            pass

        def __enter__(self) -> Probe:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def setsockopt(self, *args: object) -> None:
            return None

        def bind(self, address: tuple[str, int]) -> None:
            bound.append(address)

    monkeypatch.setattr(dev.socket, "socket", Probe)

    assert dev.port_in_use(host, 4242) is False
    assert bound == [(dev.LOOPBACK, 4242)]


def test_doctor_does_not_guess_the_volumes_it_could_not_see_for_the_ntfs_warning(
    checkout: Path,
) -> None:
    _skip_unless_modes_apply()
    (checkout / "docker").chmod(0o600)
    try:
        lines = _report(
            checkout, lambda host, port: False, system="Windows", filesystem=lambda p: "NTFS"
        )
    finally:
        (checkout / "docker").chmod(0o700)
    text = "\n".join(lines)

    line = next(ln for ln in lines if "on NTFS" in ln)
    assert line.endswith(
        "carries no Linux owner or mode, and whether the stack keeps samples and uploads"
        " on named volumes was not checked"
    )
    assert "do not keep the ownership" not in text
    assert "  volumes  not checked: docker/docker-compose.named-data.yml" in text
