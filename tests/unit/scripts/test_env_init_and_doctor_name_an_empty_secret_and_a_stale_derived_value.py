"""``env init`` and ``doctor`` name an empty secret and a derived value that lost its source.

An existing docker/.env that holds a secret key with no value gets one line
naming the key and pointing to ``env init --force``; a bootstrap.env value
derived from docker/.env that no longer carries its source gets one line naming
both keys. Neither line carries a value, and a healthy pair of files gets none.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "malspark_dev_checks_under_test", ROOT / "scripts" / "dev" / "malspark_dev.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dev = _load()
# Values joined at call time: a whole PASSWORD=value line is a credential to a scanner.
_OTHER = "-".join(("other", "key", "value"))
_MOVED = "-".join(("moved", "away", "value"))


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    for path in ("docker/.env.example", "docker/docker-compose.yml", "bootstrap.env.example"):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / path, tmp_path / path)
    assert dev.env_init(tmp_path, {}) == 0
    return tmp_path


def _set(path: Path, key: str, value: str) -> None:
    lines = [
        ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.startswith(key + "=")
    ]
    path.write_text("\n".join([*lines, f"{key}={value}"]) + "\n", encoding="utf-8")


def _doctor(root: Path) -> str:
    quiet = dict(probe=lambda argv: None, in_use=lambda host, port: False)
    return "\n".join(dev.doctor_report(root, {"PATH": ""}, filesystem=lambda p: None, **quiet))


def _init(root: Path, capsys: pytest.CaptureFixture[str]) -> str:
    assert dev.env_init(root, {}) == 0
    return capsys.readouterr().out


def _value_of(root: Path, key: str) -> str:
    return dev.read_env(root / "docker" / ".env")[key]


class TestAnEmptySecret:
    def test_env_init_names_the_key_and_points_to_force(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _set(checkout / "docker" / ".env", "REDIS_PASSWORD", "")
        other = _value_of(checkout, "QDRANT_API_KEY")
        capsys.readouterr()
        out = _init(checkout, capsys)

        line = next(ln for ln in out.splitlines() if "REDIS_PASSWORD" in ln)
        assert "empty" in line and "env init --force" in line
        assert other not in out

    def test_doctor_reports_it_as_missing_and_names_the_key(self, checkout: Path) -> None:
        _set(checkout / "docker" / ".env", "REDIS_PASSWORD", "")
        out = _doctor(checkout)

        line = next(ln for ln in out.splitlines() if "REDIS_PASSWORD" in ln)
        assert line.startswith("  missing  ") and "env init --force" in line
        assert _value_of(checkout, "QDRANT_API_KEY") not in out

    def test_a_forced_run_fills_it_and_then_says_nothing(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _set(checkout / "docker" / ".env", "REDIS_PASSWORD", "")
        assert dev.env_init(checkout, {}, force=True) == 0
        capsys.readouterr()
        assert " is empty;" not in _init(checkout, capsys)
        assert " is empty;" not in _doctor(checkout)


class TestADerivedValueThatLostItsSource:
    def _drift(self, root: Path) -> None:
        _set(root / "bootstrap.env", "MINIO_SECRET_KEY", _MOVED)

    def test_plain_env_init_names_both_keys(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._drift(checkout)
        capsys.readouterr()
        out = _init(checkout, capsys)

        line = next(ln for ln in out.splitlines() if "does not carry" in ln)
        assert "MINIO_SECRET_KEY" in line and "MINIO_ROOT_PASSWORD" in line
        assert "env init --force" in line
        assert _MOVED not in out and _value_of(checkout, "MINIO_ROOT_PASSWORD") not in out

    def test_doctor_names_both_keys(self, checkout: Path) -> None:
        self._drift(checkout)
        out = _doctor(checkout)

        line = next(ln for ln in out.splitlines() if "does not carry" in ln)
        assert "MINIO_SECRET_KEY" in line and "MINIO_ROOT_PASSWORD" in line
        assert "env init --force" in line
        assert _MOVED not in out and _value_of(checkout, "MINIO_ROOT_PASSWORD") not in out

    def test_a_url_that_lost_the_password_is_named_too(self, checkout: Path) -> None:
        _set(checkout / "docker" / ".env", "REDIS_PASSWORD", _OTHER)
        out = _doctor(checkout)

        assert any("REDIS_URL" in ln and "REDIS_PASSWORD" in ln for ln in out.splitlines())
        assert _OTHER not in out


class TestAHealthyPair:
    def test_env_init_prints_none_of_the_new_lines(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        capsys.readouterr()
        out = _init(checkout, capsys)
        assert " is empty;" not in out and "does not carry" not in out

    def test_doctor_prints_none_of_the_new_lines(self, checkout: Path) -> None:
        out = _doctor(checkout)
        assert " is empty;" not in out and "does not carry" not in out
