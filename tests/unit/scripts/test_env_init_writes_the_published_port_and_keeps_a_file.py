"""``env init`` writes docker/.env and bootstrap.env that agree, and never takes a file.

docker/.env gets generated secrets where its example leaves a required value
empty; bootstrap.env gets the same database password, settings key and JWT
secret, and a DATABASE_URL on the port the compose file publishes Postgres on.
A file already there is left as it is unless ``--force`` is given, and then
every value it set is kept. No secret value is printed.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import re
import shutil
import sys
import urllib.parse
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]
SECRETS = (
    "GHIDRA_MCP_AUTH_TOKEN",
    "REDIS_PASSWORD",
    "QDRANT_API_KEY",
    "POSTGRES_PASSWORD",
    "MINIO_ROOT_PASSWORD",
    "SETTINGS_ENCRYPTION_KEY",
    "JWT_SECRET_KEY",
)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "malspark_dev_env_under_test", ROOT / "scripts" / "dev" / "malspark_dev.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dev = _load()


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    for path in ("docker/.env.example", "docker/docker-compose.yml", "bootstrap.env.example"):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / path, tmp_path / path)
    return tmp_path


def _url(root: Path) -> urllib.parse.SplitResult:
    return urllib.parse.urlsplit(dev.read_env(root / "bootstrap.env")["DATABASE_URL"])


class TestAFreshCheckout:
    def test_both_files_are_written_and_agree(self, checkout: Path) -> None:
        assert dev.env_init(checkout, {}) == 0
        docker = dev.read_env(checkout / "docker" / ".env")
        boot = dev.read_env(checkout / "bootstrap.env")

        assert all(docker[key] for key in SECRETS)
        assert len(set(docker[key] for key in SECRETS)) == len(SECRETS)
        assert len(base64.urlsafe_b64decode(docker["SETTINGS_ENCRYPTION_KEY"])) == 32
        assert re.fullmatch(r"[0-9a-f]{64}", docker["JWT_SECRET_KEY"])
        url = _url(checkout)
        assert url.scheme == "postgresql+asyncpg" and url.hostname == "127.0.0.1"
        assert urllib.parse.unquote(url.password or "") == docker["POSTGRES_PASSWORD"]
        assert url.port == 5432
        for key in ("SETTINGS_ENCRYPTION_KEY", "JWT_SECRET_KEY"):
            assert boot[key] == docker[key]
        assert boot["MINIO_SECRET_KEY"] == docker["MINIO_ROOT_PASSWORD"]
        assert boot["MINIO_ACCESS_KEY"] == docker["MINIO_ROOT_USER"]
        assert boot["REDIS_URL"].endswith("@127.0.0.1:6379/0")

    def test_the_settings_key_is_one_fernet_reads(self, checkout: Path) -> None:
        fernet = pytest.importorskip("cryptography.fernet")
        dev.env_init(checkout, {})
        key = dev.read_env(checkout / "docker" / ".env")["SETTINGS_ENCRYPTION_KEY"]
        assert fernet.Fernet(key.encode()).decrypt(fernet.Fernet(key.encode()).encrypt(b"x"))

    def test_no_secret_value_is_printed(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dev.env_init(checkout, {})
        said = capsys.readouterr()
        docker = dev.read_env(checkout / "docker" / ".env")
        for key in SECRETS:
            assert docker[key] not in said.out + said.err

    def test_the_comments_of_the_example_are_kept(self, checkout: Path) -> None:
        dev.env_init(checkout, {})
        written = (checkout / "docker" / ".env").read_text(encoding="utf-8")
        example = (ROOT / "docker" / ".env.example").read_text(encoding="utf-8")
        comments = [line for line in example.splitlines() if line.startswith("#")]
        assert [line for line in written.splitlines() if line.startswith("#")] == comments

    @pytest.mark.skipif(os.name != "posix", reason="mode bits")
    def test_both_files_are_readable_by_their_owner_only(self, checkout: Path) -> None:
        dev.env_init(checkout, {})
        for path in (checkout / "docker" / ".env", checkout / "bootstrap.env"):
            assert path.stat().st_mode & 0o777 == 0o600


class TestThePortIsTheOneComposePublishes:
    def test_the_shipped_files_agree_on_the_host_port(self) -> None:
        published = dev.published_ports(ROOT)["POSTGRES_PORT"]
        example = dev.read_env(ROOT / "bootstrap.env.example")["DATABASE_URL"]
        assert published == 5432
        api = (ROOT / "apps" / "api" / "app" / "config.py").read_text(encoding="utf-8")
        assert f"@127.0.0.1:{published}/malspark" in api
        assert example.split("@", 1)[1].startswith(f"127.0.0.1:{published}/")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        assert "POSTGRES_PORT" not in makefile, "the compose file alone names the default"

    def test_a_port_set_in_docker_env_is_the_one_written(self, checkout: Path) -> None:
        dev.env_init(checkout, {})
        (checkout / "bootstrap.env").unlink()
        with (checkout / "docker" / ".env").open("a", encoding="utf-8") as env:
            env.write("POSTGRES_PORT=6001\nBIND_ADDRESS=0.0.0.0\n")
        assert dev.env_init(checkout, {}) == 0
        assert _url(checkout).port == 6001 and _url(checkout).hostname == "127.0.0.1"

    def test_the_environment_wins_over_docker_env_as_in_compose(self, checkout: Path) -> None:
        dev.env_init(checkout, {"POSTGRES_PORT": "6002", "BIND_ADDRESS": "10.0.0.5"})
        assert _url(checkout).port == 6002 and _url(checkout).hostname == "10.0.0.5"


class TestAFileAlreadyThere:
    def test_a_second_run_changes_nothing(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dev.env_init(checkout, {})
        before = [(checkout / p).read_bytes() for p in ("docker/.env", "bootstrap.env")]
        assert dev.env_init(checkout, {}) == 0
        assert [(checkout / p).read_bytes() for p in ("docker/.env", "bootstrap.env")] == before
        assert capsys.readouterr().out.count("left as it is") == 2

    def test_force_rewrites_but_keeps_every_value_set(self, checkout: Path) -> None:
        dev.env_init(checkout, {})
        docker_path = checkout / "docker" / ".env"
        before = dev.read_env(docker_path)
        with docker_path.open("a", encoding="utf-8") as env:
            env.write("MY_OWN=kept\n")
        with (checkout / "bootstrap.env").open("a", encoding="utf-8") as env:
            env.write("DEBUG=true\n")

        assert dev.env_init(checkout, {}, force=True) == 0

        after = dev.read_env(docker_path)
        assert all(after[key] == before[key] for key in SECRETS)
        assert after["MY_OWN"] == "kept"
        assert dev.read_env(checkout / "bootstrap.env")["DEBUG"] == "true"

    def test_an_existing_docker_env_without_a_password_writes_no_bootstrap_env(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        shutil.copy(checkout / "docker" / ".env.example", checkout / "docker" / ".env")
        assert dev.env_init(checkout, {}) == 1
        assert not (checkout / "bootstrap.env").exists()
        assert "docker/.env sets no POSTGRES_PASSWORD" in capsys.readouterr().err

    def test_a_password_with_url_characters_is_quoted_in_the_url(self, checkout: Path) -> None:
        dev.env_init(checkout, {})
        (checkout / "bootstrap.env").unlink()
        docker_path = checkout / "docker" / ".env"
        text = re.sub(
            r"^POSTGRES_PASSWORD=.*$",
            "POSTGRES_PASSWORD='p@ss:w/rd%'",
            docker_path.read_text(encoding="utf-8"),
            flags=re.M,
        )
        docker_path.write_text(text, encoding="utf-8")
        dev.env_init(checkout, {})
        assert urllib.parse.unquote(_url(checkout).password or "") == "p@ss:w/rd%"


class TestTheTwoFilesNeverDisagree:
    def test_a_new_docker_env_derives_an_existing_bootstrap_env_s_shared_values_again(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (checkout / "bootstrap.env").write_text(
            "DATABASE_URL=postgresql+asyncpg://malspark:OLD@127.0.0.1:5432/malspark\n"
            "JWT_SECRET_KEY=old-secret-old-secret-old-secret-x\nDEBUG=true\n",
            encoding="utf-8",
        )
        assert dev.env_init(checkout, {}) == 0
        docker = dev.read_env(checkout / "docker" / ".env")
        boot = dev.read_env(checkout / "bootstrap.env")
        assert urllib.parse.unquote(_url(checkout).password or "") == docker["POSTGRES_PASSWORD"]
        for key in ("SETTINGS_ENCRYPTION_KEY", "JWT_SECRET_KEY"):
            assert boot[key] == docker[key]
        assert boot["DEBUG"] == "true"
        assert "derived again from the new docker/.env: DATABASE_URL" in capsys.readouterr().out


class TestForceKeepsWhatTheUserSet:
    def test_an_empty_assignment_is_kept_and_only_an_empty_secret_is_filled(
        self, checkout: Path
    ) -> None:
        docker_path = checkout / "docker" / ".env"
        docker_path.write_text(
            "COMPOSE_PROFILES=\nPOSTGRES_PASSWORD=mine\nREDIS_PASSWORD=\n", encoding="utf-8"
        )
        assert dev.env_init(checkout, {}, force=True) == 0
        lines = docker_path.read_text(encoding="utf-8").splitlines()
        assert "COMPOSE_PROFILES=" in lines and "POSTGRES_PASSWORD=mine" in lines
        assert dev.read_env(docker_path)["REDIS_PASSWORD"]

    def test_a_derived_value_of_one_s_own_is_kept_and_a_placeholder_is_replaced(
        self, checkout: Path
    ) -> None:
        dev.env_init(checkout, {})
        boot_path = checkout / "bootstrap.env"
        own = "postgresql+asyncpg://app:x@db.example.com:6543/prod"
        text = re.sub(
            r"^DATABASE_URL=.*$", f"DATABASE_URL={own}", boot_path.read_text(), flags=re.M
        )
        text = re.sub(r"^REDIS_URL=.*$", "REDIS_URL=redis://:<password>@h:1/0", text, flags=re.M)
        boot_path.write_text(text, encoding="utf-8")

        assert dev.env_init(checkout, {}, force=True) == 0

        boot = dev.read_env(boot_path)
        assert boot["DATABASE_URL"] == own
        assert "<password>" not in boot["REDIS_URL"] and boot["REDIS_URL"].endswith(":6379/0")


@pytest.mark.parametrize(
    "value",
    ["plain-Token_1.2:3@x%2F+=,", "a b #c", "it's", 'say "$HOME" \\ it\'s', "back`quote $x", ""],
)
def test_a_written_value_reads_back_unchanged(value: str) -> None:
    assert dev.parse_env(f"KEY={dev.env_quote(value)}\n") == {"KEY": value}


def test_a_secret_with_url_and_shell_characters_survives_both_files(checkout: Path) -> None:
    docker_path = checkout / "docker" / ".env"
    docker_path.write_text('MINIO_ROOT_PASSWORD="a b #c"\nMINIO_ROOT_USER=me\n', encoding="utf-8")
    dev.env_init(checkout, {}, force=True)
    assert dev.read_env(checkout / "bootstrap.env")["MINIO_SECRET_KEY"] == "a b #c"


@pytest.mark.skipif(os.name != "posix", reason="mode bits")
def test_a_file_that_holds_no_secret_is_readable_by_all(tmp_path: Path) -> None:
    dev._write_text(tmp_path / "PINNED.txt", "pin\n")
    dev._write_text(tmp_path / "secret.env", "X=1\n", private=True)
    assert (tmp_path / "PINNED.txt").stat().st_mode & 0o777 == 0o644
    assert (tmp_path / "secret.env").stat().st_mode & 0o777 == 0o600


class TestWhatIsKeptIsSaidAboutAndRefusedWhenUnsafe:
    def test_a_kept_url_that_no_longer_carries_the_password_is_warned_about_by_name(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dev.env_init(checkout, {})
        boot_before = dev.read_env(checkout / "bootstrap.env")["DATABASE_URL"]
        docker_path = checkout / "docker" / ".env"
        text = re.sub(
            r"^POSTGRES_PASSWORD=.*$",
            "POSTGRES_PASSWORD=rotated-secret",
            docker_path.read_text(encoding="utf-8"),
            flags=re.M,
        )
        docker_path.write_text(text, encoding="utf-8")
        capsys.readouterr()

        assert dev.env_init(checkout, {}, force=True) == 0

        said = capsys.readouterr().out
        assert (
            "warn     bootstrap.env DATABASE_URL does not carry docker/.env's POSTGRES_PASSWORD;"
            " kept as written" in said
        )
        assert "rotated-secret" not in said
        assert dev.read_env(checkout / "bootstrap.env")["DATABASE_URL"] == boot_before

    def test_without_force_the_message_says_what_force_would_do(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dev.env_init(checkout, {})
        dev.env_init(checkout, {})
        assert "(--force fills only what is empty)" in capsys.readouterr().out

    def test_a_kept_database_url_with_no_numeric_port_is_reported_as_kept(
        self, checkout: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dev.env_init(checkout, {})
        boot_path = checkout / "bootstrap.env"
        text = re.sub(
            r"^DATABASE_URL=.*$",
            "DATABASE_URL=postgresql+asyncpg://u:p@db:port/x",
            boot_path.read_text(encoding="utf-8"),
            flags=re.M,
        )
        boot_path.write_text(text, encoding="utf-8")
        assert dev.env_init(checkout, {}, force=True) == 0
        assert "(database URL kept as written)" in capsys.readouterr().out

    @pytest.mark.parametrize("raw", ["pa$word", '"pa$word"'])
    def test_a_dollar_compose_would_expand_is_refused_before_anything_is_written(
        self, checkout: Path, capsys: pytest.CaptureFixture[str], raw: str
    ) -> None:
        docker_path = checkout / "docker" / ".env"
        docker_path.write_text(f"POSTGRES_PASSWORD={raw}\n", encoding="utf-8")
        assert dev.env_init(checkout, {}, force=True) == 1
        err = capsys.readouterr().err
        assert "POSTGRES_PASSWORD holds a $ that compose would expand" in err
        assert "pa$word" not in err
        assert docker_path.read_text(encoding="utf-8") == f"POSTGRES_PASSWORD={raw}\n"
        assert not (checkout / "bootstrap.env").exists()

    def test_a_single_quoted_dollar_is_taken_literally(self, checkout: Path) -> None:
        (checkout / "docker" / ".env").write_text("POSTGRES_PASSWORD='pa$word'\n")
        assert dev.env_init(checkout, {}, force=True) == 0
        assert urllib.parse.unquote(_url(checkout).password or "") == "pa$word"


def test_a_value_with_both_quote_kinds_is_refused() -> None:
    with pytest.raises(ValueError, match="both ' and `"):
        dev.env_quote("it's `x`")
