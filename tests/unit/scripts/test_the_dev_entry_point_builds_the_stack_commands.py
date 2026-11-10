"""scripts/dev/malspark_dev.py builds the stack's commands the same on every OS.

The Makefile's recipes moved into one standard-library script, so a host
without make or a POSIX shell (native Windows) runs the same commands. Read
here from the plans the script builds, never from a running docker: the env
files as ``set -a; .`` and compose read them, the compose arguments per
command, the ids the backend containers run as with and without user ids, and
what a dry run and ``doctor`` say.
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
SHIPPED = ["-f", "docker/docker-compose.yml", "-f", "docker/docker-compose.dev.yml"]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "malspark_dev_under_test", ROOT / "scripts" / "dev" / "malspark_dev.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dev = _load()


def _uid(value: int) -> Callable[[], int]:
    return lambda: value


class TestEnvFilesAreReadAsTheShellAndComposeReadThem:
    def test_crlf_quotes_comments_spaces_and_export(self) -> None:
        text = (
            "# a comment\r\n"
            "PLAIN=value\r\n"
            "SINGLE='a b # not a comment'\r\n"
            'DOUBLE="say \\"hi\\" \\$HOME"\r\n'
            "  SPACED = 2001  # the docs group\r\n"
            "export EXPORTED=yes\n"
            "HASH=a#b\n"
            "EMPTY=\n"
            "not an assignment\n"
            "OPEN='unclosed\n"
        )
        assert dev.parse_env(text) == {
            "PLAIN": "value",
            "SINGLE": "a b # not a comment",
            "DOUBLE": 'say "hi" $HOME',
            "SPACED": "2001",
            "EXPORTED": "yes",
            "HASH": "a#b",
            "EMPTY": "",
            "OPEN": "unclosed",
        }

    def test_a_later_line_wins_and_a_byte_order_mark_is_not_part_of_the_name(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "x.env"
        path.write_bytes(b"\xef\xbb\xbfFIRST=1\nFIRST=2\n")
        assert dev.read_env(path) == {"FIRST": "2"}
        assert dev.read_env(tmp_path / "missing.env") == {}


class TestTheIdsTheBackendRunsAs:
    def test_a_plain_user_s_own_ids_are_used(self) -> None:
        assert dev.compose_ids({}, {}, _uid(1000), _uid(1001)) == {
            "MALSPARK_UID": "1000",
            "MALSPARK_GID": "1001",
        }

    def test_under_sudo_the_ids_are_the_invoking_user_s(self) -> None:
        environ = {"SUDO_UID": "1234", "SUDO_GID": "1235"}
        assert dev.compose_ids(environ, {}, _uid(0), _uid(0)) == {
            "MALSPARK_UID": "1234",
            "MALSPARK_GID": "1235",
        }

    def test_an_id_that_comes_out_root_falls_back_to_the_image_s(self) -> None:
        assert set(dev.compose_ids({}, {}, _uid(0), _uid(0)).values()) == {"10001"}
        sudo_root = {"SUDO_UID": "0", "SUDO_GID": "0"}
        assert set(dev.compose_ids(sudo_root, {}, _uid(0), _uid(0)).values()) == {"10001"}

    def test_docker_env_is_read_without_quotes_spaces_or_comment(self, tmp_path: Path) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text(
            "X=1\nMALSPARK_UID=\"2000\"\n  MALSPARK_GID = '2001'  # the docs group\r\n"
        )
        ids = dev.compose_ids({"SUDO_UID": "1234"}, dev.read_env(dotenv), _uid(0), _uid(0))
        assert ids == {"MALSPARK_UID": "2000", "MALSPARK_GID": "2001"}

    def test_the_environment_wins_over_docker_env(self) -> None:
        file_ids = {"MALSPARK_UID": "2000", "MALSPARK_GID": "2001"}
        ids = dev.compose_ids({"MALSPARK_UID": "3000"}, file_ids, _uid(1000), _uid(1000))
        assert ids == {"MALSPARK_UID": "3000", "MALSPARK_GID": "2001"}

    def test_a_host_without_user_ids_sets_neither(self) -> None:
        assert dev.compose_ids({}, {"MALSPARK_UID": "2000"}, None, None) == {}

    def test_the_context_finds_no_ids_where_os_has_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delattr(os, "getuid", raising=False)
        monkeypatch.delattr(os, "getgid", raising=False)
        ctx = dev.Context.here(ROOT)
        assert ctx.getuid is None and ctx.ids({}) == {}


def _checkout(
    tmp_path: Path, bootstrap: str | None = "FROM_BOOTSTRAP=yes\nSHARED=bootstrap\n"
) -> Path:
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / ".env").write_text("MALSPARK_GID=2001\n")
    if bootstrap is not None:
        (tmp_path / "bootstrap.env").write_text(bootstrap)
    return tmp_path


def _ctx(root: Path, extra: tuple[str, ...] = (), system: str = "Linux", **environ: str) -> Any:
    return dev.Context(
        root=root,
        environ={"SHARED": "shell", **environ},
        extra_files=extra,
        system=system,
        getuid=_uid(1000),
        getgid=_uid(1000),
    )


IDS = {"MALSPARK_UID": "1000", "MALSPARK_GID": "2001"}
BOOT = {"FROM_BOOTSTRAP": "yes", "SHARED": "bootstrap"}

# command -> [(argv after "docker", cwd relative to the checkout, variables added)]
EXPECTED: dict[str, list[tuple[list[str], str, dict[str, str]]]] = {
    "docker-build": [(["compose", "build"], "docker", {})],
    "docker-up": [(["compose", "up", "-d"], "docker", IDS)],
    "docker-down": [(["compose", "--profile", "*", "down"], "docker", {})],
    "docker-logs": [(["compose", "logs", "-f"], "docker", {})],
    "up": [(["compose", *SHIPPED, "up", "-d"], ".", {**BOOT, **IDS})],
    "down": [(["compose", *SHIPPED, "--profile", "*", "down"], ".", BOOT)],
    "logs": [(["compose", *SHIPPED, "logs", "-f"], ".", BOOT)],
    "fe-rebuild": [
        (["compose", "build", "frontend"], "docker", IDS),
        (["compose", "up", "-d", "--no-deps", "frontend"], "docker", IDS),
    ],
    "worker-restart": [(["restart", "malspark-worker"], ".", {})],
}


class TestEachCommandIsTheMakefileRecipe:
    @pytest.mark.parametrize("command", sorted(EXPECTED))
    def test_arguments_directory_and_variables(self, tmp_path: Path, command: str) -> None:
        root = _checkout(tmp_path)
        steps = dev.stack_plan(command, _ctx(root))
        got = [
            (list(s.argv[1:]), s.cwd.relative_to(root).as_posix() or ".", dict(s.env))
            for s in steps
        ]
        assert [s.argv[0] for s in steps] == ["docker"] * len(steps)
        assert got == EXPECTED[command]

    def test_migrate_runs_alembic_with_bootstrap_env_over_the_environment(
        self, tmp_path: Path
    ) -> None:
        root = _checkout(tmp_path)
        (step,) = dev.stack_plan("migrate", _ctx(root))
        assert step.argv == ("uv", "run", "--directory", "apps/api", "alembic", "upgrade", "head")
        assert step.cwd == root and dict(step.env) == BOOT

    def test_bootstrap_env_s_ids_win_over_docker_env_as_sourcing_it_did(
        self, tmp_path: Path
    ) -> None:
        root = _checkout(tmp_path, bootstrap="MALSPARK_UID=4242\n")
        (step,) = dev.stack_plan("up", _ctx(root))
        assert step.env["MALSPARK_UID"] == "4242" and step.env["MALSPARK_GID"] == "2001"

    def test_without_bootstrap_env_nothing_is_added_but_the_ids(self, tmp_path: Path) -> None:
        root = _checkout(tmp_path, bootstrap=None)
        (step,) = dev.stack_plan("up", _ctx(root))
        assert dict(step.env) == IDS

    def test_the_address_is_one_argument_after_a_double_dash(self, tmp_path: Path) -> None:
        address = "x'; touch canary; '$(id)\"-"
        (step,) = dev.stack_plan("create-admin", _ctx(_checkout(tmp_path)), address)
        assert step.argv[1:] == (
            "compose", "exec", "backend-api", "malspark", "create-admin", "--", address,
        )  # fmt: skip
        assert step.cwd == tmp_path / "docker"

    @pytest.mark.parametrize("command", ["up", "docker-up", "fe-rebuild"])
    def test_a_host_without_user_ids_adds_no_ids(self, tmp_path: Path, command: str) -> None:
        root = _checkout(tmp_path, bootstrap=None)
        ctx = dev.Context(root=root, environ={}, system="Windows")
        assert all(
            "MALSPARK_UID" not in s.env and "MALSPARK_GID" not in s.env
            for s in dev.stack_plan(command, ctx)
        )


class TestExtraComposeFiles:
    @pytest.mark.parametrize(
        ("command", "tail"),
        [("up", ["up", "-d"]), ("down", ["--profile", "*", "down"]), ("logs", ["logs", "-f"])],
    )
    def test_each_extra_file_is_appended_after_the_shipped_ones_in_order(
        self, tmp_path: Path, command: str, tail: list[str]
    ) -> None:
        ctx = _ctx(_checkout(tmp_path), extra=("docker/local.yml", "/srv/gpu.yml"))
        (step,) = dev.stack_plan(command, ctx)
        extra = ["-f", "docker/local.yml", "-f", "/srv/gpu.yml"]
        assert list(step.argv[1:]) == ["compose", *SHIPPED, *extra, *tail]

    def test_the_variable_is_split_on_white_space_and_the_option_comes_after_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COMPOSE_FILE_EXTRA", "docker/local.yml  /srv/gpu.yml")
        ctx = dev.Context.here(ROOT, ["mine.yml"])
        assert ctx.extra_files == ("docker/local.yml", "/srv/gpu.yml", "mine.yml")

    def test_the_production_stack_takes_no_file_and_reads_compose_s_override_itself(
        self, tmp_path: Path
    ) -> None:
        ctx = _ctx(_checkout(tmp_path), extra=("docker/local.yml",))
        (step,) = dev.stack_plan("docker-up", ctx)
        assert "-f" not in step.argv


class TestTheHostOverlayHook:
    def _with_overlay(self, tmp_path: Path) -> Path:
        root = _checkout(tmp_path, bootstrap=None)
        (root / dev.NAMED_DATA_OVERLAY).write_text("services: {}\n")
        return root

    def test_linux_keeps_the_bind_mount_even_with_the_overlay_there(self, tmp_path: Path) -> None:
        assert dev.host_overlays(self._with_overlay(tmp_path), "Linux") == []

    def test_another_host_has_none_until_the_overlay_exists(self, tmp_path: Path) -> None:
        assert dev.host_overlays(_checkout(tmp_path, bootstrap=None), "Darwin") == []

    def test_another_host_adds_it_before_the_extra_files(self, tmp_path: Path) -> None:
        root = self._with_overlay(tmp_path)
        (step,) = dev.stack_plan("up", _ctx(root, extra=("x.yml",), system="Windows"))
        files = [a for a in step.argv if a.endswith(".yml")]
        assert files == [*SHIPPED[1::2], dev.NAMED_DATA_OVERLAY, "x.yml"]

    def test_the_production_stack_names_what_compose_would_have_read_before_it(
        self, tmp_path: Path
    ) -> None:
        root = self._with_overlay(tmp_path)
        (root / "docker" / "docker-compose.override.yml").write_text("services: {}\n")
        (step,) = dev.stack_plan("docker-up", _ctx(root, system="Darwin"))
        assert list(step.argv[2:8]) == [
            "-f", "docker-compose.yml",
            "-f", "docker-compose.override.yml",
            "-f", Path(dev.NAMED_DATA_OVERLAY).name,
        ]  # fmt: skip


class TestRunningAndDryRuns:
    def test_a_dry_run_names_every_variable_and_shows_no_secret(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _checkout(tmp_path, bootstrap="JWT_SECRET_KEY=hunter2-not-for-print\n")
        monkeypatch.delenv("COMPOSE_FILE_EXTRA", raising=False)
        assert dev.main(["dev-up", "--dry-run", "-f", "mine.yml"], root=root) == 0
        said = capsys.readouterr().out
        assert "hunter2" not in said
        assert "JWT_SECRET_KEY" in said
        assert "docker compose -f docker/docker-compose.yml" in said and "-f mine.yml up -d" in said

    def test_create_admin_takes_an_address_that_starts_with_a_dash(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _checkout(tmp_path)
        assert dev.main(["create-admin", "--dry-run", "--", "-x@example.com"], root=root) == 0
        assert "create-admin -- -x@example.com" in capsys.readouterr().out

    def test_an_empty_address_is_refused_with_the_usage(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert dev.main(["create-admin", ""], root=_checkout(tmp_path)) == 2
        assert "usage" in capsys.readouterr().err

    def test_steps_run_in_turn_with_their_variables_and_stop_at_the_first_failure(
        self, tmp_path: Path
    ) -> None:
        out = tmp_path / "out.txt"
        write = f"import os; open({str(out)!r}, 'a').write(os.environ['ADDED'] + '\\n')"
        steps = [
            dev.Step((sys.executable, "-c", write), tmp_path, {"ADDED": "one"}),
            dev.Step((sys.executable, "-c", "raise SystemExit(3)"), tmp_path),
            dev.Step((sys.executable, "-c", write), tmp_path, {"ADDED": "never"}),
        ]
        assert dev.run_steps(steps, dict(os.environ), tmp_path) == 3
        assert out.read_text().splitlines() == ["one"]

    def test_a_program_that_is_not_there_is_named_with_how_to_get_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        step = dev.Step(("docker", "info"), tmp_path)
        assert dev.run_steps([step], {"PATH": str(tmp_path)}, tmp_path) == 127
        assert "docker is not on PATH: install Docker Desktop" in capsys.readouterr().err

    def test_docker_up_names_each_corpus_external_has_not_fetched(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = _checkout(tmp_path)
        (root / "data" / "capa-rules").mkdir(parents=True)
        assert dev.main(["docker-up", "--dry-run"], root=root) == 0
        warned = capsys.readouterr().err
        assert "data/sigma_rules is missing" in warned and "make external" in warned
        assert "data/capa-signatures is missing" in warned
        assert "data/capa-rules is" not in warned


def _doctor(
    tmp_path: Path,
    engine: str | None = "linux 28.1.1",
    compose: str | None = "2.40.3",
    taken: frozenset[int] = frozenset(),
    filesystem: str | None = None,
    path: str | None = None,
) -> list[str]:
    root = tmp_path
    (root / "docker").mkdir(exist_ok=True)
    (root / "docker" / "docker-compose.yml").write_text(
        (ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    name = "docker.exe" if os.name == "nt" else "docker"
    (shims / name).write_text("")
    (shims / name).chmod(0o755)

    def probe(argv: object) -> str | None:
        return engine if "version" in list(argv)[1:2] else compose  # type: ignore[call-overload]

    return list(
        dev.doctor_report(
            root,
            {"PATH": str(shims) if path is None else path},
            probe=probe,
            in_use=lambda host, port: port in taken,
            filesystem=lambda _path: filesystem,
        )
    )


class TestDoctor:
    def test_a_ready_host(self, tmp_path: Path) -> None:
        said = "\n".join(_doctor(tmp_path))
        assert "engine   Linux containers, server 28.1.1" in said
        assert "compose  2.40.3" in said
        assert "every published port is free" in said
        assert "missing  docker/.env: run env init" in said
        assert "data/sigma_rules missing" in said and "external/ghidra-mcp missing" in said
        assert "external/ik_llama.cpp" not in said
        assert "Python" in said

    def test_windows_containers_mode_and_a_silent_engine_are_named(self, tmp_path: Path) -> None:
        assert any("switch Docker Desktop to Linux" in s for s in _doctor(tmp_path, "windows 28"))
        assert any("does not answer" in s for s in _doctor(tmp_path, engine=None))

    def test_a_missing_docker_and_compose_plugin_are_named(self, tmp_path: Path) -> None:
        assert any(s.startswith("  missing  docker:") for s in _doctor(tmp_path, path=""))
        assert any("compose plugin" in s for s in _doctor(tmp_path, compose=None))

    def test_ports_in_use_are_listed_with_their_variable(self, tmp_path: Path) -> None:
        said = "\n".join(_doctor(tmp_path, taken=frozenset({5432, 8000})))
        assert "5432 (POSTGRES_PORT)" in said and "8000 (API_PORT)" in said
        assert "set API_PORT or POSTGRES_PORT in docker/.env, and the same port" in said
        assert "bootstrap.env's DATABASE_URL" in said

    def test_a_checkout_on_ntfs_is_warned_about(self, tmp_path: Path) -> None:
        assert any("on NTFS" in s for s in _doctor(tmp_path, filesystem="NTFS"))
        assert not any("NTFS" in s for s in _doctor(tmp_path, filesystem=None))

    def test_a_port_check_sees_a_listener(self) -> None:
        import socket

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            assert dev.port_in_use("127.0.0.1", listener.getsockname()[1])


class TestSetup:
    def test_a_stack_user_s_setup_syncs_nothing_on_the_host(self) -> None:
        assert dev.setup_plan(ROOT, dev=False) == []

    def test_a_developer_s_setup_syncs_every_extra_and_installs_pre_commit(self) -> None:
        assert [s.argv for s in dev.setup_plan(ROOT, dev=True)] == [
            ("uv", "sync", "--all-extras", "--all-packages"),
            ("uv", "run", "pre-commit", "install"),
        ]

    def test_the_script_needs_only_the_standard_library(self) -> None:
        import ast

        tree = ast.parse((ROOT / "scripts" / "dev" / "malspark_dev.py").read_text("utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0
        }
        assert imported <= set(sys.stdlib_module_names) | {"__future__"}, imported


def test_where_posix_is_missing_the_stack_commands_run_and_set_no_ids() -> None:
    """Under tests/without_posix.py, as on Windows: no os.getuid, no ids, the same commands."""
    import subprocess

    code = (
        "import sys; sys.argv = ['malspark_dev.py', 'up', '--dry-run'];"
        f"import runpy; runpy.run_path({str(ROOT / 'scripts' / 'dev' / 'malspark_dev.py')!r},"
        " run_name='__main__')"
    )
    done = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "without_posix.py"), "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert (
        "docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml"
        in done.stdout
    )
    assert "MALSPARK_UID" not in done.stdout


def test_on_windows_git_runs_with_long_paths_and_a_long_checkout_is_warned_about(
    tmp_path: Path,
) -> None:
    assert dev.GIT[0] == "git"
    assert ("core.longpaths=true" in dev.GIT) == (os.name == "nt")
    # On every host, whatever its git config: no line ending is rewritten.
    assert {"core.autocrlf=false", "core.eol=lf"} <= set(dev.GIT)
    deep = tmp_path / ("d" * 70)
    deep.mkdir()
    (deep / "docker").mkdir()
    (deep / "docker" / "docker-compose.yml").write_text("{}\n")

    def said(windows: bool) -> list[str]:
        return list(
            dev.doctor_report(
                deep,
                {"PATH": ""},
                probe=lambda argv: None,
                in_use=lambda host, port: False,
                filesystem=lambda _path: None,
                windows=windows,
            )
        )

    assert any("characters long" in line for line in said(windows=True))
    assert not any("characters long" in line for line in said(windows=False))


def test_a_character_the_console_cannot_encode_is_printed_escaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Windows console piped to a file encodes in its code page; any path still prints."""
    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    err = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    dev._console_takes_any_text()
    dev._say("  ok       tree at C:\\Users\\Kişi")
    dev._fail("  FAIL     Kişi")
    out.flush()
    err.flush()
    assert (
        out.buffer.getvalue() == b"  ok       tree at C:\\Users\\Ki\\u015fi" + os.linesep.encode()
    )
    assert err.buffer.getvalue() == b"  FAIL     Ki\\u015fi" + os.linesep.encode()
