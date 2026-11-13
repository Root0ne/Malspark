"""A job may carry launch arguments for its sandbox: one bounded command line, kept as sent."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.schemas.job import JobCreateRequest
from app.worker.analysis_worker import build_job_settings, job_launch_arguments
from malspark.providers.submission import LAUNCH_ARGUMENTS_MAX_CHARS

ARGS = '--password "s3cr3t value" /S'


def test_launch_arguments_are_accepted_and_stored_as_written() -> None:
    request = JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_launch_arguments": ARGS})

    assert request.config == {"sandbox_launch_arguments": ARGS}


def test_the_longest_value_is_accepted() -> None:
    value = "x" * LAUNCH_ARGUMENTS_MAX_CHARS
    request = JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_launch_arguments": value})

    assert request.config == {"sandbox_launch_arguments": value}


@pytest.mark.parametrize(
    ("value", "said"),
    [
        ("x" * (LAUNCH_ARGUMENTS_MAX_CHARS + 1), "at most 1024 characters"),
        ("  ", "must hold some text"),
        ("-a\n-b", "control character"),
        (["-a", "-b"], "sandbox_launch_arguments"),
        (7, "sandbox_launch_arguments"),
        (True, "sandbox_launch_arguments"),
    ],
)
def test_a_value_that_is_not_one_command_line_is_refused(value: object, said: str) -> None:
    with pytest.raises(ValueError, match=said):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_launch_arguments": value})


def test_an_explicit_null_is_refused_like_every_other_known_key() -> None:
    with pytest.raises(
        ValueError, match="explicit null is not allowed for: sandbox_launch_arguments"
    ):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_launch_arguments": None})


def test_the_worker_hands_them_on_and_the_settings_ignore_them() -> None:
    config = {"sandbox_launch_arguments": ARGS}

    assert job_launch_arguments(config) == ARGS
    assert job_launch_arguments({}) == ""
    assert job_launch_arguments(None) == ""
    assert job_launch_arguments({"sandbox_launch_arguments": 7}) == ""
    assert build_job_settings({}, config) == build_job_settings({}, None)


class TestTheCommandLine:
    def _invoke(self, monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> tuple[Any, Any]:
        from typer.testing import CliRunner

        from malspark import cli

        ran: dict[str, Any] = {}

        class _App:
            def __init__(self, **_kwargs: Any) -> None:
                pass

            def run(self, **kwargs: Any) -> dict[str, Any]:
                ran.update(kwargs)
                return {"stix_output": {}, "run_summary": None}

            def remember_the_run(self) -> bool:
                return False

        monkeypatch.setattr(cli, "MalsparkApp", _App)
        monkeypatch.setattr(cli, "_release", lambda _app: None)
        result = CliRunner().invoke(cli.app, ["analyze", "sample_1", "--mock", *argv])
        return ran, result

    def test_the_option_reaches_the_run_verbatim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ran, result = self._invoke(monkeypatch, ["--sandbox-launch-arguments", ARGS])

        assert result.exit_code == 0, result.output
        assert ran["launch_arguments"] == ARGS

    def test_without_it_the_run_asks_for_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ran, result = self._invoke(monkeypatch, [])

        assert result.exit_code == 0, result.output
        assert ran["launch_arguments"] is None

    def test_a_value_the_job_would_refuse_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        too_long = "x" * (LAUNCH_ARGUMENTS_MAX_CHARS + 1)
        ran, result = self._invoke(monkeypatch, ["--sandbox-launch-arguments", too_long])

        assert result.exit_code == 2
        assert ran == {}
