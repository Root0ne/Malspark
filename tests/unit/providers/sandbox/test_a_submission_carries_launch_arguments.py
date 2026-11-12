"""A job's launch arguments reach the sandbox each provider's own way, or are said not to.

Every request is captured on a mocked transport: the exact form a submission
sends with and without the arguments. A job that asks for none sends the
request it always sent. Synthetic bytes only; nothing is detonated.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from malspark.core.config import Settings
from malspark.loaders.cape2_client import CAPEv2Client
from malspark.providers.base import SandboxCapabilities, SandboxProvider
from malspark.providers.sandbox.cape2 import CAPE2SandboxProvider
from malspark.providers.sandbox.mock import MockSandboxProvider
from malspark.providers.sandbox.rest import RestSandboxProvider
from malspark.providers.sandbox.triage import TriageSandboxProvider
from malspark.providers.sandbox.upload import UploadSandboxProvider
from malspark.providers.submission import (
    LAUNCH_ARGUMENTS_MAX_CHARS,
    LaunchArgumentsAnswer,
    SubmissionOptions,
    answer_of,
    launch_arguments_problem,
    launch_record,
    not_honoured_reason,
)
from tests.unit.providers.sandbox.test_submit_format_options import _form_fields

ARGS = '--password "s3cr3t value" -k=1'
WITH = SubmissionOptions(launch_arguments=ARGS)


def _pe(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ" + b"\x00" * 64)
    return path


# ---------------------------------------------------------------------------
# CAPE: its own option string, composed with the deployment's
# ---------------------------------------------------------------------------
def _cape(tmp_path: Path, captured: list[httpx.Request], **over) -> CAPE2SandboxProvider:
    cfg = Settings(_env_file=None)
    for key, value in over.items():
        setattr(cfg.sandbox.cape2, key, value)
    provider = CAPE2SandboxProvider.from_settings(cfg)

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"error": False, "data": {"task_ids": [7]}})

    client = CAPEv2Client(base_url="https://cape.example")
    client._http = httpx.Client(
        base_url="https://cape.example", transport=httpx.MockTransport(handler)
    )
    provider._client = client
    return provider


class TestCape:
    def test_it_declares_it_can_pass_them(self) -> None:
        provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
        assert provider.capabilities.can_pass_launch_arguments is True
        assert provider.launch_arguments_answer(ARGS) == LaunchArgumentsAnswer(honoured=True)

    def test_without_arguments_the_request_is_unchanged(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        provider = _cape(tmp_path, captured, submit_options={"options": "procmemdump=1"})
        assert provider.submit(_pe(tmp_path)) == "7"
        provider.submit(_pe(tmp_path), options=SubmissionOptions())
        assert _form_fields(captured[0]) == {"platform": "windows", "options": "procmemdump=1"}
        assert _form_fields(captured[1]) == _form_fields(captured[0])

    def test_the_arguments_ride_in_the_options_string(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        provider = _cape(tmp_path, captured)
        provider.submit(_pe(tmp_path), options=WITH)
        assert _form_fields(captured[0]) == {"platform": "windows", "options": f"arguments={ARGS}"}

    def test_the_deployment_s_options_are_kept_beside_them(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        provider = _cape(
            tmp_path,
            captured,
            submit_options={"options": "procmemdump=1,syscall=1", "route": "internet"},
        )
        provider.submit(_pe(tmp_path), options=WITH)
        assert _form_fields(captured[0]) == {
            "platform": "windows",
            "options": f"procmemdump=1,syscall=1,arguments={ARGS}",
            "route": "internet",
        }
        assert provider.launch_arguments_answer(ARGS) == LaunchArgumentsAnswer(honoured=True)

    def test_the_job_s_arguments_replace_the_deployment_s_and_say_so(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        provider = _cape(
            tmp_path, captured, submit_options={"options": "arguments=/quiet,procmemdump=1"}
        )
        provider.submit(_pe(tmp_path), options=WITH)
        assert _form_fields(captured[0])["options"] == f"procmemdump=1,arguments={ARGS}"
        answer = provider.launch_arguments_answer(ARGS)
        assert answer.honoured is True
        assert answer.note == (
            "they replace the arguments '/quiet' that sandbox.cape2.submit_options sets on "
            "every submission"
        )

    def test_a_comma_cannot_be_carried_and_is_not_honoured(self) -> None:
        provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
        answer = provider.launch_arguments_answer("a,b")
        assert answer.honoured is False
        assert "separates its options with commas" in answer.note

    def test_spaces_cape_trims_are_noted(self) -> None:
        provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
        answer = provider.launch_arguments_answer(" -x ")
        assert answer.honoured is True
        assert answer.note == "CAPE trims the spaces at their start and end"


# ---------------------------------------------------------------------------
# The REST provider: a declared field, or none
# ---------------------------------------------------------------------------
def _rest(captured: list[httpx.Request], field: str = "") -> RestSandboxProvider:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "rest"
    cfg.sandbox.rest.base_url = "https://xyz.example/api"
    cfg.sandbox.rest.submit.extra_fields = {"profile": "win10"}
    cfg.sandbox.rest.submit.launch_arguments_field = field
    provider = RestSandboxProvider.from_settings(cfg)

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"id": "T-9"})

    provider._http = httpx.Client(
        base_url="https://xyz.example/api", transport=httpx.MockTransport(handler)
    )
    return provider


class TestRest:
    def test_the_declared_field_carries_them_verbatim(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        provider = _rest(captured, field="command_line")
        assert provider.capabilities.can_pass_launch_arguments is True
        assert provider.submit(_pe(tmp_path), options=WITH) == "T-9"
        assert _form_fields(captured[0]) == {"profile": "win10", "command_line": ARGS}

    def test_without_arguments_the_field_is_not_sent(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        provider = _rest(captured, field="command_line")
        provider.submit(_pe(tmp_path))
        assert _form_fields(captured[0]) == {"profile": "win10"}

    def test_no_declared_field_cannot_honour_them(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        provider = _rest(captured)
        assert provider.capabilities.can_pass_launch_arguments is False
        answer = provider.launch_arguments_answer(ARGS)
        assert answer.honoured is False
        assert answer.note == (
            "the rest provider cannot pass launch arguments to its sandbox, so the sample "
            "was detonated without them"
        )
        # Handed them anyway, it sends nothing it was not told how to send.
        provider.submit(_pe(tmp_path), options=WITH)
        assert _form_fields(captured[0]) == {"profile": "win10"}


# ---------------------------------------------------------------------------
# Triage: its submission API has no launch-argument field
# ---------------------------------------------------------------------------
class TestTriage:
    def test_it_declares_it_cannot_pass_them(self) -> None:
        provider = TriageSandboxProvider.from_settings(Settings(_env_file=None))
        assert provider.capabilities.can_pass_launch_arguments is False
        answer = provider.launch_arguments_answer(ARGS)
        assert answer.honoured is False
        assert answer.note.startswith("the triage provider cannot pass launch arguments")

    def test_its_request_is_the_same_with_or_without_options(self, tmp_path: Path) -> None:
        bodies: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            fields = _form_fields(request)
            bodies.append(json.loads(fields["_json"]))
            return httpx.Response(200, json={"id": "s1"})

        cfg = Settings(_env_file=None)
        cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
        cfg.sandbox.triage.profile = "win10"
        provider = TriageSandboxProvider.from_settings(cfg)
        provider._http = httpx.Client(
            base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
        )
        provider.submit(_pe(tmp_path))
        provider.submit(_pe(tmp_path), options=WITH)
        assert bodies[0] == {
            "kind": "file",
            "interactive": False,
            "profiles": [{"profile": "win10", "pick": "default"}],
        }
        assert bodies[1] == bodies[0]


# ---------------------------------------------------------------------------
# Mock and upload
# ---------------------------------------------------------------------------
class TestMockAndUpload:
    def test_the_mock_s_fixtures_ran_before_any_job_asked(self) -> None:
        provider = MockSandboxProvider(fixtures_dir="/nonexistent")
        assert provider.capabilities.can_pass_launch_arguments is False
        assert provider.launch_arguments_answer(ARGS).honoured is False

    def test_the_upload_provider_detonates_nothing(self) -> None:
        provider = UploadSandboxProvider.from_settings(Settings(_env_file=None))
        answer = provider.launch_arguments_answer(ARGS)
        assert answer.honoured is False
        assert answer.note.startswith("the upload provider detonates nothing")


# ---------------------------------------------------------------------------
# The contract: a provider written before the options existed keeps working
# ---------------------------------------------------------------------------
class _OldPlugin(SandboxProvider):
    id = "old-plugin"

    @classmethod
    def from_settings(cls, cfg: Settings) -> _OldPlugin:
        return cls()

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(can_submit=True)

    def submit(self, sample_path: str) -> str:  # type: ignore[override]
        return "1"


class _DuckTyped:
    id = "duck"
    capabilities = SandboxCapabilities(can_submit=True, can_pass_launch_arguments=True)


class _Raising(_OldPlugin):
    id = "raising"

    def launch_arguments_answer(self, arguments: str) -> LaunchArgumentsAnswer:
        raise RuntimeError("no")


class TestTheContract:
    def test_a_capability_defaults_to_cannot(self) -> None:
        assert SandboxCapabilities().can_pass_launch_arguments is False

    def test_an_old_plugin_answers_by_its_capability(self) -> None:
        answer = answer_of(_OldPlugin(), ARGS)
        assert answer.honoured is False
        assert "old-plugin provider cannot pass launch arguments" in answer.note

    def test_a_provider_without_the_method_answers_by_its_flag(self) -> None:
        assert answer_of(_DuckTyped(), ARGS) == LaunchArgumentsAnswer(honoured=True)

    def test_a_provider_whose_answer_raises_passes_nothing(self) -> None:
        answer = answer_of(_Raising(), ARGS)
        assert answer.honoured is False
        assert "(RuntimeError)" in answer.note

    def test_the_record_keeps_the_arguments_verbatim(self) -> None:
        record = launch_record("lab", ARGS, LaunchArgumentsAnswer(False, "why"))
        assert record == {"provider": "lab", "arguments": ARGS, "honoured": False, "note": "why"}
        assert not_honoured_reason(record) == (
            "launch arguments requested, not honoured by lab: why"
        )
        assert not_honoured_reason({**record, "honoured": True}) is None
        assert not_honoured_reason(None) is None


class TestTheValue:
    @pytest.mark.parametrize(
        ("value", "problem"),
        [
            (7, "must be text"),
            (["-x"], "must be text"),
            ("   ", "must hold some text"),
            ("x" * (LAUNCH_ARGUMENTS_MAX_CHARS + 1), "must be at most 1024 characters (got 1025)"),
            ("-a\n-b", "must not hold a control character such as a line break or a tab"),
            ("-a\x00", "must not hold a control character such as a line break or a tab"),
        ],
    )
    def test_a_value_that_is_not_one_command_line_is_refused(self, value, problem) -> None:
        assert launch_arguments_problem(value) == problem

    @pytest.mark.parametrize(
        "value", [ARGS, "x" * LAUNCH_ARGUMENTS_MAX_CHARS, "DllRegisterServer", "/S /D=C:\\x"]
    )
    def test_any_command_line_is_taken_as_it_is(self, value: str) -> None:
        assert launch_arguments_problem(value) is None
