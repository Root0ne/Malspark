"""A job's launch arguments reach the sandbox each provider's own way, or are said not to.

Every request is captured on a mocked transport: the exact form a submission
sends with and without the arguments. A job that asks for none sends the
request it always sent. Synthetic bytes only; nothing is detonated.
"""

from __future__ import annotations

import json
import logging
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

CAPE_VIA = "CAPE's 'arguments' option"
CONTROL = (
    "must not hold a control character such as a line break or a tab, nor a format "
    "character (a bidi control, a zero-width character) or a line or paragraph separator"
)
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
        assert provider.launch_arguments_answer(ARGS) == LaunchArgumentsAnswer(
            honoured=True, via=CAPE_VIA
        )

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
        assert provider.launch_arguments_answer(ARGS) == LaunchArgumentsAnswer(
            honoured=True, via=CAPE_VIA
        )

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
    def test_with_the_launcher_off_it_declares_it_cannot_pass_them(self) -> None:
        cfg = Settings(_env_file=None)
        cfg.sandbox.triage.launcher_for_arguments = False
        provider = TriageSandboxProvider.from_settings(cfg)
        assert provider.capabilities.can_pass_launch_arguments is False
        assert provider.capabilities.launcher is None
        answer = provider.launch_arguments_answer(ARGS)
        assert answer.honoured is False
        assert answer.note.startswith("the triage provider cannot pass launch arguments")

    def test_with_the_launcher_off_its_request_is_the_same_with_or_without_options(
        self, tmp_path: Path
    ) -> None:
        bodies: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            fields = _form_fields(request)
            bodies.append(json.loads(fields["_json"]))
            return httpx.Response(200, json={"id": "s1"})

        cfg = Settings(_env_file=None)
        cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
        cfg.sandbox.triage.profile = "win10"
        cfg.sandbox.triage.launcher_for_arguments = False
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

    def launch_arguments_answer(self, arguments: str, **_: object) -> LaunchArgumentsAnswer:
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


SECRET = "--password S3cr3tValue-9f2"


def _nothing_logs(caplog: pytest.LogCaptureFixture) -> None:
    for record in caplog.records:
        assert "S3cr3tValue" not in record.getMessage()
        assert "S3cr3tValue" not in str(record.args)


class TestNoLogLineCarriesThem:
    def test_cape(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.DEBUG)
        provider = _cape(tmp_path, [])
        provider.submit(_pe(tmp_path), options=SubmissionOptions(launch_arguments=SECRET))
        assert any(
            "fields:" in r.getMessage() and "options" in r.getMessage() for r in caplog.records
        )
        _nothing_logs(caplog)

    def test_rest(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.DEBUG)
        provider = _rest([], field="command_line")
        provider.submit(_pe(tmp_path), options=SubmissionOptions(launch_arguments=SECRET))
        _nothing_logs(caplog)

    def test_the_providers_that_cannot_and_the_run_log_the_note_only(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import asyncio

        from tests.unit.pipeline.test_a_run_records_its_launch_arguments import _Provider
        from tests.unit.pipeline.test_a_sandbox_naming_another_target_is_told import _app

        caplog.set_level(logging.DEBUG)
        for provider in (
            TriageSandboxProvider.from_settings(Settings(_env_file=None)),
            MockSandboxProvider(fixtures_dir="/nonexistent"),
            UploadSandboxProvider.from_settings(Settings(_env_file=None)),
        ):
            assert answer_of(provider, SECRET, _pe(tmp_path)).honoured is False
        # A provider that cannot pass them, and a value refused where it is used:
        # the run logs the note only, and the sample goes on without them.
        for provider, value in (
            (_Provider(passes=False, note="no field"), SECRET),
            (_Provider(passes=True), SECRET + "\u200b"),
        ):
            app = _app(provider)
            app.launch_arguments = value
            asyncio.run(app._submit_to_sandbox(str(_pe(tmp_path))))
        _nothing_logs(caplog)
        assert any("not honoured" in r.getMessage() for r in caplog.records)


class TestCapeKnowsWhichPackagesReadThem:
    def test_a_package_that_documents_arguments_is_honoured(self, tmp_path: Path) -> None:
        provider = _cape(tmp_path, [], package_by_format={"*": "dll"})
        answer = provider.launch_arguments_answer(ARGS, sample_path=_pe(tmp_path))
        assert answer == LaunchArgumentsAnswer(honoured=True, via=CAPE_VIA)

    def test_a_package_the_documentation_is_silent_on_still_gets_them(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        provider = _cape(tmp_path, captured, package_by_format={"*": "pdf"})
        answer = provider.launch_arguments_answer(ARGS, sample_path=_pe(tmp_path))
        assert answer == LaunchArgumentsAnswer(
            honoured=True,
            note="whether the package 'pdf' reads it is not documented",
            via=CAPE_VIA,
        )
        provider.submit(_pe(tmp_path), options=WITH)
        assert f"arguments={ARGS}" in captured[0].content.decode("latin-1")

    def test_a_package_the_documentation_states_takes_none_is_not_honoured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.providers.sandbox import cape2

        monkeypatch.setattr(cape2, "_NO_ARGUMENT_PACKAGES", frozenset({"pdf"}))
        provider = _cape(tmp_path, [], package_by_format={"*": "pdf"})
        answer = provider.launch_arguments_answer(ARGS, sample_path=_pe(tmp_path))
        assert answer.honoured is False and "documents no arguments" in answer.note

    def test_no_package_selected_leaves_it_to_cape(self, tmp_path: Path) -> None:
        provider = _cape(tmp_path, [])
        assert provider.launch_arguments_answer(ARGS, sample_path=_pe(tmp_path)).honoured is True


class TestARestFieldOfItsOwn:
    @pytest.mark.parametrize(
        "over",
        [
            {"file_field": "file", "launch_arguments_field": "file"},
            {"extra_fields": {"profile": "win10"}, "launch_arguments_field": "profile"},
            {"submit_fields": {"timeout": "60"}, "launch_arguments_field": "timeout"},
        ],
    )
    def test_a_field_that_collides_is_refused(self, over: dict) -> None:
        from pydantic import ValidationError

        from malspark.core.config import RestSubmitConfig

        with pytest.raises(ValidationError, match="name a field of its own"):
            RestSubmitConfig(**over)

    def test_a_field_of_its_own_and_none_are_accepted(self) -> None:
        from malspark.core.config import RestSubmitConfig

        assert RestSubmitConfig(launch_arguments_field="command_line").launch_arguments_field
        assert RestSubmitConfig().launch_arguments_field == ""

    def test_the_answer_names_the_field(self) -> None:
        answer = _rest([], field="command_line").launch_arguments_answer(ARGS)
        assert answer == LaunchArgumentsAnswer(
            honoured=True, via="the multipart field 'command_line'"
        )


class TestTheValue:
    @pytest.mark.parametrize(
        ("value", "problem"),
        [
            (7, "must be text"),
            (["-x"], "must be text"),
            ("   ", "must hold some text"),
            ("x" * (LAUNCH_ARGUMENTS_MAX_CHARS + 1), "must be at most 1024 characters (got 1025)"),
            ("-a\n-b", CONTROL + ": the first is U+000A (control character) at position 3"),
            ("-a\x00", CONTROL + ": the first is U+0000 (control character) at position 3"),
        ],
    )
    def test_a_value_that_is_not_one_command_line_is_refused(self, value, problem) -> None:
        assert launch_arguments_problem(value) == problem

    def test_the_offending_character_is_named_inside_a_long_value(self) -> None:
        value = "x" * 700 + "\u200b" + "y" * 100
        assert launch_arguments_problem(value) == (
            CONTROL + ": the first is U+200B (format character) at position 701"
        )

    @pytest.mark.parametrize(
        "char", ["\u0085", "\u2028", "\u2029", "\u202e", "\u200b", "\x7f", "\t"]
    )
    def test_unicode_controls_formats_and_separators_are_refused(self, char: str) -> None:
        problem = launch_arguments_problem(f"-a{char}-b")
        assert problem is not None and problem.startswith(CONTROL)
        assert f"U+{ord(char):04X}" in problem and "at position 3" in problem

    @pytest.mark.parametrize(
        "value", [ARGS, "x" * LAUNCH_ARGUMENTS_MAX_CHARS, "DllRegisterServer", "/S /D=C:\\x"]
    )
    def test_any_command_line_is_taken_as_it_is(self, value: str) -> None:
        assert launch_arguments_problem(value) is None
