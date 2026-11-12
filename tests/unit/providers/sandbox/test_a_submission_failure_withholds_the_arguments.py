"""The submission contract's edges: one-argument plug-ins, a cut record, an echoing sandbox.

Offline; a stub sandbox on a mocked transport. Synthetic bytes only.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from malspark.core.config import Settings
from malspark.loaders.cape2_client import CAPEv2Client
from malspark.providers.errors import ProviderError
from malspark.providers.sandbox.cape2 import CAPE2SandboxProvider
from malspark.providers.sandbox.rest import RestSandboxProvider
from malspark.providers.sandbox.triage import TriageSandboxProvider
from malspark.providers.submission import (
    LAUNCH_ARGUMENTS_MAX_CHARS,
    LaunchArgumentsAnswer,
    SubmissionOptions,
    answer_of,
    mask_submitted,
    unmade_record,
)

SECRET = "--password hunter2-zq81"
WITH = SubmissionOptions(launch_arguments=SECRET)


def _pe(tmp_path: Path) -> Path:
    path = tmp_path / "sample.exe"
    blob = bytearray(b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little"))
    blob += b"PE\0\0" + b"\x00" * 18 + (0x0102).to_bytes(2, "little") + b"\x00" * 64
    path.write_bytes(bytes(blob))
    return path


class TestAnswerOf:
    def test_a_one_argument_plug_in_is_asked_with_the_arguments_alone(self) -> None:
        class Old:
            id = "old"

            def launch_arguments_answer(self, arguments: str) -> LaunchArgumentsAnswer:
                return LaunchArgumentsAnswer(honoured=True, note=f"got {len(arguments)}")

        answer = answer_of(Old(), "-x", "/p")
        assert answer == LaunchArgumentsAnswer(honoured=True, note="got 2")

    def test_a_kwargs_plug_in_gets_the_sample_path(self) -> None:
        seen: dict[str, Any] = {}

        class Wide:
            id = "wide"

            def launch_arguments_answer(self, arguments: str, **kw: Any) -> LaunchArgumentsAnswer:
                seen.update(kw)
                return LaunchArgumentsAnswer(honoured=True)

        assert answer_of(Wide(), "-x", "/p").honoured is True
        assert seen == {"sample_path": "/p"}

    def test_a_type_error_inside_the_provider_is_not_a_signature_mismatch(self) -> None:
        class Broken:
            id = "broken"

            def launch_arguments_answer(self, arguments: str, *, sample_path: Any = None) -> Any:
                raise TypeError("its own bug")

        answer = answer_of(Broken(), "-x", "/p")
        assert answer.honoured is False and "could not say" in answer.note
        assert "TypeError" in answer.note


class TestACutRecordSaysSo:
    def test_an_over_long_value_is_marked_in_the_note(self) -> None:
        record = unmade_record("cape2", "a" * 3000, "why")
        assert len(record["arguments"]) == LAUNCH_ARGUMENTS_MAX_CHARS
        assert record["note"] == (
            f"why (recorded cut to the first {LAUNCH_ARGUMENTS_MAX_CHARS} of 3000 characters)"
        )

    def test_a_value_within_the_limit_is_not_marked(self) -> None:
        assert unmade_record("cape2", "a" * 10, "why")["note"] == "why"


def test_the_mask_withholds_each_spelling_and_the_launcher_first() -> None:
    value = 'say "hi" é'
    echoed = json.dumps({"options": f"arguments={value}", "esc": value})
    out = mask_submitted(echoed, value, f"Start {value}")
    assert "hi" not in out and "é" not in out
    assert mask_submitted(f"x Start {value} y", value, f"Start {value}") == (
        "x [the launcher text, withheld] y"
    )
    assert mask_submitted("nothing here", value) == "nothing here"


def _echo(request: httpx.Request) -> httpx.Response:
    # The form's text, as a sandbox that quotes what it received would show it.
    body = "".join(
        ch for ch in request.content.decode("latin-1") if ch.isprintable() or ch in "\r\n"
    )
    return httpx.Response(400, text=f"bad form: {body}")


def _provider_of(kind: str, tmp_path: Path) -> Any:
    if kind == "cape":
        provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
        client = CAPEv2Client(base_url="https://cape.example")
        client._http = httpx.Client(
            base_url="https://cape.example", transport=httpx.MockTransport(_echo)
        )
        provider._client = client
        return provider
    cfg = Settings(_env_file=None)
    if kind == "rest":
        cfg.sandbox.rest.base_url = "https://rest.example"
        cfg.sandbox.rest.submit.launch_arguments_field = "command_line"
        provider = RestSandboxProvider.from_settings(cfg)
        provider._http = httpx.Client(
            base_url="https://rest.example", transport=httpx.MockTransport(_echo)
        )
        return provider
    cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
    provider = TriageSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(_echo)
    )
    return provider


class TestAnEchoingSandbox:
    @pytest.mark.parametrize("kind", ["cape", "rest", "triage"])
    def test_the_failure_carries_neither_the_arguments_nor_the_launcher(
        self, kind: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        provider = _provider_of(kind, tmp_path)
        with pytest.raises(Exception) as caught:  # noqa: PT011 — each provider's own error type
            provider.submit(_pe(tmp_path), options=WITH)
        assert SECRET not in str(caught.value)
        assert "hunter2" not in str(caught.value)
        assert "hunter2" not in caplog.text
        # The stub does quote the form: without the mask the value would be there.
        assert "hunter2" in _echo(httpx.Request("POST", "https://x", data={"a": SECRET})).text

    def test_triage_s_launcher_text_is_withheld_too(self, tmp_path: Path) -> None:
        provider = _provider_of("triage", tmp_path)
        with pytest.raises(ProviderError) as caught:
            provider.submit(_pe(tmp_path), options=WITH)
        # The body shows the launcher member; the text of it is masked before the cut.
        assert "launch.ps1" in str(caught.value) and "[the" in str(caught.value)
        assert "Start-Process" not in str(caught.value)

    def test_the_run_keeps_it_out_of_its_log_and_failure_reason(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import asyncio

        from tests.unit.pipeline.test_a_run_records_its_launch_arguments import _Provider
        from tests.unit.pipeline.test_a_sandbox_naming_another_target_is_told import _app

        class Echo(_Provider):
            def submit(self, sample_path: str, **kwargs: Any) -> str:
                raise RuntimeError(f"HTTP 400: form was {kwargs['options'].launch_arguments}")

        caplog.set_level(logging.DEBUG)
        app = _app(Echo(passes=True))
        app.launch_arguments = SECRET
        sample = _pe(tmp_path)
        assert asyncio.run(app._submit_to_sandbox(str(sample))) is None
        assert "hunter2" not in caplog.text
        assert "hunter2" not in (app.container.sandbox_failure or "")
        assert "withheld" in (app.container.sandbox_failure or "")
