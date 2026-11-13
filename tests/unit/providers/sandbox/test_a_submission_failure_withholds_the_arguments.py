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
        assert "ProcessStartInfo" not in str(caught.value)

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


class TestWhatTheMaskRecognises:
    @pytest.mark.parametrize(
        "spelling",
        [
            SECRET,
            "--password%20hunter2-zq81",
            "--password+hunter2-zq81",
            json.dumps(SECRET)[1:-1],
        ],
    )
    def test_as_sent_url_form_and_json_spellings_are_withheld(self, spelling: str) -> None:
        assert "hunter2" not in mask_submitted(f"echo: {spelling} end", SECRET)

    def test_a_slash_kept_or_encoded_is_withheld_either_way(self) -> None:
        value = "--url https://c2.example/x"
        for spelling in ("--url%20https%3A%2F%2Fc2.example%2Fx", "--url%20https%3A//c2.example/x"):
            assert "c2.example" not in mask_submitted(spelling, value)

    @pytest.mark.parametrize(
        "spelling",
        [
            # Any byte percent-encoded, in either case of hex digit.
            "--password%20hunter2%2Dzq81",
            "%2d%2dpassword%20hunter2-zq81",
            "".join(f"%{b:02X}" for b in SECRET.encode()),
            "".join(f"%{b:02x}" for b in SECRET.encode()),
            "--password+hunter2%2dzq81",
        ],
    )
    def test_any_percent_encoding_is_withheld_and_only_it(self, spelling: str) -> None:
        out = mask_submitted(f"HTTP 400 %FF+{spelling}&next=1 caf%C3%A9", SECRET)
        assert out == "HTTP 400 %FF+[the launch arguments, withheld]&next=1 caf%C3%A9"

    def test_a_percent_encoded_non_ascii_value_is_withheld(self) -> None:
        value = "--name café-zq81"
        assert mask_submitted("q=--name%20caf%C3%A9-zq81!", value) == (
            "q=[the launch arguments, withheld]!"
        )
        # A run of bytes that is not UTF-8 stays as written around the value.
        assert mask_submitted("%C3%2D%2Dname caf%c3%a9-zq81", value) == (
            "%C3[the launch arguments, withheld]"
        )

    def test_other_encodings_are_not_recognised(self) -> None:
        import base64

        # Stated as the guarantee's edge, not hidden: these pass through.
        encoded = base64.b64encode(SECRET.encode()).decode()
        assert mask_submitted(encoded, SECRET) == encoded
        assert mask_submitted(SECRET.upper(), SECRET) == SECRET.upper()

    @pytest.mark.parametrize("short", ["1", "-v", "/s "])
    def test_a_value_too_short_is_left_and_the_record_says_so(self, short: str) -> None:
        from malspark.providers.submission import UNMASKED_NOTE, launch_record

        assert mask_submitted("HTTP 401 for -v /s 1", short) == "HTTP 401 for -v /s 1"
        record = launch_record("triage", short, LaunchArgumentsAnswer(honoured=True))
        assert record["unmasked"] == UNMASKED_NOTE
        assert "unmasked" not in launch_record("t", SECRET, LaunchArgumentsAnswer(honoured=True))

    def test_the_run_keeps_its_own_words_and_masks_the_sandbox_s(self, tmp_path: Path) -> None:
        import asyncio

        from tests.unit.pipeline.test_a_run_records_its_launch_arguments import _Provider
        from tests.unit.pipeline.test_a_sandbox_naming_another_target_is_told import _app

        class Refusing(_Provider):
            def submit(self, sample_path: str, **kwargs: Any) -> str:
                raise RuntimeError(f"HTTP 401: {kwargs['options'].launch_arguments}")

        for arguments, kept in (("1", "HTTP 401: 1"), ("submitting", "HTTP 401: [the")):
            app = _app(Refusing(passes=True))
            app.launch_arguments = arguments
            assert asyncio.run(app._submit_to_sandbox(str(_pe(tmp_path)))) is None
            failure = app.container.sandbox_failure or ""
            # The platform's stage words are its own, never masked.
            assert failure.startswith("submitting the sample: ")
            assert kept in failure


class TestTheCapeChain:
    def _client(self, exc: Exception) -> CAPEv2Client:
        def handler(request: httpx.Request) -> httpx.Response:
            raise exc

        client = CAPEv2Client(base_url="https://cape.example")
        client._http = httpx.Client(
            base_url="https://cape.example", transport=httpx.MockTransport(handler)
        )
        return client

    def test_without_a_mask_the_cause_is_kept(self, tmp_path: Path) -> None:
        from malspark.loaders.cape2_client import SandboxError

        cause = httpx.ConnectError("refused")
        with pytest.raises(SandboxError) as caught:
            self._client(cause).submit(str(_pe(tmp_path)))
        assert caught.value.__cause__ is cause

    def test_with_a_mask_the_cause_is_dropped(self, tmp_path: Path) -> None:
        from malspark.loaders.cape2_client import SandboxError

        with pytest.raises(SandboxError) as caught:
            self._client(httpx.ConnectError(f"refused {SECRET}")).submit(
                str(_pe(tmp_path)), mask=lambda t: mask_submitted(t, SECRET)
            )
        assert caught.value.__cause__ is None and "hunter2" not in str(caught.value)
