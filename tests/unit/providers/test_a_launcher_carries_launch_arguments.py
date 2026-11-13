"""A generated launcher carries a job's launch arguments where the sandbox has no field for them.

The builder is pure and deterministic; the Triage request is captured on a
mocked transport; the record, the disclosure line and the report sentence are
read from what the run records. Synthetic bytes only; nothing is detonated.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import zipfile
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from malspark.analysis.disclosure import disclosure_lines, disclosure_record, upload_record
from malspark.core.config import Settings
from malspark.pipeline import sandbox_status as status
from malspark.providers.launcher import (
    LauncherRefused,
    LauncherSupport,
    build_launcher_archive,
    launcher_answer,
    launcher_text,
    powershell_literal,
)
from malspark.providers.sandbox.triage import TriageSandboxProvider
from malspark.providers.submission import SubmissionOptions, answer_of, launch_record
from tests.unit.providers.sandbox.test_submit_format_options import _form_fields


def _pe_bytes(dll: bool = False) -> bytes:
    blob = bytearray(b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little"))
    blob += b"PE\0\0" + b"\x00" * 18 + (0x2102 if dll else 0x0102).to_bytes(2, "little")
    return bytes(blob + b"\x00" * 64)


PE = _pe_bytes()
BOM = b"\xef\xbb\xbf"


def _members(archive: bytes) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        return [(info.filename, zf.read(info)) for info in zf.infolist()]


def _expected(literal: str) -> str:
    """The launcher text whose argument string is ``literal``."""
    return (
        "$s = $MyInvocation.MyCommand.Path\r\n"
        "if ($s) { $d = [IO.Path]::GetDirectoryName($s) } "
        "else { $d = (Get-Location).ProviderPath }\r\n"
        "$i = New-Object Diagnostics.ProcessStartInfo\r\n"
        "$i.FileName = [IO.Path]::Combine($d, 'sample.exe')\r\n"
        f"$i.Arguments = {literal}\r\n"
        "$i.WorkingDirectory = $d\r\n"
        "$i.UseShellExecute = $false\r\n"
        "[void][Diagnostics.Process]::Start($i)\r\n"
    )


class TestTheBuilder:
    def test_the_same_inputs_give_the_same_archive(self) -> None:
        a = build_launcher_archive(PE, "Evil.EXE", "-k 1")
        b = build_launcher_archive(PE, "Evil.EXE", "-k 1")
        assert a.archive == b.archive
        assert a.record["archive_sha256"] == hashlib.sha256(a.archive).hexdigest()

    def test_other_arguments_give_another_digest(self) -> None:
        a = build_launcher_archive(PE, "x.exe", "-k 1")
        b = build_launcher_archive(PE, "x.exe", "-k 2")
        assert a.record["archive_sha256"] != b.record["archive_sha256"]
        assert (
            a.record["sample_sha256"] == b.record["sample_sha256"] == hashlib.sha256(PE).hexdigest()
        )

    def test_member_names_order_timestamps_and_sample_bytes(self) -> None:
        built = build_launcher_archive(PE, "Evil Name (1).EXE", "-k 1")
        with zipfile.ZipFile(io.BytesIO(built.archive)) as zf:
            infos = zf.infolist()
        assert [i.filename for i in infos] == ["sample.exe", "launch.ps1"]
        assert all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in infos)
        assert all(i.compress_type == zipfile.ZIP_STORED for i in infos)
        assert _members(built.archive)[0][1] == PE
        assert built.record["sample_member"] == "sample.exe"
        assert built.record["launcher_member"] == "launch.ps1"

    @pytest.mark.parametrize(
        "name",
        [
            "a.exe",
            "a",
            "a.b c",
            "../../x.scr",
            "x.exe_",
            "x.bin",
            "x.txt",
            "x.ps1",
            "x.lnk",
            "X.EXE",
        ],
    )
    def test_the_sample_is_always_sample_exe(self, name: str) -> None:
        # The builder starts only a PE program; started by its path through
        # ShellExecute it needs the extension Windows runs, whatever the upload's.
        built = build_launcher_archive(PE, name, "-k")
        assert built.record["sample_member"] == "sample.exe"
        assert [n for n, _ in _members(built.archive)] == ["sample.exe", "launch.ps1"]
        assert "'sample.exe'" in built.record["launcher_text"]

    def test_the_archive_digest_is_golden(self) -> None:
        # Pinned bytes, so a Python or zipfile change that moved them is seen.
        built = build_launcher_archive(PE, "x.exe", "--url 'a b' -v")
        assert built.record["archive_bytes"] == 724
        assert built.record["archive_sha256"] == (
            "19d35d45e3bf8a53dac38ecd41f410239137c1f8228032d87f73edccb6c7b247"
        )
        assert hashlib.sha256(built.archive).hexdigest() == built.record["archive_sha256"]

    def test_the_launcher_file_is_utf8_with_a_bom_and_its_text_is_recorded_whole(self) -> None:
        built = build_launcher_archive(PE, "x.exe", "é -k")
        _name, body = _members(built.archive)[1]
        assert body.startswith(BOM)
        assert body[len(BOM) :].decode("utf-8") == built.record["launcher_text"]

    @pytest.mark.parametrize(
        ("arguments", "literal"),
        [
            ("-k 1", "'-k 1'"),
            ("it's", "'it''s'"),
            ('say "hi"', "'say \"hi\"'"),
            ("a  b", "'a  b'"),
            ("$env:X `n $(calc)", "'$env:X `n $(calc)'"),
            ("100% ^ & ; | < > !", "'100% ^ & ; | < > !'"),
            ("é 日本語", "'é 日本語'"),
            ("-password x", "'-password x'"),
            ("’x‘", "'’’x‘‘'"),
            ("x" * 1024, "'" + "x" * 1024 + "'"),
        ],
    )
    def test_the_launcher_text(self, arguments: str, literal: str) -> None:
        assert powershell_literal(arguments) == literal
        assert launcher_text("ps1", "sample.exe", arguments) == _expected(literal)
        # The literal is the argument string's only spelling: one line holds it.
        (line,) = [x for x in _expected(literal).split("\r\n") if literal in x]
        assert line == f"$i.Arguments = {literal}"

    def test_the_example_text(self) -> None:
        # Its own folder from the invocation (PowerShell 2.0 sets no
        # $PSScriptRoot outside a module), and that folder as the working one.
        built = build_launcher_archive(PE, "x.exe", "--url 'a b' -v")
        assert built.record["launcher_text"] == (
            "$s = $MyInvocation.MyCommand.Path\r\n"
            "if ($s) { $d = [IO.Path]::GetDirectoryName($s) } "
            "else { $d = (Get-Location).ProviderPath }\r\n"
            "$i = New-Object Diagnostics.ProcessStartInfo\r\n"
            "$i.FileName = [IO.Path]::Combine($d, 'sample.exe')\r\n"
            "$i.Arguments = '--url ''a b'' -v'\r\n"
            "$i.WorkingDirectory = $d\r\n"
            "$i.UseShellExecute = $false\r\n"
            "[void][Diagnostics.Process]::Start($i)\r\n"
        )
        text = built.record["launcher_text"]
        assert "$PSScriptRoot" not in text
        # No cmdlet that reads a path as a wildcard pattern, and no shell.
        for word in ("Start-Process", "Join-Path", "Split-Path", "-FilePath", "Invoke-"):
            assert word not in text
        assert built.record["script_host_images"] == ["powershell.exe", "pwsh.exe"]

    def test_the_record_holds_the_launcher_file_s_own_digest(self) -> None:
        built = build_launcher_archive(PE, "x.exe", "-k 1")
        _name, body = _members(built.archive)[1]
        assert built.record["launcher_sha256"] == hashlib.sha256(body).hexdigest()

    def test_the_archive_is_left_out_of_the_default_repr(self) -> None:
        built = build_launcher_archive(PE, "x.exe", "-k 1")
        assert "archive=" not in repr(built) and "PK" not in repr(built)
        assert built.record["archive_sha256"] in repr(built)

    @pytest.mark.parametrize("arguments", ["a\nb", "a\x00b", "a​b", "   ", "x" * 1025])
    def test_a_value_that_is_not_one_command_line_is_refused(self, arguments: str) -> None:
        with pytest.raises(LauncherRefused, match="the arguments"):
            build_launcher_archive(PE, "x.exe", arguments)

    def test_a_lone_surrogate_cannot_be_written_and_is_refused(self) -> None:
        with pytest.raises(LauncherRefused, match="UTF-8"):
            build_launcher_archive(PE, "x.exe", "a\ud800b")

    def test_a_dll_or_a_non_program_is_refused(self) -> None:
        with pytest.raises(LauncherRefused, match="not a Windows program"):
            build_launcher_archive(_pe_bytes(dll=True), "x.dll", "-k")
        with pytest.raises(LauncherRefused, match="not a Windows program"):
            build_launcher_archive(b"#!/bin/sh\n", "x.sh", "-k")
        # A script or an installer is no PE program either, and stays refused.
        for body, name in (
            (b"WScript.Echo 1", "x.vbs"),
            (b"\xd0\xcf\x11\xe0" + b"\0" * 60, "x.msi"),
        ):
            with pytest.raises(LauncherRefused, match="not a Windows program"):
                build_launcher_archive(body, name, "-k")

    @pytest.mark.parametrize("kind", ["bat", "cmd", "lnk", ""])
    def test_a_batch_launcher_is_not_built(self, kind: str) -> None:
        with pytest.raises(LauncherRefused, match="no .* launcher is built"):
            build_launcher_archive(PE, "x.exe", "-k", kind)


SUPPORT = LauncherSupport(script_types=("ps1",), picked_by="the pick field")


class TestTheAnswer:
    def test_honoured_with_the_record_and_how_it_is_carried(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(PE)
        answer = launcher_answer(SUPPORT, "-k 1", sample)
        assert answer.honoured is True
        assert answer.built is not None and answer.built.record is answer.launcher
        assert answer.via == "a generated PowerShell launcher in the submitted archive"
        assert answer.launcher is not None and answer.launcher["picked_by"] == "the pick field"

    def test_not_honoured_with_the_reason(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.dll"
        sample.write_bytes(_pe_bytes(dll=True))
        answer = launcher_answer(SUPPORT, "-k 1", sample)
        assert answer.honoured is False and answer.launcher is None
        assert "a launcher cannot carry them" in answer.note
        assert launcher_answer(SUPPORT, "-k 1", None).honoured is False
        assert launcher_answer(SUPPORT, "-k 1", tmp_path / "missing").honoured is False

    def test_a_script_type_the_builder_does_not_know_is_not_honoured(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(PE)
        answer = launcher_answer(LauncherSupport(("bat",), "x"), "-k", sample)
        assert answer.honoured is False and "is one a launcher is built for" in answer.note


def _triage(handler, **over) -> TriageSandboxProvider:
    cfg = Settings(_env_file=None)
    cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
    for key, value in over.items():
        setattr(cfg.sandbox.triage, key, value)
    provider = TriageSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
    )
    return provider


class TestTheTriageRequest:
    def _capture(self, tmp_path: Path, options, **over) -> tuple[dict, httpx.Request]:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"id": "s1"})

        sample = tmp_path / "Real Name.exe"
        sample.write_bytes(PE)
        provider = _triage(handler, **over)
        assert provider.submit(sample, options=options) == "s1"
        return json.loads(_form_fields(seen[0])["_json"]), seen[0]

    def test_with_arguments_the_archive_is_uploaded_and_the_launcher_is_picked(
        self, tmp_path: Path
    ) -> None:
        body, request = self._capture(
            tmp_path, SubmissionOptions(launch_arguments="-k 1"), profile="win10"
        )
        assert body == {
            "kind": "file",
            "interactive": False,
            "profiles": [{"profile": "win10", "pick": "launch.ps1"}],
        }
        raw = request.content
        assert b'filename="submission.zip"' in raw and b"Real Name" not in raw
        start = raw.index(b"PK\x03\x04")
        end = raw.index(b"PK\x05\x06") + 22
        assert [n for n, _ in _members(raw[start:end])] == ["sample.exe", "launch.ps1"]

    def test_the_archive_built_when_asked_is_the_one_sent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(PE)
        built = launcher_answer(SUPPORT, "-k 1", sample).built
        assert built is not None
        # Not built again: a sample changed in between cannot make the archive
        # sent differ from the one recorded.
        sample.write_bytes(_pe_bytes() + b"changed")
        import malspark.providers.sandbox.triage as triage_module

        def _no_second_build(*_a: object, **_k: object) -> None:
            raise AssertionError("built twice")

        monkeypatch.setattr(triage_module, "build_for_submission", _no_second_build)
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"id": "s1"})

        provider = _triage(handler)
        options = SubmissionOptions(launch_arguments="-k 1", launcher=built)
        assert provider.submit(sample, options=options) == "s1"
        raw = seen[0].content
        start = raw.index(b"PK\x03\x04")
        end = raw.index(b"PK\x05\x06") + 22
        assert raw[start:end] == built.archive
        # The archive's bytes never reach a repr (a log line).
        assert "PK" not in repr(options)

    def test_without_a_profile_only_the_pick_is_sent(self, tmp_path: Path) -> None:
        body, _ = self._capture(tmp_path, SubmissionOptions(launch_arguments="-k"))
        assert body["profiles"] == [{"pick": "launch.ps1"}]

    def test_the_timeout_still_rides_along(self, tmp_path: Path) -> None:
        body, _ = self._capture(
            tmp_path, SubmissionOptions(launch_arguments="-k"), analysis_seconds=120
        )
        assert body["defaults"] == {"timeout": 120}

    @pytest.mark.parametrize("options", [None, SubmissionOptions()])
    def test_without_arguments_the_request_is_the_old_one(self, tmp_path: Path, options) -> None:
        body, request = self._capture(tmp_path, options, profile="win10")
        assert body["profiles"] == [{"profile": "win10", "pick": "default"}]
        assert b'filename="Real Name.exe"' in request.content
        assert b"PK\x03\x04" not in request.content

    def test_with_the_setting_off_the_provider_answers_not_honoured(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(PE)
        provider = _triage(lambda r: httpx.Response(200), launcher_for_arguments=False)
        answer = answer_of(provider, "-k 1", sample)
        assert answer.honoured is False
        assert answer.note.startswith("the triage provider cannot pass launch arguments")

    def test_with_the_setting_on_it_is_honoured_by_a_launcher(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(PE)
        provider = _triage(lambda r: httpx.Response(200))
        answer = answer_of(provider, "-k 1", sample)
        assert answer.honoured is True and answer.launcher is not None
        assert "profiles[].pick" in answer.launcher["picked_by"]

    def test_the_setting_is_on_by_default(self) -> None:
        assert Settings(_env_file=None).sandbox.triage.launcher_for_arguments is True


def _record(tmp_path: Path) -> tuple[dict, dict]:
    sample = tmp_path / "s.exe"
    sample.write_bytes(PE)
    provider = _triage(lambda r: httpx.Response(200))
    arguments = "--password 'p w' -k"
    answer = answer_of(provider, arguments, sample)
    record = launch_record("triage", arguments, answer)
    return record, answer.launcher or {}


class TestTheRecordAndTheReport:
    def test_the_launch_record_holds_the_launcher(self, tmp_path: Path) -> None:
        record, launcher = _record(tmp_path)
        assert record["honoured"] is True
        assert record["via"] == "a generated PowerShell launcher in the submitted archive"
        assert record["launcher"] == launcher
        for key in (
            "script_type",
            "launcher_text",
            "launcher_member",
            "sample_member",
            "archive_sha256",
            "sample_sha256",
        ):
            assert launcher[key]

    def test_the_report_sentence_states_what_a_reader_must_know(self, tmp_path: Path) -> None:
        record, launcher = _record(tmp_path)
        text = status.launch_statement(record)
        assert "through a generated PowerShell launcher in the submitted archive" in text
        assert "not submitted bare" in text
        assert launcher["archive_sha256"] in text and launcher["sample_sha256"] in text
        assert "ProcessStartInfo" in text and "launch.ps1" in text and "sample.exe" in text
        assert "starts at PowerShell, not at the sample" in text
        assert "is what was disclosed to the sandbox" in text and "it is public" in text
        assert "Nothing here shows the launcher ran" in text
        assert (
            "Whether the started program read them is the sandbox's, and is not established here"
            in text
        )

    def test_a_record_without_a_launcher_reads_as_before(self) -> None:
        record = {"provider": "cape2", "arguments": "-k", "honoured": True, "via": "CAPE's option"}
        assert "launcher" not in status.launch_statement(record)

    def test_the_disclosure_counts_the_archive_and_names_the_sample(self, tmp_path: Path) -> None:
        record, launcher = _record(tmp_path)
        row = upload_record("triage", submitted=True, host="tria.ge", launch=record)
        assert row["launch_launcher"] == launcher
        rec = disclosure_record({}, uploads=[row])
        (line,) = [x for x in disclosure_lines(rec) if x.startswith("Sample upload")]
        assert f"an archive (SHA-256 `{launcher['archive_sha256']}`)" in line
        assert f"holding the sample (SHA-256 `{launcher['sample_sha256']}`)" in line
        assert "not the bare sample" in line
        assert "through a generated PowerShell launcher in the submitted archive" in line

    def test_a_plain_submission_reads_as_before(self) -> None:
        row = upload_record("cape2", submitted=True, host="cape.example")
        rec = disclosure_record({}, uploads=[row])
        (line,) = [x for x in disclosure_lines(rec) if x.startswith("Sample upload")]
        assert line.startswith("Sample upload: the sample was submitted")


class TestNothingLogsTheLauncher:
    def test_no_log_line_carries_the_arguments_or_the_text(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        marker = "zq81-secret-token"
        sample = tmp_path / "s.exe"
        sample.write_bytes(PE)
        provider = _triage(lambda r: httpx.Response(200, json={"id": "s1"}))
        answer = answer_of(provider, f"--key {marker}", sample)
        assert answer.honoured
        provider.submit(sample, options=SubmissionOptions(launch_arguments=f"--key {marker}"))
        assert marker not in caplog.text and "ProcessStartInfo" not in caplog.text
