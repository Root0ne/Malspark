"""A job's launch arguments are stated verbatim wherever the detonation is described.

The run asks the provider before it submits: arguments it passes are handed
over, and arguments it cannot pass are not, the detonation going ahead without
them. Either way the upload record, the report's sandbox mark, the pack's
ledger entry, the report's sandbox section and, where not honoured, the run's
limitations say which arguments and what became of them. A job that asked for
none reads byte for byte as before. Synthetic bytes only; no sample is run.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest

from malspark.analysis.disclosure import disclosure_lines, disclosure_record, upload_record
from malspark.pipeline import sandbox_status as status
from malspark.pipeline.triage_pack import render_pack
from malspark.providers.base import SandboxCapabilities
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.submission import LaunchArgumentsAnswer, SubmissionOptions
from malspark.schemas.sandbox_document import PLATFORM_MARKS
from malspark.schemas.sandbox_report import SandboxRun
from tests.unit.pipeline.test_a_sandbox_naming_another_target_is_told import _app, _flat, _pack
from tests.unit.pipeline.test_triage_pack import SANDBOX_REPORT

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()
ARGS = "--password hunter2 --url https://c2.example/x"


class _Provider:
    """A sandbox answering one raw report, recording what each submission was handed."""

    def __init__(self, *, passes: bool, note: str = "", id: str = "lab-box") -> None:
        self.id = id
        self._passes, self._note = passes, note
        self.submitted: list[dict[str, Any]] = []

    @property
    def capabilities(self) -> Any:
        return SandboxCapabilities(
            can_submit=True, can_poll=True, can_pass_launch_arguments=self._passes
        )

    def submission_address(self) -> str:
        return "lab.example"

    def launch_arguments_answer(self, arguments: str) -> LaunchArgumentsAnswer:
        return LaunchArgumentsAnswer(honoured=self._passes, note=self._note)

    def submit(self, sample_path: str, **kwargs: Any) -> str:
        self.submitted.append(kwargs)
        return "42"

    def wait_for_completion(self, task_id: str, **_: Any) -> str:
        return "reported"

    def fetch(self, task_id: str) -> SandboxRun:
        raw = _flat(INTAKE)
        report = required_reader("generic").read(raw, provider=self.id, task_id=task_id)
        return SandboxRun(task_id=task_id, report=report, raw=raw, status="reported")

    def signature_scale(self, run: Any, formats: Any = None) -> Any:
        return None


def _run(provider: Any, tmp_path: Path, arguments: str) -> tuple[Any, dict[str, Any] | None]:
    sample = tmp_path / "s.exe"
    sample.write_bytes(BYTES)
    app = _app(provider)
    app.launch_arguments = arguments
    document = asyncio.run(app._submit_to_sandbox(str(sample)))
    return app, app._mark_the_launch(app._tell_the_target(document, INTAKE))


class TestTheSubmission:
    def test_a_provider_that_passes_them_is_handed_them(self, tmp_path: Path) -> None:
        provider = _Provider(passes=True)
        app, report = _run(provider, tmp_path, ARGS)

        assert provider.submitted == [{"options": SubmissionOptions(launch_arguments=ARGS)}]
        assert app.container.sample_uploads == [
            {
                "provider": "lab-box",
                "submitted": True,
                "host": "lab.example",
                "launch_arguments": ARGS,
                "launch_arguments_honoured": True,
            }
        ]
        assert report is not None
        assert report[status.LAUNCH_KEY] == {
            "provider": "lab-box",
            "arguments": ARGS,
            "honoured": True,
            "note": "",
        }

    def test_a_provider_that_cannot_is_handed_nothing_and_the_run_goes_on(
        self, tmp_path: Path
    ) -> None:
        provider = _Provider(passes=False, note="no field for them")
        app, report = _run(provider, tmp_path, ARGS)

        # The call a run without arguments makes, and a report all the same.
        assert provider.submitted == [{}]
        assert report is not None and "behavior" in report
        (upload,) = app.container.sample_uploads
        assert upload["launch_arguments"] == ARGS
        assert upload["launch_arguments_honoured"] is False
        assert upload["launch_arguments_note"] == "no field for them"
        assert report[status.LAUNCH_KEY]["honoured"] is False
        assert status.launch_arguments_reason(report) == (
            "launch arguments requested, not honoured by lab-box: no field for them"
        )

    def test_no_arguments_submit_and_record_as_before(self, tmp_path: Path) -> None:
        provider = _Provider(passes=True)
        app, report = _run(provider, tmp_path, "")
        (tmp_path / "again").mkdir()
        _plain, before = _run(_Provider(passes=True), tmp_path / "again", "")

        assert provider.submitted == [{}]
        assert app.container.sample_uploads == [
            {"provider": "lab-box", "submitted": True, "host": "lab.example"}
        ]
        assert report is not None and status.LAUNCH_KEY not in report
        assert report == before
        assert status.sandbox_status(report).statement == ""
        assert status.launch_arguments_reason(report) is None

    def test_the_mark_is_a_platform_mark_a_sandbox_cannot_set(self) -> None:
        assert status.LAUNCH_KEY in PLATFORM_MARKS
        app = _app(_Provider(passes=True))
        forged = {**copy.deepcopy(SANDBOX_REPORT), status.LAUNCH_KEY: {"honoured": True}}

        handed = app._mark_the_launch(forged)

        assert handed is not None and status.LAUNCH_KEY not in handed

    def test_the_pipeline_hands_the_graph_the_marked_report(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(BYTES)
        app = _app(_Provider(passes=False, note="why"))
        handed: dict[str, Any] = {}

        async def _graph(initial_state: Any) -> dict[str, Any]:
            handed.update(initial_state)
            return {}

        app._stream_the_graph = _graph

        async def _go() -> None:
            app.launch_arguments = ARGS
            await app._run_the_pipeline(
                0.0,
                file_hash=INTAKE,
                file_name="s.exe",
                sample_path=str(sample),
                static_sample_path=None,
                static_sample_paths=None,
            )

        asyncio.run(_go())
        assert handed["sandbox_report"][status.LAUNCH_KEY]["arguments"] == ARGS

    def test_arun_keeps_the_job_s_arguments(self) -> None:
        import inspect

        from malspark.app import MalsparkApp

        assert "launch_arguments" in inspect.signature(MalsparkApp.arun).parameters
        assert "launch_arguments" in inspect.signature(MalsparkApp.run).parameters


def _marked(honoured: bool, note: str = "", arguments: str = ARGS) -> dict[str, Any]:
    return {
        **copy.deepcopy(SANDBOX_REPORT),
        status.LAUNCH_KEY: {
            "provider": "lab-box",
            "arguments": arguments,
            "honoured": honoured,
            "note": note,
        },
    }


class TestTheStatement:
    def test_honoured_arguments_are_stated_whole(self) -> None:
        found = status.sandbox_status(_marked(True))

        assert found.status == status.OBSERVED
        assert found.statement == (
            f"The job asked the sandbox to launch the sample with the arguments `{ARGS}`, and "
            "the `lab-box` provider passed them: the behaviour was observed with those "
            "arguments."
        )

    def test_arguments_not_honoured_are_stated_with_why(self) -> None:
        statement = status.sandbox_status(_marked(False, "no field for them")).statement

        assert statement == (
            f"The job asked the sandbox to launch the sample with the arguments `{ARGS}`; they "
            "were not honoured by the `lab-box` provider: no field for them. Nothing here was "
            "observed with those arguments."
        )

    def test_a_fixture_keeps_its_sentence_and_adds_the_launch(self) -> None:
        report = {**_marked(False, "why"), "recorded_fixture": True}
        found = status.sandbox_status(report)

        assert found.status == status.RECORDED_FIXTURE
        assert found.statement.startswith("The sandbox report is a recorded fixture")
        assert f"`{ARGS}`" in found.statement

    def test_backticks_in_the_arguments_cannot_close_their_span(self) -> None:
        statement = status.sandbox_status(_marked(True, arguments="a`b")).statement

        assert "`` a`b ``" in statement


class TestTheLedgerAndTheReport:
    def test_the_pack_writes_the_ledger_entry_and_the_report_says_it(self, tmp_path: Path) -> None:
        from malspark.reporting.ledger_report import build_sections
        from malspark.reporting.models import MalwareReport
        from malspark.reporting.renderers import MarkdownRenderer

        report = _marked(True)
        result = _pack(tmp_path, report)
        (entry,) = [e for e in result.entries if e.tool == "sandbox_status"]
        statement = status.sandbox_status(report).statement
        assert entry.structured == {"sandbox": status.OBSERVED, "statement": statement}
        assert render_pack([entry], 0) == f"[{entry.id}] sandbox: {statement}"

        sections = [s for s in build_sections([entry]) if s.key == "sandbox_status"]
        markdown = MarkdownRenderer().render(
            MalwareReport.model_validate(
                {
                    "identity": {"hashes": {"sha256": INTAKE}},
                    "sections": [section.model_dump() for section in sections],
                }
            )
        )
        assert "launch the sample with the arguments" in markdown
        assert "--password hunter2" in markdown

    def test_a_report_without_the_mark_packs_byte_for_byte(self, tmp_path: Path) -> None:
        before = _pack(tmp_path / "a", copy.deepcopy(SANDBOX_REPORT))
        after = _pack(
            tmp_path / "b",
            _app(_Provider(passes=True))._mark_the_launch(copy.deepcopy(SANDBOX_REPORT)),
        )

        assert "sandbox_status" not in [entry.tool for entry in after.entries]
        assert render_pack(after.entries, 0) == render_pack(before.entries, 0)

    def test_the_run_s_limitations_name_arguments_not_honoured(self) -> None:
        from malspark.pipeline import nodes

        assert nodes.launch_arguments_reason is status.launch_arguments_reason
        assert status.launch_arguments_reason(_marked(False, "why")) == (
            "launch arguments requested, not honoured by lab-box: why"
        )
        assert status.launch_arguments_reason(_marked(True)) is None
        assert status.launch_arguments_reason(None) is None


class TestTheUploadRecord:
    @pytest.mark.parametrize(
        ("honoured", "note", "said"),
        [
            (True, "", f" The job's launch arguments `{ARGS}` were passed with it."),
            (
                False,
                "no field for them",
                f" The job's launch arguments `{ARGS}` were requested and not honoured: "
                "no field for them.",
            ),
        ],
    )
    def test_the_disclosure_line_states_them(self, honoured: bool, note: str, said: str) -> None:
        launch = {"provider": "lab-box", "arguments": ARGS, "honoured": honoured, "note": note}
        record = disclosure_record(
            {},
            uploads=[upload_record("lab-box", submitted=True, host="lab.example", launch=launch)],
        )
        (line,) = [line for line in disclosure_lines(record) if line.startswith("Sample upload")]
        assert line.endswith(said)

    def test_a_record_without_them_reads_as_before(self) -> None:
        plain = upload_record("lab-box", submitted=True, host="lab.example")
        assert plain == {"provider": "lab-box", "submitted": True, "host": "lab.example"}
        record = disclosure_record({}, uploads=[plain])
        (line,) = [line for line in disclosure_lines(record) if line.startswith("Sample upload")]
        assert "launch arguments" not in line
        assert line.endswith("sandbox at `lab.example` (outside this machine).")
