"""A detonation's record states the analysis time asked and the time the sandbox gave (T-695).

A hosted sandbox can run a task for less time than the submission asked, with
no error. The run's detonation record (``run_summary.environment.detonations``)
carries, per sandbox task, the analysis time the submission asked
(``requested_seconds``, what the provider states it sent) and the time the
sandbox's own report states the task ran (``effective_seconds``, read by the
report's reader where its format places it). Where the sandbox gave a task less
than was asked, the limitations inventory says so with both numbers; where the
report states no time, the record says "not reported" and no limitation is
written.

Every name and number in the synthetic tests is made up; the stored-shape tests
read the shipped fixtures as they are.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx

from malspark.analysis.run_environment import detonations_record
from malspark.core.report_formats import ReportFormat
from malspark.providers.detonation import DetonationRecord, stated_by
from malspark.providers.sandbox.readers import report_reader, required_reader
from malspark.reporting.limitation_inventory import build_inventory, printed_rows
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from malspark.tools.capabilities import NOT_REPORTED

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "sandbox"
NR = NOT_REPORTED


def _overview(*tasks: dict[str, Any]) -> dict[str, Any]:
    return {
        "sample": {"id": "box-0001", "sha256": "e" * 64},
        "analysis": {"score": 1},
        "tasks": list(tasks),
    }


def _task(name: str, seconds: Any = None, kind: str = "behavioral") -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "kind": kind, "status": "reported"}
    if seconds is not None:
        row["timeout"] = seconds
    return row


def _record(facts: dict[str, Any] | None, **over: Any) -> DetonationRecord:
    fields: dict[str, Any] = {
        "provider": "boxprov",
        "task_id": "job-41",
        "report": {"signatures": []},
        "sandbox_facts": facts,
    }
    fields.update(over)
    return DetonationRecord(**fields)


def _row(facts: dict[str, Any] | None, **over: Any) -> dict[str, Any]:
    (row,) = detonations_record(SimpleNamespace(detonations=[_record(facts, **over)])) or []
    return row


def _report(*rows: dict[str, Any]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64), file_type="PE32"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        dynamic=DynamicBehavior(),
        run_summary={"environment": {"v": 5, "detonations": list(rows)}},
    )


def _sandbox_texts(report: MalwareReport) -> list[str]:
    inventory = build_inventory(report, [])
    return [row.text for row in printed_rows(inventory) if row.part == "sandbox"]


# ---------------------------------------------------------------------------
# What each reader reads as the time the sandbox gave


class TestTheReaderReadsTheTimeGiven:
    def test_each_behavioural_task_states_its_own_time(self) -> None:
        reader = required_reader("triage")
        facts = reader.run_facts(
            _overview(_task("run_a", 75), _task("run_b", 90), _task("still", kind="static"))
        )
        assert facts["analysis_seconds"] == {"run_a": 75, "run_b": 90}

    def test_a_task_without_a_time_or_with_a_value_that_is_no_time_states_none(self) -> None:
        reader = required_reader("triage")
        facts = reader.run_facts(
            _overview(_task("run_a"), _task("run_b", True), _task("run_c", -4), _task("run_d", "x"))
        )
        assert "analysis_seconds" not in facts

    def test_a_flat_report_states_the_time_its_format_places(self) -> None:
        reader = required_reader("cape2")
        assert reader.run_facts({"info": {"id": 3, "duration": 47}})["analysis_seconds"] == 47
        assert "analysis_seconds" not in reader.run_facts({"info": {"id": 3}})

    def test_a_declared_format_places_the_time_for_any_reader(self) -> None:
        declared = ReportFormat(
            name="acme_box",
            detect=[[{"path": "/acme", "types": ["object"]}]],  # type: ignore[list-item]
            task_id_paths=["/acme/ticket"],
            analysis_seconds_paths=["/acme/ran_for"],
            reader="generic",
        )
        reader = required_reader("generic")
        facts = reader.run_facts({"acme": {"ticket": "R-5", "ran_for": 33}}, declared)
        assert facts == {"task_ids": {"/acme/ticket": "R-5"}, "analysis_seconds": 33}
        # A format that places no time: the facts are what they were.
        plain = declared.model_copy(update={"analysis_seconds_paths": []})
        assert reader.run_facts({"acme": {"ticket": "R-5", "ran_for": 33}}, plain) == {
            "task_ids": {"/acme/ticket": "R-5"}
        }

    def test_the_stored_hosted_overview_states_each_task_s_time(self) -> None:
        overview = json.loads((FIX / "triage_live" / "overview.json").read_text())
        facts = required_reader("triage").run_facts(overview)
        assert facts["analysis_seconds"] == {"behavioral1": 150, "behavioral2": 150}

    def test_the_stored_cape_report_states_its_duration(self) -> None:
        report = json.loads((FIX / "cape2_report.json").read_text())
        reader = report_reader("cape2")
        assert reader is not None
        assert reader.run_facts(report)["analysis_seconds"] == 181


# ---------------------------------------------------------------------------
# What a provider states it asked


class TestTheProviderStatesWhatItAsked:
    def _fetch(self, **over: Any) -> dict[str, Any]:
        from tests.unit.providers.sandbox.test_triage_provider import _provider

        overview = (FIX / "triage_live" / "overview.json").read_bytes()
        tasks = {
            name: (FIX / "triage_live" / f"{name}.json").read_bytes()
            for name in ("behavioral1", "behavioral2")
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("overview.json"):
                return httpx.Response(200, content=overview)
            for name, body in tasks.items():
                if f"/{name}/" in request.url.path:
                    return httpx.Response(200, content=body)
            return httpx.Response(404)

        provider = _provider(handler, **over)
        return stated_by(provider, provider.fetch("261114-x2ds4scy5t")) or {}

    def test_the_time_set_is_the_time_asked(self) -> None:
        facts = self._fetch(analysis_seconds=420)
        assert facts["requested_seconds"] == 420
        assert facts["analysis_seconds"] == {"behavioral1": 150, "behavioral2": 150}

    def test_no_time_set_asks_none(self) -> None:
        facts = self._fetch()
        assert "requested_seconds" not in facts
        assert facts["analysis_seconds"] == {"behavioral1": 150, "behavioral2": 150}


# ---------------------------------------------------------------------------
# What the record carries


class TestTheRecordCarriesBothTimes:
    def test_per_task_both_times(self) -> None:
        row = _row({"analysis_seconds": {"run_a": 75, "run_b": 90}, "requested_seconds": 300})
        assert row["analysis_time"] == [
            {"task": "run_a", "requested_seconds": 300, "effective_seconds": 75},
            {"task": "run_b", "requested_seconds": 300, "effective_seconds": 90},
        ]

    def test_a_flat_time_is_the_task_s_the_submission_answered(self) -> None:
        row = _row({"analysis_seconds": 47})
        assert row["analysis_time"] == [
            {"task": "job-41", "requested_seconds": NR, "effective_seconds": 47}
        ]

    def test_a_report_that_states_no_time_is_said_so(self) -> None:
        row = _row({"requested_seconds": 300})
        assert row["analysis_time"] == [
            {"task": "job-41", "requested_seconds": 300, "effective_seconds": NR}
        ]

    def test_neither_time_stated_is_not_reported(self) -> None:
        assert _row({})["analysis_time"] == NR
        assert _row(None, report=None, failure="no report")["analysis_time"] == NR

    def test_a_value_that_is_no_time_is_not_reported(self) -> None:
        row = _row({"analysis_seconds": {"run_a": True, "run_b": "9"}, "requested_seconds": -1})
        assert row["analysis_time"] == NR


# ---------------------------------------------------------------------------
# What the limitations say


def _time_row(task: str, requested: Any, effective: Any) -> dict[str, Any]:
    return {"task": task, "requested_seconds": requested, "effective_seconds": effective}


class TestTheLimitationsSayAShorterRun:
    def test_tasks_given_less_than_asked_are_named_with_both_numbers(self) -> None:
        report = _report(
            {
                "detonation": "d1",
                "analysis_time": [_time_row("run_a", 300, 75), _time_row("run_b", 300, 75)],
            },
            {"detonation": "d2", "analysis_time": [_time_row("job-42", 300, 120)]},
        )
        inventory = build_inventory(report, [])
        assert [
            (s.detonation, s.task, s.requested_seconds, s.effective_seconds)
            for s in inventory.short_analyses
        ] == [("d1", "run_a", 300, 75), ("d1", "run_b", 300, 75), ("d2", "job-42", 300, 120)]
        assert _sandbox_texts(report) == [
            "Sandbox: d1's tasks run_a and run_b ran for 75 s, not the 300 s asked; "
            "d2's task job-42 ran for 120 s, not the 300 s asked."
        ]

    def test_a_task_given_what_was_asked_or_no_stated_time_adds_nothing(self) -> None:
        for rows in (
            [_time_row("run_a", 300, 300), _time_row("run_b", 300, 420)],
            [_time_row("run_a", 300, NR), _time_row("run_b", NR, 75)],
        ):
            report = _report({"detonation": "d1", "analysis_time": rows})
            assert build_inventory(report, []).short_analyses == []
        report = _report({"detonation": "d1", "analysis_time": NR})
        assert build_inventory(report, []).short_analyses == []

    def test_a_stored_record_without_the_times_reads_as_before(self) -> None:
        stored = _report({"detonation": "d1", "provider": "boxprov"})
        assert build_inventory(stored, []).short_analyses == []
        assert _sandbox_texts(stored) == []
        unobserved = stored.model_copy(update={"dynamic": None})
        assert _sandbox_texts(unobserved) == [
            "Sandbox: no sandbox observation of the sample is recorded in this run."
        ]
        assert "short_analyses" in build_inventory(stored, []).model_dump()

    def test_the_stored_hosted_run_shape_reads_through_to_the_limitation(self) -> None:
        overview = json.loads((FIX / "triage_live" / "overview.json").read_text())
        facts = required_reader("triage").run_facts(overview)
        facts["requested_seconds"] = 600
        row = _row(facts)
        report = _report(row)
        (text,) = _sandbox_texts(report)
        assert "d1's tasks behavioral1 and behavioral2 ran for 150 s, not the 600 s asked" in text
