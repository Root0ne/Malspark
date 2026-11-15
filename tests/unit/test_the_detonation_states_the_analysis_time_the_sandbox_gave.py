"""A detonation's record states the analysis time asked and the time the sandbox granted (T-695).

A hosted sandbox can grant a task less analysis time than the submission
asked, with no error. The run's detonation record
(``run_summary.environment.detonations``) carries, per sandbox task, the
analysis time the submission asked (``requested_seconds``, what the provider
states it sent with a submission it posted) and the time the sandbox's own
report states it granted the task (``granted_seconds``, read by the report's
reader where its format places it). Where the sandbox granted a task less than
was asked, the limitations inventory says so with both numbers; where the
report states no time, the record says "not reported" and no limitation is
written.

Every name and number in the synthetic tests is made up; the stored-shape tests
read the shipped fixtures as they are.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from malspark.analysis.run_environment import STATED_ENTRIES, detonations_record
from malspark.core.report_formats import (
    MAX_STATED_SECONDS,
    MIN_STATED_SECONDS,
    ReportFormat,
    format_named,
    seconds_stated,
)
from malspark.providers.detonation import DetonationRecord, stated_by
from malspark.providers.sandbox.readers import report_reader, required_reader
from malspark.reporting.limitation_inventory import build_inventory, printed_rows
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.tools.capabilities import NOT_REPORTED

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "sandbox"
NR = NOT_REPORTED


def _overview(*tasks: dict[str, Any]) -> dict[str, Any]:
    return {
        "sample": {"id": "box-0001", "sha256": "e" * 64},
        "analysis": {"score": 1},
        "tasks": list(tasks),
    }


def _task(name: str, seconds: Any = None, kind: str = "behavioral", **more: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name, "kind": kind, "status": "reported", **more}
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


def _report(*rows: dict[str, Any], dynamic: bool = True) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64), file_type="PE32"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        dynamic=DynamicBehavior() if dynamic else None,
        run_summary={"environment": {"v": 5, "detonations": list(rows)}},
    )


def _sandbox_texts(report: MalwareReport, entries: list[Any] | None = None, **kw: Any) -> list[str]:
    inventory = build_inventory(report, entries or [])
    return [row.text for row in printed_rows(inventory, **kw) if row.part == "sandbox"]


# ---------------------------------------------------------------------------
# What a time is


class TestWhatATimeIs:
    @pytest.mark.parametrize(
        "value", [1, 75, 0.5, 149.9, 150.0, MIN_STATED_SECONDS, 0.0012345, MAX_STATED_SECONDS]
    )
    def test_a_number_above_zero_within_the_bound_is_kept_as_stated(self, value: Any) -> None:
        kept = seconds_stated(value)
        assert kept == value and type(kept) is type(value)

    @pytest.mark.parametrize(
        "value",
        [
            0,
            0.0,
            -0.0,
            -1,
            -0.5,
            1e-9,
            0.0004,
            0.0005,
            0.000999,
            True,
            False,
            "150",
            None,
            math.nan,
            math.inf,
            -math.inf,
            MAX_STATED_SECONDS + 1,
            MAX_STATED_SECONDS + 0.5,
            1e308,
            10**400,
            [],
            {},
        ],
    )
    def test_anything_else_is_no_time_and_never_raises(self, value: Any) -> None:
        assert seconds_stated(value) is None

    def test_the_bounds_are_declared(self) -> None:
        assert MIN_STATED_SECONDS == 0.001
        assert MAX_STATED_SECONDS == 10**7


# ---------------------------------------------------------------------------
# What each reader reads as the time the sandbox granted


class TestTheReaderReadsTheTimeGranted:
    def test_each_behavioural_task_states_its_own_time(self) -> None:
        reader = required_reader("triage")
        facts = reader.run_facts(
            _overview(_task("run_a", 75), _task("run_b", 90.5), _task("still", kind="static"))
        )
        assert facts["granted_seconds"] == {"run_a": 75, "run_b": 90.5}

    def test_a_behavioural_task_without_a_time_reads_not_reported(self) -> None:
        reader = required_reader("triage")
        facts = reader.run_facts(
            _overview(
                _task("run_a"),
                _task("run_b", True),
                _task("run_c", -4),
                _task("run_d", "x"),
                _task("run_e", 0),
                _task("run_f", math.inf),
                _task("run_g", math.nan),
                _task("run_h", MAX_STATED_SECONDS + 1),
                _task("run_i", 60),
                _task("still", kind="static"),
            )
        )
        assert facts["granted_seconds"] == {
            "run_a": NR,
            "run_b": NR,
            "run_c": NR,
            "run_d": NR,
            "run_e": NR,
            "run_f": NR,
            "run_g": NR,
            "run_h": NR,
            "run_i": 60,
        }

    def test_a_value_that_is_no_time_costs_the_run_no_other_fact(self) -> None:
        from malspark.providers.sandbox.readers import run_facts_of

        overview = _overview(_task("run_a", math.inf, resource="win-img"))
        facts = run_facts_of(required_reader("triage"), overview)
        assert facts is not None
        assert facts["guest"] == {"run_a": {"resource": "win-img"}}
        assert facts["granted_seconds"] == {"run_a": NR}

    def test_the_detonation_report_formats_declare_no_granted_time(self) -> None:
        for name in ("cape2", "cuckoo"):
            assert format_named(name).granted_seconds_paths == []
            reader = report_reader(name)
            assert reader is not None
            facts = reader.run_facts({"info": {"id": 3, "duration": 47}})
            assert facts == {"task_ids": {"/info/id": "3"}}

    def test_the_stored_cape_report_states_no_granted_time(self) -> None:
        report = json.loads((FIX / "cape2_report.json").read_text())
        reader = report_reader("cape2")
        assert reader is not None
        assert "granted_seconds" not in reader.run_facts(report)

    def test_a_declared_format_places_the_time_for_any_reader(self) -> None:
        declared = ReportFormat(
            name="acme_box",
            detect=[[{"path": "/acme", "types": ["object"]}]],  # type: ignore[list-item]
            task_id_paths=["/acme/ticket"],
            granted_seconds_paths=["/acme/granted"],
            reader="generic",
        )
        reader = required_reader("generic")
        facts = reader.run_facts({"acme": {"ticket": "R-5", "granted": 33}}, declared)
        assert facts == {"task_ids": {"/acme/ticket": "R-5"}, "granted_seconds": 33}
        # A format that places no time: the facts are what they were.
        plain = declared.model_copy(update={"granted_seconds_paths": []})
        assert reader.run_facts({"acme": {"ticket": "R-5", "granted": 33}}, plain) == {
            "task_ids": {"/acme/ticket": "R-5"}
        }

    def test_the_first_declared_path_that_holds_a_value_wins(self) -> None:
        declared = ReportFormat(
            name="acme_box",
            detect=[[{"path": "/acme", "types": ["object"]}]],  # type: ignore[list-item]
            task_id_paths=["/acme/ticket", "/acme/job"],
            granted_seconds_paths=["/acme/granted", "/acme/limit"],
            reader="generic",
        )
        reader = required_reader("generic")
        both = {"acme": {"ticket": "R-5", "job": "J-9", "granted": 33, "limit": 44}}
        assert reader.run_facts(both, declared) == {
            "task_ids": {"/acme/ticket": "R-5"},
            "granted_seconds": 33,
        }
        later = {"acme": {"job": "J-9", "granted": 0, "limit": 44}}
        assert reader.run_facts(later, declared) == {
            "task_ids": {"/acme/job": "J-9"},
            "granted_seconds": 44,
        }

    def test_the_stored_hosted_overview_states_each_task_s_time(self) -> None:
        overview = json.loads((FIX / "triage_live" / "overview.json").read_text())
        facts = required_reader("triage").run_facts(overview)
        assert facts["granted_seconds"] == {"behavioral1": 150, "behavioral2": 150}


# ---------------------------------------------------------------------------
# What a provider states it asked


SAMPLE_ID = "261114-x2ds4scy5t"


class TestTheProviderStatesWhatItAsked:
    def _provider(self, posted: Any, listed: list[dict[str, Any]], **over: Any) -> Any:
        from tests.unit.providers.sandbox.test_triage_provider import _provider

        overview = (FIX / "triage_live" / "overview.json").read_bytes()
        tasks = {
            name: (FIX / "triage_live" / f"{name}.json").read_bytes()
            for name in ("behavioral1", "behavioral2")
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return posted(request)
            if request.url.path.endswith("overview.json"):
                return httpx.Response(200, content=overview)
            for name, body in tasks.items():
                if f"/{name}/" in request.url.path:
                    return httpx.Response(200, content=body)
            if request.url.path.endswith("/samples"):
                return httpx.Response(200, json={"data": listed})
            return httpx.Response(404)

        provider = _provider(handler, **over)
        provider._sleep = lambda _s: None
        provider._now_utc = lambda: datetime(2026, 11, 14, 19, 25, 0, tzinfo=UTC)
        return provider

    @staticmethod
    def _sample(tmp_path: Path) -> tuple[Path, str]:
        path = tmp_path / "sample.bin"
        path.write_bytes(b"MZ" + b"\x01" * 32)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def _posted_and_fetched(self, tmp_path: Path, **over: Any) -> dict[str, Any]:
        path, _sha = self._sample(tmp_path)
        provider = self._provider(
            lambda _r: httpx.Response(200, json={"id": SAMPLE_ID}), [], **over
        )
        assert provider.submit(path) == SAMPLE_ID
        return stated_by(provider, provider.fetch(SAMPLE_ID)) or {}

    def test_a_submission_this_call_posted_states_the_time_set(self, tmp_path: Path) -> None:
        facts = self._posted_and_fetched(tmp_path, analysis_seconds=420)
        assert facts["requested_seconds"] == 420
        assert facts["granted_seconds"] == {"behavioral1": 150, "behavioral2": 150}

    def test_no_time_set_asks_none(self, tmp_path: Path) -> None:
        facts = self._posted_and_fetched(tmp_path)
        assert "requested_seconds" not in facts
        assert facts["granted_seconds"] == {"behavioral1": 150, "behavioral2": 150}

    def test_a_report_fetched_without_a_submission_states_no_time_asked(self) -> None:
        provider = self._provider(lambda _r: httpx.Response(500), [], analysis_seconds=420)
        facts = stated_by(provider, provider.fetch(SAMPLE_ID)) or {}
        assert "requested_seconds" not in facts
        assert facts["granted_seconds"] == {"behavioral1": 150, "behavioral2": 150}

    def test_a_sample_the_account_already_holds_states_no_time_asked(self, tmp_path: Path) -> None:
        path, sha = self._sample(tmp_path)

        def dropped(request: httpx.Request) -> httpx.Response:
            raise httpx.RemoteProtocolError("dropped", request=request)

        held = [{"id": SAMPLE_ID, "sha256": sha, "submitted": "2026-11-14T19:20:37Z"}]
        provider = self._provider(dropped, held, analysis_seconds=420)
        assert provider.submit(path) == SAMPLE_ID
        facts = stated_by(provider, provider.fetch(SAMPLE_ID)) or {}
        assert "requested_seconds" not in facts
        row = _row(facts, task_id=SAMPLE_ID)
        assert row["analysis_time"] == [
            {"task": "behavioral1", "requested_seconds": NR, "granted_seconds": 150},
            {"task": "behavioral2", "requested_seconds": NR, "granted_seconds": 150},
        ]


# ---------------------------------------------------------------------------
# What the record carries


class TestTheRecordCarriesBothTimes:
    def test_per_task_both_times(self) -> None:
        row = _row({"granted_seconds": {"run_a": 75, "run_b": 90}, "requested_seconds": 300})
        assert row["analysis_time"] == [
            {"task": "run_a", "requested_seconds": 300, "granted_seconds": 75},
            {"task": "run_b", "requested_seconds": 300, "granted_seconds": 90},
        ]

    def test_a_flat_time_is_the_task_s_the_submission_answered(self) -> None:
        row = _row({"granted_seconds": 47})
        assert row["analysis_time"] == [
            {"task": "job-41", "requested_seconds": NR, "granted_seconds": 47}
        ]

    def test_a_report_that_states_no_time_is_said_so(self) -> None:
        row = _row({"requested_seconds": 300})
        assert row["analysis_time"] == [
            {"task": "job-41", "requested_seconds": 300, "granted_seconds": NR}
        ]

    def test_neither_time_stated_is_not_reported(self) -> None:
        assert _row({})["analysis_time"] == NR
        assert _row({"granted_seconds": 0, "requested_seconds": True})["analysis_time"] == NR
        assert _row(None, report=None, failure="no report")["analysis_time"] == NR

    def test_a_named_task_whose_value_is_no_time_reads_not_reported(self) -> None:
        stated = {"run_a": True, "run_b": "9", "run_c": 0, "run_d": NR, "run_e": math.inf}
        for asked, kept in ((-1, NR), (300, 300)):
            row = _row({"granted_seconds": stated, "requested_seconds": asked})
            assert row["analysis_time"] == [
                {"task": name, "requested_seconds": kept, "granted_seconds": NR} for name in stated
            ]

    def test_a_time_is_kept_as_stated(self) -> None:
        row = _row({"granted_seconds": {"run_a": 149.9}, "requested_seconds": 150})
        assert row["analysis_time"] == [
            {"task": "run_a", "requested_seconds": 150, "granted_seconds": 149.9}
        ]

    def test_the_row_states_at_most_the_capped_number_of_tasks(self) -> None:
        stated = {f"run_{i:02d}": 60 for i in range(STATED_ENTRIES + 8)}
        row = _row({"granted_seconds": stated, "requested_seconds": 300})
        assert [t["task"] for t in row["analysis_time"]] == list(stated)[:STATED_ENTRIES]

    def test_a_value_that_is_no_time_costs_the_row_no_other_fact(self) -> None:
        row = _row({"granted_seconds": math.inf, "guest": {"run_a": {"os": "box-os"}}})
        assert row["guest"] == {"run_a": {"os": "box-os"}}
        assert row["analysis_time"] == NR


# ---------------------------------------------------------------------------
# What the limitations say


def _time_row(task: Any, requested: Any, granted: Any) -> dict[str, Any]:
    return {"task": task, "requested_seconds": requested, "granted_seconds": granted}


def _sections_entry() -> LedgerEntry:
    return LedgerEntry(
        id="ev_0001",
        tool="section_index",
        source="mcp:box",
        facts={"v": 1, "kind": "sandbox_sections"},
        structured={
            "sections": {
                "processes": {"items": 3, "prefix": "proc"},
                "registry": {
                    "no": "no: the report lists `registry` as unavailable from its sandbox"
                },
                "mutexes": {"no": "no: the report holds no `mutexes`"},
            },
            "tool": "sandbox_items",
        },
    )


class TestTheLimitationsSayAShorterGrant:
    def test_tasks_granted_less_than_asked_are_named_with_both_numbers(self) -> None:
        report = _report(
            {
                "detonation": "d1",
                "analysis_time": [_time_row("run_a", 300, 75), _time_row("run_b", 300, 75)],
            },
            {"detonation": "d2", "analysis_time": [_time_row("job-42", 1500, 120)]},
        )
        inventory = build_inventory(report, [])
        assert [
            (s.detonation, s.task, s.requested_seconds, s.granted_seconds)
            for s in inventory.short_analyses
        ] == [("d1", "run_a", 300, 75), ("d1", "run_b", 300, 75), ("d2", "job-42", 1500, 120)]
        assert _sandbox_texts(report) == [
            "Sandbox: d1's tasks run_a and run_b were given 75 s, not the 300 s asked; "
            "d2's task job-42 was given 120 s, not the 1,500 s asked."
        ]

    def test_a_task_granted_what_was_asked_or_no_stated_time_adds_nothing(self) -> None:
        for rows in (
            [_time_row("run_a", 300, 300), _time_row("run_b", 300, 420)],
            [_time_row("run_a", 300, NR), _time_row("run_b", NR, 75)],
            [_time_row("run_a", 300, 0), _time_row("run_b", 300, True), _time_row("run_c", 0, 0)],
            [_time_row("run_a", 300, math.inf), _time_row("run_b", math.nan, 75)],
            # Below a thousandth of a second a number is no time.
            [_time_row("run_a", 600, 1e-9), _time_row("run_b", 0.0005, 0.0004)],
        ):
            report = _report({"detonation": "d1", "analysis_time": rows})
            assert build_inventory(report, []).short_analyses == []
        report = _report({"detonation": "d1", "analysis_time": NR})
        assert build_inventory(report, []).short_analyses == []

    @pytest.mark.parametrize(("asked", "granted"), [(600, 1e-9), (0.0005, 0.0004)])
    def test_below_a_thousandth_of_a_second_no_time_and_no_clause(
        self, asked: Any, granted: Any
    ) -> None:
        row = _row({"granted_seconds": {"run_a": granted}, "requested_seconds": asked})
        kept = asked if seconds_stated(asked) is not None else NR
        assert row["analysis_time"] == [_time_row("run_a", kept, NR)]
        report = _report(
            {"detonation": "d1", "analysis_time": [_time_row("run_a", asked, granted)]}
        )
        assert _sandbox_texts(report) == []

    @pytest.mark.parametrize(
        ("asked", "granted", "said"),
        [
            (150, 149.9, "was given 149.9 s, not the 150 s asked"),
            (150, 149.96, "was given 149.96 s, not the 150 s asked"),
            # Three decimals would print both as 150: both are printed in full.
            (150, 149.9996, "was given 149.9996 s, not the 150 s asked"),
            (150.0004, 150, "was given 150 s, not the 150.0004 s asked"),
            (600.0, 150.0, "was given 150 s, not the 600 s asked"),
            (1500, 120, "was given 120 s, not the 1,500 s asked"),
            (300.25, 75.5, "was given 75.5 s, not the 300.25 s asked"),
            # Three decimals keep what two would lose.
            (150, 149.125, "was given 149.125 s, not the 150 s asked"),
            # Plain decimals, never a 0 and never scientific notation.
            (0.002, 0.0012345, "was given 0.001 s, not the 0.002 s asked"),
            (0.0012, 0.0011, "was given 0.0011 s, not the 0.0012 s asked"),
            (150, 149.99961234, "was given 149.9996 s, not the 150 s asked"),
            (10**7, 9999999.9999999, "was given 9,999,999.9999999 s, not the 10,000,000 s asked"),
            (0.0010000001, 0.001, "was given 0.001 s, not the 0.0010000001 s asked"),
            # Rounded as written, a half up, not as the nearest binary number would.
            (150, 149.0005, "was given 149.001 s, not the 150 s asked"),
            (150, 149.1005, "was given 149.101 s, not the 150 s asked"),
            # Two times apart only past seventeen decimals are printed in full.
            (
                0.001234567890123457,
                0.0012345678901234567,
                "was given 0.0012345678901234567 s, not the 0.001234567890123457 s asked",
            ),
        ],
    )
    def test_a_time_is_compared_and_printed_as_stated_never_two_alike(
        self, asked: Any, granted: Any, said: str
    ) -> None:
        report = _report(
            {"detonation": "d1", "analysis_time": [_time_row("run_a", asked, granted)]}
        )
        assert _sandbox_texts(report) == [f"Sandbox: d1's task run_a {said}."]

    def test_a_row_or_task_without_a_name_gives_no_clause(self) -> None:
        short = [_time_row("run_a", 300, 75)]
        for row in (
            {"analysis_time": short},
            {"detonation": "", "analysis_time": short},
            {"detonation": None, "analysis_time": short},
            {"detonation": NR, "analysis_time": short},
            {"detonation": "d1", "analysis_time": [_time_row("", 300, 75)]},
            {"detonation": "d1", "analysis_time": [_time_row(None, 300, 75)]},
            {"detonation": "d1", "analysis_time": [_time_row(NR, 300, 75)]},
            {
                "detonation": "d1",
                "analysis_time": [{"requested_seconds": 300, "granted_seconds": 1}],
            },
        ):
            report = _report(row)
            assert build_inventory(report, []).short_analyses == []
            assert _sandbox_texts(report) == []

    def test_the_clause_names_at_most_the_capped_number_of_tasks_then_how_many_more(self) -> None:
        names = [f"t{i:02d}" for i in range(STATED_ENTRIES + 8)]
        report = _report(
            {"detonation": "d1", "analysis_time": [_time_row(n, 300, 75) for n in names]}
        )
        (text,) = _sandbox_texts(report)
        listed = ", ".join(names[: STATED_ENTRIES - 1]) + f", {names[STATED_ENTRIES - 1]}"
        assert text == (
            f"Sandbox: d1's tasks {listed} and 8 more were given 75 s, not the 300 s asked."
        )

    def test_the_clause_follows_what_the_sandbox_report_lacks(self) -> None:
        report = _report({"detonation": "d1", "analysis_time": [_time_row("run_a", 300, 75)]})
        assert _sandbox_texts(report, [_sections_entry()]) == [
            "Sandbox report [ev_0001]: registry is unavailable from the sandbox; mutexes is not "
            "in the sandbox report as read; d1's task run_a was given 75 s, not the 300 s asked."
        ]
        unobserved = _report(
            {"detonation": "d1", "analysis_time": [_time_row("run_a", 300, 75)]}, dynamic=False
        )
        assert _sandbox_texts(unobserved) == [
            "Sandbox: no sandbox observation of the sample is recorded in this run; "
            "d1's task run_a was given 75 s, not the 300 s asked."
        ]

    def test_the_names_are_written_by_the_renderer_s_naming(self) -> None:
        report = _report({"detonation": "d1", "analysis_time": [_time_row("run_a", 300, 75)]})
        assert _sandbox_texts(report, name=lambda s: f"<{s}>") == [
            "Sandbox: <d1>'s task <run_a> was given 75 s, not the 300 s asked."
        ]

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
        assert (
            "d1's tasks behavioral1 and behavioral2 were given 150 s, not the 600 s asked" in text
        )
