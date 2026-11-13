"""Each detonation is disclosed as its own submission and drawn in tables of its own.

The disclosure block lists a further detonation an agent asked for as a
submission of its own, with who asked and the arguments the agent found,
never merged into the job's own submission. The report draws a later
detonation's reads in their own tables, each titled with the launch it was
observed under, and a run with one detonation reads exactly as before.
"""

from __future__ import annotations

from typing import Any

from malspark.analysis.disclosure import disclosure_lines, disclosure_record, upload_record
from malspark.reporting.ledger_report import build_sections, launch_words
from malspark.schemas.evidence import LedgerEntry

FIRST = upload_record("cape2", submitted=True, host="cape.lab")
LAUNCH = {"provider": "cape2", "arguments": "--password x", "honoured": True, "via": "arguments="}
SECOND = {
    **upload_record("cape2", submitted=True, host="cape.lab", launch=LAUNCH),
    "detonation": "d2",
    "requested_by": ["reverser", "judge"],
}


class TestTheDisclosure:
    def test_the_job_s_own_submission_reads_as_before(self) -> None:
        (line,) = [
            x for x in disclosure_lines(disclosure_record({}, uploads=[FIRST])) if "upload" in x
        ]
        assert line.startswith("Sample upload: the sample was submitted once to the")
        assert "detonation" not in line

    def test_a_further_detonation_is_a_submission_of_its_own(self) -> None:
        lines = [
            x
            for x in disclosure_lines(disclosure_record({}, uploads=[FIRST, SECOND]))
            if x.startswith("Sample upload")
        ]
        first, second = lines
        assert "launch arguments" not in first
        assert second.startswith(
            "Sample upload (detonation 2, asked for by reverser, judge): the sample was "
            "submitted once to the"
        )
        assert "The launch arguments an agent found `--password x` were sent with the" in second
        assert "through arguments=" in second
        assert "The job's launch arguments" not in second

    def test_the_record_keeps_each_detonation_s_row(self) -> None:
        record = disclosure_record({}, uploads=[FIRST, SECOND])
        rows = [row for row in record["uploads"] if row.get("by") == "sandbox"]
        assert [row.get("detonation") for row in rows] == [None, "d2"]
        assert rows[1]["requested_by"] == ["reverser", "judge"]


def _entry(n: int, structured: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(
        id=f"ev_{n:04d}",
        agent="dynamic",
        tool="sandbox_processes",
        source="sandbox",
        facts={"v": 1, "kind": "sandbox_processes"},
        structured=structured,
        output="{}",
    )


LATER = {
    "detonation": "d2",
    "launched_with": "--password x",
    "requested_by": [{"agent": "reverser", "cited_entries": ["ev_0004"]}],
}


class TestTheReport:
    def test_a_later_detonation_s_observations_are_in_a_table_of_their_own(self) -> None:
        sections = build_sections(
            [
                _entry(1, {"processes": [{"pid": 100, "name": "locker.exe"}]}),
                _entry(2, {**LATER, "processes": [{"pid": 200, "name": "vssadmin.exe"}]}),
            ]
        )
        tables = {s.key: s for s in sections if s.key.startswith("sandbox_processes")}
        assert set(tables) == {"sandbox_processes", "sandbox_processes@d2"}
        assert [row[0] for row in tables["sandbox_processes"].rows] == ["100"]
        assert [row[0] for row in tables["sandbox_processes@d2"].rows] == ["200"]
        assert tables["sandbox_processes"].title == "Processes observed"
        assert tables["sandbox_processes@d2"].title == (
            "Processes observed when launched with `--password x` "
            "(detonation 2, asked for by reverser citing ev_0004)"
        )
        assert tables["sandbox_processes@d2"].evidence_ids == ["ev_0002"]

    def test_the_launch_words_write_the_arguments_out(self) -> None:
        said = launch_words({**LATER, "launched_with": "[ev_0001]"})
        assert "[ev_0001]" not in said


class TestTheJobsOwnDynamicBlock:
    def test_a_later_detonation_s_processes_never_join_the_job_s_tree(self) -> None:
        from malspark.reporting.ledger_projection import dynamic_from_ledger

        dynamic = dynamic_from_ledger(
            [
                _entry(1, {"processes": [{"pid": 100, "name": "locker.exe"}]}),
                _entry(2, {**LATER, "processes": [{"pid": 200, "name": "vssadmin.exe"}]}),
            ]
        )
        assert dynamic is not None
        assert [node.pid for node in dynamic.process_tree] == [100]

    def test_the_composer_is_shown_each_later_detonation_apart(self) -> None:
        from datetime import UTC, datetime

        from malspark.reporting.evidence_bundles import bundle_for
        from malspark.reporting.ledger_report import detonation_of_section
        from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity

        sections = build_sections(
            [
                _entry(1, {"processes": [{"pid": 100, "name": "locker.exe"}]}),
                _entry(2, {**LATER, "processes": [{"pid": 200, "name": "vssadmin.exe"}]}),
            ]
        )
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            sections=sections,
        )
        facts = bundle_for("execution_flow", report)["facts"]
        (later,) = facts["later_detonations"]
        assert later["observed"].startswith("Processes observed when launched with `--password x`")
        assert later["entries"] == ["ev_0002"] and later["rows"][0].startswith("200")
        assert detonation_of_section("sandbox_processes@d2") == "d2"
        assert detonation_of_section("sandbox_processes") == ""
        # A run with no further detonation is shown nothing more.
        plain = report.model_copy(
            update={"sections": build_sections([_entry(1, {"processes": []})])}
        )
        assert "later_detonations" not in bundle_for("execution_flow", plain)["facts"]
