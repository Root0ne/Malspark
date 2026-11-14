"""In a launcher run, the files the launcher's own process leaves are the launcher's.

A sandbox lists the files a run wrote and the memory regions it dumped, each
with the process that wrote it. A row written by a process of the launcher's
lineage (the script host running the generated launcher, not the program it
started) is the launcher's, read as the signatures are; a row naming no writer
keeps the reading by the archive's members. A member's copy is the platform's
only at the member's own place in the guest, the folder the archive was
unpacked into joined with the member's path inside it, holding the member's
digest where the row states one: elsewhere, a file with a member's digest is a
copy the sample made, and one at the member's place with another digest is the
member changed.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for two harmless submissions: an archive whose launcher starts cmd.exe
with a text file beside it (the second also holds ``sub/marker2.txt``).
cmd.exe stands for the started program here.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from malspark.pipeline.sandbox_status import sandbox_status
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_dropped_files
from malspark.schemas.sandbox_document import (
    LAUNCH_KEY,
    LAUNCHER_FILES_KEY,
    MEMBER_FACT_KEY,
    UNPLACED_MEMBER_FILES_KEY,
    UNSETTLED_LAUNCHER_FILES_KEY,
    sandbox_document,
    unearned_marks_removed,
)
from malspark.schemas.sandbox_report import (
    DROPPED_BY_LAUNCHER,
    DROPPED_BY_LAUNCHER_REACHED,
    DROPPED_SAMPLE,
    LINEAGE_KEY,
    LINEAGE_LAUNCHER_UNSETTLED,
    LINEAGE_REASON_KEY,
    MEMBER_CHANGED,
    MEMBER_COPIED,
    PROCESS_TASK_KEY,
    SandboxReport,
    attribute_the_launcher,
)

LIVE = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox" / "triage_live"
TEMP = "C:\\Users\\Admin\\AppData\\Local\\Temp"
PLACE = "c:/users/admin/appdata/local/temp"
HOSTS = ["powershell.exe", "pwsh.exe"]
# The first submission's launcher, with cmd.exe in the sample's place.
FIRST = {
    "sample_member": "cmd.exe",
    "launcher_member": "launch.ps1",
    "script_host_images": HOSTS,
    "launcher_sha256": "aba6bd87cb5e4c8d594551ce5194d6a120ca721d85d766c0317598e0b5754a6e",
    "sample_sha256": "",
}
MARKER = "ed5b8120601641c516d02ed9dc643a59648524248d5e2af877da39ea253c723e"
MARKER2 = "00a6580137a3a1ab1158cfb7f034486e74b561dbbeb40a375596dc0068c7b403"
# The second submission's launcher, its text file in the sample's place.
SECOND = {
    "sample_member": "marker.txt",
    "launcher_member": "launch.ps1",
    "script_host_images": HOSTS,
    "launcher_sha256": "0e60aa6a890ae2419eae133ba99e941fb80bca4fac6bf721c68f8362b3c3f82f",
    "sample_sha256": MARKER,
}


def _json(name: str) -> Any:
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


def _read(overview: str, tasks: dict[str, dict[str, Any]]) -> SandboxReport:
    return required_reader("triage").read(
        _json(overview), provider="triage", task_id="s1", task_reports=tasks
    )


def _first(*rows: dict[str, Any], signatures: list[dict[str, Any]] | None = None) -> SandboxReport:
    one, two = _json("behavioral1.json"), _json("behavioral2.json")
    one["dumped"] += list(rows)
    one["signatures"] += signatures or []
    return _read("overview.json", {"behavioral1": one, "behavioral2": two})


def _listed(report: SandboxReport) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The sample's dropped files and the launcher's, as the dropped-file view lists them."""
    answer = sandbox_dropped_files(sandbox_document(report))
    return answer["dropped"], answer.get("platform_files") or []


def _launch_mark(record: dict[str, Any]) -> dict[str, Any]:
    launcher = {**record, "launcher_text": "Start-Process ...", "script_host": "PowerShell"}
    return {"arguments": "/c x", "provider": "triage", "honoured": True, "launcher": launcher}


def _second(*rows: dict[str, Any]) -> SandboxReport:
    task = _json("second_behavioral1.json")
    task["dumped"] += list(rows)
    return _read("second_overview.json", {"behavioral1": task})


def _reasons(report: SandboxReport) -> dict[str, str | None]:
    return {
        str(row.get("path") or row.get("name")): row.get(LINEAGE_REASON_KEY)
        for row in report.dropped_files
    }


class TestTheLauncherSOwnProcess:
    def test_its_policy_test_script_and_memory_regions_are_the_launcher_s(self) -> None:
        report = _first()
        attribute_the_launcher(report, FIRST)
        # Every row of both tasks is the script host's (procid 84 and 87).
        assert len(report.dropped_files) == 7
        assert set(_reasons(report).values()) == {DROPPED_BY_LAUNCHER}
        assert all(row[LINEAGE_KEY] == "launcher" for row in report.dropped_files)
        answer = sandbox_dropped_files(sandbox_document(report))
        assert answer["dropped"] == [] and answer["total"] == 0
        assert len(answer["platform_files"]) == 7
        # Each listed with its writer, the script host (guest pids 1756 and 4316).
        assert {tuple(row["pids"]) for row in answer["platform_files"]} == {("1756",), ("4316",)}
        assert {row[LINEAGE_REASON_KEY] for row in answer["platform_files"]} == {
            DROPPED_BY_LAUNCHER
        }
        # The policy-test script the script host wrote on start, by its digest.
        policy_test = "96ad1146eb96877eab5942ae0736b82d8b5e2039a80d3d6932665c1a4c87dcf7"
        assert policy_test in {row["sha256"] for row in answer["platform_files"]}
        assert DROPPED_BY_LAUNCHER == "written by the generated launcher's process"

    def test_a_file_the_started_program_writes_is_the_sample_s(self) -> None:
        written = {"pid": 3444, "procid": 86, "path": f"{TEMP}\\argtest.txt", "sha256": "c" * 64}
        report = _first(written)
        attribute_the_launcher(report, FIRST)
        (row,) = [r for r in report.dropped_files if r.get("procid") == 86]
        assert LINEAGE_KEY not in row and MEMBER_FACT_KEY not in row
        answer = sandbox_dropped_files(sandbox_document(report))
        assert [r["sha256"] for r in answer["dropped"]] == ["c" * 64]

    def test_with_the_real_run_s_record_the_host_s_files_are_still_its(self) -> None:
        # The record of a real run names sample.exe, which no process runs
        # here: the host alone is the launcher's, and its rows with it.
        record = {**FIRST, "sample_member": "sample.exe"}
        report = _first({"procid": 86, "path": f"{TEMP}\\argtest.txt"})
        attribute_the_launcher(report, record)
        reasons = _reasons(report)
        assert reasons.pop(f"{TEMP}\\argtest.txt") is None
        assert set(reasons.values()) == {DROPPED_BY_LAUNCHER}

    def test_a_row_written_by_the_launcher_and_the_program_is_not_the_launcher_s(self) -> None:
        report = _first({"pids": [84, 86], "path": f"{TEMP}\\shared.txt"})
        # ``pids`` is read where the row names no ``procid``.
        attribute_the_launcher(report, FIRST)
        assert _reasons(report)[f"{TEMP}\\shared.txt"] is None

    def test_a_row_naming_no_writer_keeps_the_member_reading(self) -> None:
        report = _first({"path": f"{TEMP}\\notes.txt", "sha256": "d" * 64})
        attribute_the_launcher(report, FIRST)
        assert _reasons(report)[f"{TEMP}\\notes.txt"] is None

    def test_without_a_launcher_record_nothing_changes(self) -> None:
        report = _first()
        before = report.model_dump()
        attribute_the_launcher(report, None)
        assert report.model_dump() == before
        assert sandbox_dropped_files(sandbox_document(report))["total"] == 7

    def test_attributed_twice_the_rows_are_the_same(self) -> None:
        report = _first({"path": f"{TEMP}\\copy.txt", "sha256": MARKER})
        attribute_the_launcher(report, SECOND)
        once = copy.deepcopy(report.dropped_files)
        attribute_the_launcher(report, SECOND)
        assert report.dropped_files == once


class TestAMemberIsThePlatformSOnlyAtItsPlace:
    def test_the_member_at_its_place_is_the_platform_s(self) -> None:
        report = _second(
            {"path": f"{TEMP}\\marker.txt", "sha256": MARKER},
            # Read without case: the guest is Windows.
            {"path": f"{TEMP.upper()}\\MARKER.TXT", "sha256": MARKER.upper()},
            # A row that states no digest, at the place.
            {"path": f"{TEMP}\\marker.txt"},
        )
        attribute_the_launcher(report, SECOND)
        rows = report.dropped_files[-3:]
        assert [row.get(LINEAGE_REASON_KEY) for row in rows] == [DROPPED_SAMPLE] * 3
        assert report.extras[UNPLACED_MEMBER_FILES_KEY] == 0

    def test_the_same_digest_under_another_name_is_the_sample_s_copy(self) -> None:
        report = _second({"path": f"{TEMP}\\copy.txt", "sha256": MARKER})
        attribute_the_launcher(report, SECOND)
        row = report.dropped_files[-1]
        assert LINEAGE_KEY not in row
        assert row[MEMBER_FACT_KEY] == {
            "fact": MEMBER_COPIED,
            "member": "marker.txt",
            "member_at": [f"{PLACE}/marker.txt"],
            "at": [f"{TEMP}\\copy.txt"],
        }
        answer = sandbox_dropped_files(sandbox_document(report))
        (listed,) = [r for r in answer["dropped"] if r.get(MEMBER_FACT_KEY)]
        assert listed[MEMBER_FACT_KEY]["fact"] == MEMBER_COPIED

    def test_the_same_name_with_another_digest_is_the_sample_s(self) -> None:
        report = _second({"path": f"{TEMP}\\marker.txt", "sha256": "e" * 64})
        attribute_the_launcher(report, SECOND)
        row = report.dropped_files[-1]
        assert LINEAGE_KEY not in row
        assert row[MEMBER_FACT_KEY]["fact"] == MEMBER_CHANGED
        assert row[MEMBER_FACT_KEY]["member_at"] == [f"{PLACE}/marker.txt"]

    def test_a_member_in_a_subfolder_at_its_place_is_the_platform_s(self) -> None:
        record = {**SECOND, "sample_member": "sub/marker2.txt", "sample_sha256": MARKER2}
        report = _second(
            {"path": f"{TEMP}\\sub\\marker2.txt", "sha256": MARKER2},
            # The same file away from its folder is a copy.
            {"path": f"{TEMP}\\marker2.txt", "sha256": MARKER2},
        )
        attribute_the_launcher(report, record)
        placed, moved = report.dropped_files[-2:]
        assert placed[LINEAGE_REASON_KEY] == DROPPED_SAMPLE
        assert moved[MEMBER_FACT_KEY]["fact"] == MEMBER_COPIED
        assert moved[MEMBER_FACT_KEY]["member"] == "sub/marker2.txt"
        assert moved[MEMBER_FACT_KEY]["member_at"] == [f"{PLACE}/sub/marker2.txt"]

    def test_a_row_stating_no_path_keeps_the_reading_by_digest_and_is_counted(self) -> None:
        report = _second({"sha256": MARKER})
        attribute_the_launcher(report, SECOND)
        assert report.dropped_files[-1][LINEAGE_REASON_KEY] == DROPPED_SAMPLE
        assert report.extras[UNPLACED_MEMBER_FILES_KEY] == 1

    def test_the_launcher_s_own_files_are_its_in_the_second_run_too(self) -> None:
        report = _second()
        attribute_the_launcher(report, SECOND)
        assert set(_reasons(report).values()) == {DROPPED_BY_LAUNCHER}

    def test_a_sandbox_s_field_under_the_member_fact_s_name_is_taken_out(self) -> None:
        report = _second({"path": f"{TEMP}\\x.txt", MEMBER_FACT_KEY: {"fact": "forged"}})
        assert unearned_marks_removed(report) == [MEMBER_FACT_KEY]
        assert all(MEMBER_FACT_KEY not in row for row in report.dropped_files)


class TestARowIsReadInItsOwnTask:
    def test_one_id_is_the_launcher_in_one_task_and_the_program_in_the_other(self) -> None:
        one, two = _json("behavioral1.json"), _json("behavioral2.json")
        # The second task numbers its processes the other way round: 86 is its
        # script host and 84 the program it started.
        swap = {87: 86, 89: 84}
        for proc in two["processes"]:
            proc["procid"] = swap[proc["procid"]]
            if proc["procid_parent"] in swap:
                proc["procid_parent"] = swap[proc["procid_parent"]]
        two["dumped"] = [{"procid": 84, "path": f"{TEMP}\\argtest.txt", "sha256": "c" * 64}]
        one["dumped"] = [{"procid": 84, "path": f"{TEMP}\\policy.ps1", "sha256": "d" * 64}]
        report = _read("overview.json", {"behavioral1": one, "behavioral2": two})
        assert [row[PROCESS_TASK_KEY] for row in report.dropped_files] == [
            "behavioral1",
            "behavioral2",
        ]
        attribute_the_launcher(report, FIRST)
        assert _reasons(report) == {
            f"{TEMP}\\policy.ps1": DROPPED_BY_LAUNCHER,
            f"{TEMP}\\argtest.txt": None,
        }

    def test_a_row_naming_no_task_is_not_the_launcher_s_by_its_writer_and_is_counted(
        self,
    ) -> None:
        report = _first()
        report.dropped_files.append({"procid": 84, "path": f"{TEMP}\\untasked.txt"})
        attribute_the_launcher(report, FIRST)
        assert _reasons(report)[f"{TEMP}\\untasked.txt"] is None
        assert report.extras[UNSETTLED_LAUNCHER_FILES_KEY] == 1
        assert report.extras[LAUNCHER_FILES_KEY] == 7


class TestWhatTheSampleCouldHaveCausedStaysInView:
    def test_every_row_is_in_the_sample_s_list_or_the_launcher_s(self) -> None:
        report = _first({"procid": 86, "path": f"{TEMP}\\argtest.txt"})
        attribute_the_launcher(report, FIRST)
        sample, launcher = _listed(report)
        assert len(sample) + len(launcher) == len(report.dropped_files) == 8
        assert len(sample) == 1 and len(launcher) == 7

    def test_the_launch_statement_names_the_launcher_s_files(self) -> None:
        report = _first()
        attribute_the_launcher(report, FIRST)
        document = sandbox_document(report)
        document[LAUNCH_KEY] = _launch_mark(FIRST)
        assert document[LAUNCHER_FILES_KEY] == 7
        said = sandbox_status(document).statement
        assert (
            "7 files the sandbox lists as written or dumped by the launcher's own process are "
            "listed with the launcher's facts, each with its path, digest and writer, and not "
            "among the sample's files." in said
        )

    def test_a_launcher_process_the_program_wrote_into_keeps_its_files_with_the_sample(
        self,
    ) -> None:
        # The started program (86) writes into the script host (84) in the
        # first task: what the host wrote there may be the program's doing.
        injected = {
            "name": "Suspicious use of WriteProcessMemory",
            "indicators": [{"pid": 3444, "procid": 86, "procid_target": 84}],
        }
        report = _first(signatures=[injected])
        attribute_the_launcher(report, FIRST)
        first = [r for r in report.dropped_files if r[PROCESS_TASK_KEY] == "behavioral1"]
        second = [r for r in report.dropped_files if r[PROCESS_TASK_KEY] == "behavioral2"]
        assert {r[LINEAGE_KEY] for r in first} == {LINEAGE_LAUNCHER_UNSETTLED}
        assert {r[LINEAGE_REASON_KEY] for r in first} == {DROPPED_BY_LAUNCHER_REACHED}
        assert {r[LINEAGE_REASON_KEY] for r in second} == {DROPPED_BY_LAUNCHER}
        sample, launcher = _listed(report)
        assert len(sample) == 4 and len(launcher) == 3
        assert {r[LINEAGE_REASON_KEY] for r in sample} == {DROPPED_BY_LAUNCHER_REACHED}
        assert report.extras[UNSETTLED_LAUNCHER_FILES_KEY] == 4
        document = sandbox_document(report)
        document[LAUNCH_KEY] = _launch_mark(FIRST)
        assert "4 files a launcher process wrote or dumped stay among the sample's files" in (
            sandbox_status(document).statement
        )

    def test_an_indicator_naming_the_host_as_target_and_no_source_reaches_it(self) -> None:
        unsourced = {"name": "Opens a process", "indicators": [{"procid_target": 84}]}
        report = _first(signatures=[unsourced])
        attribute_the_launcher(report, FIRST)
        first = [r for r in report.dropped_files if r[PROCESS_TASK_KEY] == "behavioral1"]
        assert {r[LINEAGE_KEY] for r in first} == {LINEAGE_LAUNCHER_UNSETTLED}

    def test_the_host_acting_on_its_own_child_does_not_reach_it(self) -> None:
        # The live report's own WriteProcessMemory: the host (84) writes into
        # the program it starts (86), which is how it starts it.
        report = _first()
        attribute_the_launcher(report, FIRST)
        assert report.extras[UNSETTLED_LAUNCHER_FILES_KEY] == 0


class TestTheGuestPathIsShownWhereTheReaderDeclaresIt:
    def test_a_triage_row_shows_its_guest_path(self) -> None:
        report = _first({"procid": 86, "path": f"{TEMP}\\argtest.txt", "name": "files/0x1.dat"})
        document = sandbox_document(report)
        answer = sandbox_dropped_files(document, normalised_by=("triage", "triage", "tasks"))
        paths = {row["name"]: row["path"] for row in answer["dropped"]}
        assert paths["files/0x1.dat"] == f"{TEMP}\\argtest.txt"
        attribute_the_launcher(report, FIRST)
        answer = sandbox_dropped_files(
            sandbox_document(report), normalised_by=("triage", "triage", "tasks")
        )
        assert f"{TEMP}\\__PSScriptPolicyTest_j03iwqiu.gcj.ps1" in {
            row["path"] for row in answer["platform_files"]
        }

    def test_a_cape_row_s_path_stays_hidden(self) -> None:
        fixture = LIVE.parent / "cape2_synthetic.json"
        raw = json.loads(fixture.read_text(encoding="utf-8"))
        report = required_reader("cape2").read(raw, provider="cape2", task_id="1")
        answer = sandbox_dropped_files(sandbox_document(report), normalised_by=("cape2", "cape2"))
        (row,) = answer["dropped"]
        # CAPE's ``path`` is where the sandbox's own host stored the file.
        assert row["name"] == "second.exe" and row["path"] == ""
