"""The dropped-files view keeps each row's guest path, origin, kind and writer.

A sandbox states, for each file a run wrote or region it dumped, where in the
guest it lies, what kind of row it is and where it came from (a ransom note, a
download, a region the process protected), and which process wrote it. The
view keeps all of it: the guest path where the job's reader declares the field
that holds one (``Reading.guest_path_fields``), the row's ``kind`` and
``origin`` where it states them, and the writer by the process list's own id
first (``schemas.sandbox_report._WRITER_KEYS``), with the task the reader
listed it in and the guest's pid beside it where the reader declares the field
that holds one (``Reading.dropped_guest_pid_fields``). The pack reads the view
with the job's reader, as an agent's call does, so its entry states the same.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission; the rows added here are synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_dropped_files
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import SandboxReport

LIVE = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox" / "triage_live"
TASKS = ("triage", "triage", "tasks")
NOTE = "C:\\Users\\Admin\\Downloads\\ReadMeForDecrypt.txt"
DIGEST = "5cd55b0775d76e715b840827d0f3201470df24f2230dce71c7313de7f41761a7"
WRITTEN = {
    "at": 900,
    "pid": 3444,
    "procid": 86,
    "path": NOTE,
    "name": "files/0x0007-934.dat",
    "kind": "martian",
    "origin": "ransom",
    "sha256": DIGEST,
    "size": 4354,
}


def _json(name: str) -> Any:
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


def _report(*rows: dict[str, Any]) -> SandboxReport:
    one, two = _json("behavioral1.json"), _json("behavioral2.json")
    one["dumped"] += list(rows)
    return required_reader("triage").read(
        _json("overview.json"),
        provider="triage",
        task_id="s1",
        task_reports={"behavioral1": one, "behavioral2": two},
    )


def _rows(normalised_by: Any = TASKS, *rows: dict[str, Any]) -> dict[str, dict[str, Any]]:
    answer = sandbox_dropped_files(
        sandbox_document(_report(*(rows or (WRITTEN,)))), normalised_by=normalised_by
    )
    return {row["name"]: row for row in answer["dropped"]}


class TestEachRowKeepsWhatTheSandboxStated:
    def test_a_written_file_keeps_its_guest_path_kind_and_origin(self) -> None:
        row = _rows()[WRITTEN["name"]]

        assert row["path"] == NOTE
        assert row["kind"] == "martian"
        assert row["origin"] == "ransom"
        assert row["sha256"] == DIGEST

    def test_a_dumped_region_keeps_its_kind_and_origin(self) -> None:
        region = next(row for name, row in _rows().items() if name.startswith("memory/"))

        assert region["kind"] == "region"
        assert region["origin"]

    def test_a_row_stating_neither_states_none(self) -> None:
        bare = {"procid": 86, "name": "files/0x9.dat", "path": "C:\\x.dat"}
        row = _rows(TASKS, bare)["files/0x9.dat"]

        assert "kind" not in row and "origin" not in row


class TestTheWriterIsTheProcessListsOwnId:
    def test_the_writer_is_its_id_in_its_task_with_the_guest_pid_beside_it(self) -> None:
        row = _rows()[WRITTEN["name"]]

        assert row["pids"] == ["86"]
        assert row["task"] == "behavioral1"
        assert row["guest_pid"] == "3444"

    def test_a_row_naming_its_writer_by_one_number_states_no_alias(self) -> None:
        only = {"pid": 3444, "name": "files/0x8.dat", "path": "C:\\y.dat"}
        row = _rows(TASKS, only)["files/0x8.dat"]

        assert row["pids"] == ["3444"]
        assert "guest_pid" not in row

    def test_without_the_job_s_reader_no_field_is_read_as_a_guest_s(self) -> None:
        row = _rows(None)[WRITTEN["name"]]

        assert row["path"] == ""
        assert "guest_pid" not in row
        assert row["pids"] == ["86"]


class TestThePackReadsTheViewWithTheJobsReader:
    def test_the_pack_s_entry_states_the_path_and_the_writer(self, tmp_path: Path) -> None:
        from malspark.agents.evidence_recorder import EvidenceRecorder
        from malspark.pipeline.triage_pack import PIPELINE, run_pack
        from malspark.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_triage_pack import _inputs, _write
        from tests.unit.tools.test_binary import _pe

        document = sandbox_document(_report(WRITTEN))
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        path = _write(tmp_path, "s.exe", _pe())
        result = run_pack(
            recorder,
            _inputs(path, "pe", sandbox_report=document, sandbox_normalised_by=TASKS),
        )
        entry = {e.tool: e for e in result.entries}["sandbox_dropped_files"]
        row = next(r for r in entry.structured["dropped"] if r["name"] == WRITTEN["name"])

        assert row["path"] == NOTE
        assert row["origin"] == "ransom"
        assert (row["pids"], row["task"]) == (["86"], "behavioral1")
