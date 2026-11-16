"""The dropped-files view keeps each row's guest path, origin, kind and writer.

A sandbox states, for each file a run wrote or region it dumped, where in the
guest it lies, what kind of row it is and where it came from (a ransom note, a
download, a region the process protected), and which process wrote it. The
view keeps all of it: the guest path where the job's reader declares the field
that holds one (``Reading.guest_path_fields``), the row's ``kind`` and
``origin`` where it states them, and the writer by the process list's own id,
read from every field the reader declares holds it
(``Reading.dropped_writer_fields``, else the generic fields), with the task
the reader listed it in and the guest's pid beside it where the reader
declares the field that holds one (``Reading.dropped_guest_pid_fields``). The
pack reads the view with the job's reader, as an agent's call does, so its
entry states the same. A long answer is sized as every sibling view's is: the
rows it does not show are counted and a page names where the rest are.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission; the rows added here are synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

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

    def test_a_guest_pid_equal_to_the_id_states_no_alias(self) -> None:
        same = {"procid": 86, "pid": 86, "name": "files/0x7.dat", "path": "C:\\z.dat"}
        row = _rows(TASKS, same)["files/0x7.dat"]

        assert row["pids"] == ["86"]
        assert "guest_pid" not in row

    def test_a_row_naming_its_writer_by_one_number_states_no_alias(self) -> None:
        only = {"pid": 3444, "name": "files/0x8.dat", "path": "C:\\y.dat"}
        row = _rows(TASKS, only)["files/0x8.dat"]

        assert row["pids"] == ["3444"]
        assert "guest_pid" not in row

    def test_without_the_job_s_reader_the_generic_fields_are_read(self) -> None:
        row = _rows(None)[WRITTEN["name"]]

        assert row["path"] == ""
        assert "guest_pid" not in row
        assert row["pids"] == ["3444"]


class TestTheWriterFieldsAreTheReadersDeclaration:
    @pytest.fixture
    def declaring(self) -> Any:
        from dataclasses import replace

        from malspark.providers.sandbox.readers import (
            CapeReportReader,
            register_report_reader,
            unregister_report_reader,
        )

        class _Declaring(CapeReportReader):
            id = "writer-box"

            def reading(self, read_from: str = "", provider: str = "") -> Any:
                held = super().reading(read_from, provider)
                return replace(
                    held, dropped_writer_fields=("writer_ref",), dropped_guest_pid_fields=("guest",)
                )

        register_report_reader(_Declaring)
        yield ("writer-box", "writer-box")
        unregister_report_reader(_Declaring.id)

    def test_a_declared_field_names_the_writer_and_no_generic_one_does(
        self, declaring: Any
    ) -> None:
        row = {"name": "a.dat", "writer_ref": 12, "pid": 99, "guest": 1500}
        (answer,) = sandbox_dropped_files({"dropped_files": [row]}, normalised_by=declaring)[
            "dropped"
        ]

        assert answer["pids"] == ["12"]
        assert answer["guest_pid"] == "1500"

    def test_a_row_holding_two_numbers_keeps_both(self) -> None:
        row = {"name": "a.dat", "pid": 5, "process_id": 6}
        (answer,) = sandbox_dropped_files({"dropped_files": [row]})["dropped"]

        assert answer["pids"] == ["5", "6"]

    def test_a_field_joining_several_writers_with_commas_keeps_each(self) -> None:
        row = {"name": "a.dat", "pids": "1536,908"}
        (answer,) = sandbox_dropped_files({"dropped_files": [row]})["dropped"]

        assert answer["pids"] == ["1536", "908"]

    def test_a_reading_of_the_overview_reads_the_reader_s_declared_fields(self) -> None:
        from malspark.schemas.sandbox_report import READ_FROM_OVERVIEW

        reader = required_reader("triage")
        reading = reader.reading(READ_FROM_OVERVIEW)

        assert reading.dropped_writer_fields == reader.DROPPED_WRITER_FIELDS
        assert reading.dropped_guest_pid_fields == reader.DROPPED_GUEST_PID_FIELDS
        assert reading.dropped_writer_fields


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


class TestALongAnswerIsSizedAsEverySiblingViewIs:
    """Six hundred written files: the answer stays in the job's room, the rest a page away."""

    ROOM = 20_000

    @staticmethod
    def _many(count: int) -> list[dict[str, Any]]:
        return [
            {
                **WRITTEN,
                "name": f"files/0x{i:04x}.dat",
                "path": f"C:\\Users\\Admin\\AppData\\Local\\Temp\\f{i:04d}.dat",
                "sha256": f"{i:064x}",
            }
            for i in range(count)
        ]

    def _tool(self) -> Any:
        from malspark.agents.mcp_client import MCPLangChainToolkit
        from malspark.core.truncation_ledger import TruncationLedger
        from malspark.providers import sandbox_tools

        room = self.ROOM

        class _Registry:
            def answer_sizer(self) -> MCPLangChainToolkit:
                return MCPLangChainToolkit(
                    None, max_output_chars=room, truncation_ledger=TruncationLedger()
                )

        class _Container:
            sandbox_report = sandbox_document(_report(*self._many(600)))
            sandbox_normalised = TASKS

            def get_server_registry(self) -> _Registry:
                return _Registry()

        return next(
            t
            for t in sandbox_tools.sandbox_tools(_Container())
            if t.name == "sandbox_dropped_files"
        )

    def test_the_answer_counts_what_it_does_not_show_and_names_the_page(self) -> None:
        from malspark.agents.evidence_recorder import shortened_notice
        from malspark.agents.output_shortening import BOOKKEEPING_KEY

        answer = self._tool().invoke({})

        assert len(answer) <= self.ROOM
        parsed = json.loads(answer)
        assert BOOKKEEPING_KEY in parsed
        assert parsed["total"] >= 600
        notice = shortened_notice(answer, narrowing=("offset", "limit"))
        assert "`offset`" in notice and "`limit`" in notice

    def test_the_rows_not_shown_are_one_page_away(self) -> None:
        tool = self._tool()
        shown = len(json.loads(tool.invoke({}))["dropped"])

        page = json.loads(tool.invoke({"offset": shown, "limit": 20}))

        assert len(page["dropped"]) == 20
        assert page["next_offset"] == shown + 20
