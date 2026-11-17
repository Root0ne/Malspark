"""The place a sandbox started the submitted file from, read from the report's own processes.

Each report is read by the real reader of its family, with that family's own
field names, and the fact is read from the document's processes through the
reader's declaration and the one process identity, never from the view's
printed rows. Where the listing states no ids, nothing is marked. A path the
record shows written (its collected files or its file-write operations) is
never marked; where the reader records no file writes at all, nothing is.
At most one row of a task is marked: the earliest started of those that
qualify, only where their starts can be compared. Where the sandbox marks the
sample's processes on any row, a row without that mark is never marked.
Synthetic reports only; nothing is run.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import read_view
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import STAGED_KEY, STAGED_NOTE_KEY

DIGEST = "e" * 64
NAME = "invoice.exe"
TEMP = "C:\\Users\\u\\AppData\\Local\\Temp\\"
STAGED = f"{TEMP}{DIGEST}.exe"
RANDOM = f"{TEMP}a8f3k2.exe"
COPY = f"C:\\Users\\u\\AppData\\Roaming\\svc\\{NAME}"
SVCHOST = "C:\\Windows\\System32\\svchost.exe"
CAPE_FAMILY = ("cape2", "cuckoo", "mock")

# A process: (id, parent id, image, start); ``None`` for an id leaves it out.
Proc = tuple[Any, Any, str, str]


def _cape(
    reader: str,
    procs: list[Proc],
    *,
    dropped: tuple[str, ...] = (),
    writes: tuple[str, ...] | None = (),
    collected: bool = True,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    rows = []
    for pid, ppid, image, start in procs:
        row: dict[str, Any] = {
            "parent_id": ppid,
            "process_name": image.rsplit("\\", 1)[-1],
            "module_path": image,
            "first_seen": start,
            "calls": [],
        }
        if pid is not None:
            row["process_id"] = pid
        rows.append(row)
    behavior: dict[str, Any] = {"processes": rows}
    if writes is not None:
        behavior["summary"] = {"write_files": list(writes)}
    raw: dict[str, Any] = {
        "target": {"category": "file", "file": {"name": NAME, "sha256": DIGEST}},
        "behavior": behavior,
    }
    if collected:
        raw["dropped"] = [
            {"name": path.rsplit("\\", 1)[-1], "filepath": path, "sha256": "f" * 64}
            for path in dropped
        ]
    report = required_reader(reader).read(raw, provider="lab")
    return sandbox_document(report), ("lab", reader)


def _triage(
    tasks: dict[str, list[Proc]],
    *,
    dumped: tuple[str, ...] = (),
    sample_marked: tuple[tuple[str, int], ...] = (),
) -> tuple[dict[str, Any], tuple[str, ...]]:
    reports: dict[str, dict[str, Any]] = {}
    for task, procs in tasks.items():
        rows = []
        for pid, ppid, image, start in procs:
            row: dict[str, Any] = {"procid": pid, "procid_parent": ppid, "image": image}
            row["cmd"] = f'"{image}"'
            if start:
                row["started"] = start
            if (task, pid) in sample_marked:
                row["orig"] = True
            rows.append(row)
        reports[task] = {"processes": rows}
    first = next(iter(reports.values()))
    first["dumped"] = [{"name": p.rsplit("\\", 1)[-1], "path": p} for p in dumped]
    overview = {"sample": {"id": "s1", "target": NAME, "sha256": DIGEST}}
    report = required_reader("triage").read(
        overview, provider="lab", task_id="s1", task_reports=reports
    )
    return sandbox_document(report), ("lab", "triage", "tasks")


def _generic(procs: list[Proc], dropped: tuple[str, ...] = ()) -> tuple[dict[str, Any], Any]:
    from malspark.core.config import RestMappingConfig

    mapping = RestMappingConfig(
        target_sha256="$.sample.sha256",
        processes="$.run.procs[*]",
        dropped_files="$.files[*]",
        field_names={
            "processes.pid": "id",
            "processes.ppid": "parent",
            "processes.name": "image",
            "dropped_files.name": "path",
        },
    )
    payload = {
        "sample": {"sha256": DIGEST},
        "run": {"procs": [{"id": p, "parent": pp, "image": i} for p, pp, i, _s in procs]},
        "files": [{"path": path} for path in dropped],
    }
    report = required_reader("generic").read(payload, provider="lab", mapping=mapping)
    return sandbox_document(report), ("lab", "generic")


def _marked(built: tuple[dict[str, Any], Any]) -> list[int]:
    """The indices of the marked rows, which hold whatever id the view prints."""
    document, reader = built
    answer = read_view("sandbox_processes", document, reader)
    marked = [i for i, row in enumerate(answer["processes"]) if row.get(STAGED_KEY)]
    assert (STAGED_NOTE_KEY in answer) == bool(marked)
    return marked


@pytest.mark.parametrize("reader", CAPE_FAMILY)
class TestTheCapeFamilyIsReadByItsOwnIds:
    def test_only_the_root_of_a_chain_that_runs_the_file_is_marked(self, reader: str) -> None:
        procs = [(1, 99, STAGED, "1"), (2, 1, STAGED, "2"), (3, 2, COPY, "3")]
        assert _marked(_cape(reader, procs)) == [0]

    def test_a_listing_that_states_no_id_marks_nothing(self, reader: str) -> None:
        procs = [(1, 99, STAGED, "1"), (None, 1, COPY, "2")]
        assert _marked(_cape(reader, procs)) == []

    def test_a_copy_shown_only_among_the_file_writes_is_not_marked(self, reader: str) -> None:
        procs = [(1, 99, RANDOM, "1"), (3, 77, SVCHOST, "2"), (4, 3, COPY, "3")]
        assert _marked(_cape(reader, procs, writes=(COPY,))) == []
        # The same copy, not shown written: the record does not contradict it.
        assert _marked(_cape(reader, procs)) == [2]

    def test_a_report_that_records_no_file_writes_marks_nothing(self, reader: str) -> None:
        procs = [(1, 99, STAGED, "1")]
        assert _marked(_cape(reader, procs, writes=None, collected=False)) == []
        assert _marked(_cape(reader, procs, writes=None)) == [0]


class TestATriageTaskMarksAtMostOneRow:
    def test_the_same_path_run_twice_marks_the_earliest(self) -> None:
        procs = [(1, 56, STAGED, "200"), (3, 6, SVCHOST, "150"), (4, 3, STAGED, "100")]
        assert _marked(_triage({"behavioral1": procs})) == [2]

    def test_two_forms_of_time_state_no_order(self) -> None:
        procs = [
            (1, 56, STAGED, "2026-08-13T09:00:00.000"),
            (3, 6, SVCHOST, ""),
            (4, 3, STAGED, "2026-08-13 23:00:00,000"),
        ]
        assert _marked(_triage({"behavioral1": procs})) == []

    def test_a_start_left_unstated_states_no_order(self) -> None:
        procs = [(1, 56, STAGED, "100"), (3, 6, SVCHOST, ""), (4, 3, STAGED, "")]
        assert _marked(_triage({"behavioral1": procs})) == []

    def test_each_task_marks_its_own(self) -> None:
        tasks = {"behavioral1": [(1, 56, STAGED, "125")], "behavioral2": [(1, 81, STAGED, "719")]}
        assert _marked(_triage(tasks)) == [0, 1]

    def test_a_copy_the_record_shows_written_is_not_marked(self) -> None:
        procs = [(1, 56, RANDOM, "100"), (3, 6, SVCHOST, "150"), (4, 3, COPY, "200")]
        assert _marked(_triage({"behavioral1": procs}, dumped=(COPY,))) == []
        assert _marked(_triage({"behavioral1": procs})) == [2]


class TestTheSandbox_sOwnMarkBoundsIt:
    def test_a_row_without_the_mark_is_never_marked_where_another_has_it(self) -> None:
        procs = [(1, 56, STAGED, "100"), (2, 1, "C:\\Windows\\System32\\cmd.exe", "120")]
        tasks = {"behavioral1": procs, "behavioral2": [(1, 81, STAGED, "700")]}
        built = _triage(tasks, sample_marked=(("behavioral1", 2),))
        # Task one carries the mark on its child, so its root is not marked;
        # task two carries none, so its root is.
        assert _marked(built) == [2]

    def test_a_row_with_the_mark_is_marked(self) -> None:
        procs = [(1, 56, STAGED, "100"), (2, 1, "C:\\Windows\\System32\\cmd.exe", "120")]
        built = _triage({"behavioral1": procs}, sample_marked=(("behavioral1", 1),))
        assert _marked(built) == [0]


class TestAMappedReport:
    def test_the_root_is_marked_and_a_written_copy_is_not(self) -> None:
        procs = [(1, 99, STAGED, ""), (3, 77, SVCHOST, ""), (4, 3, COPY, "")]
        assert _marked(_generic(procs, dropped=(COPY,))) == [0]


class TestAParentTheListingNamesTwice:
    def test_a_parent_number_two_processes_carry_marks_nothing(self) -> None:
        # Two processes of the task carry the number the qualifying process
        # names as its parent: which started it cannot be told.
        procs = [(1, 99, STAGED, ""), (99, 4, SVCHOST, ""), (99, 5, SVCHOST, "")]
        assert _marked(_generic(procs)) == []
        assert _marked(_generic(procs[:2])) == [0]


class TestTheWrittenPathsAreReadWhereTheReaderDeclares:
    def _document(self) -> dict[str, Any]:
        return {
            "behavior": {"summary": {"write_files": [COPY]}},
            "dropped": [{"guestfile": STAGED}],
        }

    def test_only_the_parts_the_reader_fills_are_read(self) -> None:
        from malspark.schemas.sandbox_report import Reading, written_during_the_run

        assert written_during_the_run(self._document(), Reading(frozenset({"processes"}))) is None
        held = written_during_the_run(self._document(), Reading(frozenset({"summary.write_files"})))
        assert held == [COPY]

    def test_a_declared_guest_path_field_is_read(self) -> None:
        from malspark.schemas.sandbox_report import Reading, written_during_the_run

        reading = Reading(frozenset({"dropped_files"}), guest_path_fields=("guestfile",))
        assert written_during_the_run(self._document(), reading) == [STAGED]
        assert written_during_the_run(self._document(), Reading(frozenset({"dropped_files"}))) == []

    def test_an_undeclared_document_is_read_through_every_part(self) -> None:
        from malspark.schemas.sandbox_report import written_during_the_run

        assert written_during_the_run(self._document(), None) == [COPY]
