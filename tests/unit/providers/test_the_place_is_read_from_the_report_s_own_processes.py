"""The place a sandbox started the submitted file from, read from the report's own processes.

Each report is read by the real reader of its family, with that family's own
field names, and the fact is read from the document's processes through the
document's one reading of a process row (its id, its parent, its name and its
image path) and the one process identity, never from the view's printed rows.
Where the listing states no ids, nothing is marked. The image path a row
states is what is asked and compared, its bare name only where it states no
path. A path the record shows written (its collected files, its file-write
operations or its modified files) is never marked; where the reader records
no file writes at all, nothing is. At most one row of a task is marked: the
earliest started of those that qualify, only where their starts can be
compared. The sandbox's own mark of the sample's processes is not read.
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
    modified: tuple[str, ...] = (),
    operations: tuple[str, ...] = (),
    collected: bool = True,
    name: str = NAME,
    paths: bool = True,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    rows = []
    for pid, ppid, image, start in procs:
        row: dict[str, Any] = {
            "parent_id": ppid,
            "process_name": image.rsplit("\\", 1)[-1],
            "first_seen": start,
            "calls": [],
        }
        if paths:
            row["module_path"] = image
        if pid is not None:
            row["process_id"] = pid
        rows.append(row)
    behavior: dict[str, Any] = {"processes": rows}
    if writes is not None:
        behavior["summary"] = {"write_files": list(writes), "modified_files": list(modified)}
    raw: dict[str, Any] = {
        "target": {"category": "file", "file": {"name": name, "sha256": DIGEST}},
        "behavior": behavior,
    }
    if operations:
        raw["file_writes"] = list(operations)
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
    name: str = NAME,
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
    overview = {"sample": {"id": "s1", "target": name, "sha256": DIGEST}}
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


def _marked(built: tuple[dict[str, Any], Any], *, read_by: Any = ...) -> list[int]:
    """The indices of the marked rows, which hold whatever id the view prints.

    Read with the report's own reader, or with ``read_by`` where it is given.
    """
    document, reader = built
    reader = reader if read_by is ... else read_by
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

    def test_a_copy_shown_only_among_the_file_write_operations_is_not_marked(
        self, reader: str
    ) -> None:
        procs = [(1, 99, RANDOM, "1"), (3, 77, SVCHOST, "2"), (4, 3, COPY, "3")]
        assert _marked(_cape(reader, procs, operations=(COPY,))) == []
        assert _marked(_cape(reader, procs, operations=(SVCHOST,))) == [2]

    def test_a_copy_shown_only_among_the_modified_files_is_not_marked(self, reader: str) -> None:
        procs = [(1, 99, RANDOM, "1"), (3, 77, SVCHOST, "2"), (4, 3, COPY, "3")]
        assert _marked(_cape(reader, procs, modified=(COPY,))) == []
        assert _marked(_cape(reader, procs, modified=(SVCHOST,))) == [2]

    def test_a_row_is_read_one_way_whatever_reader_is_named(self, reader: str) -> None:
        # The id, the parent and the image of a process row are the document's
        # one reading of a row: a read that names no reader reads them alike.
        # The record shows a write of another path, so it records file writes.
        procs = [(1, 99, STAGED, "1"), (2, 1, STAGED, "2"), (3, 2, COPY, "3")]
        assert _marked(_cape(reader, procs, writes=(SVCHOST,)), read_by=None) == [0]

    def test_the_image_path_is_compared_with_a_written_path(self, reader: str) -> None:
        # A file of the submitted name written in another folder is not the
        # process's image: the row states its path, and the path is compared.
        procs = [(1, 99, f"{TEMP}{NAME}", "1")]
        assert _marked(_cape(reader, procs, dropped=(COPY,))) == [0]
        assert _marked(_cape(reader, procs, dropped=(f"{TEMP}{NAME}",))) == []

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


class TestTheSandbox_sOwnMarkIsNotRead:
    """The stored series runs' shape: the sandbox marks the sample's children or the
    desktop's processes, never the process it started; that process is the place."""

    def test_the_root_is_marked_where_the_sandbox_marks_its_child_or_the_desktop(self) -> None:
        defrag = "C:\\Windows\\system32\\defrag.exe"
        tasks = {
            "behavioral1": [(85, 56, STAGED, "141"), (87, 85, defrag, "563")],
            "behavioral2": [
                (88, 81, STAGED, "719"),
                (94, 29, "C:\\Windows\\system32\\sihost.exe", "418328"),
                (96, 94, "C:\\Windows\\explorer.exe", "419687"),
            ],
        }
        marks = (("behavioral1", 87), ("behavioral2", 94), ("behavioral2", 96))
        assert _marked(_triage(tasks, sample_marked=marks)) == [0, 2]

    def test_a_row_the_sandbox_marks_is_read_as_any_other(self) -> None:
        procs = [(1, 56, STAGED, "100"), (2, 1, "C:\\Windows\\System32\\cmd.exe", "120")]
        built = _triage({"behavioral1": procs}, sample_marked=(("behavioral1", 1),))
        assert _marked(built) == [0]


SYSTEM_SVCHOST = "C:\\Windows\\System32\\svchost.exe"
STAGED_SVCHOST = f"{TEMP}svchost.exe"


class TestAPathTheSystemShipsIsNoCandidate:
    """A file submitted under the name of a program the system has."""

    def test_triage_marks_the_submitted_file_s_path_never_the_system_s(self) -> None:
        procs = [(5, 77, SYSTEM_SVCHOST, "50"), (1, 56, STAGED_SVCHOST, "100")]
        assert _marked(_triage({"behavioral1": procs}, name="svchost.exe")) == [1]

    @pytest.mark.parametrize("reader", CAPE_FAMILY)
    def test_this_family_s_image_path_is_asked_never_its_bare_name(self, reader: str) -> None:
        # This family names a process by its bare name and states its image's
        # path beside it: the path is asked, so the row the other shapes mark
        # is marked.
        procs = [(5, 77, SYSTEM_SVCHOST, "1"), (1, 56, STAGED_SVCHOST, "2")]
        assert _marked(_cape(reader, procs, name="svchost.exe")) == [1]

    @pytest.mark.parametrize("reader", CAPE_FAMILY)
    def test_a_bare_name_the_system_ships_cannot_be_told(self, reader: str) -> None:
        # A row that states no path: the system's svchost and the submitted one
        # read alike, so neither is marked.
        procs = [(5, 77, SYSTEM_SVCHOST, "1"), (1, 56, STAGED_SVCHOST, "2")]
        assert _marked(_cape(reader, procs, name="svchost.exe", paths=False)) == []

    def test_only_the_system_s_own_process_marks_nothing(self) -> None:
        procs = [(5, 77, SYSTEM_SVCHOST, "50")]
        assert _marked(_triage({"behavioral1": procs}, name="svchost.exe")) == []

    def test_a_shipped_name_run_from_a_path_the_system_does_not_ship_is_marked(self) -> None:
        desktop = "C:\\Users\\u\\Desktop\\notepad.exe"
        assert _marked(_triage({"behavioral1": [(1, 56, desktop, "10")]}, name="notepad.exe")) == [
            0
        ]
        cape = _cape("cape2", [(1, 56, f"{TEMP}{DIGEST}.exe", "1")])
        assert _marked(cape) == [0]


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


def _any_marked(document: dict[str, Any], reader: Any) -> bool:
    """Whether the process view marks anything; a document that lists no process has no rows."""
    answer = read_view("sandbox_processes", document, reader)
    rows = answer.get("processes") or []
    return STAGED_NOTE_KEY in answer or any(row.get(STAGED_KEY) for row in rows)


class TestARecordReadWithNoReaderStatesTheWritesItShows:
    """With no reader, a write part counts as held only where it is not empty: a
    composed document lays every part out, so an empty one says nothing written."""

    def test_a_document_read_from_its_overview_only_marks_nothing(self) -> None:
        from malspark.schemas.sandbox_report import written_during_the_run

        overview = {"sample": {"id": "s1", "target": NAME, "sha256": DIGEST}}
        report = required_reader("triage").read(overview, provider="lab", task_id="s1")
        document = sandbox_document(report)
        assert written_during_the_run(document, None) is None
        assert not _any_marked(document, None)
        assert not _any_marked(document, ("lab", "triage", "overview"))

    def test_a_document_of_the_reader_for_unread_shapes_marks_nothing(self) -> None:
        from malspark.schemas.sandbox_report import written_during_the_run

        payload = {"blob": {"k": 1}, "processes": [{"pid": 1}]}
        document = sandbox_document(required_reader("unread").read(payload, provider="lab"))
        assert written_during_the_run(document, None) is None
        assert not _any_marked(document, None)

    @pytest.mark.parametrize("reader", CAPE_FAMILY)
    def test_a_document_that_shows_no_write_marks_nothing(self, reader: str) -> None:
        procs = [(1, 99, STAGED, "1")]
        assert _marked(_cape(reader, procs, writes=None, collected=False), read_by=None) == []
        assert _marked(_cape(reader, procs), read_by=None) == []

    def test_a_task_document_whose_parts_are_laid_out_empty_marks_nothing(self) -> None:
        procs = [(1, 56, STAGED, "100")]
        assert _marked(_triage({"behavioral1": procs}), read_by=None) == []
        assert _marked(_generic([(1, 99, STAGED, "")]), read_by=None) == []

    @pytest.mark.parametrize("reader", CAPE_FAMILY)
    def test_a_write_of_another_path_still_marks_the_root(self, reader: str) -> None:
        procs = [(1, 99, STAGED, "1"), (2, 1, STAGED, "2"), (3, 2, COPY, "3")]
        assert _marked(_cape(reader, procs, writes=(SVCHOST,)), read_by=None) == [0]
        assert _marked(_cape(reader, procs, dropped=(SVCHOST,)), read_by=None) == [0]

    @pytest.mark.parametrize("reader", CAPE_FAMILY)
    def test_the_copy_shown_written_marks_nothing(self, reader: str) -> None:
        procs = [(1, 99, RANDOM, "1"), (3, 77, SVCHOST, "2"), (4, 3, COPY, "3")]
        assert _marked(_cape(reader, procs, writes=(COPY,)), read_by=None) == []
        assert _marked(_cape(reader, procs, dropped=(COPY,)), read_by=None) == []
