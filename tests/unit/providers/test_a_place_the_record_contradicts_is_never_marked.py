"""The mark is given only where the record does not contradict it.

A path the report shows written during the run is the sample's doing and is
never marked; the marked rows of one task share one image path, the path of
the process the record states started first, and none where it states no
order; where nothing is marked the view answers as it did and says nothing.
Synthetic documents only; nothing is run.
"""

from __future__ import annotations

from typing import Any

from malspark.providers.sandbox_tools import read_view, sandbox_processes
from malspark.schemas.sandbox_report import STAGED_KEY, STAGED_NOTE_KEY

DIGEST = "d" * 64
STAGED = f"C:\\Users\\u\\AppData\\Local\\Temp\\{DIGEST}.exe"
INSTALLED = "C:\\Users\\u\\AppData\\Roaming\\svc\\invoice.exe"
SVCHOST = "C:\\Windows\\System32\\svchost.exe"


def _process(pid: int, ppid: int, name: str, seen: str = "") -> dict[str, Any]:
    row: dict[str, Any] = {"pid": pid, "ppid": ppid, "process_name": name}
    if seen:
        row["first_seen"] = seen
    return row


def _report(processes: list[dict[str, Any]], written: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "target": {"name": "invoice.exe", "sha256": DIGEST},
        "behavior": {"processes": processes},
        "dropped": [{"name": path.rsplit("\\", 1)[-1], "filepath": path} for path in written],
    }


def _marked(answer: dict[str, Any]) -> list[Any]:
    return [row["pid"] for row in answer["processes"] if STAGED_KEY in row]


class TestAWrittenPathIsTheSample_s:
    def test_a_copy_at_a_written_path_is_not_marked_and_the_first_root_still_is(self) -> None:
        # The copy runs under the submitted name, started by a service outside
        # the tree; the report shows it written. No order is stated, so only
        # the written path leaving the race lets the root be marked.
        report = _report(
            [
                _process(10, 4, STAGED),
                _process(30, 2, SVCHOST),
                _process(31, 30, INSTALLED),
            ],
            (INSTALLED,),
        )
        assert _marked(sandbox_processes(report)) == [10]

    def test_the_written_path_is_read_through_the_entry_point(self) -> None:
        report = _report([_process(31, 30, INSTALLED)], (INSTALLED,))
        answer = read_view("sandbox_processes", report, None)
        assert _marked(answer) == []
        assert STAGED_NOTE_KEY not in answer


class TestOneTaskMarksOnePath:
    def _two_places(self, root_seen: str, copy_seen: str) -> dict[str, Any]:
        return _report(
            [
                _process(10, 4, STAGED, root_seen),
                _process(30, 2, SVCHOST),
                _process(31, 30, INSTALLED, copy_seen),
            ]
        )

    def test_the_process_the_record_states_started_first_is_marked(self) -> None:
        assert _marked(sandbox_processes(self._two_places("125", "90412"))) == [10]

    def test_the_order_stated_the_other_way_marks_the_other(self) -> None:
        assert _marked(sandbox_processes(self._two_places("90412", "125"))) == [31]

    def test_no_stated_order_marks_none(self) -> None:
        answer = sandbox_processes(self._two_places("", ""))
        assert _marked(answer) == []
        assert STAGED_NOTE_KEY not in answer

    def test_an_order_stated_for_one_only_marks_none(self) -> None:
        assert _marked(sandbox_processes(self._two_places("125", ""))) == []

    def test_one_path_run_twice_is_marked_on_both_rows(self) -> None:
        report = _report([_process(10, 4, STAGED), _process(12, 4, STAGED)])
        assert _marked(sandbox_processes(report)) == [10, 12]


class TestNothingMarkedSaysNothing:
    def test_a_renamed_root_whose_only_qualifying_process_is_a_written_copy(self) -> None:
        renamed = "C:\\Users\\u\\AppData\\Local\\Temp\\a8f3k2.exe"
        processes = [_process(10, 4, renamed), _process(11, 10, INSTALLED)]
        written = sandbox_processes(_report(processes, (INSTALLED,)))
        assert _marked(written) == []
        assert STAGED_NOTE_KEY not in written
        # The rows are the rows the view gives where nothing qualifies at all.
        plain = sandbox_processes(_report([_process(10, 4, renamed), _process(11, 10, SVCHOST)]))
        assert [set(row) for row in written["processes"]] == [
            set(row) for row in plain["processes"]
        ]
        assert set(written) == set(plain)


class TestTheStatedOrder:
    def _two(self, root_seen: str, copy_seen: str) -> list[Any]:
        report = _report(
            [
                _process(10, 4, STAGED, root_seen),
                _process(30, 2, SVCHOST),
                _process(31, 30, INSTALLED, copy_seen),
            ]
        )
        return _marked(sandbox_processes(report))

    def test_timestamps_of_one_form_are_read_in_time_order(self) -> None:
        assert self._two("2026-08-13 20:08:27,020", "2026-08-13 20:09:01,500") == [10]

    def test_two_forms_state_no_order(self) -> None:
        assert self._two("125", "2026-08-13 20:09:01,500") == []

    def test_a_tie_states_no_order(self) -> None:
        assert self._two("125", "125") == []

    def test_a_text_that_is_no_time_states_no_order(self) -> None:
        assert self._two("early", "late") == []


class TestABareImage:
    def test_an_image_that_states_no_folder_is_read_against_the_written_names(self) -> None:
        report = _report([_process(10, 4, "invoice.exe")], (INSTALLED,))
        assert _marked(sandbox_processes(report)) == []

    def test_a_written_name_with_no_folder_does_not_contradict_a_full_path(self) -> None:
        report = {
            **_report([_process(10, 4, STAGED)]),
            "dropped": [{"name": f"{DIGEST}.exe"}],
        }
        assert _marked(sandbox_processes(report)) == [10]
