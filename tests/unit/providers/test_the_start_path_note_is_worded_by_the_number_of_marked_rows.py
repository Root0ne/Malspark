"""The start-path note is worded by the number of rows it speaks of.

The sentence beside the rows marked ``staged_by_sandbox`` speaks of one row
where one is marked, word for word as it always was
(``sandbox_report.STAGED_NOTE``), and of each row where more are: a report of
two tasks, each starting the submitted file from the same place, marks a row
in each. Both writers (the process view's answer and the facts the writers
that decide are shown, ``evidence_bundles.sandbox_start_facts``) pass the
number of marked rows in what they write. Synthetic reports only; nothing is
run.
"""

from __future__ import annotations

from typing import Any

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_processes
from malspark.reporting import evidence_bundles
from malspark.reporting.models import ProcessNode
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import (
    STAGED_KEY,
    STAGED_NOTE,
    STAGED_NOTE_KEY,
    STAGED_WORDS,
    staged_note,
)
from tests.unit.reporting._report_shapes import rich_report

DIGEST = "c" * 64
STAGED = f"C:\\Users\\u\\AppData\\Local\\Temp\\{DIGEST}.exe"
PLURAL = (
    f"Each of the 2 rows marked {STAGED_KEY} is the first process of its own lineage that "
    "runs the submitted file, started by no process that runs it, at a path the report does "
    "not show written during the run: the sandbox started the submitted file from each "
    "row's path."
)


def _tasks(count: int) -> dict[str, Any]:
    overview = {"sample": {"id": "s1", "target": "invoice.exe", "sha256": DIGEST}}
    task = {
        "processes": [{"procid": 1, "procid_parent": 0, "image": STAGED, "cmd": f'"{STAGED}"'}],
        "dumped": [{"name": "run.log", "path": "C:\\Users\\u\\AppData\\Local\\Temp\\run.log"}],
    }
    report = required_reader("triage").read(
        overview,
        provider="lab-box",
        task_id="s1",
        task_reports={f"behavioral{n}": task for n in range(1, count + 1)},
    )
    return sandbox_document(report)


class TestTheSentence:
    def test_one_row_is_spoken_of_as_it_always_was(self) -> None:
        assert staged_note(1) == STAGED_NOTE

    def test_more_rows_are_each_spoken_of(self) -> None:
        assert staged_note(2) == PLURAL


class TestEachWriterPassesTheNumber:
    def test_the_process_view_of_one_marked_row_says_the_row(self) -> None:
        answer = sandbox_processes(_tasks(1))
        assert [STAGED_KEY in row for row in answer["processes"]] == [True]
        assert answer[STAGED_NOTE_KEY] == STAGED_NOTE

    def test_the_process_view_of_two_marked_rows_says_each_row(self) -> None:
        answer = sandbox_processes(_tasks(2))
        assert [STAGED_KEY in row for row in answer["processes"]] == [True, True]
        assert answer[STAGED_NOTE_KEY] == PLURAL

    def test_the_facts_of_two_marked_rows_of_one_path_say_each_row(self) -> None:
        report = rich_report()
        assert report.dynamic is not None
        report.dynamic.process_tree = [
            ProcessNode(pid=pid, name=STAGED, task=task, staged_by_sandbox=True)
            for pid, task in ((10, "behavioral1"), (12, "behavioral2"))
        ]
        assert evidence_bundles.sandbox_start_facts(report) == {
            STAGED: f"{STAGED_WORDS} (pid 10, pid 12). {PLURAL}"
        }
