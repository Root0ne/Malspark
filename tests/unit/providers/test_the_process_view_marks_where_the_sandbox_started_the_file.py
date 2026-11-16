"""The process view marks the row whose image is where the sandbox started the submitted file.

That row carries ``staged_by_sandbox: true`` (left out on every other row) and
the answer carries one sentence, once, that states the fact first. Two
differently shaped reports mark it alike; a report whose sandbox renamed the
copy marks nothing and reads as it did; a child the sample runs is never
marked. Synthetic reports only; nothing is run.
"""

from __future__ import annotations

from typing import Any

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import read_view, sandbox_processes
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import (
    STAGED_KEY,
    STAGED_NOTE,
    STAGED_NOTE_KEY,
    cape_report_to_sandbox_report,
)

DIGEST = "c" * 64
TEMP = "C:\\Users\\u\\AppData\\Local\\Temp"
STAGED = f"{TEMP}\\{DIGEST}.exe"
COPY = "C:\\Users\\u\\AppData\\Roaming\\svc.exe"


def _triage(image: str = STAGED, copy: str = COPY) -> dict[str, Any]:
    overview = {"sample": {"id": "s1", "target": "invoice.exe", "sha256": DIGEST}}
    task = {
        "processes": [
            {"procid": 1, "procid_parent": 0, "image": image, "cmd": f'"{image}"'},
            # The sample copies itself and runs the copy: behaviour.
            {"procid": 2, "procid_parent": 1, "image": copy, "cmd": f'"{copy}" -r'},
            {
                "procid": 3,
                "procid_parent": 0,
                "image": "C:\\Windows\\explorer.exe",
                "cmd": "explorer.exe",
                "orig": True,
            },
        ]
    }
    report = required_reader("triage").read(
        overview, provider="lab-box", task_id="s1", task_reports={"behavioral1": task}
    )
    return sandbox_document(report)


def _cape(name: str = "invoice.exe") -> dict[str, Any]:
    raw = {
        "target": {"file": {"name": "invoice.exe", "sha256": DIGEST}},
        "behavior": {
            "processes": [
                {"pid": 400, "ppid": 300, "process_name": name, "command_line": f'"{name}"'},
                {
                    "pid": 404,
                    "ppid": 400,
                    "process_name": "cmd.exe",
                    "command_line": "cmd.exe /c invoice.exe -r",
                },
            ]
        },
    }
    report = cape_report_to_sandbox_report(raw, provider="cape", source_format="cape")
    return sandbox_document(report)


def _marked(answer: dict[str, Any]) -> list[Any]:
    return [row["pid"] for row in answer["processes"] if STAGED_KEY in row]


class TestTheRowIsMarked:
    def test_a_triage_shaped_report_marks_the_root_that_runs_the_digest_named_file(
        self,
    ) -> None:
        answer = sandbox_processes(_triage())
        assert _marked(answer) == [1]
        (row,) = [row for row in answer["processes"] if row["pid"] == 1]
        assert row[STAGED_KEY] is True
        assert answer[STAGED_NOTE_KEY] == STAGED_NOTE

    def test_a_copy_the_sample_runs_under_the_digest_name_is_not_marked(self) -> None:
        copy = f"C:\\Users\\u\\AppData\\Roaming\\{DIGEST}.exe"
        assert _marked(sandbox_processes(_triage(copy=copy))) == [1]

    def test_a_cape_shaped_report_marks_the_root_that_runs_the_submitted_name(self) -> None:
        answer = sandbox_processes(_cape())
        assert _marked(answer) == [400]
        assert answer[STAGED_NOTE_KEY] == STAGED_NOTE

    def test_the_read_through_the_entry_point_marks_it_too(self) -> None:
        assert _marked(read_view("sandbox_processes", _triage(), None)) == [1]

    def test_the_sentence_states_the_fact_first_and_is_said_once(self) -> None:
        answer = sandbox_processes(_triage())
        # What the record shows first, then what it means; nothing of what the
        # sample did elsewhere.
        assert STAGED_NOTE.startswith(f"The row marked {STAGED_KEY} is the first process")
        assert STAGED_NOTE.endswith("the sandbox started the submitted file from there.")
        assert "sample" not in STAGED_NOTE
        assert str(answer).count(STAGED_NOTE) == 1


class TestNothingElseChanges:
    def test_a_renamed_copy_marks_nothing_and_reads_as_before(self) -> None:
        renamed = f"{TEMP}\\a8f3k2.exe"
        answer = sandbox_processes(_triage(renamed))
        assert _marked(answer) == []
        assert STAGED_NOTE_KEY not in answer
        assert [row["name"] for row in answer["processes"]] == [
            renamed,
            COPY,
            "C:\\Windows\\explorer.exe",
        ]

    def test_the_marked_row_keeps_every_field_it_had(self) -> None:
        marked = sandbox_processes(_triage())["processes"][0]
        plain = sandbox_processes(_triage(f"{TEMP}\\a8f3k2.exe"))["processes"][0]
        assert set(marked) - set(plain) == {STAGED_KEY}

    def test_a_page_without_the_row_carries_no_sentence(self) -> None:
        answer = sandbox_processes(_triage(), offset=1, limit=2)
        assert _marked(answer) == []
        assert STAGED_NOTE_KEY not in answer

    def test_a_page_with_the_row_carries_it(self) -> None:
        answer = sandbox_processes(_triage(), offset=0, limit=1)
        assert _marked(answer) == [1]
        assert answer[STAGED_NOTE_KEY] == STAGED_NOTE
