"""The place a sandbox started the submitted file from is read from the report's own lineage.

A process that runs the submitted file (by the name it was submitted under or
by its digest, the lineage reading every surface places a process by), whose
image is that file, and that starts the sample's tree (no process its parent
chain reaches runs the file) has the sandbox's path as its image: the sandbox
started the file from there. A copy the sample makes of itself and
runs is a child inside the tree and is behaviour. No product, path or folder
names the place; a sandbox that starts the file under a name the reading does
not know marks nothing.
"""

from __future__ import annotations

from typing import Any

from malspark.schemas.sandbox_report import (
    STAGED_KEY,
    STAGED_WORDS,
    staged_words,
    started_by_the_sandbox,
)

DIGEST = "9" * 64
STAGED = f"C:\\Users\\u\\AppData\\Local\\Temp\\{DIGEST}.exe"


def _row(pid: int, ppid: int, name: str, command_line: str = "", **extra: Any) -> dict[str, Any]:
    return {"pid": pid, "ppid": ppid, "name": name, "command_line": command_line, **extra}


def _pids(rows: list[dict[str, Any]], file_name: str = "", sha256: str = "") -> list[Any]:
    return [row["pid"] for row in started_by_the_sandbox(rows, file_name, sha256)]


class TestTheRootThatRunsTheFileIsTheSandboxS:
    def test_a_root_running_the_digest_named_file_is_it_and_a_copy_it_runs_is_not(
        self,
    ) -> None:
        copy = "C:\\Users\\u\\AppData\\Roaming\\svc\\" + DIGEST + ".exe"
        rows = [
            _row(10, 4, STAGED, f'"{STAGED}"'),
            # The sample copies itself under the same digest name and runs it.
            _row(11, 10, copy, f'"{copy}" /install'),
            _row(12, 11, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami"),
        ]
        assert _pids(rows, "invoice.exe", DIGEST) == [10]

    def test_the_submitted_name_reads_as_the_digest_does(self) -> None:
        rows = [
            _row(10, 4, "C:\\Users\\u\\Desktop\\invoice.exe"),
            _row(11, 10, "C:\\Users\\u\\AppData\\invoice.exe", "invoice.exe -r"),
        ]
        assert _pids(rows, "invoice.exe") == [10]

    def test_each_task_has_its_own_root(self) -> None:
        rows = [
            _row(83, 56, STAGED, task="t1"),
            _row(88, 81, STAGED, task="t2"),
            # The same id in the other task, under that task's root.
            _row(83, 88, STAGED, task="t2"),
        ]
        assert _pids(rows, "", DIGEST) == [83, 88]

    def test_a_process_of_another_task_is_never_a_parent(self) -> None:
        # Task t2 lists a process with the id task t1's root names as its
        # parent: read on its own, each task's root is its own.
        rows = [_row(83, 56, STAGED, task="t1"), _row(56, 4, STAGED, task="t2")]
        assert _pids(rows, "", DIGEST) == [83, 56]

    def test_a_process_that_names_the_file_on_its_command_line_is_not_the_place(self) -> None:
        # rundll32 runs the file, but its image is rundll32's: not where the
        # sandbox placed the file.
        rows = [_row(5, 1, "C:\\Windows\\System32\\rundll32.exe", f"rundll32.exe {STAGED},#1")]
        assert _pids(rows, "", DIGEST) == []

    def test_where_the_sandbox_marks_another_process_this_one_is_not_marked(self) -> None:
        rows = [
            _row(10, 4, STAGED),
            _row(20, 2, "C:\\Windows\\explorer.exe", marked=True),
        ]
        assert _pids(rows, "", DIGEST) == []
        rows[0]["marked"] = True
        assert _pids(rows, "", DIGEST) == [10]


class TestNothingIsGuessed:
    def test_a_renamed_copy_marks_nothing(self) -> None:
        rows = [_row(10, 4, "C:\\Users\\u\\AppData\\Local\\Temp\\a8f3k2.exe", marked=True)]
        assert _pids(rows, "invoice.exe", DIGEST) == []

    def test_no_name_and_no_digest_mark_nothing(self) -> None:
        assert _pids([_row(10, 4, STAGED)]) == []

    def test_a_name_that_holds_the_submitted_name_is_not_it(self) -> None:
        rows = [_row(10, 4, "C:\\Program Files\\MicrosoftEdgeUpdate.exe")]
        assert _pids(rows, "update.exe") == []

    def test_a_generated_launcher_s_run_marks_by_the_same_rule(self) -> None:
        # The sandbox runs an archive (the submitted file) whose script host
        # starts the member: no process runs the archive, so nothing is marked;
        # the launcher's row and the member's row read as they did.
        rows = [
            _row(1, 0, "C:\\Windows\\System32\\wscript.exe", "wscript.exe launch.js"),
            _row(2, 1, "C:\\Temp\\unpack001\\sample.exe", lineage="sample", marked=True),
        ]
        assert _pids(rows, "submission.zip", "a" * 64) == []


class TestTheWordsReadTheMarkAlone:
    def test_only_a_true_mark_gives_the_words(self) -> None:
        assert staged_words({STAGED_KEY: True}) == STAGED_WORDS
        for value in ("true", 1, "yes", None, False):
            assert staged_words({STAGED_KEY: value}) == ""
