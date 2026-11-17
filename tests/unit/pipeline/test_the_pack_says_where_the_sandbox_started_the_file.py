"""The pack's process line writes the words beside the row the process view marks.

The row whose image is the submitted file as the sandbox started it
(``staged_by_sandbox``) is named with the same words every surface writes
beside it; a line with no such row reads as it did. Offline.
"""

from __future__ import annotations

from typing import Any

from malspark.pipeline.triage_pack import PIPELINE, pack_block, pack_entries
from malspark.providers import sandbox_tools
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.sandbox_report import STAGED_WORDS

DIGEST = "c" * 64
STAGED = f"C:\\Users\\u\\AppData\\Local\\Temp\\{DIGEST}.exe"


def _report(image: str) -> dict[str, Any]:
    return {
        "target": {"name": "invoice.exe", "sha256": DIGEST},
        "behavior": {
            "processes": [
                {"pid": 4, "ppid": 1, "process_name": image},
                {"pid": 5, "ppid": 4, "process_name": "C:\\Windows\\System32\\cmd.exe"},
            ]
        },
        # The record of files written during the run: a file no process runs.
        # Read with no reader, a record states its file writes only where it
        # shows one.
        "dropped": [{"name": "run.log", "filepath": "C:\\Users\\u\\AppData\\Local\\Temp\\run.log"}],
    }


def _line(image: str) -> str:
    answer = sandbox_tools.sandbox_processes(_report(image))
    row = LedgerEntry(
        id="ev_0001",
        seq=1,
        tool="sandbox_processes",
        agent=PIPELINE,
        source="pack",
        structured=answer,
        output="x",
    ).model_dump(mode="json")
    (line,) = [one for one in pack_block(pack_entries([row]), 0).splitlines() if "ev_0001" in one]
    return line


class TestThePackLine:
    def test_the_marked_row_is_named_with_the_words(self) -> None:
        line = _line(STAGED)
        assert f"{DIGEST}.exe ({STAGED_WORDS})" in line
        assert line.count(STAGED_WORDS) == 1

    def test_a_line_with_no_marked_row_reads_as_before(self) -> None:
        line = _line("C:\\Users\\u\\AppData\\Local\\Temp\\a8f3k2.exe")
        assert STAGED_WORDS not in line
        assert "2 processes (" in line
