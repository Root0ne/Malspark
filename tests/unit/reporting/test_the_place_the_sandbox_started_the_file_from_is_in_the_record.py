"""The row the process view marks as where the sandbox started the file is marked in the record.

The ledger keeps the view's answer as written, so the mark is in the record;
``ProcessNode`` carries it (left out of the dump when false) and the projection
reads it from the row. The report's process tree, its figure and the ledger's
table each write the same words beside that row, read from one helper; a row
not marked renders as it did.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.figures import build_process_tree
from malspark.reporting.ledger_projection import dynamic_from_ledger
from malspark.reporting.ledger_report import build_sections
from malspark.reporting.models import ProcessNode
from malspark.reporting.renderers.markdown import _process_tree_lines
from malspark.schemas.evidence import EvidenceCounter
from malspark.schemas.sandbox_report import STAGED_KEY, STAGED_NOTE, STAGED_NOTE_KEY, STAGED_WORDS
from tests.unit._ledger_helpers import entry
from tests.unit.reporting._report_shapes import rich_report

STAGED = "C:\\Users\\u\\AppData\\Local\\Temp\\" + "c" * 64 + ".exe"
ANSWER: dict[str, Any] = {
    STAGED_NOTE_KEY: STAGED_NOTE,
    "processes": [
        {"pid": 10, "ppid": 4, "name": STAGED, "command_line": f'"{STAGED}"', STAGED_KEY: True},
        {"pid": 11, "ppid": 10, "name": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd"},
    ],
    "total": 2,
}


def _nodes() -> list[ProcessNode]:
    dynamic = dynamic_from_ledger(
        [entry("sandbox_processes", ANSWER, EvidenceCounter(), agent="dynamic")]
    )
    assert dynamic is not None
    return dynamic.process_tree


class TestTheRecordCarriesIt:
    def test_a_process_node_round_trips_the_field_and_leaves_it_out_when_false(self) -> None:
        marked = ProcessNode(pid=10, name=STAGED, staged_by_sandbox=True)
        dumped = marked.model_dump()
        assert dumped[STAGED_KEY] is True
        assert ProcessNode.model_validate(dumped) == marked
        assert STAGED_KEY not in ProcessNode(pid=11).model_dump()
        # A node stored before the field existed reads as not marked.
        assert ProcessNode.model_validate({"pid": 12}).staged_by_sandbox is False

    def test_the_projection_reads_the_row_s_mark(self) -> None:
        (root,) = _nodes()
        assert root.staged_by_sandbox is True
        (child,) = root.children
        assert child.staged_by_sandbox is False


class TestEverySurfaceWritesTheWords:
    def test_the_report_s_process_tree_writes_them_beside_the_row(self) -> None:
        lines = _process_tree_lines(_nodes()[0], 0)
        assert lines[0].endswith(f"  [{STAGED_WORDS}]")
        assert STAGED_WORDS not in lines[1]
        assert lines[1] == "  └─ pid=11 ppid=10 C:\\Windows\\System32\\cmd.exe  (cmd)"

    def test_the_figure_writes_them_beside_the_row(self) -> None:
        report = rich_report()
        assert report.dynamic is not None
        report.dynamic.process_tree = _nodes()
        figure = build_process_tree(report)
        assert figure is not None
        assert figure.content.count(STAGED_WORDS) == 1

    def test_the_ledger_s_table_writes_them_in_the_name_cell(self) -> None:
        ledger = [entry("sandbox_processes", ANSWER, EvidenceCounter(), agent="dynamic")]
        (section,) = [s for s in build_sections(ledger) if s.key == "sandbox_processes"]
        first, second = section.rows
        assert first[2] == f"{STAGED} ({STAGED_WORDS})"
        assert second[2] == "C:\\Windows\\System32\\cmd.exe"
