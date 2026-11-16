"""Every sandbox view is read with the run's reader, through one entry point.

The pack, the read of a later detonation and an analyst's call each read the
sandbox's views, and the reader that built the report declares what its rows
mean (``Reading``): which field of a dropped row is its guest path, which
names its writer. A read without that declaration printed a written file with
an empty path beside the analyst's row with its guest path, and the report
listed the one file twice. Every view is read through ``sandbox_view``, which
takes the reader's declaration as a required argument: a call without it does
not run, and no module reads a view by its function.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission; the rows added here are synthetic.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from malspark.providers import sandbox_tools
from malspark.providers.detonation import DetonationRecord
from malspark.providers.sandbox_tools import sandbox_view
from malspark.reporting.ledger_projection import dynamic_from_ledger
from malspark.schemas.evidence import LedgerEntry, build_entry
from malspark.schemas.sandbox_document import sandbox_document
from tests.unit.providers.test_the_dropped_files_view_keeps_each_row_s_path_origin_kind_and_writer import (  # noqa: E501
    NOTE,
    TASKS,
    WRITTEN,
    _report,
)

SRC = Path(sandbox_tools.__file__).resolve().parents[1]
PACK_VIEWS = (
    "sandbox_processes",
    "sandbox_network",
    "sandbox_signatures",
    "sandbox_dropped_files",
    "sandbox_channels",
)


def _document() -> dict[str, Any]:
    return sandbox_document(_report(WRITTEN))


class TestOneEntryPoint:
    def test_a_view_is_not_read_without_the_reader_s_declaration(self) -> None:
        with pytest.raises(TypeError):
            sandbox_view("sandbox_dropped_files", _document())  # type: ignore[call-arg]

    def test_no_module_reads_a_view_but_through_the_entry_point(self) -> None:
        views = set(sandbox_tools.DETONATION_READERS) - {sandbox_tools.ITEMS_TOOL}
        found: list[str] = []
        for path in sorted(SRC.rglob("*.py")):
            if path == Path(sandbox_tools.__file__).resolve():
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                # A view taken from the module, by its attribute or by its import.
                names = (
                    [node.attr]
                    if isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "sandbox_tools"
                    else [alias.name for alias in node.names]
                    if isinstance(node, ast.ImportFrom)
                    and (node.module or "").endswith("sandbox_tools")
                    else []
                )
                found += [f"{path.relative_to(SRC)}:{node.lineno} {n}" for n in names if n in views]  # type: ignore[attr-defined]
        assert found == []

    @pytest.mark.parametrize(
        "tool", sorted(set(sandbox_tools.DETONATION_READERS) - {sandbox_tools.ITEMS_TOOL})
    )
    def test_each_view_an_agent_is_offered_is_read_through_it(self, tool: str) -> None:
        asked = ("dropped",) if tool == "sandbox_report_section" else ()
        answer = sandbox_view(tool, _document(), TASKS, *asked)

        assert isinstance(answer, dict) and not answer.get("error")


class TestThePackReadsEachViewAsAnAnalystDoes:
    def _pack(self, tmp_path: Path) -> dict[str, Any]:
        from malspark.agents.evidence_recorder import EvidenceRecorder
        from malspark.pipeline.triage_pack import PIPELINE, run_pack
        from malspark.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_triage_pack import _inputs, _write
        from tests.unit.tools.test_binary import _pe

        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        path = _write(tmp_path, "s.exe", _pe())
        result = run_pack(
            recorder,
            _inputs(path, "pe", sandbox_report=_document(), sandbox_normalised_by=TASKS),
        )
        return {e.tool: e for e in result.entries}

    @pytest.mark.parametrize("tool", PACK_VIEWS)
    def test_each_pack_view_answers_as_the_entry_point_does_with_the_run_s_reader(
        self, tool: str, tmp_path: Path
    ) -> None:
        entry = self._pack(tmp_path)[tool]

        assert entry.ok, entry.error
        assert entry.structured == sandbox_view(tool, _document(), TASKS)


class _Container:
    event_sink = None
    detonations: list[Any] = []


def _later() -> list[LedgerEntry]:
    from malspark.pipeline.detonations import platform_reads

    record = DetonationRecord(ordinal=2, origin="agent", report=_document(), normalised_by=TASKS)
    return [LedgerEntry.model_validate(row) for row in platform_reads(_Container(), record, "")]


class TestALaterDetonationIsReadWithItsReader:
    def test_the_pack_s_read_of_a_later_detonation_states_the_guest_path(self) -> None:
        entry = next(e for e in _later() if e.tool == "sandbox_dropped_files")
        row = next(r for r in entry.structured["dropped"] if r["name"] == WRITTEN["name"])

        assert row["path"] == NOTE

    def test_every_view_of_a_later_detonation_is_read(self) -> None:
        read = {e.tool: e for e in _later()}

        assert all(read[tool].ok for tool in PACK_VIEWS), {
            tool: read[tool].error for tool in PACK_VIEWS
        }


class TestThePackAndAnAnalystGiveOneRow:
    def test_the_pack_and_an_analyst_read_of_one_task_give_one_dropped_row(self) -> None:
        pack = next(e for e in _later() if e.tool == "sandbox_dropped_files")
        analyst = build_entry(
            entry_id="ev_0149",
            seq=149,
            agent="dynamic",
            tool="sandbox_dropped_files",
            args={"detonation": "d2"},
            server="pipeline",
            output="{}",
        ).model_copy(
            update={"structured": sandbox_view("sandbox_dropped_files", _document(), TASKS)}
        )
        dynamic = dynamic_from_ledger([pack, analyst])
        assert dynamic is not None
        names = [op["name"] for op in dynamic.file_operations if op.get("operation") == "write"]

        assert names.count(WRITTEN["name"]) == 1
        assert len(names) == len(set(names))
