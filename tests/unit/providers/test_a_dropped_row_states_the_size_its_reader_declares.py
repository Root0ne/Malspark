"""A dropped row states the size its reader declares the row holds.

A sandbox states a written file's size in one field and a dumped region's
length in another, and a view that read only ``size`` printed every region as
"not recorded" while the report held its length. Which fields of a dropped row
state its size is the reader's declaration, in the channel that declares the
guest path fields (``Reading.dropped_size_fields``): every declared field is
read and the first one stated wins; a reader that declares none, and a row
none of whose declared fields is stated, reads ``size``; a row stating none
states no size, and the report prints "not recorded" for it.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission; the rows added here are synthetic.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_view
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import READ_FROM_OVERVIEW
from tests.unit.providers.test_the_dropped_files_view_keeps_each_row_s_path_origin_kind_and_writer import (  # noqa: E501
    TASKS,
    WRITTEN,
    _report,
)

REGION = {
    "at": 901,
    "pid": 3444,
    "procid": 86,
    "name": "memory/3444-1-0x0000000000400000-0x0000000000500000-memory.dmp",
    "kind": "region",
    "origin": "protect",
    "addr": 4194304,
    "length": 1048576,
}


def _rows(normalised_by: Any, *rows: dict[str, Any]) -> dict[str, dict[str, Any]]:
    answer = sandbox_view("sandbox_dropped_files", sandbox_document(_report(*rows)), normalised_by)
    return {row["name"]: row for row in answer["dropped"]}


class TestTheReadersDeclaredFieldStatesTheSize:
    def test_a_dropped_row_states_the_size_its_reader_declares(self) -> None:
        rows = _rows(TASKS, WRITTEN, REGION)

        assert rows[REGION["name"]]["size"] == 1048576
        assert rows[WRITTEN["name"]]["size"] == WRITTEN["size"]

    def test_the_first_declared_field_stated_wins(self) -> None:
        both = {**REGION, "name": "memory/both.dmp", "size": 4096}

        assert _rows(TASKS, both)["memory/both.dmp"]["size"] == 4096

    def test_each_reading_of_the_reader_declares_the_same_fields(self) -> None:
        reader = required_reader("triage")

        assert reader.reading(READ_FROM_OVERVIEW).dropped_size_fields == (
            reader.reading().dropped_size_fields
        )
        assert "size" in reader.reading().dropped_size_fields


class TestWithoutADeclarationSizeIsRead:
    def test_a_dropped_row_with_no_declared_size_reads_size(self) -> None:
        rows = _rows(None, WRITTEN, REGION)

        assert rows[WRITTEN["name"]]["size"] == WRITTEN["size"]
        assert rows[REGION["name"]]["size"] is None

    def test_a_dropped_row_with_no_declared_size_prints_not_recorded(self) -> None:
        from malspark.reporting.ledger_projection import dynamic_from_ledger
        from malspark.reporting.models import (
            FileHashes,
            MalwareReport,
            SampleIdentity,
        )
        from malspark.reporting.renderers import MarkdownRenderer
        from malspark.reporting.renderers.layout import ANALYST
        from malspark.schemas.evidence import build_entry

        bare = {"name": "files/0xbare.dat", "procid": 86, "path": "C:\\bare.dat"}
        answer = sandbox_view("sandbox_dropped_files", sandbox_document(_report(bare)), TASKS)
        entry = build_entry(
            entry_id="ev_0015",
            seq=15,
            agent="pipeline",
            tool="sandbox_dropped_files",
            args={},
            server="pipeline",
            output="{}",
        ).model_copy(update={"structured": answer})
        dynamic = dynamic_from_ledger([entry])
        assert dynamic is not None
        (row,) = [op for op in dynamic.file_operations if op["name"] == "files/0xbare.dat"]
        assert row["size"] is None
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64)), dynamic=dynamic
        )
        text = MarkdownRenderer(layout=ANALYST).render(report)
        (line,) = [ln for ln in text.splitlines() if "bare.dat" in ln and "|" in ln]
        assert "not recorded" in line


class TestADeclaringReaderOfItsOwn:
    @pytest.fixture
    def declaring(self) -> Any:
        from dataclasses import replace

        from malspark.providers.sandbox.readers import (
            CapeReportReader,
            register_report_reader,
            unregister_report_reader,
        )

        class _Declaring(CapeReportReader):
            id = "size-box"

            def reading(self, read_from: str = "", provider: str = "") -> Any:
                held = super().reading(read_from, provider)
                return replace(held, dropped_size_fields=("bytes_written", "region_length"))

        register_report_reader(_Declaring)
        yield ("size-box", "size-box")
        unregister_report_reader(_Declaring.id)

    def test_every_declared_field_is_read(self, declaring: Any) -> None:
        rows = [
            {"name": "a.dat", "bytes_written": 10, "size": 99},
            {"name": "b.dmp", "region_length": 20},
            {"name": "c.dat", "size": 30},
            {"name": "d.dat"},
        ]
        answer = sandbox_view("sandbox_dropped_files", {"dropped_files": rows}, declaring)
        sizes = {row["name"]: row["size"] for row in answer["dropped"]}

        assert sizes == {"a.dat": 10, "b.dmp": 20, "c.dat": 30, "d.dat": None}
