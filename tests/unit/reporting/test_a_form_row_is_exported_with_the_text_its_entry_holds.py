"""A form row is exported with the text its entry holds (T-841).

The network block reads a dotted name as a host and folds its case: a host
name is read without regard to case. A row of the file's strings that nothing
in the run reads as its kind (a *form row*, ``reporting.string_row_form``) is
no host name, so every surface that carries it — the IOC table the report
stores, the indicator list (``/iocs``), the table ``/full`` serves and the
second-source reads — carries the text its entry holds, character for
character. Where the strings hold one name in two cases, each is exported as
written. A row read as a host keeps the lower-case reading, and no publish
decision moves.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.services.report_service import ioc_feed_rows, with_current_iocs
from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers.stix_renderer import publishes
from malspark.reporting.string_row_form import (
    EXPORTED_FORM_KINDS,
    exported_form,
    string_row_forms,
)
from malspark.schemas.evidence import build_entry

# Dotted names as the strings entry holds them, one written in two cases, and
# a host name in mixed case that a URL row of the run reads as a host.
_WRITTEN = ("runtime.typePointers.next", "abi.Name.Data", "abi.NAME.data")
_HOST = "Relay-Node.Example-Test.COM"
_SWEEP = {
    "iocs": [
        *({"kind": "domain", "value": value} for value in _WRITTEN),
        {"kind": "domain", "value": _HOST},
        {"kind": "url", "value": f"http://{_HOST}/gate"},
    ]
}
# Another entry, not the sweep, that holds one of the names in a third spelling.
_DUMP = "symbol table: RUNTIME.typePointers.NEXT (offset 0x40)"


def _entry(seq: int, tool: str, output: str) -> Any:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="static",
        tool=tool,
        args={},
        server="analysis",
        output=output,
    )


def _ledger() -> list[Any]:
    return [
        _entry(1, "iocs_from_file", json.dumps(_SWEEP)),
        _entry(2, "symbol_dump", _DUMP),
    ]


def _built() -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        evidence_ledger=_ledger(),
    ).build_deterministic()


def _form_rows(report: MalwareReport) -> list[Any]:
    forms = string_row_forms(report, report.consolidated_iocs)
    return [row for row in report.consolidated_iocs if exported_form(row, forms)]


def _feed(report: MalwareReport) -> dict[str, dict[str, Any]]:
    rows = ioc_feed_rows(report.model_dump(mode="json"), None)
    return {row["value"]: row for row in rows}


class TestAFormRowCarriesItsEntrysText:
    def test_the_stored_table_carries_each_written_text(self) -> None:
        values = {row.value for row in _form_rows(_built())}
        assert set(_WRITTEN) <= values
        assert not {value.lower() for value in _WRITTEN} & values

    def test_the_indicator_list_carries_each_written_text(self) -> None:
        feed = _feed(_built())
        for value in _WRITTEN:
            assert feed[value]["kind"] == EXPORTED_FORM_KINDS["Dotted name"]
        assert not {value.lower() for value in _WRITTEN} & set(feed)

    def test_the_served_table_carries_each_written_text(self) -> None:
        served, _note = with_current_iocs(_built().model_dump(mode="json"), "owner")
        values = {row["value"] for row in served["consolidated_iocs"]}
        assert set(_WRITTEN) <= values
        assert not {value.lower() for value in _WRITTEN} & values

    def test_two_cases_of_one_name_are_two_rows_each_as_written(self) -> None:
        values = [row.value for row in _form_rows(_built())]
        assert values.count("abi.Name.Data") == 1
        assert values.count("abi.NAME.data") == 1

    def test_each_form_row_is_held_whole_by_an_entry_its_reason_names(self) -> None:
        ledger = {entry.id: entry for entry in _ledger()}
        rows = _form_rows(_built())
        assert rows
        for row in rows:
            named = re.search(r"the rows? from \S+ \(([^)]*)\) holds? it", row.published or "")
            assert named, row.published
            ids = [eid.strip() for eid in named.group(1).split(",")]
            assert any(row.value in str(ledger[eid].output) for eid in ids), row.value

    def test_the_second_source_read_carries_the_text_its_entry_holds(self) -> None:
        reads = {read.entry: read for read in _built().second_source_reads or []}
        assert "RUNTIME.typePointers.NEXT" in reads["ev_0002"].holds
        assert "runtime.typepointers.next" not in reads["ev_0002"].holds


class TestAHostKeepsItsReading:
    def test_a_host_name_in_mixed_case_is_exported_lower_case(self) -> None:
        feed = _feed(_built())
        assert _HOST.lower() in feed
        assert _HOST not in feed
        assert feed[_HOST.lower()]["kind"] == "domain"

    def test_no_publish_decision_moves(self) -> None:
        report = _built()
        decided = {
            (row.kind, row.value.lower()): publishes(row.published)
            for row in report.consolidated_iocs
        }
        assert not any(decided[("domain", value.lower())] for value in _WRITTEN)
