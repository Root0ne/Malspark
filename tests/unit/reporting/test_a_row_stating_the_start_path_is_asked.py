"""A configuration or identifier row stating the start path from process rows alone is asked.

A row whose value is the image path (or the command line) of a process the
report marks as where the sandbox started the submitted file from, and whose
every cited entry holds that value only as a process row (the process view,
the item reader's processes, the behaviour links' command line of a process),
is asked about once with the fact. The writer keeps it (with what it says of
the path), rewrites it or leaves it out: code drops nothing, and the check
keys on the row's value and its cited entries only. A row whose cited entries
hold the path anywhere else, a row of another value and a report with no mark
are not asked. Offline.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.analysis import behaviour_code as bc
from malspark.pipeline import validation as v
from malspark.reporting import evidence_bundles
from malspark.reporting.ledger_projection import dynamic_from_ledger
from malspark.reporting.models import MalwareReport
from malspark.schemas.evidence import LedgerEntry, build_entry
from malspark.schemas.sandbox_report import STAGED_KEY, STAGED_NOTE, STAGED_NOTE_KEY
from tests.unit.reporting._report_shapes import rich_report

STAGED = "C:\\Users\\u\\AppData\\Local\\Temp\\" + "c" * 64 + ".exe"
CHILD = "C:\\Windows\\System32\\cmd.exe"


def _entry(number: int, tool: str, payload: Any, args: dict[str, Any] | None = None) -> Any:
    return build_entry(
        entry_id=f"ev_{number:04d}",
        seq=number,
        agent="dynamic",
        tool=tool,
        args=args or {},
        server=None,
        output=json.dumps(payload),
    )


def _processes(marked: bool = True) -> dict[str, Any]:
    row: dict[str, Any] = {"pid": 10, "ppid": 4, "name": STAGED, "command_line": f'"{STAGED}"'}
    if marked:
        row[STAGED_KEY] = True
    return {
        **({STAGED_NOTE_KEY: STAGED_NOTE} if marked else {}),
        "processes": [row, {"pid": 11, "ppid": 10, "name": CHILD, "command_line": "cmd"}],
        "total": 2,
    }


def _ledger(marked: bool = True) -> list[LedgerEntry]:
    links = {
        "tool": bc.TOOL,
        "links": [
            {"kind": "command line", "value": f'"{STAGED}"', "items": ["proc:10"], "held": []},
            {"kind": "path", "value": CHILD, "items": ["file:1"], "held": []},
        ],
    }
    return [
        _entry(1, "sandbox_processes", _processes(marked)),
        _entry(2, "behaviour_code_links", links),
        _entry(3, "strings", {"strings": [{"offset": 16, "enc": "ascii", "text": STAGED}]}),
        _entry(
            4,
            "sandbox_items",
            {"section": "processes", "items": [{"id": "proc:10", "fields": {"pid": 10}}]},
            {"section": "processes"},
        ),
        _entry(
            5,
            "sandbox_items",
            {"section": "files", "items": [{"id": "file:1", "fields": {"path": STAGED}}]},
            {"section": "files"},
        ),
    ]


def _report(marked: bool = True) -> MalwareReport:
    dynamic = dynamic_from_ledger(_ledger(marked)[:1])
    assert dynamic is not None
    report = rich_report()
    assert report.dynamic is not None
    report.dynamic.process_tree = dynamic.process_tree
    return report


def _asked(payload: dict[str, Any], marked: bool = True) -> list[v.Violation]:
    report = _report(marked)
    question = evidence_bundles.sandbox_start_question(
        report, v.EntryTexts.from_ledger(_ledger(marked))
    )
    return v.start_path_value_violations(payload, question)


def _config(value: str, *refs: str) -> dict[str, Any]:
    return {
        "items": [
            {
                "key": "Version",
                "value": "1.0",
                "how_obtained": "static-string",
                "evidence_refs": ["ev_0003"],
            },
            {
                "key": "Launch path",
                "value": value,
                "how_obtained": "observed",
                "evidence_refs": list(refs),
            },
        ]
    }


def _identifier(value: str, *refs: str) -> dict[str, Any]:
    return {"identifiers": [{"kind": "file path", "value": value, "evidence_refs": list(refs)}]}


class TestARowFromProcessRowsAlone:
    def test_a_configuration_row_citing_the_process_view_is_asked_with_the_fact(self) -> None:
        (found,) = _asked(_config(STAGED, "ev_0001"))
        assert found.code == v.SANDBOX_START_PATH_VALUE_CODE
        assert found.path == "items.1.value"
        assert found.statements == ("items.1",)
        assert STAGED_NOTE in found.message
        assert evidence_bundles.sandbox_start_facts(_report())[STAGED] in found.message
        assert "Launch path" in found.message

    def test_an_identifier_citing_the_view_and_the_links_command_line_is_asked(self) -> None:
        (found,) = _asked(_identifier(STAGED, "ev_0001", "ev_0002"))
        assert found.path == "identifiers.0.value"

    def test_the_command_line_as_the_value_is_asked(self) -> None:
        assert _asked(_identifier(f'"{STAGED}"', "ev_0002"))

    def test_the_item_reader_s_processes_are_process_rows(self) -> None:
        assert _asked(_config(STAGED, "ev_0004"))

    def test_the_path_in_another_spelling_is_the_path(self) -> None:
        assert _asked(_config(STAGED.lower().replace("\\", "/"), "ev_0001"))


class TestACitationIsReadInItsNormalForm:
    @pytest.mark.parametrize("cited", ["[ev_0001]", " EV_0001 ", "[ EV_0001 ]", "ev_0001:proc:10"])
    def test_a_citation_of_the_process_view_however_written_is_asked(self, cited: str) -> None:
        (found,) = _asked(_config(STAGED, cited))
        assert found.code == v.SANDBOX_START_PATH_VALUE_CODE

    def test_an_item_citation_of_another_entry_is_that_entry_s(self) -> None:
        assert _asked(_config(STAGED, "ev_0001:proc:10", "[ev_0003]")) == []

    def test_a_citation_of_an_item_alone_names_no_entry(self) -> None:
        assert _asked(_config(STAGED, "proc:10")) == []


class TestWhatIsNotAsked:
    def test_a_row_also_citing_an_entry_holding_the_path_otherwise_is_not_asked(self) -> None:
        assert _asked(_config(STAGED, "ev_0001", "ev_0003")) == []
        assert _asked(_config(STAGED, "ev_0001", "ev_0005")) == []

    def test_a_behaviour_link_also_observed_outside_the_processes_is_not_a_process_row(
        self,
    ) -> None:
        links = {
            "tool": bc.TOOL,
            "links": [
                {
                    "kind": "command line",
                    "value": f'"{STAGED}"',
                    "items": ["proc:10", "cmd:1"],
                    "held": [],
                }
            ],
        }
        ledger = [*_ledger(), _entry(6, "behaviour_code_links", links)]
        question = evidence_bundles.sandbox_start_question(
            _report(), v.EntryTexts.from_ledger(ledger)
        )
        assert v.start_path_value_violations(_config(STAGED, "ev_0006"), question) == []

    def test_a_row_citing_nothing_or_an_entry_the_run_did_not_issue_is_not_asked(self) -> None:
        assert _asked(_config(STAGED)) == []
        assert _asked(_config(STAGED, "ev_0099")) == []

    def test_a_row_of_another_process_s_path_is_not_asked(self) -> None:
        assert _asked(_config(CHILD, "ev_0001")) == []

    def test_a_report_with_no_marked_row_asks_nothing(self) -> None:
        assert evidence_bundles.sandbox_start_question(_report(marked=False), None) is None
        assert v.start_path_value_violations(_config(STAGED, "ev_0001"), None) == []


class TestTheWriterDecides:
    def test_the_check_drops_nothing_and_a_row_kept_after_it_stands(self) -> None:
        payload = _config(STAGED, "ev_0001")
        before = json.dumps(payload, sort_keys=True)
        assert _asked(payload)
        assert json.dumps(payload, sort_keys=True) == before
        assert v.SANDBOX_START_PATH_VALUE_CODE in v.KEPT_WITH_A_FINDING
