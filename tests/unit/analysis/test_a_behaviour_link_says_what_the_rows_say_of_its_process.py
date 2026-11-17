"""A behaviour link says what the sandbox's rows say of the process behind a value.

A row that names a process the report does not list (``process_not_listed``)
states a fact: the traffic is another process's, one the sandbox does not
follow. The link line and its table say so, with the process as the rows name
it, and never "process not attributed" for a value whose rows state that fact.
A row of the sample's tree still decides, and a value whose rows name no
process at all is still not attributed.
"""

from __future__ import annotations

from typing import Any

from tests.unit.analysis.test_observed_behaviour_is_linked_to_code import (
    _entry,
    _link,
    _report,
    _strings,
)

from malspark.analysis import behaviour_code as bc
from malspark.pipeline.triage_pack import render_pack
from malspark.reporting.ledger_report import BEHAVIOUR_CODE_SECTION, build_sections

ADDRESS = "192.0.2.7"
HOST = "crl.example.test"
# A flow row naming a process the task does not list, as the reader writes one.
UNLISTED_ROW = {"platform_process": "46", "process_not_listed": True}
UNLISTED_WORDS = "a process the report does not list (procid 46)"


def _network(**kinds: Any) -> dict[str, Any]:
    report = _report()
    report["network"] = kinds
    return report


def _strings_of(*texts: str) -> bc.StaticInputs:
    rows = [{"offset": 0x10 * (i + 1), "enc": "ascii", "text": t} for i, t in enumerate(texts)]
    return bc.StaticInputs(strings=[("ev_0004", "strings", _strings(*rows))])


def _line_and_cells(answer: dict[str, Any]) -> tuple[str, list[str]]:
    entry = _entry(bc.TOOL, answer, 8)
    table = next(s for s in build_sections([entry]) if s.key == BEHAVIOUR_CODE_SECTION)
    return render_pack([entry], 0), [row[2] for row in table.rows]


class TestAProcessTheReportDoesNotList:
    def test_every_row_naming_one_says_so_and_the_value_stays_linked(self) -> None:
        report = _network(tcp=[{"dst": ADDRESS, **UNLISTED_ROW}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS))
        link = _link(answer, ADDRESS)
        assert link["attribution"] != bc.NOT_ATTRIBUTED
        assert UNLISTED_WORDS in link["attribution"]
        line, cells = _line_and_cells(answer)
        assert bc.NOT_ATTRIBUTED not in line
        assert f"(net:1; {link['attribution']})" in line
        assert f"net:1 ({link['attribution']})" in cells

    def test_a_row_naming_no_process_beside_them_does_not_make_it_unattributed(self) -> None:
        report = _network(
            dns=[{"request": HOST, "type": "A"}],
            http=[{"host": HOST, "uri": "/r.crl", **UNLISTED_ROW}],
        )
        answer = bc.link_behaviour_to_code(report, None, _strings_of(HOST))
        link = _link(answer, HOST)
        assert UNLISTED_WORDS in link["attribution"]
        line, _cells = _line_and_cells(answer)
        assert bc.NOT_ATTRIBUTED not in line

    def test_each_process_the_rows_name_is_named_once(self) -> None:
        report = _network(
            tcp=[
                {"dst": ADDRESS, **UNLISTED_ROW},
                {"dst": ADDRESS, **UNLISTED_ROW},
                {"dst": ADDRESS, "platform_process": "36", "process_not_listed": True},
            ]
        )
        link = _link(bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS)), ADDRESS)
        assert link["attribution"].count("procid 46") == 1
        assert "procid 36" in link["attribution"]

    def test_a_request_one_of_whose_flows_names_no_process_is_not_called_unlisted(self) -> None:
        flows = [UNLISTED_ROW, {}]
        report = _network(http=[{"host": HOST, "uri": "/r.crl", "platform_flows": flows}])
        link = _link(bc.link_behaviour_to_code(report, None, _strings_of(HOST)), HOST)
        assert link["attribution"] == bc.NOT_ATTRIBUTED


class TestWhatStaysAsItWas:
    def test_a_row_of_the_sample_s_tree_still_decides(self) -> None:
        report = _network(
            tcp=[{"dst": ADDRESS, **UNLISTED_ROW}, {"dst": ADDRESS, "sample_process_tree": True}]
        )
        link = _link(bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS)), ADDRESS)
        assert link["attribution"] == bc.SAMPLE_TREE

    def test_a_value_whose_rows_name_no_process_is_still_not_attributed(self) -> None:
        report = _network(tcp=[{"dst": ADDRESS}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS))
        assert _link(answer, ADDRESS)["attribution"] == bc.NOT_ATTRIBUTED
        line, cells = _line_and_cells(answer)
        assert f"(net:1; {bc.NOT_ATTRIBUTED})" in line
        assert f"net:1 ({bc.NOT_ATTRIBUTED})" in cells

    def test_a_value_only_a_listed_process_outside_the_tree_made_is_still_not_linked(
        self,
    ) -> None:
        report = _network(tcp=[{"dst": ADDRESS, "sample_process_tree": False}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS))
        assert all(row["value"] != ADDRESS for row in answer["links"])
        assert answer["not_linked"] == {"other processes": 1}
