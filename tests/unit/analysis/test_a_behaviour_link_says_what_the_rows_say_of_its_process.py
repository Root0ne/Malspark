"""A behaviour link says what the sandbox's rows say of the process behind a value.

A row that names a process the report does not list (``process_not_listed``)
states a fact: the traffic is another process's, one the sandbox does not
follow. Whether a value's traffic is such a process's is the publish rule's
decision (``stix_renderer.unlisted_reasons``), read over the report's network
block, not a second precedence of the links' own: where the rule puts it on
an unlisted process, the link line and its table say so in the rule's words,
and never "process not attributed"; where a row of the value names no process
and the rule says the report does not say, the link is not attributed, as the
capture line and the rule say. A row of the sample's tree still decides, and
the publish rule's own sentences are unchanged.
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.unit.analysis.test_observed_behaviour_is_linked_to_code import (
    _entry,
    _link,
    _report,
    _strings,
)

from malspark.analysis import behaviour_code as bc
from malspark.pipeline.triage_pack import render_pack
from malspark.providers.sandbox_tools import read_view
from malspark.reporting import ledger_projection
from malspark.reporting.ledger_report import BEHAVIOUR_CODE_SECTION, build_sections
from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import stix_renderer as sr

ADDRESS = "192.0.2.7"
HOST = "crl.example.test"
# A flow row naming a process the task does not list, as the reader writes one.
UNLISTED_ROW = {"platform_process": "46", "process_not_listed": True}
UNLISTED_WORDS = "a process the report does not list (procid 46)"
# What the rule read in an unlisted flow beside one naming no process.
UNLISTED_AND_NONE = (
    "the publish rule found a flow to it made by a process the report does not list "
    "(platform_process 46) and read no process id from its other flow"
)
# Every flow to the address named by a process the report does not list.
UNLISTED_ONLY = "the publish rule found a flow to it made by " + UNLISTED_WORDS
# A row that carries no reading of its flow rows: the rule states no count of them.
UNLISTED_COUNTED = "the publish rule counted its flows as made by " + UNLISTED_WORDS


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

    def test_a_dns_request_naming_no_process_does_not_unsay_the_request_s_process(
        self,
    ) -> None:
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


def _publish_rule(report: dict[str, Any], address: str) -> str:
    """The publish rule's sentence for an address of the report's network block."""
    network = ledger_projection.network_from_sandbox_report(report, None)
    assert network is not None
    row = next(ip for ip in network.ips if ip.address == address)
    return sr.address_flow_reason(row)


def _capture_words(report: dict[str, Any], address: str) -> str:
    """What the capture line says of an address beside the report's network view."""
    view = read_view("sandbox_network", report, None)
    entry = _entry("sandbox_network", view, 3)
    facts = ledger_projection.address_flow_facts([entry], normalised_by=None)
    assert facts is not None
    return facts(address)[1]


class TestOneDecisionWithThePublishRule:
    def test_an_unlisted_row_beside_one_naming_none_is_not_attributed_on_both_lines(
        self,
    ) -> None:
        report = _network(tcp=[{"dst": ADDRESS, **UNLISTED_ROW}, {"dst": ADDRESS}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS))
        assert _link(answer, ADDRESS)["attribution"] == bc.NOT_ATTRIBUTED
        assert _publish_rule(report, ADDRESS) == UNLISTED_AND_NONE
        assert _capture_words(report, ADDRESS) == UNLISTED_AND_NONE
        line, _cells = _line_and_cells(answer)
        assert UNLISTED_AND_NONE not in line

    def test_an_unlisted_row_beside_one_of_a_listed_process_is_not_called_unlisted(
        self,
    ) -> None:
        report = _network(
            tcp=[{"dst": ADDRESS, **UNLISTED_ROW}, {"dst": ADDRESS, "sample_process_tree": False}]
        )
        answer = bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS))
        assert _link(answer, ADDRESS)["attribution"] == bc.NOT_ATTRIBUTED
        assert _publish_rule(report, ADDRESS) == (
            "the publish rule found flows to it made by a process outside the sample's process "
            "tree and by a process the report does not list (platform_process 46)"
        )

    def test_every_row_unlisted_is_worded_as_the_publish_rule_on_both_lines(self) -> None:
        report = _network(tcp=[{"dst": ADDRESS, **UNLISTED_ROW}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS))
        said = _publish_rule(report, ADDRESS)
        assert said == UNLISTED_ONLY
        assert _link(answer, ADDRESS)["attribution"] == said
        assert _capture_words(report, ADDRESS) == said

    def test_a_name_whose_requests_all_name_an_unlisted_process_takes_the_rule_s_words(
        self,
    ) -> None:
        report = _network(http=[{"host": HOST, "uri": "/r.crl", **UNLISTED_ROW}])
        network = ledger_projection.network_from_sandbox_report(report, None)
        assert network is not None
        row = next(d for d in network.domains if d.fqdn == HOST)
        answer = bc.link_behaviour_to_code(report, None, _strings_of(HOST))
        assert _link(answer, HOST)["attribution"] == sr.name_made_by_reason(row.made_by)
        assert _link(answer, HOST)["attribution"] == (
            "the publish rule counted its requests as made by a process the report does not "
            "list (procid 46)"
        )

    def test_a_request_one_of_two_naming_no_process_is_not_attributed(self) -> None:
        report = _network(
            http=[
                {"host": HOST, "uri": "/r.crl", **UNLISTED_ROW},
                {"host": HOST, "uri": "/s.crl"},
            ]
        )
        answer = bc.link_behaviour_to_code(report, None, _strings_of(HOST))
        assert _link(answer, HOST)["attribution"] == bc.NOT_ATTRIBUTED


URL = f"http://{ADDRESS}/x"
PATH = "/x"


def _publish_rule_of_the_url(report: dict[str, Any]) -> str | None:
    """The publish rule's sentence for the request's URL, which its host's row decides."""
    network = ledger_projection.network_from_sandbox_report(report, None)
    held = MalwareReport.model_construct(network=network)
    return sr.sandbox_row_kwargs(held, "url", URL).get("unattributed")


class TestAValueAtAnAddressTakesTheAddressRow:
    """A URL whose host is an address, and a request's path or agent at one, take its row."""

    @pytest.mark.parametrize(
        ("request_row", "value"),
        [({"uri": URL}, URL), ({"host": ADDRESS, "uri": PATH}, PATH)],
        ids=["url", "path"],
    )
    def test_an_unlisted_request_to_an_address_not_put_on_it_is_not_attributed(
        self, request_row: dict[str, Any], value: str
    ) -> None:
        report = _network(
            http=[{**request_row, "dst": ADDRESS, **UNLISTED_ROW}],
            tcp=[{"dst": ADDRESS, **UNLISTED_ROW}, {"dst": ADDRESS}],
        )
        answer = bc.link_behaviour_to_code(report, None, _strings_of(value, ADDRESS))
        assert _publish_rule_of_the_url(report) == UNLISTED_AND_NONE
        assert _capture_words(report, ADDRESS) == UNLISTED_AND_NONE
        assert _link(answer, value)["attribution"] == bc.NOT_ATTRIBUTED
        assert _link(answer, ADDRESS)["attribution"] == bc.NOT_ATTRIBUTED
        line, _cells = _line_and_cells(answer)
        assert UNLISTED_WORDS not in line

    @pytest.mark.parametrize(
        ("request_row", "value"),
        [({"uri": URL}, URL), ({"host": ADDRESS, "uri": PATH}, PATH)],
        ids=["url", "path"],
    )
    def test_a_request_to_an_address_put_on_an_unlisted_process_says_so(
        self, request_row: dict[str, Any], value: str
    ) -> None:
        report = _network(
            http=[{**request_row, "dst": ADDRESS}], tcp=[{"dst": ADDRESS, **UNLISTED_ROW}]
        )
        answer = bc.link_behaviour_to_code(report, None, _strings_of(value, ADDRESS))
        said = _publish_rule_of_the_url(report)
        assert said == UNLISTED_ONLY
        assert _capture_words(report, ADDRESS) == said
        assert _link(answer, value)["attribution"] == said
        assert _link(answer, ADDRESS)["attribution"] == said

    def test_an_address_with_no_row_puts_nothing_on_an_unlisted_process(self) -> None:
        report = _network(http=[{"uri": URL, "dst": ADDRESS, **UNLISTED_ROW}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of(URL, ADDRESS))
        assert _publish_rule_of_the_url(report) is None
        assert _link(answer, URL)["attribution"] == bc.NOT_ATTRIBUTED
        assert _link(answer, ADDRESS)["attribution"] == bc.NOT_ATTRIBUTED

    def test_an_address_with_no_row_is_not_read_by_a_request_to_a_name(self) -> None:
        report = _network(http=[{"host": HOST, "uri": PATH, "dst": ADDRESS, **UNLISTED_ROW}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of(ADDRESS))
        network = ledger_projection.network_from_sandbox_report(report, None)
        assert network is not None and all(ip.address != ADDRESS for ip in network.ips)
        assert _link(answer, ADDRESS)["attribution"] == bc.NOT_ATTRIBUTED

    def test_a_value_only_listed_processes_made_stays_unlinked_whatever_its_address_says(
        self,
    ) -> None:
        report = _network(
            http=[{"uri": URL, "dst": ADDRESS, "sample_process_tree": False}],
            tcp=[{"dst": ADDRESS, **UNLISTED_ROW}],
        )
        answer = bc.link_behaviour_to_code(report, None, _strings_of(URL, ADDRESS))
        assert all(row["value"] != URL for row in answer["links"])
        assert _link(answer, ADDRESS)["attribution"] == UNLISTED_ONLY

    def test_an_address_written_with_a_port_takes_its_address_row(self) -> None:
        written = f"{ADDRESS}:8080"
        report = _network(
            http=[{"host": written, "uri": PATH, "dst": ADDRESS, "user_agent": "Agent/9.9"}],
            tcp=[{"dst": ADDRESS, **UNLISTED_ROW}],
        )
        answer = bc.link_behaviour_to_code(report, None, _strings_of(written, PATH, "Agent/9.9"))
        said = UNLISTED_ONLY
        assert _capture_words(report, ADDRESS) == said
        for value in (written, PATH, "Agent/9.9"):
            assert _link(answer, value)["attribution"] == said, value

    @pytest.mark.parametrize(
        ("name_row", "expected"),
        [({}, bc.NOT_ATTRIBUTED), (UNLISTED_ROW, UNLISTED_WORDS)],
        ids=["the name's request names no process", "both requests name the process"],
    )
    def test_a_path_requested_from_an_address_and_a_name_takes_one_decision_of_both(
        self, name_row: dict[str, Any], expected: str
    ) -> None:
        other = "198.51.100.9"
        report = _network(
            http=[
                {"host": ADDRESS, "uri": "/p", "dst": ADDRESS},
                {"host": "evil.example", "uri": "/p", "dst": other, **name_row},
            ],
            tcp=[{"dst": ADDRESS, **UNLISTED_ROW}, {"dst": other}],
        )
        answer = bc.link_behaviour_to_code(report, None, _strings_of("/p"))
        assert _link(answer, "/p")["attribution"].endswith(expected)

    def test_the_rule_s_decisions_key_the_url_by_its_address_row(self) -> None:
        report = _network(
            http=[{"uri": URL, "dst": ADDRESS, **UNLISTED_ROW}],
            tcp=[{"dst": ADDRESS, **UNLISTED_ROW}, {"dst": ADDRESS}],
        )
        network = ledger_projection.network_from_sandbox_report(report, None)
        assert ("url", URL) not in sr.unlisted_reasons(network)


class TestThePublishRuleIsUnchanged:
    @pytest.mark.parametrize(
        ("row", "said"),
        [
            ({"sample_process_tree": None}, sr.FLOW_NOT_PLACED),
            (
                {"sample_process_tree": False},
                "the publish rule counted its flows as made by a process outside the sample's "
                "process tree",
            ),
            (
                {"sample_process_tree": False, "outside_processes": ["x.exe (procid 7)"]},
                "the publish rule counted its flows as made by a process outside the sample's "
                "process tree (x.exe (procid 7))",
            ),
            (
                {"sample_process_tree": None, "unlisted_processes": ["procid 46"]},
                UNLISTED_COUNTED,
            ),
            (
                {"sample_process_tree": False, "unlisted_processes": ["procid 46"]},
                "the publish rule counted its flows as made by a process outside the sample's "
                "process tree",
            ),
            (
                {
                    "sample_process_tree": None,
                    "unlisted_processes": ["procid 46"],
                    "marked_only_processes": ["m.exe"],
                },
                sr.disputed_flow_reason(["m.exe"], []),
            ),
            (
                {"sample_process_tree": None, "launcher_unsettled_processes": ["w.exe"]},
                "the publish rule counted its flows as made by a script host naming the "
                "launcher, whose attribution is not established (w.exe)",
            ),
            (
                {
                    "sample_process_tree": None,
                    "launcher_unsettled_processes": ["w.exe"],
                    "unlisted_processes": ["procid 46"],
                },
                UNLISTED_COUNTED,
            ),
        ],
    )
    def test_each_reason_is_the_rule_s_sentence(self, row: dict[str, Any], said: str) -> None:
        assert sr.address_flow_reason(row) == said

    @pytest.mark.parametrize(
        ("rows", "unlisted"),
        [
            ([UNLISTED_ROW], ["procid 46"]),
            ([UNLISTED_ROW, {}], []),
            ([UNLISTED_ROW, {"sample_process_tree": False}], []),
            ([UNLISTED_ROW, {"sample_process_tree": True}], []),
            ([UNLISTED_ROW, {"platform_process": "36", "process_not_listed": True}], None),
        ],
    )
    def test_the_rule_s_unlisted_decision_over_rows(
        self, rows: list[dict[str, Any]], unlisted: list[str] | None
    ) -> None:
        report = _network(tcp=[{"dst": ADDRESS, **row} for row in rows])
        network = ledger_projection.network_from_sandbox_report(report, None)
        assert network is not None
        (row,) = [ip for ip in network.ips if ip.address == ADDRESS]
        expected = ["procid 46", "procid 36"] if unlisted is None else unlisted
        assert list(row.unlisted_processes or []) == expected
