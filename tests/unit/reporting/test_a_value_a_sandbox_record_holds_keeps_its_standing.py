"""A value only sandbox records hold keeps an analyst's standing; a printed string does not.

A sighting gives a listed value the string sweep's standing (``strings``) only
where a text-printing tool's answer holds it: the file's strings, a decoder's
output, a decompilation. An entry of a sandbox kind is a record of the
detonation (``evidence_bundles.SANDBOX_TOOL_PREFIXES``), not such a holder: a
value an analyst listed that only such entries hold keeps the analyst's
standing, and with it the decision it has where no answer holds it (the
judge's keep), and the reason still names where it was seen. The entry's kind
decides, never its tool's name.

Every value here is synthetic: routable addresses the reference run never
reached, and example names.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.renderers.stix_renderer import publishes
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, Artifact

NAME = "relay-alpha-7f3c.top"
ADDRESS = "185.199.110.77"


def _entry(entry_id: str, tool: str, structured: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="dynamic", tool=tool, structured=structured)


def _indicator_entry(entry_id: str = "ev_0007") -> LedgerEntry:
    """A signatures answer whose only mention of the values is one indicator's."""
    return _entry(
        entry_id,
        "sandbox_signatures",
        {
            "signatures": [{"name": "Contacts a host", "indicators": 1}],
            "total": 1,
            "indicators": [
                {
                    "signature": "Contacts a host",
                    "process": {"id": "84", "image": "powershell.exe"},
                    "values": {"domain": NAME, "dst": ADDRESS},
                }
            ],
        },
    )


def _strings_entry() -> LedgerEntry:
    """The file's strings, printing the name."""
    return _entry("ev_0002", "strings", {"strings": [{"offset": "0x40", "string": NAME}]})


def _kept() -> dict[str, Any]:
    patterns = [f"[domain-name:value = '{NAME}']", f"[ipv4-addr:value = '{ADDRESS}']"]
    return {
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--0f1e2d3c-4b5a-4968-8776-65544333221{i}",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": "2026-01-01T00:00:00Z",
            }
            for i, pattern in enumerate(patterns)
        ]
    }


def _listed() -> dict[str, Any]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            artifacts=[
                Artifact(
                    kind="endpoints",
                    rows=[["domain", NAME], ["ip", ADDRESS]],
                    evidence_ids=[],
                    source="static",
                )
            ],
        )
    }


def _build(ledger: list[LedgerEntry]) -> Any:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=_listed(),
        stix_output=_kept(),
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=ledger,
    ).build_deterministic()


def _published(report: Any, value: str) -> str:
    (row,) = [r for r in report.consolidated_iocs if r.value == value]
    return str(row.published)


def _sources(report: Any) -> dict[str, str]:
    network = report.network
    assert network is not None
    return {
        **{d.fqdn: d.source for d in network.domains},
        **{i.address: i.source for i in network.ips},
    }


def _signatures_answer() -> dict[str, Any]:
    """The signature view's answer over a report whose marks alone name the two values."""
    from malspark.providers.sandbox.readers import required_reader
    from malspark.providers.sandbox_tools import sandbox_signatures
    from malspark.schemas.sandbox_document import sandbox_document

    payload = {
        "info": {"id": 7},
        "behavior": {"processes": [{"process_id": 1000, "parent_id": 4, "process_name": "a.exe"}]},
        "signatures": [
            {
                "name": "network_contact",
                "severity": 2,
                "description": "Contacts a host",
                "data": [
                    {"type": "ioc", "pid": 1000, "category": "domain", "ioc": NAME},
                    {"type": "ioc", "pid": 1000, "category": "ip", "ioc": ADDRESS},
                ],
            }
        ],
    }
    report = required_reader("cape2").read(payload, provider="cape")
    answer: dict[str, Any] = sandbox_signatures(
        sandbox_document(report), normalised_by=("cape", "cape2")
    )
    return answer


class TestTheSignatureView:
    """The view's own answer, as the ledger records it: decided as where no answer holds them."""

    def test_values_its_indicators_alone_hold_are_published_on_the_judge_s_keep(self) -> None:
        report = _build([_entry("ev_0007", "sandbox_signatures", _signatures_answer())])

        assert _sources(report) == {NAME: "analyst", ADDRESS: "analyst"}
        for value in (NAME, ADDRESS):
            assert publishes(_published(report, value)), value


class TestAValueOnlyASandboxRecordHolds:
    def test_it_keeps_the_analyst_s_standing_and_the_judge_s_keep_publishes_it(self) -> None:
        report = _build([_indicator_entry()])

        assert _sources(report) == {NAME: "analyst", ADDRESS: "analyst"}
        for value in (NAME, ADDRESS):
            assert publishes(_published(report, value)), value

    def test_it_decides_as_a_value_no_answer_holds(self) -> None:
        held = _build([_indicator_entry()])
        unheld = _build([])

        for value in (NAME, ADDRESS):
            assert _published(held, value) == _published(unheld, value), value

    def test_the_search_still_names_the_entry_that_holds_it(self) -> None:
        report = _build([_indicator_entry()])

        assert report.tool_sightings[NAME] == [("ev_0007", "sandbox_signatures")]


class TestAValueATextPrintingToolPrinted:
    def test_it_is_a_string_sighting(self) -> None:
        report = _build([_strings_entry()])

        assert _sources(report)[NAME] == "strings"
        assert not publishes(_published(report, NAME))

    def test_it_is_one_beside_a_sandbox_record_too(self) -> None:
        report = _build([_strings_entry(), _indicator_entry()])

        assert _sources(report) == {NAME: "strings", ADDRESS: "analyst"}
        assert _published(report, NAME).startswith("no: seen only in the text of ev_0002 (strings)")
