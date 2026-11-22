"""A value an analyst listed stands on the tool whose answer holds it; the search is said as run.

One run's endpoints artifact listed sixteen addresses the capture's conversations
held, and the rule told each of them "no tool in this run saw it": the network
block never read the capture. The capture's conversations and TLS names are now
sandbox rows the sandbox rule decides, and a value an analyst listed is looked
for, whole, in every tool answer of the run that did not fail. Found, the row
takes that answer's source and the reason names the entry; the reason says what
the publish rule's whole-value search read and what it found, never that no tool
saw the value. A stored report, built before the search existed, is searched in
the tool sections it keeps, and says only what that search can.

Every value here is synthetic: routable addresses the reference run never reached, and
example names. A documentation address would be refused by the address rule before
the question here is asked.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.models import (
    EvidenceSection,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
)
from malspark.reporting.renderers.stix_renderer import emulation_kwargs, publish_answer
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, Artifact

CAPTURED = "185.199.110.61"
DECOMPILED = "185.199.110.62"
NOWHERE = "185.199.110.63"
TLS_NAME = "relay-alpha-7f3c.top"


def _capture() -> LedgerEntry:
    return LedgerEntry(
        id="ev_0001",
        agent="pipeline",
        tool="pcap_summary",
        structured={
            "conversations": [{"dst": CAPTURED, "dport": 443, "proto": "tcp", "bytes": 10}],
            "sni": {TLS_NAME: 2},
            "empty": False,
        },
    )


def _decompile() -> LedgerEntry:
    text = f'connect(sock, "{DECOMPILED}", 443);'
    return LedgerEntry(
        id="ev_0002",
        agent="reverser",
        tool="decompile_function",
        output=text,
        structured={"code": text},
    )


def _listed(*addresses: str) -> dict[str, Any]:
    return {
        "network": AgentISR(
            agent_id="network",
            domain="network",
            artifacts=[
                Artifact(
                    kind="endpoints",
                    rows=[["ip", address] for address in addresses],
                    evidence_ids=[],
                    source="network",
                )
            ],
        )
    }


def _build(ledger: list[LedgerEntry], isrs: dict[str, Any]) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=isrs,
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=ledger,
    ).build_deterministic()


def _published(report: MalwareReport, value: str) -> str:
    (row,) = [r for r in report.consolidated_iocs if r.value == value]
    return str(row.published)


class TestTheCaptureIsASandboxView:
    def test_a_conversation_is_an_unattributed_sandbox_row(self) -> None:
        report = _build([_capture()], {})

        assert report.network is not None
        (ip,) = report.network.ips
        assert (ip.address, ip.source, ip.sample_process_tree) == (CAPTURED, "sandbox", None)
        # No network view was read; the capture recorded a conversation with it (T-842).
        assert _published(report, CAPTURED).startswith(
            "no: the publish rule read no network view of the sandbox while the capture recorded "
            "a conversation with it"
        )

    def test_a_tls_name_is_a_name_the_sandbox_saw(self) -> None:
        report = _build([_capture()], {})

        assert report.network is not None
        assert [(d.fqdn, d.source) for d in report.network.domains] == [(TLS_NAME, "sandbox")]

    def test_an_address_an_artifact_lists_that_the_capture_holds_is_the_sandbox_s(self) -> None:
        answer = _published(_build([_capture()], _listed(CAPTURED)), CAPTURED)

        # The judge's test refuses it beside the sandbox's fact; the listing is a fact (T-782b).
        assert answer.startswith(
            "no: the publish rule read no network view of the sandbox while the capture recorded "
            "a conversation with it, and the judge did not keep it as an indicator; an artifact "
            "of the network analyst lists it"
        )
        assert "named only" not in answer


class TestAListedValueIsLookedForInEveryToolAnswer:
    def test_a_value_a_decompile_holds_is_answered_as_that_answer_s_and_names_it(self) -> None:
        report = _build([_capture(), _decompile()], _listed(DECOMPILED))

        assert report.network is not None
        (row,) = [ip for ip in report.network.ips if ip.address == DECOMPILED]
        assert row.source == "strings"
        answer = _published(report, DECOMPILED)
        assert answer == (
            "no: its row's source is strings and no row of the string sweep holds it and the "
            "publish rule found no recovery of it and read no reputation record for it; the "
            "publish rule's whole-value search of the kept text of the run's successful tool "
            "answers, which sets apart an answer to a call whose arguments hold it, found it in "
            "ev_0002 (decompile_function); an artifact of the network analyst lists it"
        )

    def test_a_value_the_search_finds_in_no_answer_is_refused_as_an_analyst_s_listing(
        self,
    ) -> None:
        answer = _published(_build([_capture(), _decompile()], _listed(NOWHERE)), NOWHERE)

        assert answer == (
            "no: its row is an analyst's listing (an artifact of the network analyst) and the "
            "publish rule takes no listing as a source, and the judge did not keep it as an "
            "indicator; the publish rule's whole-value search of the kept text of the run's "
            "successful tool answers, which sets apart an answer to a call whose arguments hold "
            "it, found it in none"
        )


def _stored(sections: list[EvidenceSection]) -> MalwareReport:
    """A report stored before the search existed: an analyst row, and no sightings recorded."""
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        overall_confidence=0.8,
        network=NetworkIOCs(
            domains=[
                NetworkDomain(
                    fqdn=TLS_NAME, source="analyst", kept_by=["an artifact of the network analyst"]
                )
            ]
        ),
        sections=sections,
    )


def _stored_answer(report: MalwareReport) -> str:
    return publish_answer(
        "domain", TLS_NAME, "analyst", None, **emulation_kwargs(report, "domain", TLS_NAME)
    )


class TestAStoredReport:
    def test_a_value_its_kept_tool_section_holds_is_answered_as_that_tool_s(self) -> None:
        section = EvidenceSection(
            key="iocs",
            title="IOCs",
            kind="table",
            columns=["Kind", "Value"],
            rows=[["domain", TLS_NAME]],
            evidence_ids=["ev_0006"],
            source="tool:iocs_from_file",
        )

        answer = _stored_answer(_stored([section]))

        assert answer == (
            "no: its row is an analyst's listing (an artifact of the network analyst) and the "
            "publish rule takes no listing as a source, and the judge did not keep it as an "
            "indicator; the publish rule's whole-value search of the tool sections this report "
            "keeps found it in ev_0006 (iocs_from_file)"
        )

    def test_a_value_no_kept_section_holds_says_only_what_the_report_can(self) -> None:
        answer = _stored_answer(_stored([]))

        assert answer == (
            "no: its row is an analyst's listing (an artifact of the network analyst) and the "
            "publish rule takes no listing as a source, and the judge did not keep it as an "
            "indicator; this report keeps no tool section for the publish rule's search to read"
        )
        assert "kept text of the run's" not in answer and "found it" not in answer
