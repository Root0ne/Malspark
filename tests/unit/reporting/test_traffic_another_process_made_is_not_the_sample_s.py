"""A name, a URL or an address another process made traffic to is not published as the sample's.

A DNS or HTTP request a sandbox records names no process of its own; it rides
on a flow that does. The request takes the flow's process facts, and one rule
decides the three kinds: where the report names the process that made the
traffic and that process is not of the sample's lineage (a process outside its
tree, the launcher's, or one the report does not list among the task's
processes), the value is not published as observed from the sample, and the
answer says whose it is. Where the report names no process, the value is
decided as it is without one; where the sample's tree made it, it is published.

The live reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission; their DNS and HTTP requests are the guest's
own certificate-revocation traffic, made by processes the report does not list.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_network
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers.stix_renderer import (
    ExtendedSTIXRenderer,
    emulation_kwargs,
    publish_answer,
    publishes,
)
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import SandboxReport, attribute_the_launcher

LIVE = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox" / "triage_live"
SHA256 = "a" * 64
CRL = "http://c.pki.goog/r/r1.crl"
HOST = "c.pki.goog"
LAUNCHER = {
    "sample_member": "cmd.exe",
    "launcher_member": "launch.ps1",
    "script_host_images": ["powershell.exe", "pwsh.exe"],
    "launcher_sha256": "aba6bd87cb5e4c8d594551ce5194d6a120ca721d85d766c0317598e0b5754a6e",
    "sample_sha256": "",
}


def _json(name: str) -> Any:
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


def _sandbox(task: dict[str, Any], launcher: dict[str, Any] | None = None) -> SandboxReport:
    report = required_reader("triage").read(
        _json("overview.json"), provider="triage", task_id="s1", task_reports={"behavioral1": task}
    )
    if launcher:
        attribute_the_launcher(report, launcher)
    return report


def _report(sandbox: SandboxReport) -> MalwareReport:
    view = sandbox_network(sandbox_document(sandbox))
    ledger = [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps(view),
        )
    ]
    report = MalwareReportBuilder(
        file_hash=SHA256,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        sample_platform="windows",
        sample_file_type="pe",
        evidence_ledger=ledger,
    ).build_deterministic()
    report.network = network_from_ledger(ledger)
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _patterns(report: MalwareReport) -> list[str]:
    return [str(getattr(o, "pattern", "")) for o in ExtendedSTIXRenderer().render(report).objects]


def _answer(report: MalwareReport, kind: str, value: str) -> str:
    return publish_answer(kind, value, "sandbox", None, **emulation_kwargs(report, kind, value))


def _with_flows(**procids: Any) -> dict[str, Any]:
    """The live task with each flow's process replaced (``flow_<id>=procid``, None for none)."""
    task = _json("behavioral1.json")
    for flow in task["network"]["flows"]:
        key = f"flow_{flow['id']}"
        if key in procids:
            if procids[key] is None:
                flow.pop("procid", None)
                flow.pop("pid", None)
            else:
                flow["procid"] = procids[key]
    return task


class TestTheLiveReport:
    def test_the_revocation_list_url_and_its_host_are_not_the_sample_s(self) -> None:
        report = _report(_sandbox(_json("behavioral1.json")))
        patterns = _patterns(report)
        assert not any(HOST in p for p in patterns)
        url = _answer(report, "url", CRL)
        assert url.startswith(
            "no: the sandbox report says it was made by a process the report does not list "
            "(procid 46)"
        )
        host = _answer(report, "domain", HOST)
        assert host.startswith(
            "no: the sandbox report says it was made by a process the report does not list "
            "(procid 36, procid 46)"
        )
        # The rows stay, as recorded, with whose they are.
        (domain,) = [d for d in report.network.domains if d.fqdn == HOST]
        assert domain.sample_process_tree is False
        assert domain.made_by is not None and domain.made_by.unlisted == ["procid 36", "procid 46"]
        (table_row,) = [i for i in report.consolidated_iocs if i.value == CRL]
        assert table_row.published == url

    def test_the_address_names_the_process_the_report_does_not_list(self) -> None:
        report = _report(_sandbox(_json("behavioral1.json")))
        assert _answer(report, "ip", "172.217.76.94").startswith(
            "no: the sandbox report says it was made by a process the report does not list "
            "(procid 46)"
        )


class TestAFlowOfTheStartedProgram:
    def test_publishes_its_requests(self) -> None:
        # cmd.exe (procid 86), marked as the sample's by the sandbox, made both flows.
        report = _report(_sandbox(_with_flows(flow_31=86, flow_32=86)))
        assert publishes(_answer(report, "url", CRL))
        assert f"[url:value = '{CRL}']" in _patterns(report)
        (domain,) = [d for d in report.network.domains if d.fqdn == HOST]
        assert domain.sample_process_tree is True and domain.made_by is None


class TestTheLauncherSFlow:
    def test_says_it_is_the_launcher_s(self) -> None:
        report = _report(_sandbox(_with_flows(flow_31=84, flow_32=84), LAUNCHER))
        assert _answer(report, "url", CRL).startswith(
            "no: the sandbox report says it was made by the launcher's process "
            "(powershell.exe (procid 84))"
        )
        assert not any(HOST in p for p in _patterns(report))


class TestAReportNamingNoProcess:
    def test_decides_as_without_a_process(self) -> None:
        report = _report(_sandbox(_with_flows(flow_31=None, flow_32=None)))
        (domain,) = [d for d in report.network.domains if d.fqdn == HOST]
        assert domain.sample_process_tree is None and domain.made_by is None
        assert publishes(_answer(report, "url", CRL))
        assert f"[url:value = '{CRL}']" in _patterns(report)
        # Stored without the new facts, the row dumps as it did.
        assert "made_by" not in domain.model_dump()
        assert "sample_process_tree" not in domain.model_dump()
