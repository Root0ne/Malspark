"""Built runs with a further detonation launched with arguments, for the launch-echo tests.

Every value is invented. A run is a ledger: the platform's reads of the job's
own detonation (``d1``), of each further detonation (``platform_reads``, its
answer stating the launch text), the request that asked for it (its call
given the launch text) and any static entry a test adds; the report is built
from it as the report node builds one, and the analysis's identifier rows are
checked against the entries as the composer checks them.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.analysis.detonation_reads import later_detonation_name
from malspark.pipeline.detonations import platform_reads
from malspark.pipeline.validation import EntryTexts
from malspark.providers.detonation import DetonationRecord
from malspark.providers.sandbox_tools import read_view
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.models import (
    ConsolidatedIOC,
    HostIdentifier,
    JudgeIndicator,
    MalwareReport,
    TechnicalAnalysis,
)
from malspark.reporting.stated_host_values import identifier_answers, with_held_in
from malspark.schemas.evidence import LedgerEntry

SHA256 = "c" * 64
# The job's own detonation: one process, run with no arguments.
D1_PLAIN: dict[str, Any] = {
    "behavior": {
        "processes": [{"pid": 4, "ppid": 1, "process_name": "x.exe", "command_line": "x.exe"}]
    },
    "network": {"dns": [{"request": "cdn.example.org", "type": "A"}]},
}


class _Container:
    event_sink = None
    detonations: list[Any] = []


def own_reads(report: dict[str, Any] | None = None, start: int = 2) -> list[LedgerEntry]:
    """The pack's reads of the job's own detonation."""
    held = report if report is not None else D1_PLAIN
    out = []
    for n, tool in enumerate(("sandbox_processes", "sandbox_network", "sandbox_dropped_files")):
        view = read_view(tool, held, None)
        out.append(
            LedgerEntry(
                id=f"ev_{start + n:04d}",
                tool=tool,
                agent="pipeline",
                source="pack",
                output=json.dumps(view),
                structured=view,
            )
        )
    return out


def further_reads(
    launch: str, report: dict[str, Any], *, ordinal: int = 2, start: int = 20
) -> list[LedgerEntry]:
    """The platform's reads of a further detonation launched with ``launch``, from ``start``."""
    record = DetonationRecord(
        ordinal=ordinal,
        origin="agent",
        arguments=launch,
        report=report,
        requested_by=[{"agent": "dynamic", "cited_entries": ["ev_0001"]}],
    )
    rows = [LedgerEntry.model_validate(row) for row in platform_reads(_Container(), record, "")]
    return [row.model_copy(update={"id": f"ev_{start + n:04d}"}) for n, row in enumerate(rows)]


def request(launch: str, entry_id: str = "ev_0009") -> LedgerEntry:
    """The request for a further detonation: its call given the launch text."""
    return LedgerEntry(
        id=entry_id,
        tool="request_detonation",
        agent="dynamic",
        server="platform",
        output=json.dumps({"accepted": True, "detonation": "d2", "arguments": launch}),
        args={"arguments": launch, "cited_entries": ["ev_0001"]},
    )


def static(entry_id: str, answer: Any, tool: str = "strings") -> LedgerEntry:
    """A static tool's entry over the file."""
    return LedgerEntry(
        id=entry_id,
        tool=tool,
        agent="static",
        server="static",
        output=answer if isinstance(answer, str) else json.dumps(answer),
        args={"path": "sample.bin"},
    )


def further_report(
    *,
    command: str = "",
    written: tuple[str, ...] = (),
    dns: tuple[tuple[str, str], ...] = (),
    signature: str = "",
    children: tuple[tuple[str, str], ...] = (),
    flows: tuple[str, ...] = (),
) -> dict[str, Any]:
    """A further detonation's sandbox report: the launched process and the processes it
    started (``(name, command line)``), files written, names resolved with their address,
    addresses the launched process's tree reached, a signature's text."""
    report: dict[str, Any] = {
        "behavior": {
            "processes": [
                {"pid": 9, "ppid": 4, "process_name": "x.exe", "command_line": command or "x.exe"},
                *(
                    {"pid": 10 + n, "ppid": 9, "process_name": name, "command_line": line}
                    for n, (name, line) in enumerate(children)
                ),
            ]
        },
        "network": {
            "dns": [
                {"request": host, "type": "A", "answers": [{"data": address, "type": "A"}]}
                for host, address in dns
            ],
            "tcp": [
                {"dst": address, "dport": 443, "sample_process_tree": True} for address in flows
            ],
        },
        "dropped": [
            {"name": path.rsplit("\\", 1)[-1], "filepath": path, "sha256": f"{n + 1:x}" * 64}
            for n, path in enumerate(written)
        ],
    }
    if signature:
        report["signatures"] = [{"name": "wrote_files", "severity": 2, "description": signature}]
    return report


def detonations_of(
    ledger: list[LedgerEntry], not_honoured: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    """The run's record of its detonations (``run_environment.detonations_record``'s rows): the
    job's own, and each further one the ledger reads, its launch honoured unless named in
    ``not_honoured``."""
    rows: list[dict[str, Any]] = [{"detonation": "d1", "origin": "job"}]
    for entry in ledger:
        name = later_detonation_name(entry)
        if not name or any(row["detonation"] == name for row in rows):
            continue
        data = entry.structured if isinstance(entry.structured, dict) else {}
        rows.append(
            {
                "detonation": name,
                "origin": "agent",
                "launched_with": str(data.get("launched_with") or ""),
                "arguments_honoured": name not in not_honoured,
            }
        )
    return rows


def built(
    ledger: list[LedgerEntry],
    identifiers: tuple[HostIdentifier, ...] = (),
    judged: tuple[tuple[str, str], ...] = (),
    *,
    not_honoured: tuple[str, ...] = (),
) -> MalwareReport:
    """The report the run builds, with the analysis's identifier rows and the judge's values;
    the run's record states each further detonation's launch honoured unless named in
    ``not_honoured``."""
    report = MalwareReportBuilder(
        file_hash=SHA256,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={"environment": {"detonations": detonations_of(ledger, not_honoured)}},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        judge_assessment=None,
        malware_category="rat",
        evidence_ledger=ledger,
    ).build_deterministic()
    report.judge_indicators = [JudgeIndicator(kind=kind, value=value) for kind, value in judged]
    report.technical_analysis = TechnicalAnalysis(
        host_identifiers=with_held_in(list(identifiers), EntryTexts.from_ledger(ledger))
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def stated(kind: str, value: str, *cited: str) -> HostIdentifier:
    """An identifier row the analysis states the sample creates or writes."""
    return HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=list(cited))


def answer_for(report: MalwareReport, value: str) -> str:
    """The rule's answer for ``value``: its identifier row's where the analysis states it, else
    its IOC row's (a sandbox's row, a judge's value)."""
    for held, said in identifier_answers(report):
        if held.value == value:
            return said
    rows: list[ConsolidatedIOC] = list(report.consolidated_iocs)
    for row in rows:
        if row.value == value:
            return str(row.published)
    raise AssertionError(f"no row holds {value!r}")
