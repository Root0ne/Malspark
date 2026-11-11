"""An IOC row and the indicator built from it carry the ledger entries the record ties to them.

The export wrote ledger ids on the sample's ``uses`` edges and a minted malware
object only; an indicator, an ``/iocs`` row and a MISP attribute named no entry,
so a receiver could not go from a published value to the call that found it.
The IOC table's row now carries the entries the run's record ties to it (an
analyst's listing cites them, a call binding was read in one, a recovering
tool's answer is one), only those the report's evidence index holds; the STIX
indicator takes its rows' ids through the ledger-checked path, and a MISP
attribute names them in its comment.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting import builder as builder_module
from malspark.reporting.builder import MalwareReportBuilder, ioc_table
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    ConsolidatedIOC,
    EvidenceIndexRow,
    EvidenceSection,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
)
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"
C2 = "82.157.13.47"
MUTEX = "Global\\ExampleLoaderMutex"


def _report() -> MalwareReport:
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
        evidence_ledger=[],
    ).build_deterministic()
    report.executive_summary = "A loader."
    report.evidence_index = [EvidenceIndexRow(id="ev_a"), EvidenceIndexRow(id="ev_b")]
    return report


def test_an_analyst_row_carries_the_entries_its_listing_cites_that_the_index_holds() -> None:
    report = _report()
    report.sections = [
        EvidenceSection(
            key="artifact_iocs",
            title="Indicators",
            kind="table",
            columns=["Label", "Value"],
            rows=[["mutex", MUTEX]],
            source="artifact:dynamic",
            evidence_ids=["ev_b", "ev_gone", "ev_a"],
        )
    ]

    (row,) = [r for r in ioc_table(report) if r.kind == "mutex"]

    assert row.model_dump() == {
        "type": "Mutex",
        "description": "listed by the dynamic analyst",
        "value": MUTEX,
        "is_network": False,
        "kind": "mutex",
        "source": "analyst",
        "context": "listed by the dynamic analyst",
        "published": (
            "no: named only by an analyst (an artifact of the dynamic analyst); no tool answer "
            "this report keeps holds it, and the judge did not keep it as an indicator"
        ),
        "recovered_by": "",
        "evidence_ids": ["ev_a", "ev_b"],
    }


def _with_ids(monkeypatch: pytest.MonkeyPatch, ids: list[str]) -> None:
    """The report's table, its address row tied to ``ids``: what the export reads of it."""
    real = builder_module.ioc_table

    def _table(report: Any, **kwargs: Any) -> list[ConsolidatedIOC]:
        return [
            row.model_copy(update={"evidence_ids": ids}) if row.kind == "ip" else row
            for row in real(report, **kwargs)
        ]

    monkeypatch.setattr(builder_module, "ioc_table", _table)


def _c2_indicator(bundle: dict[str, Any]) -> dict[str, Any]:
    (found,) = [o for o in bundle["objects"] if o["type"] == "indicator" and C2 in o["pattern"]]
    return found


def test_the_indicator_takes_its_row_s_ids_that_the_ledger_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report()
    report.network = NetworkIOCs(
        ips=[NetworkIP(address=C2, source="sandbox", sample_process_tree=True)]
    )
    _with_ids(monkeypatch, ["ev_b", "ev_x", "ev_a"])

    bundle = (
        ExtendedSTIXRenderer().render(report, ledger_ids=["ev_a", "ev_b"]).model_dump(mode="json")
    )
    unledgered = ExtendedSTIXRenderer().render(report).model_dump(mode="json")

    assert _c2_indicator(bundle)["x_malspark_evidence_refs"] == ["ev_a", "ev_b"]
    assert "x_malspark_evidence_refs" not in _c2_indicator(unledgered)
    sample = next(o for o in bundle["objects"] if o.get("name", "").startswith("Sample hash"))
    assert "x_malspark_evidence_refs" not in sample


def test_a_misp_attribute_names_its_row_s_entries_in_its_comment() -> None:
    report = _report()
    row = ConsolidatedIOC(
        type="IPv4",
        kind="ip",
        value=C2,
        source="sandbox",
        published="yes: the sandbox recorded it",
        is_network=True,
        evidence_ids=["ev_a", "ev_b"],
    )

    (attribute,) = build_misp_attributes(report, [row], owner="report-1")

    assert attribute == {
        "uuid": "8e96cb3a-ad34-5f09-87c5-260bcb788051",
        "type": "ip-dst",
        "category": "Network activity",
        "value": C2,
        "to_ids": True,
        "comment": "published because the sandbox recorded it; evidence ev_a, ev_b",
        "Tag": [{"name": "tlp:clear"}],
    }
