"""Every published value that rests on a later detonation's read carries its mark.

A row of the IOC table and a published technique rest on the entries the run's
record ties to them: the entries an analysis statement is found whole in, the
entries an analyst's listing cites, the sources behind a technique. Where one
of those is the platform's read of a further detonation an agent asked for
(``detonation_reads.later_detonation_name``, recorded on its index row), the
value is marked with that detonation and its launch, whatever its kind; a read
of the same kind that is not a later one is the job's own detonation's, and a
read of any other kind (a static tool's) observed no detonation. A run with one
detonation marks nothing (T-679).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.builder import (
    MalwareReportBuilder,
    build_consolidated_iocs,
    evidence_index_row,
)
from malspark.reporting.detonation_marks import entry_marks, with_technique_marks
from malspark.reporting.models import (
    EvidenceIndexRow,
    FileHashes,
    HostIdentifier,
    MalwareReport,
    ObservedIn,
    SampleIdentity,
    TechnicalAnalysis,
    TTPMapping,
)
from malspark.reporting.stated_host_values import host_kinds, with_held_in

ARGS = "-p hunter2"
D1 = ObservedIn(detonation="d1")
D2 = ObservedIn(detonation="d2", launched_with=ARGS)
MARK = f"observed in detonation 2, launched with `{ARGS}`"

# One value of each host kind the analysis may state, each one the table publishes.
VALUES = {
    "mutex": "Global\\ExampleMutex7731",
    "file path": "C:\\Users\\Public\\ExampleVendor7731\\payload7731.exe",
    "file name": "\\example7731.dat",
    "folder": "ExampleFolder7731",
    "registry key": "HKCU\\Software\\ExampleVendor7731",
    "registry value": "HKCU\\Software\\ExampleVendor7732\\Updater7731",
    "scheduled task": "ExampleTask7731",
    "service": "ExampleSvc7731",
    "named pipe": "\\\\.\\pipe\\examplepipe_7731",
    "alternate data stream": ":example7731",
}
LATER, OWN, STATIC = "ev_0031", "ev_0021", "ev_0041"


def _index(*, later: bool = True, launch: str = ARGS) -> list[EvidenceIndexRow]:
    return [
        EvidenceIndexRow(id=STATIC, agent="static", tool="floss"),
        EvidenceIndexRow(id=OWN, agent="pipeline", tool="sandbox_signatures"),
        EvidenceIndexRow(
            id=LATER,
            agent="pipeline",
            tool="sandbox_signatures",
            observed_in=[ObservedIn(detonation="d2", launched_with=launch)] if later else [],
        ),
    ]


def _report(cited: list[str], *, later: bool = True, launch: str = ARGS) -> MalwareReport:
    texts = json.dumps(list(VALUES.values())).lower()
    entries = EntryTexts(texts={ref: texts for ref in (LATER, OWN, STATIC)})
    identifiers = [
        HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=cited)
        for kind, value in VALUES.items()
    ]
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="loader",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in(identifiers, entries)),
        evidence_index=_index(later=later, launch=launch),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _stated(report: MalwareReport) -> dict[str, Any]:
    return {row.kind: row for row in report.consolidated_iocs if row.source == "analysis"}


class TestEveryKind:
    def test_every_published_kind_resting_on_a_later_read_carries_the_mark(self) -> None:
        rows = _stated(_report([LATER]))
        # Every table kind the vocabulary publishes a value under is walked.
        kinds = {kind.table_kind for kind in host_kinds().values() if kind.table_kind}
        assert set(rows) == kinds
        dropped = sorted(kind for kind, row in rows.items() if row.observed_in != [D2])
        assert dropped == []

    def test_a_static_read_beside_it_observed_no_detonation(self) -> None:
        rows = _stated(_report([STATIC, LATER]))
        assert {kind: row.observed_in for kind, row in rows.items()} == {
            kind: [D2] for kind in rows
        }

    def test_a_read_of_the_same_kind_that_is_no_later_one_is_the_job_s_own(self) -> None:
        rows = _stated(_report([OWN, LATER]))
        assert {kind: row.observed_in for kind, row in rows.items()} == {
            kind: [D1, D2] for kind in rows
        }

    def test_a_value_resting_on_no_later_read_carries_none(self) -> None:
        for cited in ([OWN], [STATIC], [OWN, STATIC]):
            rows = _stated(_report(cited))
            assert all(not row.observed_in for row in rows.values()), cited


class TestTheSurfaces:
    """Each surface that shows a newly marked kind shows its mark."""

    @pytest.fixture
    def report(self) -> MalwareReport:
        return MalwareReportBuilder.attach_detection_signatures(_report([LATER]))

    def test_the_markdown_host_table(self, report: MalwareReport) -> None:
        from malspark.reporting.renderers import MarkdownRenderer

        text = MarkdownRenderer().render(report)
        for value in ("ExampleVendor7731", "ExampleTask7731", "ExampleSvc7731"):
            line = next(x for x in text.split("\n") if x.startswith("|") and value in x)
            assert MARK in line, line

    def test_the_iocs_feed(self, report: MalwareReport) -> None:
        from app.services.report_service import ioc_feed_rows

        rows = ioc_feed_rows(report.model_dump(mode="json"))
        registry = next(r for r in rows if r.get("value") == VALUES["registry key"])
        assert registry["observed_in"] == [D2.model_dump()]

    def test_the_misp_comment(self, report: MalwareReport) -> None:
        from malspark.reporting.misp import build_misp_attributes

        attributes = build_misp_attributes(report, report.consolidated_iocs, owner="u")
        regkey = next(a for a in attributes if a["value"].endswith("ExampleVendor7731"))
        assert MARK in regkey["comment"]

    def test_the_stix_indicator(self, report: MalwareReport) -> None:
        from malspark.reporting.renderers.stix_renderer import _with_the_detonations
        from malspark.schemas.stix_models import Indicator

        indicator = Indicator(
            name="Registry key",
            pattern="[windows-registry-key:key = 'HKCU\\\\Software\\\\ExampleVendor7731']",
        )
        (marked,) = _with_the_detonations([indicator], report.consolidated_iocs, report)
        assert marked.x_malspark_observed_in == [D2.model_dump()]

    def test_every_sigma_draft_names_its_later_values(self, report: MalwareReport) -> None:
        docs = [yaml.safe_load(r.body) for r in report.detection_signatures if r.kind == "sigma"]
        first = next(d for d in docs if d["logsource"].get("category") == "registry_event")
        assert f"{VALUES['registry key']}: {MARK}" in first["description"]
        task = next(d for d in docs if d["logsource"].get("service") == "security")
        assert f"{VALUES['scheduled task']}: {MARK}" in task["description"]

    def test_a_draft_over_a_value_the_job_s_own_read_holds_too_says_nothing(self) -> None:
        report = MalwareReportBuilder.attach_detection_signatures(_report([OWN, LATER]))
        assert not any(
            "observed in" in r.body for r in report.detection_signatures if r.kind == "sigma"
        )


class TestTechniques:
    def test_a_technique_whose_source_is_a_later_read_carries_the_mark(self) -> None:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64)),
            evidence_index=_index(),
            ttp_mappings=[
                TTPMapping(technique_id="T1486", technique_name="x", sources=[STATIC, LATER]),
                TTPMapping(technique_id="T1027", technique_name="y", sources=[OWN, LATER]),
                TTPMapping(technique_id="T1055", technique_name="z", sources=[OWN, STATIC]),
            ],
        )
        with_technique_marks(report.ttp_mappings, report)
        assert [m.observed_in for m in report.ttp_mappings] == [[D2], [D1, D2], []]


class TestTheIndex:
    def test_a_later_detonation_s_read_is_marked_on_its_index_row(self) -> None:
        import tests.unit.reporting.test_a_later_detonation_s_observations_reach_the_report as base

        rows = [evidence_index_row(entry) for entry in base._ledger()]
        marked = {row.id: row.observed_in for row in rows if row.observed_in}
        assert marked and all(marks == [base.D2_MARK] for marks in marked.values())
        assert all(row.agent == "pipeline" for row in rows if row.observed_in)

    def test_a_run_with_one_detonation_indexes_as_it_did(self) -> None:
        import tests.unit.reporting.test_a_later_detonation_s_observations_reach_the_report as base

        rows = [evidence_index_row(entry) for entry in base._ledger(later=False)]
        assert all("observed_in" not in row.model_dump() for row in rows)

    def test_a_sandbox_item_names_its_detonation(self) -> None:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64)), evidence_index=_index()
        )
        assert entry_marks(["d2/reg:3"], report) == [D2]
        assert entry_marks(["reg:3", "d2/reg:3"], report) == [D1, D2]
        assert entry_marks(["reg:3"], report) == []
        # A detonation the index states no read of has no launch to name.
        assert entry_marks(["d3/reg:3"], report) == []
