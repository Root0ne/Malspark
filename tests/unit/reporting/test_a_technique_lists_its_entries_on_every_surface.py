"""A published technique shows one evidence set, the builder's, on every surface.

The capability matrix builder records the ledger entries behind each
technique (``evidence_ids``). The Markdown and analyst ATT&CK tables, the STIX
``uses`` edge, the MISP technique attribute, the ATT&CK Navigator layer, the
ATT&CK defence rows and the API's technique list each print that set, read
through one function (``reporting.technique_evidence``). A technique no entry
stands behind says so on each surface in its own form.
"""

from __future__ import annotations

import json
import re
from typing import Any

from malspark.agents.judge_postprocess import (
    lift_misplaced_extensions,
    postprocess_judge_bundle,
)
from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.models import MalwareReport, TTPMapping
from malspark.reporting.technique_evidence import (
    NO_LEDGER_ENTRY,
    technique_evidence_ids,
    technique_evidence_words,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, ClaimEvidence, Finding
from malspark.schemas.stix_models import (
    Bundle,
)

CLAIMED = "T1055"
JUDGE_ONLY = "T1057"
# The ledger in its order, out of numeric order so ledger order shows.
LEDGER = ["ev_0001", "ev_0002", "ev_0004", "ev_0003", "ev_0005"]
# The entries behind the claimed technique, in ledger order: the claim's
# sentence cites ev_0003, its evidence line ev_0001, a finding ev_0004.
# ev_0099 is cited and never issued.
EXPECTED = ["ev_0001", "ev_0004", "ev_0003"]


def _ledger() -> list[LedgerEntry]:
    return [LedgerEntry(id=eid, tool="pe_info", seq=i) for i, eid in enumerate(LEDGER, 1)]


def _isrs() -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="It writes into a remote process [ev_0003] and [ev_0099].",
                    evidence_ref="[ev_0001] WriteProcessMemory import",
                    confidence=0.8,
                    technique_id=CLAIMED,
                )
            ],
            findings=[
                Finding(
                    title="injects",
                    detail="it injects",
                    technique_ids=[CLAIMED],
                    evidence_ids=["ev_0004"],
                )
            ],
        )
    }


def _judge() -> Bundle:
    def pattern(index: int, tid: str) -> dict[str, Any]:
        return {
            "type": "attack-pattern",
            "id": f"attack-pattern--{index}",
            "name": tid,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        }

    def uses(index: int) -> dict[str, Any]:
        return {
            "type": "relationship",
            "id": f"relationship--{index}",
            "relationship_type": "uses",
            "source_ref": "malware--1",
            "target_ref": f"attack-pattern--{index}",
            "x_malspark_confidence": 0.8,
        }

    data = json.loads(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {"type": "malware", "id": "malware--1", "name": "loader", "is_family": False},
                    pattern(1, CLAIMED),
                    pattern(2, JUDGE_ONLY),
                    uses(1),
                    uses(2),
                ],
            }
        )
    )
    lift_misplaced_extensions(data)
    return Bundle.model_validate(postprocess_judge_bundle(data))


def _report(ledger: list[LedgerEntry] | None = None) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=_isrs(),
        stix_output=_judge().model_dump(mode="json"),
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        evidence_ledger=_ledger() if ledger is None else ledger,
    ).build_deterministic()


def _mapping(report: MalwareReport, tid: str) -> TTPMapping:
    (mapping,) = [m for m in report.ttp_mappings if m.technique_id == tid]
    return mapping


def _attack_rows(markdown: str) -> dict[str, list[str]]:
    """The full report's ATT&CK table, cells per technique id."""
    rows: dict[str, list[str]] = {}
    for line in markdown.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 8 and re.fullmatch(r"T\d{4}(\.\d{3})?", cells[1]):
            rows[cells[1]] = cells
    return rows


class TestTheBuilderRecordsTheSet:
    def test_the_entries_its_statements_cite_that_the_run_issued_in_ledger_order(self) -> None:
        report = _report()

        assert _mapping(report, CLAIMED).evidence_ids == EXPECTED
        cell = next(c for c in report.capability_matrix if c.technique_id == CLAIMED)
        assert cell.evidence_ids == EXPECTED

    def test_a_technique_only_the_judge_names_has_none(self) -> None:
        assert _mapping(_report(), JUDGE_ONLY).evidence_ids == []

    def test_without_a_ledger_the_ids_its_statements_cite(self) -> None:
        ids = _mapping(_report(ledger=[]), CLAIMED).evidence_ids

        assert ids is not None
        assert set(ids) == {"ev_0001", "ev_0003", "ev_0004", "ev_0099"}

    def test_a_stored_row_without_the_set_reads_its_sources_and_statements(self) -> None:
        stored = {
            "technique_id": CLAIMED,
            "sources": ["ev_0002", "proc:85"],
            "evidence_quotes": ["it injects [ev_0007]"],
        }

        assert technique_evidence_ids(stored) == ["ev_0002", "ev_0007"]
        assert technique_evidence_words(stored) == "ev_0002, ev_0007; sandbox items: proc:85"

    def test_a_stored_row_naming_no_entry_says_nothing_either_way(self) -> None:
        stored = {"technique_id": CLAIMED, "sources": [], "evidence_quotes": ["it injects"]}

        assert technique_evidence_ids(stored) is None
        assert technique_evidence_words(stored) == "-"
        assert technique_evidence_ids({**stored, "evidence_ids": []}) == []
        assert technique_evidence_words({**stored, "evidence_ids": []}) == NO_LEDGER_ENTRY

    def test_a_dumped_row_keeps_the_set_and_a_stored_row_dumps_as_before(self) -> None:
        mapping = _mapping(_report(), JUDGE_ONLY)

        assert mapping.model_dump()["evidence_ids"] == []
        stored = TTPMapping(technique_id=CLAIMED, technique_name="x")
        assert "evidence_ids" not in stored.model_dump()
