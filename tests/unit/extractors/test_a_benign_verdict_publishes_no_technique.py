"""Under a Benign verdict no technique is published; the matrix keeps every cell.

The judge said the same thing of two Benign runs in two encodings: it dropped
every technique it was asked about in one, and in the other kept four in its
verdict bundle, each described "Capability only". The second four were
published bare, because the matrix never read the verdict. It does now: under
Benign every cell is listed and none is published, its reason states the
verdict first and then the judge's own words, whole, and the cell keeps every
statement. Every other verdict publishes as before.
"""

from __future__ import annotations

import pytest

from malspark.extractors.capability_matrix import (
    BENIGN_TECHNIQUE_REASON,
    build_capability_matrix,
)
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

CAPABILITY_ONLY = (
    "Capability only: the archiver's file-enumeration APIs fit normal archive operation; "
    "no discovery use against targets was observed."
)


def _bundle() -> dict:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "File and Directory Discovery",
                "description": CAPABILITY_ONLY,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1083"}],
            }
        ],
    }


def _isrs() -> dict:
    claim = ClaimEvidence(
        claim="FindFirstFileW enumerates the files it archives",
        evidence_ref="ev_0001",
        confidence=0.8,
        technique_id="T1083",
    )
    return {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}


def test_under_benign_the_cell_is_listed_with_the_verdict_and_the_judge_s_words() -> None:
    cells, mappings = build_capability_matrix(
        stix_output=_bundle(), isr_reports=_isrs(), verdict="Benign"
    )

    assert mappings == []
    (cell,) = cells
    assert cell.not_published.startswith(BENIGN_TECHNIQUE_REASON)
    assert cell.not_published.endswith(CAPABILITY_ONLY)
    # Nothing is deleted from the record: the analyst's statement stays.
    assert cell.evidence == ["FindFirstFileW enumerates the files it archives"]
    assert any("FindFirstFileW" in statement for statement in cell.statements)


@pytest.mark.parametrize("verdict", ["Malware", "Suspicious", None])
def test_every_other_verdict_publishes_as_before(verdict: str | None) -> None:
    cells, mappings = build_capability_matrix(
        stix_output=_bundle(), isr_reports=_isrs(), verdict=verdict
    )

    assert [m.technique_id for m in mappings] == ["T1083"]
    assert cells[0].not_published == ""


def test_a_technique_the_judge_dropped_keeps_its_reason_after_the_verdict() -> None:
    bundle = _bundle()
    bundle["objects"][0].pop("description")
    bundle["x_malspark_technique_review"] = {
        "asked": ["T1083"],
        "decisions": [{"technique_id": "T1083", "decision": "drop", "reason": "Not shown."}],
    }

    cells, mappings = build_capability_matrix(
        stix_output=bundle, isr_reports=_isrs(), verdict="Benign"
    )

    assert mappings == []
    assert cells[0].not_published == (
        f"{BENIGN_TECHNIQUE_REASON}; the judge dropped it (Not shown.)"
    )


def test_mitre_json_reads_the_empty_published_list_not_the_judge_s_bundle() -> None:
    from app.worker.analysis_worker import _extract_mitre

    result = {"malware_report": {"ttp_mappings": []}, "stix_output": _bundle()}

    assert _extract_mitre(result) is None
