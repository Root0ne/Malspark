"""The ``uses`` edge the export adds for a technique carries the status its ATT&CK row prints.

The judge's own edge carries the judge's confidence; an edge the export adds,
for a technique the judge related to nothing, carries none. Where the
technique's row of the capability matrix holds a note ("not confirmed by the
judge", a claim carried forward), the edge carries that note as its
description, so a technique the judge did not confirm is not exported as an
unqualified "uses"; a row with no note leaves the edge without one (T-785).
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.models import (
    CapabilityCell,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from malspark.schemas.isr_models import JUDGE_UNCONFIRMED_TECHNIQUE_MARKER
from malspark.schemas.stix_models import Bundle

SHA256 = "a" * 64
MALWARE = "malware--0f1e2d3c-4b5a-4968-8776-655443332211"
CARRIED = "carried forward: the round-1 revision neither wrote it again nor withdrew it"


def _cell(tid: str, note: str = "", not_published: str = "") -> CapabilityCell:
    return CapabilityCell(
        tactic="TA0004",
        tactic_name="Privilege Escalation",
        technique_id=tid,
        technique_name=tid,
        note=note,
        not_published=not_published,
    )


def _edges(cells: list[CapabilityCell]) -> dict[str, dict[str, Any]]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        overall_confidence=0.9,
        ttp_mappings=[
            TTPMapping(technique_id=c.technique_id, technique_name=c.technique_id)
            for c in cells
            if not c.not_published
        ],
        capability_matrix=cells,
    )
    judge = Bundle.model_validate(
        {
            "type": "bundle",
            "objects": [
                {
                    "type": "malware",
                    "id": MALWARE,
                    "name": "Sample",
                    "is_family": False,
                    "malware_types": ["ransomware"],
                }
            ],
        }
    )
    objects = ExtendedSTIXRenderer().render(report, judge).model_dump(mode="json")["objects"]
    patterns = {
        o["id"]: o["external_references"][0]["external_id"]
        for o in objects
        if o["type"] == "attack-pattern"
    }
    return {
        patterns[o["target_ref"]]: o
        for o in objects
        if o["type"] == "relationship"
        and o["relationship_type"] == "uses"
        and o["target_ref"] in patterns
    }


def test_a_technique_the_judge_did_not_confirm_is_not_an_unqualified_uses() -> None:
    edges = _edges([_cell("T1134", JUDGE_UNCONFIRMED_TECHNIQUE_MARKER)])

    assert edges["T1134"]["description"] == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER


def test_the_edge_carries_the_row_s_whole_note() -> None:
    note = f"{CARRIED}; {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}"

    edges = _edges([_cell("T1489", note)])

    assert edges["T1489"]["description"] == note


def test_a_row_with_no_note_leaves_the_edge_without_a_description() -> None:
    edges = _edges([_cell("T1055"), _cell("T1134", JUDGE_UNCONFIRMED_TECHNIQUE_MARKER)])

    assert "description" not in edges["T1055"]
    assert edges["T1134"]["description"] == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER
