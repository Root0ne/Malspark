"""The ``uses`` edge the export adds for a technique the judge did not confirm says so.

The judge's own edge carries the judge's confidence; an edge the export adds,
for a technique the judge related to nothing, carries none. Where the
technique's row of the capability matrix says the judge was asked about it and
did not confirm it, the edge carries those words as its description, so the
technique is not exported as an unqualified "uses"; any other row leaves the
edge as it was (T-785). The status is read as the row's last note, whole
(``isr_models.is_judge_unconfirmed``): the marker's words inside an earlier
note, a reason the judge gave among them, are not the status.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.models import (
    CapabilityCell,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from malspark.schemas.isr_models import (
    CAPABILITY_NOTE_JOINER,
    JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
    judge_kept_note,
)
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


def test_the_status_is_read_beside_another_note_of_the_row() -> None:
    edges = _edges([_cell("T1489", f"{CARRIED}; {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}")])

    assert edges["T1489"]["description"] == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER


def test_the_status_is_read_after_other_notes_of_the_row() -> None:
    edges = _edges(
        [
            _cell(
                "T1489", CAPABILITY_NOTE_JOINER.join([CARRIED, JUDGE_UNCONFIRMED_TECHNIQUE_MARKER])
            ),
            _cell(
                "T1490",
                CAPABILITY_NOTE_JOINER.join(
                    [
                        "asked after the bundle carries it; no claim describes it",
                        CARRIED,
                        JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
                    ]
                ),
            ),
        ]
    )

    assert edges["T1489"]["description"] == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER
    assert edges["T1490"]["description"] == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER


def test_a_reason_the_judge_kept_it_with_carries_no_status() -> None:
    reason = f"the call is shown; {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}; the strings agree"
    edges = _edges(
        [
            _cell(
                "T1059",
                CAPABILITY_NOTE_JOINER.join(
                    ["no corroboration record speaks for it", judge_kept_note(reason)]
                ),
            )
        ]
    )

    assert "description" not in edges["T1059"]


@pytest.mark.parametrize(
    "reason",
    [
        f"weak; {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}",
        f"the listing shows it; {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}",
        f"the listing (shows it; {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}",
        f"the listing shows it); {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}",
        f"(((; {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}",
        f")); {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}",
    ],
)
def test_a_kept_reason_ending_in_the_marker_s_words_carries_no_status(reason: str) -> None:
    edges = _edges([_cell("T1059", judge_kept_note(reason))])

    assert "description" not in edges["T1059"]


def test_the_marker_s_words_inside_another_note_are_not_the_status() -> None:
    edges = _edges(
        [
            _cell("T1082", f"kept as {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER} said; {CARRIED}"),
            _cell("T1083", f"{CARRIED}; the row was {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER} once"),
        ]
    )

    assert all("description" not in edges[tid] for tid in ("T1082", "T1083"))


def test_a_row_the_judge_did_not_leave_unconfirmed_leaves_the_edge_without_one() -> None:
    edges = _edges(
        [
            _cell("T1055"),
            _cell("T1057", CARRIED),
            # A reason that quotes the words is the judge's keeping, not the status.
            _cell("T1082", f"kept by the judge when asked ({JUDGE_UNCONFIRMED_TECHNIQUE_MARKER})"),
            _cell("T1134", JUDGE_UNCONFIRMED_TECHNIQUE_MARKER),
        ]
    )

    assert all("description" not in edges[tid] for tid in ("T1055", "T1057", "T1082"))
    assert edges["T1134"]["description"] == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER
