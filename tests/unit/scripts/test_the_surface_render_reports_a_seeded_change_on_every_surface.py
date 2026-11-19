"""A value changed in the platform is a difference ``--compare`` reports, on every kind of surface.

A repository of the test's own holds this checkout's platform with its replay
(so both modes render), and its second commit changes one value of each kind
a surface prints: a figure's caption (the network figure, which the build
draws without the sandbox report), a figure's legend, a matrix column's name,
an SVG tooltip, the degraded-run sentence, a section 11 sentence, a printed
finding's label, a note of the evidence bundle and a line of its fenced
process tree, the reason the export publishes an indicator with, the
description of the export's identity and of a relationship it adds, the ends
of a relationship, an indicator's ``valid_from`` timestamp, the namespace the
export's ids are derived in, a MISP comment, the event's threat level and an
object attribute's category, and a ``/mitre`` description. Each is reported as
a change, in the mode and on the surface that prints it, and every surface is
produced by both refs.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import (
    commit_edits,
    full_report,
    platform_repository,
    stored_run,
)

R = "src/malspark/reporting"
Change = Mapping[str, Any]


def _says(word: str) -> Callable[[Change], bool]:
    return lambda c: word in str(c["new"]) and word not in str(c["old"])


def _id_changed(c: Change) -> bool:
    return c["change"] == "changed" and str(c["key"]).endswith(" id")


def _ends_swapped(c: Change) -> bool:
    key = str(c["key"])
    return (
        c["change"] == "added" and key.startswith("relationship malware") and " indicates " in key
    )


# (file, old, new, mode, surfaces, what a change reporting it shows)
SEEDS: tuple[tuple[str, str, str, str, frozenset[str], Callable[[Change], bool]], ...] = (
    (
        f"{R}/figures.py",
        'caption="Network endpoints (observed)"',
        'caption="Network endpoints (observed) SEED-NETWORK"',
        "build",
        frozenset({"html.figure"}),
        _says("SEED-NETWORK"),
    ),
    (
        f"{R}/figures.py",
        'legend="Tactics are drawn in ATT&CK order, not',
        'legend="Tactics are drawn in ATT&CK order SEED-CHAIN, not',
        "build",
        frozenset({"html.figure"}),
        _says("SEED-CHAIN"),
    ),
    (
        f"{R}/figures.py",
        '("TA0005", "Defense Evasion"),',
        '("TA0005", "Defense Evasion SEED-COLUMN"),',
        "build",
        frozenset({"html.figure"}),
        _says("SEED-COLUMN"),
    ),
    (
        f"{R}/figures.py",
        "({mark})'))}</title>",
        "({mark}) SEED-TOOLTIP'))}</title>",
        "serve",
        frozenset({"html.figure"}),
        _says("SEED-TOOLTIP"),
    ),
    (
        f"{R}/renderers/markdown.py",
        'parts.append("this run had less evidence than a full analysis")',
        'parts.append("this run had less SEED-BANNER evidence than a full analysis")',
        "serve",
        frozenset({"banner", "report.md"}),
        _says("SEED-BANNER"),
    ),
    (
        f"{R}/renderers/analyst.py",
        '"Without a sandbox observation, what the sample does is read from its code and "',
        '"Without a sandbox observation SEED-LIMITS, what the sample does is read from its '
        'code and "',
        "build",
        frozenset({"report.md", "html.body"}),
        _says("SEED-LIMITS"),
    ),
    (
        f"{R}/renderers/analyst.py",
        '_item(f"_Unresolved:_ ',
        '_item(f"_Unresolved SEED-LABEL:_ ',
        "serve",
        frozenset({"report.md"}),
        _says("SEED-LABEL"),
    ),
    (
        f"{R}/renderers/markdown.py",
        "_The platform's unresolved findings on this section",
        "_The platform's SEED-NOTE unresolved findings on this section",
        "serve",
        frozenset({"bundle.lines"}),
        _says("SEED-NOTE"),
    ),
    (
        f"{R}/renderers/markdown.py",
        'line = f"{indent}{prefix}pid={node.pid} ppid=',
        'line = f"{indent}{prefix}pid={node.pid} SEED-FENCED ppid=',
        "serve",
        frozenset({"bundle.lines"}),
        _says("SEED-FENCED"),
    ),
    (
        f"{R}/renderers/stix_renderer.py",
        'PUBLISHED_BECAUSE = "Published because"',
        'PUBLISHED_BECAUSE = "Published SEED-REASON because"',
        "build",
        frozenset({"stix"}),
        _says("SEED-REASON"),
    ),
    (
        f"{R}/renderers/stix_renderer.py",
        'description="Automated multi-agent malware analysis pipeline"',
        'description="Automated multi-agent malware analysis pipeline SEED-IDENTITY"',
        "build",
        frozenset({"stix"}),
        _says("SEED-IDENTITY"),
    ),
    (
        f"{R}/renderers/stix_renderer.py",
        '"Added by the platform: the indicator was published for this sample, and no edge "',
        '"Added by the platform SEED-RELATIONSHIP: the indicator was published for this '
        'sample, and no edge "',
        "build",
        frozenset({"stix"}),
        _says("SEED-RELATIONSHIP"),
    ),
    (
        f"{R}/renderers/stix_renderer.py",
        'relationship_type="indicates",\n                        source_ref=indicator.id,\n'
        "                        target_ref=malware_id,",
        'relationship_type="indicates",\n                        source_ref=malware_id,\n'
        "                        target_ref=indicator.id,",
        "build",
        frozenset({"stix"}),
        _ends_swapped,
    ),
    (
        f"{R}/renderers/stix_renderer.py",
        'update["valid_from"] = stamp',
        'update["valid_from"] = stamp.replace(year=2001)',
        "build",
        frozenset({"stix"}),
        _says('"valid_from": "2001-'),
    ),
    (
        "src/malspark/schemas/stix_models.py",
        'STIX_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "malspark:stix")',
        'STIX_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "malspark:stix-seeded")',
        "build",
        frozenset({"stix"}),
        _id_changed,
    ),
    (
        f"{R}/misp.py",
        'f"published because {why}" if why else "",',
        'f"published SEED-COMMENT because {why}" if why else "",',
        "build",
        frozenset({"misp"}),
        _says("SEED-COMMENT"),
    ),
    (
        f"{R}/misp.py",
        '"threat_level_id": "4",',
        '"threat_level_id": "1",',
        "build",
        frozenset({"misp"}),
        _says('"threat_level_id": "1"'),
    ),
    (
        f"{R}/misp.py",
        '"Other" if kind == "size-in-bytes" else "Payload delivery"',
        '"Other" if kind == "size-in-bytes" else "Payload delivery SEED-CATEGORY"',
        "build",
        frozenset({"misp"}),
        _says("SEED-CATEGORY"),
    ),
    (
        "apps/api/app/worker/analysis_worker.py",
        '"description": " | ".join(m.get("evidence_quotes") or [])[:512],',
        '"description": "SEED-MITRE " + " | ".join(m.get("evidence_quotes") or [])[:512],',
        "build",
        frozenset({"mitre"}),
        _says("SEED-MITRE"),
    ),
)


@pytest.mark.slow
def test_each_seeded_value_is_a_reported_change(tmp_path: Path) -> None:
    repo, first = platform_repository(tmp_path, extra=("scripts/replay",))
    second = commit_edits(repo, [(name, old, new) for name, old, new, *_rest in SEEDS])
    run = stored_run(tmp_path, malware_report=full_report())
    out = tmp_path / "diff.json"
    argv = [str(run), "--repo", str(repo), "--work", str(tmp_path / "work"), "--quiet"]

    status = rs.main([*argv, "--compare", first, second, "--json", str(out)])

    [diff] = json.loads(out.read_text(encoding="utf-8"))["runs"]
    assert status == rs.EXIT_UNEXPECTED
    assert "errors" not in diff and "not_compared" not in diff and diff["neither"] == 0
    missed = []
    for _name, old, _new, mode, surfaces, shows in SEEDS:
        hits = {(c["mode"], c["surface"]) for c in diff["changes"] if shows(c)}
        if not {(mode, surface) for surface in surfaces} <= hits:
            missed.append((old[:60], sorted(hits)))
    assert missed == []
    # The figure the build draws without the sandbox report is compared all the same.
    assert diff["dynamic_compared"] > 0
    assert any(
        c["group"] == "fig-network" and "SEED-NETWORK" in str(c["new"]) for c in diff["changes"]
    )
