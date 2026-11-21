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
object attribute's category, a ``/mitre`` description, a table-of-contents
href, a citation's class, a data attribute and its href pointed off-site, a
field the IOC row model drops, the rules the printed download serves and the
owner the MISP event is derived from in the service. Each is reported as a
change, in the mode and on the surface that prints it, every changed file is
a change of its own, and every surface is produced by both refs.
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
SERVICE = "apps/api/app/services/report_service.py"
Change = Mapping[str, Any]


def _says(word: str) -> Callable[[Change], bool]:
    return lambda c: word in str(c["new"]) and word not in str(c["old"])


def _id_changed(c: Change) -> bool:
    return c["change"] == "changed" and str(c["key"]).endswith(" id")


def _lost_source(c: Change) -> bool:
    return '"source": ' in str(c["old"]) and '"source": ' not in str(c["new"])


def _printed_gone(c: Change) -> bool:
    return c["change"] == "removed" and c["group"] == "sigma printed"


def _event_uuid_moved(c: Change) -> bool:
    return c["change"] == "changed" and c["key"] == "event" and '"uuid"' in str(c["new"])


def _ends_swapped(c: Change) -> bool:
    key = str(c["key"])
    return (
        c["change"] == "added" and key.startswith("relationship malware") and " indicates " in key
    )


# (file, old, new, mode, surfaces, what a change reporting it shows)
SEEDS: tuple[tuple[str, str, str, str, frozenset[str], Callable[[Change], bool]], ...] = (
    (
        f"{R}/figures.py",
        'caption="Network endpoints"',
        'caption="Network endpoints SEED-NETWORK"',
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
        "cols = [(tid, name) for tid, name in _tactic_columns()",
        'cols = [(tid, name + " SEED-COLUMN") for tid, name in _tactic_columns()',
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
        "apps/api/app/services/technique_descriptions.py",
        "return printed_procedures(typed), None",
        'return {k: "SEED-MITRE " + v for k, v in printed_procedures(typed).items()}, None',
        "build",
        frozenset({"mitre"}),
        _says("SEED-MITRE"),
    ),
    (
        f"{R}/renderers/html.py",
        'entries.append(f\'<li><a href="#{match.group(1)}">',
        'entries.append(f\'<li><a href="#seed-{match.group(1)}">',
        "serve",
        frozenset({"html.tags", "file.lines"}),
        _says('href="#seed-'),
    ),
    (
        f"{R}/renderers/html.py",
        'f\'<sup class="cite"><a href="{BUNDLE_HTML}#cite-',
        'f\'<sup class="citex" data-seed="1"><a href="https://evil.example/{BUNDLE_HTML}#cite-',
        "build",
        frozenset({"html.tags", "file.lines"}),
        _says("evil.example"),
    ),
    (
        f"{R}/figures.py",
        'caption="MITRE ATT&CK tactic coverage"',
        'caption="MITRE ATT&CK tactic coverage SEED-CAPTION"',
        "build",
        frozenset({"html.figure"}),
        _says("SEED-CAPTION"),
    ),
    (
        "apps/api/app/schemas/job.py",
        "    source: str | None = None\n",
        "",
        "serve",
        frozenset({"iocs.all", "iocs.default"}),
        _lost_source,
    ),
    (
        SERVICE,
        "        if not (printed or every):",
        "        if not every:",
        "serve",
        frozenset({"rules.download"}),
        _printed_gone,
    ),
    (
        SERVICE,
        "        owner = misp_owner(typed, report.job_id) if built else str(report.id)",
        "        owner = str(report.id)",
        "build",
        frozenset({"misp"}),
        _event_uuid_moved,
    ),
)
# A rule the analyst report prints, so the printed download holds it.
SIGMA = {
    "kind": "sigma",
    "name": "fixture_sigma",
    "body": "title: fixture\nlogsource: {product: windows}\ndetection: {s: {Image: x}, "
    "condition: s}\n",
}


@pytest.mark.slow
def test_each_seeded_value_is_a_reported_change(tmp_path: Path) -> None:
    repo, first = platform_repository(tmp_path, extra=("scripts/replay",))
    second = commit_edits(repo, [(name, old, new) for name, old, new, *_rest in SEEDS])
    stored = full_report()
    stored["detection_signatures"] = [*stored["detection_signatures"], SIGMA]
    run = stored_run(tmp_path, malware_report=stored)
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
    # The off-site href and the caption in one report.html are two changes, and the file a third.
    surfaces = {c["surface"] for c in diff["changes"] if c["mode"] == "build"}
    assert {"html.figure", "html.tags", "file.lines", "file"} <= surfaces
    # The figure the build draws without the sandbox report is compared all the same.
    assert diff["dynamic_compared"] > 0
    assert any(
        c["group"] == "fig-network" and "SEED-NETWORK" in str(c["new"]) for c in diff["changes"]
    )
