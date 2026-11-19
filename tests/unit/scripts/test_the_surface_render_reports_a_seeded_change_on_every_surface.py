"""A string changed in the platform is a difference ``--compare`` reports, on every kind of surface.

A repository of the test's own holds this checkout's platform with its replay
(so both modes render), and its second commit changes five strings the tiny
run's surfaces print: the network figure's caption, which the build draws
without the sandbox report (a unit marked dynamic); the description of a
relationship the export adds; the heading tag of the evidence bundle's
sections the report model wrote; the reason the export publishes an indicator
with; and the degraded-run banner. Each is reported as a change, in the mode
and on the surface that prints it, and every surface is produced by both refs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import (
    commit_edits,
    platform_repository,
    stored_run,
)

REPORTING = "src/malspark/reporting"
# (file, old, new, the mode and surfaces the new text must be reported on)
SEEDS: tuple[tuple[str, str, str, str, frozenset[str]], ...] = (
    (
        f"{REPORTING}/figures.py",
        'caption="Network endpoints (observed)"',
        'caption="Network endpoints (observed) SEED-FIGURE"',
        "build",
        frozenset({"html.figure"}),
    ),
    (
        f"{REPORTING}/renderers/stix_renderer.py",
        '"Added by the platform: the indicator was published for this sample, and no edge "',
        '"Added by the platform SEED-RELATIONSHIP: the indicator was published for this '
        'sample, and no edge "',
        "build",
        frozenset({"stix"}),
    ),
    (
        f"{REPORTING}/renderers/markdown.py",
        'REPORT_MODEL = "Written by the report model"',
        'REPORT_MODEL = "Written by the report model SEED-BUNDLE"',
        "serve",
        frozenset({"bundle.lines"}),
    ),
    (
        f"{REPORTING}/renderers/stix_renderer.py",
        'PUBLISHED_BECAUSE = "Published because"',
        'PUBLISHED_BECAUSE = "Published SEED-REASON because"',
        "build",
        frozenset({"stix"}),
    ),
    (
        f"{REPORTING}/renderers/analyst.py",
        '"\\n> **[DEGRADED RUN]** "',
        '"\\n> **[DEGRADED RUN SEED-BANNER]** "',
        "serve",
        frozenset({"banner", "report.md"}),
    ),
)


@pytest.mark.slow
def test_each_seeded_string_is_a_reported_change(tmp_path: Path) -> None:
    repo, first = platform_repository(tmp_path, extra=("scripts/replay",))
    second = commit_edits(repo, [(name, old, new) for name, old, new, _m, _s in SEEDS])
    run = stored_run(tmp_path)
    out = tmp_path / "diff.json"
    argv = [str(run), "--repo", str(repo), "--work", str(tmp_path / "work"), "--quiet"]

    status = rs.main([*argv, "--compare", first, second, "--json", str(out)])

    [diff] = json.loads(out.read_text(encoding="utf-8"))["runs"]
    assert status == rs.EXIT_UNEXPECTED
    assert "errors" not in diff and "not_compared" not in diff and diff["neither"] == 0
    for _name, _old, new, mode, surfaces in SEEDS:
        seed = next(word for word in new.replace('"', " ").split() if word.startswith("SEED-"))
        hits = {
            (change["mode"], change["surface"])
            for change in diff["changes"]
            if seed in str(change["new"]) and seed not in str(change["old"])
        }
        assert {(mode, surface) for surface in surfaces} <= hits, (seed, hits)
    # The figure the build draws without the sandbox report is compared all the same.
    assert diff["dynamic_compared"] > 0
    assert any(
        change["group"] == "fig-network" and "SEED-FIGURE" in str(change["new"])
        for change in diff["changes"]
    )
