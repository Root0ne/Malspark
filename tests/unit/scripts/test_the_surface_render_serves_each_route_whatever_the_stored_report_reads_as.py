"""Each route is asked and its answer compared whether or not the stored report types.

The stored run's report does not read as the tree's model (its confidence is
not a number), so the API answers the routes that type it with an error. A
repository of the test's own holds this checkout's platform; its second
commit changes only the error the Markdown route answers. What that route
served is a difference, and the comparison ends with the differences status
whether or not surfaces both refs lack alike are accepted. Every route that
types the report is asked all the same: its status, its headers and its body
are units, and its headers file is written.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import (
    commit_edits,
    platform_repository,
    report,
    stored_run,
)

REPORTS = "apps/api/app/api/v1/reports.py"
EDITS: tuple[tuple[str, str, str], ...] = (
    (
        REPORTS,
        'detail="Report not found or markdown could not be rendered",',
        'detail="The Markdown is gone",',
    ),
)
# The routes whose answer the API builds from the typed report.
TYPED_ROUTES: tuple[str, ...] = (
    "report.md",
    "report.html",
    "misp-event.json",
    "evidence-bundle.json",
    "evidence-bundle.html",
)


def _untyped() -> dict[str, Any]:
    stored = report()
    stored["overall_confidence"] = "not-a-number"
    return stored


@pytest.fixture(scope="module")
def compared(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    at = tmp_path_factory.mktemp("untyped")
    repo, first = platform_repository(at)
    second = commit_edits(repo, EDITS)
    run = stored_run(at, malware_report=_untyped())
    out = at / "diff.json"
    work = at / "work"
    argv = [str(run), "--repo", str(repo), "--work", str(work), "--mode", "serve"]
    argv += ["--compare", first, second, "--json", str(out), "--quiet"]
    plain = rs.main(argv)
    accepted = rs.main([*argv, "--accept-not-compared"])
    [diff] = json.loads(out.read_text(encoding="utf-8"))["runs"]
    [record] = json.loads((work / "a-out" / rs.RECORD_FILE).read_text(encoding="utf-8"))
    return {
        "plain": plain,
        "accepted": accepted,
        "diff": diff,
        "record": record,
        "files": work / "a-out" / record["files"] / "serve",
    }


@pytest.mark.slow
def test_an_error_a_route_answers_for_an_untyped_report_is_compared(
    compared: dict[str, Any],
) -> None:
    found = [
        c
        for c in compared["diff"]["changes"]
        if c["surface"] == rs.HTTP_SURFACE and c["key"] == "GET /reports/{id}/markdown body"
    ]
    assert len(found) == 1, [c["key"] for c in compared["diff"]["changes"]]
    assert "markdown could not be rendered" in found[0]["old"]
    assert "The Markdown is gone" in found[0]["new"]
    assert compared["plain"] == compared["accepted"] == rs.EXIT_UNEXPECTED


@pytest.mark.slow
def test_every_route_that_types_the_report_is_asked_when_it_does_not_type(
    compared: dict[str, Any],
) -> None:
    keys = {row["key"] for row in compared["record"]["units"] if row["surface"] == rs.HTTP_SURFACE}
    for file in TYPED_ROUTES:
        label = rs.request_label(file)
        assert f"{label} status" in keys and f"{label} body" in keys, file
        assert any(k.startswith(f"{label} header ") for k in keys), file
        assert (compared["files"] / f"{file}.headers").is_file(), file
