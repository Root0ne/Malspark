"""The surface render compares two git refs, running this checkout's driver against each tree.

A repository of the test's own holds this checkout's platform as its working
tree has it (``pyproject.toml``, ``src``, ``data`` with a placeholder under
``data/samples``, ``apps/api``) and no ``scripts/replay``: a ref from before
the render tool. Its second commit rewords one sentence the evidence bundle
prints. ``--compare`` writes each ref out of the object store and runs this
checkout's driver against it with that tree first on the import path: the
first commit against itself renders the same units, and the build mode, which
needs the tree's replay, is a surface produced by neither ref, listed with the
reason on both sides and ending the comparison with its own status unless it is
accepted; against the second, the one sentence is the one change (status 1),
and an expectation naming it makes the status 0.
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

SENTENCE_FILE = "src/malspark/reporting/renderers/bundle.py"
OLD = "_The record behind the analyst report of the same name"
NEW = "_The evidence behind the analyst report of the same name"


def _repository(at: Path) -> tuple[Path, str, str]:
    repo, first = platform_repository(at)
    return repo, first, commit_edits(repo, [(SENTENCE_FILE, OLD, NEW)])


@pytest.mark.slow
def test_each_tree_is_rendered_by_this_driver_and_the_one_sentence_is_the_one_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo, first, second = _repository(tmp_path)
    run = stored_run(tmp_path)
    work = tmp_path / "work"
    argv = [str(run), "--repo", str(repo), "--work", str(work)]

    assert rs.main([*argv, "--compare", first, first]) == rs.EXIT_NOT_COMPARED
    printed = capsys.readouterr().out
    # The build mode needs the tree's replay, which these refs predate: said on both sides,
    # and never read as no difference.
    assert "NOT COMPARED [build report.md]: produced by neither ref" in printed
    assert "this tree has no replay build to rebuild the report with" in printed
    assert "no difference: both refs render the same units" not in printed
    assert "no difference in the units compared" in printed
    assert rs.main([*argv, "--compare", first, first, "--accept-not-compared"]) == 0
    capsys.readouterr()
    record = json.loads((work / "a-out" / rs.RECORD_FILE).read_text(encoding="utf-8"))[0]
    assert Path(record["tree"]) == (work / "a-tree").resolve()
    assert (work / "a-tree" / "apps" / "api" / "app").is_dir()
    assert not (work / "a-tree" / "scripts").exists()

    out = tmp_path / "diff.json"
    assert (
        rs.main(
            [*argv, "--compare", first, second, "--json", str(out), "--quiet"]
            + ["--accept-not-compared"]
        )
        == 1
    )
    [diff] = json.loads(out.read_text(encoding="utf-8"))["runs"]
    [change] = diff["changes"]
    assert (change["mode"], change["surface"], change["change"]) == (
        "serve",
        "bundle.lines",
        "changed",
    )
    assert change["old"].startswith(OLD) and change["new"].startswith(NEW)

    expect = tmp_path / "expect.json"
    expect.write_text(
        json.dumps(
            [
                {
                    "surface": "bundle.lines",
                    "old": "^_The record behind",
                    "new": "^_The evidence behind",
                    "reason": "the bundle's opening line is reworded",
                }
            ]
        ),
        encoding="utf-8",
    )
    accepted = ["--accept-not-compared"]
    assert rs.main([*argv, "--compare", first, second, "--expect", str(expect), *accepted]) == 0
    assert "CHANGED expected" in capsys.readouterr().out
