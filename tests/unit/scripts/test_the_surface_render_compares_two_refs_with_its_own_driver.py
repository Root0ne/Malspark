"""The surface render compares two git refs, running this checkout's driver against each tree.

A repository of the test's own holds this checkout's platform as its working
tree has it (``pyproject.toml``, ``src``, ``data`` with a placeholder under
``data/samples``, ``apps/api``) and no ``scripts/replay``: a ref from before
the render tool. Its second commit rewords one sentence the evidence bundle
prints. ``--compare`` writes each ref out of the object store and runs this
checkout's driver against it with that tree first on the import path: the
first commit against itself renders the same; against the second, the one
sentence is the one change (status 1), an expectation naming it makes the
status 0, and the build mode, which needs the tree's replay, is a surface not
produced with the reason on both sides.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404 — git, argument lists only
from pathlib import Path

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import stored_run

ROOT = Path(__file__).resolve().parents[3]
SENTENCE_FILE = "src/malspark/reporting/renderers/bundle.py"
OLD = "_The record behind the analyst report of the same name"
NEW = "_The evidence behind the analyst report of the same name"
# A commit of the test's own needs a name, and no hook or signing of the
# machine's may run on it.
GIT = (
    "-c",
    "user.name=Render Test",
    "-c",
    "user.email=render-test@example.invalid",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "commit.gpgsign=false",
)


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        ["git", *GIT, "-C", str(repo), *args], capture_output=True, check=True
    )
    return done.stdout.decode().strip()


def _working_tree_files() -> list[str]:
    if shutil.which("git") is None:
        pytest.skip("git is not on this machine")
    listed = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "pyproject.toml",
            "src",
            "data",
            ":(exclude)data/samples",
            "apps/api/app",
        ],
        capture_output=True,
        check=False,
    )
    if listed.returncode != 0:
        pytest.skip("this checkout is not a git repository")
    names = [name for name in listed.stdout.decode().split("\0") if name]
    return [name for name in names if (ROOT / name).is_file()]


def _repository(at: Path) -> tuple[Path, str, str]:
    repo = at / "platform"
    for name in _working_tree_files():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, repo / name)
    placeholder = repo / "data" / "samples" / "placeholder.json"
    placeholder.parent.mkdir(parents=True, exist_ok=True)
    placeholder.write_text("{}", encoding="utf-8")
    _git(repo, "init", "--quiet")
    _git(repo, "add", "--", ".")
    _git(repo, "commit", "--quiet", "-m", "the platform")
    first = _git(repo, "rev-parse", "HEAD")
    target = repo / SENTENCE_FILE
    text = target.read_text(encoding="utf-8")
    assert OLD in text
    target.write_text(text.replace(OLD, NEW), encoding="utf-8")
    _git(repo, "commit", "--quiet", "--all", "-m", "a sentence reworded")
    return repo, first, _git(repo, "rev-parse", "HEAD")


@pytest.mark.slow
def test_each_tree_is_rendered_by_this_driver_and_the_one_sentence_is_the_one_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo, first, second = _repository(tmp_path)
    run = stored_run(tmp_path)
    work = tmp_path / "work"
    argv = [str(run), "--repo", str(repo), "--work", str(work)]

    assert rs.main([*argv, "--compare", first, first]) == 0
    printed = capsys.readouterr().out
    assert "no difference: both refs render the same units" in printed
    # The build mode needs the tree's replay, which these refs predate: said on both sides.
    assert "NOT COMPARED [build report.md]" in printed
    assert "this tree has no replay build to rebuild the report with" in printed
    record = json.loads((work / "a-out" / rs.RECORD_FILE).read_text(encoding="utf-8"))[0]
    assert Path(record["tree"]) == (work / "a-tree").resolve()
    assert (work / "a-tree" / "apps" / "api" / "app").is_dir()
    assert not (work / "a-tree" / "scripts").exists()

    out = tmp_path / "diff.json"
    assert rs.main([*argv, "--compare", first, second, "--json", str(out), "--quiet"]) == 1
    [diff] = json.loads(out.read_text(encoding="utf-8"))["runs"]
    [change] = diff["changes"]
    assert (change["mode"], change["surface"], change["change"]) == (
        "serve",
        "bundle.notes",
        "changed",
    )
    assert change["old"].startswith(OLD) and change["new"].startswith(NEW)

    expect = tmp_path / "expect.json"
    expect.write_text(
        json.dumps(
            [
                {
                    "surface": "bundle.notes",
                    "old": "^_The record behind",
                    "new": "^_The evidence behind",
                    "reason": "the bundle's opening line is reworded",
                }
            ]
        ),
        encoding="utf-8",
    )
    assert rs.main([*argv, "--compare", first, second, "--expect", str(expect)]) == 0
    assert "CHANGED expected" in capsys.readouterr().out
