"""A caller that brings its own driver writes out a ref from before the replay tool.

``compare.materialise`` with ``harness=None`` writes a ref that has no replay
harness out of the object store, as the surface render does; by default such a
ref still raises ``PredatesTheReplay``. A path of the archive list the ref does
not hold (the API, the replay, ``data/samples``) is left out, and nothing
outside the list is written: an exclusion whose path is absent is not passed
alone, which would archive everything else.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.replay import compare

from tests.unit.scripts._surfaces_render_run import git


@pytest.fixture
def old_ref(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "old"
    for name, text in (
        ("pyproject.toml", "[project]\nname = 'old'\n"),
        ("src/malspark/__init__.py", ""),
        ("data/table.json", "{}"),
        ("README.md", "not archived"),
    ):
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    git(repo, "init", "--quiet")
    git(repo, "add", "--", ".")
    git(repo, "commit", "--quiet", "-m", "before the replay tool")
    return repo, git(repo, "rev-parse", "HEAD")


def test_the_default_still_refuses_a_ref_without_the_harness(
    old_ref: tuple[Path, str], tmp_path: Path
) -> None:
    repo, ref = old_ref
    with pytest.raises(compare.PredatesTheReplay):
        compare.materialise(repo, ref, tmp_path / "tree")


def test_a_caller_with_its_own_driver_writes_the_ref_out_and_only_what_it_holds(
    old_ref: tuple[Path, str], tmp_path: Path
) -> None:
    repo, ref = old_ref
    tree = compare.materialise(repo, ref, tmp_path / "tree", harness=None)
    written = sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file())
    assert written == ["data/table.json", "pyproject.toml", "src/malspark/__init__.py"]
