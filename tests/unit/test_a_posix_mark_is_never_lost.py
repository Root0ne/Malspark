"""A test marked ``posix`` keeps the mark it was given.

A module's ``pytestmark`` assigned twice keeps only the second value, so a
module marked ``posix`` and then given a ``skipif`` loses the first without a
word. No scope of a test module assigns it twice, and every test of a module
marked ``posix`` as a whole is collected with the mark.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"


def _modules() -> list[Path]:
    return sorted(path for path in TESTS.rglob("*.py") if "fixtures" not in path.parts)


def _assigns_pytestmark(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Assign):
        return any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in statement.targets)
    if isinstance(statement, ast.AnnAssign | ast.AugAssign):
        return isinstance(statement.target, ast.Name) and statement.target.id == "pytestmark"
    return False


def _scopes(tree: ast.Module) -> list[list[ast.stmt]]:
    return [tree.body] + [node.body for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]


def test_no_scope_assigns_pytestmark_twice() -> None:
    twice = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for body in _scopes(tree):
            if sum(_assigns_pytestmark(statement) for statement in body) > 1:
                twice.append(path.relative_to(ROOT).as_posix())
    assert twice == []


def _marked_whole() -> list[str]:
    """The modules whose ``pytestmark`` names ``posix``."""
    marked = []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for statement in tree.body:
            if _assigns_pytestmark(statement) and "mark.posix" in ast.unparse(statement):
                marked.append(path.relative_to(ROOT).as_posix())
    return marked


def test_every_test_of_a_module_marked_posix_carries_the_mark() -> None:
    modules = _marked_whole()
    assert modules, "a module marked posix as a whole is what this holds to its mark"
    finished = subprocess.run(  # noqa: S603 - this interpreter, pytest, the suite's own files
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "-m",
            "not posix",
            *modules,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    # Every test deselected: pytest's "no tests collected" exit status.
    assert finished.returncode == 5, finished.stdout[-4000:]
    assert "::" not in finished.stdout
