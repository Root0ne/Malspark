"""Split the test suite into CI shards of about equal duration.

A shard's unit is a directory directly below ``tests/`` or ``tests/unit/``,
or the group of test files lying directly in one of those two. Every test file
in the tree falls in exactly one unit, so a test added later lands in a shard
without an edit here: a new file joins the unit of its directory or of the
loose files beside it, and a new directory is a unit of its own. A unit not in
``WEIGHTS`` (a new directory, or the first loose file directly in ``tests/``)
is placed with ``UNMEASURED`` seconds until the table is rebalanced. Units are
placed longest first, each on the shard with the least time so far (ties go to
the lower shard number), which makes the map a pure function of the tree and
the table.

    shard_map.py --suite linux --shard 3   the paths shard 3 of 6 runs
    shard_map.py --suite linux --list      every shard with its units and seconds
    shard_map.py --suite linux --check     fails unless the shards together collect
                                           every test of the suite exactly once
    shard_map.py --weigh junit-*.xml       a WEIGHTS table from the shards' JUnit reports

The workflows' shard matrices must list 1..``Suite.shards``; a unit test holds
them to it.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import NamedTuple

from defusedxml import ElementTree

ROOT = Path(__file__).resolve().parents[2]

# Directories whose children are units rather than the directory itself.
SPLIT = ("tests", "tests/unit")

# The key of the unit made of the test files lying directly in a SPLIT directory.
LOOSE_FILES = "test_*.py"

# pytest's default ``python_files``; pyproject.toml does not change it.
TEST_FILE_PATTERNS = ("test_*.py", "*_test.py")

# Seconds per unit on ubuntu-latest, from the serial run of the suite on dev at
# 1f1f7c3c (CI run 42397638675). The macOS shards are balanced on the same
# table: that runner's times per unit keep about the same proportions.
WEIGHTS: dict[str, float] = {
    "tests/integration": 905,
    "tests/unit/pipeline": 883,
    "tests/unit/agents": 438,
    "tests/unit/api": 415,
    "tests/unit/test_*.py": 380,
    "tests/unit/reporting": 373,
    "tests/unit/core": 352,
    "tests/unit/providers": 284,
    "tests/unit/tools": 276,
    "tests/unit/servers": 167,
    "tests/unit/llm": 152,
    "tests/unit/scripts": 150,
    "tests/unit/analysis": 136,
    "tests/api": 80,
    "tests/unit/memory": 34,
    "tests/unit/extractors": 32,
    "tests/unit/enrichment": 4,
    "tests/unit/loaders": 2,
    "tests/unit/schemas": 2,
    "tests/unit/parsers": 1,
    "tests/unit/utils": 1,
}

# The weight of a unit the table does not name yet.
UNMEASURED = 60.0


class Suite(NamedTuple):
    roots: tuple[str, ...]
    shards: int


SUITES = {
    # ci.yml: the whole suite on ubuntu-latest.
    "linux": Suite(roots=("tests",), shards=6),
    # macos.yml: the unit and API suites on macos-15. Four shards and the map
    # check fill the five macOS runners an account runs at once.
    "macos": Suite(roots=("tests/unit", "tests/api"), shards=4),
}


def _is_test_file(path: Path) -> bool:
    return any(path.match(pattern) for pattern in TEST_FILE_PATTERNS)


def suite_files(root: Path = ROOT, roots: tuple[str, ...] = ("tests",)) -> list[str]:
    """Every test file below ``roots``, relative to ``root``, in a stable order."""
    found: set[str] = set()
    for top in roots:
        for path in (root / top).rglob("*.py"):
            if "__pycache__" not in path.parts and _is_test_file(path):
                found.add(path.relative_to(root).as_posix())
    return sorted(found)


def unit_of(path: str) -> str:
    """The unit a test file belongs to: see the module docstring."""
    parts = path.split("/")
    key = parts[0]
    depth = 1
    while key in SPLIT:
        if depth == len(parts) - 1:
            return f"{key}/{LOOSE_FILES}"
        key = f"{key}/{parts[depth]}"
        depth += 1
    return key


def units(root: Path = ROOT, roots: tuple[str, ...] = ("tests",)) -> dict[str, list[str]]:
    """Each unit below ``roots`` with the paths pytest is given to run it."""
    grouped: dict[str, list[str]] = {}
    for path in suite_files(root, roots):
        key = unit_of(path)
        if key.endswith(f"/{LOOSE_FILES}"):
            grouped.setdefault(key, []).append(path)
        else:
            grouped[key] = [key]
    return grouped


def assign(unit_keys: list[str], shards: int) -> list[list[str]]:
    """Longest unit first, each on the least loaded shard; the lower shard wins a tie."""
    loads = [0.0] * shards
    placed: list[list[str]] = [[] for _ in range(shards)]
    for key in sorted(unit_keys, key=lambda k: (-WEIGHTS.get(k, UNMEASURED), k)):
        index = min(range(shards), key=lambda i: (loads[i], i))
        placed[index].append(key)
        loads[index] += WEIGHTS.get(key, UNMEASURED)
    return placed


def shard_paths(suite: Suite, shard: int, root: Path = ROOT) -> list[str]:
    """The paths shard ``shard`` (1-based) of ``suite`` hands pytest."""
    if not 1 <= shard <= suite.shards:
        raise SystemExit(f"shard {shard} is outside 1..{suite.shards}")
    grouped = units(root, suite.roots)
    keys = assign(list(grouped), suite.shards)[shard - 1]
    if not keys:
        # pytest given no path would run its whole test path: never hand it none.
        raise SystemExit(f"shard {shard} of {suite.shards} has no unit")
    return [path for key in keys for path in grouped[key]]


def collect(paths: list[str], root: Path = ROOT) -> list[str]:
    """The node ids ``pytest --collect-only`` finds under ``paths``."""
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *paths],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        sys.stderr.write(done.stdout + done.stderr)
        raise SystemExit(f"collecting {' '.join(paths)} failed with exit code {done.returncode}")
    return [line.rstrip("\n") for line in done.stdout.splitlines() if "::" in line]


def check(suite: Suite, root: Path = ROOT) -> int:
    """0 when the shards together collect every test of the suite exactly once."""
    full = Counter(collect(list(suite.roots), root))
    sharded: Counter[str] = Counter()
    for shard in range(1, suite.shards + 1):
        ids = collect(shard_paths(suite, shard, root), root)
        print(f"shard {shard}/{suite.shards}: {len(ids)} tests")
        sharded.update(ids)
    missing = sorted(full - sharded)
    extra = sorted(sharded - full)
    print(f"full collection: {sum(full.values())} tests; shards together: {sum(sharded.values())}")
    for node in missing:
        print(f"in no shard: {node}")
    for node in extra:
        print(f"run twice or outside the suite: {node}")
    return 1 if missing or extra else 0


def weigh(reports: list[Path], root: Path = ROOT) -> dict[str, float]:
    """Seconds per unit summed from JUnit reports (``pytest --junitxml``).

    A test case's ``classname`` is its module's dotted path followed by any
    class names. The module is the longest dotted prefix that names a test
    file in the tree, which holds whatever case the class names are in. A case
    whose module is no longer in the tree is named on stderr and left out.
    """
    modules = {path.removesuffix(".py").replace("/", "."): path for path in suite_files(root)}
    seconds: dict[str, float] = {}
    for report in reports:
        for case in ElementTree.parse(report).iter("testcase"):
            file = case.get("file") or ""
            if not file:
                parts = (case.get("classname") or "").split(".")
                prefixes = (".".join(parts[:end]) for end in range(len(parts), 0, -1))
                file = next((modules[p] for p in prefixes if p in modules), "")
            if not file:
                sys.stderr.write(f"no test file in the tree for {case.get('classname')}\n")
                continue
            key = unit_of(file)
            seconds[key] = seconds.get(key, 0.0) + float(case.get("time") or 0)
    return dict(sorted(seconds.items(), key=lambda item: (-item[1], item[0])))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--suite", choices=sorted(SUITES), default="linux")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--shard", type=int, help="print the paths of this shard (1-based)")
    action.add_argument("--list", action="store_true", help="print every shard's units")
    action.add_argument("--check", action="store_true", help="compare the shards to the suite")
    action.add_argument("--weigh", nargs="+", type=Path, metavar="JUNIT_XML")
    args = parser.parse_args()
    suite = SUITES[args.suite]

    if args.shard is not None:
        print("\n".join(shard_paths(suite, args.shard)))
        return 0
    if args.list:
        for number, keys in enumerate(assign(list(units(ROOT, suite.roots)), suite.shards), 1):
            total = sum(WEIGHTS.get(key, UNMEASURED) for key in keys)
            print(f"shard {number}/{suite.shards}: {total:.0f} s")
            for key in keys:
                measured = "" if key in WEIGHTS else " (unmeasured)"
                print(f"  {WEIGHTS.get(key, UNMEASURED):6.0f} {key}{measured}")
        return 0
    if args.check:
        return check(suite)
    for key, value in weigh(args.weigh).items():
        print(f'    "{key}": {value:.0f},')
    return 0


if __name__ == "__main__":
    sys.exit(main())
