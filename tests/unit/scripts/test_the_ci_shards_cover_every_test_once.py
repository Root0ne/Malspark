"""The CI shards together run every test file once, and the workflows run every shard.

``scripts/ci/shard_map.py`` splits the suite for the parallel test jobs. The
CI job "Test shard map" compares collected node ids; these tests hold the map
itself: a test file added anywhere lands in exactly one shard, and each
workflow's matrix lists every shard the script defines.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "ci" / "shard_map.py"


def _module():
    spec = importlib.util.spec_from_file_location("shard_map", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


shard_map = _module()


def _covering(paths: list[str], test_file: str) -> list[str]:
    return [p for p in paths if test_file == p or test_file.startswith(f"{p}/")]


@pytest.mark.parametrize(
    ("path", "unit"),
    [
        ("tests/unit/agents/test_x.py", "tests/unit/agents"),
        ("tests/unit/agents/deeper/test_x.py", "tests/unit/agents"),
        ("tests/unit/test_x.py", "tests/unit/test_*.py"),
        ("tests/api/test_x.py", "tests/api"),
        ("tests/integration/sub/test_x.py", "tests/integration"),
        ("tests/test_x.py", "tests/test_*.py"),
    ],
)
def test_each_test_file_has_one_unit(path: str, unit: str) -> None:
    assert shard_map.unit_of(path) == unit


@pytest.mark.parametrize("suite_name", sorted(shard_map.SUITES))
def test_every_test_file_in_the_tree_is_in_exactly_one_shard(suite_name: str) -> None:
    suite = shard_map.SUITES[suite_name]
    shards = [shard_map.shard_paths(suite, n) for n in range(1, suite.shards + 1)]
    assert all(shards)
    every = [path for paths in shards for path in paths]
    assert len(every) == len(set(every))
    files = shard_map.suite_files(ROOT, suite.roots)
    assert files
    for test_file in files:
        assert len(_covering(every, test_file)) == 1, test_file


def test_a_directory_or_file_added_later_lands_in_a_shard(tmp_path: Path) -> None:
    for name in (
        "tests/unit/agents/test_a.py",
        "tests/unit/test_loose.py",
        "tests/unit/brand_new/test_b.py",
        "tests/new_suite/test_c.py",
        "tests/test_top.py",
        "tests/unit/brand_new/helpers.py",
        "tests/unit/brand_new/__pycache__/test_b.py",
    ):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("")
    suite = shard_map.Suite(roots=("tests",), shards=3)
    every = [p for n in (1, 2, 3) for p in shard_map.shard_paths(suite, n, tmp_path)]
    assert sorted(every) == sorted(
        [
            "tests/unit/agents",
            "tests/unit/test_loose.py",
            "tests/unit/brand_new",
            "tests/new_suite",
            "tests/test_top.py",
        ]
    )


def test_the_placement_is_longest_first_and_stable() -> None:
    keys = list(shard_map.WEIGHTS)
    placed = shard_map.assign(keys, 3)
    assert placed == shard_map.assign(list(reversed(keys)), 3)
    assert sorted(k for shard in placed for k in shard) == sorted(keys)
    heaviest = max(keys, key=lambda k: shard_map.WEIGHTS[k])
    assert placed[0][0] == heaviest


def test_a_shard_outside_the_suite_is_refused() -> None:
    suite = shard_map.SUITES["linux"]
    with pytest.raises(SystemExit):
        shard_map.shard_paths(suite, suite.shards + 1)
    with pytest.raises(SystemExit):
        shard_map.shard_paths(suite, 0)


@pytest.mark.parametrize(
    ("workflow", "job", "suite_name"),
    [("ci.yml", "test-shard", "linux"), ("macos.yml", "test-macos-shard", "macos")],
)
def test_each_workflow_runs_every_shard_of_its_suite(
    workflow: str, job: str, suite_name: str
) -> None:
    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())["jobs"]
    shards = shard_map.SUITES[suite_name].shards
    assert jobs[job]["strategy"]["matrix"]["shard"] == list(range(1, shards + 1))
    assert jobs[job]["name"].endswith(f"/{shards})")
    assert f"--suite {suite_name} --shard" in str(jobs[job]["steps"])


@pytest.mark.parametrize(
    ("workflow", "job", "name", "needs"),
    [
        ("ci.yml", "test", "Test Suite (Python 3.13)", ["test-shard", "test-shard-map"]),
        (
            "macos.yml",
            "test-macos",
            "Test Suite (macOS arm64)",
            ["test-macos-shard", "test-macos-shard-map"],
        ),
    ],
)
def test_the_suite_check_passes_only_when_every_shard_and_the_map_passed(
    workflow: str, job: str, name: str, needs: list[str]
) -> None:
    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())["jobs"]
    check = jobs[job]
    assert check["name"] == name
    assert check["needs"] == needs
    assert check["if"] == "always()"
    script = check["steps"][-1]["run"]
    for needed in needs:
        variable = next(k for k, v in check["steps"][-1]["env"].items() if needed + ".result" in v)
        assert f'test "${variable}" = success' in script


@pytest.mark.parametrize(
    ("shard_two", "code", "said"),
    [
        (["tests/b/test_b.py::t"], 0, ""),
        ([], 1, "in no shard: tests/b/test_b.py::t"),
        (["tests/b/test_b.py::t", "tests/a/test_a.py::t"], 1, "run twice"),
    ],
)
def test_the_map_check_fails_a_test_missing_or_run_twice(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    shard_two: list[str],
    code: int,
    said: str,
) -> None:
    collected = {
        ("tests",): ["tests/a/test_a.py::t", "tests/b/test_b.py::t"],
        ("tests/a",): ["tests/a/test_a.py::t"],
        ("tests/b",): shard_two,
    }
    monkeypatch.setattr(shard_map, "collect", lambda paths, root: collected[tuple(paths)])
    monkeypatch.setattr(
        shard_map, "shard_paths", lambda suite, n, root: [("tests/a", "tests/b")[n - 1]]
    )
    assert shard_map.check(shard_map.Suite(roots=("tests",), shards=2)) == code
    assert said in capsys.readouterr().out
