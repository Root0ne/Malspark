"""The CI shards together run every test file once, and the workflows run every shard.

``scripts/ci/shard_map.py`` splits the suite for the parallel test jobs. The
CI job "Test shard map" compares collected node ids; these tests hold the map
itself: a test file added anywhere lands in exactly one shard, and each
workflow's matrix lists every shard the script defines.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from defusedxml import ElementTree

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


def _jobs(workflow: str) -> dict:
    return yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())["jobs"]


def _shard_step(job: dict) -> str:
    (run,) = [step["run"] for step in job["steps"] if "--shard" in step.get("run", "")]
    return run


@pytest.mark.parametrize(
    ("workflow", "job", "suite_name"),
    [("ci.yml", "test-shard", "linux"), ("macos.yml", "test-macos-shard", "macos")],
)
def test_each_workflow_runs_every_shard_of_its_suite(
    workflow: str, job: str, suite_name: str
) -> None:
    shard_job = _jobs(workflow)[job]
    shards = shard_map.SUITES[suite_name].shards
    assert shard_job["strategy"]["matrix"] == {"shard": list(range(1, shards + 1))}
    assert shard_job["name"].endswith(f"/{shards})")
    run = _shard_step(shard_job)
    assert f'--suite {suite_name} --shard "$SHARD" > "$RUNNER_TEMP/shard-paths"' in run
    assert 'test -s "$RUNNER_TEMP/shard-paths"' in run
    # Every test the shard's paths hold runs: no selection narrows them.
    assert 'pytest "${paths[@]}" -q --tb=short' in run
    assert " -k " not in run and " -m " not in run


def test_the_linux_shards_run_after_the_quality_gate_on_the_named_python() -> None:
    jobs = _jobs("ci.yml")
    shard_job = jobs["test-shard"]
    assert shard_job["needs"] == "quality"
    assert shard_job["name"].startswith("Tests (3.13, shard ")
    (setup,) = [s for s in shard_job["steps"] if "setup-python" in s.get("uses", "")]
    assert setup["with"]["python-version"] == "3.13"
    assert jobs["test"]["name"] == "Test Suite (Python 3.13)"


def test_the_macos_shards_keep_the_hang_report_and_the_library_path() -> None:
    run = _shard_step(_jobs("macos.yml")["test-macos-shard"])
    assert "-o faulthandler_timeout=600" in run
    assert 'DYLD_FALLBACK_LIBRARY_PATH="$(brew --prefix)/lib"' in run


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
    check = _jobs(workflow)[job]
    assert check["name"] == name
    assert check["needs"] == needs
    assert check["if"] == "always()"
    (step,) = check["steps"]
    assert step["env"] == {
        "SHARDS": f"${{{{ needs.{needs[0]}.result }}}}",
        "SHARD_MAP": f"${{{{ needs.{needs[1]}.result }}}}",
    }
    assert step["run"] == (
        'echo "shards: $SHARDS, shard map: $SHARD_MAP"\n'
        'test "$SHARDS" = success\n'
        'test "$SHARD_MAP" = success\n'
    )


def test_the_weights_are_read_from_a_junit_report_of_the_tree(tmp_path: Path) -> None:
    files = {
        "tests/unit/test_loose.py": (
            "class lowercase_cases:\n    def test_a(self):\n        pass\n\n"
            "def test_b():\n    pass\n"
        ),
        "tests/unit/agents/test_deep.py": (
            "class TestUpper:\n    class TestInner:\n        def test_c(self):\n            pass\n"
        ),
        "tests/api/test_api.py": "def test_d():\n    pass\n",
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    report = tmp_path / "junit.xml"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-o",
            "junit_family=xunit2",
            "-o",
            "python_classes=Test* lowercase*",
            f"--junitxml={report}",
            "tests",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    classnames = {c.get("classname") for c in ElementTree.parse(report).iter("testcase")}
    assert "tests.unit.test_loose.lowercase_cases" in classnames
    assert "tests.unit.agents.test_deep.TestUpper.TestInner" in classnames
    weights = shard_map.weigh([report], tmp_path)
    assert sorted(weights) == ["tests/api", "tests/unit/agents", "tests/unit/test_*.py"]


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
