"""The replay's comparison writes its differences as canonical lines and takes an approved file.

Each difference is one line built from both records' values, naming the run by
its path under the stored runs' root, which ``--lines`` and ``--expect``
require, so two different differences never give one line and two runs of one
name never share one. ``--lines`` writes them to a file outside the
repository; ``--expect`` compares them with a file as a multiset, exactly, and
is never taken without ``--expect-sha256``, which refuses a file whose digest
is not the approved one. ``--lines`` and ``--expect`` never name one file. An
error, a part that raised, a partial comparison and two schemas are never
expected: whatever the file says, the status is then 2.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess  # nosec B404 — this interpreter, an argument list only
import sys
from pathlib import Path, PureWindowsPath
from typing import Any, cast

import pytest
from scripts.replay import compare
from scripts.replay import run as replay_cli
from scripts.replay.compare import diff_records, difference_lines, read_expected, run_label
from scripts.replay.rules import replay_run
from scripts.replay.stored import read_run

from tests.unit.scripts._replay_tiny import FIXTURE

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def record() -> dict[str, Any]:
    return replay_run(read_run(FIXTURE))


def _moved(record: dict[str, Any]) -> dict[str, Any]:
    moved = copy.deepcopy(record)
    moved["judge"]["flags"].append({"code": "stix.malformed_hash", "path": "objects[9]"})
    moved["report"]["severity"] = "High"
    moved["report"]["sections"] = list(reversed(moved["report"]["sections"]))
    return moved


def _compare_with(monkeypatch: pytest.MonkeyPatch, a: dict[str, Any], b: dict[str, Any]) -> None:
    monkeypatch.setattr(compare, "materialise", lambda _repo, _ref, into: into)
    monkeypatch.setattr(
        compare,
        "replay_under",
        lambda _tree, _runs, out, **_kwargs: [a if out.name.startswith("a-") else b],
    )


def _main(tmp_path: Path, *extra: str, root: Path | None = FIXTURE.parent) -> int:
    argv = [str(FIXTURE), "--compare", "A-ref", "B-ref", "--repo", str(tmp_path)]
    if root is not None:
        argv += ["--runs-root", str(root)]
    return replay_cli.main([*argv, "--work", str(tmp_path / "work"), *extra])


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"this platform refuses to create a symbolic link ({exc.strerror})")


def _dot_dot(start: Path, target: Path) -> Path:
    """``target`` spelled from ``start`` through ``..``; from inside ``target`` where the two
    sit on different drives, which no relative path joins."""
    if start.drive.casefold() == target.drive.casefold():
        return start / os.path.relpath(target, start)
    return target / "tests" / "unit" / ".." / ".."


def _ended(tmp_path: Path, *extra: str, root: Path | None = FIXTURE.parent) -> int:
    with pytest.raises(SystemExit) as ended:
        _main(tmp_path, *extra, root=root)
    return int(ended.value.code or 0)


class TestTheLines:
    def test_a_line_holds_both_values_and_two_reorders_give_two_lines(self) -> None:
        def lines(b: list[str]) -> list[str]:
            a: dict[str, Any] = {
                "schema": 5,
                "report": {"replayed": True, "sections": ["x", "y", "z"]},
            }
            other = copy.deepcopy(a)
            other["report"]["sections"] = b
            return difference_lines(diff_records(a, other), "r1")

        swapped, reversed_ = lines(["y", "x", "z"]), lines(["z", "y", "x"])
        assert swapped == ['["r1","report.sections",null,["x","y","z"],["y","x","z"]]']
        assert swapped != reversed_

    def test_a_count_is_written_from_both_records(self, record: dict[str, Any]) -> None:
        one, two, three = (copy.deepcopy(record) for _ in range(3))
        extra = {"code": "stix.malformed_hash", "path": "objects[9]"}
        two["judge"]["flags"].append(extra)
        three["judge"]["flags"] += [extra, extra]
        first = difference_lines(diff_records(one, three), "r")
        second = difference_lines(diff_records(two, three), "r")
        assert first != second
        assert any(line.endswith(",0,2]") for line in first)
        assert any(line.endswith(",1,2]") for line in second)

    def test_two_runs_of_one_name_are_named_by_their_paths_under_the_root(
        self, tmp_path: Path
    ) -> None:
        first, second = tmp_path / "family-r1" / "1", tmp_path / "family-r2" / "1"
        for run in (first, second):
            run.mkdir(parents=True)
        assert [run_label(r, tmp_path) for r in (first, second)] == ["family-r1/1", "family-r2/1"]
        diff = {"run": "1", "tool": {"calls": {"a": 1, "b": 2}}}
        assert difference_lines(diff, "family-r1/1") != difference_lines(diff, "family-r2/1")
        with pytest.raises(compare.CompareError):
            run_label(tmp_path, first)

    def test_a_line_ending_or_a_hash_inside_a_value_stays_inside_its_quoted_field(self) -> None:
        diff = {"run": "r", "composer": {"not_written": {"only_a": ["x\n# y"], "only_b": []}}}
        [line] = difference_lines(diff, "r")
        assert "\n" not in line and not line.startswith("#")
        assert json.loads(line) == ["r", "composer.not_written", "x\n# y", True, False]

    def test_how_the_comparison_went_is_never_a_line(self) -> None:
        diff = {
            "run": "r",
            "errors": {"a": [{"part": "judge", "why": "boom", "error": True}], "b": []},
            "schema": {"a": 4, "b": 5},
            "not_compared": {"b": ["findings: words"]},
            "not_replayed": {"only_a": [{"part": "judge", "why": "boom"}], "only_b": []},
        }
        assert difference_lines(diff, "r") == []

    def test_the_lines_are_the_same_under_two_hash_seeds(self, tmp_path: Path) -> None:
        script = (
            "import copy, json\n"
            "from scripts.replay.compare import diff_records, difference_lines\n"
            "from scripts.replay.rules import replay_run\n"
            "from scripts.replay.stored import read_run\n"
            "from tests.unit.scripts._replay_tiny import FIXTURE\n"
            "a = replay_run(read_run(FIXTURE))\n"
            "b = copy.deepcopy(a)\n"
            "b['judge']['flags'] = b['judge']['flags'][1:]\n"
            "b['report']['export']['attack_patterns'] = ['T0001', 'T0002']\n"
            "b['environment']['settings_from_run'] = ['x.one', 'x.two', 'x.three']\n"
            "b['report']['techniques']['T1105'] = {'published': False, 'why': 'r'}\n"
            "print(json.dumps(difference_lines(diff_records(a, b), 'r')))\n"
        )
        said = []
        for seed in ("1", "2"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
            done = subprocess.run(  # nosec B603 — this interpreter, an argument list
                [sys.executable, "-c", script],
                env=env,
                cwd=tmp_path,
                capture_output=True,
                check=True,
                timeout=600,
            )
            said.append(done.stdout.decode().strip().splitlines()[-1])
        assert said[0] == said[1] and len(json.loads(said[0])) > 5


class TestTheExpectedFile:
    def test_the_written_lines_expected_are_clean_by_one_line(
        self,
        record: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        lines = tmp_path / "expected.txt"
        assert _main(tmp_path, "--lines", str(lines)) == 1
        written = lines.read_text(encoding="ascii").splitlines()
        assert len(written) >= 3 and all(json.loads(w)[0] == "tiny" for w in written)
        capsys.readouterr()
        digest = hashlib.sha256(lines.read_bytes()).hexdigest()
        assert _main(tmp_path, "--expect", str(lines), "--expect-sha256", digest) == 0
        said = [s for s in capsys.readouterr().out.splitlines() if s.startswith("replay:")]
        assert said == [f"replay: clean by {len(written)} approved line(s) with sha256 {digest}"]

    @pytest.mark.parametrize("edit", ["more", "fewer", "duplicate", "other", "crlf"])
    def test_any_other_multiset_of_lines_is_red(
        self,
        edit: str,
        record: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        lines = tmp_path / "expected.txt"
        _main(tmp_path, "--lines", str(lines), "--quiet")
        written = lines.read_text(encoding="ascii").splitlines()
        edited = {
            "more": [*written, '["tiny","tool.calls",null,1,2]'],
            "fewer": written[1:],
            "duplicate": [*written, written[0]],
            "other": [json.dumps([*json.loads(written[0])[:4], "other"]), *written[1:]],
            "crlf": [f"{w}\r" for w in written],
        }[edit]
        lines.write_bytes("".join(f"{w}\n" for w in edited).encode())
        capsys.readouterr()
        assert _main(tmp_path, "--expect", str(lines), "--expect-sha256", _sha(lines)) == 1
        out = capsys.readouterr().out
        assert "UNEXPECTED: " in out or "EXPECTED BUT ABSENT: " in out
        assert "clean by" not in out

    def test_reordered_lines_and_comments_are_the_same_multiset(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        lines = tmp_path / "expected.txt"
        _main(tmp_path, "--lines", str(lines), "--quiet")
        written = lines.read_text(encoding="ascii").splitlines()
        lines.write_bytes(("# approved\n" + "\n".join(reversed(written))).encode("ascii"))
        assert _main(tmp_path, "--expect", str(lines), "--expect-sha256", _sha(lines)) == 0

    def test_the_lines_file_ends_each_line_with_a_line_feed_alone(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The same lines give the same bytes, and so the same digest, wherever the file is
        # written.
        _compare_with(monkeypatch, record, _moved(record))
        lines = tmp_path / "lines.txt"
        _main(tmp_path, "--lines", str(lines), "--quiet")
        data = lines.read_bytes()
        assert data and b"\r" not in data and data.endswith(b"\n")
        produced = difference_lines(diff_records(record, _moved(record)), "tiny")
        assert data == "".join(f"{line}\n" for line in produced).encode("ascii")

    def test_an_empty_file_against_no_difference_is_clean(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _compare_with(monkeypatch, record, copy.deepcopy(record))
        empty = tmp_path / "empty.txt"
        empty.write_bytes(b"")
        assert _main(tmp_path, "--expect", str(empty), "--expect-sha256", _sha(empty)) == 0

    def test_a_missing_file_or_a_wrong_digest_is_an_error(
        self,
        record: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _compare_with(monkeypatch, record, copy.deepcopy(record))
        absent = str(tmp_path / "absent.txt")
        assert _ended(tmp_path, "--expect", absent, "--expect-sha256", "0" * 64) == 2
        assert "cannot be read" in capsys.readouterr().err
        empty = tmp_path / "empty.txt"
        empty.write_bytes(b"")
        assert _ended(tmp_path, "--expect", str(empty), "--expect-sha256", "0" * 64) == 2
        assert "not the approved" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "line",
        [
            '["tiny","errors",null,[],[{"part":"judge"}]]',
            '["tiny","not_compared",null,null,["findings: words"]]',
            '["tiny","schema",null,4,5]',
        ],
    )
    def test_a_file_expecting_how_the_comparison_went_is_refused(
        self, line: str, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _compare_with(monkeypatch, record, copy.deepcopy(record))
        expected = tmp_path / "expected.txt"
        expected.write_bytes(f"{line}\n".encode("ascii"))
        assert _ended(tmp_path, "--expect", str(expected), "--expect-sha256", _sha(expected)) == 2

    def test_a_partial_comparison_is_red_whatever_the_file_says(
        self,
        record: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        older = copy.deepcopy(_moved(record))
        older["schema"] = 4
        del older["report"]["detection_drafts"]
        _compare_with(monkeypatch, older, record)
        lines = tmp_path / "expected.txt"
        assert _main(tmp_path, "--lines", str(lines)) == 2
        produced = lines.read_text(encoding="ascii").splitlines()
        assert produced
        said = capsys.readouterr().out
        assert f"the parts it compared hold {len(produced)} difference line(s)" in said
        digest = hashlib.sha256(lines.read_bytes()).hexdigest()
        assert _main(tmp_path, "--expect", str(lines), "--expect-sha256", digest) == 2
        assert "clean by" not in capsys.readouterr().out
        # Without --expect the statuses are as they were: a partial comparison is 2.
        assert _main(tmp_path) == 2

    def test_a_part_that_raised_is_red_whatever_the_file_says(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        raised = copy.deepcopy(record)
        raised["not_replayed"] = [
            *raised["not_replayed"],
            {"part": "judge", "why": "RuntimeError at x.py:1 (f)", "error": True},
        ]
        _compare_with(monkeypatch, record, raised)
        lines = tmp_path / "expected.txt"
        assert _main(tmp_path, "--lines", str(lines), "--quiet") == 2
        assert _main(tmp_path, "--expect", str(lines), "--expect-sha256", _sha(lines)) == 2

    def test_lines_are_never_written_inside_the_repository(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        inside = ROOT / "replay-expected-lines.txt"
        assert _ended(tmp_path, "--lines", str(inside)) == 2
        assert not inside.exists()

    def test_the_options_go_with_a_comparison_only(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as ended:
            replay_cli.main([str(FIXTURE), "--expect", str(tmp_path / "x.txt")])
        assert ended.value.code == 2

    def test_read_expected_splits_at_a_line_feed_alone(self, tmp_path: Path) -> None:
        path = tmp_path / "e.txt"
        path.write_bytes(b'["r","a",null,1,2]\r\n# a comment\n["r","b",null,1,2]\n')
        lines, found = read_expected(path)
        assert lines == {'["r","a",null,1,2]\r': 1, '["r","b",null,1,2]': 1}
        assert found == hashlib.sha256(path.read_bytes()).hexdigest()


def _git_common_tree() -> Path:
    said = (
        subprocess.run(  # nosec B603 B607 — a fixed git argument list
            ["git", "-C", str(ROOT), "rev-parse", "--git-common-dir"],
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    common = Path(said) if Path(said).is_absolute() else ROOT / said
    return common.resolve().parent


class TestTheApproval:
    def test_an_expected_file_without_its_approved_digest_is_refused_in_one_line(
        self,
        record: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _compare_with(monkeypatch, record, copy.deepcopy(record))
        empty = tmp_path / "empty.txt"
        empty.write_bytes(b"")
        capsys.readouterr()
        assert _ended(tmp_path, "--expect", str(empty)) == 2
        said = capsys.readouterr()
        assert said.out == ""
        assert said.err.splitlines() == [
            "replay: refused: --expect is never taken without --expect-sha256, its approved digest"
        ]

    @pytest.mark.parametrize(
        ("first", "second"),
        [("--lines", "--expect"), ("--json", "--expect"), ("--json", "--lines")],
    )
    @pytest.mark.parametrize("spelling", ["same", "dot-dot", "relative", "symlink", "hardlink"])
    def test_two_options_naming_one_file_are_refused_before_anything_is_compared_or_written(
        self,
        first: str,
        second: str,
        spelling: str,
        record: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        replayed: list[str] = []
        _compare_with(monkeypatch, record, _moved(record))
        replay_under = compare.replay_under

        def counted(*args: Any, **kwargs: Any) -> Any:
            replayed.append("x")
            return replay_under(*args, **kwargs)

        monkeypatch.setattr(compare, "replay_under", counted)
        target = tmp_path / "approved" / "lines.txt"
        target.parent.mkdir()
        target.write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        other = {
            "same": target,
            "dot-dot": tmp_path / "approved" / ".." / "approved" / "lines.txt",
            "relative": Path("approved/lines.txt"),
            "symlink": tmp_path / "link.txt",
            "hardlink": tmp_path / "hard.txt",
        }[spelling]
        if spelling == "symlink":
            _symlink(other, target)
        if spelling == "hardlink":
            os.link(target, other)
        capsys.readouterr()
        argv = [first, str(other), second, str(target)]
        if "--expect" in argv:
            argv += ["--expect-sha256", _sha(target)]
        assert _ended(tmp_path, *argv) == 2
        said = capsys.readouterr()
        assert said.out == "" and replayed == []
        assert f"refused: {first} and {second} name one file" in said.err
        assert target.read_bytes() == b""

    def test_json_naming_the_approved_file_leaves_it_untouched(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        approved = tmp_path / "approved.txt"
        _main(tmp_path, "--lines", str(approved), "--quiet")
        before = approved.read_bytes()
        digest = _sha(approved)
        argv = ("--json", str(approved), "--expect", str(approved), "--expect-sha256", digest)
        assert _ended(tmp_path, *argv) == 2
        assert approved.read_bytes() == before

    def test_one_file_for_lines_and_expect_without_a_digest_ends_with_the_error_status(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        same = tmp_path / "f.txt"
        same.write_bytes(b"")
        assert _ended(tmp_path, "--lines", str(same), "--expect", str(same)) == 2
        assert same.read_bytes() == b""

    @pytest.mark.parametrize("option", ["--lines", "--expect"])
    def test_lines_and_expect_require_the_runs_root(
        self,
        option: str,
        record: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        path = tmp_path / "lines.txt"
        path.write_bytes(b"")
        extra = (option, str(path)) + (
            ("--expect-sha256", _sha(path)) if option == "--expect" else ()
        )
        assert _ended(tmp_path, *extra, root=None) == 2
        assert "--runs-root, which is required" in capsys.readouterr().err
        assert path.read_bytes() == b""
        # Without either, the runs' root may be left out.
        assert _main(tmp_path, "--quiet", root=None) == 1

    def test_a_run_outside_the_root_or_named_twice_is_an_error(
        self,
        record: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        lines = tmp_path / "lines.txt"
        assert _ended(tmp_path, "--lines", str(lines), root=tmp_path) == 2
        assert "is not inside the stored runs' root" in capsys.readouterr().err
        assert _ended(tmp_path, "--lines", str(lines), root=FIXTURE) == 2
        twice = [str(FIXTURE), str(FIXTURE.parent / ".." / FIXTURE.parent.name / FIXTURE.name)]
        with pytest.raises(SystemExit) as ended:
            replay_cli.main(
                [
                    *twice,
                    "--compare",
                    "A",
                    "B",
                    "--repo",
                    str(tmp_path),
                    "--work",
                    str(tmp_path / "work"),
                    "--runs-root",
                    str(FIXTURE.parent),
                    "--lines",
                    str(lines),
                ]
            )
        assert ended.value.code == 2
        assert "names two runs tiny" in capsys.readouterr().err
        assert not lines.exists()

    def test_records_of_two_schemas_alone_with_a_matching_file_are_red(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        newer = _moved(record)
        newer["schema"] = record["schema"] + 1
        _compare_with(monkeypatch, record, newer)
        # Both define every part: nothing is left uncompared, only the schemas differ.
        diff = diff_records(record, newer)
        assert diff["schema"] and not compare.is_partial(diff) and not compare.has_errors(diff)
        lines = tmp_path / "lines.txt"
        assert _main(tmp_path, "--lines", str(lines), "--quiet") == 1
        assert lines.read_bytes()
        assert _main(tmp_path, "--expect", str(lines), "--expect-sha256", _sha(lines)) == 2

    @pytest.mark.parametrize(
        "where", ["this tree", "dot-dot into this tree", "symlink into this tree", "main checkout"]
    )
    def test_lines_are_never_written_inside_any_spelling_of_the_repository(
        self, where: str, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _compare_with(monkeypatch, record, _moved(record))
        link = tmp_path / "into-repo"
        if where == "symlink into this tree":
            _symlink(link, ROOT)
        inside = {
            "this tree": ROOT / "replay-lines.txt",
            "dot-dot into this tree": _dot_dot(tmp_path, ROOT) / "x.txt",
            "symlink into this tree": link / "replay-lines.txt",
            "main checkout": _git_common_tree() / "replay-lines.txt",
        }[where]
        assert _ended(tmp_path, "--lines", str(inside)) == 2
        assert not inside.exists()

    def test_the_digest_is_read_in_either_case_and_refused_with_spaces(
        self, record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _compare_with(monkeypatch, record, copy.deepcopy(record))
        empty = tmp_path / "empty.txt"
        empty.write_bytes(b"")
        upper = _sha(empty).upper()
        assert _main(tmp_path, "--expect", str(empty), "--expect-sha256", upper, "--quiet") == 0
        spaced = f" {_sha(empty)} "
        assert _ended(tmp_path, "--expect", str(empty), "--expect-sha256", spaced) == 2


class _WindowsPath(PureWindowsPath):
    """A Windows path already resolved, so the tool's checks read drives and case as Windows
    does on any platform."""

    def resolve(self, strict: bool = False) -> _WindowsPath:
        return self


def _windows(path: str) -> Path:
    return cast(Path, _WindowsPath(path))


class TestPathsOnTwoDrives:
    def test_a_run_on_another_drive_than_the_root_is_an_error_not_a_traceback(self) -> None:
        with pytest.raises(compare.CompareError, match="is not inside the stored runs' root"):
            run_label(_windows("D:/runs/family-r1/1"), _windows("C:/runs"))

    def test_a_run_is_named_with_slashes_and_a_drive_letter_in_either_case(self) -> None:
        assert run_label(_windows(r"c:\Runs\family-r1\1"), _windows("C:/runs")) == "family-r1/1"

    def test_a_path_on_another_drive_is_outside_a_stored_run_and_the_repository(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_git(*_args: Any) -> bytes:
            raise compare.CompareError("no git")

        checkout = _windows("C:/checkout")
        monkeypatch.setattr(compare, "_git", no_git)
        monkeypatch.setattr(replay_cli, "_ROOT", checkout)
        elsewhere = _windows("D:/work/lines.txt")
        replay_cli._outside(elsewhere, [_windows("C:/runs/1")])
        assert replay_cli._inside_a_repository(elsewhere, checkout) is None
        assert replay_cli._inside_a_repository(_windows("c:/CHECKOUT/x.txt"), checkout) is not None
        with pytest.raises(SystemExit):
            replay_cli._outside(_windows("c:/RUNS/1/x.json"), [_windows("C:/runs/1")])
