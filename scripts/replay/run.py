"""Replay the platform's deterministic rules over stored runs, at zero cost.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/run.py runs/haiku4

re-runs every deterministic decision of the platform over what the run
stored, with no model call: the analysts' validation checks over each answer
stored as written and over the claims in force, the judge's checks over its
answer as written, the report's deterministic build, the export and its
publish rules, the report rounds' checks, the tool-call checks and
corroboration (``scripts/replay/rules.py`` says what each part reads). It
prints codes, entry ids and counts; ``--show-text`` adds each finding's words
and the claim it is about. ``--json OUT`` writes the record. The exit status
is 0 when every part replayed or was named as not replayable, and 2 when a
part raised (a crash is not a decision) or on an error.

``--compare REF_A REF_B`` replays the same runs under two git refs, each with
its own harness over its own rules, written out of the object store into a
directory of its own, and names every difference: codes gained or lost per
claim, published techniques and their reasons, indicator publish answers and
report values. ``--timeout SECONDS`` gives each ref's replay that long (no
limit by default); one still running then is stopped and named. The exit
status is 0 when the two refs decide the same over every run, 1 when they
differ, and 2 when a part raised in either tree, when a part was defined on
one side only and left uncompared (a partial comparison), when a ref predates
the replay tool or was stopped at its time limit, or on an error. A partial
comparison, or one where a part raised, also says how many differences the
parts it compared hold.

Every difference is also a canonical line (``compare.difference_lines``),
naming the run by its path under the stored runs' root, which ``--runs-root``
names and which ``--lines`` and ``--expect`` require; a run outside it, or two
runs of one path under it, is an error. ``--lines OUT`` writes them, one per
line, to a file outside the repository, for a reviewer to approve.
``--expect FILE`` compares them with the lines FILE approves, as a multiset
and exactly, and is never taken without ``--expect-sha256 HEX``, the SHA-256
its reviewer approved: a FILE with another is refused. Equal is status 0 with
one line saying so, any line produced and not approved (``UNEXPECTED:``) or
approved and not produced (``EXPECTED BUT ABSENT:``) is status 1. No two of
``--json``, ``--lines`` and ``--expect`` name one file, however it is spelled:
that is refused with status 2 before anything is compared or written. An
error, a part that raised, a partial comparison and records of two schemas
are never expected: whatever FILE says, the status is then 2, as it is for a
FILE that is missing, cannot be read or names one of them.

``--job ID`` reads a job from the database, read-only, into a directory in the
same layout (``--job-dir``, a temporary one by default) and replays that.
A ``--job-dir/<job id>`` that already holds a stored run is refused, before
the database is read, unless ``--overwrite`` is given.

``replay_run(run, show_text=False)`` is the same replay of one run directory as
a function: it returns the run's record (what ``--json`` writes for it), and
the command line goes through it.

The stored runs are read and never written: every file of each run's
directory is digested before and after, and the replay fails when a digest
changed. No network is reached and nothing is written outside the output
named and a temporary directory of the replay's own.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.replay.guard import prepare_process, restore_process  # noqa: E402
from scripts.replay.record import errors  # noqa: E402
from scripts.replay.stored import check_unchanged, digests  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/replay/run.py",
        description="Replay the platform's deterministic rules over stored runs, at zero cost.",
    )
    parser.add_argument("runs", nargs="*", type=Path, help="stored run directories")
    parser.add_argument("--json", type=Path, help="write the record (or the comparison) here")
    parser.add_argument(
        "--show-text",
        action="store_true",
        help="add each finding's words and the claim it is about",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("REF_A", "REF_B"),
        help="replay under two git refs, each with its own harness, and name every difference",
    )
    parser.add_argument(
        "--work",
        type=Path,
        help="where --compare writes the two refs' trees (a temporary directory by default)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        metavar="SECONDS",
        help="how long --compare gives each ref's replay before stopping it (no limit by default)",
    )
    parser.add_argument(
        "--runs-root",
        type=Path,
        help="the directory --compare names each run's path under in its difference lines "
        "(required with --lines and --expect)",
    )
    parser.add_argument(
        "--lines",
        type=Path,
        metavar="OUT",
        help="write --compare's difference lines to OUT, a file outside the repository",
    )
    parser.add_argument(
        "--expect",
        type=Path,
        metavar="FILE",
        help="the difference lines --compare is expected to produce, exactly "
        "(only with --expect-sha256)",
    )
    parser.add_argument(
        "--expect-sha256",
        metavar="HEX",
        help="the approved SHA-256 of --expect's FILE (required with it); "
        "a FILE with another is refused",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=_ROOT,
        help="the repository --compare reads the refs from (this checkout's by default)",
    )
    parser.add_argument(
        "--job", action="append", default=[], help="a job id to read from the database"
    )
    parser.add_argument("--job-dir", type=Path, help="where --job writes the job it reads")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="let --job replace a stored run already in --job-dir/<job id> (refused otherwise)",
    )
    parser.add_argument(
        "--database-url",
        help="the database --job reads (DATABASE_URL, else the API's bootstrap setting)",
    )
    parser.add_argument("--quiet", action="store_true", help="print nothing; write --json only")
    return parser


def _error(words: str, *values: object) -> NoReturn:
    """Say ``words`` with each ``{}`` filled by a value, and end with the status an error has (2).

    A value can be a path or a name from a stored run, so each is escaped on its
    own: a mark that starts one is shown as an escape, never drawn on the words.
    """
    from scripts.replay.output import terminal_safe

    said = terminal_safe(words).format(*(terminal_safe(value) for value in values))
    print(f"replay: {said}", file=sys.stderr)
    raise SystemExit(2)


def _outside(path: Path, runs: list[Path]) -> None:
    """Refuse a path the replay writes when it is inside a stored run's directory."""
    target = path.resolve()
    for run in runs:
        if target == run.resolve() or run.resolve() in target.parents:
            _error("refused: {} is inside the stored run {}", path, run)


def _write(path: Path | None, value: Any) -> None:
    if path is not None:
        from scripts.replay.output import write_json

        write_json(path, value, indent=1, sort_keys=True)


def replay_run(run: Path, *, show_text: bool = False) -> dict[str, Any]:
    """One stored run directory replayed with the rules this process imports, as its record.

    The record is what ``--json`` writes for the run: every part's codes, entry
    ids, counts and each finding's ``statements``, and with ``show_text`` the
    words beside them. Every file of ``run`` is digested before and after
    (``record["stored"]["files"]``) and the replay raises
    :class:`scripts.replay.stored.StoredRunChanged` when a digest changed.
    Nothing is written but a temporary directory of the replay's own, removed
    on return; no network is reached. A part that raised is named in the record
    (``scripts.replay.record.errors``), not raised here.
    """
    cache = Path(tempfile.mkdtemp(prefix="malspark-replay-"))
    previous = prepare_process(cache)
    try:
        from scripts.replay import rules
        from scripts.replay.stored import read_run

        before = digests(run)
        record = rules.replay_run(read_run(run), show_text=show_text)
        check_unchanged(before, digests(run))
        record["stored"] = {"files": before}
        return record
    finally:
        restore_process(previous)
        shutil.rmtree(cache, ignore_errors=True)


def _replay(runs: list[Path], show_text: bool) -> list[dict[str, Any]]:
    """Each run replayed with the rules this process imports (:func:`replay_run`)."""
    return [replay_run(run, show_text=show_text) for run in runs]


def _compare(
    runs: list[Path],
    refs: tuple[str, str],
    *,
    repo: Path,
    work: Path | None,
    show_text: bool,
    quiet: bool,
    timeout: float | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """The diff of each run between the two refs, and the status the comparison ends with."""
    from scripts.replay import compare
    from scripts.replay.output import render_diff

    ref_a, ref_b = refs
    owned = work is None
    base = Path(tempfile.mkdtemp(prefix="malspark-replay-compare-")) if work is None else work
    try:
        before = {str(run): digests(run) for run in runs}
        records: dict[str, list[dict[str, Any]]] = {}
        for side, ref in (("a", ref_a), ("b", ref_b)):
            try:
                tree = compare.materialise(repo, ref, base / f"{side}-tree")
                records[side] = compare.replay_under(
                    tree, runs, base / f"{side}-replay.json", show_text=show_text, timeout=timeout
                )
            except compare.PredatesTheReplay as exc:
                _error("{}", exc)
            except compare.RefTimedOut as exc:
                _error("{}: {}", ref, exc)
        for run in runs:
            check_unchanged(before[str(run)], digests(run))
        diffs = [
            compare.diff_records(a, b) for a, b in zip(records["a"], records["b"], strict=True)
        ]
        if not quiet:
            print("\n\n".join(render_diff(diff, ref_a, ref_b) for diff in diffs))
        if any(compare.has_errors(diff) or compare.is_partial(diff) for diff in diffs):
            return diffs, 2
        return diffs, 1 if any(compare.differs(diff) for diff in diffs) else 0
    finally:
        if owned:
            shutil.rmtree(base, ignore_errors=True)


def _labels(runs: list[Path], root: Path) -> list[str]:
    """Each run's path under the stored runs' root; a run outside it, or two runs of one path
    under it, is an error."""
    from scripts.replay import compare

    try:
        labels = [compare.run_label(run, root) for run in runs]
    except compare.CompareError as exc:
        _error("{}", exc)
    for label in labels:
        if labels.count(label) > 1:
            _error(
                "the stored runs' root {} names two runs {}: their lines would be one", root, label
            )
    return labels


def _lines(runs: list[Path], diffs: list[dict[str, Any]], labels: list[str]) -> list[str]:
    """Every run's difference lines, each naming the run by its label, sorted."""
    from scripts.replay import compare

    return sorted(
        line
        for label, diff in zip(labels, diffs, strict=True)
        for line in compare.difference_lines(diff, label)
    )


def _one_file(first: Path, second: Path) -> bool:
    """Whether two paths name one file: resolved alike (a ``..``, a symlink, a relative
    spelling) or, where both exist, the same file under two names."""
    if first.resolve() == second.resolve():
        return True
    try:
        return first.exists() and second.exists() and first.samefile(second)
    except OSError:
        return False


def _inside_a_repository(path: Path, repo: Path) -> Path | None:
    """The repository tree ``path`` lies in: this checkout, ``repo`` or the checkout either
    is a worktree of; ``None`` when it lies in none of them."""
    from scripts.replay import compare

    trees = {_ROOT.resolve()}
    for at in (_ROOT, repo):
        for asked in (("rev-parse", "--show-toplevel"), ("rev-parse", "--git-common-dir")):
            try:
                said = compare._git(at, *asked).decode().strip()
            except compare.CompareError:
                continue
            found = Path(said) if Path(said).is_absolute() else at / said
            trees.add(found.resolve().parent if asked[1] == "--git-common-dir" else found.resolve())
    target = path.resolve()
    for tree in sorted(trees):
        if target == tree or tree in target.parents:
            return tree
    return None


def _judge_expected(
    diffs: list[dict[str, Any]],
    lines: list[str],
    status: int,
    *,
    expect: Path | None,
    sha256: str | None,
    quiet: bool,
) -> int:
    """The status the comparison ends with, the expected-difference file read where given.

    A partial comparison, or one where a part raised, says how many differences the parts
    it compared hold. An error, a part that raised, a partial comparison and records of two
    schemas are never expected: they end with status 2 whatever the file says.
    """
    from collections import Counter

    from scripts.replay import compare
    from scripts.replay.output import terminal_safe

    def say(words: str) -> None:
        if not quiet:
            print(words)

    not_a_decision = any(compare.has_errors(d) or compare.is_partial(d) for d in diffs)
    if not_a_decision:
        say(
            "replay: the comparison is partial or a part raised, so it is not a decision "
            f"(status 2); the parts it compared hold {len(lines)} difference line(s)"
        )
    if expect is None:
        return status
    try:
        approved, found = compare.read_expected(expect, sha256)
    except compare.ExpectedFileError as exc:
        _error("{}", exc)
    two_schemas = any(d.get("schema") for d in diffs)
    if not_a_decision or two_schemas:
        say(
            "replay: NOT AS EXPECTED: an error, a partial comparison or records of two schemas "
            "are never expected (status 2)"
        )
        return 2
    produced = Counter(lines)
    unexpected, absent = produced - approved, approved - produced
    for line in sorted(unexpected.elements()):
        say(f"UNEXPECTED: {terminal_safe(line)}")
    for line in sorted(absent.elements()):
        say(f"EXPECTED BUT ABSENT: {terminal_safe(line)}")
    if unexpected or absent:
        return 1
    say(f"replay: clean by {sum(approved.values())} approved line(s) with sha256 {found}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.timeout is not None and not args.timeout > 0:
        parser.error("--timeout takes a number of seconds above 0")
    if not args.compare and (args.expect or args.expect_sha256 or args.lines or args.runs_root):
        parser.error("--expect, --expect-sha256, --lines and --runs-root go with --compare")
    if args.expect_sha256 is not None and (
        args.expect is None or not re.fullmatch(r"[0-9a-fA-F]{64}", args.expect_sha256)
    ):
        parser.error("--expect-sha256 takes the 64 hex digits of --expect's FILE's SHA-256")
    if args.expect is not None and args.expect_sha256 is None:
        _error("refused: --expect is never taken without --expect-sha256, its approved digest")
    if (args.lines or args.expect) and args.runs_root is None:
        _error("refused: --lines and --expect name each run under --runs-root, which is required")
    # No option writes the file another option of the same invocation reads or writes.
    named = [
        (flag, path)
        for flag, path in (
            ("--json", args.json),
            ("--lines", args.lines),
            ("--expect", args.expect),
        )
        if path is not None
    ]
    for i, (flag, path) in enumerate(named):
        for other_flag, other in named[i + 1 :]:
            if _one_file(path, other):
                _error(
                    "refused: {} and {} name one file ({}); nothing is compared or written",
                    flag,
                    other_flag,
                    other,
                )
    runs = [Path(run) for run in args.runs]
    job_dirs: list[Path] = []
    try:
        for written in (args.json, args.work, args.job_dir, args.lines):
            if written is not None:
                _outside(written, runs)
        if args.lines is not None:
            tree = _inside_a_repository(args.lines, args.repo)
            if tree is not None:
                _error(
                    "refused: --lines writes outside the repository; {} is inside {}",
                    args.lines,
                    tree,
                )
        if args.job:
            from scripts.replay.database import StoredRunExists, export_jobs

            target = args.job_dir or Path(tempfile.mkdtemp(prefix="malspark-replay-jobs-"))
            job_dirs = [] if args.job_dir else [target]
            try:
                exported = export_jobs(
                    args.job, target, database_url=args.database_url, overwrite=args.overwrite
                )
            except StoredRunExists as exc:
                _error("refused: {}", exc)
            for directory, cleared in exported:
                if cleared and not args.quiet:
                    from scripts.replay.output import terminal_safe

                    print(
                        "replay: cleared the earlier export's "
                        f"{', '.join(terminal_safe(c) for c in cleared)} in "
                        f"{terminal_safe(directory)}",
                        file=sys.stderr,
                    )
                runs.append(directory)
        if not runs:
            _parser().error("name a stored run or a --job")
        for run in runs:
            if not run.is_dir():
                _error("no stored run at {}", run)
        if args.compare:
            # Without --runs-root (and so without --lines and --expect) the lines are only
            # counted, and a run's name serves as its label.
            labels = (
                [run.name for run in runs]
                if args.runs_root is None
                else _labels(runs, args.runs_root)
            )
            diffs, status = _compare(
                runs,
                (args.compare[0], args.compare[1]),
                repo=args.repo,
                work=args.work,
                show_text=args.show_text,
                quiet=args.quiet,
                timeout=args.timeout,
            )
            _write(args.json, diffs[0] if len(diffs) == 1 else diffs)
            lines = _lines(runs, diffs, labels)
            if args.lines is not None:
                args.lines.write_bytes("".join(f"{line}\n" for line in lines).encode("ascii"))
            return _judge_expected(
                diffs,
                lines,
                status,
                expect=args.expect,
                sha256=args.expect_sha256,
                quiet=args.quiet,
            )
        records = _replay(runs, args.show_text)
        _write(args.json, records[0] if len(records) == 1 else records)
        from scripts.replay.output import render_record, terminal_safe

        if not args.quiet:
            print("\n\n".join(render_record(record) for record in records))
        raised = [(record.get("run"), row) for record in records for row in errors(record)]
        for name, row in raised:
            print(
                f"replay: {terminal_safe(name)}: {terminal_safe(row['part'])} raised: "
                f"{terminal_safe(row['why'])}",
                file=sys.stderr,
            )
        return 2 if raised else 0
    finally:
        for directory in job_dirs:
            shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — said, and the status says it failed
        # The class and where it was raised: a message can quote a value from the run.
        import traceback

        frames = traceback.extract_tb(exc.__traceback__)
        where = f" at {Path(frames[-1].filename).name}:{frames[-1].lineno} ({frames[-1].name})"
        print(f"replay failed: {type(exc).__name__}{where if frames else ''}", file=sys.stderr)
        sys.exit(2)
