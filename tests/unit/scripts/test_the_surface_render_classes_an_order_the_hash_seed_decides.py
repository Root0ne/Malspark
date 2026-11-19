"""A unit whose order the interpreter's hash seed decides is its own class, never pinned away.

A comparison renders build mode under two string hash seeds per ref, the
same two for both refs, and serve mode under the first; no seed is pinned by
default. A unit that differs between the two seeds of one ref is listed as an
order the hash seed decides, by surface and unit path; a difference between
the refs in it is left out only when the refs agree under the other seed, and
one they differ in under both seeds is a difference. Each render's process is
given its seed and stores no request can reach.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 — the type of a stand-in's answer only
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import (
    commit_edits,
    platform_repository,
    stored_run,
)


def _record(**units: str) -> dict[str, Any]:
    return {
        "run": "fixture/1",
        "modes": ["serve", "build"],
        "units": [
            {"mode": "build", "surface": "full", "group": "", "key": key, "text": text}
            for key, text in units.items()
        ],
        "file_digests": {},
        "not_produced": [],
    }


def _build(record: dict[str, Any]) -> dict[str, Any]:
    return {**record, "modes": ["build"]}


class TestTheClass:
    def test_a_unit_that_differs_between_two_seeds_of_one_ref_is_classed_not_compared(
        self,
    ) -> None:
        a = _record(stable="x", roots="p q")
        a2 = _build(_record(stable="x", roots="q p"))
        b = _record(stable="x", roots="q p")
        b2 = _build(_record(stable="x", roots="q p"))
        diff = rs.compare_records(a, b)
        assert [c["key"] for c in diff["changes"]] == ["roots"]

        rs.apply_hash_seeds(diff, ("1", "2"), a, a2, b, b2)

        assert diff["changes"] == [] and diff["summary"] == {}
        seeded = diff["hash_seed"]
        assert seeded["class"] == rs.SEED_CLASS and seeded["seeds"] == ["1", "2"]
        assert seeded["a"] == [{"mode": "build", "surface": "full", "key": "roots"}]
        assert seeded["b"] == []
        assert [c["key"] for c in seeded["excluded"]] == ["roots"]

    def test_a_classed_unit_the_refs_differ_in_under_both_seeds_is_a_difference(self) -> None:
        a = _record(stable="x", roots="1 2")
        a2 = _build(_record(stable="x", roots="2 1"))
        b = _record(stable="y", roots="1 2 3")
        b2 = _build(_record(stable="y", roots="3 2 1"))
        diff = rs.compare_records(a, b)

        rs.apply_hash_seeds(diff, ("1", "2"), a, a2, b, b2)

        assert sorted(c["key"] for c in diff["changes"]) == ["roots", "stable"]
        assert diff["hash_seed"]["excluded"] == []
        assert [row["key"] for row in diff["hash_seed"]["b"]] == ["roots"]

    def test_the_class_is_printed_with_its_seeds_and_every_unit(self) -> None:
        a = _record(roots="p q")
        a2 = _build(_record(roots="q p"))
        diff = rs.compare_records(a, a)
        rs.apply_hash_seeds(diff, ("11", "22"), a, a2, a, a2)
        printed = rs.render_comparison([diff], ("A", "B"), [])
        assert rs.SEED_CLASS.upper() in printed
        assert "the seeds 11 and 22" in printed
        assert "A [build full] roots" in printed and "B [build full] roots" in printed


class TestEachRefIsRenderedUnderTwoSeeds:
    def test_build_mode_is_rendered_under_two_seeds_the_same_for_both_refs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from scripts.replay import compare

        calls: list[tuple[str, tuple[str, ...], str | None]] = []

        def _materialise(_repo: Path, ref: str, into: Path, **_kwargs: Any) -> Path:
            return into

        def _render_under(tree: Path, _runs: Any, out: Path, **kwargs: Any) -> Any:
            calls.append((out.name, tuple(kwargs["modes"]), kwargs["hash_seed"]))
            return [_record(stable="x")] if "serve" in kwargs["modes"] else [_build(_record())]

        monkeypatch.setattr(compare, "materialise", _materialise)
        monkeypatch.setattr(rs, "render_under", _render_under)
        [diff] = rs._compare(
            [tmp_path], ("A", "B"), repo=tmp_path, work=tmp_path / "work", timeout=None
        )
        [(a1, _m1, s1), (a2, m2, s2), (b1, _m3, s3), (b2, m4, s4)] = calls
        assert (a1, a2, b1, b2) == ("a-out", "a-out-seed2", "b-out", "b-out-seed2")
        assert m2 == m4 == ("build",)
        assert s1 == s3 and s2 == s4 and s1 != s2
        assert diff["hash_seed"]["seeds"] == [s1, s2]

    def test_no_seed_is_pinned_by_default(self) -> None:
        drawn = {rs.draw_hash_seeds() for _ in range(4)}
        assert all(first != second for first, second in drawn)
        assert len(drawn) > 1
        assert not hasattr(rs, "HASH_SEED")

    def test_a_render_s_process_is_given_its_seed_and_closed_stores(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, str] = {}

        def _run(command: list[str], **kwargs: Any) -> Any:
            seen.update(kwargs["env"])
            out = Path(command[command.index("--out") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / rs.RECORD_FILE).write_text("[]", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, b"", b"")

        monkeypatch.setattr(rs.subprocess, "run", _run)
        rs.render_under(tmp_path, [tmp_path], tmp_path / "out", hash_seed="4242")
        assert seen[rs.HASH_SEED_VARIABLE] == "4242"
        for name, value in rs.CLOSED_STORES.items():
            assert seen[name] == value


NAVIGATOR = "src/malspark/reporting/navigator_layer.py"
WORDS = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa")


@pytest.mark.slow
def test_an_order_one_ref_takes_from_the_hash_seed_is_classed_and_still_a_difference(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo, first = platform_repository(tmp_path, extra=["scripts/replay"])
    seeded = repr(set(WORDS))
    second = commit_edits(
        repo,
        [
            (
                NAVIGATOR,
                'entry["score"] = score',
                f'entry["score"] = score\n            entry["x_order"] = list({seeded})',
            )
        ],
    )
    run = stored_run(tmp_path)
    out = tmp_path / "diff.json"
    argv = [str(run), "--repo", str(repo), "--work", str(tmp_path / "work")]
    argv += ["--compare", first, second, "--hash-seeds", "1", "2", "--json", str(out)]

    assert rs.main(argv) == rs.EXIT_UNEXPECTED
    printed = capsys.readouterr().out
    assert rs.SEED_CLASS.upper() in printed and "the seeds 1 and 2" in printed
    [diff] = json.loads(out.read_text(encoding="utf-8"))["runs"]
    under_b = {(r["surface"], r["key"]) for r in diff["hash_seed"]["b"]}
    under_a = {(r["surface"], r["key"]) for r in diff["hash_seed"]["a"]}
    assert ("navigator", "technique T1027") in under_b
    assert ("navigator", "technique T1027") not in under_a
    # The refs differ in it under both seeds: a difference.
    kept = {(c["mode"], c["surface"], c["key"]) for c in diff["changes"]}
    assert ("build", "navigator", "technique T1027") in kept
    assert not any(c["surface"] == "navigator" for c in diff["hash_seed"]["excluded"])
