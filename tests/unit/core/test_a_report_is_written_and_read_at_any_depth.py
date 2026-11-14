"""A report document is written out and read back at any nesting depth, never raising.

``core.safe_json.dumps`` writes the bytes ``json.dumps`` writes for every value
nested no deeper than the guard, and a marked placeholder below it;
``core.safe_json.loads`` reads the values ``json.loads`` reads, at any depth.
"""

from __future__ import annotations

import gc
import json
import math
import random
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel
from tests.linear_cost import assert_scales, held_over_rounds

from malspark.core import safe_json
from malspark.core.safe_json import (
    CYCLE_MARK,
    DEEPER_MARK,
    DEPTH_GUARD,
    SHARED_MARK,
    dumps,
    exceeds_depth,
    loads,
    within_depth,
)


def _deep_list(depth: int, leaf: Any = 1) -> Any:
    node: Any = leaf
    for _ in range(depth):
        node = [node]
    return node


def _deep_object(depth: int, leaf: Any = 1) -> Any:
    node: Any = leaf
    for _ in range(depth):
        node = {"x": node, "n": 1}
    return node


def _depth(value: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict | list):
            deepest = max(deepest, depth)
            children = node.values() if isinstance(node, dict) else node
            stack.extend((child, depth + 1) for child in children)
    return deepest


def _random_value(rng: random.Random, depth: int = 0) -> Any:
    roll = rng.random()
    if depth > 6 or roll < 0.35:
        return rng.choice(
            [
                None,
                True,
                False,
                0,
                -7,
                3.25,
                1e-9,
                12345678901234567890,
                "",
                "plain",
                "ünïcödé ☃",
                'quote " back \\ slash',
                "\u0000\u001f control",
                "😀",
            ]
        )
    if roll < 0.7:
        return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    width = rng.randint(0, 4)
    return {f"k{rng.randint(0, 9)}": _random_value(rng, depth + 1) for _ in range(width)}


_KWARGS: tuple[dict[str, Any], ...] = (
    {},
    {"default": str},
    {"separators": (",", ":"), "default": str},
    {"indent": 2},
    {"sort_keys": True, "ensure_ascii": False},
)


class TestTheBytesAreJsonDumpsBytes:
    @pytest.mark.parametrize("kwargs", _KWARGS)
    def test_random_values_write_as_json_dumps_writes_them(self, kwargs: dict[str, Any]) -> None:
        rng = random.Random(7)
        for _ in range(300):
            value = _random_value(rng)
            assert dumps(value, **kwargs) == json.dumps(value, **kwargs)

    def test_a_value_at_the_guard_is_handed_over_itself(self) -> None:
        value = _deep_object(DEPTH_GUARD)
        assert _depth(value) == DEPTH_GUARD
        assert not exceeds_depth(value)
        assert safe_json.within_depth(value) is value
        assert dumps(value) == json.dumps(value)

    def test_one_level_past_the_guard_is_marked(self) -> None:
        value = _deep_list(DEPTH_GUARD + 1, leaf=[])
        assert exceeds_depth(value)
        text = dumps(value)
        assert DEEPER_MARK in text
        assert _depth(json.loads(text)) == DEPTH_GUARD


class TestADeepValueNeverRaises:
    @pytest.mark.parametrize("make", [_deep_list, _deep_object])
    @pytest.mark.parametrize("depth", [DEPTH_GUARD + 1, 1_000, 10_000, 100_000])
    def test_it_is_written_marked_and_read_back_by_every_reader(
        self, make: Callable[[int], Any], depth: int
    ) -> None:
        value = make(depth)
        with pytest.raises(RecursionError):
            json.dumps(make(20_000))
        text = dumps(value, default=str)
        assert DEEPER_MARK in text
        back = json.loads(text)
        assert _depth(back) <= DEPTH_GUARD

        class Holder(BaseModel):
            held: Any = None

        # The ledger and the report are pydantic models, holding an answer some
        # levels down: they read it back and write it again.
        wrapped: Any = back
        for _ in range(18):
            wrapped = {"entries": [wrapped]}  # two levels each
        holder = Holder.model_validate_json(json.dumps({"held": wrapped}))
        assert holder.model_dump_json()

    def test_the_mark_is_written_where_the_value_went_on(self) -> None:
        value = {"a": 1, "deep": _deep_list(DEPTH_GUARD + 5), "z": [1, 2]}
        back = json.loads(dumps(value))
        assert list(back) == ["a", "deep", "z"]
        assert back["a"] == 1
        assert back["z"] == [1, 2]
        node = back["deep"]
        for _ in range(DEPTH_GUARD - 2):
            node = node[0]
        assert node == [DEEPER_MARK]


class TestAnyDepthIsRead:
    @pytest.mark.parametrize("depth", [DEPTH_GUARD + 1, 3_000, 10_000, 200_000])
    def test_a_deep_body_is_read_marked_below_the_guard(self, depth: int) -> None:
        text = "[" * depth + '{"k": "v"}' + "]" * depth
        value = loads(text)
        assert _depth(value) == DEPTH_GUARD
        node = value
        for _ in range(DEPTH_GUARD - 1):
            assert isinstance(node, list)
            assert len(node) == 1
            node = node[0]
        assert node == [DEEPER_MARK]

    def test_a_body_within_the_guard_is_read_whole(self) -> None:
        text = "[" * (DEPTH_GUARD - 1) + '{"k": "v"}' + "]" * (DEPTH_GUARD - 1)
        assert loads(text) == json.loads(text)
        assert safe_json._loads_iteratively(text) == json.loads(text)

    def test_a_deep_object_body_keeps_its_keys_down_to_the_guard(self) -> None:
        depth = 5_000
        text = '{"a": ' * depth + "1" + ', "b": [true, null]}' * depth
        for value in (loads(text), safe_json._loads_iteratively(text)):
            node = value
            for _ in range(DEPTH_GUARD - 1):
                assert list(node) == ["a", "b"]
                assert node["b"] == [True, None]
                node = node["a"]
            assert node == {"a": DEEPER_MARK, "b": DEEPER_MARK}

    def test_the_iterative_reader_gives_what_json_loads_marked_gives(self) -> None:
        text = '{"x": ' + "[" * 400 + "1" + "]" * 400 + ', "y": [1, {"z": []}]}'
        assert safe_json._loads_iteratively(text) == within_depth(json.loads(text))

    def test_bytes_are_read_as_json_loads_reads_them(self) -> None:
        text = "[" * 3_000 + '"\\u00e9"' + "]" * 3_000
        for encoding in ("utf-8", "utf-16"):
            assert loads(text.encode(encoding)) == loads(text)

    def test_the_iterative_reader_reads_what_json_loads_reads(self) -> None:
        rng = random.Random(11)
        cases = [json.dumps(_random_value(rng), indent=rng.choice([None, 1])) for _ in range(400)]
        cases += [
            "  [1, 2.5, -0, -0.0, 1e5, 1E-2, 3e+2]  ",
            '{"a": NaN, "b": Infinity, "c": -Infinity}',
            '{"dup": 1, "dup": 2}',
            '"\\ud83d\\ude00 \\n \\t \\" \\\\ \\/"',
            "{}",
            "[]",
            "[[], {}, [[]]]",
            '\n\t{ "k" :\r [ ] }\n',
        ]
        for text in cases:
            expected = json.loads(text)
            got = safe_json._loads_iteratively(text)
            if isinstance(expected, dict) and isinstance(expected.get("a"), float):
                assert math.isnan(got["a"])
                assert got["b"] == expected["b"]
                assert got["c"] == expected["c"]
                continue
            assert got == expected
            assert json.dumps(got) == json.dumps(expected)

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "   ",
            "[1, 2",
            "[1 2]",
            '{"a" 1}',
            '{"a": 1,}',
            "[1,]",
            "{1: 2}",
            "[1] x",
            "tru",
            '"open',
            "[}",
            "{]",
        ],
    )
    def test_a_malformed_body_is_refused_as_json_loads_refuses_it(self, text: str) -> None:
        with pytest.raises(json.JSONDecodeError):
            json.loads(text)
        with pytest.raises(json.JSONDecodeError):
            safe_json._loads_iteratively(text)


def _linear(make: Callable[[int], Any], run: Callable[[Any], Any], small: int) -> None:
    # Ten times the input in under fifteen times the time, and 50 ms of
    # allowance for a small run that is mostly fixed cost.
    assert_scales(make, small, run, factor=10, limit=15, floor=0.05 / 15)


class TestLinearTime:
    def test_writing_a_deep_value_is_linear(self) -> None:
        _linear(_deep_list, dumps, 20_000)

    def test_writing_a_wide_shallow_value_is_linear(self) -> None:
        _linear(lambda n: [{"k": [i, str(i)]} for i in range(n)], dumps, 20_000)

    def test_reading_a_deep_body_is_linear(self) -> None:
        # A run of brackets below the guard is read in one match, about two
        # milliseconds a million brackets, so each side is read 30 times
        # rather than grown to hundreds of megabytes.
        _linear(
            lambda n: "[" * n + "]" * n,
            lambda text: [safe_json._loads_iteratively(text) for _ in range(30)],
            200_000,
        )

    def test_reading_a_wide_body_is_linear(self) -> None:
        _linear(
            lambda n: json.dumps([{"k": [i, "v"]} for i in range(n)]),
            safe_json._loads_iteratively,
            5_000,
        )


def _shared_chain(n: int) -> Any:
    """``n`` levels, each a list holding the level below twice: 2**n paths, n containers."""
    node: Any = [1]
    for _ in range(n):
        node = [node, node]
    return node


def _cycle(n: int) -> Any:
    """``n`` levels of shared lists whose innermost holds the outermost."""
    innermost: list[Any] = [1]
    node: Any = innermost
    for _ in range(n):
        node = [node, node, {"k": node}]
    innermost.append(node)
    return node


def _peak(run: Callable[[], Any]) -> int:
    import tracemalloc

    gc.collect()
    tracemalloc.start()
    try:
        run()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class TestSharedContainersAndCycles:
    def test_a_shared_chain_within_the_guard_is_measured_once(self) -> None:
        # 2**100 paths: walked path by path it would never end.
        value = _shared_chain(100)
        assert not exceeds_depth(value)
        assert within_depth(value) is value

    def test_a_shared_chain_past_the_guard_is_copied_once_and_written_linearly(self) -> None:
        value = _shared_chain(5_000)
        assert exceeds_depth(value)
        text = dumps(value)
        assert len(text) < 200 * 5_000
        assert SHARED_MARK in text
        assert _depth(json.loads(text)) <= DEPTH_GUARD

    def test_a_cycle_is_written_once_and_marked(self) -> None:
        for value in (_cycle(3), _cycle(400)):
            with pytest.raises(ValueError):
                json.dumps(value)
            text = dumps(value)
            # The return is a cycle within the guard, and below it a deeper container.
            assert CYCLE_MARK in text or DEEPER_MARK in text
            assert _depth(json.loads(text)) <= DEPTH_GUARD
        assert CYCLE_MARK in dumps(_cycle(3))
        holder: dict[str, Any] = {"a": 1}
        holder["self"] = holder
        assert json.loads(dumps(holder)) == {"a": 1, "self": CYCLE_MARK}

    def test_the_shared_and_cyclic_walks_are_linear(self) -> None:
        _linear(_shared_chain, exceeds_depth, 20_000)
        _linear(_shared_chain, dumps, 20_000)
        _linear(_cycle, dumps, 12_000)

    def test_the_shared_walk_holds_memory_linear_in_the_containers(self) -> None:
        small = _peak(lambda: dumps(_shared_chain(5_000)))
        large = _peak(lambda: dumps(_shared_chain(50_000)))
        assert large <= 10 * small * 1.5, (small, large)


class TestAHostileDeepBody:
    def test_a_ten_million_character_body_is_read_linearly_in_time_and_memory(self) -> None:
        depth = 5_000_000
        text = "[" * depth + "]" * depth
        assert len(text) == 10_000_000
        value = loads(text)
        assert _depth(value) == DEPTH_GUARD
        small_text = "[" * (depth // 10) + "]" * (depth // 10)
        small = _peak(lambda: loads(small_text))
        large = _peak(lambda: loads(text))
        # The dropped levels are held as one byte each: never more than the body.
        assert large <= len(text), (small, large)
        assert large <= 10 * small * 1.5 + 65_536, (small, large)
        # Read 10 times on each side: one read of the small body is a millisecond.
        _linear(lambda n: "[" * n + "]" * n, lambda text: [loads(text) for _ in range(10)], 500_000)

    def test_a_deep_body_of_mixed_brackets_is_read_linearly(self) -> None:
        def body(n: int) -> str:
            return '[{"a": ' * n + "1" + "}]" * n

        assert _depth(loads(body(50_000))) == DEPTH_GUARD
        _linear(body, loads, 20_000)

    @pytest.mark.posix
    @pytest.mark.parametrize(
        "unit",
        ['[{"":', '{"":['],
        ids=["array-object", "object-array"],
    )
    def test_an_alternating_deep_body_costs_no_more_memory_than_a_shallow_one(
        self, unit: str
    ) -> None:
        """Peak memory within a small constant factor of ``json.loads`` on a shallow body.

        Alternating brackets make every level a run of its own; each still
        costs one byte, so a deep body never costs more than a shallow body of
        the same size read by ``json.loads``. Measured as the peak resident
        size a fresh process adds while reading, one process per reading.
        """
        held = _added_peak("deep", unit, 1_000_000)
        size = len(unit) * 1_000_000
        baseline = _added_peak("shallow", unit, size)
        assert held <= 2 * baseline, (held, baseline)
        assert held <= size, (held, size)
        small = _added_peak("deep", unit, 100_000)
        assert held <= 10 * small * 1.5 + 8 * 2**20, (small, held)

    def test_an_alternating_deep_body_is_read_linearly(self) -> None:
        _linear(lambda n: '[{"":' * n + "0" + "}]" * n, loads, 20_000)

    def test_a_shallow_body_is_measured_without_a_record_per_container(self) -> None:
        text = json.dumps([{"k": [i, {"v": i}]} for i in range(20_000)])
        read = _peak(lambda: json.loads(text))
        held = _peak(lambda: loads(text))
        # What ``json.loads`` builds, and a walk holding one iterator per level.
        assert held <= read * 1.05 + 65_536, (read, held)

    def test_the_guard_says_how_many_containers_it_marked(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level("WARNING", logger="malspark.core.safe_json")
        loads('{"a": ' + "[" * 10_000 + "]" * 10_000 + ', "b": ' + "[" * 300 + "]" * 300 + "}")
        loads("[" * 300 + "]" * 300)
        said = [r.getMessage() for r in caplog.records]
        assert len(said) == 2
        assert "2 containers" in said[0]
        assert "1 containers" in said[1]
        caplog.clear()
        loads(json.dumps({"a": [[1]]}))
        assert not caplog.records

    def test_a_deep_object_body_is_validated_while_dropped(self) -> None:
        bad = '{"a": ' * 10_000 + "1" + "}" * 9_999 + ","
        with pytest.raises(json.JSONDecodeError):
            loads(bad)

    @pytest.mark.posix
    def test_a_deep_body_json_loads_reads_is_cut_in_place_at_its_cost(self) -> None:
        """Bodies of 500-deep chunks: ``json.loads`` reads them, and the guard cuts them.

        The cut is made in the tree ``json.loads`` returned, never in a copy, so
        the peak resident size a fresh process adds on ten megabytes stays that
        of ``json.loads`` on the same body. The time is held to ``json.loads``
        itself: the guarded read costs within a small constant of it, and five
        times the body costs the guarded read at most half as much again of
        what it costs ``json.loads``. Measured against ``json.loads`` on the
        same machine, the memory and kernel cost of building millions of
        lists, which differs from one system to the next, is in both sides.
        The cut alone is also held to the body's growth, with no
        ``json.loads`` in its bound. A measure that fails is taken again by
        the rounds every ratio here is read over (``held_over_rounds``), the
        smaller body's times bounding a round read on its own.
        """
        size = 10_000_000
        plain_bytes = _chunked_read("json", 500, size)
        held_bytes = _chunked_read("safe", 500, size)
        assert held_bytes <= 1.2 * plain_bytes + 8 * 2**20, (plain_bytes, held_bytes)

        small, large = 1_000_000, 5_000_000

        def verdict(times: dict[str, float]) -> tuple[float, float, bool]:
            plain_growth = times[f"json {large}"] / times[f"json {small}"]
            held_growth = times[f"safe {large}"] / times[f"safe {small}"]
            # Half a second on ten megabytes, scaled to the body measured.
            near = times[f"safe {large}"] < 4 * times[f"json {large}"] + 0.5 * large / size
            # The cut alone, held to the body's own growth: a json.loads that
            # grows faster on some machine cannot widen this bound. The cut is
            # a walk in the interpreter and grows 5.0 times for five times the
            # body; a quarter more is the bound.
            cut_growth = times[f"safe {large} cut part"] / times[f"safe {small} cut part"]
            cut_linear = cut_growth < 1.25 * large / small
            return (
                plain_growth,
                held_growth,
                held_growth < 1.5 * plain_growth and near and cut_linear,
            )

        held, attempts, best = held_over_rounds(
            lambda: _chunked_times(500, small, large),
            lambda times: verdict(times)[2],
            [f"json {small}", f"safe {small}", f"safe {small} cut part"],
        )
        plain_growth, held_growth, _ = verdict(best if held is None else held)
        assert held is not None, (
            f"five times the body: json.loads {plain_growth:.1f} times, the guarded read "
            f"{held_growth:.1f} times (limit 1.5 times json.loads's), its cut at most "
            f"{1.25 * large / small:g} times; each attempt's CPU "
            f"seconds with their user and system parts, and the guarded read's cut "
            f"alone, then the best of all: {[*attempts, best]}"
        )

    def test_a_cut_body_reads_as_the_marked_copy_would(self) -> None:
        chunk = "[" * 500 + "]" * 500
        text = '{"a": [' + ",".join([chunk] * 3) + '], "b": {"c": 1}}'
        value = loads(text)
        assert value == within_depth(json.loads(text))
        assert _depth(value) == DEPTH_GUARD


_CHUNK_SCRIPT = """
import json, resource, sys
from malspark.utils.peak_memory import rss_to_bytes
from malspark.core.safe_json import loads
mode, depth, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
chunk = "[" * depth + "]" * depth
text = "[" + ",".join([chunk] * max(1, size // (2 * depth + 1))) + "]"
read = json.loads if mode == "json" else loads
base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
value = read(text)
print(rss_to_bytes(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - base))
"""

# Both reads at both sizes in one process, taken in turn three times, the
# collector held: the best CPU time of each, with its user and system parts;
# for the guarded read at each size also its cut alone, on a tree of its own
# (the rest is the json.loads it starts with). macOS counts user time exactly
# and its kernel's cost of building and freeing millions of lists differs from
# Linux's, so there the time is the user time; Linux splits user from system
# time only by sampling at the scheduler's tick, a few ticks of noise on the
# smaller body, so there the time is both, which it counts exactly.
_TIMES_SCRIPT = """
import gc, json, resource, sys
from malspark.core.safe_json import DEPTH_GUARD, _cut_below, loads
user_only = sys.platform == "darwin"
depth, small, large = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
chunk = "[" * depth + "]" * depth
texts = {n: "[" + ",".join([chunk] * max(1, n // (2 * depth + 1))) + "]" for n in (small, large)}

def cpu(call):
    gc.collect()
    gc.disable()
    before = resource.getrusage(resource.RUSAGE_SELF)
    value = call()
    after = resource.getrusage(resource.RUSAGE_SELF)
    gc.enable()
    del value
    return after.ru_utime - before.ru_utime, after.ru_stime - before.ru_stime

best = {}
def keep(key, took):
    user, system = took
    seconds = user if user_only else user + system
    if key not in best or seconds < best[key]:
        best[key] = seconds
        best[key + " user"] = user
        best[key + " system"] = system

for _ in range(3):
    for n, text in texts.items():
        keep(f"json {n}", cpu(lambda: json.loads(text)))
        keep(f"safe {n}", cpu(lambda: loads(text)))
        tree = json.loads(text)
        keep(f"safe {n} cut part", cpu(lambda: _cut_below(tree, DEPTH_GUARD)))
        del tree
print(json.dumps(best))
"""


def _chunked_times(depth: int, small: int, large: int) -> dict[str, float]:
    """The CPU seconds of each read at each size, from a process of its own."""
    import os
    import subprocess
    import sys

    import malspark

    env = {**os.environ, "PYTHONPATH": str(Path(malspark.__file__).resolve().parents[1])}
    done = subprocess.run(
        [sys.executable, "-c", _TIMES_SCRIPT, str(depth), str(small), str(large)],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        timeout=300,
    )
    times: dict[str, float] = json.loads(done.stdout.strip().splitlines()[-1])
    return times


def _chunked_read(mode: str, depth: int, size: int) -> int:
    """The peak resident bytes a fresh process adds reading the chunked body."""
    import os
    import subprocess
    import sys

    import malspark

    env = {**os.environ, "PYTHONPATH": str(Path(malspark.__file__).resolve().parents[1])}
    done = subprocess.run(
        [sys.executable, "-c", _CHUNK_SCRIPT, mode, str(depth), str(size)],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        timeout=300,
    )
    return int(done.stdout.strip().splitlines()[-1])


_PEAK_SCRIPT = """
import json, resource, sys
from malspark.utils.peak_memory import rss_to_bytes
from malspark.core.safe_json import loads
kind, unit, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
closer = "}]" if unit.startswith("[") else "]}"
if kind == "deep":
    text, read = unit * n + "0" + closer * n, loads
else:
    text, read = "[" + ",".join(['{"":0}'] * (n // 7)) + "]", json.loads
base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
value = read(text)
print(rss_to_bytes(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - base))
"""


def _added_peak(kind: str, unit: str, n: int) -> int:
    """The peak resident bytes a fresh process adds reading the body (``ru_maxrss``)."""
    import os
    import subprocess
    import sys

    import malspark

    env = {**os.environ, "PYTHONPATH": str(Path(malspark.__file__).resolve().parents[1])}
    done = subprocess.run(
        [sys.executable, "-c", _PEAK_SCRIPT, kind, unit, str(n)],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        timeout=300,
    )
    return int(done.stdout.strip().splitlines()[-1])


def _stored_report_paths() -> list[Any]:
    from tests.unit.providers.test_sandbox_tools_golden import ROOT, _globs

    return [path for pattern in _globs() for path in sorted(ROOT.glob(pattern))]


class TestEveryStoredReportIsWrittenAsBefore:
    """Every stored CAPE report and its document are written by ``json.dumps`` itself."""

    @pytest.mark.parametrize("path", _stored_report_paths(), ids=lambda path: path.stem)
    def test_the_report_and_its_document_are_handed_to_json_dumps_unchanged(
        self, path: Any
    ) -> None:
        from malspark.providers.sandbox.readers import required_reader
        from malspark.schemas.sandbox_document import sandbox_document

        text = path.read_text(encoding="utf-8")
        raw = json.loads(text)
        assert loads(text) == raw
        document = sandbox_document(required_reader("cape2").read(raw, provider="upload"))
        for value in (raw, document):
            assert safe_json.within_depth(value) is value
            assert dumps(value, separators=(",", ":"), default=str) == json.dumps(
                value, separators=(",", ":"), default=str
            )
