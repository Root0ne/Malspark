"""Cost measures for tests that hold a reader to linear cost, none of them a bare wall-clock bound.

A test that says "the cost grows with the input, not with its square" must not
fail on a slow or loaded machine, and must still fail on a quadratic reader.
A shared runner moves even CPU time: a busy neighbour on the same core, a
cache another process emptied or a clock that stepped down makes one run of
the same call take twice as long as the next. Every measure here is built so
that such a run is not the one the assertion reads.

* :func:`assert_ratio` is the measure for "``k`` times the input costs about
  ``k`` times as much". It warms the call up, then times the small and the
  large call in turn (small, large, small, large, ...) so a slow stretch of
  the machine lands on both sizes rather than on one, keeps the best time of
  each size with the collector off, and holds the ratio of the best times
  under the test's limit. Only when that ratio fails does it measure up to
  :data:`ROUNDS` rounds of the same pairs in all, by the rule of
  :func:`held_over_rounds`, and the message gives every round.
* :func:`held_over_rounds` is that rule, for a test that takes its own
  measurements (in a child process, for one): a first round that holds is
  the whole measure; a later round passes when the best of every round taken
  together holds, or when its own times hold and its small times are within
  :data:`ROUND_DRIFT` of the best small times of every round. A round is
  judged on its own because a runner's speed drifts between rounds: the best
  small time of a quick stretch over the best large time of a slow one reads
  a ratio no pair of runs had. The drift it forgives is bounded: a round's
  large time is never under the best large time, and its small time is at
  most :data:`ROUND_DRIFT` times the best small time, so no round passes a
  call whose best times read a ratio :data:`ROUND_DRIFT` times its limit or
  more.
* :func:`assert_scales` builds the two inputs from one size and a factor and
  holds them to :func:`assert_ratio` with a limit of :data:`SCALING_SLACK`
  times the factor (a quadratic reader takes ``factor`` times more). It
  refuses a limit a quadratic's ``factor`` squared is not over
  :data:`ROUND_DRIFT` times, which that bound would not keep failing.
* :func:`assert_under` holds one call under an absolute CPU-time bound, for
  a hostile input whose cost the test bounds rather than compares. It runs
  the call again only when a run is over the bound, so a passing call is
  timed once.
* :func:`cpu_seconds` is the best of several CPU times of one call, for a
  test that compares a cost with something other than the same call on a
  smaller input (a wait it injects, for one).
* :func:`calls` counts the function calls (Python and built-in) a call makes.
  It does not move with load, but it cannot see work done inside one C
  operation, so it is an extra assertion, never the only one.
* :func:`peak_bytes` is the most memory a call holds at once, by tracemalloc:
  a count, for a call whose input is built before the measure, that the
  timed call does not copy that input. A timed call that builds or copies a
  large input times the allocator: one process takes fresh pages for the
  large block on every call and reuses them for the small one, another
  reuses both, and the same call reads 25 times or 4 times as dear.

The clock is the calling thread's CPU time, the whole process's with
``whole_process`` for work that crosses threads, or a clock the test passes
(``time.perf_counter`` for work whose time is a wait). On macOS it is the
process's user time: there a thread's CPU time counts the kernel's mapping
and zeroing of the pages a large input takes, which grows with the heap
rather than with the work, and macOS counts user time exactly. That time is
the whole process's, so a test measured on macOS must not leave a thread
spinning behind it: its time would be read as the measured call's.
:func:`default_clock` is that clock, for a test that counts runs by it. Size the inputs so the
small call takes about 10 ms or more: a ratio over a small run of a few
clock ticks says nothing about the code, and a quadratic call whose small run
is that short passes any limit. :func:`assert_ratio` fails a measure whose
best small run is under :data:`FLOOR_SECONDS`, so such a test cannot pass by
being too fast to measure.
"""

from __future__ import annotations

import gc
import os
import sys
import time
import tracemalloc
from collections.abc import Callable, Collection
from typing import Any

try:
    import resource
except ImportError:  # Windows, whose default clock is the thread's anyway
    resource = None  # type: ignore[assignment]

__all__ = [
    "FLOOR_SECONDS",
    "GRAINS",
    "ROUNDS",
    "ROUND_DRIFT",
    "SCALING_SLACK",
    "TIME_RATIO_LIMIT",
    "assert_ratio",
    "assert_scales",
    "assert_under",
    "calls",
    "clock_grain",
    "cpu_seconds",
    "default_clock",
    "held_over_rounds",
    "peak_bytes",
    "repeated",
]

# Four times the input may take under eight times as long; a quadratic reader
# takes sixteen times as long.
TIME_RATIO_LIMIT = 8

# A linear call on k times the input takes k times as long; up to this many
# times that is noise and cache effects, a quadratic call takes k times more.
SCALING_SLACK = 3.0

# The rounds of pairs a ratio is read from before it fails: a passing first
# round is the only one, a later round runs only when every one before failed.
ROUNDS = 3

# How much slower a later round's small runs may be than the best small runs
# of every round, for that round to be judged on its own times. The CI records
# a later round held showed its small time 1.22 and 1.28 times the first
# round's. A round read on its own holds the best large time over the best
# small time under this factor times the limit; a slowdown common to every
# small run of every round is not seen by the rule, so a limit must leave a
# quadratic call further over it than this factor.
ROUND_DRIFT = 1.3

# The least a small run may take: under it the clock's grain is the ratio, and
# the measure fails rather than read it.
FLOOR_SECONDS = 0.002

# The fewest of the clock's ticks a timed run spans where a tick is coarse:
# Windows' thread and process clocks move in steps of about 15.6 ms, so a run
# of one or two steps is read as up to half or twice what it took.
GRAINS = 8

# Each clock's tick, once measured.
_GRAIN: dict[Callable[[], float], float] = {}


def calls(call: Callable[[], Any]) -> int:
    """How many function calls ``call`` makes: a count, not a time."""
    made = 0

    def _count(_frame: Any, event: str, _arg: Any) -> None:
        nonlocal made
        if event in ("call", "c_call"):
            made += 1

    previous = sys.getprofile()
    sys.setprofile(_count)
    try:
        call()
    finally:
        sys.setprofile(previous)
    return made


def peak_bytes(call: Callable[[], Any]) -> int:
    """The most memory ``call`` holds at once while it runs, in bytes: a count, not a time."""
    tracing = tracemalloc.is_tracing()
    if tracing:
        tracemalloc.reset_peak()
    else:
        tracemalloc.start()
    try:
        held = tracemalloc.get_traced_memory()[0]
        call()
        return tracemalloc.get_traced_memory()[1] - held
    finally:
        if not tracing:
            tracemalloc.stop()


def repeated(call: Callable[[], Any], times: int) -> Callable[[], None]:
    """A call that runs ``call`` ``times`` times and keeps none of its answers.

    For a call too quick for the clock, or one whose cost does not grow with
    its input: the ratio of ``times`` runs is the ratio of one, and an answer
    is freed before the next run, so the measure holds one answer at a time.
    """

    def run() -> None:
        for _ in range(times):
            call()

    return run


def _user_seconds() -> float:
    """The process's user CPU time, without the kernel's time on its behalf.

    ``getrusage`` where there is one: ``os.times`` counts the same time on
    POSIX, but in clock ticks (a hundredth of a second), coarser than a small
    run may be.
    """
    if resource is None:
        return os.times().user
    return resource.getrusage(resource.RUSAGE_SELF).ru_utime


def default_clock() -> Callable[[], float]:
    """The clock the measures read when a test names none: the one to calibrate by."""
    return _clock_of(None, whole_process=False)


def _clock_of(clock: Callable[[], float] | None, whole_process: bool) -> Callable[[], float]:
    if clock is not None:
        return clock
    if sys.platform == "darwin":
        return _user_seconds
    return time.process_time if whole_process else time.thread_time


def clock_grain(clock: Callable[[], float]) -> float:
    """The step ``clock`` moves in: the first change it reads, within half a second."""
    if clock not in _GRAIN:
        start = now = clock()
        deadline = time.perf_counter() + 0.5
        while now == start and time.perf_counter() < deadline:
            now = clock()
        _GRAIN[clock] = now - start
    return _GRAIN[clock]


def _timed_once(call: Callable[[], Any], clock: Callable[[], float]) -> float:
    """One run of ``call`` by ``clock``, the collector held during it.

    Only the young generations are emptied before the run: what an earlier
    run left is young, and a full collection of the test process's heap
    before every run would cost more than most runs it precedes.
    """
    was_enabled = gc.isenabled()
    gc.collect(1)
    gc.disable()
    try:
        started = clock()
        call()
        return clock() - started
    finally:
        if was_enabled:
            gc.enable()


def _runs_to_span_the_clock(call: Callable[[], Any], clocked: Callable[[], float]) -> int:
    """How many runs of ``call`` it takes to span :data:`GRAINS` ticks of ``clocked``.

    One where the tick is fine enough to read a single run.
    """
    times = 1
    if (least := GRAINS * clock_grain(clocked)) > FLOOR_SECONDS:
        while times < 1 << 16 and _timed_once(repeated(call, times), clocked) < least:
            times *= 2
    return times


def cpu_seconds(
    call: Callable[[], Any],
    repeats: int = 5,
    *,
    whole_process: bool = False,
    clock: Callable[[], float] | None = None,
) -> float:
    """The best of ``repeats`` CPU times of ``call``, in seconds, with the collector off.

    The calling thread's CPU time, or the whole process's with
    ``whole_process`` for work that crosses threads. ``clock`` replaces both,
    for work whose time is a wait (``time.perf_counter``). Where the default
    clock's tick is coarse (Windows), each timed run repeats ``call`` as often
    as it takes to span :data:`GRAINS` ticks and the time is per call.
    """
    measure = _clock_of(clock, whole_process)
    gc.collect()
    times = 1 if clock is not None else _runs_to_span_the_clock(call, measure)
    timed = repeated(call, times) if times > 1 else call
    return min(_timed_once(timed, measure) for _ in range(repeats)) / times


def _best_pair(
    small: Callable[[], Any],
    large: Callable[[], Any],
    repeats: int,
    measure: Callable[[Callable[[], Any]], float],
) -> tuple[float, float]:
    """The best time of each call over ``repeats`` runs taken in turn: small, large, small, ..."""
    best_small = best_large = float("inf")
    for _ in range(repeats):
        best_small = min(best_small, measure(small))
        best_large = min(best_large, measure(large))
    return best_small, best_large


def held_over_rounds(
    measure: Callable[[], dict[str, float]],
    holds: Callable[[dict[str, float]], bool],
    small: Collection[str],
    rounds: int | None = None,
) -> tuple[dict[str, float] | None, list[dict[str, float]], dict[str, float]]:
    """Measure up to ``rounds`` rounds (:data:`ROUNDS`) until one holds: every ratio's rule.

    ``measure()`` takes one round, the best time of each named run in it;
    ``holds(times)`` is the test's verdict on a set of times, and reads only
    the times it is handed; ``small`` names every time whose slowing makes
    ``holds`` easier (the smaller input's in a plain ratio). A first round
    that holds is the whole measure. After each later round the best of
    every round so far, name by name, is judged, and so is the round itself
    if each of its ``small`` times is within :data:`ROUND_DRIFT` of the best
    one; the round is judged first. An empty ``small``, or a name the first
    round did not return, is refused. Returns the times that held (``None``
    if none did), every round, and the best of every round.
    """
    count = ROUNDS if rounds is None else rounds
    assert count >= 2, f"{count} rounds: a ratio is read again on at least a second round"
    taken = [measure()]
    assert small, "no time is named whose slowing makes the verdict easier: name every one"
    for name in small:
        assert name in taken[0], f"{name!r} is not a time the measure returned: {sorted(taken[0])}"
    pooled = taken[0]
    judged = [pooled]
    while True:
        for times in judged:
            if holds(times):
                return times, taken, pooled
        if len(taken) == count:
            return None, taken, pooled
        taken.append(measure())
        pooled = {name: min(times[name] for times in taken) for name in taken[0]}
        drifted = any(taken[-1][name] > ROUND_DRIFT * pooled[name] for name in small)
        judged = [pooled] if drifted else [taken[-1], pooled]


def assert_ratio(
    small: Callable[[], Any],
    large: Callable[[], Any],
    limit: float,
    *,
    what: str = "the larger input",
    repeats: int = 3,
    warm: bool = True,
    floor: float = 0.0,
    whole_process: bool = False,
    clock: Callable[[], float] | None = None,
    self_timed: bool = False,
) -> tuple[float, float]:
    """Assert ``large`` costs under ``limit`` times what ``small`` costs, on their best times.

    ``small`` and ``large`` are zero-argument calls on inputs built before
    the call, so the setup is outside the measure. ``warm`` runs ``small``
    once untimed first, so a first call's imports and compiled patterns are
    not in the small time. The bound is ``limit * small + limit * floor``:
    ``floor`` is a test's additive allowance, so ``large < a * small + b`` is
    ``limit=a, floor=b / a`` and keeps that bound exactly; without it the
    bound is ``limit * small``. A best small time under
    :data:`FLOOR_SECONDS` fails whatever the floor: grow the input until the
    small run is measurable.
    With ``self_timed`` each call returns the seconds it measured itself (a
    child process timing its own work), and the clock is not read.
    Where the default clock's tick is coarse (Windows), each timed run
    repeats both calls as often as it takes the small one to span
    :data:`GRAINS` ticks; the times and the floor are per call all the same.
    Each round is ``repeats`` pairs, judged by :func:`held_over_rounds`.
    Returns the best small and large times that held, per call: the first
    round's, a later round's own, or the best of every round, in that order.
    """
    clocked = _clock_of(clock, whole_process)

    def measure(call: Callable[[], Any]) -> float:
        return float(call()) if self_timed else _timed_once(call, clocked)

    if warm:
        small()
    gc.collect()
    times = 1
    coarse = not self_timed and clock is None
    if coarse:
        times = _runs_to_span_the_clock(small, clocked)
        if times > 1:
            small, large, floor = repeated(small, times), repeated(large, times), floor * times

    def one_round() -> dict[str, float]:
        best_small, best_large = _best_pair(small, large, repeats, measure)
        return {"small": best_small, "large": best_large}

    first = one_round()
    assert first["small"] >= FLOOR_SECONDS, (
        f"the small run of {what} took {first['small'] * 1000:.2f} ms, under the "
        f"{FLOOR_SECONDS * 1000:g} ms a ratio can be read from: grow the input"
    )
    unread = [first]
    held, taken, best = held_over_rounds(
        lambda: unread.pop() if unread else one_round(),
        lambda t: t["large"] < limit * (t["small"] + floor),
        ["small"],
    )
    if held is not None:
        return held["small"] / times, held["large"] / times
    rounds = [(t["small"], t["large"]) for t in taken]
    pooled = (best["small"], best["large"])
    allowed = f"limit {limit:g}" + (f" plus {limit * floor * 1000:.1f} ms" if floor else "")
    named = ["on the first", *["on the next"] * (len(rounds) - 2), "on the last"]
    # A later round whose small runs drifted past ROUND_DRIFT was read only in the best of all.
    drift = [s / min(r[0] for r in rounds[: at + 1]) for at, (s, _) in enumerate(rounds)]
    read = [
        f"{s * 1000:.1f} ms to {t * 1000:.1f} ms ({t / s:.1f} times) {name} {repeats}"
        + (f" (its small runs {d:.2f} times the best, not read alone)" if d > ROUND_DRIFT else "")
        for name, (s, t), d in zip(named, rounds, drift, strict=True)
    ]
    alone = [t / s for (s, t), d in zip(rounds, drift, strict=True) if d <= ROUND_DRIFT]
    raise AssertionError(
        f"{what} took {min([*alone, pooled[1] / pooled[0]]):.1f} times as long, "
        f"{allowed}: {read[0]} pairs, {', '.join(read[1:])}, "
        f"{pooled[1] / pooled[0]:.1f} times on the best of all {len(rounds) * repeats}"
        + (f" (each run {times} calls)" if times > 1 else "")
    )


def assert_scales(
    build: Callable[[int], Any],
    small: int,
    call: Callable[[Any], Any] | None = None,
    *,
    factor: int = 8,
    repeats: int = 3,
    limit: float | None = None,
    floor: float = 0.0,
    whole_process: bool = False,
) -> tuple[float, float]:
    """Assert ``factor`` times the input costs under ``SCALING_SLACK * factor`` times as much.

    ``build(size)`` makes the input, so the setup is outside the measure, and
    ``call(input)`` is what is timed; without ``call``, ``build(size)`` returns
    the zero-argument call itself. Size ``small`` so its call takes a few
    milliseconds. ``limit`` replaces the default bound where the test states
    its own, and ``floor`` its additive allowance, as in :func:`assert_ratio`.
    A limit is refused unless ``factor`` squared, a quadratic call's ratio, is
    over :data:`ROUND_DRIFT` times it: a later round read on its own holds
    the best times' ratio under that many times the limit. A limit under
    ``factor`` (a cost that does not grow) is always further from ``factor``
    squared than that.
    """
    bound = SCALING_SLACK * factor if limit is None else limit
    # The refusal line is ROUND_DRIFT times the limit: a call at factor 4 with
    # the default limit of 12 sits just above it, 16 against 15.6.
    assert factor**2 > ROUND_DRIFT * bound, (
        f"a limit of {bound:g} on {factor} times the input is within {ROUND_DRIFT:g} of "
        f"a quadratic call's {factor**2}, which a later round's drift may pass: "
        f"state a limit under {factor**2 / ROUND_DRIFT:.1f} or a larger factor"
    )

    def timed(size: int) -> Callable[[], Any]:
        made = build(size)
        return made if call is None else (lambda: call(made))

    return assert_ratio(
        timed(small),
        timed(small * factor),
        bound,
        what=f"{factor} times the input",
        repeats=repeats,
        floor=floor,
        whole_process=whole_process,
    )


def assert_under(
    call: Callable[[], Any],
    seconds: float,
    *,
    what: str = "the call",
    repeats: int = 3,
    whole_process: bool = False,
    clock: Callable[[], float] | None = None,
    self_timed: bool = False,
) -> float:
    """Assert one run of ``call`` takes under ``seconds``, running it again only when it does not.

    A run over the bound is run again, up to ``repeats`` runs, and the
    assertion reads the best of them; a call that is over the bound on
    every run fails with every time it took. With ``self_timed`` the call
    returns the seconds it measured itself, as in :func:`assert_ratio`.
    Returns the best time.
    """
    clocked = _clock_of(clock, whole_process)
    gc.collect()
    took: list[float] = []
    for _ in range(repeats):
        took.append(float(call()) if self_timed else _timed_once(call, clocked))
        if took[-1] < seconds:
            return took[-1]
    assert min(took) < seconds, (
        f"{what} took {', '.join(f'{t:.3f}' for t in took)} s, over {seconds:g} s every time"
    )
    return min(took)
