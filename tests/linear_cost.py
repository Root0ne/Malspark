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
  under the test's limit. Only when that ratio fails does it measure the
  same pairs once more, keeps the best of every run, and fails only if the
  ratio still does; the message gives both attempts. A quadratic reader is
  over its limit on every pair, so a second attempt never passes it.
* :func:`assert_scales` builds the two inputs from one size and a factor and
  holds them to :func:`assert_ratio` with a limit of :data:`SCALING_SLACK`
  times the factor (a quadratic reader takes ``factor`` times more).
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

The clock is the calling thread's CPU time, the whole process's with
``whole_process`` for work that crosses threads, or a clock the test passes
(``time.perf_counter`` for work whose time is a wait). Size the inputs so the
small call takes about 10 ms or more: a ratio over a small run of a few
clock ticks says nothing about the code, and a quadratic call whose small run
is that short passes any limit. :func:`assert_ratio` fails a measure whose
best small run is under :data:`FLOOR_SECONDS`, so such a test cannot pass by
being too fast to measure.
"""

from __future__ import annotations

import gc
import sys
import time
from collections.abc import Callable
from typing import Any

__all__ = [
    "FLOOR_SECONDS",
    "SCALING_SLACK",
    "TIME_RATIO_LIMIT",
    "assert_ratio",
    "assert_scales",
    "assert_under",
    "calls",
    "cpu_seconds",
    "repeated",
]

# Four times the input may take under eight times as long; a quadratic reader
# takes sixteen times as long.
TIME_RATIO_LIMIT = 8

# A linear call on k times the input takes k times as long; up to this many
# times that is noise and cache effects, a quadratic call takes k times more.
SCALING_SLACK = 3.0

# The least a small run may take: under it the clock's grain is the ratio, and
# the measure fails rather than read it.
FLOOR_SECONDS = 0.002


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


def _clock_of(clock: Callable[[], float] | None, whole_process: bool) -> Callable[[], float]:
    if clock is not None:
        return clock
    return time.process_time if whole_process else time.thread_time


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
    for work whose time is a wait (``time.perf_counter``).
    """
    measure = _clock_of(clock, whole_process)
    gc.collect()
    return min(_timed_once(call, measure) for _ in range(repeats))


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
    Returns the best small and large times.
    """
    clocked = _clock_of(clock, whole_process)

    def measure(call: Callable[[], Any]) -> float:
        return float(call()) if self_timed else _timed_once(call, clocked)

    if warm:
        small()
    gc.collect()
    first_small, first_large = _best_pair(small, large, repeats, measure)
    assert first_small >= FLOOR_SECONDS, (
        f"the small run of {what} took {first_small * 1000:.2f} ms, under the "
        f"{FLOOR_SECONDS * 1000:g} ms a ratio can be read from: grow the input"
    )
    first_ratio = first_large / first_small
    if first_large < limit * (first_small + floor):
        return first_small, first_large
    again_small, again_large = _best_pair(small, large, repeats, measure)
    best_small, best_large = min(first_small, again_small), min(first_large, again_large)
    ratio = best_large / best_small
    allowed = f"limit {limit:g}" + (f" plus {limit * floor * 1000:.1f} ms" if floor else "")
    assert best_large < limit * (best_small + floor), (
        f"{what} took {ratio:.1f} times as long, {allowed}: "
        f"{first_small * 1000:.1f} ms to {first_large * 1000:.1f} ms "
        f"({first_ratio:.1f} times) on the first {repeats} pairs, "
        f"{again_small * 1000:.1f} ms to {again_large * 1000:.1f} ms on the next {repeats}"
    )
    return best_small, best_large


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
    """

    def timed(size: int) -> Callable[[], Any]:
        made = build(size)
        return made if call is None else (lambda: call(made))

    return assert_ratio(
        timed(small),
        timed(small * factor),
        SCALING_SLACK * factor if limit is None else limit,
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
