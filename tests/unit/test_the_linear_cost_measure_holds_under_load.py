"""The shared cost measure passes linear work on a loaded machine and fails quadratic work.

Two kinds of proof. The real ones time a synthetic linear and a synthetic
quadratic call on the CPU clock, as every scaling test does. The simulated
ones replace the clock with one the calls advance by a cost the test sets, so
a busy machine is a run the test makes slower on purpose: that is the noise a
shared runner adds, written down, and the measure must read through it.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

import pytest

from tests import linear_cost
from tests.linear_cost import (
    ROUNDS,
    TIME_RATIO_LIMIT,
    assert_ratio,
    assert_scales,
    assert_under,
    calls,
    cpu_seconds,
    peak_bytes,
)


def _linear(n: int) -> Callable[[], int]:
    def run() -> int:
        total = 0
        for i in range(n):
            total += i & 7
        return total

    return run


def _quadratic(n: int) -> Callable[[], int]:
    # The membership test on a list a growing reader keeps: n**2 / 2 steps.
    def run() -> int:
        seen: list[int] = []
        for i in range(n):
            if i not in seen:
                seen.append(i)
        return len(seen)

    return run


class TestOnTheCpuClock:
    def test_linear_work_four_times_larger_passes(self) -> None:
        small, large = assert_ratio(_linear(500_000), _linear(2_000_000), TIME_RATIO_LIMIT)
        assert small > 0.002 and large > small

    def test_quadratic_work_four_times_larger_fails_and_says_every_round(self) -> None:
        with pytest.raises(AssertionError) as failed:
            assert_ratio(_quadratic(2_300), _quadratic(9_200), TIME_RATIO_LIMIT)
        message = str(failed.value)
        assert "on the first 3 pairs" in message and "on the next 3" in message
        assert "on the last 3" in message and "on the best of all 9" in message

    def test_assert_scales_passes_linear_and_fails_quadratic(self) -> None:
        assert_scales(_linear, 500_000, factor=8)
        # Failed on its ratio, not on a small run too short to read; one pair
        # an attempt, as the large quadratic run takes over half a second.
        with pytest.raises(AssertionError, match="times as long"):
            assert_scales(_quadratic, 2_300, factor=8, repeats=1)

    def test_assert_under_bounds_a_cost(self) -> None:
        assert assert_under(_linear(10_000), 1.0) < 1.0
        with pytest.raises(AssertionError, match="every time"):
            assert_under(_quadratic(3_000), 0.0001)

    def test_cpu_seconds_is_the_best_run(self) -> None:
        assert 0 < cpu_seconds(_linear(50_000), repeats=3) < 1.0

    def test_calls_counts_and_does_not_time(self) -> None:
        assert calls(lambda: [abs(i) for i in range(100)]) >= 100

    def test_peak_bytes_counts_a_copy_and_not_a_read(self) -> None:
        line = "x" * 160_000
        assert peak_bytes(lambda: "CLAIM " + line) >= len(line)
        assert peak_bytes(lambda: line.startswith("CLAIM")) < 4096


class TestOnACoarseClock:
    """Windows' CPU clocks move in steps of about 15.6 ms."""

    @staticmethod
    def _coarse(monkeypatch: pytest.MonkeyPatch) -> Callable[[], float]:
        step = 0.015625

        def clock() -> float:
            return int(time.perf_counter() / step) * step

        monkeypatch.setattr(linear_cost, "_clock_of", lambda _clock, _whole: clock)
        return clock

    def test_its_step_is_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert linear_cost.clock_grain(self._coarse(monkeypatch)) == pytest.approx(0.015625)

    def test_linear_work_is_read_over_enough_steps_and_given_per_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._coarse(monkeypatch)
        counted = [0]
        work = _linear(50_000)

        def small() -> int:
            counted[0] += 1
            return work()

        low, high = assert_ratio(small, _linear(200_000), TIME_RATIO_LIMIT)
        assert counted[0] > 2 * 3 + 1, "each timed run repeats the small call"
        assert 0 < low < linear_cost.GRAINS * 0.015625 and high > low

    def test_quadratic_work_still_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._coarse(monkeypatch)
        with pytest.raises(AssertionError, match="times as long"):
            assert_ratio(_quadratic(1_000), _quadratic(4_000), TIME_RATIO_LIMIT, repeats=1)


class _Machine:
    """A clock that only the calls advance, and a load the test lays on chosen runs."""

    def __init__(self, load: Callable[[int], float]) -> None:
        self.now = 0.0
        self.runs = 0
        self._load = load

    def clock(self) -> float:
        return self.now

    def work(self, cost: float) -> Callable[[], None]:
        def run() -> None:
            self.now += cost * self._load(self.runs)
            self.runs += 1

        return run


def _every(period: int, slower: float) -> Callable[[int], float]:
    return lambda run: slower if run % period == 0 else 1.0


class TestUnderSimulatedLoad:
    def test_a_burst_of_load_on_the_large_runs_does_not_fail_linear_work(self) -> None:
        # Runs 0 (warm-up), then small, large, small, large ...: the load lands
        # on the first two large runs only, at three times their cost, the
        # ratio 12 a sequential best-of-two on a busy stretch would have read.
        machine = _Machine(lambda run: 3.0 if run in (2, 4) else 1.0)
        assert_ratio(machine.work(0.01), machine.work(0.04), TIME_RATIO_LIMIT, clock=machine.clock)

    def test_load_on_every_third_run_does_not_fail_linear_work(self) -> None:
        # Every third run is two and a half times slower, so the load falls on
        # each size in turn, as a neighbour's work does that is not in step.
        machine = _Machine(_every(3, 2.5))
        assert_ratio(machine.work(0.01), machine.work(0.04), TIME_RATIO_LIMIT, clock=machine.clock)

    def test_a_whole_first_attempt_under_load_is_measured_again(self) -> None:
        # Every large run of the first attempt (runs 1..6) is slowed to five
        # times its cost; the second attempt is quiet and the test passes.
        machine = _Machine(lambda run: 5.0 if 1 <= run <= 6 and run % 2 == 0 else 1.0)
        small, large = assert_ratio(
            machine.work(0.01), machine.work(0.04), TIME_RATIO_LIMIT, clock=machine.clock
        )
        assert large / small == pytest.approx(4.0)
        assert machine.runs == 13

    def test_quadratic_work_fails_with_load_on_the_small_runs_only(self) -> None:
        # The small runs are never slowed and the large ones are as cheap as
        # they ever get: the quadratic ratio of sixteen still fails.
        machine = _Machine(lambda run: 1.0)
        with pytest.raises(AssertionError, match="took 16.0 times as long"):
            assert_ratio(
                machine.work(0.01), machine.work(0.16), TIME_RATIO_LIMIT, clock=machine.clock
            )

    def test_quadratic_work_fails_however_the_load_falls(self) -> None:
        for load in (_every(2, 3.0), _every(3, 3.0), lambda run: 1.0 + (run % 5) / 2):
            machine = _Machine(load)
            with pytest.raises(AssertionError):
                assert_ratio(
                    machine.work(0.01),
                    machine.work(0.16),
                    TIME_RATIO_LIMIT,
                    clock=machine.clock,
                )

    def test_a_small_run_too_short_to_measure_fails_rather_than_pass(self) -> None:
        # A small run of half a millisecond against a quadratic large one: a
        # floor would have passed it, the measure says to grow the input.
        machine = _Machine(lambda run: 1.0)
        with pytest.raises(AssertionError, match="grow the input"):
            assert_ratio(
                machine.work(0.0005), machine.work(0.008), TIME_RATIO_LIMIT, clock=machine.clock
            )

    def test_without_a_floor_the_bound_is_the_small_run_itself(self) -> None:
        machine = _Machine(lambda run: 1.0)
        with pytest.raises(AssertionError, match="took 9.0 times"):
            assert_ratio(
                machine.work(0.003), machine.work(0.027), TIME_RATIO_LIMIT, clock=machine.clock
            )

    def test_a_stated_allowance_is_added_to_the_bound(self) -> None:
        # ``large < 8 * small + 0.03`` holds 10 ms against 100 ms: 80 + 30 ms.
        # The allowance is added whatever the small run takes, not only when
        # it is under the allowance: a bound of ``8 * max(small, 0.03 / 8)``
        # would be 80 ms here and fail.
        machine = _Machine(lambda run: 1.0)
        assert_ratio(
            machine.work(0.010),
            machine.work(0.100),
            TIME_RATIO_LIMIT,
            floor=0.03 / TIME_RATIO_LIMIT,
            clock=machine.clock,
        )
        over = _Machine(lambda run: 1.0)
        with pytest.raises(AssertionError, match="limit 8 plus 30.0 ms"):
            assert_ratio(
                over.work(0.010),
                over.work(0.111),
                TIME_RATIO_LIMIT,
                floor=0.03 / TIME_RATIO_LIMIT,
                clock=over.clock,
            )

    def test_quadratic_work_fails_after_every_round(self) -> None:
        machine = _Machine(lambda run: 1.0)
        with pytest.raises(AssertionError, match="on the best of all 9"):
            assert_ratio(
                machine.work(0.01), machine.work(0.16), TIME_RATIO_LIMIT, clock=machine.clock
            )
        assert machine.runs == 1 + 2 * 3 * ROUNDS

    def test_a_passing_ratio_takes_one_attempt(self) -> None:
        machine = _Machine(lambda run: 1.0)
        assert_ratio(machine.work(0.01), machine.work(0.04), TIME_RATIO_LIMIT, clock=machine.clock)
        assert machine.runs == 7

    def test_assert_under_runs_a_passing_call_once_and_a_slow_one_again(self) -> None:
        quiet = _Machine(lambda run: 1.0)
        assert_under(quiet.work(0.5), 1.0, clock=quiet.clock)
        assert quiet.runs == 1
        busy = _Machine(lambda run: 3.0 if run == 0 else 1.0)
        assert assert_under(busy.work(0.5), 1.0, clock=busy.clock) == pytest.approx(0.5)
        assert busy.runs == 2


def _by_round(drift: list[tuple[float, float]], jitter: list[float]) -> Callable[[int], float]:
    """A load set per round of three pairs and per size, times a load of each run its own.

    Run 0 is the warm-up; then each round is small, large, small, large ...,
    and a round past the listed ones keeps the last one's drift.
    """

    def load(run: int) -> float:
        if run == 0:
            return 1.0
        slowed = drift[min((run - 1) // 6, len(drift) - 1)][(run - 1) % 2]
        return slowed * jitter[run % len(jitter)]

    return load


def _noisy(seed: int) -> Callable[[int], float]:
    # A shared runner's speed, drawn once per seed: each round slows each size
    # by up to a quarter (the CI record moved a best time by 22 per cent from
    # one round to the next), and each run by up to a tenth more.
    rng = random.Random(seed)
    drift = [(rng.uniform(1.0, 1.25), rng.uniform(1.0, 1.25)) for _ in range(ROUNDS)]
    return _by_round(drift, [rng.uniform(1.0, 1.1) for _ in range(64)])


class TestOnANoisyRunner:
    """The jitter a shared CI runner showed, laid on the runs by a clock the calls advance."""

    def test_the_macos_record_of_a_ratio_its_second_round_held_passes(self) -> None:
        # 43.9 ms to 541.2 ms on the first round (12.3 times), 53.7 ms to
        # 529.5 ms on the next (9.9 times), limit 12: the best of both rounds
        # taken together, 43.9 ms to 529.5 ms, reads 12.1 times, a ratio no
        # round had, and failed the job.
        machine = _Machine(_by_round([(1.0, 541.2 / 529.5), (53.7 / 43.9, 1.0)], [1.0]))
        small, large = assert_ratio(
            machine.work(0.0439), machine.work(0.5295), 12, clock=machine.clock
        )
        assert (small, large) == pytest.approx((0.0537, 0.5295))
        assert machine.runs == 13

    def test_the_macos_record_of_an_allowance_its_second_round_held_passes(self) -> None:
        # Limit 15 plus 50 ms: 13.8 ms to 289.5 ms on the first round, 17.7 ms
        # to 273.2 ms on the next, which holds on its own (under 315.5 ms);
        # the best of both, 13.8 ms to 273.2 ms, is over its 257 ms.
        machine = _Machine(_by_round([(1.0, 289.5 / 273.2), (17.7 / 13.8, 1.0)], [1.0]))
        assert_ratio(
            machine.work(0.0138), machine.work(0.2732), 15, floor=0.05 / 15, clock=machine.clock
        )

    def test_the_same_jitter_on_quadratic_work_fails(self) -> None:
        for drift in ([(1.0, 541.2 / 529.5), (53.7 / 43.9, 1.0)], [(1.0, 1.06), (1.28, 1.0)]):
            machine = _Machine(_by_round(drift, [1.0]))
            with pytest.raises(AssertionError, match="on the best of all 9"):
                assert_ratio(machine.work(0.01), machine.work(0.16), 8, clock=machine.clock)

    def test_linear_work_near_its_limit_passes_whatever_the_seed(self) -> None:
        # Ten times the cost against a limit of twelve: a quarter's drift on
        # the large runs alone fails a round, so some seeds need a later one.
        later = 0
        for seed in range(500):
            machine = _Machine(_noisy(seed))
            assert_ratio(machine.work(0.01), machine.work(0.10), 12, clock=machine.clock)
            later += machine.runs > 7
        assert later >= 10, "the jitter fails a first round now and then"

    def test_quadratic_work_fails_whatever_the_seed(self) -> None:
        for seed in range(500):
            machine = _Machine(_noisy(seed))
            with pytest.raises(AssertionError):
                assert_ratio(machine.work(0.01), machine.work(0.16), 8, clock=machine.clock)
            assert machine.runs == 1 + 2 * 3 * ROUNDS

    def test_on_a_coarse_clock_linear_work_passes_and_quadratic_work_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Windows' 15.6 ms tick over the simulated runner: each timed run
        # repeats its call until it spans the ticks, every call jittered.
        step = 0.015625
        for seed in range(20):
            rng = random.Random(seed)
            machine = _Machine(lambda _run, rng=rng: rng.uniform(1.0, 1.25))

            def coarse(machine: _Machine = machine) -> float:
                return int(machine.clock() / step) * step

            monkeypatch.setattr(linear_cost, "_clock_of", lambda _clock, _whole, c=coarse: c)
            monkeypatch.setitem(linear_cost._GRAIN, coarse, step)
            small, large = assert_ratio(machine.work(0.01), machine.work(0.10), 12)
            assert 0.01 <= small < 0.0125 and 0.1 <= large < 0.125
            with pytest.raises(AssertionError, match="each run 16 calls"):
                assert_ratio(machine.work(0.01), machine.work(0.16), 8)


def test_on_macos_the_clock_is_the_process_s_user_time(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import time

    from tests import linear_cost

    monkeypatch.setattr(sys, "platform", "darwin")
    assert linear_cost._clock_of(None, whole_process=False) is linear_cost._user_seconds
    assert linear_cost._clock_of(None, whole_process=True) is linear_cost._user_seconds
    assert linear_cost._clock_of(time.perf_counter, whole_process=False) is time.perf_counter
    assert linear_cost.default_clock() is linear_cost._user_seconds
    monkeypatch.setattr(sys, "platform", "linux")
    assert linear_cost._clock_of(None, whole_process=False) is time.thread_time
    assert linear_cost.default_clock() is time.thread_time
    assert linear_cost._user_seconds() > 0
