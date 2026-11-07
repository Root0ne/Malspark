"""The shared cost measure passes linear work on a loaded machine and fails quadratic work.

Two kinds of proof. The real ones time a synthetic linear and a synthetic
quadratic call on the CPU clock, as every scaling test does. The simulated
ones replace the clock with one the calls advance by a cost the test sets, so
a busy machine is a run the test makes slower on purpose: that is the noise a
shared runner adds, written down, and the measure must read through it.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tests.linear_cost import (
    TIME_RATIO_LIMIT,
    assert_ratio,
    assert_scales,
    assert_under,
    calls,
    cpu_seconds,
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
        small, large = assert_ratio(_linear(200_000), _linear(800_000), TIME_RATIO_LIMIT)
        assert small > 0.002 and large > small

    def test_quadratic_work_four_times_larger_fails_and_says_both_attempts(self) -> None:
        with pytest.raises(AssertionError) as failed:
            assert_ratio(_quadratic(1_500), _quadratic(6_000), TIME_RATIO_LIMIT)
        message = str(failed.value)
        assert "on the first 3 pairs" in message and "on the next 3" in message

    def test_assert_scales_passes_linear_and_fails_quadratic(self) -> None:
        assert_scales(_linear, 100_000, factor=8)
        with pytest.raises(AssertionError):
            assert_scales(_quadratic, 800, factor=8)

    def test_assert_under_bounds_a_cost(self) -> None:
        assert assert_under(_linear(10_000), 1.0) < 1.0
        with pytest.raises(AssertionError, match="every time"):
            assert_under(_quadratic(3_000), 0.0001)

    def test_cpu_seconds_is_the_best_run(self) -> None:
        assert 0 < cpu_seconds(_linear(50_000), repeats=3) < 1.0

    def test_calls_counts_and_does_not_time(self) -> None:
        assert calls(lambda: [abs(i) for i in range(100)]) >= 100


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
