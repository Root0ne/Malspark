"""Nothing slow is read under the request lock, the ceiling holds, and a repeat is answered truly.

Whether the provider can pass the arguments (a launcher builds and hashes
the sample's archive) is read before the process-wide lock; requests filed
at once never pass the ceiling; a request with a made detonation's
arguments is answered by whether that detonation reported, is running, or
returned nothing (T-671 review B9). Offline.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from malspark.providers import detonation_requests as dr
from malspark.providers.detonation import DetonationRecord
from tests.unit.providers.test_every_detonation_request_is_located_in_the_ledger import (
    a_job,
    filed,
)


def test_the_launch_answer_is_built_outside_the_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    held: list[bool] = []

    def _slow(container: Any, arguments: str) -> str:
        held.append(dr._LOCK.locked())
        return ""

    monkeypatch.setattr(dr, "_cannot_detonate", _slow)
    request = filed(a_job())
    assert request.state == dr.ACCEPTED and held == [False]


def test_the_ceiling_is_never_passed_by_requests_filed_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = a_job(max_detonations_per_job=2)

    def _slow(container: Any, arguments: str) -> str:
        time.sleep(0.05)
        return ""

    monkeypatch.setattr(dr, "_cannot_detonate", _slow)
    threads = [threading.Thread(target=filed, args=(container, f"-p {n}")) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    accepted = [r for r in container.detonation_requests if r.state == dr.ACCEPTED]
    assert len(accepted) == 1 and accepted[0].detonation == "d2"


def test_a_made_detonation_s_arguments_are_answered_by_how_it_stands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dr, "_cannot_detonate", lambda container, arguments: "")
    container = a_job()
    first = container.detonations[0]
    first.arguments = "-p x"
    first.launch = {"honoured": True}
    first.report = None
    first.failure = "the sandbox timed out"
    assert filed(container).answer == (
        "detonation d1 was already launched with exactly these arguments and returned no "
        "sandbox report, so it is not launched again: the sandbox timed out"
    )
    first.report = {}
    assert filed(container).answer == dr.REFUSED_EXISTS.format(name="d1")
    running = DetonationRecord(ordinal=2, origin="agent", arguments="-r")
    running.launch, running.running = {"honoured": True}, True
    container.detonations.append(running)
    assert filed(container, "-r").answer == dr.REFUSED_RUNNING.format(name="d2")


def test_an_id_issued_while_the_request_is_read_never_makes_a_false_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cited id is issued between the read before the lock and the check under it (r2 N4)."""
    monkeypatch.setattr(dr, "_cannot_detonate", lambda container, arguments: "")
    # Not issued yet while the request is read; issued by the time the lock is taken.
    monkeypatch.setattr(
        dr, "_unissued", lambda container, cited: [] if dr._LOCK.locked() else list(cited)
    )
    request = filed(a_job())
    assert request.state == dr.ACCEPTED, request.answer
    assert request.answer != dr.NO_LATER_STEP


def test_a_repeat_is_compared_on_the_exact_launch_text_and_the_tool_says_where_it_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """r3 R6: the pack shows a launch text escaped; the request tool compares the exact text."""
    from types import SimpleNamespace

    monkeypatch.setattr(dr, "_cannot_detonate", lambda container, arguments: "")
    container = a_job()
    made = DetonationRecord(ordinal=2, origin="agent", arguments="-p a|b", report={})
    made.launch = {"honoured": True}
    container.detonations.append(made)
    assert filed(container, "-p a|b").answer == dr.REFUSED_EXISTS.format(name="d2")
    # The text as the pack shows it is another argument set: not the one made.
    assert filed(container, "-p a\\x7cb").answer != dr.REFUSED_EXISTS.format(name="d2")
    container.get_sandbox_provider = lambda: SimpleNamespace(
        capabilities=SimpleNamespace(can_submit=True, can_pass_launch_arguments=True)
    )
    description = dr.request_tool(container).description
    assert "launched_with" in description and "escaped" in description
