"""A job's detonation state is reset together, so a container's second job starts as its first.

The further turns given and owed, what each agent's turn read, the step
noted and the detonations in flight go with the detonations and requests
when the job's first detonation opens them (T-671 review B10). Offline.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

from malspark.pipeline import detonations as dt


def test_every_per_job_record_is_reset() -> None:
    container = SimpleNamespace(
        further_turns=[{"agent": "dynamic"}],
        detonations_seen={"dynamic": {"d1", "d2"}},
        current_step="judge",
        _further_turns_given=True,
        _detonations_in_flight={"d2": threading.Event()},
    )
    dt.reset_detonation_state(container)
    assert container.further_turns == [] and container.detonations_seen == {}
    assert container.current_step == "" and dt.turns_ahead(container)
    assert not dt.in_flight(container)


def test_the_app_resets_it_with_the_job_s_first_detonation() -> None:
    from malspark.app import MalsparkApp

    app = MalsparkApp(mock=True)
    app.container._further_turns_given = True
    app.container.further_turns = [{"agent": "x"}]
    app.container.detonations_seen = {"x": {"d2"}}
    asyncio.run(app._submit_the_sample(None))
    assert app.container.further_turns == [] and app.container.detonations_seen == {}
    assert dt.turns_ahead(app.container)
