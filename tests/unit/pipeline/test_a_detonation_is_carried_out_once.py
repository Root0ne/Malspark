"""A further detonation is carried out once, by the step that claimed it.

Two reading steps entered at once (siblings of a parallel stage, run on
threads as the graph runs synchronous nodes) find the same pending
detonation: one claims it under the job's lock and submits it; the other
waits for it and reads its result. Offline: the detonator is a stand-in.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from malspark.pipeline import detonations as dt
from malspark.providers.detonation import DetonationRecord
from malspark.providers.detonation_requests import ACCEPTED, DetonationRequest
from tests.unit.pipeline.test_a_later_detonation_is_read_by_the_platform import (
    D2_REPORT,
    container_with_a_pending_request,
)


def _two_steps_at_once(container: Any) -> list[Any]:
    """Two sibling reading steps entered on two threads, as the graph runs synchronous nodes."""
    seen: dict[str, Any] = {}

    def _node(label: str) -> Any:
        def node(state: Any) -> dict[str, Any]:
            seen[label] = {
                "records": [r.name for r in container.detonations],
                "d2_reported": container.detonations[-1].reported,
                "rows": [
                    row["id"] for row in state.get("evidence_ledger") or () if isinstance(row, dict)
                ],
            }
            return {}

        return node

    first = dt.on_entry(
        container,
        "dynamic_analyst",
        _node("dynamic"),
        reading_agents=("dynamic",),
        analysis_agents=("dynamic",),
    )
    second = dt.on_entry(
        container,
        "network_analyst",
        _node("network"),
        reading_agents=("network",),
        analysis_agents=("network",),
    )

    async def main() -> list[Any]:
        loop = asyncio.get_running_loop()
        return list(
            await asyncio.gather(
                loop.run_in_executor(None, first, {"evidence_ledger": []}),
                loop.run_in_executor(None, second, {"evidence_ledger": []}),
            )
        )

    outs = asyncio.run(main())
    container.seen = seen
    return outs


class TestOneSubmissionPerRequest:
    def test_two_steps_entering_at_once_submit_the_sample_once(self, monkeypatch: Any) -> None:
        container = container_with_a_pending_request()
        monkeypatch.setattr(dt, "reads_the_sandbox", lambda container, agent: True)
        started = threading.Event()
        release = threading.Event()

        async def _slow(record: DetonationRecord) -> None:
            container.detonated.append(record.name)
            started.set()
            # Held until the second step has entered and found it in flight.
            await asyncio.to_thread(release.wait, 5)
            record.report = D2_REPORT

        container.detonator = _slow
        threading.Timer(0.3, release.set).start()
        outs = _two_steps_at_once(container)

        assert started.is_set()
        assert container.detonated == ["d2"]
        assert [r.name for r in container.detonations] == ["d1", "d2"]
        # Both steps read d2 with its report, and its reads.
        for label in ("dynamic", "network"):
            assert container.seen[label]["d2_reported"] is True
            assert len(container.seen[label]["rows"]) == 6
        assert container.detonations_seen == {"dynamic": {"d1", "d2"}, "network": {"d1", "d2"}}
        # Only the step that carried it out returns its reads.
        returned = [out.get("evidence_ledger") or [] for out in outs]
        assert sorted(len(rows) for rows in returned) == [0, 6]
        assert dt.in_flight(container) is False

    def test_every_pending_detonation_is_claimed_once_by_one_step(self, monkeypatch: Any) -> None:
        container = container_with_a_pending_request()
        monkeypatch.setattr(dt, "reads_the_sandbox", lambda container, agent: True)
        container.detonation_requests.append(
            DetonationRequest(
                number=2,
                agent="network",
                stage="analysis",
                arguments="-other",
                reason="a switch",
                cited_entries=["ev_0001"],
                state=ACCEPTED,
                detonation="d3",
            )
        )
        _two_steps_at_once(container)
        assert container.detonated == ["d2", "d3"]
        assert [r.name for r in container.detonations] == ["d1", "d2", "d3"]
