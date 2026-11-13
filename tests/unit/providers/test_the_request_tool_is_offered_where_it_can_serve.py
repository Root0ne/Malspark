"""The request tool is offered only to an agent a later step of its team could serve.

Decided from the team's shape (a step that carries a request out reachable
after the agent's own stage) and the ceiling, never from the agent's name
(T-671 review B11). Offline.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from malspark.core.config import StageDefinition
from malspark.providers import detonation_requests as dr
from tests.unit.providers.test_every_detonation_request_is_located_in_the_ledger import a_job


def _with_a_box(container: Any) -> Any:
    caps = SimpleNamespace(can_submit=True, can_pass_launch_arguments=True, launcher=None)
    container.get_sandbox_provider = lambda: SimpleNamespace(capabilities=caps)
    return container


def test_an_analyst_is_offered_it_and_the_judge_is_not() -> None:
    container = _with_a_box(a_job())
    assert dr.offered(container, "dynamic")
    # Nothing after the verdict stage reads the sandbox in the default team.
    assert not dr.offered(container, "judge")


def test_a_ceiling_of_one_offers_it_to_no_one() -> None:
    container = _with_a_box(a_job(max_detonations_per_job=1))
    assert not dr.offered(container, "dynamic")
    assert not dr.offered(container)


def test_a_team_with_no_reading_step_after_the_analyst_does_not_offer_it() -> None:
    stages = [
        StageDefinition(key="triage_pack", kind="triage"),
        StageDefinition(key="analysis", kind="analysis", agents=["dynamic"]),
        StageDefinition(
            key="verdict", kind="verdict", agents=["reporter"], depends_on=["analysis"]
        ),
    ]
    container = _with_a_box(a_job(stages))
    assert not dr.offered(container, "dynamic")
