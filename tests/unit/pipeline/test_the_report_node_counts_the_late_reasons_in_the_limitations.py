"""The report node reads the recorded reasons again after the composer and after the round (T-601).

The limitations inventory is built before the report's prose is written; the
composer and the section agreement round each record what they could not do
after that. Driven through the node: the round is shown the composer's reason
among the inventory's rows, a reason each one records is on the stored
inventory, and section 11 counts the same other limitations the bundle's list
of what limited the run holds.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from malspark.pipeline.validation import ValidationTally
from malspark.reporting.limitation_facts import _ANSWER_READ_NOTE
from malspark.reporting.models import MalwareReport, TechnicalAnalysis, TechnicalSubsection
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from tests.stages import paper_profile
from tests.unit.pipeline.test_what_is_served_is_the_final_report import _state

COMPOSER_REASON = "The conclusion section was left out after its retries."
ROUND_REASON = "The section agreement question was not answered after its retries."


class _Composer:
    """Writes the limitations paragraph and records one section it could not write."""

    llm = None

    def __init__(self) -> None:
        self.degradations = [COMPOSER_REASON]
        self.validation_tally = ValidationTally()

    async def compose(self, report: MalwareReport, *_args: Any, **_kwargs: Any) -> None:
        report.technical_analysis = TechnicalAnalysis(
            analyst_limitations=TechnicalSubsection(
                title="Limitations", body="The run's evidence is partial."
            )
        )


@pytest.fixture
def container() -> Any:
    fake = MagicMock()
    fake.agent_registry.list_agents.return_value = ["static"]
    fake.analyst_keys.return_value = ["static"]
    fake.agent_role.side_effect = lambda n: n
    fake.is_mock = False
    fake.config.reporting.enabled = True
    fake.config.llm.parallel_analysts = False
    fake.config.negotiation.max_iterations = 3
    fake.active_profile.return_value = paper_profile(["static"], parallel=False)
    fake.get_narrative_agent.return_value = None
    fake.get_report_composer.return_value = _Composer()
    fake.get_static_provider.return_value.capabilities.provides_evidence = False
    return fake


@pytest.mark.asyncio
async def test_the_composer_s_and_the_round_s_reasons_are_counted_in_section_11(
    container: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import malspark.pipeline.analyst_mode as analyst_mode
    import malspark.pipeline.nodes as nodes

    shown: list[str] = []

    async def _round(report: MalwareReport, *_args: Any, **_kwargs: Any) -> None:
        # What the round is shown: the inventory's rows, read off the report as it stands.
        assert report.limitation_inventory is not None
        shown.extend(report.limitation_inventory.recorded)
        report.degradation_reasons.append(ROUND_REASON)

    monkeypatch.setattr(nodes, "_ask_section_agreement", _round)
    monkeypatch.setattr(
        analyst_mode,
        "resolve_reporter_mode",
        lambda _config: SimpleNamespace(parallel=False, at_once=None, reason="one slot"),
    )
    stage = next(step for step in container.active_profile().stages if step.kind == "report")
    node = nodes.make_report_node(container, stage=stage, announces=False)

    result = await node(_state())  # type: ignore[arg-type]

    assert COMPOSER_REASON in shown and ROUND_REASON not in shown
    stored = MalwareReport.model_validate(result["malware_report"])
    inventory = stored.limitation_inventory
    assert inventory is not None
    assert COMPOSER_REASON in inventory.recorded and ROUND_REASON in inventory.recorded
    # Section 11's count is the bundle's list of what limited the run, less its tool lines
    # and the answer-read notes.
    bundle = MarkdownRenderer(layout=BUNDLE).render(stored)
    limited = bundle.split("**What limited this run:**", 1)[1].split("\n\n", 2)[1]
    items = [line for line in limited.splitlines() if line.startswith("- ")]
    notes = [r for r in stored.degradation_reasons if _ANSWER_READ_NOTE.match(str(r))]
    others = len(items) - len(inventory.not_offered) - len(notes)
    assert others == len(inventory.recorded) >= 2
    analyst = MarkdownRenderer(layout=ANALYST).render(stored)
    section = analyst.split("## 11. Limitations", 1)[1].split("\n## ", 1)[0]
    assert f"{others} other limitations the run recorded" in section
