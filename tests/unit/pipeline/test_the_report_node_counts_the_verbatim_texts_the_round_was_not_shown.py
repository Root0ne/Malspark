"""The report node counts, on the round's record, the verbatim texts the round was not shown.

Driven through the node: once every other change to the report is in, the round's record in
the run summary carries how many texts the finished analyst report prints in their writer's
own words that the round was not shown (T-613). The round here records an empty set, as a
round that was not asked does, so the count is that of the texts the report prints.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.reporting.models import CapabilityCell, MalwareReport
from malspark.reporting.section_agreement import VERBATIM_SHOWN, VERBATIM_UNSEEN
from tests.unit.pipeline.test_the_report_node_counts_the_late_reasons_in_the_limitations import (
    container,  # noqa: F401 — the fixture, by name
)
from tests.unit.pipeline.test_what_is_served_is_the_final_report import _state


@pytest.mark.asyncio
async def test_the_node_puts_the_unseen_count_on_the_round_s_record(
    container: Any,  # noqa: F811 — the fixture imported above
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import malspark.pipeline.analyst_mode as analyst_mode
    import malspark.pipeline.nodes as nodes

    async def _round(report: MalwareReport, *_args: Any, **_kwargs: Any) -> None:
        # One claim sentence the ATT&CK table prints in its writer's own words.
        report.capability_matrix.append(
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1622",
                technique_name="Debugger Evasion",
                evidence=["Routine 0x5b20 returns -1 when the BeingDebugged byte is set."],
            )
        )
        report.run_summary = {
            **(report.run_summary or {}),
            "section_agreement": {VERBATIM_SHOWN: {}},
        }

    monkeypatch.setattr(nodes, "_ask_section_agreement", _round)
    monkeypatch.setattr(
        analyst_mode,
        "resolve_reporter_mode",
        lambda _config: SimpleNamespace(parallel=False, at_once=None, reason="one slot"),
    )
    stage = next(step for step in container.active_profile().stages if step.kind == "report")
    node = nodes.make_report_node(container, stage=stage, announces=False)

    result = await node(_state())  # type: ignore[arg-type]

    stored = MalwareReport.model_validate(result["malware_report"])
    assert stored.run_summary["section_agreement"][VERBATIM_UNSEEN] >= 1
