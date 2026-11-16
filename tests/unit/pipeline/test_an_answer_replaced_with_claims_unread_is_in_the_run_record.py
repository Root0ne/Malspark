"""An answer replaced while claims it began were unread is in the run record (T-708).

Only the answer in force can degrade the run: a retry or a later round that
replaced an answer carries its own read, and the replaced one's unread claims
were in the log alone. Each time such an answer leaves force, the run summary
records it beside ``validation.retry_drops``: the analyst, the round, the
claims begun, read and unread, why, and what replaced it. It is a fact of the
record only: no degradation reason, no sentence in the report.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from malspark.agents.base_agent import BaseAnalyst
from malspark.agents.static_analyst import StaticAnalyst
from malspark.analysis.run_summary import RunSummaryBuilder
from malspark.core.truncation_ledger import TruncationLedger
from malspark.pipeline.nodes import claims_unread_in_force
from malspark.pipeline.revision_merge import UNREAD_BLOCKS_WHY
from malspark.pipeline.validation import (
    CLAIMS_UNREAD_REPLACED_RECORD,
    claims_unread_replaced_row,
    validation_metrics,
)

# A block whose heading was written and whose claim was not.
SHORT = (
    "CLAIM 1: The loader resolves its imports by hash.\n"
    "EVIDENCE: [ev_0002]\n"
    "CONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n"
    "\n"
    "**CLAIM 2:**\n"
)
# Five headings begun and none read.
NONE_READ = "".join(f"**CLAIM {n}:**\n\n" for n in range(1, 6)) + "CLAIM 6\n"
WHOLE = (
    "CLAIM 1: The loader resolves its imports by hash.\n"
    "EVIDENCE: [ev_0002]\n"
    "CONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n"
)


def _analyst() -> StaticAnalyst:
    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.name = "reverser"
    analyst.logger = logging.getLogger("test.replaced")
    analyst.truncation_ledger = TruncationLedger()
    return analyst


def test_the_reader_keeps_the_counts_beside_the_reason() -> None:
    isr = _analyst()._text_to_isr(SHORT, revision_round=1)
    assert isr.claims_unread_reason
    assert isr.claims_unread_counts == (2, 1, 1)
    assert _analyst()._text_to_isr(WHOLE, revision_round=1).claims_unread_counts is None


def test_a_replaced_answer_s_unread_claims_are_one_row() -> None:
    analyst = _analyst()
    first = analyst._text_to_isr(SHORT, revision_round=0)
    retry = analyst._text_to_isr(WHOLE, revision_round=0)
    row = claims_unread_replaced_row("reverser", first, retry, "retry")
    assert row == {
        "record": CLAIMS_UNREAD_REPLACED_RECORD,
        "agent": "reverser",
        "round": "0",
        "begun": "2",
        "read": "1",
        "unread": "1",
        "why": UNREAD_BLOCKS_WHY,
        "replaced_by": "retry",
    }
    # The retry in force read whole: the run is not degraded by the first's read.
    assert claims_unread_in_force({"reverser": retry}) == []


def test_an_answer_whose_reason_stays_in_force_is_no_row() -> None:
    first = _analyst()._text_to_isr(SHORT, revision_round=0)
    assert claims_unread_replaced_row("reverser", first, first, "retry") is None
    copied = first.model_copy(update={"claims": []})
    assert claims_unread_replaced_row("reverser", first, copied, "round 1") is None
    whole = _analyst()._text_to_isr(WHOLE, revision_round=0)
    assert claims_unread_replaced_row("reverser", whole, first, "retry") is None
    assert claims_unread_replaced_row("reverser", None, first, "retry") is None


def test_a_retry_that_replaces_an_answer_read_to_nothing_is_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyst = _analyst()
    first = analyst._text_to_isr(NONE_READ, revision_round=0)
    assert first.claims_unread_counts is not None
    begun, read, unread = first.claims_unread_counts
    assert (begun, read, unread) == (5, 0, 4)
    retry = analyst._text_to_isr(WHOLE, revision_round=0)

    def _turn(_self: Any, isr: Any, _evidence: str, **_kw: Any) -> Any:
        return retry

    monkeypatch.setattr(BaseAnalyst, "_validation_turn", _turn)
    assert analyst._validate_isr(first, "evidence") is retry
    (row,) = analyst.drain_unparsed_answers()
    assert row["record"] == CLAIMS_UNREAD_REPLACED_RECORD
    assert (row["begun"], row["read"], row["unread"]) == ("5", "0", "4")
    assert row["replaced_by"] == "retry"
    assert claims_unread_in_force({"reverser": retry}) == []


def test_a_validation_turn_that_keeps_the_answer_records_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyst = _analyst()
    first = analyst._text_to_isr(SHORT, revision_round=0)
    monkeypatch.setattr(BaseAnalyst, "_validation_turn", lambda _s, isr, _e, **_k: isr)
    assert analyst._validate_isr(first, "evidence") is first
    assert analyst.drain_unparsed_answers() == []
    assert claims_unread_in_force({"reverser": first}) == [first.claims_unread_reason]


def test_the_run_summary_lists_the_rows_beside_the_retry_drops() -> None:
    analyst = _analyst()
    first = analyst._text_to_isr(SHORT, revision_round=2)
    later = analyst._text_to_isr(WHOLE, revision_round=3)
    row = claims_unread_replaced_row("reverser", first, later, "round 3")
    assert row is not None
    metrics = validation_metrics(0, [], unparsed_answers=[row])
    assert metrics["claims_unread_replaced"] == [{k: v for k, v in row.items() if k != "record"}]
    assert "unparsed_answers" not in metrics
    summary = RunSummaryBuilder(start_time=0.0).set_validation(metrics).build()
    assert summary.validation is not None
    assert summary.validation.answers["claims_unread_replaced"][0]["replaced_by"] == "round 3"


def test_a_later_round_that_replaces_the_answer_in_force_is_recorded() -> None:
    import asyncio
    from unittest.mock import MagicMock

    from malspark.core.config import MEDIATOR_AGENT_NAME
    from malspark.pipeline.nodes import make_revision_node
    from malspark.pipeline.state import AgentArgument

    analyst = _analyst()
    in_force = analyst._text_to_isr(SHORT, revision_round=0)
    in_force.note_answer_text(SHORT)
    revision = analyst._text_to_isr(WHOLE, revision_round=1)
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["reverser"]
    container.analyst_keys.return_value = ["reverser"]
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    agent = MagicMock()
    agent.safe_revise_isr.return_value = (WHOLE, revision)
    container.get_agent.return_value = agent
    container.load_chunked.return_value = [MagicMock(content="data")]
    container.load_data.return_value = "data"
    mediation = AgentArgument(
        agent_name=MEDIATOR_AGENT_NAME,
        finding="revise",
        contradictions=["[analysts: REVERSER] claim 1 versus the listing."],
        revise=["reverser"],
    )
    state = {
        "file_hash": "abc",
        "iteration_count": 1,
        "discussion_history": [mediation],
        "reports": {"reverser": SHORT},
        "isr_reports": {"reverser": in_force},
    }
    out = asyncio.run(make_revision_node(container)(state))
    rows = [
        row
        for row in out.get("validation_unparsed_answers") or []
        if row.get("record") == CLAIMS_UNREAD_REPLACED_RECORD
    ]
    assert [(r["agent"], r["round"], r["unread"], r["replaced_by"]) for r in rows] == [
        ("reverser", "0", "1", "round 1")
    ]
    assert claims_unread_in_force(out["isr_reports"]) == []
