"""A further turn runs through the analyst's real revision path, and its rows are its own.

The analyst is the real ``BaseAnalyst`` with a scripted model, as the
record-only analyst tests build it: the directive naming the later
detonation reaches the prompt, the turn's ledger entries and spend are
carried in the update, its validation runs, and each row it records is
marked as the further turn's, so nothing keyed by round is taken for the
first answer's. A claim citing the later detonation's item is no unknown id.
Every sentence, address and id here is made up for the test.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from malspark.agents.base_agent import BaseAnalyst
from malspark.analysis import sandbox_sections as ss
from malspark.pipeline import detonations as dt
from malspark.providers.detonation import DetonationRecord
from malspark.schemas.evidence import LedgerEntry
from tests.unit.pipeline.test_a_later_detonation_is_read_by_the_platform import (
    D2_REPORT,
    container_with_a_pending_request,
)

# The revised answer: one claim citing the later detonation's process, and one
# that cites nothing, which validation records (the job runs record_only).
REVISED = (
    "CLAIM 1: Started with the password, the sample encrypts the user's files.\n"
    "EVIDENCE: [ev_0003] [d2/proc:9]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    "CLAIM 2: The sample waits before it encrypts.\nEVIDENCE:\nCONFIDENCE: 0.6\n"
    "TECHNIQUE: NONE\n---\n"
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="dynamic")
        self._evidence_entries = [LedgerEntry(id="ev_0003", tool="any_reader", output="file")]
        self._replies: list[str] = list(replies)
        self.seen_turns: list[list[Any]] = []
        # What the turn's meter recorded, as the record-only analyst tests seed it.
        self._budget_records: list[dict[str, Any]] = [{"agent": "dynamic", "turn": "further"}]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(
        self, original_data: str, own_report: str, peer_reports: Any, mediator_feedback: str
    ) -> str:
        """A revision prompt as an analyst's is built, answered by the base revision call."""
        from langchain_core.messages import HumanMessage, SystemMessage

        return self.revision_answer(
            [
                SystemMessage(content="You are in a negotiation round."),
                HumanMessage(
                    content=f"YOUR ORIGINAL REPORT:\n{own_report}\n\n"
                    f"MEDIATOR FEEDBACK:\n{mediator_feedback}\n\nRAW DATA:\n{original_data}"
                ),
            ]
        )

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0) if self._replies else REVISED
        self._record_usage(AIMessage(content=text))
        return text


@pytest.fixture
def record_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from malspark.core.settings_overrides import build_settings

    built = build_settings({"validation": {"feedback": "record_only"}})
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)


def test_a_further_turn_goes_through_the_real_revision(
    record_only: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from malspark.pipeline import nodes

    container = container_with_a_pending_request()
    analyst = _Analyst([REVISED])
    container.get_agent = lambda name: analyst
    # The d2 index entry the platform recorded when d2 returned: in the state.
    record = DetonationRecord(
        ordinal=2,
        origin="agent",
        arguments="-p hunter2",
        report=D2_REPORT,
        requested_by=[{"agent": "reversing", "cited_entries": ["ev_0001"]}],
    )
    container.detonation_requests = []
    container.detonations.append(record)
    container.detonations_seen["dynamic"] = {"d1"}
    rows = dt.platform_reads(container, record, "negotiation")
    state = {
        "reports": {"dynamic": "CLAIM 1: The sample reads a file.\nEVIDENCE: [ev_0003]"},
        "evidence_ledger": rows,
    }
    # The analyst's first input, and the two standing blocks, read off a full
    # state elsewhere; here what matters is the turn itself.
    monkeypatch.setattr(
        nodes, "_revision_input", lambda state, container, name: nodes.RevisionInput(text="raw")
    )
    briefed: list[Any] = []

    def _brief(agent: Any, state: Any, container: Any) -> None:
        agent.pack_entries = nodes.pack_entries(state.get("evidence_ledger") or [])
        agent.pack_ledger_ids = [e.id for e in agent.pack_entries]
        briefed.append(state)

    monkeypatch.setattr(nodes, "brief_agent", _brief)
    with (
        patch("malspark.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", lambda *_a: True),
        patch.object(BaseAnalyst, "_callees_to_ask", return_value=None),
    ):
        update = asyncio.run(dt.further_turns(container, state, "negotiation"))

    assert container.further_turns[0]["outcome"] == "revised", container.further_turns
    # The directive reached the model's prompt.
    prompt = " ".join(str(m.content) for m in analyst.seen_turns[0])
    assert "detonation d2: launched with '-p hunter2', asked for by reversing" in prompt
    # The answer replaced the one in force.
    assert update["revised_reports"]["dynamic"].startswith("CLAIM 1: Started with the password")
    assert update["isr_reports"]["dynamic"].claims
    # The turn's ledger and spend are carried.
    assert {row["id"] for row in update["evidence_ledger"]} == {"ev_0003"}
    assert update["budget_records"] == {"dynamic": [{"agent": "dynamic", "turn": "further"}]}
    # Validation ran: the claim citing nothing is recorded, marked as the further turn's.
    findings = update["validation_findings"]["dynamic"]
    assert findings and all(row[dt.FURTHER_TURN_KEY] == "true" for row in findings)
    # The claim citing d2's process is no unknown item: the analyst's index knows it.
    index = ss.item_index_of(analyst.pack_entries)
    assert index is not None and index.known("d2/proc:9")
    assert not any("d2/proc:9" in str(row.get("message")) for row in findings)
    (turn,) = container.further_turns
    assert turn["outcome"] == "revised"


def test_every_row_of_a_further_turn_is_marked() -> None:
    update = {
        "validation_unparsed_answers": [{"agent": "dynamic", "round": "0", "answer": "x"}],
        "validation_findings": {"dynamic": [{"code": "isr.empty_evidence"}]},
        "validation_retries": 1,
    }
    marked = dt.mark_further_turn(update)
    assert marked["validation_unparsed_answers"][0][dt.FURTHER_TURN_KEY] == "true"
    assert marked["validation_findings"]["dynamic"][0][dt.FURTHER_TURN_KEY] == "true"
    assert marked["validation_retries"] == 1
