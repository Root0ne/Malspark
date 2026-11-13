"""A run in ``record_only`` asks nothing, records every finding and names its mode (T-672).

An analyst whose validation turn runs on a stub model, and the judge node whose
verdict round runs on another, build the run summary as a job does. In
``record_only`` no correction turn is sent (``retries`` 0), the findings of
both are recorded, and the summary names the mode in its validation block and
among the operator's choices. In the default the same run sends its turns and
its summary carries neither, so a default run's summary is as it was.

Every sentence, value and id here is made up for the test.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from malspark.agents.base_agent import BaseAnalyst
from malspark.agents.judge_agent import JudgeAgent as JudgeAgentClass
from malspark.core.token_ledger import TokenLedger
from malspark.core.truncation_ledger import TruncationLedger
from malspark.pipeline.feedback_mode import RECORD_ONLY_CHOICE
from malspark.pipeline.nodes import _validation_update, make_judge_node
from malspark.schemas.evidence import EvidenceCounter, LedgerEntry
from tests.stages import paper_profile
from tests.unit.agents.test_record_only_the_judge import FIRST, FIXED
from tests.unit.pipeline.test_evidence_ledger_channel import _JudgeContainer

PLAIN = (
    "CLAIM 1: The sample reads a file.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
    "TECHNIQUE: NONE\n---\n"
)
# A second claim that cites nothing: a finding that opens a turn in feed_back.
UNCITED = PLAIN + (
    "CLAIM 2: The sample sleeps before it starts.\nEVIDENCE:\nCONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n---\n"
)
FIXED_ANSWER = PLAIN + (
    "CLAIM 2: The sample sleeps before it starts.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n---\n"
)


def _settings(mode: str) -> Any:
    from malspark.core.settings_overrides import build_settings

    return build_settings({"validation": {"feedback": mode}})


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self._evidence_entries = [LedgerEntry(id="ev_0003", tool="any_reader", output="file")]
        self._replies = list(replies)
        self.calls = 0
        self._budget_records: list[dict[str, Any]] = [{"agent": "static"}]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.calls += 1
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


class _Llm:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.calls = 0

    async def ainvoke(self, messages: list[Any], **_: Any) -> Any:
        self.calls += 1
        return AIMessage(content=self._answers.pop(0) if self._answers else "")


class _Container(_JudgeContainer):
    def server_degradation_reasons(self) -> list[str]:
        return []

    def server_rests(self) -> list[dict]:
        return []

    def active_profile(self) -> Any:
        return paper_profile(["static"])

    def get_token_ledger(self) -> TokenLedger:
        return TokenLedger()

    def get_truncation_ledger(self) -> TruncationLedger:
        return TruncationLedger()


def _analysis() -> tuple[_Analyst, dict[str, Any]]:
    """The analyst's validation turn, and what its node puts on the state channel."""
    analyst = _Analyst([FIXED_ANSWER])
    analyst._container = SimpleNamespace(event_sink=None)
    isr = analyst._text_to_isr(UNCITED, 0)
    with (
        patch("malspark.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", lambda *_a: True),
        patch.object(BaseAnalyst, "_seconds_the_last_loop_left", return_value=None),
        patch.object(BaseAnalyst, "_callees_to_ask", return_value=None),
    ):
        isr = analyst._validate_isr(isr, "evidence")
    return analyst, {
        "iteration_count": 1,
        "reports": {"static": "static findings"},
        "isr_reports": {"static": isr},
        "evidence_ledger": [],
        "sandbox_report": {"signatures": []},
        "sample_path": None,
        "triage_facts": {"degradation_reasons": []},
        "validation_findings": {},
        "validation_not_run": [],
        # What the analyst node puts on the state's channels.
        **_validation_update(analyst, "static"),
    }


def _node(mode: str, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], Any, int, _Llm]:
    """The judge node's update, the judge, the analyst's calls and the judge's model."""
    built = _settings(mode)
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)
    analyst, state = _analysis()
    container = _Container(EvidenceCounter())
    judge = container.get_judge_agent(role="judge")
    llm = _Llm(json.dumps(FIRST), json.dumps(FIXED))
    judge.llm = llm  # type: ignore[assignment]
    update = asyncio.run(make_judge_node(container)(state))
    return update, judge, analyst.calls, llm


def _run(mode: str, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], int, int]:
    update, _judge, analyst_calls, llm = _node(mode, monkeypatch)
    return update["run_summary"], analyst_calls, llm.calls


def test_a_record_only_run_asks_nothing_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    summary, analyst_calls, judge_calls = _run("record_only", monkeypatch)

    assert (analyst_calls, judge_calls) == (0, 1)
    validation = summary["validation"]
    assert validation["retries"] == 0
    assert validation["feedback"] == "record_only"
    analysed = [row for row in validation["unresolved"] if row["agent"] == "static"]
    assert [row["code"] for row in analysed] == ["isr.empty_evidence"]
    # Crossed the state channel and still a finding nobody was asked about.
    assert all(row.get("asked") == "false" for row in analysed)
    judged = [row for row in validation["unresolved"] if row["agent"] == "judge"]
    assert judged and all(row.get("asked") == "false" for row in judged)
    assert RECORD_ONLY_CHOICE in summary["operator_choices"]
    assert RECORD_ONLY_CHOICE not in summary.get("degradation_reasons", [])


def test_a_default_run_carries_no_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    summary, analyst_calls, judge_calls = _run("feed_back", monkeypatch)

    assert (analyst_calls, judge_calls) == (1, 2)
    assert summary["validation"]["retries"] == 2
    assert "feedback" not in summary["validation"]
    assert RECORD_ONLY_CHOICE not in summary.get("operator_choices", [])
    assert "record_only" not in json.dumps(summary, default=str)


def test_the_record_only_choice_reaches_the_state_and_not_the_judge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    notes: list[str] = []
    real = JudgeAgentClass.give_verdict

    async def _noted(self: Any, *args: Any, **kwargs: Any) -> Any:
        notes.append(str(kwargs.get("degradation_note") or ""))
        return await real(self, *args, **kwargs)

    monkeypatch.setattr(JudgeAgentClass, "give_verdict", _noted)
    update, _judge, _calls, _llm = _node("record_only", monkeypatch)

    # The state channel the report node reads its operator choices from.
    assert update["operator_choices"].count(RECORD_ONLY_CHOICE) == 1
    assert update["run_summary"]["operator_choices"].count(RECORD_ONLY_CHOICE) == 1
    # The judge's prompt is the same in both modes.
    assert notes and all("record_only" not in note for note in notes)


def test_a_record_only_run_whose_judge_failed_names_its_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fails(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("no verdict")

    monkeypatch.setattr(JudgeAgentClass, "give_verdict", _fails)
    update, _judge, _calls, _llm = _node("record_only", monkeypatch)

    assert update["final_decision"] == "Suspicious"
    assert RECORD_ONLY_CHOICE in update["operator_choices"]
    assert RECORD_ONLY_CHOICE in update["run_summary"]["operator_choices"]
