"""Every id on a claim's EVIDENCE line is one the job issued.

The job's evidence counter issues ``ev_0001`` up to its count, to every agent
of the job; an id past that count names no entry at all. A claim citing one is
asked once (``isr.unissued_evidence``), whether or not it names a technique and
whatever else its line cites. The check reads the job's issued ids, never the
analyst's own citable list: an analyst citing another analyst's real entry is
citing the run's evidence. Item ids (``proc:9``, ``d2/proc:84``) and ids the
claim sentence names outside its EVIDENCE line are not read.

Every sentence and id here is made up for the test.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from malspark.agents.base_agent import BaseAnalyst
from malspark.pipeline.validation import (
    UNGROUNDED_TECHNIQUE_CODE,
    UNISSUED_EVIDENCE_CODE,
    Violation,
    validate_isr,
)
from malspark.schemas.evidence import EvidenceCounter, LedgerEntry, unissued_ids
from malspark.schemas.isr_models import AgentISR, ClaimEvidence


def _claim(evidence: str, technique: str | None = None, text: str = "it reads a file") -> Any:
    return ClaimEvidence(claim=text, evidence_ref=evidence, confidence=0.6, technique_id=technique)


def _isr(*claims: Any) -> AgentISR:
    return AgentISR(agent_id="static", domain="static", claims=list(claims))


def _found(*claims: Any, issued: int | None = 10, own: tuple[str, ...] = ("ev_0002",)) -> list:
    return validate_isr(_isr(*claims), ledger_ids=list(own), issued=issued)


def _unissued(found: list[Violation]) -> list[Violation]:
    return [v for v in found if v.code == UNISSUED_EVIDENCE_CODE]


class TestTheSharedDecision:
    def test_an_id_past_the_count_is_unissued_and_one_inside_it_is_not(self) -> None:
        assert unissued_ids(["ev_0001", "ev_0010", "ev_0011", "EV_0012"], 10) == [
            "ev_0011",
            "EV_0012",
        ]

    def test_nothing_is_issued_by_a_counter_that_issued_none(self) -> None:
        assert unissued_ids(["ev_0001"], 0) == ["ev_0001"]

    def test_a_value_that_is_no_entry_id_is_not_read(self) -> None:
        assert unissued_ids(["ev_12", "proc:9", "d2/proc:84", "ev_0005x", ""], 1) == []


class TestTheMessage:
    def test_it_names_at_most_six_ids(self) -> None:
        cited = ", ".join(f"[ev_{n:04d}]" for n in range(11, 19))

        (found,) = _unissued(_found(_claim(cited)))

        assert "ev_0011, ev_0012, ev_0013, ev_0014, ev_0015, ev_0016 and 2 more" in found.message
        assert "ev_0017" not in found.message


class TestTheClaimCheck:
    def test_a_claim_with_no_technique_citing_an_unissued_id_is_asked(self) -> None:
        (found,) = _unissued(_found(_claim("[ev_9999]")))

        assert found.path == "static.claims[0]"
        assert found.subject == "ev_9999"
        assert "ev_9999" in found.message
        assert "ev_0001 to ev_0010" in found.message

    def test_an_issued_id_beside_it_is_not_named(self) -> None:
        (found,) = _unissued(_found(_claim("[ev_0002], [ev_9999]")))

        assert found.subject == "ev_9999"
        assert "ev_0002" not in found.message

    def test_another_agent_s_issued_entry_is_not_asked(self) -> None:
        # ev_0007 is not among this analyst's citable ids, and the job issued it.
        assert _found(_claim("[ev_0007]")) == []

    def test_item_ids_are_not_read(self) -> None:
        assert _unissued(_found(_claim("[proc:9], [d2/proc:84], [ev_0002]"))) == []

    def test_an_id_in_the_claim_sentence_is_not_read(self) -> None:
        claim = _claim("[ev_0002]", text="as ev_9999 does not show, it reads a file")

        assert _unissued(_found(claim)) == []

    def test_each_end_of_a_range_is_read(self) -> None:
        (found,) = _unissued(_found(_claim("ev_0005-ev_0012"), issued=10))

        assert found.subject == "ev_0012"
        assert "ev_0005" not in found.message.split("which")[0]

    def test_a_malformed_id_is_not_read(self) -> None:
        assert _unissued(_found(_claim("[ev_12], ev_0005x, [ev_0002]"))) == []

    def test_an_id_in_a_code_span_on_the_evidence_line_is_read(self) -> None:
        # The EVIDENCE line is the claim's citation, quoted or not.
        (found,) = _unissued(_found(_claim("`ev_9999`")))

        assert found.subject == "ev_9999"

    def test_a_job_that_issued_nothing_names_every_id(self) -> None:
        (found,) = _unissued(_found(_claim("[ev_0001]"), issued=0, own=()))

        assert found.subject == "ev_0001"
        assert "issued none" in found.message

    def test_no_count_asks_nothing(self) -> None:
        assert _unissued(_found(_claim("[ev_9999]"), issued=None)) == []

    def test_one_block_is_asked_once(self) -> None:
        claims = [
            ClaimEvidence(
                claim="it injects code",
                evidence_ref="[ev_0002], [ev_9999]",
                confidence=0.6,
                technique_id=tid,
            )
            for tid in ("T1055", "T1055.012")
        ]

        assert len(_unissued(_found(*claims))) == 1


class TestATechniqueClaimCitingOnlyUnissuedIds:
    def test_it_is_one_question_and_says_the_ids_were_never_issued(self) -> None:
        found = _found(_claim("[ev_9999]", technique="T1055"))

        assert [v.code for v in found] == [UNGROUNDED_TECHNIQUE_CODE]
        assert "ev_9999" in found[0].message
        assert "never issued" in found[0].message

    def test_an_issued_id_of_another_agent_beside_it_keeps_both_questions(self) -> None:
        found = _found(_claim("[ev_0007], [ev_9999]", technique="T1055"))

        assert sorted(v.code for v in found) == [UNGROUNDED_TECHNIQUE_CODE, UNISSUED_EVIDENCE_CODE]


# ---------------------------------------------------------------------------
# Through the analyst's validation turn
# ---------------------------------------------------------------------------

UNISSUED = (
    "CLAIM 1: The sample reads a file.\nEVIDENCE: [ev_0050]\nCONFIDENCE: 0.8\n"
    "TECHNIQUE: NONE\n---\n"
)
FIXED = (
    "CLAIM 1: The sample reads a file.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
    "TECHNIQUE: NONE\n---\n"
)


def _settings(mode: str) -> Any:
    from malspark.core.settings_overrides import build_settings

    return build_settings({"validation": {"feedback": mode}})


@pytest.fixture(params=["feed_back", "record_only"])
def mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    built = _settings(request.param)
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)
    return str(request.param)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str], counted: bool = True) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self._evidence_entries = [LedgerEntry(id="ev_0003", tool="any_reader", output="file")]
        self._replies: list[str] = list(replies)
        self.seen_turns: list[list[Any]] = []
        self._budget_records: list[dict[str, Any]] = [{"agent": "reverser"}]
        if counted:
            self.evidence_counter = EvidenceCounter()
            for _ in range(3):
                self.evidence_counter.next_id()

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst, first: str) -> AgentISR:
    analyst._container = SimpleNamespace(event_sink=object())
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("malspark.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", lambda *_a: True),
        patch.object(BaseAnalyst, "_seconds_the_last_loop_left", return_value=None),
        patch.object(BaseAnalyst, "_callees_to_ask", return_value=None),
        patch("malspark.pipeline.validation.emit_validation_feedback", lambda _sink, **kw: None),
    ):
        return analyst._validate_isr(isr, "evidence")


def test_the_turn_asks_about_an_id_the_job_s_counter_never_issued(mode: str) -> None:
    analyst = _Analyst([FIXED])

    result = _check(analyst, UNISSUED)

    if mode == "feed_back":
        assert len(analyst.seen_turns) == 1
        assert f"[{UNISSUED_EVIDENCE_CODE}]" in str(analyst.seen_turns[0][-1].content)
        assert [c.evidence_ref for c in result.claims] == ["[ev_0003]"]
        return
    assert analyst.seen_turns == []
    (found,) = [v for v in analyst.validation_findings if v.code == UNISSUED_EVIDENCE_CODE]
    assert found.asked is False
    assert [c.evidence_ref for c in result.claims] == ["[ev_0050]"]


def test_an_analyst_without_a_counter_is_not_asked() -> None:
    analyst = _Analyst([], counted=False)

    _check(analyst, UNISSUED)

    assert analyst.seen_turns == []
    assert not [v for v in analyst.validation_findings if v.code == UNISSUED_EVIDENCE_CODE]
