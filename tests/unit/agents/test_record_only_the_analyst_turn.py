"""An analyst's validation turn in both ``validation.feedback`` modes (T-672).

``feed_back``: a finding opens the turn, as it always did. ``record_only``: no
turn is sent, every finding is recorded and published as not asked, the
claims stand as written and an unknown id is still marked. An answer that
could not be read is asked about in both, and only that is asked.

Every sentence, address and id here is made up for the test.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from malspark.agents.base_agent import BaseAnalyst
from malspark.pipeline.validation import (
    ANALYST_CUT_CODE,
    CLAIM_WITHOUT_CONFIDENCE_CODE,
    UNPARSED_ANSWER_CODE,
    VALIDATION_TURN_NOT_RUN_CODE,
    Violation,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR

PLAIN = (
    "CLAIM 1: The sample reads a file.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
    "TECHNIQUE: NONE\n---\n"
)
# A second claim that cites nothing: a finding that opens a turn in feed_back.
UNCITED = PLAIN + (
    "CLAIM 2: The sample sleeps before it starts.\nEVIDENCE:\nCONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n---\n"
)
# A second claim with no confidence line: a block that is not a claim until it
# is asked about, in both modes.
UNSURE = PLAIN + (
    "CLAIM 2: The sample sleeps before it starts.\nEVIDENCE: [ev_0003]\nTECHNIQUE: NONE\n---\n"
)
FIXED = PLAIN + (
    "CLAIM 2: The sample sleeps before it starts.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n---\n"
)
# A claim naming an id the catalogue does not hold.
UNKNOWN = (
    "CLAIM 1: The sample reads a file.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
    "TECHNIQUE: T1059.099\n---\n"
)
PROSE = "The sample reads a file and then sleeps; nothing else was seen."
SLEEPS_UNCITED = "CLAIM 3: The sample sleeps.\nEVIDENCE:\nCONFIDENCE: 0.6\nTECHNIQUE: NONE\n---\n"
SCRIPT = "CLAIM 2: The sample runs a script.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.7\n"
# A TECHNIQUE line that is more than ids, beside a claim that cites nothing.
LINE_UNREAD = (
    PLAIN + SCRIPT + "TECHNIQUE: probably a script interpreter, maybe T1059\n---\n" + SLEEPS_UNCITED
)
LINE_READ = PLAIN + SCRIPT + "TECHNIQUE: T1059\n---\n" + SLEEPS_UNCITED
# A claim heading under DISPUTES, beside a claim that cites nothing.
UNDER_DISPUTES = (
    PLAIN
    + SLEEPS_UNCITED
    + "DISPUTES:\nCLAIM 4: The sample runs a script.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n---\n"
)
ABOVE_DISPUTES = (
    PLAIN
    + SLEEPS_UNCITED
    + "CLAIM 4: The sample runs a script.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n---\n"
)
EMPTY_EVIDENCE = "isr.empty_evidence"


def _settings(mode: str) -> Any:
    from malspark.core.settings_overrides import build_settings

    return build_settings({"validation": {"feedback": mode}})


@pytest.fixture(params=["feed_back", "record_only"])
def mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    built = _settings(request.param)
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)
    return str(request.param)


@pytest.fixture
def record_only(monkeypatch: pytest.MonkeyPatch) -> None:
    built = _settings("record_only")
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self._evidence_entries = [LedgerEntry(id="ev_0003", tool="any_reader", output="file")]
        self._replies: list[str] = list(replies)
        self.seen_turns: list[list[Any]] = []
        self._budget_records: list[dict[str, Any]] = [{"agent": "reverser"}]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst, first: str) -> tuple[AgentISR, list[tuple[str, str]]]:
    published: list[tuple[str, str]] = []
    analyst._container = SimpleNamespace(event_sink=object())
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("malspark.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", lambda *_a: True),
        patch.object(BaseAnalyst, "_seconds_the_last_loop_left", return_value=None),
        patch.object(BaseAnalyst, "_callees_to_ask", return_value=None),
        patch(
            "malspark.pipeline.validation.emit_validation_feedback",
            lambda _sink, **kw: published.append((kw["state"], kw["code"])),
        ),
    ):
        return analyst._validate_isr(isr, "evidence"), published


def _recorded(analyst: _Analyst, code: str) -> list[Violation]:
    return [v for v in analyst.validation_findings if v.code == code]


def test_a_finding_opens_the_turn_only_in_feed_back(mode: str) -> None:
    analyst = _Analyst([FIXED])

    result, published = _check(analyst, UNCITED)

    if mode == "feed_back":
        assert len(analyst.seen_turns) == 1
        assert f"[{EMPTY_EVIDENCE}]" in str(analyst.seen_turns[0][-1].content)
        assert analyst.validation_retries == 1
        assert published == [("retried", EMPTY_EVIDENCE), ("resolved", EMPTY_EVIDENCE)]
        assert [c.evidence_ref for c in result.claims] == ["[ev_0003]", "[ev_0003]"]
        return
    assert analyst.seen_turns == []
    assert analyst.validation_retries == 0
    assert analyst.validation_fed_back == {}
    (found,) = _recorded(analyst, EMPTY_EVIDENCE)
    assert found.asked is False
    assert found.to_dict()["asked"] == "false"
    assert published == [("survived", EMPTY_EVIDENCE)]
    # The answer stands as written: the claim that cites nothing is still there.
    assert [c.evidence_ref for c in result.claims] == ["[ev_0003]", ""]
    # A turn that was not sent is no turn that could not run.
    assert VALIDATION_TURN_NOT_RUN_CODE not in (analyst.validation_not_run or [])


def test_a_block_that_is_not_a_claim_is_asked_in_both_modes(mode: str) -> None:
    analyst = _Analyst([FIXED])

    result, published = _check(analyst, UNSURE)

    assert len(analyst.seen_turns) == 1
    assert f"[{CLAIM_WITHOUT_CONFIDENCE_CODE}]" in str(analyst.seen_turns[0][-1].content)
    assert analyst.validation_retries == 1
    assert published == [
        ("retried", CLAIM_WITHOUT_CONFIDENCE_CODE),
        ("resolved", CLAIM_WITHOUT_CONFIDENCE_CODE),
    ]
    assert [c.confidence for c in result.claims] == [0.8, 0.7]


def test_an_unknown_id_is_marked_and_kept_in_record_only(record_only: None) -> None:
    analyst = _Analyst([])

    # The suggestions an unknown id's question carries come from the index.
    with patch("malspark.pipeline.validation._suggest_techniques", return_value=[]):
        result, _published = _check(analyst, UNKNOWN)

    assert analyst.seen_turns == []
    (claim,) = result.claims
    assert claim.technique_id == "T1059.099"
    assert claim.technique_id_valid is False
    assert all(v.asked is False for v in analyst.validation_findings)
    assert any(v.code == "attck.unknown_id" for v in analyst.validation_findings)


def test_an_answer_that_could_not_be_read_is_asked_in_both_modes(mode: str) -> None:
    analyst = _Analyst([PLAIN])

    result, _published = _check(analyst, PROSE)

    assert len(analyst.seen_turns) == 1
    assert f"[{UNPARSED_ANSWER_CODE}]" in str(analyst.seen_turns[0][-1].content)
    assert analyst.validation_retries == 1
    assert [c.claim for c in result.claims] == ["The sample reads a file."]


def test_in_record_only_a_cut_answer_is_asked_about_the_cut_alone(record_only: None) -> None:
    analyst = _Analyst([UNCITED])
    analyst._last_answer_cut = (300, UNCITED)

    result, published = _check(analyst, UNCITED)

    (turns,) = analyst.seen_turns
    question = str(turns[-1].content)
    assert f"[{ANALYST_CUT_CODE}]" in question
    assert f"[{EMPTY_EVIDENCE}]" not in question
    assert analyst.validation_fed_back == {ANALYST_CUT_CODE: 1}
    # What the whole answer still holds is recorded, and was not asked.
    (left,) = _recorded(analyst, EMPTY_EVIDENCE)
    assert left.asked is False
    assert ("retried", EMPTY_EVIDENCE) not in published
    assert [c.evidence_ref for c in result.claims] == ["[ev_0003]", ""]


@pytest.mark.parametrize(
    ("first", "fixed", "code"),
    [
        (LINE_UNREAD, LINE_READ, "isr.technique_line_unread"),
        (UNDER_DISPUTES, ABOVE_DISPUTES, "isr.claims_under_disputes"),
    ],
    ids=["technique_line", "disputes"],
)
def test_a_block_read_as_no_claim_is_asked_in_both_modes_and_alone_in_record_only(
    mode: str, first: str, fixed: str, code: str
) -> None:
    analyst = _Analyst([fixed])

    result, published = _check(analyst, first)

    (turns,) = analyst.seen_turns
    question = str(turns[-1].content)
    assert f"[{code}]" in question
    assert ("retried", code) in published and ("resolved", code) in published
    assert analyst.validation_retries == 1
    (left,) = _recorded(analyst, EMPTY_EVIDENCE)
    if mode == "feed_back":
        # Every finding of the answer is in the one turn.
        assert f"[{EMPTY_EVIDENCE}]" in question
        assert left.asked is True
    else:
        # The other finding is kept out of the turn and recorded, not asked.
        assert f"[{EMPTY_EVIDENCE}]" not in question
        assert left.asked is False
        assert ("retried", EMPTY_EVIDENCE) not in published
    assert "The sample runs a script." in [c.claim for c in result.claims]
