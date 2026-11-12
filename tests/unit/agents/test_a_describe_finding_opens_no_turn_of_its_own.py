"""A claim whose sentence does not describe its technique opens no validation turn of its own.

Over six stored runs the describe check was most of what the analysts' retries
asked about, and in a read of its refusals most were words the check's
vocabulary lacks, answered by padding the sentence. The judge's technique
question already asks about each technique no claim naming it describes, with
the check's finding. So the finding:

- joins a turn another finding opens, as the same question with the same card;
- standing alone (beside nothing that opens a turn: a check that could not run,
  or the exit branches that joined it), opens none. It is recorded as not asked
  and published as a finding nobody was shown, the claims stand as written,
  and the technique reaches the judge's question as an undescribed technique.

Every sentence, address and id here is made up for the test.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from malspark.agents.base_agent import UNREAD_CALLEES_CODE, BaseAnalyst
from malspark.agents.judge_agent import JudgeAgent
from malspark.extractors.capability_matrix import (
    JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
    build_capability_matrix,
    judge_questions,
)
from malspark.pipeline.validation import (
    ANALYST_CUT_CODE,
    CHECK_FAILED_CODE,
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    CLAIM_WITHOUT_CONFIDENCE_CODE,
    DECOMPILED_NOT_DESCRIBED_CODE,
    DESCRIBE_NOT_ASKED,
    RETRY_DROPPED_CODE,
    VALIDATION_TURN_NOT_RUN_CODE,
    Violation,
    describe_stands_alone,
    describe_without_a_turn,
    undescribed_technique_finding,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, ClaimEvidence
from malspark.schemas.stix_models import Bundle
from malspark.tools import knowledge

UNDESCRIBED = "T1003"  # OS Credential Dumping: the sentence below shares no term with it
WINDOW = "The sample opens a window on the desktop."

BASE = 0x140000000
GATE = BASE + 0x2A10
HELPER = BASE + 0x6D30
# One branch that ends the routine with a constant on a condition no claim names.
GATE_LISTING = (
    f"int FUN_{GATE:x}(int param_1)\n{{\n"
    f"  if (FUN_{HELPER:x}(param_1) == 0x2c) {{\n    return -1;\n  }}\n  return 0;\n}}\n"
)

DESCRIBE_ONLY = (
    f"CLAIM 1: {WINDOW}\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: {UNDESCRIBED}\n---\n"
)
# The same answer with a second finding: a claim with no confidence line.
WITH_ANOTHER = DESCRIBE_ONLY + (
    "CLAIM 2: The sample sleeps before it starts.\nEVIDENCE: [ev_0003]\nTECHNIQUE: NONE\n---\n"
)
RETRIED = (
    "CLAIM 2: The sample sleeps before it starts.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n---\n"
)
# A first claim that raises nothing, and the same second claim with no confidence line.
PLAIN = (
    "CLAIM 1: The sample reads a file.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
    "TECHNIQUE: NONE\n---\n"
)
ANOTHER_ONLY = PLAIN + WITH_ANOTHER[len(DESCRIBE_ONLY) :]
# The retries: the first claim as it was, the second fixed.
RETRIED_BOTH = DESCRIBE_ONLY + RETRIED
RETRIED_PLAIN = PLAIN + RETRIED


def _v(code: str, **kw: Any) -> Violation:
    return Violation(code=code, message=f"{code} finding.", **kw)


class TestTheRule:
    def test_a_describe_finding_alone_stands_alone(self) -> None:
        assert describe_stands_alone([_v(CLAIM_DOES_NOT_DESCRIBE_CODE)])
        assert describe_stands_alone(
            [_v(CLAIM_DOES_NOT_DESCRIBE_CODE, path="a"), _v(CLAIM_DOES_NOT_DESCRIBE_CODE, path="b")]
        )

    def test_beside_its_own_follow_ons_it_still_stands_alone(self) -> None:
        exits = _v(DECOMPILED_NOT_DESCRIBED_CODE, question_only=True)
        failed = _v(CHECK_FAILED_CODE, advisory=True, asked=False)

        assert describe_stands_alone([_v(CLAIM_DOES_NOT_DESCRIBE_CODE), exits])
        assert describe_stands_alone([failed, _v(CLAIM_DOES_NOT_DESCRIBE_CODE)])

    def test_beside_a_finding_that_opens_a_turn_it_joins_it(self) -> None:
        for other in (
            CLAIM_WITHOUT_CONFIDENCE_CODE,
            DECOMPILED_NOT_DESCRIBED_CODE,
            RETRY_DROPPED_CODE,
            "isr.technique_line_unread",
        ):
            assert not describe_stands_alone([_v(CLAIM_DOES_NOT_DESCRIBE_CODE), _v(other)])
            assert not describe_stands_alone([_v(other), _v(CLAIM_DOES_NOT_DESCRIBE_CODE)])

    def test_without_a_describe_finding_the_rule_says_nothing(self) -> None:
        assert not describe_stands_alone([])
        assert not describe_stands_alone([_v(CLAIM_WITHOUT_CONFIDENCE_CODE)])
        assert not describe_stands_alone([_v(CHECK_FAILED_CODE)])
        assert not describe_stands_alone([_v(DECOMPILED_NOT_DESCRIBED_CODE, question_only=True)])

    def test_what_is_recorded_is_the_finding_marked_not_asked_and_the_exits_left_out(self) -> None:
        described = _v(CLAIM_DOES_NOT_DESCRIBE_CODE, path="claims[0].T1003", subject="T1003")
        failed = _v(CHECK_FAILED_CODE, advisory=True, asked=False)
        exits = _v(DECOMPILED_NOT_DESCRIBED_CODE, question_only=True)

        recorded = describe_without_a_turn([described, exits, failed])

        assert [v.code for v in recorded] == [CLAIM_DOES_NOT_DESCRIBE_CODE, CHECK_FAILED_CODE]
        first = recorded[0]
        # The validator's own row, marked not asked, its words untouched.
        assert (first.message, first.sentence) == (described.message, described.sentence)
        assert (first.asked, first.path, first.subject) == (False, described.path, "T1003")
        assert first.to_dict()["asked"] == "false"
        assert recorded[1] is failed


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str], entries: list[LedgerEntry] | None = None) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self._evidence_entries = list(
            entries or [LedgerEntry(id="ev_0003", tool="any_reader", output="window")]
        )
        self._replies: list[str] = list(replies)
        self.seen_turns: list[list[Any]] = []
        self._budget_records: list[dict[str, Any]] = [{"agent": "reverser"}]
        self.pack_entries = [
            LedgerEntry(
                id="ev_0001",
                agent="pipeline",
                tool="function_index",
                output="{}",
                structured={"image_base": hex(BASE)},
            )
        ]
        self.pack_image_bases = (BASE,)

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(
    analyst: _Analyst, first: str, *, time_left: float | None = None, fits: bool = True
) -> tuple[AgentISR, list[tuple[str, str]]]:
    published: list[tuple[str, str]] = []
    analyst._container = SimpleNamespace(event_sink=object())
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("malspark.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", lambda *_a: fits),
        patch.object(BaseAnalyst, "_seconds_the_last_loop_left", return_value=time_left),
        patch.object(BaseAnalyst, "seconds_an_answer_needs", return_value=60.0),
        patch(
            "malspark.pipeline.validation.emit_validation_feedback",
            lambda _sink, **kw: published.append((kw["state"], kw["code"])),
        ),
    ):
        return analyst._validate_isr(isr, "evidence"), published


def _recorded(analyst: _Analyst, code: str = CLAIM_DOES_NOT_DESCRIBE_CODE) -> list[Violation]:
    return [v for v in analyst.validation_findings if v.code == code]


class TestTheValidationTurn:
    def test_a_describe_finding_alone_opens_no_turn_and_is_recorded_not_asked(self) -> None:
        analyst = _Analyst([])

        result, published = _check(analyst, DESCRIBE_ONLY)

        assert analyst.seen_turns == []
        assert analyst.validation_retries == 0
        assert analyst.validation_fed_back == {}
        (found,) = _recorded(analyst)
        assert found.asked is False
        assert found.subject == UNDESCRIBED
        assert DESCRIBE_NOT_ASKED not in found.message
        assert "carries TECHNIQUE T1003 OS Credential Dumping" in found.message
        # Published as a finding nobody was shown, never as asked.
        assert published == [("survived", CLAIM_DOES_NOT_DESCRIBE_CODE)]
        # The claim stands as written, and the turn is no turn that could not run.
        assert [(c.claim, c.technique_id, c.technique_id_valid) for c in result.claims] == [
            (WINDOW, UNDESCRIBED, True)
        ]
        assert VALIDATION_TURN_NOT_RUN_CODE not in (analyst.validation_not_run or [])

    def test_its_technique_reaches_the_judge_s_question_as_undescribed(self) -> None:
        analyst = _Analyst([])
        result, _published = _check(analyst, DESCRIBE_ONLY)
        bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "name": "OS Credential Dumping",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": UNDESCRIBED}
                    ],
                }
            ]
        }

        questions, not_asked = judge_questions(bundle, {"reverser": result}, attck=knowledge)

        (question,) = questions
        assert (question.technique_id, question.kind) == (UNDESCRIBED, "undescribed")
        assert question.check == undescribed_technique_finding(UNDESCRIBED, knowledge, 1)
        assert not_asked == {}

    def test_beside_another_finding_it_is_asked_in_that_turn_with_its_card(self) -> None:
        analyst = _Analyst([RETRIED_BOTH])

        result, published = _check(analyst, WITH_ANOTHER)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert f"[{CLAIM_WITHOUT_CONFIDENCE_CODE}]" in question
        assert f"[{CLAIM_DOES_NOT_DESCRIBE_CODE}]" in question
        assert question.count("The technique's ") == 1
        assert DESCRIBE_NOT_ASKED not in question
        assert analyst.validation_retries == 1
        assert analyst.validation_fed_back == {
            CLAIM_WITHOUT_CONFIDENCE_CODE: 1,
            CLAIM_DOES_NOT_DESCRIBE_CODE: 1,
        }
        assert ("retried", CLAIM_DOES_NOT_DESCRIBE_CODE) in published
        # Asked and left as written: recorded as asked, as a finding that survived.
        (found,) = _recorded(analyst)
        assert found.asked is True
        assert DESCRIBE_NOT_ASKED not in found.message
        assert [c.technique_id for c in result.claims][0] == UNDESCRIBED

    def test_beside_only_the_exit_branches_it_still_opens_no_turn(self) -> None:
        entries = [
            LedgerEntry(
                id="ev_0003",
                tool="decompile_function",
                args={"address": hex(GATE)},
                output=GATE_LISTING,
            )
        ]
        first = (
            f"CLAIM 1: {GATE:#x} opens a window on the desktop.\nEVIDENCE: [ev_0003]\n"
            f"CONFIDENCE: 0.8\nTECHNIQUE: {UNDESCRIBED}\n---\n"
        )
        analyst = _Analyst([], entries)

        # The routine's callee is a question of its own, which opens a turn: not asked here.
        with patch.object(BaseAnalyst, "_callees_to_ask", return_value=None):
            _result, published = _check(analyst, first)

        assert analyst.seen_turns == []
        assert [v.code for v in analyst.validation_findings] == [CLAIM_DOES_NOT_DESCRIBE_CODE]
        assert published == [("survived", CLAIM_DOES_NOT_DESCRIBE_CODE)]
        note = analyst._budget_records[-1]["exit_branches"]
        assert (note["left"], note["asked"]) == (1, False)

    def test_another_finding_alone_opens_its_turn_as_before(self) -> None:
        analyst = _Analyst([RETRIED_PLAIN])

        result, published = _check(analyst, ANOTHER_ONLY)

        assert len(analyst.seen_turns) == 1
        assert analyst.validation_retries == 1
        assert published == [
            ("retried", CLAIM_WITHOUT_CONFIDENCE_CODE),
            ("resolved", CLAIM_WITHOUT_CONFIDENCE_CODE),
        ]
        assert [c.confidence for c in result.claims] == [0.8, 0.7]

    def test_with_no_time_left_it_is_recorded_as_a_finding_with_no_turn_of_its_own(self) -> None:
        analyst = _Analyst([])

        _check(analyst, DESCRIBE_ONLY, time_left=1.0)

        (found,) = _recorded(analyst)
        assert DESCRIBE_NOT_ASKED not in found.message
        assert VALIDATION_TURN_NOT_RUN_CODE not in (analyst.validation_not_run or [])

    def test_with_no_time_left_beside_another_finding_the_turn_is_not_run_as_before(
        self,
    ) -> None:
        analyst = _Analyst([])

        _check(analyst, WITH_ANOTHER, time_left=1.0)

        (found,) = _recorded(analyst)
        assert found.asked is False
        assert DESCRIBE_NOT_ASKED not in found.message
        assert "Not asked: 1s of the loop's time were left" in found.message
        assert VALIDATION_TURN_NOT_RUN_CODE in analyst.validation_not_run


class TestAFindingTakenOutBeforeTheQuestionIsSent:
    """Where a finding that opened the turn is taken out, the rule is asked again."""

    def _gate(self) -> tuple[list[LedgerEntry], str]:
        entries = [
            LedgerEntry(
                id="ev_0003",
                tool="decompile_function",
                args={"address": hex(GATE)},
                output=GATE_LISTING,
            )
        ]
        first = (
            f"CLAIM 1: {GATE:#x} opens a window on the desktop.\nEVIDENCE: [ev_0003]\n"
            f"CONFIDENCE: 0.8\nTECHNIQUE: {UNDESCRIBED}\n---\n"
        )
        return entries, first

    def test_the_callees_question_dropped_for_want_of_tools_leaves_no_turn(self) -> None:
        entries, first = self._gate()
        analyst = _Analyst([first], entries)

        # The routine's unread callee opens the turn; the turn carries no tools.
        with patch.object(BaseAnalyst, "_turns_carry_tools", return_value=False):
            _result, published = _check(analyst, first)

        assert analyst.seen_turns == []
        assert analyst.validation_retries == 0
        (found,) = _recorded(analyst)
        assert found.asked is False and DESCRIBE_NOT_ASKED not in found.message
        assert published == [("survived", CLAIM_DOES_NOT_DESCRIBE_CODE)]
        # The callees question is stated as not put, as on dev, and recorded nowhere else.
        assert analyst._callees_stated_job == "job"
        assert _recorded(analyst, UNREAD_CALLEES_CODE) == []

    def test_the_callees_question_dropped_beside_another_finding_still_asks_it(self) -> None:
        entries, first = self._gate()
        unsure = first + WITH_ANOTHER[len(DESCRIBE_ONLY) :]
        analyst = _Analyst([first + RETRIED], entries)

        with patch.object(BaseAnalyst, "_turns_carry_tools", return_value=False):
            _check(analyst, unsure)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert f"[{CLAIM_WITHOUT_CONFIDENCE_CODE}]" in question
        assert f"[{CLAIM_DOES_NOT_DESCRIBE_CODE}]" in question
        assert f"[{UNREAD_CALLEES_CODE}]" not in question

    def test_a_cut_question_that_does_not_fit_leaves_no_turn(self) -> None:
        analyst = _Analyst([DESCRIBE_ONLY])
        analyst._last_answer_cut = (300, DESCRIBE_ONLY)

        _result, published = _check(analyst, DESCRIBE_ONLY, fits=False)

        assert analyst.seen_turns == []
        assert analyst.validation_retries == 0
        (found,) = _recorded(analyst)
        assert found.asked is False and DESCRIBE_NOT_ASKED not in found.message
        assert published == [("survived", CLAIM_DOES_NOT_DESCRIBE_CODE)]
        # The cut question is recorded not asked, with why, as on dev.
        (cut,) = _recorded(analyst, ANALYST_CUT_CODE)
        assert cut.asked is False
        assert "do not fit this model's window" in cut.message

    def test_a_cut_question_that_does_not_fit_beside_another_finding_still_asks_it(
        self,
    ) -> None:
        analyst = _Analyst([RETRIED_BOTH])
        analyst._last_answer_cut = (300, WITH_ANOTHER)

        _check(analyst, WITH_ANOTHER, fits=False)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert f"[{CLAIM_WITHOUT_CONFIDENCE_CODE}]" in question
        assert f"[{CLAIM_DOES_NOT_DESCRIBE_CODE}]" in question
        assert f"[{ANALYST_CUT_CODE}]" not in question
        (cut,) = _recorded(analyst, ANALYST_CUT_CODE)
        assert cut.asked is False


def _undescribed_ids(count: int) -> list[str]:
    """Catalogued technique ids the sentence ``WINDOW`` does not describe, by the check."""
    from malspark.extractors.capability_matrix import _undescribed

    found: list[str] = []
    for n in range(1001, 1700):
        tid = f"T{n}"
        claim = ClaimEvidence(
            claim=WINDOW, evidence_ref="[ev_0003]", confidence=0.6, technique_id=tid
        )
        if _undescribed(tid, [claim], knowledge, {"platform": "windows", "file_type": "pe"}):
            found.append(tid)
            if len(found) == count:
                break
    return found


class _Llm:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content=self.answer)


class TestTheJudgeQuestionBound:
    """The undescribed techniques keep their place in the judge's question.

    They are among the claimed, finding and undescribed questions the
    question's room is sized for (``JudgeAgent.decide_techniques``): with no
    room, the reports and the evidence shorten, and no undescribed technique is
    left out or recorded as not asked. A question that brings no answer leaves
    every technique asked as it would be without the question, marked as not
    confirmed by the judge, with the check's finding beside it.
    """

    @pytest.fixture
    def many(self) -> tuple[list[str], dict[str, AgentISR]]:
        ids = _undescribed_ids(24)
        assert len(ids) == 24
        claims = [
            ClaimEvidence(claim=WINDOW, evidence_ref="[ev_0003]", confidence=0.6, technique_id=t)
            for t in ids
        ]
        return ids, {"static": AgentISR(agent_id="static", domain="static", claims=claims)}

    def test_with_no_room_every_undescribed_technique_is_still_asked(
        self, monkeypatch: pytest.MonkeyPatch, many: tuple[list[str], dict[str, AgentISR]]
    ) -> None:
        ids, isrs = many
        llm = _Llm("[]")
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
        monkeypatch.setattr(judge, "_question_room", lambda fixed, cap: 0)

        review = asyncio.run(
            judge.decide_techniques(
                Bundle.model_validate({"objects": []}),
                isrs,
                reports={"static": "r" * 50_000},
                evidence_texts={"ev_0003": "w" * 50_000},
                routed={"platform": "windows", "file_type": "pe"},
            )
        )

        assert len(llm.calls) == 1
        assert review is not None
        assert review.asked == ids
        assert review.not_asked == {}
        assert set(review.undescribed) == set(ids)
        assert all(f"{tid} " in str(llm.calls[0][1].content) for tid in ids)

    def test_an_unanswered_question_publishes_each_as_without_it_and_says_so(
        self, many: tuple[list[str], dict[str, AgentISR]]
    ) -> None:
        ids, isrs = many
        judge = JudgeAgent(llm=_Llm("nothing readable"))  # type: ignore[arg-type]
        review = asyncio.run(
            judge.decide_techniques(
                Bundle.model_validate({"objects": []}),
                isrs,
                reports={"static": "r"},
                evidence_texts={},
                routed={"platform": "windows", "file_type": "pe"},
            )
        )
        assert review is not None and review.unanswered and review.asked == ids
        bundle = Bundle.model_validate({"objects": []})
        bundle.x_malspark_technique_review = review

        cells, mappings = build_capability_matrix(
            stix_output=bundle.model_dump(),
            isr_reports=isrs,
            sample={"platform": "windows", "file_type": "pe"},
        )

        by_id = {c.technique_id: c for c in cells}
        published = {m.technique_id for m in mappings}
        for tid in ids:
            assert tid in published
            assert JUDGE_UNCONFIRMED_TECHNIQUE_MARKER in by_id[tid].note
            assert "no claim naming it uses the catalogue's terms for it" in by_id[tid].note
