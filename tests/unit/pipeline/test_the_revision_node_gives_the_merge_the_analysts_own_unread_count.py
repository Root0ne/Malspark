"""The revision node gives the merge the count of claims the analyst's own reading left unread.

The count is what the revision's answer holds after its validation turn: a
reason that claims it began were not read (a note that parts of the input
were not analysed among them) and the blocks that stated no confidence. With
one or more, the line rule withdraws nothing for that revision, and the merge
does not read the text again: the analyst's own reading is the one that
counts, a claim heading quoted in a code fence among what it began and did
not read.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from malspark.agents.base_agent import read_claim_blocks
from malspark.schemas.isr_models import AgentISR


def _block(sentence: str) -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


def _isr(text: str, note: str = "") -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    if note:
        isr.note_claims_unread(note)
    return isr


LOADER = "0x40cf14 loads the saved URL list from the file at 0x4103b8."
GATE = "0x406328 returns 1 only when the tables at 0x4084e4 and 0x40abd4 resolve."
IN_FORCE = _block(LOADER) + _block(GATE)
LINE = (
    "[analysts: STATIC ANALYST] STATIC claim 2 says 0x406328 needs both tables, versus the "
    "listing. [blocking: the listing shows one table.]"
)


def _run(answer: str, revision: AgentISR, in_force: str = IN_FORCE, line: str = LINE) -> Any:
    from malspark.core.config import MEDIATOR_AGENT_NAME
    from malspark.pipeline.nodes import make_revision_node
    from malspark.pipeline.state import AgentArgument

    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static"]
    container.analyst_keys.return_value = ["static"]
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    agent = MagicMock()
    agent.safe_revise_isr.return_value = (answer, revision)
    container.get_agent.return_value = agent
    container.load_chunked.return_value = [MagicMock(content="data")]
    container.load_data.return_value = "data"
    mediation = AgentArgument(
        agent_name=MEDIATOR_AGENT_NAME, finding="revise", contradictions=[line], revise=["static"]
    )
    state = {
        "file_hash": "abc",
        "iteration_count": 1,
        "discussion_history": [mediation],
        "reports": {"static": in_force},
        "isr_reports": {"static": _isr(in_force)},
    }
    out = asyncio.run(make_revision_node(container)(state))
    return [c.claim for c in out["isr_reports"]["static"].claims]


def _analyst() -> Any:
    import logging

    from malspark.agents.static_analyst import StaticAnalyst

    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.name = "static"
    analyst.logger = logging.getLogger("test")
    return analyst


class TestTheCountComesFromTheAnswer:
    def test_a_reason_the_answer_holds_keeps_the_named_claim(self) -> None:
        answer = _block(LOADER)

        stands = _run(answer, _isr(answer, "1 claim block it began could not be read."))

        assert GATE in stands

    def test_a_note_of_parts_not_analysed_keeps_it_too(self) -> None:
        answer = _block(LOADER)

        stands = _run(answer, _isr(answer, "Parts of the input were not analysed: chunk 3."))

        assert GATE in stands

    def test_a_heading_quoted_in_a_code_fence_is_begun_and_not_read(self) -> None:
        # The analyst's own reading counts the fenced example as a claim
        # begun and not read: the line rule withdraws nothing (the safe side).
        answer = _block(LOADER) + "```\nCLAIM: example\nEVIDENCE: [ev_x]\n```\n"
        from malspark.pipeline.revision_merge import claims_left_unread_of

        revision = _analyst()._text_to_isr(answer, revision_round=1)
        assert claims_left_unread_of(revision) == 1

        stands = _run(answer, revision)

        assert GATE in stands

    def test_with_every_claim_read_the_line_rule_withdraws(self) -> None:
        answer = _block(LOADER)

        stands = _run(answer, _analyst()._text_to_isr(answer, revision_round=1))

        assert GATE not in stands

    def test_the_count_adds_the_blocks_without_a_confidence(self) -> None:
        from malspark.pipeline.revision_merge import claims_left_unread_of

        isr = _isr(_block(LOADER))
        isr.note_parse(blocks_without_confidence=2)
        isr.note_claims_unread("1 claim block it began could not be read.")

        assert claims_left_unread_of(isr) == 3
        assert claims_left_unread_of(_isr(_block(LOADER))) == 0


class TestAClaimBegunUnderAHeadingTheReaderDoesNotRead:
    # Claims in force 1-3; the blocking line names claim 3. The revision keeps
    # claim 1, revises claim 2 and writes claim 3 again under a plain-dot
    # heading with every field beneath: begun, and not read.
    MUTEX = "The mutex name at 0x403962 is not recovered."
    LINE_3 = (
        "[analysts: STATIC ANALYST] STATIC claim 3 says the mutex name at 0x403962 is not "
        "recovered; ev_0109 gives it. [blocking: ev_0109 shows the name argument.]"
    )
    ANSWER = (
        f"CLAIM 1 (kept). {LOADER}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
        "CLAIM 2 (revised). 0x406328 returns 1 when the table at 0x4084e4 resolves.\n"
        "EVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
        "CLAIM 3. The mutex name at 0x403962 is not recovered; ev_0109 holds only (0,0).\n"
        "EVIDENCE: [ev_0109]\nCONFIDENCE: 0.6\nTECHNIQUE: NONE\n---\n"
    )

    def test_the_named_claim_stays_in_force(self) -> None:
        import logging

        from malspark.agents.static_analyst import StaticAnalyst

        analyst = StaticAnalyst.__new__(StaticAnalyst)
        analyst.name = "static"
        analyst.logger = logging.getLogger("test")
        # The analyst's own reading of its revision, as the revision node gets it.
        revision = analyst._text_to_isr(self.ANSWER, revision_round=1)
        assert len(revision.claims) == 2 and revision.claims_unread_reason

        in_force = IN_FORCE + _block(self.MUTEX)
        stands = _run(self.ANSWER, revision, in_force=in_force, line=self.LINE_3)

        assert self.MUTEX in stands


class TestTheRecordSurvivesTheValidationTurn:
    """The analyst's real revision path, its validation turn included, into the revision node."""

    MUTEX = TestAClaimBegunUnderAHeadingTheReaderDoesNotRead.MUTEX
    LINE_3 = TestAClaimBegunUnderAHeadingTheReaderDoesNotRead.LINE_3
    ANSWER = TestAClaimBegunUnderAHeadingTheReaderDoesNotRead.ANSWER

    def _revised(self, first: str) -> tuple[str, Any, int]:
        from unittest.mock import patch

        from langchain_core.messages import AIMessage

        from malspark.agents.base_agent import BaseAnalyst

        retry = self.ANSWER
        asked: list[int] = []

        class _Model:
            def invoke(self, messages: Any, *args: Any, **kwargs: Any) -> AIMessage:
                asked.append(1)
                return AIMessage(content=retry)

            async def ainvoke(self, messages: Any, *args: Any, **kwargs: Any) -> AIMessage:
                return self.invoke(messages)

        class _Reviser(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - unused
                return ""

            def revise(self, *args: Any, **kwargs: Any) -> str:
                return first

        analyst = _Reviser(llm=_Model(), name="static")  # type: ignore[arg-type]
        with patch("malspark.agents.base_agent.validity_check_available", return_value=True):
            text, revision = analyst.safe_revise_isr("data", "own", {}, "feedback", 1)
        return text, revision, len(asked)

    def _stands(self, text: str, revision: Any) -> list[str]:
        return _run(text, revision, in_force=IN_FORCE + _block(self.MUTEX), line=self.LINE_3)

    def test_with_no_question_asked_the_record_reaches_the_node(self) -> None:
        from malspark.pipeline.revision_merge import claims_left_unread_of

        text, revision, asked = self._revised(self.ANSWER)

        assert asked == 0 and claims_left_unread_of(revision) == 1
        assert self.MUTEX in self._stands(text, revision)

    def test_a_retry_the_validation_turn_keeps_carries_its_own_record(self) -> None:
        from malspark.pipeline.revision_merge import claims_left_unread_of

        # Claim 2's confidence cannot be read: the turn asks, and the retry it
        # keeps reads it but still begins claim 3 under the plain-dot heading.
        first = self.ANSWER.replace(
            "resolves.\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8",
            "resolves.\nEVIDENCE: [ev_0001]\nCONFIDENCE: high",
        )
        assert first != self.ANSWER

        text, revision, asked = self._revised(first)

        assert asked >= 1 and len(revision.claims) == 2
        assert claims_left_unread_of(revision) >= 1
        assert self.MUTEX in self._stands(text, revision)
