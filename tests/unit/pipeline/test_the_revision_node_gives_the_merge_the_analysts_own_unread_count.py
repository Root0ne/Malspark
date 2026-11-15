"""The revision node gives the merge the count of claims the analyst's own reading left unread.

The count is what the revision's answer holds after its validation turn: a
reason that claims it began were not read (a note that parts of the input
were not analysed among them) and the blocks that stated no confidence. With
one or more, the line rule withdraws nothing for that revision; with none,
the merge does not read the text again, so a claim heading quoted in prose
or a code fence switches nothing off.

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


def _run(answer: str, revision: AgentISR) -> Any:
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
        agent_name=MEDIATOR_AGENT_NAME, finding="revise", contradictions=[LINE], revise=["static"]
    )
    state = {
        "file_hash": "abc",
        "iteration_count": 1,
        "discussion_history": [mediation],
        "reports": {"static": IN_FORCE},
        "isr_reports": {"static": _isr(IN_FORCE)},
    }
    out = asyncio.run(make_revision_node(container)(state))
    return [c.claim for c in out["isr_reports"]["static"].claims]


class TestTheCountComesFromTheAnswer:
    def test_a_reason_the_answer_holds_keeps_the_named_claim(self) -> None:
        answer = _block(LOADER)

        stands = _run(answer, _isr(answer, "1 claim block it began could not be read."))

        assert GATE in stands

    def test_a_note_of_parts_not_analysed_keeps_it_too(self) -> None:
        answer = _block(LOADER)

        stands = _run(answer, _isr(answer, "Parts of the input were not analysed: chunk 3."))

        assert GATE in stands

    def test_with_none_a_heading_quoted_in_a_code_fence_switches_nothing_off(self) -> None:
        answer = _block(LOADER) + "```\nCLAIM: example\nEVIDENCE: [ev_x]\n```\n"

        stands = _run(answer, _isr(answer))

        assert GATE not in stands

    def test_the_count_adds_the_blocks_without_a_confidence(self) -> None:
        from malspark.pipeline.revision_merge import claims_left_unread_of

        isr = _isr(_block(LOADER))
        isr.note_parse(blocks_without_confidence=2)
        isr.note_claims_unread("1 claim block it began could not be read.")

        assert claims_left_unread_of(isr) == 3
        assert claims_left_unread_of(_isr(_block(LOADER))) == 0
