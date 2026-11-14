"""A revision that began a claim the platform did not read withdraws nothing by rule.

The claim left unread may be the named claim restated: a claim a blocking
line named is then carried with its line, its mark kept, and the merge says
why. With every claim it began read, the line rule withdraws as before.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.revision_merge import merge_revision
from malspark.schemas.isr_models import AgentISR


def _block(sentence: str) -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


LOADER = "0x40cf14 loads the saved URL list from the file at 0x4103b8."
GATE = "0x406328 returns 1 only when the tables at 0x4084e4 and 0x40abd4 resolve."
MUTEX = "The mutex name at 0x403962 is not recovered."
IN_FORCE = _block(LOADER) + _block(GATE) + _block(MUTEX)
ANSWER = _block(LOADER) + _block(GATE)
UNREAD = "1 claim block it began was not read: its confidence 'high-ish' is no number."


def _isr(text: str, unread: str = "") -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    if unread:
        isr.note_claims_unread(unread)
    return isr


def _merge(unread: str) -> Any:
    return merge_revision(_isr(IN_FORCE), _isr(ANSWER, unread), ANSWER, 2, {3: [(1, True)]})


class TestAClaimBegunAndNotRead:
    def test_the_named_claim_stays_with_its_mark(self) -> None:
        merge = _merge(UNREAD)

        assert merge.withdrawn_by_rule == ()
        assert merge.merged is not None
        kept = next(c for c in merge.merged.claims if c.claim == MUTEX)
        assert kept.carried_contested_by == ["L1 (round 2)"]
        assert [(n, lines) for n, _s, lines, _why in merge.held_unread] == [(3, (1,))]
        assert any(
            s.startswith("Claim 3 of the static analyst's answer in force (\"")
            and "is carried with blocking line L1" in s
            and "began a claim the platform did not read" in s
            for s in merge.sentences("static", 2)
        )

    def test_with_every_claim_read_the_line_rule_withdraws(self) -> None:
        merge = _merge("")

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [3]
        assert merge.held_unread == ()
