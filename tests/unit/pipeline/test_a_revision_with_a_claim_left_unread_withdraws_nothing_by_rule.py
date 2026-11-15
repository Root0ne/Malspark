"""A revision that began a claim the platform did not read withdraws nothing by rule.

The claim left unread may be the named claim restated: a claim a blocking
line named is then carried with its line, its mark kept, and the merge says
why. The signal is the revision's own reading of its claim blocks: a block
whose confidence cannot be read, or that states none, is a claim begun and not
read; a note that parts of the input were not analysed is not. With every
claim it began read, the line rule withdraws as before.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.revision_merge import merge_revision
from malspark.schemas.isr_models import AgentISR


def _block(sentence: str, confidence: str = "0.8") -> str:
    return (
        f"CLAIM: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: {confidence}\nTECHNIQUE: NONE\n---\n"
    )


LOADER = "0x40cf14 loads the saved URL list from the file at 0x4103b8."
GATE = "0x406328 returns 1 only when the tables at 0x4084e4 and 0x40abd4 resolve."
MUTEX = "The mutex name at 0x403962 is not recovered."
IN_FORCE = _block(LOADER) + _block(GATE) + _block(MUTEX)
READ = _block(LOADER) + _block(GATE)
# The third block restates the mutex claim with a confidence no reader takes.
UNREADABLE = READ + _block("The mutex name at 0x403962 is read from ev_0109.", "high-ish")
NOT_ANALYSED = "Parts of the input were not analysed: chunk 3 of 4 was never started."


def _isr(text: str, note: str = "") -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    if note:
        isr.note_claims_unread(note)
    return isr


def _merge(answer: str, note: str = "", **kwargs: Any) -> Any:
    return merge_revision(_isr(IN_FORCE), _isr(answer, note), answer, 2, {3: [(1, True)]}, **kwargs)


class TestAClaimBegunAndNotRead:
    def test_the_named_claim_stays_with_its_mark(self) -> None:
        merge = _merge(UNREADABLE)

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

    def test_a_count_the_caller_holds_is_taken_as_given(self) -> None:
        merge = _merge(READ, claims_unread=1)

        assert merge.withdrawn_by_rule == () and [n for n, *_r in merge.held_unread] == [3]


class TestEveryClaimBegunWasRead:
    def test_the_line_rule_withdraws(self) -> None:
        merge = _merge(READ)

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [3]
        assert merge.held_unread == ()

    def test_a_note_of_parts_not_analysed_alone_changes_nothing(self) -> None:
        merge = _merge(READ, NOT_ANALYSED)

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [3]
        assert merge.held_unread == ()


class TestTheCountCostsTheAnswersLength:
    def test_an_answer_of_many_blocks(self) -> None:
        from malspark.pipeline.revision_merge import claims_left_unread
        from tests.linear_cost import assert_scales

        def build(size: int) -> Any:
            answer = "".join(_block(f"0x{0x401000 + i:x} reads table {i}.") for i in range(size))
            return lambda: claims_left_unread(answer)

        assert_scales(build, 400)
