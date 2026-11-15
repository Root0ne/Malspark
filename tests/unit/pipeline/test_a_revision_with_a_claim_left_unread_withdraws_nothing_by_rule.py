"""A revision that began a claim the platform did not read withdraws nothing by rule.

The claim left unread may be the named claim restated: a claim a blocking
line named is then carried with its line, its mark kept, and the merge says
why. The signal is the revision's own reading of its claim blocks, as its
answer holds it (``revision_merge.claims_left_unread_of``): a reason that
claims it began were not read, a note that parts of the input were not
analysed among them, and each block that states no confidence. A caller that
holds no such reading has the text read once: a block whose confidence cannot
be read, or that states none, counts, a note in the text does not. With every
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
            and "began 1 claim block(s) the platform did not read" in s
            for s in merge.sentences("static", 2)
        )

    def test_a_block_that_states_no_confidence_counts(self) -> None:
        answer = (
            READ
            + "CLAIM: The mutex name at 0x403962 is read from ev_0109.\nEVIDENCE: [ev_0109]\n---\n"
        )

        merge = _merge(answer)

        assert merge.withdrawn_by_rule == () and [n for n, *_r in merge.held_unread] == [3]

    def test_a_count_the_caller_holds_is_taken_as_given(self) -> None:
        merge = _merge(READ, claims_unread=1)

        assert merge.withdrawn_by_rule == () and [n for n, *_r in merge.held_unread] == [3]


class TestEveryClaimBegunWasRead:
    def test_the_line_rule_withdraws(self) -> None:
        merge = _merge(READ)

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [3]
        assert merge.held_unread == ()

    def test_a_note_of_parts_not_analysed_in_the_text_alone_changes_nothing(self) -> None:
        merge = _merge(READ, NOT_ANALYSED)

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [3]
        assert merge.held_unread == ()


class TestTheCountTheAnswerHolds:
    def test_a_note_of_parts_not_analysed_keeps_the_named_claim(self) -> None:
        from malspark.pipeline.revision_merge import claims_left_unread_of

        merge = _merge(READ, claims_unread=claims_left_unread_of(_isr(READ, NOT_ANALYSED)))

        assert merge.withdrawn_by_rule == () and [n for n, *_r in merge.held_unread] == [3]


class TestTheCountCostsTheAnswersLength:
    def test_an_answer_of_many_blocks(self) -> None:
        from malspark.pipeline.revision_merge import claims_left_unread
        from tests.linear_cost import assert_scales

        def build(size: int) -> Any:
            answer = "".join(_block(f"0x{0x401000 + i:x} reads table {i}.") for i in range(size))
            return lambda: claims_left_unread(answer)

        assert_scales(build, 400)


class TestTheSentenceStatesWhatTheRecordStates:
    def _held(self, revision: AgentISR, answer: str) -> str:
        from malspark.pipeline.revision_merge import claims_left_unread_of

        merge = merge_revision(
            _isr(IN_FORCE),
            revision,
            answer,
            2,
            {3: [(1, True)]},
            claims_unread=claims_left_unread_of(revision),
        )
        said = [s for s in merge.sentences("static", 2) if "is carried with blocking line" in s]
        assert len(said) == 1
        return said[0]

    def test_parts_not_analysed(self) -> None:
        from malspark.agents.base_agent import parts_not_analysed_reason

        revision = _isr(READ, parts_not_analysed_reason("static", ["chunk 3 of 4 never started"]))

        said = self._held(revision, READ)

        assert "parts of the input were not analysed" in said
        assert "claim block" not in said and "chunk 3" not in said

    def test_a_claim_block_begun_and_not_read(self) -> None:
        from malspark.agents.base_agent import claims_unread_sentence

        note = claims_unread_sentence("static", read_claim_blocks(UNREADABLE), 2)
        revision = _isr(UNREADABLE, note)

        said = self._held(revision, UNREADABLE)

        assert "began claim blocks the platform did not read" in said
        assert "parts of the input" not in said and "high-ish" not in said

    def test_a_reason_in_other_words(self) -> None:
        from malspark.pipeline.revision_merge import OTHER_UNREAD_WHY

        revision = _isr(READ, "The answer stopped at the output limit before its last section.")

        said = self._held(revision, READ)

        assert f"the round-2 revision {OTHER_UNREAD_WHY}, so nothing" in said
        assert "claim block" not in said and "output limit" not in said

    def test_a_block_without_a_confidence_alone(self) -> None:
        from malspark.pipeline.revision_merge import UNREAD_BLOCKS_WHY

        answer = (
            READ
            + "CLAIM: The mutex name at 0x403962 is read from ev_0109.\nEVIDENCE: [ev_0109]\n---\n"
        )
        read = read_claim_blocks(answer)
        assert read.without_confidence == 1
        revision = _isr(answer)
        revision.note_parse(blocks_without_confidence=read.without_confidence)
        assert revision.claims_unread_reason == ""

        said = self._held(revision, answer)

        assert f"the round-2 revision {UNREAD_BLOCKS_WHY}, so nothing" in said
        assert "claim block(s)" not in said

    def test_both_in_their_own_words(self) -> None:
        from malspark.agents.base_agent import claims_unread_sentence, parts_not_analysed_reason

        note = claims_unread_sentence("static", read_claim_blocks(UNREADABLE), 2)
        note += " " + parts_not_analysed_reason("static", ["chunk 3 of 4 never started"])
        said = self._held(_isr(UNREADABLE, note), UNREADABLE)

        assert "began claim blocks the platform did not read" in said
        assert "parts of the input were not analysed" in said
