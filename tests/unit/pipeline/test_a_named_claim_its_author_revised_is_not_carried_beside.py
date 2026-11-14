"""A claim a blocking line named, in a round its analyst revised, is not carried beside it.

The revision answers the line: one block that restates the claim replaces
it, its addresses stated or not; with no block restating it, the line rule
withdraws it, unless the revision's disputes defend it. A claim no blocking
line named keeps the subject test: a block that restates it without one of
its addresses leaves it carried beside that block. A dispute in which the
analyst rejects its own earlier claim withdraws that claim; one that rejects
another analyst's claim is a dispute.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import random
from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.claim_drops import dropped_values
from malspark.pipeline.retry_merge import read_own_withdrawals
from malspark.pipeline.revision_merge import merge_revision
from malspark.schemas.isr_models import AgentISR
from tests.linear_cost import assert_scales, assert_under


def _block(sentence: str, technique: str = "NONE") -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: {technique}\n---\n"


def _isr(text: str, disputes: tuple[str, ...] = (), revision_round: int = 0) -> AgentISR:
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=read_claim_blocks(text).claims,
        dissent_items=list(disputes),
        revision_round=revision_round,
    )
    isr.note_answer_text(text)
    return isr


def _carried(merge: Any) -> list[int]:
    return [n for n, _s in merge.carried]


LOADER = (
    "0x40cf14 loads the saved URL list from the file at 0x4103b8 through 0x40cea4 and 0x40c964."
)
# The loader claim written again without the routine it was about.
CORRECTED = "0x40cea4 reads the URL list from the file at 0x4103b8 and 0x40c964 decrypts it."
GATE = "0x406328 returns 1 only when the tables at 0x4084e4 and 0x40abd4 resolve."
GATE_AGAIN = "0x406328 returns 1 when both tables at 0x4084e4 and 0x40abd4 resolve."
MUTEX = "The mutex name at 0x403962 is not recovered; the call shows only (0,0)."
ADDED = "0x409000 enumerates the running processes with a snapshot."
IN_FORCE = _block(LOADER) + _block(GATE)
BLOCKING_L3 = {1: [(3, True)]}


class TestANamedClaimRestatedWithoutAnAddress:
    def test_the_block_replaces_it(self) -> None:
        answer = _block(CORRECTED) + _block(GATE_AGAIN)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2, BLOCKING_L3)

        assert merge.replaced == (1, 2)
        assert merge.beside == () and merge.withdrawn_by_rule == ()
        # Every claim in force written again: the revision stands as written.
        assert merge.merged is None

    def test_beside_a_carried_claim_the_block_stands_once_in_its_place(self) -> None:
        answer = _block(CORRECTED) + _block(ADDED)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2, BLOCKING_L3)

        assert merge.merged is not None
        assert merge.replaced == (1,) and _carried(merge) == [2] and merge.beside == ()
        assert [c.claim for c in merge.merged.claims] == [CORRECTED, GATE, ADDED]

    def test_the_value_no_block_states_is_still_recorded_as_dropped(self) -> None:
        answer = _block(CORRECTED) + _block(ADDED)
        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2, BLOCKING_L3)

        dropped = dropped_values(_isr(IN_FORCE), merge.merged, answer, 2)

        assert [(d.claim, d.missing) for d in dropped] == [(LOADER, ("0x40cf14",))]

    def test_a_line_that_does_not_block_leaves_it_carried_beside(self) -> None:
        answer = _block(CORRECTED) + _block(GATE_AGAIN)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2, {1: [(3, False)]})

        assert merge.replaced == (2,) and _carried(merge) == [1]
        assert merge.beside == ((1, LOADER, 3, ("0x40cf14",)),)


class TestAClaimNoLineNamedKeepsTheSubjectTest:
    def test_it_is_carried_beside_the_block(self) -> None:
        answer = _block(CORRECTED) + _block(GATE_AGAIN)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2, {2: [(1, True)]})

        assert merge.merged is not None
        assert [c.claim for c in merge.merged.claims] == [LOADER, GATE_AGAIN, CORRECTED]
        assert merge.replaced == (2,) and _carried(merge) == [1]
        assert merge.beside == ((1, LOADER, 3, ("0x40cf14",)),)


class TestANamedClaimNoBlockRestates:
    def test_it_is_withdrawn_by_rule_and_recorded(self) -> None:
        answer = _block(GATE_AGAIN) + _block(ADDED)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2, BLOCKING_L3)

        reason = (
            "named by blocking line L3 of the round-2 mediation; the revision did not restate it"
        )
        assert merge.withdrawn_by_rule == ((1, LOADER, reason),)
        assert [c.claim for c in merge.ruled_claims] == [LOADER]
        assert (
            f'Claim 1 of the static analyst\'s answer in force ("{LOADER}") is withdrawn by rule '
            f"after the round-2 revision: {reason}."
        ) in merge.sentences("static", 2)

    def test_defended_in_the_disputes_it_stays_with_the_line(self) -> None:
        answer = _block(GATE_AGAIN) + _block(ADDED)
        defence = (
            "L3 on my claim 1: I keep it. ev_0001 shows 0x40cf14 calling 0x40cea4 on the file "
            "at 0x4103b8."
        )

        merge = merge_revision(_isr(IN_FORCE), _isr(answer, (defence,)), answer, 2, BLOCKING_L3)

        assert merge.merged is not None
        assert merge.withdrawn_by_rule == () and _carried(merge) == [1]
        carried = next(c for c in merge.merged.claims if c.claim == LOADER)
        assert carried.carried_contested_by == ["L3 (round 2)"]


class TestTheAnalystRejectsItsOwnClaim:
    IN_FORCE = _block(LOADER) + _block(MUTEX) + _block(GATE)

    def _merge(self, dispute: str, *, named: Any = None, revision_round: int = 3) -> Any:
        answer = _block(GATE_AGAIN) + _block(ADDED)
        return merge_revision(
            _isr(self.IN_FORCE, revision_round=revision_round - 1),
            _isr(answer, (dispute,), revision_round=revision_round),
            answer,
            revision_round,
            named,
        )

    def _withdrawn(self, merge: Any) -> list[int]:
        return [n for n, _s, _r in merge.withdrawn]

    def test_its_claim_listed_among_the_rejected_ones_is_withdrawn(self) -> None:
        dispute = (
            "Peer claims that the mutex name is not recovered (STATIC ANALYST claim 23, my own "
            "earlier claim 2). I reject this. [ev_0109] passes the buffer as the third argument."
        )

        merge = self._merge(dispute, named={2: [(1, True)]})

        assert self._withdrawn(merge) == [2]
        assert merge.withdrawn_by_rule == () and 2 not in _carried(merge)
        assert merge.withdrawn[0][2].startswith("Peer claims that the mutex name")

    def test_the_forms_the_revisions_write(self) -> None:
        for dispute in (
            "My own claim 2 in the earlier round said the name was not shown, and I withdraw it.",
            "My claim 2 (the mutex name is not recovered). Withdrawn as stated; see the new claim.",
            "My claims 1 and 2 are superseded by the claims above.",
            "I retract my earlier claim 2: ev_0109 shows the third argument.",
            "I reject my own claim 2; ev_0109 shows the buffer passed as R8.",
        ):
            merge = self._merge(dispute)
            assert 2 in self._withdrawn(merge), dispute

    def test_another_analysts_claim_rejected_is_a_dispute(self) -> None:
        for dispute in (
            "STATIC claim 2 says the mutex name is not recovered. I reject this.",
            "Triage claim 2 and dynamic claim 1 hold the name unread; I reject both.",
            "Peer claim 2 contradicts my claim 1. I reject this.",
        ):
            merge = self._merge(dispute)
            assert self._withdrawn(merge) == [], dispute

    def test_a_doubt_withdraws_nothing(self) -> None:
        for dispute in (
            # A part of the claim, not the claim.
            "I withdraw my earlier claim 2 confidence of 0.60 and rely on the candidate reading.",
            "Peer claim 5 and my claim 2 say nothing shows the key in use. I reject that wording.",
            "My own claim 2 detail that the name is unread is withdrawn.",
            # The claim kept.
            "My claim 2 stands: ev_0109 shows no third argument. I reject the peer's reading.",
            "My own claims 1 and 2 are revised as above.",
            # Another answer's numbers.
            "My round-0 claim 2 (name not recovered). Withdrawn as stated.",
        ):
            merge = self._merge(dispute)
            assert self._withdrawn(merge) == [], dispute

    def test_a_round_named_for_the_answer_in_force_is_read(self) -> None:
        merge = self._merge("My round-2 claim 2 (name not recovered). Withdrawn as stated.")

        assert self._withdrawn(merge) == [2]

    def test_a_claim_it_rejects_and_no_line_named_is_withdrawn_too(self) -> None:
        merge = self._merge("My own earlier claim 2 is wrong, and I withdraw it.")

        assert self._withdrawn(merge) == [2] and 2 not in _carried(merge)


class TestNoClaimStandsBesideTheBlockThatReplacedIt:
    def test_over_random_revisions(self) -> None:
        # Claims in force, each with a subject address and a helper; revision
        # blocks restate some, with or without the subject, or add new ones.
        rng = random.Random(696)
        for _case in range(150):
            count = rng.randint(1, 5)
            subjects = [0x401000 + 0x100 * i for i in range(count)]
            in_force = "".join(
                _block(f"0x{s:x} decodes the string table at 0x{s + 0x10000:x} with key k{i}x.")
                for i, s in enumerate(subjects)
            )
            answer = ""
            for i, s in enumerate(subjects):
                kind = rng.choice(("same", "without", "skip"))
                if kind == "same":
                    answer += _block(f"0x{s:x} decodes the table at 0x{s + 0x10000:x} with k{i}x.")
                elif kind == "without":
                    answer += _block(
                        f"The string table at 0x{s + 0x10000:x} is decoded with k{i}x."
                    )
            answer += _block(ADDED)
            named = {
                n: [(1, rng.random() < 0.7)] for n in range(1, count + 1) if rng.random() < 0.5
            }

            merge = merge_revision(_isr(in_force), _isr(answer), answer, 2, named)

            first = read_claim_blocks(in_force).claims
            stands = merge.merged.claims if merge.merged is not None else _isr(answer).claims
            sentences = [c.claim for c in stands]
            for number in merge.replaced:
                assert first[number - 1].claim not in sentences
                assert number not in _carried(merge)
            for number, _s, _now, _a in merge.beside:
                assert not any(blocks for _line, blocks in named.get(number, ()))


class TestAHostileDisputeCostsItsLength:
    # A dispute is model text and can carry what a sample planted in a tool's
    # answer: a range is read against the claims that exist, and the reader
    # reads each item in one pass.
    IN_FORCE = _block(LOADER) + _block(MUTEX) + _block(GATE)

    def _merge(self, dispute: str) -> Any:
        answer = _block(GATE_AGAIN) + _block(ADDED)
        return merge_revision(
            _isr(self.IN_FORCE, revision_round=1),
            _isr(answer, (dispute,), revision_round=2),
            answer,
            2,
        )

    def test_a_range_with_a_nine_digit_end_withdraws_only_the_claims_there_are(self) -> None:
        dispute = "My claims 2-999999999 are withdrawn."

        merge = assert_under(lambda: self._merge(dispute), 0.5, what="the merge")
        merge = self._merge(dispute)

        # Claim 3 is written again by a block, and stands as written.
        assert [n for n, _s, _r in merge.withdrawn] == [2] and 3 in merge.replaced

    def test_a_range_with_an_end_too_long_to_convert_is_read(self) -> None:
        merge = self._merge(f"My claims 2-{'9' * 5000} are withdrawn.")

        # Claim 3 is written again by a block, and stands as written.
        assert [n for n, _s, _r in merge.withdrawn] == [2] and 3 in merge.replaced

    def test_a_withdraw_line_with_a_nine_digit_range_is_read_the_same(self) -> None:
        answer = _block(GATE_AGAIN) + _block(ADDED) + "WITHDRAW CLAIMS 2-999999999: gone.\n"

        merge = assert_under(
            lambda: merge_revision(_isr(self.IN_FORCE), _isr(answer), answer, 2),
            0.5,
            what="the merge",
        )
        merge = merge_revision(_isr(self.IN_FORCE), _isr(answer), answer, 2)

        # Claim 3 is written again by a block, and stands as written.
        assert [n for n, _s, _r in merge.withdrawn] == [2] and 3 in merge.replaced

    def test_a_reversed_range_withdraws_nothing(self) -> None:
        assert self._merge("My claims 3-2 are withdrawn.").withdrawn == ()

    def test_an_item_of_many_claim_mentions_is_read_in_linear_time(self) -> None:
        def build(size: int) -> Any:
            item = "my claim 1, " * size + "and my own earlier claim 2. I reject this."
            return lambda: read_own_withdrawals([item], None)

        assert_scales(build, 2_000)

    def test_an_item_of_many_mentions_with_no_withdrawal_is_read_in_linear_time(self) -> None:
        def build(size: int) -> Any:
            item = "Static claim 4 and my claim 1 says (" * size + "x"
            return lambda: read_own_withdrawals([item], None)

        assert_scales(build, 2_000)
