"""A dispute item is read as the author's withdrawal of its claim only where it says so of it.

The reading only decides whether a block restating the claim may replace it
without the address test, so where it is unsure it reads nothing. A
withdrawn word after the reference is read only when nothing but words of
the passive stand between them and it ends the item, a sentence or a clause,
or goes on with "as", "and", or "by" with the author or a claim; a place, a
part, a colon or another agent after it makes it a doubt. A verb on a pronoun
in a later sentence is read only when no sentence between them has another
subject, no keeping word stands between them, and a plural pronoun does not
stand for one claim. "to" between two numbers is a range only when the
second is not below the first and is no decimal.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.retry_merge import read_own_withdrawals
from malspark.pipeline.revision_merge import claims_named_in_force, merge_revision
from malspark.schemas.isr_models import AgentISR
from tests.unit.pipeline.prose_dispute_items import DEFENCES, RESTATED_ELSEWHERE, WITHDRAWALS


def _read(item: str) -> list[tuple[str, str]]:
    return [c[:2] for c in read_own_withdrawals([item], 1).claims]


def _claims_read(item: str) -> set[int]:
    return {n for low, high in _read(item) for n in range(int(low), int(high) + 1)}


class TestADefenceReadsAsNoWithdrawalOfItsClaim:
    def test_none_of_them_withdraws_claim_3_or_4(self) -> None:
        read = [item for item in DEFENCES if _claims_read(item) & {3, 4}]

        assert read == []

    def test_each_path_alone(self) -> None:
        for item in (
            # A pronoun in a later sentence that stands for the challenge.
            "My claim 4. L2 says it is unsupported. I reject this: ev_0012 shows the call.",
            "My claim 4: TRIAGE disputes it. We reject this.",
            "My claim 4 is supported by ev_0012. The mediator calls it stale. I reject this.",
            "My claim 4 stands. I reject it: the L2 ruling.",
            "My claim 4. I reject them: the peers' objections cite no ledger id.",
            "My claim 4 stands. I reject it.",
            "My claim 4. I reject them.",
            # A passive word with another agent, a place or a part after it.
            "My claim 4 was rejected in L2.",
            "My claim 4: the handle is withdrawn by CloseHandle at 0x7a54.",
            "My claims 3 and 4 are superseded in part: 3 is narrowed, 4 is unchanged.",
            # A withdrawn word as a label, or said of another noun.
            "My claim 4. Rejected: STATIC's idea that the mutex is unused.",
            "My claim 4 refined: the earlier Win32 path is superseded.",
        ):
            assert _claims_read(item) & {3, 4} == set(), item


class TestTheFirstReviewsDefencesStillReadAsNothing:
    def test_each_reads_as_nothing(self) -> None:
        for item in (
            "My claim 4 is not withdrawn.",
            "My claim 4 was rejected by the mediator, but ev_0012 supports it.",
            "My earlier claim 4 has been rejected by two peers; I maintain it.",
            "My claim 4. Peers rejected it but ev_0012 confirms.",
            "My claim 4 is not superseded by STATIC's reading.",
            "If ev_0012 is wrong, I withdraw my claim 4.",
            "I withdraw my claim 4 — no, I keep it.",
            "My claims 3-5: TRIAGE says they are superseded; I disagree.",
            'STATIC wrote: "my claim 3 is wrong. I reject this."',
            "I reject my claim 4's critics.",
        ):
            assert _read(item) == [], item


class TestAWithdrawalSaidOfTheClaimIsRead:
    def test_each_form(self) -> None:
        for item in (
            "I withdraw my claim 4.",
            "My claim 4 is withdrawn.",
            "My claim 4. Withdrawn as stated.",
            "My earlier claim 4 is superseded by Claim 2 above.",
            "My claim 4 is rejected by me on re-reading ev_0012.",
            "My claims 4 and 5 are withdrawn.",
            "My claim 4 was wrong. I withdraw it.",
            "My claims 4 and 5. I reject them.",
            "My claims 4 and 5 are withdrawn and replaced by claims 1 and 2 above.",
        ):
            assert 4 in _claims_read(item), item

    def test_a_replacement_by_another_claim_may_be_read(self) -> None:
        for item in RESTATED_ELSEWHERE:
            assert _claims_read(item) <= {4}, item

    def test_the_real_withdrawals_read_are_the_ones_said_of_the_claim(self) -> None:
        read = [item for item in WITHDRAWALS if 4 in _claims_read(item)]

        assert read == [
            "I withdraw my claim 4.",
            "I retract my claim 4: the ledger has no entry for it.",
            "I withdraw my claim 4 because ev_0012 shows a different call.",
            "My claim 4 is withdrawn.",
            "My claim 4 is retracted.",
            "My claim 4. Withdrawn as stated.",
            "My earlier claim 4 is superseded by Claim 2 above.",
            "My round-1 claim 4 (the port is 80). Withdrawn.",
            "My claims 4 and 5 are withdrawn.",
            "My claims 4-6 are superseded by Claim 2.",
            "I withdraw my claims 4 and 5.",
            "My claim 4 was wrong. I withdraw it.",
            "My claim 4 was wrong; I withdraw it.",
            "My claim 4 is wrong and I withdraw it.",
            "My claim 4 has been superseded by Claim 2.",
            "L1 is right: my claim 4 is withdrawn.",
            "I retract my earlier claim 4 entirely.",
            "My claim 4 is rejected by me on re-reading ev_0012.",
        ]


class TestToBeforeANumber:
    def test_a_decimal_after_it_is_no_range(self) -> None:
        read = read_own_withdrawals(["I lower the confidence of my claim 1 to 0.6."], 0)

        assert read.claims == () and read.spoken == (("1", "1"),)

    def test_a_lower_second_end_is_no_range(self) -> None:
        assert _read("My claims 2 to 1 are withdrawn.") == [("2", "2")]

    def test_a_rising_range_is_read(self) -> None:
        assert _read("My claims 3 to 5 are withdrawn.") == [("3", "5")]


RC4 = "Routine 0x401000 decrypts the config at 0x405000 with RC4 key 'k3y' from 0x406000 (T1027)."
RUN_KEY = "Routine 0x407000 writes the Run key value 'upd' through 0x408000 (T1547.001)."
AGAIN = "The config at 0x405000 is decrypted with RC4 key 'k3y' from 0x406000 (T1027)."


def _block(sentence: str, technique: str) -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: {technique}\n---\n"


def _isr(text: str, disputes: tuple[str, ...] = ()) -> AgentISR:
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=read_claim_blocks(text).claims,
        dissent_items=list(disputes),
    )
    isr.note_answer_text(text)
    return isr


class TestTheMergeReadsTheDisputeAsTheReaderDoes:
    LINE = (
        "[analysts: STATIC ANALYST, TRIAGE ANALYST] STATIC claim 1 says 0x405000 is "
        "RC4-decrypted; nothing shows it. [blocking: the listing shows another call.]"
    )

    def _merge(self, dispute: str) -> Any:
        in_force = _isr(_block(RC4, "T1027") + _block(RUN_KEY, "T1547.001"))
        answer = _block(AGAIN, "T1027") + _block(RUN_KEY, "T1547.001")
        named = claims_named_in_force([self.LINE], ["static", "triage"], {"static": in_force})
        return merge_revision(in_force, _isr(answer, (dispute,)), answer, 2, named.get("static"))

    def test_a_confidence_lowered_to_a_decimal_speaks_for_the_claim(self) -> None:
        merge = self._merge("I lower the confidence of my claim 1 to 0.6; ev_0001 still shows it.")

        assert 1 not in merge.replaced and [n for n, *_r in merge.beside] == [1]

    def test_a_participant_named_between_makes_the_pronoun_its_act(self) -> None:
        merge = self._merge(
            "My claim 1 puts the key in the config. Triage sees it as a decoy. I reject that."
        )

        assert 1 not in merge.replaced and [n for n, *_r in merge.beside] == [1]

    def test_a_withdrawal_said_of_the_claim_lets_the_block_replace_it(self) -> None:
        merge = self._merge("My claim 1 is withdrawn.")

        assert 1 in merge.replaced and merge.beside == ()


class TestTheNewReadingsCostTheItemsLength:
    def test_each_unit_repeated(self) -> None:
        from tests.linear_cost import assert_scales

        participants = ("static", "dynamic", "triage", "reverser")
        for unit in (
            "My claim 1. Triage calls it L2. ",
            "My claim 1 the path is superseded by x, ",
            "My claim 1 stands. I reject them. ",
            "my claims 1 to 0.6 and ",
            "My claim 1 is withdrawn by claim 2 by me in ",
        ):

            def build(size: int, unit: str = unit) -> Any:
                item = unit * size + " I reject this."
                return lambda: read_own_withdrawals([item], 1, participants)

            assert_scales(build, 2_000)


class TestEachRoleWordIsAnotherSubject:
    def test_each_role_word_between_the_reference_and_the_verb(self) -> None:
        for role in ("mediator", "peer", "reviewer"):
            item = f"My claim 4 sets the key. The {role} sees it as a decoy. I reject it."

            assert _read(item) == [], role
