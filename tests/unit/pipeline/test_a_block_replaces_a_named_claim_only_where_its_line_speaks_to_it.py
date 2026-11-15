"""A block replaces a named claim without the address test only where its line speaks to it.

A blocking line speaks to a claim itself when the claim shares a ledger id or
a value with the whole line, or when the line writes a run of four
consecutive words of the claim's sentence. Only such a claim, and only where
no own reference of the revision's disputes speaks for it, is replaced by
the block that restates it best whatever addresses that block drops. Every
other named claim keeps the address and subject tests of a claim no line
named: a block that restates it without an address of it leaves it carried
beside that block, and a claim a block restates is never withdrawn by rule.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.revision_merge import claims_named_in_force, merge_revision
from malspark.schemas.isr_models import AgentISR

STATIC = "[analysts: STATIC ANALYST]"
BLOCKS = "[blocking: the listing shows another call.]"


def _block(sentence: str, evidence: str) -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [{evidence}]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


def _isr(text: str) -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    return isr


GATE = "0x406328 returns 1 only when the tables at 0x4084e4 and 0x40abd4 resolve."
MUTEX = "The mutex name at 0x403962 is not recovered."
SLEEP = "0x40a000 sleeps 60 seconds between beacons."
IN_FORCE = _block(GATE, "ev_0012") + _block(MUTEX, "ev_0013") + _block(SLEEP, "ev_0014")
# A block about the beacon's timing that shares two of the gate's addresses
# and drops the gate's routine: another finding.
BEACON = "0x40abd4 schedules the beacon after the table at 0x4084e4 resolves."
ADDED = "0x409000 enumerates the running processes with a snapshot."


def _merge(line: str, answer: str, disputes: tuple[str, ...] = ()) -> Any:
    in_force = _isr(IN_FORCE)
    revision = _isr(answer)
    revision.dissent_items = list(disputes)
    named = claims_named_in_force([line], ["static"], {"static": in_force})
    return merge_revision(in_force, revision, answer, 2, named.get("static"))


class TestALineThatSpeaksToNoClaimItself:
    # A line written about an older claim 1: it shares no id, value or words
    # with the claim of that number in force.
    STALE = f"{STATIC} STATIC claim 1 says the loader at 0x40cf14 reads the URL list. {BLOCKS}"

    def test_a_block_about_another_finding_leaves_the_claim_carried_beside_it(self) -> None:
        merge = _merge(self.STALE, _block(BEACON, "ev_0020") + _block(SLEEP, "ev_0014"))

        assert 1 not in merge.replaced
        assert [(n, a) for n, _s, _now, a in merge.beside] == [(1, ("0x406328",))]
        assert merge.withdrawn_by_rule == ()

    def test_with_no_block_restating_the_claim_the_line_rule_still_withdraws_it(self) -> None:
        merge = _merge(self.STALE, _block(ADDED, "ev_0020") + _block(SLEEP, "ev_0014"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [1]


class TestALineThatSpeaksToTheClaimItself:
    def test_by_a_value_the_block_replaces_it_whatever_address_it_drops(self) -> None:
        line = f"{STATIC} STATIC claim 1 puts the gate at 0x406328; nothing shows it. {BLOCKS}"

        merge = _merge(line, _block(BEACON, "ev_0020") + _block(SLEEP, "ev_0014"))

        assert 1 in merge.replaced and merge.beside == ()

    def test_by_a_quotation_of_four_words_the_block_replaces_it(self) -> None:
        line = (
            f"{STATIC} STATIC claim 1 says the gate returns 1 only when a table resolves. {BLOCKS}"
        )

        merge = _merge(line, _block(BEACON, "ev_0020") + _block(SLEEP, "ev_0014"))

        assert 1 in merge.replaced and merge.beside == ()

    def test_an_own_reference_that_speaks_for_it_keeps_the_address_test(self) -> None:
        line = f"{STATIC} STATIC claim 1 puts the gate at 0x406328; nothing shows it. {BLOCKS}"

        merge = _merge(
            line,
            _block(BEACON, "ev_0020") + _block(SLEEP, "ev_0014"),
            ("My claim 1 stands: ev_0012 shows the gate at 0x406328.",),
        )

        assert 1 not in merge.replaced and [n for n, *_r in merge.beside] == [1]


class TestALineThatQuotesOneClaimAndNamesAnother:
    def test_it_does_not_withdraw_the_other_by_rule(self) -> None:
        line = (
            f"{STATIC} STATIC claims 1 and 2 say the gate returns 1 only when a table resolves. "
            f"{BLOCKS}"
        )

        merge = _merge(line, _block(ADDED, "ev_0020") + _block(SLEEP, "ev_0014"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [1]
        assert [n for n, *_r in merge.not_spoken_to] == [2]
