"""A blocking line withdraws by rule only a claim it speaks to, whatever form names it.

A line speaks to a claim when the clause of a reference naming it shares a
ledger id or an address with the claim, as a range is read: a single number,
a list and a range alike. A claim the line names without speaking to it is
left as a claim no line named: never withdrawn by rule, no mark from that
line, and the reference is stated as not placed on it.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.debate_facts import claims_named_by_lines
from malspark.pipeline.revision_merge import claim_tokens_by_number, merge_revision
from malspark.schemas.isr_models import AgentISR

PARTICIPANTS = ["static", "dynamic"]
STATIC = "[analysts: STATIC ANALYST]"
BLOCKS = "[blocking: the listing shows another call.]"


def _block(sentence: str, evidence: str) -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [{evidence}]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


LOADER = "0x40cf14 loads the saved URL list from the file at 0x4103b8."
GATE = "0x406328 returns 1 only when the tables at 0x4084e4 and 0x40abd4 resolve."
MUTEX = "The mutex name at 0x403962 is not recovered."
ADDED = "0x409000 enumerates the running processes with a snapshot."
IN_FORCE = _block(LOADER, "ev_0011") + _block(GATE, "ev_0012") + _block(MUTEX, "ev_0013")


def _isr(text: str) -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    return isr


def _merge(line: str, answer: str) -> Any:
    in_force = _isr(IN_FORCE)
    named = claims_named_by_lines(
        [line], PARTICIPANTS, {"static": claim_tokens_by_number(in_force)}
    )
    return merge_revision(in_force, _isr(answer), answer, 2, named.get("static"))


class TestALineAboutOneClaim:
    def test_a_number_it_also_names_withdraws_nothing_of_that_claim(self) -> None:
        line = (
            f"{STATIC} STATIC claims 1 and 2 say 0x40cf14 loads the URL list; the listing "
            f"shows it reads the config. {BLOCKS}"
        )

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [1]
        assert [n for n, _s in merge.carried] == [2, 3]
        assert merge.merged is not None
        gate = next(c for c in merge.merged.claims if c.claim == GATE)
        assert not gate.carried_contested_by
        assert [(n, line_number) for n, _s, line_number, _ref in merge.not_spoken_to] == [(2, 1)]
        said = merge.sentences("static", 2)
        assert any(
            s.startswith("Blocking line L1 of the round-2 mediation names claims 1-2 of the static")
            and s.endswith("so the reference is not placed on it and withdraws nothing of it.")
            for s in said
        )

    def test_a_single_number_whose_clause_is_about_another_claim_withdraws_nothing(self) -> None:
        line = f"{STATIC} STATIC claim 3 says the beacon at 0x40cf14 sleeps 60 s. {BLOCKS}"

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert merge.withdrawn_by_rule == ()
        assert [n for n, _s in merge.carried] == [1, 2, 3]

    def test_the_unrelated_claim_keeps_the_subject_test_of_an_unnamed_claim(self) -> None:
        # The block restates the gate without 0x40abd4: an unnamed claim stays
        # beside it, and so does the claim the line names without speaking to.
        line = f"{STATIC} STATIC claims 1 and 2 say 0x40cf14 loads the URL list. {BLOCKS}"
        again = "0x406328 returns 1 only when the table at 0x4084e4 resolves."

        merge = _merge(line, _block(again, "ev_0012"))

        assert 2 not in merge.replaced
        assert [n for n, *_rest in merge.beside] == [2]


class TestALineThatParaphrasesItsClaim:
    def test_with_a_shared_token_it_still_withdraws_the_claim(self) -> None:
        line = (
            f"{STATIC} STATIC claim 2 overstates the gate: ev_0012 shows the check at "
            f"0x406328 returns 0 on a single table. {BLOCKS}"
        )

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2]
        assert merge.not_spoken_to == ()

    def test_a_shared_ledger_id_alone_speaks_to_it(self) -> None:
        line = f"{STATIC} STATIC claim 3 rests on ev_0013 alone. {BLOCKS}"

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [3]
