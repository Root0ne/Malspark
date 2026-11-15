"""The line rule reads the disputes once per merge; a reversed range refers to both ends.

Each dispute item is read once, outside the loop over the claims in force,
and whether the disputes refer to a claim is asked only of a claim a blocking
line names. A range written backwards ("my claims 9-2", "claims 6 to 4")
names no claim, but both its ends count as referred to for the line rule:
any reference defends.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.revision_merge import merge_revision
from malspark.schemas.isr_models import AgentISR
from tests.linear_cost import assert_scales


def _block(sentence: str) -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


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


ADDED = _block("Routine 0x9a0000 enumerates the running processes.")


class TestAMergeWithNoLineNamingAnything:
    def test_many_claims_and_as_many_disputes_cost_their_length(self) -> None:
        def build(size: int) -> Any:
            text = "".join(
                _block(
                    f"Routine 0x{0x400000 + i * 16:x} does thing {i} via 0x{0x600000 + i * 16:x}."
                )
                for i in range(size)
            )
            disputes = tuple(
                f"Peer point {i}: ev_0001 shows 0x{0x700000 + i * 16:x} with words {'x ' * 20}"
                for i in range(size)
            )
            in_force, revision = _isr(text, revision_round=1), _isr(ADDED, disputes, 2)
            return lambda: merge_revision(in_force, revision, ADDED, 2, {}, claims_unread=0)

        assert_scales(build, 400)

    def test_with_one_claim_named_the_disputes_are_read_in_their_length(self) -> None:
        def build(size: int) -> Any:
            text = "".join(
                _block(
                    f"Routine 0x{0x400000 + i * 16:x} does thing {i} via 0x{0x600000 + i * 16:x}."
                )
                for i in range(size)
            )
            disputes = tuple(
                f"Peer point {i}: ev_0001 shows 0x{0x700000 + i * 16:x} with words {'x ' * 20}"
                for i in range(size)
            )
            in_force, revision = _isr(text, revision_round=1), _isr(ADDED, disputes, 2)
            named = {1: [(1, True)]}
            return lambda: merge_revision(in_force, revision, ADDED, 2, named, claims_unread=0)

        assert_scales(build, 100)


class TestAReversedRangeRefersToBothEnds:
    IN_FORCE = "".join(
        _block(f"Routine 0x{0x401000 + i * 0x100:x} reads table {i}.") for i in range(9)
    )

    def _ruled(self, dispute: str, claim: int) -> list[int]:
        merge = merge_revision(
            _isr(self.IN_FORCE, revision_round=1),
            _isr(ADDED, (dispute,), 2),
            ADDED,
            2,
            {claim: [(1, True)]},
            claims_unread=0,
        )
        return [n for n, _s, _r in merge.withdrawn_by_rule]

    def test_with_a_dash(self) -> None:
        assert self._ruled("My claims 9-2 hold: ev_0001 shows both.", 2) == []
        assert self._ruled("My claims 9-2 hold: ev_0001 shows both.", 9) == []

    def test_with_to(self) -> None:
        assert self._ruled("Claims 6 to 4 hold; ev_0001 shows them.", 4) == []

    def test_a_claim_inside_it_is_not_referred_to(self) -> None:
        assert self._ruled("My claims 9-2 hold: ev_0001 shows both.", 5) == [5]
