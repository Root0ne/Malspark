"""No reading of a revision's free prose removes a claim by itself.

A claim in force leaves the merged answer only where a block of the revision
replaces it, where a ``WITHDRAW`` line names it, or where the line rule
withdraws it, and the line rule never withdraws a claim the revision's
disputes refer to in any way. A dispute item read as the author's withdrawal
of its own claim has one effect: where a blocking line speaks to that claim
itself and a block of the same revision restates it, the block replaces it
without the address test. With no restating block the claim stays, carried,
with the line's mark where a line named it.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import random
import re
from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.retry_merge import read_withdrawals
from malspark.pipeline.revision_merge import claims_named_in_force, merge_revision
from malspark.schemas.isr_models import AgentISR
from tests.unit.pipeline.prose_dispute_items import DEFENCES, RESTATED_ELSEWHERE, WITHDRAWALS

STATIC = "[analysts: STATIC ANALYST]"
BLOCKS = "[blocking: the listing shows another call.]"


def _block(sentence: str, evidence: str = "ev_0001", technique: str = "NONE") -> str:
    return (
        f"CLAIM: {sentence}\nEVIDENCE: [{evidence}]\nCONFIDENCE: 0.8\nTECHNIQUE: {technique}\n---\n"
    )


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


def _named(lines: list[str], in_force: AgentISR) -> Any:
    return claims_named_in_force(lines, ["static"], {"static": in_force}).get("static")


RC4 = "Routine 0x401000 decrypts the config at 0x405000 with RC4 key 'k3y' from 0x406000 (T1027)."
RUN_KEY = "Routine 0x407000 writes the Run key value 'upd' through 0x408000 (T1547.001)."
SLEEP = "Routine 0x40a000 sleeps 60 seconds."
IN_FORCE = _block(RC4, technique="T1027") + _block(RUN_KEY, technique="T1547.001")
# A blocking line that speaks to claim 1 itself: it writes the claim's address.
ON_CLAIM_1 = f"{STATIC} STATIC claim 1 says 0x405000 is RC4-decrypted; nothing shows it. {BLOCKS}"
# Items that read, or once read, as the author's withdrawal of claim 1.
READ_AS_WITHDRAWN = (
    "My claim 1. L2 says it is unsupported. I reject this: ev_0001 shows the key at 0x406000.",
    "My claim 1 was rejected in L2. ev_0001 shows the key at 0x406000.",
    "My claim 1: the handle is withdrawn by CloseHandle at 0x407000 after decryption.",
    "My claim 1 answers L1: the mediator's reading is superseded by ev_0001.",
    "My claim 1 is withdrawn.",
    "I withdraw my claim 1.",
)


class TestAnOwnWithdrawalWithdrawsNothing:
    def test_with_no_restating_block_the_claim_stays_carried(self) -> None:
        answer = _block(SLEEP)
        for dispute in READ_AS_WITHDRAWN:
            merge = merge_revision(_isr(IN_FORCE), _isr(answer, (dispute,)), answer, 2)

            assert merge.withdrawn == () and merge.withdrawn_by_rule == (), dispute
            assert [n for n, _s in merge.carried] == [1, 2], dispute

    def test_named_by_a_blocking_line_it_stays_with_the_lines_mark(self) -> None:
        answer = _block(SLEEP)
        in_force = _isr(IN_FORCE)
        for dispute in READ_AS_WITHDRAWN:
            merge = merge_revision(
                in_force, _isr(answer, (dispute,)), answer, 2, _named([ON_CLAIM_1], in_force)
            )

            assert merge.withdrawn == () and merge.withdrawn_by_rule == (), dispute
            assert merge.merged is not None
            kept = next(c for c in merge.merged.claims if c.claim == RC4)
            assert kept.carried_contested_by == ["L1 (round 2)"], dispute

    def test_a_withdraw_line_still_withdraws(self) -> None:
        answer = _block(SLEEP) + "WITHDRAW CLAIM 1: the key is read from another routine.\n"

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2)

        assert merge.withdrawn == ((1, RC4, "the key is read from another routine."),)
        assert [n for n, _s in merge.carried] == [2]

    def test_a_dispute_line_read_as_a_withdrawal_is_still_a_line_not_read_exactly(self) -> None:
        dispute = "My claim 1 (0x405000) is withdrawn as stated."
        answer = _block(SLEEP) + f"DISPUTES:\n- {dispute}\n"

        merge = merge_revision(_isr(IN_FORCE), _isr(answer, (dispute,)), answer, 2)

        assert merge.withdrawn == () and merge.unread == 1


class TestAnOwnWithdrawalLetsTheRestatingBlockReplaceTheClaim:
    # The block drops the routine's address: without the line it is carried beside.
    AGAIN = "The config at 0x405000 is decrypted with RC4 key 'k3y' from 0x406000 (T1027)."

    def _merge(self, dispute: str) -> Any:
        answer = _block(self.AGAIN, technique="T1027") + _block(RUN_KEY, technique="T1547.001")
        in_force = _isr(IN_FORCE)
        return merge_revision(
            in_force, _isr(answer, (dispute,)), answer, 2, _named([ON_CLAIM_1], in_force)
        )

    def test_the_block_replaces_it_without_the_address_test(self) -> None:
        merge = self._merge("My claim 1 is withdrawn.")

        assert merge.replaced == (1, 2) and merge.beside == () and merge.withdrawn == ()

    def test_a_defence_of_it_keeps_the_address_test(self) -> None:
        merge = self._merge("My claim 1 stands: ev_0001 shows the routine at 0x401000.")

        assert 1 not in merge.replaced and [n for n, *_r in merge.beside] == [1]


# Each claim in force names a subject address, a helper address and a key of
# its own, in words no other claim uses.
_VERBS = ("decodes", "packs", "hashes", "maps", "loads", "signs", "parses", "seeds", "wipes")
_THINGS = ("table", "buffer", "list", "header", "stub", "store", "queue", "image", "record")
_REFERENCE_RE = re.compile(
    r"\bclaims?\s*#?\s*(\d+(?:\s*(?:,|&|\band\b|\bto\b|-|–|/|\+)\s*#?\d+)*)", re.IGNORECASE
)


def _referenced(disputes: tuple[str, ...]) -> set[int]:
    """Every claim number a dispute item writes after "claim", ranges spelled out."""
    out: set[int] = set()
    for item in disputes:
        for match in _REFERENCE_RE.finditer(item):
            for part in re.split(r"\s*(?:,|&|\band\b|/|\+)\s*", match.group(1), flags=re.I):
                ends = [int(n) for n in re.findall(r"\d+", part)]
                if len(ends) == 2 and ends[0] <= ends[1]:
                    out.update(range(ends[0], ends[1] + 1))
                elif ends:
                    out.add(ends[0])
    return out


def _sentence(index: int) -> str:
    base = 0x401000 + 0x100 * index
    return (
        f"0x{base:x} {_VERBS[index]} the {_THINGS[index]} at 0x{base + 0x10000:x} "
        f"with key k{index}x."
    )


def _again(index: int, kind: str) -> str:
    base = 0x401000 + 0x100 * index
    if kind == "same":
        return f"0x{base:x} {_VERBS[index]} the {_THINGS[index]} at 0x{base + 0x10000:x} again."
    return f"The {_THINGS[index]} at 0x{base + 0x10000:x} is handled with key k{index}x."


def _line(rng: random.Random, count: int) -> str:
    first = rng.randint(1, count)
    other = rng.randint(1, count)
    naming = rng.choice(
        (
            f"STATIC claim {first}",
            f"STATIC claims {min(first, other)} and {max(first, other)}",
            f"STATIC claims {min(first, other)}-{max(first, other)}",
        )
    )
    index = rng.randint(0, count - 1)
    said = rng.choice(
        (
            f"put the call at 0x{0x401000 + 0x100 * index:x}",
            f"say the {_VERBS[index]} the {_THINGS[index]} at",
            "overstate what the listing shows",
            f"cite ev_000{index + 1}",
        )
    )
    mark = BLOCKS if rng.random() < 0.7 else "[not blocking: a detail.]"
    return f"{STATIC} {naming} {said}. {mark}"


class TestNoClaimLeavesTheAnswerWithoutABlockALineOrTheLineRule:
    ITEMS = (*DEFENCES, *RESTATED_ELSEWHERE, *WITHDRAWALS)

    def test_over_random_revisions(self) -> None:
        rng = random.Random(6961)
        for case in range(400):
            count = rng.randint(3, 9)
            in_force_text = "".join(_block(_sentence(i), f"ev_000{i + 1}") for i in range(count))
            in_force = _isr(in_force_text, revision_round=1)
            answer = ""
            for i in range(count):
                kind = rng.choice(("same", "without", "skip", "skip"))
                if kind != "skip":
                    answer += _block(_again(i, kind), f"ev_000{i + 1}")
            answer += _block("0x409000 enumerates the running processes with a snapshot.")
            disputes = tuple(
                re.sub(r"(?<=claim )4\b", str(rng.randint(1, count)), rng.choice(self.ITEMS))
                for _n in range(rng.randint(0, 3))
            )
            if rng.random() < 0.2:
                answer += f"WITHDRAW CLAIM {rng.randint(1, count)}: the address is wrong.\n"
            lines = [_line(rng, count) for _n in range(rng.randint(0, 3))]
            named = (
                _named(lines, in_force)
                if rng.random() < 0.7
                else {rng.randint(1, count): [(1, rng.random() < 0.7)]}
            )
            unread = rng.choice((None, 0, 0, 1))

            merge = merge_revision(
                in_force, _isr(answer, disputes, 2), answer, 2, named, claims_unread=unread
            )

            withdraw_lines = {
                n
                for low, high, _r in read_withdrawals(answer).claims
                for n in range(int(low), int(high) + 1)
            }
            referenced = _referenced(disputes)
            carried = {n for n, _s in merge.carried}
            ruled = {n for n, _s, _r in merge.withdrawn_by_rule}
            stands = [c.claim for c in merge.merged.claims] if merge.merged is not None else []
            for number in range(1, count + 1):
                where = f"case {case}, claim {number}: {disputes} {lines} {named}"
                if number in carried:
                    assert _sentence(number - 1) in stands, where
                elif number in merge.replaced:
                    continue
                elif number in {n for n, _s, _r in merge.withdrawn}:
                    assert number in withdraw_lines, where
                else:
                    assert number in ruled, where
                    assert number not in referenced, where


class TestAWithdrawLineWithANoteAfterTheNumber:
    @staticmethod
    def _round_notes() -> list[str]:
        """Each round note the claim list writes, as the claim list writes it."""
        from malspark.schemas.isr_models import (
            ClaimEvidence,
            round_note_on_line,
            written_round_note,
        )

        written = ClaimEvidence(claim="c", evidence_ref="e", confidence=0.5)
        unchanged = ClaimEvidence(claim="c", evidence_ref="e", confidence=0.5)
        unchanged.carried_since_round = 2
        notes = [
            round_note_on_line(written_round_note(written, 1, 2)),
            round_note_on_line(written_round_note(unchanged, 2, 2)),
        ]
        assert notes == ["(written in round 1)", "(unchanged since round 1)"]
        return notes

    def test_each_round_note_the_claim_list_writes_is_read_through(self) -> None:
        for note in self._round_notes():
            for line in (
                f"WITHDRAW CLAIM 1 {note}: the key is read elsewhere.",
                f"WITHDRAW CLAIM 1 {note} - the key is read elsewhere.",
                f"WITHDRAW CLAIM 1 {note}",
            ):
                answer = _block(SLEEP) + line + "\n"

                merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2)

                assert [n for n, _s, _r in merge.withdrawn] == [1], line
                assert merge.unread == 0, line

    def test_the_shape_decides_not_the_rounds_value(self) -> None:
        for line in (
            "WITHDRAW CLAIM 1 (written in round 97): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (unchanged since round 0): the key is read elsewhere.",
            "withdraw claim 1 (unchanged since round 0): the key is read elsewhere.",
        ):
            assert read_withdrawals(line + "\n").claims == (
                ("1", "1", "the key is read elsewhere."),
            ), line

    def test_any_other_bracket_leaves_the_line_read_as_before(self) -> None:
        # Each line withdraws nothing on the platform's earlier reading and is
        # one doubt: a bracket that qualifies, conditions, negates, points or
        # widens the line is no note of the platform's own.
        for line in (
            "WITHDRAW CLAIM 1 (withdrawn in part): only the port.",
            "WITHDRAW CLAIM 1 (if L4 holds): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (no, keep it)",
            "WITHDRAW CLAIM 1 (see L4)",
            "WITHDRAW CLAIM 1 (and 2): the key is read elsewhere.",
            "WITHDRAW CLAIMS 1-2 (both): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 [written in round 1]: the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (written in round 1)(see L4): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (written in round one): the key is read elsewhere.",
            # The note's shape is the writer's exactly: its case, a space and
            # ASCII digits, one note.
            "WITHDRAW CLAIM 1 (written in round): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (written in round1): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (written in round 1)(written in round 2): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (UNCHANGED SINCE ROUND 2): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (Unchanged Since Round 2): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (written in Round 1): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (written in round \u0661): the key is read elsewhere.",
            "WITHDRAW CLAIM 1 (written in round \uff11): the key is read elsewhere.",
        ):
            read = read_withdrawals(line + "\n")
            assert read.claims == (), line
            assert read.unread == 1, line

            answer = _block(SLEEP) + line + "\n"
            merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2)

            assert merge.withdrawn == (), line
            assert merge.unread == 1, line

    def test_a_note_costs_its_length(self) -> None:
        from tests.linear_cost import assert_scales

        def build(size: int) -> Any:
            text = "WITHDRAW CLAIM 1 " + "(x " * size + "\n"
            text += "WITHDRAW CLAIM 1 (written in round " + "1" * size + "\n"
            text += "WITHDRAW CLAIM 1 " + "(written in round 1)" * size + ": x\n"
            text += "WITHDRAW CLAIM 1 (note) x\n" * size
            text += "WITHDRAW CLAIM 1 (unchanged since round 1): x\n" * size
            return lambda: read_withdrawals(text)

        assert_scales(build, 20_000)
