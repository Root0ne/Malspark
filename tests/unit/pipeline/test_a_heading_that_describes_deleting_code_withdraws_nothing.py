"""A claim heading that describes deleting code and cites a claim elsewhere withdraws nothing.

A retry's claim heading may describe what code does with a word of deleting,
dropping or removing ("sets delete-on-close") and cite another claim further
on ("as claim 15 states"). The withdraw reader took any such word anywhere on
the heading line, beside any claim number, for a withdrawal it could not read,
and the retry was asked for again as a whole answer. On a heading line the
word is a withdrawal only in the clause that writes the claim number ("This
replaces claim 2, which is dropped"): a sentence end, a semicolon or a bracket
ends a clause. Withdraw or retract anywhere in the sentence, a withdrawing word
in the heading's note and a bare "Removed" opening the sentence are doubts as
before, and the ``WITHDRAW CLAIM`` lines are read as before.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.retry_merge import merge_retry, read_withdrawals
from malspark.schemas.isr_models import AgentISR


def _block(sentence: str, number: int, technique: str = "NONE") -> str:
    return (
        f"CLAIM {number}: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\n"
        f"TECHNIQUE: {technique}\n---\n"
    )


def _isr(text: str) -> AgentISR:
    read = read_claim_blocks(text)
    isr = AgentISR(agent_id="static", domain="static", claims=read.claims)
    isr.note_parse(
        blocks_without_confidence=read.without_confidence,
        confidence_unreadable=read.confidence_unreadable,
    )
    isr.note_answer_text(text)
    return isr


MUTEX = "0x401000 creates the mutex Global\\qx7 before anything else."
BEACON = "0x402000 beacons every 600 seconds to the configured host."
FIRST = _block(MUTEX, 1) + _block(BEACON, 2)
FIXED = "0x402000 beacons every 600 seconds over HTTP to the configured host."

DESCRIPTIONS = (
    "Neither 0x403000 nor 0x404000 has a file open-for-write, delete or encryption call; "
    "the write path is the one claim 1 names.",
    "Routine 0x405000 releases the mutex and deletes the original (0x405a24, claim 1).",
    "0x406000 copies the module and writes it through 0x406acc; the source is not deleted). "
    "It launches the copy as claim 1 states.",
    "The sandbox report shows no dropped files (raw report, see claim 1) for this sample.",
    "0x407000 builds the second URL with its last five characters removed. The host is "
    "the one of claim 1.",
    "The sandbox dropped no files [raw report, as claim 1 cites] in this run.",
)


@pytest.mark.parametrize("sentence", DESCRIPTIONS)
def test_a_description_with_a_claim_cited_in_another_clause_is_no_doubt(sentence: str) -> None:
    answer = _block(FIXED, 2) + _block(sentence, 5)

    merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

    assert read_withdrawals(answer).unread == 0, sentence
    assert merge.merged is not None, (sentence, merge.why)


@pytest.mark.parametrize(
    "sentence",
    [
        # A withdrawing word in the clause that writes another claim's number.
        "This replaces claim 1, which is dropped.",
        "Drop claim 1, it repeats.",
        "0x408000 runs once; claim 1 is removed as unsupported.",
        "The mutex (claim 1 deleted) is not created here.",
        # Withdraw or retract anywhere in the sentence.
        "The mutex reading is withdrawn; 0x401000 creates nothing (see claim 1).",
        "I retract the earlier reading. 0x401000 is the entry point.",
        # A bare "Removed" opening the sentence.
        "Removed as unsupported; 0x401000 is not in the ledger.",
    ],
)
def test_a_heading_that_withdraws_is_a_doubt_as_before(sentence: str) -> None:
    answer = _block(FIXED, 2) + _block(sentence, 5)

    merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

    assert read_withdrawals(answer).unread == 1, sentence
    assert merge.merged is None, sentence
    assert merge.why == "a line of the retry that withdraws could not be read exactly"


def test_a_heading_note_with_a_deleting_word_is_a_doubt_as_before() -> None:
    answer = (
        "CLAIM 5 (copy, self-delete and relaunch, code-level): 0x409000 copies the module.\n"
        "EVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    )

    assert read_withdrawals(answer).unread == 1


def test_a_line_that_is_no_heading_is_read_whole_as_before() -> None:
    answer = "The decoder had dropped the name. Claims 1 and 2 stand as written.\n"

    assert read_withdrawals(answer).unread == 1


def test_the_declared_withdraw_lines_are_read_as_before() -> None:
    read = read_withdrawals(
        "WITHDRAW CLAIM 1: the mutex is created by the loader, not the sample.\n"
        "WITHDRAW CLAIMS 3-4 and 7: repeated.\n"
        'WITHDRAW FINDING "Deletes its own file": no entry holds it.\n'
    )

    assert read.claims == (
        ("1", "1", "the mutex is created by the loader, not the sample."),
        ("3", "4", "repeated."),
        ("7", "7", "repeated."),
    )
    assert [f[1] for f in read.findings] == ["Deletes its own file"]
    assert read.unread == 0
