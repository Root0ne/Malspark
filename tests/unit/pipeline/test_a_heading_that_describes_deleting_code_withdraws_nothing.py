"""A claim heading that describes deleting code withdraws nothing; one that withdraws is a doubt.

A retry's claim heading may describe what code does with a word of deleting,
dropping or removing ("deletes the file") and cite another claim in another
sentence ("Claim 1 states the path"). On a heading line the text after the
heading is read a sentence at a time; a sentence ends at a period, "!" or "?"
that white space or the end of the line follows. A withdrawing word is a
withdrawal the reader cannot read, a doubt, where its own sentence writes a
claim number or the sentence right before it does. A bracket, a semicolon and a
period inside a token ("payload.exe", "0.8", "T1070.004") end nothing, so a
withdrawal written across them is a doubt. Withdraw or retract anywhere in the
sentence, a withdrawing word in the heading's note and a bare "Removed" opening
the sentence are doubts, a line that is no heading is read whole, and the
``WITHDRAW CLAIM`` lines are read by their form.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.retry_merge import merge_retry, read_withdrawals
from malspark.schemas.isr_models import AgentISR

# The two heading forms a claim's sentence follows: the delimiter, and a note
# ended by a dot.
HEADINGS = ("CLAIM {number}: ", "**CLAIM {number}** (new). ")


def _block(sentence: str, number: int, technique: str = "NONE", heading: str = HEADINGS[0]) -> str:
    return (
        f"{heading.format(number=number)}{sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\n"
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
    # The deleting sentence comes before the sentence that cites a claim.
    "0x401000 deletes the file. Claim 1 states the path.",
    "0x406000 copies the module and writes it through 0x406acc; the source is not deleted). "
    "It launches the copy as claim 1 states.",
    "0x407000 builds the second URL with its last five characters removed. The host is "
    "the one of claim 1.",
    # The deleting sentence comes two sentences after the one that cites a claim.
    "Claim 1 states the path. 0x401000 opens it. 0x405a24 sets delete-on-close.",
    "Claim 1 names the mutex! 0x401000 opens it? 0x401a10 then drops the handle.",
)


@pytest.mark.parametrize("heading", HEADINGS)
@pytest.mark.parametrize("sentence", DESCRIPTIONS)
def test_a_description_with_a_claim_cited_in_another_sentence_is_no_doubt(
    sentence: str, heading: str
) -> None:
    answer = _block(FIXED, 2, heading=heading) + _block(sentence, 5, heading=heading)

    merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

    assert read_withdrawals(answer).unread == 0, sentence
    assert merge.merged is not None, (sentence, merge.why)


WITHDRAWALS = (
    # A period inside a token ends no sentence.
    "Claim 1 about payload.exe is removed.",
    "Claim 1, at confidence 0.8, is dropped.",
    "I drop the T1070.004 reading of claim 1.",
    # A bracket ends no sentence.
    "Claim 1 (T1070.004 reading) is removed.",
    "The mutex claim (claim 1) is dropped.",
    "claim 1 (the mutex reading): dropped.",
    "This replaces claim 1 (dropped).",
    "I drop (claim 1) entirely.",
    "Claim 1 (dropped)",
    "Claim 1 [deleted]",
    "The mutex (claim 1 deleted) is not created here.",
    # A semicolon ends no sentence.
    "Claim 1 was wrong; I remove it.",
    "0x408000 runs once; claim 1 is removed as unsupported.",
    # The word in the sentence right after the one that writes the number.
    "Claim 1. Dropped as unsupported.",
    "Claim 1 was wrong. I remove it.",
    "This replaces claim 1. It is dropped.",
    # The word in the sentence that writes the number.
    "This replaces claim 1, which is dropped.",
    "Drop claim 1, it repeats.",
    # Word and number in one sentence cannot be told from a description, so
    # these are doubts too.
    "Neither 0x403000 nor 0x404000 has a file open-for-write, delete or encryption call; "
    "the write path is the one claim 1 names.",
    "Routine 0x405000 releases the mutex and deletes the original (0x405a24, claim 1).",
    "The sandbox report shows no dropped files (raw report, see claim 1) for this sample.",
    "The sandbox dropped no files [raw report, as claim 1 cites] in this run.",
    # Withdraw or retract anywhere in the sentence.
    "The mutex reading is withdrawn; 0x401000 creates nothing (see claim 1).",
    "I retract the earlier reading. 0x401000 is the entry point.",
    # A bare "Removed" opening the sentence.
    "Removed as unsupported; 0x401000 is not in the ledger.",
)


@pytest.mark.parametrize("heading", HEADINGS)
@pytest.mark.parametrize("sentence", WITHDRAWALS)
def test_a_heading_that_withdraws_is_a_doubt(sentence: str, heading: str) -> None:
    answer = _block(FIXED, 2, heading=heading) + _block(sentence, 5, heading=heading)

    merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

    assert read_withdrawals(answer).unread == 1, sentence
    assert merge.merged is None, sentence
    assert merge.why == "a line of the retry that withdraws could not be read exactly"


def test_a_new_claim_that_drops_an_earlier_one_in_a_bracket_is_refused() -> None:
    answer = _block(FIXED, 2) + _block(
        "The loader, not 0x401000, creates the mutex Global\\qx7; this replaces claim 1 (dropped).",
        5,
    )

    merge = merge_retry(_isr(FIRST), _isr(answer), answer, asked=[1])

    assert merge.merged is None
    assert merge.why == "a line of the retry that withdraws could not be read exactly"


def test_a_heading_note_with_a_deleting_word_is_a_doubt() -> None:
    answer = (
        "CLAIM 5 (copy, self-delete and relaunch, code-level): 0x409000 copies the module.\n"
        "EVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    )

    assert read_withdrawals(answer).unread == 1


def test_a_line_that_is_no_heading_is_read_whole() -> None:
    answer = "The decoder had dropped the name. Claims 1 and 2 stand as written.\n"

    assert read_withdrawals(answer).unread == 1


def test_the_declared_withdraw_lines_are_read_by_their_form() -> None:
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
