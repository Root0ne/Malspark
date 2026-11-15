"""A closing ``CONTRADICTIONS:`` remark after the block leaves the block read.

The mediator's final block is the one read: a block drafted above it and then
argued away is not its word. A last label whose one line is a remark written
on the label line itself, holding no field of the block's lines, is no block
of its own when it points at the block above with a pointing word ("listed
above") and holds no word of an end, no negation and no zero anywhere: the
block above it is read when a line of it holds the fields.

Every name and sentence here is made up for the test.
"""

from __future__ import annotations

from malspark.agents.judge_agent import read_contradictions_block

LINES = [
    "[analysts: ALL_TOOLS_STATIC_R2 ANALYST] Claim 17 says the mutex name is not recovered; "
    "ev_0109 gives the third argument. [blocking: ev_0109 shows the argument]",
    "[analysts: ALL_TOOLS_STATIC_R2 ANALYST] Claim 24 says no data-flow hop reaches the key "
    "routine; ev_0057 shows it. [blocking: the hop is in ev_0057]",
    "[analysts: DYNAMIC ANALYST] Claims 23 and 37 hold the launches the sandbox's own; claim 43 "
    "leaves their origin open. [blocking: the analyst contradicts itself]",
]
REMARK = "CONTRADICTIONS: standing blocking lines are listed above."


def _answer(*parts: str) -> str:
    return "\n".join(["The reasoning.", "", *parts, "", "agreement_confidence: 0.80"])


class TestARemarkLabel:
    def test_the_block_above_it_is_read(self) -> None:
        reading = read_contradictions_block(_answer("CONTRADICTIONS:", *LINES, REMARK))

        assert reading.items == LINES and not reading.mixed and not reading.ambiguous

    def test_with_a_blank_line_before_it(self) -> None:
        reading = read_contradictions_block(_answer("CONTRADICTIONS:", *LINES, "", REMARK))

        assert reading.items == LINES

    def test_after_a_block_with_no_field_the_remark_is_read_as_written(self) -> None:
        plain = "Claim 4 of the static analyst and claim 9 of the reverser differ."
        reading = read_contradictions_block(_answer("CONTRADICTIONS:", plain, REMARK))

        assert reading.items == [REMARK.removeprefix("CONTRADICTIONS: ")]


class TestTheLastBlockStillCounts:
    def test_a_draft_above_a_final_none_is_not_read(self) -> None:
        answer = _answer(
            "CONTRADICTIONS:", *LINES, "", "On reading ev_0109 again:", "", "CONTRADICTIONS: NONE"
        )

        assert read_contradictions_block(answer).items == []

    def test_a_draft_above_a_final_line_with_its_fields_is_not_read(self) -> None:
        answer = _answer("CONTRADICTIONS:", *LINES, "", f"CONTRADICTIONS: {LINES[2]}")

        assert read_contradictions_block(answer).items == [LINES[2]]

    def test_a_final_block_of_its_own_lines_is_read_alone(self) -> None:
        answer = _answer("CONTRADICTIONS:", *LINES, "", "CONTRADICTIONS:", LINES[0])

        assert read_contradictions_block(answer).items == [LINES[0]]


class TestARemarkAdoptsTheBlockAboveOnlyRightAfterIt:
    def test_prose_between_the_block_and_the_remark_leaves_the_remark_read(self) -> None:
        answer = _answer("CONTRADICTIONS:", *LINES, "", "On reading ev_0109 again:", "", REMARK)

        assert read_contradictions_block(answer).items == [REMARK.removeprefix("CONTRADICTIONS: ")]

    def test_the_stored_layout_with_a_blank_line_between_is_read_as_the_block(self) -> None:
        answer = _answer("The reasoning ends.", "", "CONTRADICTIONS:", *LINES, "", "", REMARK)

        assert read_contradictions_block(answer).items == LINES


class TestARemarkThatSaysNoneStandsNeverBringsADraftBack:
    def test_each_wording_of_none(self) -> None:
        for remark in (
            "nothing stands",
            "no contradiction stands after the revisions",
            "none of the lines above survives the revisions",
            "all of the above were resolved by the revisions",
            "every line above is settled",
        ):
            answer = _answer("CONTRADICTIONS:", *LINES, "", f"CONTRADICTIONS: {remark}")

            assert read_contradictions_block(answer).items != LINES, remark

    def test_a_draft_then_a_final_none_reads_none(self) -> None:
        answer = _answer("CONTRADICTIONS:", *LINES, "", "CONTRADICTIONS: NONE")

        assert read_contradictions_block(answer).items == []


class TestAFinalOneLineBlockThatNamesAClaimOrAnEntryIsTheBlock:
    def test_without_a_field(self) -> None:
        for line in (
            "DYNAMIC claim 2 contradicts the sandbox's process list.",
            "The process list in ev_0005 contradicts the dynamic analyst.",
            "ev_0005 contradicts the lines listed above.",
        ):
            answer = _answer("CONTRADICTIONS:", *LINES, "", f"CONTRADICTIONS: {line}")

            assert read_contradictions_block(answer).items == [line], line


class TestARemarkAdoptsTheBlockOnlyWhereItPointsAtItAndEndsNothing:
    # Each remark ends the block, negates, counts zero or points nowhere.
    def test_none_of_these_adopts_the_block(self) -> None:
        for remark in (
            "the line above is resolved by the revision.",
            "The above no longer stand after the revisions.",
            "resolved, see the revisions.",
            "after review, zero remain.",
            "0 open.",
            "STATIC withdrew it, so the line is settled.",
            "standing blocking lines are listed above; the other differences do not hold up "
            "agreement.",
            "the standing lines are the ones the reasoning gives",
        ):
            answer = _answer("CONTRADICTIONS:", *LINES, "", f"CONTRADICTIONS: {remark}")

            assert read_contradictions_block(answer).items == [remark], remark

    def test_each_pointing_word_adopts_it(self) -> None:
        for remark in (
            "see above.",
            "the standing lines are listed above",
            "as in the preceding block",
            "the foregoing lines stand",
        ):
            answer = _answer("CONTRADICTIONS:", *LINES, "", f"CONTRADICTIONS: {remark}")

            assert read_contradictions_block(answer).items == LINES, remark
