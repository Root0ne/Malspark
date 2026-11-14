"""A closing ``CONTRADICTIONS:`` remark after the block leaves the block read.

The mediator's final block is the one read: a block drafted above it and then
argued away is not its word. A last label whose one line is a remark written
on the label line itself, holding no field of the block's lines, is no block
of its own: the block above it is read when a line of it holds the fields.

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
REMARK = (
    "CONTRADICTIONS: standing blocking lines are listed above; the other differences do not "
    "hold up agreement."
)


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
