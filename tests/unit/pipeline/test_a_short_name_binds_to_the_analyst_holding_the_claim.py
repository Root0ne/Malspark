"""A short name before "claim N" binds to the analyst it can mean.

"STATIC" names the analyst whose name it is, ``static``, even beside
``all_tools_static_r2``. On a line whose field names only analysts other than
``static``, while ``static``'s answer in force holds no claim of that number,
the form is read for the one analyst of the field it fits whose answer holds
the claim. A form that fits several analysts and equals none names no one.

Every name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.pipeline.debate_facts import claims_named_by_lines
from tests.linear_cost import assert_scales

TEAM = ["static", "all_tools_static_r2", "all_tools_qu1cksc0pe", "dynamic"]


def _owners(**counts: int) -> dict[str, dict[int, frozenset[str]]]:
    return {name: {n: frozenset() for n in range(1, count + 1)} for name, count in counts.items()}


def _rows(
    named: dict[str, dict[int, list[tuple[int, bool]]]],
) -> dict[str, dict[int, list[tuple[int, bool]]]]:
    return {
        name: {n: list(lines) for n, lines in claims.items()}
        for name, claims in named.items()
        if claims
    }


R2_LINE = (
    "[analysts: ALL_TOOLS_STATIC_R2 ANALYST] STATIC claim 17 describes the pipe pass as a "
    "0x200-byte read. ev_0133 shows the count capped at 0x2800. [blocking: the read size "
    "misstates ev_0133]"
)


class TestTheFieldsAnalystHoldsTheClaim:
    def test_the_form_is_read_for_it(self) -> None:
        owners = _owners(static=16, all_tools_static_r2=40, all_tools_qu1cksc0pe=30, dynamic=20)

        named = claims_named_by_lines([R2_LINE], TEAM, owners)

        assert _rows(named) == {"all_tools_static_r2": {17: [(1, True)]}}

    def test_where_static_holds_the_claim_it_is_static_s(self) -> None:
        owners = _owners(static=20, all_tools_static_r2=40, all_tools_qu1cksc0pe=30, dynamic=20)

        named = claims_named_by_lines([R2_LINE], TEAM, owners)

        # Static's claim, on a line whose field does not name it: no question
        # put to any analyst.
        assert _rows(named) == {}

    def test_a_peer_claim_static_holds_stays_static_s(self) -> None:
        line = (
            "[analysts: ALL_TOOLS_STATIC_R2 ANALYST, DYNAMIC ANALYST] Static claim 12 and dynamic "
            "claim 3 tag T1055 for the write API set. [not blocking: only the tag differs]"
        )
        owners = _owners(static=20, all_tools_static_r2=40, all_tools_qu1cksc0pe=30, dynamic=20)

        named = claims_named_by_lines([line], TEAM, owners)

        assert _rows(named) == {"dynamic": {3: [(1, False)]}}

    def test_without_the_answers_in_force_the_form_is_static_s(self) -> None:
        assert _rows(claims_named_by_lines([R2_LINE], TEAM)) == {}

    def test_a_field_analyst_without_the_claim_gets_nothing(self) -> None:
        owners = _owners(static=16, all_tools_static_r2=10, all_tools_qu1cksc0pe=30, dynamic=20)

        assert _rows(claims_named_by_lines([R2_LINE], TEAM, owners)) == {}


class TestAFormThatFitsSeveral:
    def test_names_no_one(self) -> None:
        line = (
            "[analysts: ALL_TOOLS_STATIC_R2 ANALYST, ALL_TOOLS_QU1CKSC0PE ANALYST] TOOLS claim 5 "
            "says the slot is TerminateProcess. [blocking: the slot is not mapped]"
        )
        owners = _owners(static=16, all_tools_static_r2=40, all_tools_qu1cksc0pe=30, dynamic=20)

        named = claims_named_by_lines([line], TEAM, owners)

        assert _rows(named) == {}
        assert [u.claims for u in named.references.unplaced] == ["claim 5"]


class TestALineOfManyReferencesCostsItsLength:
    def test_a_line_of_thousands_of_short_forms(self) -> None:
        owners = _owners(static=4, all_tools_static_r2=30, all_tools_qu1cksc0pe=30, dynamic=20)

        def build(size: int) -> Any:
            refs = " ".join(f"STATIC claim {17 + i % 3}," for i in range(size))
            line = f"[analysts: ALL_TOOLS_STATIC_R2 ANALYST] {refs} [blocking: the reads differ]"
            return lambda: claims_named_by_lines([line], TEAM, owners)

        assert_scales(build, 1_000)
