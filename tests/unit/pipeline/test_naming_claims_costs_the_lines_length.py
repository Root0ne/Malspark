"""Reading which claims the lines of a mediation name costs the lines' length.

Many lines may name the same claims: each line's rows are kept once per
claim without searching the rows earlier lines left there.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.pipeline.debate_facts import claims_named_by_lines
from tests.linear_cost import assert_scales


def test_many_lines_naming_the_same_claims() -> None:
    def build(size: int) -> Any:
        refs = ", ".join(str(n) for n in range(1, 21))
        lines = [
            f"[analysts: STATIC ANALYST] STATIC claims {refs} and claim 3 contradict ev_0002 at "
            f"0x{0x401000 + 16 * i:x}. [blocking: x]"
            for i in range(size)
        ]
        return lambda: claims_named_by_lines(lines, ["static"])

    assert_scales(build, 200)


def test_each_line_is_one_row_of_a_claim_it_names_twice() -> None:
    lines = [
        "[analysts: STATIC ANALYST] STATIC claims 3 and 3 differ. [blocking: x]",
        "[analysts: STATIC ANALYST] STATIC claim 3 again. [not blocking: y]",
    ]

    assert claims_named_by_lines(lines, ["static"])["static"][3] == [(1, True), (2, False)]
