"""A branch that ends a decompiled function with a constant joins the decompiled question.

A reverser read a routine whose checks each handed back ``-1`` when they
failed, named the routine in its claims, and said what none of the checks
tested. The branches are read off the analyst's own listings by their shape:

- an exit is a ``return`` of a constant, or a constant given to the variable
  the function returns, inside a condition;
- its terms come from the innermost condition alone: the functions it calls,
  the slots it calls through (or the function index resolved), its constants
  of 10 or more, and for each of its variables the calls of the nearest
  statement before it that mentioned it;
- a listing with a label or a ``goto`` says nothing, and so does an exit with
  no term.

An exit is covered when one claim names its function and one of its terms.
The ones left join the decompiled-functions question, at most 8 listed,
ranked, but only in a validation turn that is asked anyway: they never open
one. They are a question, not a finding: what is recorded of the code is the
functions alone, and the loop's record notes the branches the kept answer
leaves.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import json
import re
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from malspark.agents.base_agent import BaseAnalyst
from malspark.core.undeclared_tools import DeclaredLabels, auto_name_pattern
from malspark.pipeline import exit_branches
from malspark.pipeline.exit_branches import (
    EXITS_LISTED,
    exit_line,
    listing_exits,
    read_listings,
    resolved_slots,
    uncovered_exits,
)
from malspark.pipeline.exit_branches import (
    exit_branches as read_exits,
)
from malspark.pipeline.validation import (
    CLAIM_WITHOUT_CONFIDENCE_CODE,
    DECOMPILED_NOT_DESCRIBED_CODE,
    Violation,
    decompiled_functions,
    decompiled_not_described_violation,
    exit_branches_left_out,
    with_exit_branches,
)
from malspark.schemas.evidence import LedgerEntry, not_shown_record
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

BASE = 0x140000000
GATE = BASE + 0x2A10
CHECK = BASE + 0x51C0
HELPER = BASE + 0x6D30
OTHER = BASE + 0x7E40
SLOT_A = BASE + 0x9B10
SLOT_B = BASE + 0x9B28
SLOT_C = BASE + 0x9B40
SLOTS = {SLOT_A: "QueryAlpha", SLOT_B: "OpenBeta", SLOT_C: "ReadGamma"}

# A gate routine of the shape a decompiler writes: one variable returned, set
# to -1 by every check that fails.
GATE_LISTING = f"""
int FUN_{GATE:x}(void)
{{
  int iVar2;
  undefined8 uVar6;
  int local_40 [2];

  uVar6 = FUN_{HELPER:x}();
  if ((int)uVar6 == 0) {{
    iVar2 = -1;
  }}
  else {{
    local_40[0] = 0;
    (*_DAT_{SLOT_A:x})(uVar6,local_40);
    if (local_40[0] == 0) {{
      uVar6 = FUN_{CHECK:x}();
      if ((int)uVar6 == 0) {{
        iVar2 = -1;
      }}
      else {{
        DAT_{BASE + 0x9F00:x} = (*_DAT_{SLOT_B:x})(0,0);
        if ((DAT_{BASE + 0x9F00:x} == 0) || (iVar2 = (*_DAT_{SLOT_C:x})(), iVar2 == 0x3c)) {{
          iVar2 = -1;
        }}
        else {{
          iVar2 = 0;
        }}
      }}
    }}
    else {{
      iVar2 = -1;
    }}
  }}
  return iVar2;
}}
"""


def _entry(entry_id: str, address: int, listing: str, tool: str = "decompile_function") -> Any:
    return LedgerEntry(id=entry_id, tool=tool, args={"address": hex(address)}, output=listing)


def _exits(*entries: Any, slots: dict[int, str] | None = None) -> list[Any]:
    return read_exits(entries, SLOTS if slots is None else slots)


def _claim(text: str, evidence: str = "[ev_0003]") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=evidence, confidence=0.8)


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="reverser", domain="static", claims=list(claims))


def _terms(found: Any) -> list[tuple[int, tuple[int, ...], tuple[int, ...], tuple[int, ...]]]:
    return [(value, callees, slots, constants) for value, _w, callees, slots, constants in found]


def _function(body: str, address: int = OTHER) -> str:
    return f"int FUN_{address:x}(int param_1)\n{{\n{body}\n}}\n"


class TestTheReader:
    def test_a_constant_returned_on_a_condition_is_an_exit_with_its_condition_s_terms(
        self,
    ) -> None:
        found = listing_exits(
            _function(
                f"  if (FUN_{HELPER:x}(param_1) == 0x2c) {{\n    return -1;\n  }}\n  return 0;"
            )
        )

        assert _terms(found) == [(-1, (HELPER,), (), (0x2C,))]

    def test_a_constant_given_to_the_returned_variable_is_an_exit(self) -> None:
        found = listing_exits(
            _function(
                f"  int r;\n  r = 1;\n  if (FUN_{HELPER:x}() == 0) {{\n    r = 0x7f;\n  }}\n"
                "  return r;"
            )
        )

        assert [(value, written) for value, written, *_ in found] == [(0x7F, "0x7f")]

    def test_the_innermost_condition_alone_gives_the_terms(self) -> None:
        found = listing_exits(
            _function(
                f"  if (FUN_{HELPER:x}() == 0) {{\n"
                f"    if (FUN_{CHECK:x}() == 0) {{\n      return 0x10;\n    }}\n  }}\n  return 0;"
            )
        )

        assert _terms(found) == [(0x10, (CHECK,), (), ())]

    def test_a_variable_in_the_condition_brings_the_calls_of_the_statement_that_wrote_it(
        self,
    ) -> None:
        found = listing_exits(GATE_LISTING, SLOTS)

        assert (-1, (HELPER,), (), ()) in _terms(found)
        assert (-1, (), (SLOT_A,), ()) in _terms(found)

    def test_a_variable_assigned_inside_the_condition_takes_no_hop(self) -> None:
        found = listing_exits(
            _function(
                f"  int v;\n  v = FUN_{HELPER:x}();\n"
                f"  if ((v = FUN_{CHECK:x}(), v == 0x40)) {{\n    return -1;\n  }}\n  return v;"
            )
        )

        assert _terms(found) == [(-1, (CHECK,), (), (0x40,))]

    def test_the_gate_routine_s_three_gates_are_read_with_their_terms(self) -> None:
        found = listing_exits(GATE_LISTING, SLOTS)

        assert sorted(_terms(found)) == sorted(
            [
                (-1, (HELPER,), (), ()),
                (-1, (CHECK,), (), ()),
                (-1, (), (SLOT_B, SLOT_C), (0x3C,)),
                (0, (), (SLOT_B, SLOT_C), (0x3C,)),
                (-1, (), (SLOT_A,), ()),
            ]
        )

    def test_a_constant_below_ten_is_no_term(self) -> None:
        found = listing_exits(
            _function("  if (param_1 == 9) {\n    return 0x20;\n  }\n  return 0;")
        )

        assert found == []

    def test_an_exit_without_a_term_says_nothing(self) -> None:
        found = listing_exits(
            _function("  if (param_1 == 0) {\n    return 0x20;\n  }\n  return 1;")
        )

        assert found == []

    def test_a_listing_with_a_label_says_nothing(self) -> None:
        goto = (
            f"int fcn.{OTHER:x} (int rcx) {{\n  if (!rcx) goto loc_0x{OTHER + 4:x}\n"
            f"  rax = fcn.{HELPER:x} ();\n  if (rax == 0x20) return 0x30;\n"
            f"loc_0x{OTHER + 4:x}:\n  return rax;\n}}\n"
        )
        labelled = _function(
            f"  if (FUN_{HELPER:x}() == 0x20) {{\n    return 0x30;\n  }}\nLAB_{OTHER + 8:x}:\n"
            "  return 0;"
        )

        assert listing_exits(goto) is None
        assert listing_exits(labelled) is None
        assert listing_exits(json.dumps({"rows": [1, 2]})) is None
        assert listing_exits("The routine returns early when the check fails.") is None

    def test_an_unguarded_return_is_no_exit_branch(self) -> None:
        found = listing_exits(_function(f"  FUN_{HELPER:x}(0x30);\n  return 0x20;"))

        assert found == []

    def test_a_goto_alone_says_nothing(self) -> None:
        found = listing_exits(
            _function(
                f"  if (FUN_{HELPER:x}() == 0x20) {{\n    goto fail;\n  }}\n"
                f"  if (FUN_{CHECK:x}() == 0x30) {{\n    return -1;\n  }}\n  return 0;"
            )
        )

        assert found is None

    def test_a_label_in_a_comment_or_outside_the_body_silences_nothing(self) -> None:
        body = (
            "  /* WARNING:\nnote:\n  */\n"
            f"  if (FUN_{HELPER:x}() == 0x20) {{\n    return 0x30;\n  }}\n  return 0;"
        )
        listing = "Note:\n" + _function(body) + "after:\n"

        assert _terms(listing_exits(listing)) == [(0x30, (HELPER,), (), (0x20,))]

    def test_a_constant_of_ten_is_a_term_and_a_negative_one_keeps_its_sign(self) -> None:
        ten = listing_exits(_function("  if (param_1 == 10) {\n    return 0x20;\n  }\n  return 0;"))
        negative = listing_exits(
            _function("  if (param_1 == -0x20) {\n    return 5;\n  }\n  return 0;")
        )

        assert _terms(ten) == [(0x20, (), (), (10,))]
        assert _terms(negative) == [(5, (), (), (-0x20,))]

    def test_a_write_in_another_branch_does_not_reach_a_later_condition(self) -> None:
        found = listing_exits(
            _function(
                f"  int v;\n  v = FUN_{HELPER:x}();\n"
                f"  if (param_1 == 0) {{\n    v = FUN_{CHECK:x}();\n  }}\n"
                "  else {\n    if (v == 0) {\n      return -1;\n    }\n  }\n  return 0;"
            )
        )

        assert _terms(found) == [(-1, (HELPER,), (), ())]

    def test_a_constant_given_to_a_variable_never_returned_is_no_exit(self) -> None:
        found = listing_exits(
            _function(
                f"  int r;\n  int s;\n  r = 0;\n  if (FUN_{HELPER:x}() == 0) {{\n"
                "    s = 0x7f;\n  }\n  return r;"
            )
        )

        assert found == []

    def test_a_slot_the_index_resolved_is_a_term_without_a_call_through_it(self) -> None:
        listing = _function(f"  if (_DAT_{SLOT_A:x} == 0) {{\n    return -1;\n  }}\n  return 0;")

        assert _terms(listing_exits(listing, SLOTS)) == [(-1, (), (SLOT_A,), ())]
        assert listing_exits(listing, {}) == []

    def test_a_cast_s_type_is_no_variable(self) -> None:
        found = listing_exits(
            _function(
                f"  undefined8 local_10 = FUN_{HELPER:x}();\n"
                "  if ((undefined8)param_1 == 0) {\n    return -1;\n  }\n  return 0;"
            )
        )

        assert found == []

    def test_no_tool_name_or_api_name_decides(self) -> None:
        # A tool the platform has never heard of, a server that declares its
        # own prefixes, and a slot the index resolved to a name of no API.
        declared = DeclaredLabels(functions=("routine_",), data=("glob_",))
        listing = (
            f"int routine_{OTHER:x}(void)\n{{\n  int v;\n  v = (*glob_{SLOT_A:x})();\n"
            "  if (v == 0) {\n    return -1;\n  }\n  return 0;\n}\n"
        )
        entry = _entry("ev_0005", OTHER, listing, tool="zz_listing_service")
        with (
            patch.object(exit_branches, "declared_labels", return_value=declared),
            patch.object(
                exit_branches,
                "declared_auto_name_pattern",
                return_value=auto_name_pattern(declared.function_words),
            ),
        ):
            (site,) = _exits(entry, slots={SLOT_A: "Qx9Mn"})
            line = exit_line(site)
            covered = uncovered_exits(_isr(_claim(f"{OTHER:#x} stops when Qx9Mn fails.")), [site])

        assert (site.slots, site.value) == ((SLOT_A,), -1)
        assert "(Qx9Mn)" in line
        assert covered == []

    def test_a_repeat_and_an_answer_not_shown_are_not_read(self) -> None:
        repeat = LedgerEntry(
            id="ev_0004",
            tool="decompile_function",
            args={"address": hex(GATE)},
            output=GATE_LISTING,
            repeated_of="ev_0002",
        )
        unseen = LedgerEntry(
            id="ev_0005",
            tool="decompile_function",
            args={"address": hex(OTHER)},
            output=not_shown_record(4000),
            truncated=True,
        )

        assert _exits(repeat, unseen) == []

    def test_a_listing_that_says_nothing_does_not_hide_a_later_whole_one(self) -> None:
        cut = _entry("ev_0003", GATE, GATE_LISTING[: GATE_LISTING.index("else")])
        labelled = _entry(
            "ev_0004", GATE, GATE_LISTING.replace("  return iVar2;", "LAB_1:\n  return iVar2;")
        )
        whole = _entry("ev_0005", GATE, GATE_LISTING)

        found = read_listings([cut, labelled, whole], SLOTS)

        assert {site.function.entries for site in found.exits} == {("ev_0005",)}
        assert (found.listings, len(found.exits)) == (1, 5)

    def test_a_condition_handing_back_one_value_twice_is_one_exit(self) -> None:
        (site,) = _exits(
            _entry(
                "ev_0007",
                OTHER,
                _function(
                    f"  int r;\n  r = 0;\n  if (FUN_{HELPER:x}() == 0x20) {{\n    r = -1;\n"
                    "    return -1;\n  }\n  return r;"
                ),
            )
        )

        assert (site.value, site.same_value) == (-1, 1)

    def test_an_exit_ranks_by_the_fewest_listings_calling_a_term_and_its_value_s_count(
        self,
    ) -> None:
        # The condition's own call, and the call its variable hops to.
        both = _function(
            f"  int v;\n  v = FUN_{HELPER:x}();\n"
            f"  if ((v == 0) || (FUN_{CHECK:x}() == 0)) {{\n    return -1;\n  }}\n  return 0;"
        )
        callers = [
            _entry(
                f"ev_00{20 + i}",
                OTHER + (i + 1) * 0x100,
                _function(f"  FUN_{HELPER:x}();", OTHER + (i + 1) * 0x100),
            )
            for i in range(2)
        ]

        (site,) = _exits(_entry("ev_0007", OTHER, both), *callers)
        gate = _exits(_entry("ev_0003", GATE, GATE_LISTING))

        assert site.fan_in == 1
        assert sorted((s.value, s.same_value) for s in gate) == [(-1, 4)] * 4 + [(0, 1)]

    def test_every_entry_is_read_by_its_shape_and_a_function_listed_twice_once(self) -> None:
        first = _entry("ev_0003", GATE, GATE_LISTING)
        again = _entry("ev_0004", GATE, GATE_LISTING)
        xrefs = LedgerEntry(
            id="ev_0002",
            tool="bulk_xrefs",
            args={},
            output=json.dumps({hex(GATE): "[{'from': '1400'}]"}),
        )

        found = _exits(xrefs, first, again)

        assert {site.function.entries for site in found} == {("ev_0003",)}
        assert len(found) == 5


class TestWhatAClaimNames:
    def _left(self, *claims: ClaimEvidence) -> list[tuple[int, ...]]:
        found = _exits(_entry("ev_0003", GATE, GATE_LISTING))
        return [
            (site.value, *site.callees, *site.slots)
            for site in uncovered_exits(_isr(*claims), found)
        ]

    def test_an_exit_one_claim_names_with_its_routine_is_covered(self) -> None:
        said = _claim(f"{GATE:#x} hands back -1 when FUN_{CHECK:x} reports nothing.")

        assert (-1, CHECK) not in self._left(said)
        assert (-1, HELPER) in self._left(said)

    def test_a_term_named_in_another_routine_s_claim_does_not_cover_it(self) -> None:
        apart = (
            _claim(f"{GATE:#x} is the entry's first routine."),
            _claim(f"{OTHER:#x} calls {CHECK:#x} once."),
        )

        assert (-1, CHECK) in self._left(*apart)

    def test_a_slot_is_named_by_its_address_or_by_the_name_the_run_resolved_for_it(
        self,
    ) -> None:
        by_name = _claim(f"{GATE:#x} returns -1 when QueryAlpha reports a flag.")
        by_offset = _claim(f"{GATE - BASE:#x} returns -1 unless the slot at {SLOT_A:#x} says no.")
        neither = _claim(f"{GATE:#x} returns -1 unless QueryAlphaEx says no.")

        assert (-1, SLOT_A) not in self._left(by_name)
        assert (-1, SLOT_A) not in self._left(by_offset)
        assert (-1, SLOT_A) in self._left(neither)

    def test_a_slot_is_named_by_the_data_label_its_listing_writes(self) -> None:
        by_label = _claim(f"{GATE:#x} returns -1 unless _DAT_{SLOT_A:x} says no.")

        assert (-1, SLOT_A) not in self._left(by_label)

    def test_with_no_image_base_a_callee_64_kib_away_is_not_named_by_its_function(self) -> None:
        far = OTHER + 0x10000
        found = _exits(
            _entry(
                "ev_0007",
                OTHER,
                _function(f"  if (FUN_{far:x}() == 0) {{\n    return -1;\n  }}\n  return 0;"),
            )
        )

        left = uncovered_exits(_isr(_claim(f"{OTHER:#x} decides the run.")), found)

        assert [site.callees for site in left] == [(far,)]

    def test_a_constant_is_named_in_hex_or_in_decimal(self) -> None:
        in_hex = _claim(f"{GATE:#x} gives up when the error is 0x3c.")
        in_decimal = _claim(f"{GATE:#x} gives up when the error is 60.")

        assert (-1, SLOT_B, SLOT_C) not in self._left(in_hex)
        assert (-1, SLOT_B, SLOT_C) not in self._left(in_decimal)
        assert (-1, SLOT_B, SLOT_C) in self._left(_claim(f"{GATE:#x} gives up on error 3c."))


def _many(count: int) -> list[Any]:
    body = "\n".join(
        f"  if (FUN_{HELPER + i * 0x10:x}() == 0) {{\n    return {0x100 + i};\n  }}"
        for i in range(count)
    )
    return _exits(_entry("ev_0007", OTHER, _function(body + "\n  return 0;")))


def _many(count: int) -> list[Any]:
    body = "\n".join(
        f"  if (FUN_{HELPER + i * 0x10:x}() == 0) {{\n    return {0x100 + i};\n  }}"
        for i in range(count)
    )
    return _exits(_entry("ev_0007", OTHER, _function(body + "\n  return 0;")))


def _inputs(*entries: Any) -> Any:
    from tests.unit.agents.test_the_unread_functions_around_what_an_analyst_read_are_asked_once import (  # noqa: E501
        _inputs as inputs,
    )

    held = inputs()
    object.__setattr__(held, "decompiled", decompiled_functions(list(entries)))
    return held


OTHER_FINDING = Violation(code=CLAIM_WITHOUT_CONFIDENCE_CODE, message="Claim 1 has no confidence.")


class TestTheQuestion:
    def test_at_most_the_cap_are_listed_with_how_many_more(self) -> None:
        left = uncovered_exits(_isr(), _many(11))

        violation = decompiled_not_described_violation([], left)

        assert violation is not None
        message = violation.message
        assert EXITS_LISTED == 8
        assert message.count(" on [calls ") == 8
        assert message.startswith("Of the functions you decompiled, 11 branch(es) end one")
        assert "; and 3 more." in message

    def test_the_rank_puts_a_named_routine_s_specific_gate_first(self) -> None:
        shared = f"  FUN_{HELPER:x}();\n  return 0;"
        others = [
            _entry(f"ev_00{10 + i}", OTHER + i * 0x100, _function(shared, OTHER + i * 0x100))
            for i in range(3)
        ]
        found = _exits(_entry("ev_0003", GATE, GATE_LISTING), *others)

        left = uncovered_exits(_isr(_claim(f"{GATE:#x} runs first.")), found)

        assert all(site.function.address == GATE for site in left)
        # The helper four listings call ranks after every gate whose term only
        # this routine calls.
        assert [site.callees for site in left][-1] == (HELPER,)

    def test_a_routine_a_claim_names_ranks_before_one_no_claim_names(self) -> None:
        # The unnamed routine's exit has the rarer term and more exits of its value.
        unnamed = _function(
            "\n".join(
                f"  if (FUN_{OTHER + 0x10 + i:x}() == 0) {{\n    return -1;\n  }}" for i in range(5)
            )
            + "\n  return 0;"
        )
        found = _exits(_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0007", OTHER, unnamed))

        left = uncovered_exits(_isr(_claim(f"{GATE:#x} runs first.")), found)

        assert [site.function.address for site in left] == [GATE] * 5 + [OTHER] * 5

    def test_the_whole_question_for_one_branch(self) -> None:
        listing = _function(
            f"  if (FUN_{HELPER:x}(param_1) == 0x2c) {{\n    return -1;\n  }}\n"
            f"  if ((*_DAT_{SLOT_A:x})() == 0x51) {{\n    return 2;\n  }}\n  return 0;"
        )
        left = uncovered_exits(_isr(), _exits(_entry("ev_0005", OTHER, listing)))

        violation = decompiled_not_described_violation([], left)

        assert violation is not None
        assert violation.message == (
            "Of the functions you decompiled, 2 branch(es) end one with a constant on a "
            "condition, and no one claim names that function together with a term of the "
            "condition. Ranked, functions a claim names first, then by how few of your listings "
            f"call the terms: {OTHER:#x} (ev_0005) hands back -1 on [calls {HELPER:#x}, "
            f"constant 0x2c], 2 on [slot {SLOT_A:#x} (QueryAlpha), constant 0x51]. For each "
            "that matters, write one claim naming the function (by a name the decompiler gave "
            "it, or its address or offset from the image base in hex: with 0x, a trailing h, "
            "as bare hex digits, or inside the decompiler's generic name) and one of its terms "
            "(an address written the same ways or inside a data label, a slot's API name, or a "
            "constant in hex with 0x or in decimal), saying what the condition checks and what "
            "the function does when it holds. A branch that only handles a failed call or "
            "allocation, or that this analysis does not need, may stay undescribed."
        )

    def test_the_branches_join_the_functions_question(self) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, _function(""))]
        inputs = _inputs(*entries)
        isr = _isr(_claim(f"{GATE:#x} checks the host."))
        functions = decompiled_not_described_violation([decompiled_functions(entries)[1]])
        assert functions is not None

        joined = with_exit_branches([OTHER_FINDING, functions], isr, inputs, _exits(*entries))

        assert joined[0] == OTHER_FINDING
        (question,) = joined[1:]
        assert question.code == DECOMPILED_NOT_DESCRIBED_CODE
        # The finding's words are the functions'; the branches are only shown.
        assert question.message == functions.message
        assert question.shown.startswith("Of the functions you decompiled, 5 branch(es)")
        assert exit_branches_left_out(joined) == [OTHER_FINDING, functions]

    def test_the_branches_stand_alone_beside_another_finding(self) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING)]
        inputs = _inputs(*entries)
        isr = _isr(_claim(f"{GATE:#x} checks the host."))

        joined = with_exit_branches([OTHER_FINDING], isr, inputs, _exits(*entries))

        assert [v.code for v in joined] == [
            CLAIM_WITHOUT_CONFIDENCE_CODE,
            DECOMPILED_NOT_DESCRIBED_CODE,
        ]
        assert joined[1].message.startswith("Of the functions you decompiled, 5 branch(es)")
        assert [v.question_only for v in joined] == [False, True]
        assert exit_branches_left_out(joined) == [OTHER_FINDING]

    def test_the_branches_alone_or_beside_a_check_that_could_not_run_ask_nothing(self) -> None:
        from malspark.pipeline.validation import CHECK_FAILED_CODE

        entries = [_entry("ev_0003", GATE, GATE_LISTING)]
        inputs = _inputs(*entries)
        isr = _isr(_claim(f"{GATE:#x} checks the host."))
        failed = Violation(code=CHECK_FAILED_CODE, message="A check could not run.")

        assert with_exit_branches([], isr, inputs, _exits(*entries)) == []
        assert with_exit_branches([failed], isr, inputs, _exits(*entries)) == [failed]


FIRST = (
    f"CLAIM 1: {GATE:#x} decides whether the sample runs.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
# The same answer with a second finding: a claim with no confidence line.
UNSURE = FIRST + (
    f"CLAIM 2: {GATE:#x} is reached from the entry.\nEVIDENCE: [ev_0003]\nTECHNIQUE: NONE\n---\n"
)
GATES = FIRST + (
    f"CLAIM 2: {GATE:#x} returns -1 when FUN_{HELPER:x} or FUN_{CHECK:x} returns 0.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    f"CLAIM 3: {GATE:#x} returns -1 when QueryAlpha reports a flag, or OpenBeta fails or "
    "ReadGamma gives 0x3c.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
SOME = FIRST + (
    f"CLAIM 2: {GATE:#x} returns -1 when FUN_{HELPER:x} returns 0.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    f"CLAIM 3: {GATE:#x} is reached from the entry.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[Any], entries: list[LedgerEntry]) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self._evidence_entries = list(entries)
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []
        self._budget_records = [{"agent": "reverser"}]
        self.pack_entries = [
            LedgerEntry(
                id="ev_0001",
                agent="pipeline",
                tool="function_index",
                output="{}",
                structured={
                    "image_base": hex(BASE),
                    "resolved_slots": {hex(a): name for a, name in SLOTS.items()},
                },
            )
        ]
        self.pack_image_bases = (BASE,)

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0)
        if isinstance(text, Exception):
            raise text
        self._record_usage(AIMessage(content=text))
        return text


def _check(
    analyst: _Analyst,
    first: str = FIRST,
    *,
    time_left: float | None = None,
    whole: bool = False,
    fits: Any = None,
) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    if whole:
        # An answer not written as one is fixed by a whole retry, never merged.
        isr.note_answer_text("")
    with (
        patch("malspark.agents.base_agent.validity_check_available", return_value=True),
        patch.object(
            BaseAnalyst, "_fits_the_window", fits if fits is not None else lambda *_a: True
        ),
        patch.object(BaseAnalyst, "_seconds_the_last_loop_left", return_value=time_left),
        patch.object(BaseAnalyst, "seconds_an_answer_needs", return_value=60.0),
    ):
        return analyst._validate_isr(isr, "evidence")


def _recorded(analyst: _Analyst, code: str = DECOMPILED_NOT_DESCRIBED_CODE) -> list[str]:
    return [v.message for v in analyst.validation_findings if v.code == code]


class TestTheValidationTurn:
    def test_an_answer_whose_only_shortcoming_is_its_branches_is_not_asked(self) -> None:
        analyst = _Analyst([], [_entry("ev_0003", GATE, GATE_LISTING)])

        result = _check(analyst)

        assert analyst.seen_turns == []
        assert analyst.validation_retries == 0
        assert analyst.validation_findings == []
        assert len(result.claims) == 1
        note = analyst._budget_records[-1]["exit_branches"]
        assert (note["listings"], note["exits"], note["left"], note["asked"]) == (1, 5, 5, False)
        assert len(note["shown"]) == 5

    def test_the_branches_are_asked_when_another_finding_opens_the_turn(self) -> None:
        analyst = _Analyst([GATES], [_entry("ev_0003", GATE, GATE_LISTING)])

        result = _check(analyst, UNSURE)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert CLAIM_WITHOUT_CONFIDENCE_CODE in question
        assert "Of the functions you decompiled, 5 branch(es)" in question
        assert f"slot {SLOT_A:#x} (QueryAlpha)" in question
        assert len(result.claims) == 3
        assert _recorded(analyst) == []
        note = analyst._budget_records[-1]["exit_branches"]
        assert (note["left"], note["shown"], note["asked"]) == (0, [], True)

    def test_an_exits_only_question_asked_beside_a_finding_counts_only_that_finding(self) -> None:
        from types import SimpleNamespace

        published: list[tuple[str, str]] = []
        analyst = _Analyst([GATES], [_entry("ev_0003", GATE, GATE_LISTING)])
        analyst._container = SimpleNamespace(event_sink=object())

        with patch(
            "malspark.pipeline.validation.emit_validation_feedback",
            lambda _sink, **kw: published.append((kw["state"], kw["code"])),
        ):
            _check(analyst, UNSURE)

        (turns,) = analyst.seen_turns
        assert "Of the functions you decompiled, 5 branch(es)" in str(turns[-1].content)
        # The counts, the published lines and the records are the other finding's alone.
        assert analyst.validation_retries == 1
        assert analyst.validation_fed_back == {CLAIM_WITHOUT_CONFIDENCE_CODE: 1}
        assert published == [
            ("retried", CLAIM_WITHOUT_CONFIDENCE_CODE),
            ("resolved", CLAIM_WITHOUT_CONFIDENCE_CODE),
        ]
        assert analyst.validation_findings == []
        note = analyst._budget_records[-1]["exit_branches"]
        assert (note["left"], note["asked"]) == (0, True)

    def test_what_the_kept_answer_leaves_is_recorded_as_the_functions_alone(self) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, _function(""))]
        analyst = _Analyst([SOME], entries)

        _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert "You decompiled 1 function(s)" in question
        assert "Of the functions you decompiled, 5 branch(es)" in question
        functions = decompiled_not_described_violation([decompiled_functions(entries)[1]])
        assert functions is not None
        assert _recorded(analyst) == [functions.message]
        # Joined to the functions, the counts are the one question's, as without them.
        assert analyst.validation_fed_back == {DECOMPILED_NOT_DESCRIBED_CODE: 1}
        note = analyst._budget_records[-1]["exit_branches"]
        assert (note["left"], note["asked"]) == (4, True)
        assert note["shown"][0].startswith(f"{GATE:#x} (ev_0003) hands back -1")

    def test_a_first_answer_kept_over_its_retry_is_checked_without_its_branches(self) -> None:
        analyst = _Analyst(
            ["The answer stands as written."], [_entry("ev_0003", GATE, GATE_LISTING)]
        )

        result = _check(analyst, UNSURE, whole=True)

        assert len(analyst.seen_turns) == 1
        assert [c.claim for c in result.claims] == [f"{GATE:#x} decides whether the sample runs."]
        assert _recorded(analyst, CLAIM_WITHOUT_CONFIDENCE_CODE)
        assert _recorded(analyst) == []
        note = analyst._budget_records[-1]["exit_branches"]
        assert (note["left"], note["asked"]) == (5, True)

    def test_a_turn_not_asked_records_the_functions_alone(self) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, _function(""))]
        analyst = _Analyst([], entries)

        _check(analyst, time_left=1.0)

        assert analyst.seen_turns == []
        (message,) = _recorded(analyst)
        assert message.startswith("You decompiled 1 function(s)")
        assert "branch(es)" not in message and "hands back" not in message
        assert analyst._budget_records[-1]["exit_branches"]["asked"] is False

    def test_an_analyst_whose_branches_are_all_named_is_not_asked(self) -> None:
        analyst = _Analyst([], [_entry("ev_0003", GATE, GATE_LISTING)])

        _check(analyst, GATES)

        assert analyst.seen_turns == []
        assert analyst._budget_records[-1]["exit_branches"]["left"] == 0


BIG = "1" * 5000
OTHER_LISTING = _function("")


def _turn(
    replies: list[Any],
    entries: list[LedgerEntry],
    first: str = UNSURE,
    *,
    patches: tuple[Any, ...] = (),
    **check: Any,
) -> dict[str, Any]:
    """One validation turn as everything outside the loop's record sees it."""
    from contextlib import ExitStack
    from types import SimpleNamespace

    published: list[tuple[str, str, str]] = []
    analyst = _Analyst(replies, entries)
    analyst._container = SimpleNamespace(event_sink=object())
    with ExitStack() as stack:
        for held in patches:
            stack.enter_context(held)
        stack.enter_context(
            patch(
                "malspark.pipeline.validation.emit_validation_feedback",
                lambda _sink, **kw: published.append((kw["state"], kw["code"], kw["message"])),
            )
        )
        result = _check(analyst, first, **check)
    record = dict(analyst._budget_records[-1])
    return {
        "claims": [c.claim for c in result.claims],
        "sent": [[str(m.content) for m in turn] for turn in analyst.seen_turns],
        "retries": analyst.validation_retries,
        "fed_back": dict(analyst.validation_fed_back),
        "findings": [(v.code, v.message, v.asked) for v in analyst.validation_findings],
        "events": published,
        "note": record.pop("exit_branches", None),
        "record": record,
    }


def _without(view: dict[str, Any]) -> dict[str, Any]:
    """``view`` less the note and the branches' words in what was sent."""
    return {
        **{k: v for k, v in view.items() if k not in ("note", "sent")},
        "calls": len(view["sent"]),
    }


def _as_without_branches(
    replies: list[Any], entries: list[LedgerEntry], *, patches: tuple[Any, ...] = (), **check: Any
) -> Any:
    """The same turn with no branch read: the turn as it is without them."""
    from malspark.pipeline.exit_branches import ListingsRead

    return _turn(
        replies,
        entries,
        patches=(
            *patches,
            patch(
                "malspark.agents.base_agent.read_listings",
                return_value=ListingsRead(listings=0, exits=()),
            ),
        ),
        **check,
    )


class TestTheBranchesNeverCostAnAnswer:
    def test_a_number_longer_than_a_constant_is_no_constant_and_reads_in_one_token(
        self,
    ) -> None:
        compared = listing_exits(
            _function(f"  if (FUN_{HELPER:x}() == {BIG}) {{\n    return -1;\n  }}\n  return 0;")
        )
        returned = listing_exits(
            _function(f"  if (FUN_{HELPER:x}() == 0) {{\n    return {BIG};\n  }}\n  return 0;")
        )
        wide_hex = listing_exits(
            _function(
                f"  if (FUN_{HELPER:x}() == 0x{'f' * 17}) {{\n    return 0x{'f' * 17};\n  }}\n"
                "  return 0;"
            )
        )
        widest = listing_exits(
            _function(
                f"  if (param_1 == {'9' * 20}) {{\n    return 0x{'f' * 16};\n  }}\n  return 0;"
            )
        )

        assert _terms(compared) == [(-1, (HELPER,), (), ())]
        assert returned == [] and wide_hex == []
        assert _terms(widest) == [(0xFFFFFFFFFFFFFFFF, (), (), (10**20 - 1,))]

    def test_a_turn_over_a_listing_with_a_huge_number_answers_as_without_branches(
        self,
    ) -> None:
        entries = [
            _entry("ev_0003", GATE, GATE_LISTING),
            _entry(
                "ev_0004",
                OTHER,
                _function(
                    f"  if (FUN_{HELPER:x}() == {BIG}) {{\n    return {BIG};\n  }}\n  return 0;"
                ),
            ),
        ]

        view = _turn([GATES], entries)

        assert view["claims"] and view["retries"] == 1
        assert view["note"]["asked"] is True

    def test_a_reader_that_raises_changes_nothing_against_the_turn_without_branches(
        self,
    ) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, OTHER_LISTING)]
        without = _as_without_branches([SOME], entries)
        for target in (
            "malspark.agents.base_agent.read_listings",
            "malspark.agents.base_agent.with_exit_branches",
        ):
            view = _turn(
                [SOME], entries, patches=(patch(target, side_effect=RuntimeError("boom")),)
            )

            assert _without(view) == _without(without), target
            assert view["sent"] == without["sent"], target

    def test_a_note_that_cannot_be_written_changes_nothing_else(self) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, OTHER_LISTING)]
        asked = _turn([SOME], entries)
        view = _turn(
            [SOME],
            entries,
            patches=(
                patch(
                    "malspark.agents.base_agent.uncovered_exits",
                    side_effect=RuntimeError("boom"),
                ),
            ),
        )

        assert view["note"] is None
        assert {k: v for k, v in view.items() if k != "note"} == {
            k: v for k, v in asked.items() if k != "note"
        }

    def test_each_line_of_the_note_is_bounded_as_a_finding_value(self) -> None:
        from malspark.pipeline.events import FINDING_VALUE_LIMIT

        long_name = "routine_" + "q" * 5000
        listing = (
            f"int {long_name}(int param_1)\n{{\n  if (FUN_{HELPER:x}() == 0x20) {{\n"
            "    return -1;\n  }\n  return 0;\n}\n"
        )
        entry = LedgerEntry(
            id="ev_0003", tool="decompile_function", args={"address": hex(OTHER)}, output=listing
        )

        view = _turn([], [entry], FIRST)

        (line,) = view["note"]["shown"]
        assert len(line) <= FINDING_VALUE_LIMIT + 1


class TestTheBranchesAreNotPublished:
    def test_joined_to_the_functions_the_events_carry_the_functions_alone(self) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, OTHER_LISTING)]
        asked = _turn([SOME], entries, FIRST)
        without = _as_without_branches([SOME], entries, first=FIRST)

        assert "Of the functions you decompiled, 5 branch(es)" in asked["sent"][0][-1]
        assert asked["events"] == without["events"]
        assert all("branch(es)" not in message for _s, _c, message in asked["events"])
        assert _without(asked) == _without(without)
        assert asked["note"]["asked"] is True


class TestTheBranchesGoFirstFromATurnThatDoesNotFit:
    def test_a_window_too_narrow_for_the_branches_drops_them_and_measures_as_without(
        self,
    ) -> None:
        # A window that holds every turn but one carrying the branches. The
        # second answer's technique question carries a card, kept only where
        # the turn is measured as it is without the branches.
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, OTHER_LISTING)]
        # The describe question opens no turn of its own: the claim with no
        # confidence line opens it, and the describe question joins it.
        technique = UNSURE.replace("TECHNIQUE: NONE", "TECHNIQUE: T1082", 1)

        def narrow(_self: Any, turns: list[Any], _cap: int) -> bool:
            return not any("branch(es)" in str(getattr(m, "content", m)) for m in turns)

        for listed, first in ((entries, FIRST), (entries[:1], technique)):
            view = _turn([GATES], listed, first, fits=narrow)
            without = _as_without_branches([GATES], listed, first=first, fits=narrow)

            assert view["sent"] and view["sent"] == without["sent"]
            assert _without(view) == _without(without)
            assert view["note"]["asked"] is False


class TestATurnThatFailsRecordsTheTurnWithoutBranches:
    def test_a_retry_that_raises_after_the_joined_question(self) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, OTHER_LISTING)]
        for listed in (entries, entries[:1]):
            view = _turn([RuntimeError("boom")], listed)
            without = _as_without_branches([RuntimeError("boom")], listed)

            assert _without(view) == _without(without)
            assert all("branch(es)" not in message for _c, message, _a in view["findings"])

    def test_a_retry_answered_and_then_lost_counts_and_records_as_without(self) -> None:
        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, OTHER_LISTING)]
        for listed in (entries, entries[:1]):
            # The retry answered; settling what it left out of the first fails.
            views = [
                make(
                    [SOME],
                    listed,
                    patches=(
                        patch.object(
                            BaseAnalyst, "_settle_retry_drops", side_effect=RuntimeError("lost")
                        ),
                    ),
                )
                for make in (_turn, _as_without_branches)
            ]

            assert views[0]["sent"] and views[0]["retries"] == 1
            assert _without(views[0]) == _without(views[1])
            assert views[0]["findings"] and all(
                "branch(es)" not in message for _c, message, _a in views[0]["findings"]
            )

    def test_a_turn_without_tools_whose_only_other_question_was_the_callees_asks_nothing(
        self,
    ) -> None:
        from malspark.agents.callees_question import CalleesFound, CalleeToRead

        callees = CalleesFound(
            ranked=(
                CalleeToRead(
                    address=HELPER, callers=(GATE,), depth=1, start=GATE, called_from=1, calls=0
                ),
            )
        )
        built = MagicMock()
        view = _turn(
            [GATES],
            [_entry("ev_0003", GATE, GATE_LISTING)],
            FIRST,
            patches=(
                patch.object(BaseAnalyst, "_callees_to_ask", return_value=callees),
                patch.object(BaseAnalyst, "_callees_without_tools", return_value="no tools"),
                patch.object(BaseAnalyst, "_question_base_of", built),
            ),
        )

        # The turn stops where it stops without the branches: no question is built.
        assert view["sent"] == [] and view["retries"] == 0
        built.assert_not_called()
        assert view["note"]["asked"] is False


# A window measured by size: a turn fits when its characters and an answer of
# the cap do, and the room the cited entries are fitted in is the same. The
# run-state block every turn is framed with is part of what is measured.
CAP = 300
STATE = "run state: " + "r" * 120
# The branches' words as a question carries them, joined to the functions
# line or standing under their code.
BRANCHES_SAID = re.compile(
    r"(?:\n- \[[\w.]+\])? Of the functions you decompiled, \d+ branch\(es\).*?"
    r"may stay undescribed\.",
    re.S,
)


def _size(turn: list[Any]) -> int:
    return sum(len(str(getattr(m, "content", m))) for m in turn)


def _window(limit: int) -> dict[str, Any]:
    """``_turn``'s arguments for a window of ``limit`` characters."""

    def fits(_self: Any, turns: list[Any], cap: int) -> bool:
        return _size(turns) + int(cap) <= limit

    return {
        "fits": fits,
        "patches": (
            patch.object(BaseAnalyst, "output_cap_tokens", return_value=CAP),
            patch.object(BaseAnalyst, "_window_room_chars", lambda _s, cap: float(limit - cap)),
            patch("malspark.agents.base_agent.current_run_state", lambda _agent: STATE),
        ),
    }


def _unsaid(sent: list[list[str]]) -> list[list[str]]:
    return [[BRANCHES_SAID.sub("", text) for text in turn] for turn in sent]


WINDOW_CASES = (
    # The branches joined to the functions line, then standing beside another
    # finding; each again with a technique card the turn carries.
    ([SOME], "functions", FIRST),
    ([GATES], "alone", UNSURE),
    ([SOME], "functions", FIRST.replace("TECHNIQUE: NONE", "TECHNIQUE: T1082")),
    ([GATES], "alone", UNSURE.replace("TECHNIQUE: NONE", "TECHNIQUE: T1082")),
)


def _listed(kind: str) -> list[LedgerEntry]:
    gate = _entry("ev_0003", GATE, GATE_LISTING)
    return [gate, _entry("ev_0004", OTHER, OTHER_LISTING)] if kind == "functions" else [gate]


class TestTheWindowIsMeasuredBySize:
    def test_at_every_size_the_turn_is_the_one_without_branches_or_it_plus_them(
        self,
    ) -> None:
        # Every size at which a turn of either, unbounded, starts or stops
        # fitting beside the cap, and a step through the rest: the cited
        # entry, the card and the branches each go in turn as it narrows.
        for replies, kind, first in WINDOW_CASES:
            listed = _listed(kind)
            wide = _window(10**9)
            sizes = {
                _size(turn)
                for view in (
                    _turn(replies, listed, first, **wide),
                    _as_without_branches(replies, listed, first=first, **wide),
                )
                for turn in view["sent"]
            }
            limits = sorted(
                {s + CAP + d for s in sizes for d in (-1, 0, 1)}
                | set(range(min(sizes) - 1500, max(sizes) + CAP + 100, 61))
            )
            seen: set[bool] = set()
            for limit in limits:
                window = _window(limit)
                view = _turn(replies, listed, first, **window)
                without = _as_without_branches(replies, listed, first=first, **window)
                kept = view["sent"] != without["sent"]
                seen.add(kept)

                assert _unsaid(view["sent"]) == without["sent"], (first, limit)
                assert _without(view) == _without(without), (first, limit)
                assert view["note"]["asked"] is kept, (first, limit)
                # What the turn without them fits, the turn sent fits.
                for asked, bare in zip(view["sent"], without["sent"], strict=True):
                    if _size(bare) + CAP <= limit:
                        assert _size(asked) + CAP <= limit, (first, limit)
            assert seen == {True, False}, first

    def test_an_entry_that_fits_only_without_the_branches_is_shown_and_they_go(
        self,
    ) -> None:
        # The narrowest window whose turn without the branches shows the cited
        # entry: measured with the branches, the entry would not fit.
        listed = _listed("functions")
        shown = "[ev_0003] decompile_function:\n"

        def without_at(limit: int) -> Any:
            return _as_without_branches([SOME], listed, first=FIRST, **_window(limit))

        low, high = 0, 2 * _size(without_at(10**9)["sent"][0]) + CAP
        while high - low > 1:
            middle = (low + high) // 2
            low, high = (
                (low, middle) if shown in without_at(middle)["sent"][0][-1] else (middle, high)
            )
        wide = _turn([SOME], listed, FIRST, **_window(10**9))
        assert _size(wide["sent"][0]) + CAP > high

        view = _turn([SOME], listed, FIRST, **_window(high))
        without = without_at(high)

        assert shown in without["sent"][0][-1]
        assert view["sent"] == without["sent"]
        assert _without(view) == _without(without)
        assert view["note"]["asked"] is False


def _continued(limit: int, paths: list[tuple[tuple[bool, bool], ...]]) -> dict[str, Any]:
    """``_window``, the retry continuing the loop's own conversation where it fits.

    ``paths`` gets, for each retry, each continued question tried: whether it
    carried the branches and whether it is asked.
    """
    import time

    from langchain_core.messages import HumanMessage

    from malspark.agents.base_agent import KeptConversation

    window = _window(limit)
    plains: list[Any] = []
    tried: list[tuple[bool, bool]] = []
    continued = BaseAnalyst._continued_question

    def trying(self: Any, turns: list[Any], *args: Any, **kwargs: Any) -> Any:
        found = continued(self, turns, *args, **kwargs)
        tried.append(("branch(es)" in str(turns[-1].content), found is not None))
        return found

    def asked(
        self: Any, messages: list[Any], _timeout: Any, *, what: str, tools: bool, plain: Any = None
    ) -> Any:
        paths.append(tuple(tried))
        tried.clear()
        self.seen_turns.append(list(messages))
        plains.append(None if plain is None else [str(m.content) for m in plain])
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return AIMessage(content=text)

    base = KeptConversation((HumanMessage(content="Analyse. " + "y" * 3000),), time.monotonic())
    window["patches"] = (
        *window["patches"],
        patch.object(BaseAnalyst, "_turns_carry_tools", return_value=True),
        patch.object(BaseAnalyst, "_question_base_of", lambda *_a, **_k: base),
        patch("malspark.llm.anthropic_history.prompt_cache_seconds", lambda *_a, **_k: 300),
        patch.object(BaseAnalyst, "_shows_what_the_rebuilt_shows", return_value=True),
        patch.object(BaseAnalyst, "_continued_question", trying),
        patch.object(BaseAnalyst, "_answer_after_loop", asked),
    )
    window["plains"] = plains
    return window


class TestAContinuedQuestion:
    def test_one_that_fits_only_without_the_branches_is_asked_and_noted_without_them(
        self,
    ) -> None:
        # Through every size: the question is continued with the branches, or
        # without them where only that fits, or rebuilt; what is sent, and
        # the turn its tools-free call would ask, is the turn without them or
        # it plus them, and the note says which.
        listed = _listed("functions")
        taken: set[tuple[tuple[bool, bool], ...]] = set()
        for limit in range(3000, 12000, 37):
            views = []
            for make in (_turn, _as_without_branches):
                paths: list[tuple[tuple[bool, bool], ...]] = []
                window = _continued(limit, paths)
                plains = window.pop("plains")
                if make is _turn:
                    view = _turn([SOME], listed, FIRST, **window)
                else:
                    view = _as_without_branches([SOME], listed, first=FIRST, **window)
                views.append((view, plains, paths))
            (view, plains, paths), (without, without_plains, _p) = views
            kept = view["sent"] != without["sent"]
            taken.update(paths)

            assert _unsaid(view["sent"]) == without["sent"], limit
            assert [None if p is None else _unsaid([p])[0] for p in plains] == without_plains
            assert all(p is None or not kept or "branch(es)" in p[-1] for p in plains), limit
            if not kept:
                assert plains == without_plains, limit
            assert _without(view) == _without(without), limit
            assert view["note"]["asked"] is kept, limit
        # Continued with them, continued only without them, and rebuilt.
        assert {
            ((True, True),),
            ((True, False), (False, True)),
            ((True, False), (False, False)),
        } <= taken


class TestTheWholeAnswerAskedAfterARetryNotMerged:
    def test_it_asks_without_the_branches(self) -> None:
        # The retry writes a block without its number: not merged, so the
        # analyst's whole answer is asked for after it.
        listed = _listed("functions")
        replies = [SOME.replace("CLAIM 3:", "CLAIM:"), SOME]

        view = _turn(replies, listed, FIRST)
        without = _as_without_branches(replies, listed, first=FIRST)

        retry, whole = view["sent"]
        assert "branch(es)" in retry[-1]
        assert "whole" in whole[-1]
        assert whole == without["sent"][1]
        assert _unsaid([retry]) == without["sent"][:1]
        assert _without(view) == _without(without)


def test_a_cut_chunk_s_turn_writes_no_note() -> None:
    analyst = _Analyst([], [_entry("ev_0003", GATE, GATE_LISTING)])
    isr = analyst._text_to_isr(FIRST, 0)

    with patch("malspark.agents.base_agent.validity_check_available", return_value=True):
        analyst._validate_isr(isr, "evidence", only_cut=True)

    assert analyst.seen_turns == []
    assert analyst._budget_records == [{"agent": "reverser"}]


def test_the_slots_are_read_off_the_function_index_by_offset_and_by_each_base() -> None:
    from malspark.analysis.slot_names import slot_names

    index = _Analyst([], []).pack_entries

    assert resolved_slots(slot_names(index), (BASE,))[SLOT_A] == "QueryAlpha"
    assert resolved_slots(slot_names(index), (BASE,))[SLOT_A - BASE] == "QueryAlpha"
