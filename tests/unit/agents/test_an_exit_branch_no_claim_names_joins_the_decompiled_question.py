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
The ones left join the decompiled-functions question, one finding, at most 8
listed, ranked; the report prints their count and the run record their list.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from malspark.agents.base_agent import BaseAnalyst
from malspark.core.undeclared_tools import DeclaredLabels, auto_name_pattern
from malspark.pipeline import exit_branches
from malspark.pipeline.exit_branches import (
    EXITS_LISTED,
    exit_line,
    exits_left_in_report,
    listing_exits,
    resolved_slots,
    uncovered_exits,
)
from malspark.pipeline.exit_branches import (
    exit_branches as read_exits,
)
from malspark.pipeline.validation import (
    DECOMPILED_NOT_DESCRIBED_CODE,
    analyst_answer_checks,
    decompiled_functions,
    decompiled_not_described_violation,
)
from malspark.schemas.evidence import LedgerEntry
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


class TestTheQuestion:
    def test_at_most_the_cap_are_listed_with_how_many_more(self) -> None:
        left = uncovered_exits(_isr(), _many(11))

        violation = decompiled_not_described_violation([], left)

        assert violation is not None
        message = violation.message
        assert EXITS_LISTED == 8
        assert message.count(" hands back ") == 8
        assert "11 branch(es) end the function" in message
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

    def test_the_question_says_what_it_accepts_and_lets_a_branch_stay(self) -> None:
        left = uncovered_exits(_isr(), _exits(_entry("ev_0003", GATE, GATE_LISTING)))

        violation = decompiled_not_described_violation([], left)

        assert violation is not None
        assert (
            "names the function, by a name the decompiler gave it or by its address or its "
            "offset from the image base in hex (with 0x, with a trailing h, as bare hex "
            "digits, or inside the decompiler's generic name), and one term listed with it: "
            "an address written the same ways, a slot's API name, or a constant written in "
            "hex with 0x or in decimal"
        ) in violation.message
        assert violation.message.endswith(
            "A branch that only handles a failed call or allocation, or that this analysis "
            "does not need, may stay undescribed."
        )
        assert f"slot {SLOT_A:#x} (QueryAlpha)" in violation.message

    def test_the_exits_join_the_one_decompiled_question_and_add_no_call(self) -> None:
        from tests.unit.agents.test_the_unread_functions_around_what_an_analyst_read_are_asked_once import (  # noqa: E501
            _inputs,
        )

        entries = [_entry("ev_0003", GATE, GATE_LISTING), _entry("ev_0004", OTHER, _function(""))]
        inputs = _inputs()
        object.__setattr__(inputs, "decompiled", decompiled_functions(entries))
        object.__setattr__(inputs, "exits", _exits(*entries))
        isr = _isr(_claim(f"{GATE:#x} checks the host."))

        with patch("malspark.pipeline.validation.validate_isr", return_value=[]):
            found = analyst_answer_checks(
                isr,
                inputs,
                whole_answer=[],
                unread=[],
                functions=[],
                weak_alignment_challenges=False,
                callees=None,
            )

        (question,) = found
        assert question.code == DECOMPILED_NOT_DESCRIBED_CODE
        assert question.message.startswith("You decompiled 1 function(s)")
        assert f"{OTHER:#x}" in question.message
        assert "Of the functions you decompiled, 5 branch(es)" in question.message


FIRST = (
    f"CLAIM 1: {GATE:#x} decides whether the sample runs.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
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
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str], entries: list[LedgerEntry]) -> None:
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
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst, first: str = FIRST) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("malspark.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


class TestTheValidationTurn:
    def test_the_slots_the_index_resolved_name_the_slots(self) -> None:
        analyst = _Analyst([GATES], [_entry("ev_0003", GATE, GATE_LISTING)])

        _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert DECOMPILED_NOT_DESCRIBED_CODE in question
        assert f"slot {SLOT_A:#x} (QueryAlpha)" in question

    def test_an_answer_naming_every_gate_with_its_routine_stands(self) -> None:
        analyst = _Analyst([GATES], [_entry("ev_0003", GATE, GATE_LISTING)])

        result = _check(analyst)

        assert len(result.claims) == 3
        assert DECOMPILED_NOT_DESCRIBED_CODE not in [v.code for v in analyst.validation_findings]
        assert analyst._budget_records[-1]["exit_branches"] == {"read": 5, "left": []}

    def test_the_exits_left_after_the_retry_are_recorded_and_not_printed(self) -> None:
        from malspark.pipeline.validation import validation_metrics
        from malspark.reporting.renderers.bundle import bundle_json
        from malspark.reporting.renderers.markdown import MarkdownRenderer
        from tests.unit.reporting._report_shapes import rich_report

        analyst = _Analyst([SOME], [_entry("ev_0003", GATE, GATE_LISTING)])
        _check(analyst)
        (left,) = [
            v for v in analyst.validation_findings if v.code == DECOMPILED_NOT_DESCRIBED_CODE
        ]
        report = rich_report()
        rows = validation_metrics(1, [("reverser", left)])["unresolved"]
        report.run_summary["validation"]["unresolved"].extend(rows)

        markdown = MarkdownRenderer().render(report)
        bundle = bundle_json(report)

        # The finding and the run record list them; the loop record too.
        assert f"{GATE:#x} (ev_0003) hands back -1" in rows[0]["message"]
        assert len(analyst._budget_records[-1]["exit_branches"]["left"]) == 4
        # The report's line, here alone, gives their count and no list.
        (line,) = [text for text in markdown.splitlines() if DECOMPILED_NOT_DESCRIBED_CODE in text]
        assert "(reverser)" in line
        assert "Of the functions you decompiled, 4 branch(es) that end the function" in line
        assert "hands back" not in line and "You decompiled" not in line
        assert "hands back" not in bundle

    def test_the_report_keeps_naming_the_functions_and_adds_the_count(self) -> None:
        left = uncovered_exits(_isr(), _exits(_entry("ev_0003", GATE, GATE_LISTING)))
        functions = decompiled_functions([_entry("ev_0004", OTHER, _function(""))])
        message = decompiled_not_described_violation(functions, left).message  # type: ignore[union-attr]

        printed = exits_left_in_report(f"{message} Not asked: no time was left.")

        assert (
            printed
            == (
                decompiled_not_described_violation(functions).message  # type: ignore[union-attr]
                + " Of the functions you decompiled, 5 branch(es) that end the function with a "
                "constant on a condition are named with their function by no claim; the run "
                "record lists them. Not asked: no time was left."
            )
        )

    def test_an_analyst_whose_branches_are_all_named_is_not_asked(self) -> None:
        analyst = _Analyst([], [_entry("ev_0003", GATE, GATE_LISTING)])

        _check(analyst, GATES)

        assert analyst.seen_turns == []


def test_the_slots_are_read_off_the_function_index_by_offset_and_by_each_base() -> None:
    from malspark.analysis.slot_names import slot_names

    index = _Analyst([], []).pack_entries

    assert resolved_slots(slot_names(index), (BASE,))[SLOT_A] == "QueryAlpha"
    assert resolved_slots(slot_names(index), (BASE,))[SLOT_A - BASE] == "QueryAlpha"
