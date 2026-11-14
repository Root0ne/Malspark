"""A table row's id is held by an entry the row cites.

A command row states the id the operator sends and cites entries, and nothing
compared that id with what the cited entries hold. The rule: a number is held
by a cited entry whose text writes it as a compared operand (an equality test,
a case label, a compare instruction), any other id by a cited entry whose text
writes it whole; a failed call holds nothing. A number none of its cited
entries holds is asked about only with the entry whose one compared expression
holds the most of the table's numbers, where the entries holding as many agree
on its values, and not when a cited entry is code the reader cannot read; any
other id with every entry that writes it. A table of fewer than four numbered
ids, or of ids that are a plain count, is not checked for its numbers. A row
kept after the question is marked beside its evidence.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from malspark.pipeline.validation import (
    ASKED_BY_VALUE,
    ID_NOT_IN_CITED_ENTRY_CODE,
    KEPT_WITH_A_FINDING,
    MARKED_IN_PLACE,
    ComparedValues,
    EntryTexts,
    _read_compared_operands,
    cited_id_violations,
    command_value_violations,
    compared_operands,
    record_flagged_statements,
)
from malspark.reporting.composer import ReportComposer, _CommandsOut
from malspark.reporting.models import (
    CommandRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.schemas.evidence import LedgerEntry
from tests.credential_shapes import prefixed_key
from tests.linear_cost import assert_scales, assert_under, peak_bytes

DISPATCHER = (
    "void dispatch(int param_2) {\n"
    "  switch (param_2) {\n"
    "  case 2: run_shell(); break;\n"
    "  case 0xc: upload(); break;\n"
    "  case 0x13: sleep_for(); break;\n"
    "  case 0x15: uninstall(); break;\n"
    "  }\n"
    "}\n"
)
HANDLER = "void upload(void) {\n  WriteFile(h, buf, n, &w, 0);\n}\n"


def _entry(entry_id: str, tool: str, output: str, *, truncated: bool = False) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent="pipeline", server="pipeline", tool=tool, output=output,
        truncated=truncated,
    )  # fmt: skip


def _texts(*, partial: bool = False) -> EntryTexts:
    # The code is stored as JSON, its line breaks escaped, as a tool's answer is.
    return EntryTexts.from_ledger(
        [
            _entry("ev_0010", "batch_decompile", json.dumps({"code": DISPATCHER})),
            _entry("ev_0011", "decompile_function", json.dumps({"code": HANDLER})),
            _entry("ev_0012", "strings", json.dumps({"strings": ["ERROR", "OK"]})),
            _entry(
                "ev_0013",
                "decompile_function",
                json.dumps({"code": "int f(void) {\n  return g(1);\n}\n"}),
                truncated=partial,
            ),
        ]
    )


def _commands(*rows: tuple[str, list[str]]) -> dict[str, Any]:
    return {
        "commands": [
            {"id": written, "name": f"command {written}", "evidence_refs": refs}
            for written, refs in rows
        ]
    }


def _table(first: tuple[str, list[str]]) -> dict[str, Any]:
    """``first`` as row 1 of a table whose other rows the dispatcher holds."""
    return _commands(first, ("2", ["ev_0010"]), ("0x13", ["ev_0010"]), ("0x15", ["ev_0010"]))


class TestANumberedId:
    def test_an_id_the_cited_code_compares_stands(self) -> None:
        assert cited_id_violations(_commands(("0xc", ["ev_0010"])), _texts()) == []

    def test_an_id_only_another_entry_s_code_compares_is_asked_naming_it(self) -> None:
        (found,) = cited_id_violations(_table(("0xc", ["ev_0011"])), _texts())

        assert found.code == ID_NOT_IN_CITED_ENTRY_CODE == "report.id_not_in_cited_entry"
        assert "Row 1 of commands" in found.message
        assert "ev_0010 (batch_decompile)" in found.message
        assert found.path == "commands.id"

    def test_an_id_read_as_its_last_word_and_in_any_base(self) -> None:
        payload = _commands(
            ("COMMAND 21", ["ev_0011"]),
            ("COMMAND 012", ["ev_0010"]),
            ("COMMAND 2", ["ev_0010"]),
            ("COMMAND 19", ["ev_0010"]),
        )

        (found,) = cited_id_violations(payload, _texts())

        # 21 is 0x15, compared by ev_0010; 012 is octal 10, compared by none.
        assert found.message.startswith("Row 1 of commands")

    def test_rows_one_entry_holds_are_asked_together(self) -> None:
        payload = _commands(
            ("2", ["ev_0011"]), ("0xc", ["ev_0012"]), ("0x13", ["ev_0010"]), ("0x15", ["ev_0010"])
        )

        (found,) = cited_id_violations(payload, _texts())

        assert found.message.startswith("Rows 1, 2 of commands")
        assert len(found.quoted) == 2

    def test_an_id_no_entry_s_code_compares_is_not_asked_here(self) -> None:
        assert cited_id_violations(_commands(("0x99", ["ev_0011"])), _texts()) == []

    def test_a_number_written_in_the_text_and_compared_by_no_code_is_not_held(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "strings", json.dumps({"strings": ["12"]})),
                _entry("ev_0002", "batch_decompile", json.dumps({"code": DISPATCHER})),
            ]
        )

        (found,) = cited_id_violations(
            _commands(
                ("12", ["ev_0001"]), ("2", ["ev_0002"]), ("0x13", ["ev_0002"]),
                ("0x15", ["ev_0002"]),
            ),
            texts,
        )  # fmt: skip

        assert "ev_0002" in found.message


class TestAnyOtherId:
    def test_an_id_a_cited_entry_writes_whole_stands(self) -> None:
        assert cited_id_violations(_commands(("ERROR", ["ev_0012"])), _texts()) == []

    def test_an_id_only_another_entry_writes_is_asked_naming_it(self) -> None:
        (found,) = cited_id_violations(_commands(("ERROR", ["ev_0011"])), _texts())

        assert "ev_0012 (strings)" in found.message

    def test_a_label_no_entry_writes_is_not_asked_here(self) -> None:
        assert cited_id_violations(_commands(("net_view", ["ev_0011"])), _texts()) == []


# A dispatcher on the command (4, 5, 6, 7), and a runtime function whose small
# switch also has a case 4: it merely contains the number.
COMMAND_SWITCH = (
    "void on_command(int cmd) {\n"
    "  switch (cmd) {\n"
    "  case 4: download(); break;\n"
    "  case 5: upload(); break;\n"
    "  case 6: run(); break;\n"
    "  case 7: stop(); break;\n"
    "  }\n"
    "}\n"
)
RUNTIME_SWITCH = (
    "int _setmode(int fd, int m) {\n"
    "  switch (m) {\n"
    "  case 0: a(); break;\n"
    "  case 1: b(); break;\n"
    "  case 2: c(); break;\n"
    "  case 4: d(); break;\n"
    "  }\n"
    "  return 0;\n"
    "}\n"
)


def _ledger(cited: str, *, tool: str = "decompile_function", dispatcher: bool = True) -> EntryTexts:
    entries = [
        _entry("ev_0001", tool, json.dumps({"code": cited})),
        _entry("ev_0002", "decompile_function", json.dumps({"code": RUNTIME_SWITCH})),
    ]
    if dispatcher:
        entries.append(
            _entry("ev_0003", "decompile_function", json.dumps({"code": COMMAND_SWITCH}))
        )
    return EntryTexts.from_ledger(entries)


def _rows(first: str, label: str = "") -> dict[str, Any]:
    return _commands(
        (first, ["ev_0001"]),
        *((f"{label}{n}", ["ev_0003"]) for n in (5, 6, 7)),
    )


class TestACitedEntryHoldsANumberItComparesInAnyForm:
    @pytest.mark.parametrize(
        "code",
        [
            "void handler(int cmd) {\n  if (cmd == 4) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == 0x4) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (4 == cmd) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd != 4) {\n    return;\n  }\n  download();\n}\n",
            "void handler(int cmd) {\n  switch (cmd >> 1) {\n  case 4:\n    download();\n  }\n}\n",
            "cmp eax, 4\njz 0x401000\ncmp eax, 9\njz 0x401100",
            "CMP dword ptr [EBP + -0x8],0x4\nJZ LAB_00401000",
            "0040100a  83 f8 04  cmp eax, 4h\n0040100d  74 10     je 0x40101f",
        ],
    )
    @pytest.mark.parametrize(
        ("written", "label"), [("4", ""), ("0x4", ""), ("04", ""), ("COMMAND 4", "COMMAND ")]
    )
    def test_the_row_stands(self, code: str, written: str, label: str) -> None:
        assert cited_id_violations(_rows(written, label), _ledger(code)) == []

    @pytest.mark.parametrize(
        "code",
        [
            "void handler(int cmd) {\n  if (cmd == 14) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == 0x40) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == 4096) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == -4) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == 4 + base) {\n    download();\n  }\n}\n",
            "cmp eax, 40h\njz 0x401000\ncmp eax, 9\njz 0x401100",
        ],
    )
    def test_a_number_that_is_not_the_whole_operand_is_not_held(self, code: str) -> None:
        (found,) = cited_id_violations(_rows("4"), _ledger(code))

        assert "ev_0003 (decompile_function)" in found.message

    def test_readable_code_comparing_other_values_is_asked(self) -> None:
        code = "void handler(int cmd) {\n  if (cmd == 9) {\n    download();\n  }\n}\n"

        (found,) = cited_id_violations(_rows("4"), _ledger(code))

        assert found.message.startswith("Row 1 of commands states the id '4'")

    def test_code_the_reader_cannot_read_is_never_asked_about(self) -> None:
        # Declared code, in no form the reader knows: a doubt is silence.
        code = "MATCH cmd WITH\n| 4 -> download\n| 5 -> upload"

        assert cited_id_violations(_rows("4"), _ledger(code)) == []
        assert cited_id_violations(_rows("4"), _ledger(code, tool="disassemble_function")) == []


class TestTheEntryOfferedForANumber:
    HANDLER_9 = "void handler(int cmd) {\n  if (cmd == 9) {\n    download();\n  }\n}\n"

    def test_only_the_expression_holding_most_of_the_table_s_numbers(self) -> None:
        (found,) = cited_id_violations(_rows("4"), _ledger(self.HANDLER_9))

        assert "ev_0003 (decompile_function)" in found.message
        assert "ev_0002" not in found.message
        assert found.labels == ('"4" is not in ev_0001; ev_0003 (decompile_function) holds it',)

    def test_an_entry_that_merely_contains_the_number_is_never_offered(self) -> None:
        texts = _ledger(self.HANDLER_9, dispatcher=False)

        assert cited_id_violations(_rows("4"), texts) == []

    def test_entries_tied_on_the_most_are_all_offered(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "decompile_function", json.dumps({"code": self.HANDLER_9})),
                _entry("ev_0003", "decompile_function", json.dumps({"code": COMMAND_SWITCH})),
                _entry("ev_0004", "decompile_function", json.dumps({"code": COMMAND_SWITCH})),
            ]
        )

        (found,) = cited_id_violations(_rows("4"), texts)

        assert "ev_0003 (decompile_function), ev_0004 (decompile_function)" in found.message

    def test_one_number_picks_no_expression(self) -> None:
        assert _ledger(self.HANDLER_9).choosing({4}) == {}
        assert _ledger(self.HANDLER_9).choosing({4, 5, 6}) != {}


class TestAFailedCallHoldsNothing:
    def _texts(self) -> EntryTexts:
        return EntryTexts.from_ledger(
            [
                _entry("ev_0001", "strings", json.dumps({"strings": ["ERROR", "OK"]})),
                _entry("ev_0002", "decompile_function", json.dumps({"code": HANDLER})),
                LedgerEntry(
                    id="ev_0003", agent="a", server="s", tool="yara_scan", ok=False,
                    error="ERROR: rules not loaded", output="ERROR: rules not loaded",
                ),
                _entry("ev_0004", "list_imports", json.dumps({"error": "ERROR: no program"})),
                _entry("ev_0005", "get_info", "Error: binary not loaded"),
            ]
        )  # fmt: skip

    def test_a_failed_call_or_an_error_envelope_is_not_offered(self) -> None:
        (found,) = cited_id_violations(_commands(("ERROR", ["ev_0002"])), self._texts())

        assert "holds it in ev_0001 (strings)." in found.message
        for failed in ("ev_0003", "ev_0004", "ev_0005"):
            assert failed not in found.message

    @pytest.mark.parametrize("cited", ["ev_0003", "ev_0004", "ev_0005"])
    def test_citing_one_does_not_hold_the_id(self, cited: str) -> None:
        (found,) = cited_id_violations(_commands(("ERROR", [cited])), self._texts())

        assert "ev_0001 (strings)" in found.message


class TestTheOperandReader:
    @pytest.mark.parametrize(
        ("code", "held"),
        [
            ("cmp eax, 4h", {4}),
            ("if (c == 010) {\n  a();\n}\n", {8, 10}),
            ("cmpl $0x4,%eax", {4}),
            ("cmpq $4, -0x8(%rbp)", {4}),
            ("cmp r0, #4", {4}),
            ("cmp w0, #0x4", {4}),
            ("CMP dword ptr [EBP + -0x8],0x4", {4}),
            ("/* c == 4 */ x();", {4}),
            ('s = "c == 4";', {4}),
            ("switch (c) {\n  case 1 ... 5: a();\n}\n", {1, 2, 3, 4, 5}),
        ],
    )
    def test_a_compared_number_in_any_written_form(self, code: str, held: set[int]) -> None:
        assert held <= compared_operands(code)

    @pytest.mark.parametrize(
        "code", ["cmp eax, ebx", "cmpl %eax,%ebx", "x = arr[4];", "if (c == 4 + k) {}"]
    )
    def test_a_compare_without_a_number_or_a_sum_holds_none(self, code: str) -> None:
        assert 4 not in compared_operands(code)


class TestACompareTheReaderCannotTakeIsNotAsked:
    @pytest.mark.parametrize(
        "listing",
        [
            "  401000:\t83 f8 04             \tcmpl   $0x4,%eax\n"
            "  401003:\t74 10   \tje     401015\n",
            "0x00010000      cmp r0, #4\n0x00010004      beq 0x10020\n",
        ],
    )
    def test_a_compare_instruction_in_another_syntax_holds_its_number(self, listing: str) -> None:
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "disassemble_function", listing),
                _entry("ev_0003", "decompile_function", json.dumps({"code": COMMAND_SWITCH})),
            ]
        )

        assert not texts.code_not_read("ev_0001")
        assert cited_id_violations(_rows("4"), texts) == []

    @pytest.mark.parametrize(
        "code",
        [
            "0x1000  cmp w0, #4, lsl #12\n0x1004  b.eq 0x1020\n",
            "0x1000  cmp eax, 0b100\n0x1004  je 0x1020\n",
            "void handler(int cmd) {\n  switch (cmd) {\n  case 0 ... 9000:\n    run();\n  }\n}\n",
        ],
    )
    @pytest.mark.parametrize("tool", ["disassemble_function", "an_undeclared_tool"])
    def test_a_compare_whose_operands_are_not_taken_is_code_not_read(
        self, code: str, tool: str
    ) -> None:
        assert cited_id_violations(_rows("4"), _ledger(code, tool=tool)) == []


class TestACompareInstructionIsOneWhereAnInstructionStands:
    PROSE = (
        '{"how": "32-bit immediates of push, mov and cmp byte patterns in executable '
        'sections, and every aligned value in the other sections"}'
    )

    def test_the_word_in_prose_is_no_compare_not_taken(self) -> None:
        assert _read_compared_operands(self.PROSE) == (frozenset(), False)

    def test_a_row_citing_the_prose_is_still_asked(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "resolve_api_hashes", self.PROSE),
                _entry("ev_0003", "decompile_function", json.dumps({"code": COMMAND_SWITCH})),
            ]
        )

        (found,) = cited_id_violations(_rows("4"), texts)

        assert "ev_0003 (decompile_function)" in found.message

    @pytest.mark.parametrize(
        "listing",
        [
            "cmp w0, #4, lsl #12",
            "loc_401000: cmp eax, 0b100",
            ".text:00401000                 cmp     eax, 0b100",
            "│      0x00401000      83f804         cmp eax, 0b100",
        ],
    )
    def test_an_instruction_at_its_place_on_the_line_is_read(self, listing: str) -> None:
        assert _read_compared_operands(listing)[1] is True


class TestTheCaseRangesOfOneTextHaveOneBudget:
    @staticmethod
    def _ranges(count: int) -> str:
        return "".join(f"  case {n * 5000} ... {n * 5000 + 4000}:\n" for n in range(count))

    def test_many_ranges_are_a_compare_not_taken_read_fast_and_small(self) -> None:
        text = self._ranges(300)

        assert _read_compared_operands(text)[1] is True
        assert_under(lambda: _read_compared_operands(text), 1.0, what="300 wide ranges")
        assert peak_bytes(lambda: _read_compared_operands(text)) < 4_000_000

    def test_ranges_within_the_budget_hold_every_value(self) -> None:
        read, untaken = _read_compared_operands("case 1 ... 5:\ncase 0x100 ... 0x110:\n")

        assert not untaken
        assert read == {*range(1, 6), *range(0x100, 0x111)}

    def test_the_cost_of_many_ranges_grows_with_the_text(self) -> None:
        assert_scales(self._ranges, 4000, _read_compared_operands)


class TestARowIdIsCheckedOnlyWhereACoincidenceIsImplausible:
    HANDLER = "void handler(void) {\n  download();\n}\n"
    SWITCH_0_TO_4 = (
        "int _setmode(int m) {\n  switch (m) {\n"
        + "".join(f"  case {n}: f{n}(); break;\n" for n in range(5))
        + "  }\n}\n"
    )

    def _ledger(self, *codes: str) -> EntryTexts:
        return EntryTexts.from_ledger(
            [_entry("ev_0001", "decompile_function", json.dumps({"code": self.HANDLER}))]
            + [
                _entry(f"ev_{n + 2:04d}", "decompile_function", json.dumps({"code": code}))
                for n, code in enumerate(codes)
            ]
        )

    @pytest.mark.parametrize("ids", [("1", "2", "3", "4"), ("0", "1", "2", "3")])
    def test_a_table_whose_ids_are_a_plain_count_is_not_checked(self, ids: tuple[str]) -> None:
        payload = _commands(*((i, ["ev_0001"]) for i in ids))

        assert cited_id_violations(payload, self._ledger(self.SWITCH_0_TO_4)) == []

    def test_the_command_value_check_shares_the_count_guard(self) -> None:
        payload = _commands(("0", ["ev_0001"]), ("1", ["ev_0001"]), ("2", ["ev_0001"]))
        compared = [ComparedValues(where="ev_0002", subject="m", values=(0, 1, 2, 3))]

        assert command_value_violations(payload, compared) == []

    def test_fewer_than_four_numbered_ids_are_not_checked_its_text_ids_are(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "decompile_function", json.dumps({"code": self.HANDLER})),
                _entry("ev_0002", "decompile_function", json.dumps({"code": COMMAND_SWITCH})),
                _entry("ev_0003", "strings", json.dumps({"strings": ["PING"]})),
            ]
        )
        payload = _commands(
            ("4", ["ev_0001"]), ("5", ["ev_0001"]), ("6", ["ev_0001"]), ("PING", ["ev_0001"])
        )

        (found,) = cited_id_violations(payload, texts)

        assert found.message.startswith("Row 4 of commands states the id 'PING'")

    def test_entries_whose_expressions_hold_different_sets_offer_nothing(self) -> None:
        other = COMMAND_SWITCH.replace("case 7:", "case 9:").replace("on_command", "on_other")

        texts = self._ledger(COMMAND_SWITCH.replace("case 7:", "case 8:"), other)
        payload = _commands(*((str(n), ["ev_0001"]) for n in (4, 5, 6, 7)))

        assert cited_id_violations(payload, texts) == []

    def test_one_expression_read_in_two_entries_offers_both(self) -> None:
        texts = self._ledger(COMMAND_SWITCH, COMMAND_SWITCH)
        payload = _commands(("4", ["ev_0001"]), *((str(n), ["ev_0002"]) for n in (5, 6, 7)))

        (found,) = cited_id_violations(payload, texts)

        assert "ev_0002 (decompile_function), ev_0003 (decompile_function)" in found.message

    def test_an_expression_holding_two_of_five_ids_is_not_offered(self) -> None:
        two = "void f(int c) {\n  switch (c) {\n  case 4: a(); break;\n  case 5: b();\n  }\n}\n"
        payload = _commands(*((str(n), ["ev_0001"]) for n in (4, 5, 9, 11, 13)))

        assert cited_id_violations(payload, self._ledger(two)) == []


class TestAFailedEntryInTheNumberCheck:
    HANDLER_4 = "void handler(int cmd) {\n  if (cmd == 4) {\n    download();\n  }\n}\n"

    def test_an_entry_filed_as_failed_holds_nothing_even_with_a_plain_answer(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                LedgerEntry(
                    id="ev_0001", agent="a", server="s", tool="decompile_function", ok=False,
                    output=json.dumps({"code": self.HANDLER_4}),
                ),
                _entry("ev_0003", "decompile_function", json.dumps({"code": COMMAND_SWITCH})),
            ]
        )  # fmt: skip

        (found,) = cited_id_violations(_rows("4"), texts)

        assert "ev_0003 (decompile_function)" in found.message

    @pytest.mark.parametrize("failed", [True, False])
    def test_a_failed_entry_whose_code_holds_the_switch_is_never_offered(
        self, failed: bool
    ) -> None:
        handler = "void handler(void) {\n  download();\n}\n"
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "decompile_function", json.dumps({"code": handler})),
                LedgerEntry(
                    id="ev_0003", agent="a", server="s", tool="decompile_function",
                    ok=not failed, output=json.dumps({"code": COMMAND_SWITCH}),
                ),
            ]
        )  # fmt: skip

        found = cited_id_violations(_rows("4"), texts)

        assert (found == []) is failed


class TestWhenAnIdIsANumber:
    def test_a_common_label_before_the_number(self) -> None:
        code = "void handler(int cmd) {\n  if (cmd == 9) {\n    download();\n  }\n}\n"

        (found,) = cited_id_violations(_rows("COMMAND 4", "COMMAND "), _ledger(code))

        assert "ev_0003 (decompile_function)" in found.message

    def test_a_label_the_other_numbered_rows_do_not_share_is_text(self) -> None:
        code = "void handler(int cmd) {\n  if (cmd == 9) {\n    download();\n  }\n}\n"

        assert cited_id_violations(_rows("HTTP 4"), _ledger(code)) == []
        assert cited_id_violations(_rows("HTTP 4", "COMMAND "), _ledger(code)) == []


class TestWhatIsNotAsked:
    def test_a_row_citing_no_entry_with_text_or_nothing(self) -> None:
        payload = _commands(("0xc", ["ev_0999"]), ("0xc", []), ("", ["ev_0011"]))

        assert cited_id_violations(payload, _texts()) == []

    def test_a_row_citing_a_partial_entry(self) -> None:
        payload = _table(("0xc", ["ev_0011", "ev_0013"]))

        assert cited_id_violations(payload, _texts(partial=True)) == []
        assert cited_id_violations(payload, _texts()) != []

    def test_without_the_entries_nothing_is_judged(self) -> None:
        assert cited_id_violations(_commands(("0xc", ["ev_0011"])), None) == []
        assert cited_id_violations(None, _texts()) == []

    def test_odd_rows_raise_nothing(self) -> None:
        payload = {
            "commands": [None, "row", {"id": 7, "evidence_refs": "ev_0011"}, {"id": None}],
            "Odd Key": [{"id": "0xc", "evidence_refs": ["ev_0011"]}],
            "flags": {"not": "a list"},
        }

        assert cited_id_violations(payload, _texts()) == []


class TestTheFindingIsKeptAndMarked:
    def test_the_code_is_kept_marked_and_asked_by_value(self) -> None:
        assert ID_NOT_IN_CITED_ENTRY_CODE in KEPT_WITH_A_FINDING
        assert ID_NOT_IN_CITED_ENTRY_CODE in MARKED_IN_PLACE
        assert ID_NOT_IN_CITED_ENTRY_CODE in ASKED_BY_VALUE

    def test_the_message_never_carries_a_secret(self) -> None:
        secret = prefixed_key("ghs_")
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "strings", json.dumps({"strings": [f"token={secret}"]})),
                _entry("ev_0002", "strings", json.dumps({"strings": ["other"]})),
            ]
        )

        (found,) = cited_id_violations(_commands((f"token={secret}", ["ev_0002"])), texts)

        assert secret not in found.message

    def test_a_kept_row_is_marked_beside_its_evidence(self) -> None:
        rows = [
            CommandRow(id="0xc", name="upload", evidence_refs=["ev_0011"]),
            CommandRow(id="0x15", name="uninstall", evidence_refs=["ev_0010"]),
            CommandRow(id="2", name="shell", evidence_refs=["ev_0010"]),
            CommandRow(id="0x13", name="sleep", evidence_refs=["ev_0010"]),
        ]
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            technical_analysis=TechnicalAnalysis(commands=rows),
        )
        payload = {"commands": [row.model_dump() for row in rows]}
        record_flagged_statements(report, cited_id_violations(payload, _texts()))

        text = MarkdownRenderer().render(report)

        upload = next(line for line in text.splitlines() if "| upload" in line)
        assert "an id none of its cited entries holds" in upload
        assert "ev_0010 (batch_decompile) holds it" in upload
        uninstall = next(line for line in text.splitlines() if "| uninstall" in line)
        assert "cited entries holds" not in uninstall


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


class TestTheComposer:
    def test_compose_puts_the_check_on_the_command_table(self) -> None:
        seen: dict[str, list[Any]] = {}

        async def _author(self: Any, section: str, *args: Any, validators: Any = None) -> None:
            seen[section] = list(validators or [])

        comp = ReportComposer(llm=_RawLLM(), per_section_timeout=5)  # type: ignore[arg-type]
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), verdict="Malware"
        )
        with patch.object(ReportComposer, "_author", _author):
            asyncio.run(comp.compose(report, evidence=_texts()))

        found = [v for check in seen["commands"] for v in check(_table(("0xc", ["ev_0011"])))]
        assert ID_NOT_IN_CITED_ENTRY_CODE in [v.code for v in found]

    def test_a_row_the_model_fixes_is_taken(self) -> None:
        from langchain_core.messages import HumanMessage

        wrong = json.dumps(_table(("0xc", ["ev_0011"])))
        right = json.dumps(_table(("0xc", ["ev_0010", "ev_0011"])))
        llm = _RawLLM(wrong, right)
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        comp._entries = _texts()
        comp._citable = ["ev_0010", "ev_0011", "ev_0012", "ev_0013"]
        comp._report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), verdict="Malware"
        )
        with patch(
            "malspark.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            result = asyncio.run(
                comp._invoke(
                    [HumanMessage(content="write it")],
                    _CommandsOut,
                    section="commands",
                    validators=[lambda p: cited_id_violations(p, comp._entries)],
                )
            )

        assert len(llm.sent) == 2
        assert "ev_0010 (batch_decompile)" in str(llm.sent[1][-1].content)
        assert result is not None and result.commands[0].evidence_refs == ["ev_0010", "ev_0011"]
        assert comp.validation_tally.unresolved == []


def test_the_cost_grows_with_the_rows_and_the_entries_together() -> None:
    """Each entry's code is read once and each row looks its id up: no row reads every entry."""

    def build(size: int) -> Any:
        entries = [
            _entry(
                f"ev_{n:05d}",
                "decompile_function",
                json.dumps(
                    {"code": f"switch (p) {{ case {n}: a(); break; case {n + 1}: b(); break; }}"}
                ),
            )
            for n in range(1, size + 1)
        ]
        payload = _commands(*((str(n + 2), [f"ev_{n:05d}"]) for n in range(1, size + 1)))

        def call() -> list[Any]:
            return cited_id_violations(payload, EntryTexts.from_ledger(entries))

        return call

    assert_scales(build, 300)
