"""A citation's reason for giving no root says what the reading did and what it gave.

Each ``<citation>: no: <reason>`` a technique's row stores
(``analysis.evidence_roots``) is in the reader's voice: what was read and what
that reading gave, never what an answer, a row or a statement holds or names.
An entry whose reading gave no root says so; a row of an entry that gives
roots, picked out by a statement's words or by the technique it names, in
which the reading found nothing to place, says that, in one wording for both
pickings so a technique's row counts it once. A call given a name says whether
it was given an address, and an address given says why it gave none; a match
says whether a process listing was indexed to join its command line against;
a signatures answer says what the reading found and read; a sandbox item says
where the reading looked. Each form carries only the values the reason it
replaces carried, and names no tool, server or sample (T-816).

Every value is synthetic.
"""

from __future__ import annotations

import ast
import inspect
import re
from typing import Any

from malspark.analysis import evidence_roots as er
from malspark.analysis.evidence_roots import RootCount, run_roots
from malspark.schemas.evidence import LedgerEntry

SECTIONS = [
    {
        "name": ".text",
        "virtual_address": "0x1000",
        "virtual_size": 0x1000,
        "raw_offset": 0x400,
        "raw_size": 0x1000,
    },
]
COMMAND = "cmd.exe /c whoami"

# Every form T-816 writes, as each is written for one value.
FORMS = {
    "NOTHING_TO_PLACE": er.NOTHING_TO_PLACE,
    "ROW_NOTHING_TO_PLACE": er.ROW_NOTHING_TO_PLACE,
    "NAMES_NO_ROW": er.NAMES_NO_ROW,
    "ROWS_UNCHOSEN": er.ROWS_UNCHOSEN,
    "BY_NAME_ONLY": er.BY_NAME_ONLY,
    "ADDRESS_NOT_NUMBER": er.ADDRESS_NOT_NUMBER,
    "MATCH_UNPLACED": er.MATCH_UNPLACED,
    "MATCH_NO_LISTING": er.MATCH_NO_LISTING,
    "ITEM_ROW_UNREAD": er.ITEM_ROW_UNREAD,
    "SIGNATURE_UNPLACED": er.SIGNATURE_UNPLACED,
    "SIGNATURES_NONE": er.SIGNATURES_NONE,
    "SIGNATURE_NAMES_NONE": er.SIGNATURE_NAMES_NONE,
    "SIGNATURE_ITEM_UNREAD": er.SIGNATURE_ITEM_UNREAD,
    "ITEM_UNSETTLED": er.ITEM_UNSETTLED,
    "REPEAT_UNPLACED": er.REPEAT_UNPLACED,
}


def _entry(eid: str, tool: str, structured: Any = None, **kwargs: Any) -> LedgerEntry:
    return LedgerEntry(id=eid, tool=tool, structured=structured, agent="pipeline", **kwargs)


def _sample_pe() -> LedgerEntry:
    return _entry(
        "ev_0001",
        "pe_info",
        {"image_base": "0x400000", "sections": SECTIONS},
        args={"path": "/stage/sample.exe"},
    )


def _rules() -> LedgerEntry:
    """A rule answer of two placed rows and one row with no address."""
    return _entry(
        "ev_0008",
        "capa",
        {
            "capabilities": [
                {"rule": "get system information", "attck": ["T1082"], "addresses": ["0x401350"]},
                {"rule": "get disk size", "attck": ["T1082"], "addresses": ["0x401eac"]},
                {"rule": "reference anti-VM strings", "attck": ["T1497.001"], "addresses": []},
            ]
        },
    )


class TestAnUnplacedRowOfAnEntryThatGivesRoots:
    def test_a_row_the_statement_quotes_says_the_reading_found_nothing_to_place_in_it(
        self,
    ) -> None:
        roots, reasons = run_roots([_sample_pe(), _rules()]).of_statement(
            'It checks for a VM ("reference anti-VM strings") [ev_0008].', ["ev_0008"]
        )

        assert roots == []
        assert reasons == [
            "ev_0008: no: the reading found nothing to place in a row of capa's answer that the "
            "statement's words or the technique pick out"
        ]
        # The entry gave roots: no reason says its reading gave none.
        assert run_roots([_sample_pe(), _rules()]).of_entry("ev_0008").roots == [
            "0x1350 in .text",
            "0x1eac in .text",
        ]

    def test_the_row_a_technique_names_is_said_in_the_same_words(self) -> None:
        found = run_roots([_sample_pe(), _rules()])

        assert found.of_assertion("ev_0008", "T1497.001") == (
            [],
            [
                "ev_0008: no: the reading found nothing to place in a row of capa's answer that "
                "the statement's words or the technique pick out"
            ],
        )

    def test_a_statement_and_an_assertion_of_one_row_count_one_reason(self) -> None:
        found = run_roots([_sample_pe(), _rules()])
        counted = RootCount()
        counted.add(
            *found.of_statement('A VM check ("reference anti-VM strings") [ev_0008].', ["ev_0008"])
        )
        counted.add(*found.of_assertion("ev_0008", "T1497.001"))

        assert len(counted.not_read) == 1

    def test_a_declared_row_the_statement_quotes_is_said_in_the_same_words(self) -> None:
        declared = LedgerEntry(
            id="ev_0010",
            seq=1,
            agent="static",
            tool="operator_scan",
            source="mcp:invented",
            output="{}",
            structured={"m": [{"o": "0x500", "n": "first"}, {"n": "beacon_cfg"}]},
            facts={
                "v": 1,
                "kind": "event_rules",
                "rows": "/m/*",
                "places": {"offset": "/o"},
                "values": {"name": "/n"},
            },
        )
        found = run_roots([declared])

        assert found.of_entry("ev_0010").roots
        assert found.of_statement("It holds `beacon_cfg` [ev_0010].", ["ev_0010"]) == (
            [],
            [
                "ev_0010: no: the reading found nothing to place in a row of operator_scan's "
                "answer that the statement's words or the technique pick out"
            ],
        )

    def test_an_entry_none_of_whose_rows_gives_a_root_says_its_reading_gave_none(self) -> None:
        bare = _entry(
            "ev_0009", "capa", {"capabilities": [{"rule": "xor loop", "attck": ["T1140"]}]}
        )

        assert run_roots([_sample_pe(), bare]).of_entry("ev_0009").reason == (
            "no: reading capa's answer gave no root"
        )


class TestAStatementPickingOutNoRow:
    def test_a_value_two_rows_hold_picks_out_neither(self) -> None:
        listing = _entry(
            "ev_0012",
            "sandbox_processes",
            {
                "processes": [
                    {"pid": 83, "name": "rundll32.exe"},
                    {"pid": 87, "name": "rundll32.exe"},
                ]
            },
        )

        assert run_roots([listing]).of_statement("`rundll32.exe` ran [ev_0012].", ["ev_0012"]) == (
            [],
            ["ev_0012: no: the statement's words, as read, pick out none of ev_0012's rows"],
        )


class TestACallGivenANameSaysWhatItWasGiven:
    @staticmethod
    def _program() -> list[LedgerEntry]:
        return [
            _sample_pe(),
            _entry(
                "ev_0037",
                "get_current_program_info",
                {"image_base": "0x10000000", "name": "payload.dll"},
            ),
        ]

    def test_a_name_and_no_address(self) -> None:
        ledger = [_entry("ev_0041", "query_calls", {"rows": []}, args={"name": "Create"})]

        assert run_roots(ledger).of_entry("ev_0041").reason == (
            "no: the call is given a name and no address, and reading its answer gave no root"
        )

    def test_an_address_outside_the_named_program_says_so_beside_a_name(self) -> None:
        call = _entry("ev_0038", "decompile_function", args={"address": "0x401100", "name": "main"})

        assert run_roots([*self._program(), call]).of_entry("ev_0038").reason == (
            "no: the address lies outside the program the server last named"
        )

    def test_an_address_not_read_as_a_number_says_so_beside_a_name(self) -> None:
        call = _entry("ev_0039", "decompile_function", args={"address": "start", "name": "main"})

        assert run_roots([call]).of_entry("ev_0039").reason == (
            "no: the call's address argument is not read as a number, and reading its answer "
            "gave no root"
        )


class TestAMatchJoinedToNoProcess:
    @staticmethod
    def _match() -> LedgerEntry:
        return _entry(
            "ev_0054",
            "sigma_match_sandbox",
            {"matches": [{"matched_fields": {"CommandLine": COMMAND}, "tags": []}]},
        )

    def test_a_listing_whose_rows_the_reading_did_not_index_by_command_line(self) -> None:
        listing = _entry(
            "ev_0052", "sandbox_processes", {"processes": [{"pid": "84", "command_line": COMMAND}]}
        )

        assert run_roots([listing, self._match()]).of_entry("ev_0054").reason == (
            "no: the reading joined the match by command line to none of the process rows it "
            "indexed"
        )

    def test_no_listing_read(self) -> None:
        assert run_roots([self._match()]).of_entry("ev_0054").reason == (
            "no: the reading joined the match by command line to no process, and it indexed no "
            "listing of processes"
        )


class TestASignaturesAnswerSaysWhatTheReadingFound:
    def test_an_indicator_row_with_no_process(self) -> None:
        page = _entry(
            "ev_0085",
            "sandbox_signatures",
            {"indicators": [{"signature": "Writes", "description": "an act"}]},
        )

        assert run_roots([page]).of_entry("ev_0085").reason == (
            "no: the reading found no process in a sandbox signature's indicator row"
        )

    def test_signature_rows_none_of_them_named(self) -> None:
        page = _entry("ev_0086", "sandbox_signatures", {"signatures": [{"severity": 2}]})

        assert run_roots([page]).of_entry("ev_0086").reason == (
            "no: the reading found no signature name and read no indicator row in the answer"
        )

    def test_no_signature_row(self) -> None:
        page = _entry("ev_0087", "sandbox_signatures", {"signatures": []})

        assert run_roots([page]).of_entry("ev_0087").reason == (
            "no: the reading found no signature row and read no indicator row in the answer"
        )


class TestASandboxItemSaysWhereTheReadingLooked:
    @staticmethod
    def _index() -> LedgerEntry:
        return _entry(
            "ev_0060",
            "sandbox_sections",
            {
                "sections": {
                    "processes": {
                        "items": 2,
                        "prefix": "proc",
                        "pids": [[84, 84]],
                        "repeats": [[84, 2]],
                    },
                    "network": {"items": 1, "prefix": "net"},
                    "signatures": {"items": 1, "prefix": "sig"},
                }
            },
        )

    def test_a_network_item_only_a_paged_answer_holds(self) -> None:
        paged = _entry(
            "ev_0063",
            "sandbox_network",
            {"tcp": [{"dst": "192.0.2.7", "dport": 443}]},
            args={"limit": 1},
        )

        assert run_roots([self._index(), paged]).of_item("net:1") == (
            "",
            "no: the reading found no row of net:1 in the answers it indexed",
        )

    def test_a_signature_item_no_answer_gave_indicator_rows_for(self) -> None:
        assert run_roots([self._index()]).of_item("sig:1") == (
            "",
            "no: the reading found no indicator row of the signature item in the answers it "
            "indexed",
        )

    def test_a_repeat_past_the_listing_and_a_repeat_part_that_is_no_place(self) -> None:
        found = run_roots(
            [self._index(), _entry("ev_0061", "sandbox_processes", {"processes": [{"pid": 84}]})]
        )

        assert found.of_item("proc:84.2") == (
            "",
            "no: the reading found no single process at proc:84.2 in the listings of processes "
            "it indexed",
        )
        items = _entry(
            "ev_0064",
            "sandbox_items",
            {"section": "processes", "items": [{"id": "proc:84.0", "kind": "processes"}]},
            args={"section": "processes"},
        )
        held = run_roots(
            [
                self._index(),
                _entry("ev_0061", "sandbox_processes", {"processes": [{"pid": 84}]}),
                items,
            ]
        )
        assert held.of_entry("ev_0064").reason == (
            "no: the reading takes no place from the repeat part of proc:84.0"
        )

    def test_a_signature_item_of_several_roots_read_where_no_statement_is(self) -> None:
        listing = _entry(
            "ev_0011",
            "sandbox_processes",
            {"processes": [{"pid": 85, "name": "a.exe"}, {"pid": 87, "name": "b.exe"}]},
        )
        rows = [
            {"process": {"id": "85", "image": "a.exe"}, "target": {"id": "87", "image": "b.exe"}}
        ]
        signatures = _entry(
            "ev_0089",
            "sandbox_items",
            {
                "section": "signatures",
                "items": [{"id": "sig:1", "kind": "signatures", "indicators": rows}],
            },
            args={"section": "signatures"},
        )

        assert run_roots([listing, self._index(), signatures]).of_item("sig:1") == (
            "",
            "no: reading sig:1 gave more than one root, and which one is meant is not read here",
        )


class TestEachFormCarriesOnlyItsOldValuesAndNamesNoTool:
    def test_each_form_interpolates_only_the_values_the_reason_it_replaces_did(self) -> None:
        held = {name: set(re.findall(r"{(\w+)}", form)) for name, form in FORMS.items()}

        assert held == {
            "NOTHING_TO_PLACE": {"tool"},
            "ROW_NOTHING_TO_PLACE": {"tool"},
            "NAMES_NO_ROW": {"entry"},
            "ROWS_UNCHOSEN": {"entry"},
            "BY_NAME_ONLY": set(),
            "ADDRESS_NOT_NUMBER": set(),
            "MATCH_UNPLACED": set(),
            "MATCH_NO_LISTING": set(),
            "ITEM_ROW_UNREAD": {"item"},
            "SIGNATURE_UNPLACED": set(),
            "SIGNATURES_NONE": set(),
            "SIGNATURE_NAMES_NONE": set(),
            "SIGNATURE_ITEM_UNREAD": set(),
            "ITEM_UNSETTLED": {"item"},
            "REPEAT_UNPLACED": {"item"},
        }

    def test_no_form_names_a_shipped_tool_or_server(self) -> None:
        from malspark.core import builtin_declarations as built

        names: set[str] = {*built.builtin_server_names(), *built.provider_names()}

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                for key, held in value.items():
                    if key == "tool_facts" and isinstance(held, dict):
                        names.update(str(name) for name in held)
                    walk(held)

        for blocks in (built._SERVER_BLOCKS, built._PROVIDER_BLOCKS, built._IN_PROCESS_BLOCKS):
            walk(blocks)
        words = {name: set(re.findall(r"[a-z0-9_]+", form.lower())) for name, form in FORMS.items()}

        assert len(names) > 20
        assert {name: sorted(w & names) for name, w in words.items() if w & names} == {}

    def test_the_conditions_added_hold_no_literal_but_a_separator(self) -> None:
        held: set[str] = set()
        for helper in (er._address_list, er._addresses_given):
            body = ast.parse(inspect.getsource(helper)).body[0]
            assert isinstance(body, ast.FunctionDef)
            for statement in body.body[1:]:  # the docstring left out
                held |= {
                    node.value
                    for node in ast.walk(statement)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                }

        assert held <= {",", ""}
