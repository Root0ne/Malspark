"""Each evidence root, and each reason a citation gives none, is written in one wording.

A technique's row stores the roots its citations read and one
``<citation>: no: <reason>`` per citation that gave none
(``analysis.evidence_roots``); the served report carries both lists, and the
ATT&CK table names a single root and counts the rest (``roots_phrase``). Each
root is written by its kind: a table of the file, the whole file, an external
assessment, a sandbox process, a network flow, a DNS query, a sandbox
signature, a file offset no section table places, and a place or the whole of
another file named by that file. Each reason says what the reading did and
gave: a failed call, a reference lookup, an answer whose reading gave no root
or a row of one it found nothing to place in, a call given a name and no
address or an address not read as a number, a repeat of nothing, a carved path
naming no one file, an address outside the named program, a file offset no
section table places against a stated base, a call site whose blobs decode to
other text, a signatures answer in which the reading found no process, no
signature row or no named one, an indicator the process list does not settle,
a match joined to no process by its command line, with a listing indexed or
none, a command line several processes share, a statement whose words pick out
none of an entry's rows, a signature item of several roots read where no
statement is, and a sandbox item whose row the reading found in no indexed
answer, that names nothing to place, states no pid, or that the reading places
at no single process or at no place. Each wording is pinned whole here under
the condition that writes it (T-770, T-816).

Every value is synthetic.
"""

from __future__ import annotations

from typing import Any

from malspark.analysis.evidence_roots import roots_phrase, run_roots
from malspark.schemas.evidence import LedgerEntry

SECTIONS = [
    {
        "name": ".text",
        "virtual_address": "0x1000",
        "virtual_size": 0x1000,
        "raw_offset": 0x400,
        "raw_size": 0x1000,
    },
    {
        "name": ".rdata",
        "virtual_address": "0x9000",
        "virtual_size": 0x1000,
        "raw_offset": 0x1400,
        "raw_size": 0x1000,
    },
]
COMMAND = "cmd.exe /c whoami"


def _entry(eid: str, tool: str, structured: Any = None, **kwargs: Any) -> LedgerEntry:
    return LedgerEntry(id=eid, tool=tool, structured=structured, agent="pipeline", **kwargs)


def _sample_pe(**structured: Any) -> LedgerEntry:
    return _entry(
        "ev_0001",
        "pe_info",
        {"image_base": "0x400000", "sections": SECTIONS, **structured},
        args={"path": "/stage/sample.exe"},
    )


def _said(ledger: list[LedgerEntry], *cited: str) -> tuple[list[str], list[str]]:
    """The roots and reasons one statement citing ``cited`` gives, naming no row."""
    said: tuple[list[str], list[str]] = run_roots(ledger).of_statement("as cited", list(cited))
    return said


class TestEachRootIsWrittenByItsKind:
    def test_the_tables_of_the_file_and_its_sections(self) -> None:
        pe = _sample_pe(
            imports=[{"dll": "KERNEL32.dll", "function": "VirtualAlloc"}],
            exports=["run"],
            resources=[{"name": "RT_ICON"}],
            pdb_path="C:\\build\\x.pdb",
            overlay={"present": True},
        )

        assert run_roots([pe]).of_entry("ev_0001").roots == [
            "the PE header",
            "the import table",
            "the export table",
            "section .text",
            "section .rdata",
            "the resource table",
            "the debug directory",
            "the overlay",
        ]

    def test_a_header_with_no_table_is_the_header_alone(self) -> None:
        pe = _entry("ev_0001", "pe_info", {})

        assert run_roots([pe]).of_entry("ev_0001").roots == ["the PE header"]

    def test_a_disassembler_s_import_and_export_listings_are_those_tables(self) -> None:
        roots = run_roots(
            [
                _entry("ev_0002", "get_imports", output="VirtualAlloc"),
                _entry("ev_0003", "get_exports", output="run"),
            ]
        )

        assert roots.of_entry("ev_0002").roots == ["the import table"]
        assert roots.of_entry("ev_0003").roots == ["the export table"]

    def test_the_whole_file_and_an_external_assessment_of_it(self) -> None:
        roots = run_roots(
            [
                _entry("ev_0004", "hashes", {"sha256": "a" * 64}),
                _entry("ev_0005", "get_file_report", {"data": {}}),
            ]
        )

        assert roots.of_entry("ev_0004").roots == ["the whole file"]
        assert roots.of_entry("ev_0005").roots == ["an external assessment of the whole file"]

    def test_a_rule_match_with_no_offset_is_the_whole_file(self) -> None:
        match = {"matches": [{"rule": "packed", "strings": []}]}

        assert run_roots([_entry("ev_0006", "yara_scan", match)]).of_entry("ev_0006").roots == [
            "the whole file"
        ]

    def test_a_process_a_flow_a_query_and_a_signature(self) -> None:
        roots = run_roots(
            [
                _entry("ev_0010", "sandbox_processes", {"processes": [{"pid": 84}]}),
                _entry(
                    "ev_0011",
                    "sandbox_network",
                    {"tcp": [{"dst": "192.0.2.7", "dport": 443}], "dns": [{"request": "c2.test"}]},
                ),
                _entry(
                    "ev_0012", "sandbox_signatures", {"signatures": [{"name": "Writes elsewhere"}]}
                ),
            ]
        )

        assert roots.of_entry("ev_0010").roots == ["sandbox process 84"]
        assert roots.of_entry("ev_0011").roots == [
            "network flow tcp to 192.0.2.7:443",
            "DNS query c2.test",
        ]
        assert roots.of_entry("ev_0012").roots == ["sandbox signature Writes elsewhere"]

    def test_a_file_offset_no_section_table_places_is_written_as_one(self) -> None:
        strings = _entry("ev_0013", "strings", {"strings": [{"offset": 0x500, "text": "abc"}]})

        assert run_roots([strings]).of_entry("ev_0013").roots == ["file offset 0x500"]

    def test_a_root_of_another_file_names_that_file(self) -> None:
        digest = "ab" * 32
        roots = run_roots(
            [
                _sample_pe(),
                _entry(
                    "ev_0020",
                    "strings",
                    {"strings": [{"offset": 0x500, "text": "abc"}]},
                    args={"carved_path": "payload.bin"},
                ),
                _entry(
                    "ev_0021",
                    "carve_payloads",
                    {"payloads": [{"carved_path": "/staged/drop.bin", "sha256": digest}]},
                ),
                _entry("ev_0022", "hashes", {}, args={"carved_path": "/staged/drop.bin"}),
            ]
        )

        assert roots.of_entry("ev_0020").roots == ['file offset 0x500 of file "payload.bin"']
        assert roots.of_entry("ev_0022").roots == [f"the whole of file sha256 {digest[:12]}"]

    def test_a_root_of_the_sample_names_no_file(self) -> None:
        sample = {"path": "/stage/sample.exe"}
        roots = run_roots([_sample_pe(), _entry("ev_0023", "hashes", {}, args=sample)])

        assert roots.of_entry("ev_0023").roots == ["the whole file"]


class TestAnEntryThatGivesNoRootSaysWhy:
    def test_a_failed_call_a_reference_lookup_and_a_call_by_name(self) -> None:
        ledger = [
            _entry("ev_0030", "decompile_function", ok=False, args={"address": "0x1100"}),
            _entry("ev_0031", "get_ip_report", {"data": {}}),
            _entry("ev_0032", "decompile_function", args={"name": "main"}),
        ]

        assert _said(ledger, "ev_0030", "ev_0031", "ev_0032") == (
            [],
            [
                "ev_0030: no: the call failed, so it read nothing",
                "ev_0031: no: get_ip_report is a reference lookup and reads nothing of the sample",
                "ev_0032: no: the call is given a name and no address, and reading its answer "
                "gave no root",
            ],
        )

    def test_an_answer_with_nothing_to_place(self) -> None:
        ledger = [_entry("ev_0033", "decompile_function", {"code": "int f();"})]

        assert _said(ledger, "ev_0033") == (
            [],
            ["ev_0033: no: reading decompile_function's answer gave no root"],
        )

    def test_an_entry_naming_no_tool_says_the_tool(self) -> None:
        ledger = [_entry("ev_0033", "sigscan__", {"x": 1})]

        assert _said(ledger, "ev_0033") == (
            [],
            ["ev_0033: no: reading the tool's answer gave no root"],
        )

    def test_a_rule_row_with_no_address_says_so_for_its_technique(self) -> None:
        capa = _entry(
            "ev_0034",
            "capa",
            {
                "capabilities": [
                    {"rule": "hash names", "attck": ["T1027"], "addresses": ["0x401100"]},
                    {"rule": "xor loop", "attck": ["T1140"]},
                ]
            },
        )
        roots = run_roots([_sample_pe(), capa])

        assert roots.of_assertion("ev_0034", "T1027") == (["0x1100 in .text"], [])
        assert roots.of_assertion("ev_0034", "T1140") == (
            [],
            [
                "ev_0034: no: the reading found nothing to place in a row of capa's answer that "
                "the statement's words or the technique pick out"
            ],
        )

    def test_a_repeat_of_no_entry_holding_an_answer(self) -> None:
        ledger = [_entry("ev_0035", "decompile_function", repeated_of="ev_0999")]

        assert _said(ledger, "ev_0035") == (
            [],
            ["ev_0035: no: ev_0035 repeats an entry that holds no answer"],
        )

    def test_a_carved_path_naming_no_one_file(self) -> None:
        ledger = [_entry("ev_0036", "strings", {"strings": []}, args={"carved_path": ["a", "b"]})]

        assert _said(ledger, "ev_0036") == (
            [],
            ["ev_0036: no: the call's carved_path names no one file"],
        )

    def test_an_address_outside_the_program_the_server_last_named(self) -> None:
        ledger = [
            _sample_pe(),
            _entry(
                "ev_0037",
                "get_current_program_info",
                {"image_base": "0x10000000", "name": "payload.dll"},
            ),
            _entry("ev_0038", "decompile_function", args={"address": "0x10001100"}),
            _entry("ev_0039", "decompile_function", args={"address": "0x401100"}),
        ]

        assert _said(ledger, "ev_0038", "ev_0039") == (
            ['0x1100 of file "payload.dll"'],
            ["ev_0039: no: the address lies outside the program the server last named"],
        )

    def test_a_file_offset_against_a_base_with_no_section_table(self) -> None:
        ledger = [
            _entry("ev_0040", "function_index", {"image_base": "0x400000", "rows": []}),
            _entry("ev_0041", "strings", {"strings": [{"offset": 0x500, "text": "abc"}]}),
        ]

        assert _said(ledger, "ev_0041") == (
            [],
            [
                "ev_0041: no: the file states an image base and no section table, so a file "
                "offset cannot be placed against its addresses"
            ],
        )

    def test_a_call_site_whose_blobs_decode_to_other_text(self) -> None:
        ledger = [
            _sample_pe(),
            _entry(
                "ev_0042",
                "decode_string_blobs",
                {
                    "results": [
                        {
                            "rva": "0x9100",
                            "text": "alpha.test",
                            "floss": {"called_at_rva": "0x1200"},
                        }
                    ]
                },
            ),
            _entry(
                "ev_0043",
                "floss",
                {"strings": [{"string": "bravo.test", "called_at_rva": "0x1200"}]},
            ),
        ]

        assert _said(ledger, "ev_0043") == (
            [],
            [
                "ev_0043: no: the call site holds blobs the blob decoder read, and none of "
                "them decodes to this text"
            ],
        )


class TestASandboxSignatureOrCommandLineThatGivesNoProcessSaysWhy:
    def test_a_signatures_answer_with_no_signature_row_and_no_indicator_row_read(self) -> None:
        ledger = [_entry("ev_0050", "sandbox_signatures", {"indicators": [], "matched": 0})]

        assert _said(ledger, "ev_0050") == (
            [],
            [
                "ev_0050: no: the reading found no signature row and read no indicator row in "
                "the answer"
            ],
        )

    def test_an_indicator_naming_a_process_the_list_does_not_settle(self) -> None:
        page = _entry(
            "ev_0051",
            "sandbox_signatures",
            {
                "indicators": [
                    {
                        "signature": "Writes elsewhere",
                        "process": {"id": "91", "not_settled": "listed in 2 tasks"},
                        "description": "an act",
                    }
                ]
            },
        )

        assert _said([page], "ev_0051") == (
            [],
            [
                "ev_0051: no: the process a sandbox signature's indicator names is not one the "
                "report's process list settles"
            ],
        )

    def test_a_command_line_of_no_recorded_process_and_of_several(self) -> None:
        def match(eid: str, command: str) -> LedgerEntry:
            return _entry(
                eid,
                "sigma_match_sandbox",
                {"matches": [{"matched_fields": {"CommandLine": command}, "tags": []}]},
            )

        processes = {
            "processes": [
                {"pid": 84, "command_line": COMMAND},
                {"pid": 90, "command_line": "ping 127.0.0.1"},
                {"pid": 91, "command_line": "ping 127.0.0.1"},
            ]
        }
        ledger = [
            _entry("ev_0052", "sandbox_processes", processes),
            match("ev_0053", COMMAND),
            match("ev_0054", "powershell -enc AAAA"),
            match("ev_0055", "ping 127.0.0.1"),
        ]

        assert _said(ledger, "ev_0053", "ev_0054", "ev_0055") == (
            ["sandbox process 84"],
            [
                "ev_0054: no: the reading joined the match by command line to none of the "
                "process rows it indexed",
                "ev_0055: no: more than one process the sandbox recorded has this command line",
            ],
        )

    def test_a_statement_whose_words_pick_out_none_of_an_entry_s_rows(self) -> None:
        ledger = [_entry("ev_0056", "sandbox_processes", {"processes": [{"pid": 84}, {"pid": 85}]})]

        assert _said(ledger, "ev_0056") == (
            [],
            ["ev_0056: no: the statement's words, as read, pick out none of ev_0056's rows"],
        )
        assert run_roots(ledger).of_statement("pid 85 ran", ["ev_0056"]) == (
            ["sandbox process 85"],
            [],
        )


class TestASandboxItemThatGivesNoRootSaysWhy:
    @staticmethod
    def _ledger() -> list[LedgerEntry]:
        index = _entry(
            "ev_0060",
            "sandbox_sections",
            {
                "sections": {
                    "processes": {
                        "items": 3,
                        "prefix": "proc",
                        "pids": [[84, 84]],
                        "repeats": [[84, 2]],
                        "unstated": [[3, 3]],
                    },
                    "network": {"items": 4, "prefix": "net"},
                    "files": {"items": 1, "prefix": "file"},
                }
            },
        )
        processes = _entry("ev_0061", "sandbox_processes", {"processes": [{"pid": 84}]})
        network = _entry(
            "ev_0062",
            "sandbox_items",
            {
                "section": "network",
                "items": [
                    {"id": "net:1", "kind": "tcp", "fields": {"dst": "192.0.2.7", "dport": 443}},
                    {"id": "net:2", "kind": "dns", "fields": {"request": "c2.test"}},
                    {"id": "net:3", "kind": "http", "fields": {"url": "/gate"}},
                ],
            },
            args={"section": "network"},
        )
        return [index, processes, network]

    def test_a_process_flow_and_query_item_give_their_roots(self) -> None:
        assert _said(self._ledger(), "proc:84", "net:1", "net:2") == (
            ["sandbox process 84", "network flow tcp to 192.0.2.7:443", "DNS query c2.test"],
            [],
        )

    def test_each_item_that_gives_none_says_why(self) -> None:
        assert _said(self._ledger(), "net:3", "file:1", "net:4", "proc:p3", "proc:84.2") == (
            [],
            [
                "net:3: no: a sandbox `network` item names no process, flow or query to place",
                "file:1: no: a sandbox `files` item names no process, flow or query to place",
                "net:4: no: the reading found no row of net:4 in the answers it indexed",
                "proc:p3: no: the report states no pid for this process",
                "proc:84.2: no: the reading found no single process at proc:84.2 in the "
                "listings of processes it indexed",
            ],
        )


class TestTheRowSaysHowManyRootsItHas:
    def test_one_root_is_named_and_several_are_counted(self) -> None:
        assert roots_phrase(["the import table"], []) == "one evidence root (the import table)"
        assert roots_phrase(["a", "b", "c"], []) == "3 evidence roots"

    def test_the_citations_that_gave_none_are_counted_beside_them(self) -> None:
        assert roots_phrase(["the import table"], ["ev_1: no: x"]) == (
            "one evidence root (the import table), and 1 citation whose root could not be read"
        )
        assert roots_phrase([], ["ev_1: no: x", "ev_2: no: y"]) == (
            "no evidence root read (2 citations whose root could not be read)"
        )

    def test_a_row_with_neither_says_nothing(self) -> None:
        assert roots_phrase([], []) == ""
