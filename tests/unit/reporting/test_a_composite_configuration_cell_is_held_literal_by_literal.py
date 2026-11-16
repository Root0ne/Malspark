"""A configuration cell is held literal by literal; a value read out of a longer run is not asked.

A configuration cell often states several values in one sentence: a module, a
fallback and the call that loads them, or a hive written beside its handle.
The check read the whole cell as one value, and almost every such cell was
asked about although each value it states stands in an entry the row cites.
The model was then told to write the value as the entry records it, and wrote
C escapes and sign-extended handles into the report.

The rule now:

- a configuration cell that states several literals is held when some cited
  entry holds each literal it states; a path is one literal, never split, and
  a cell with no literal, or whose only literals are numbers, is read whole;
- an identifier row is never split;
- a doubled backslash, as a C string writes it, and a 32-bit constant
  sign-extended to 64 bits are spellings of the same value, and a leading
  registry hive is held by its name or by its predefined handle;
- a value a cited entry holds only inside a longer run of letters or digits
  is recorded under its own code and never asked; a short one, or one that
  cuts a number, is asked as any value no cited entry holds;
- the question names the literals no cited entry holds and, for a path, what
  the entry holds of it.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from malspark.agents._indicator_denylists import inside_a_longer_token
from malspark.pipeline.validation import (
    ASKED_BY_NO_TURN,
    KEPT_WITH_A_FINDING,
    STATED_VALUE_INSIDE_A_TOKEN_CODE,
    STATED_VALUE_UNHELD_CODE,
    EntryTexts,
    Violation,
    asked_in_this_mode,
    raised_only_in_retry,
    stated_value_violations,
)
from malspark.reporting.composer import ReportComposer, _HostIdentifiersOut
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.schemas.evidence import LedgerEntry
from tests.linear_cost import assert_under

# A decompile as a tool returns it: JSON around C source, whose string
# literals double each backslash.
_CODE = (
    "void fun_140001000(void) {\n"
    '  lvar4 = fun_14003b1d0(0xffffffff80000001, "Software\\\\ExampleVendor\\\\Tool\\\\Hosts");\n'
    '  pcvar13 = "SOFTWARE\\\\ExampleVendor\\\\Tool";\n'
    '  name = "InstallDir";\n'
    '  hmod = LoadLibraryA("ws2_32.dll");\n'
    "  WSAStartup(0x202, &data);\n"
    "}\n"
)


def _entry(entry_id: str, tool: str, output: str) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="pipeline", server="pipeline", tool=tool, output=output)


def _texts() -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _entry("ev_0010", "batch_decompile", json.dumps({"code": _CODE})),
            _entry(
                "ev_0011",
                "strings",
                json.dumps({"strings": ["wsock32.dll", "GetProcAddress", "C:\\Users\\Public"]}),
            ),
            # A run-together string pool: values written with no separator.
            _entry(
                "ev_0012",
                "strings",
                json.dumps(
                    {
                        "strings": [
                            "txtExampleNoteFile-READ.txtServiceNameAlpha",
                            "ExampleCounter123456789",
                            "ExampleCache.dat.bak",
                            "evil.exe",
                            "usageError: --alpha cannot be combined with --beta.zz",
                        ]
                    }
                ),
            ),
        ]
    )


def _items(value: str, *refs: str) -> dict[str, Any]:
    return {
        "items": [
            {
                "key": "Setting",
                "value": value,
                "how_obtained": "decompiled",
                "evidence_refs": list(refs),
            }
        ]
    }


def _identifiers(value: str, *refs: str) -> dict[str, Any]:
    return {"identifiers": [{"kind": "string", "value": value, "evidence_refs": list(refs)}]}


def _codes(found: list[Violation]) -> list[str]:
    return [v.code for v in found]


class TestACompositeCell:
    def test_a_composite_cell_is_held_when_every_literal_it_states_is_held(self) -> None:
        cell = "ws2_32.dll (primary), wsock32.dll (fallback), loaded by LoadLibraryA"

        assert stated_value_violations(_items(cell, "ev_0010", "ev_0011"), _texts()) == []

    def test_a_composite_cell_with_one_unheld_literal_is_still_asked(self) -> None:
        cell = "ws2_32.dll (primary), loaded by LoadLibraryExW"

        (found,) = stated_value_violations(_items(cell, "ev_0010", "ev_0011"), _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert found.asked

    def test_a_path_is_held_only_whole_never_by_its_components(self) -> None:
        # The entries hold the folder and the file name, never the path.
        (found,) = stated_value_violations(
            _items("C:\\Users\\Public\\evil.exe", "ev_0011", "ev_0012"), _texts()
        )

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_registry_hive_is_held_by_its_predefined_handle(self) -> None:
        cell = "HKEY_CURRENT_USER (0x80000001), passed to the registry helper"
        assert stated_value_violations(_items(cell, "ev_0010"), _texts()) == []
        key = "HKCU\\Software\\ExampleVendor\\Tool\\Hosts"
        assert stated_value_violations(_identifiers(key, "ev_0010"), _texts()) == []
        # Another hive's name is not held by this hive's handle.
        assert _codes(
            stated_value_violations(
                _identifiers("HKLM\\Software\\ExampleVendor\\Tool\\Hosts", "ev_0010"), _texts()
            )
        ) == [STATED_VALUE_UNHELD_CODE]

    def test_a_key_path_with_a_value_name_appended_is_asked(self) -> None:
        key = "HKCU\\SOFTWARE\\ExampleVendor\\Tool\\InstallDir"

        (found,) = stated_value_violations(_identifiers(key, "ev_0010"), _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE
        # What the entry holds of the path is said.
        assert "'SOFTWARE\\\\ExampleVendor\\\\Tool'" in found.message

    def test_a_backslash_value_is_held_by_a_c_string_literal(self) -> None:
        value = "Software\\ExampleVendor\\Tool\\Hosts"

        assert stated_value_violations(_identifiers(value, "ev_0010"), _texts()) == []

    def test_a_32_bit_constant_is_held_by_its_sign_extended_spelling(self) -> None:
        assert stated_value_violations(_items("0x80000001", "ev_0010"), _texts()) == []
        texts = EntryTexts.from_ledger([_entry("ev_0020", "decompile", "push 0x80000002")])
        assert stated_value_violations(_items("0xffffffff80000002", "ev_0020"), texts) == []
        # A constant under bit 31 is no negative number and has no such spelling.
        texts = EntryTexts.from_ledger([_entry("ev_0021", "decompile", "push 0xffffffff00000202")])
        assert stated_value_violations(_items("0x202", "ev_0021"), texts)

    def test_a_cell_with_no_literal_is_still_asked(self) -> None:
        (found,) = stated_value_violations(
            _items("primary module with a fallback", "ev_0010"), _texts()
        )

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_short_number_never_carries_a_cell(self) -> None:
        # Both numbers stand in the entry; no other literal does: read whole.
        (found,) = stated_value_violations(_items("0x202, then 2", "ev_0010"), _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_an_address_carries_a_cell(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _entry(
                    "ev_0030",
                    "sandbox_network",
                    json.dumps({"hosts": ["192.0.2.10", "198.51.100.7"]}),
                )
            ]
        )
        cell = "192.0.2.10 (DNS); 198.51.100.7 (HTTP)"

        assert stated_value_violations(_items(cell, "ev_0030"), texts) == []

    def test_an_identifier_row_is_never_split(self) -> None:
        value = "ws2_32.dll (primary), loaded by LoadLibraryA"

        (found,) = stated_value_violations(_identifiers(value, "ev_0010"), _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_name_and_its_number_are_held_only_as_the_pair(self) -> None:
        texts = EntryTexts.from_ledger(
            [_entry("ev_0050", "decoder", json.dumps({"seed": "0x5a17c0de", "first_key": "0x2b"}))]
        )
        # Each part stands in the entry; the pair it states does not.
        (found,) = stated_value_violations(
            _items("first_key 0x5a17c0de; seed 0x5a17c0de", "ev_0050"), texts
        )
        assert found.code == STATED_VALUE_UNHELD_CODE
        assert "'first_key 0x5a17c0de'" in found.message
        assert (
            stated_value_violations(_items("first_key 0x2b; seed 0x5a17c0de", "ev_0050"), texts)
            == []
        )

    def test_a_hive_written_apart_from_its_path_opens_it(self) -> None:
        cell = "HKCU \\Software\\ExampleVendor\\Tool\\Hosts, loaded by LoadLibraryA"

        assert stated_value_violations(_items(cell, "ev_0010"), _texts()) == []


class TestTheQuestion:
    def test_feedback_names_the_literals_no_cited_entry_holds(self) -> None:
        cell = "ws2_32.dll (primary), loaded by LoadLibraryExW and FreeLibraryX"

        (found,) = stated_value_violations(_items(cell, "ev_0010"), _texts())

        assert "'LoadLibraryExW'" in found.message
        assert "'FreeLibraryX'" in found.message
        assert "'ws2_32.dll'" not in found.message.split(": '")[-1]
        assert "write the value as that entry records it" not in found.message
        assert "Cite an entry that holds each value the row states" in found.message

    def test_a_list_word_is_no_part_of_a_literal(self) -> None:
        cell = "LoadLibraryExW, then 2, then 0x101"

        (found,) = stated_value_violations(_items(cell, "ev_0010"), _texts())

        assert "'then 2'" not in found.message
        assert "'then 0x101'" not in found.message
        assert "'LoadLibraryExW'" in found.message


class TestInsideALongerToken:
    def test_a_value_read_out_of_a_longer_run_is_recorded_and_never_asked(self) -> None:
        (found,) = stated_value_violations(
            _identifiers("ExampleNoteFile-READ.txt", "ev_0012"), _texts()
        )

        assert found.code == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert not found.asked
        assert found.message.startswith("identifier 1 (")
        assert "longer run of text in ev_0012 (strings)" in found.message
        assert found.statements == ("identifiers.0.value",)
        assert asked_in_this_mode([found]) == []

    def test_the_code_is_declared_beside_the_codes(self) -> None:
        assert STATED_VALUE_INSIDE_A_TOKEN_CODE == "report.value_inside_a_longer_token"
        assert STATED_VALUE_INSIDE_A_TOKEN_CODE in ASKED_BY_NO_TURN
        assert STATED_VALUE_INSIDE_A_TOKEN_CODE in KEPT_WITH_A_FINDING
        # Never shown, so never a finding the retry left unasked.
        found = Violation(code=STATED_VALUE_INSIDE_A_TOKEN_CODE, message="m", asked=False)
        assert not raised_only_in_retry(found, [])

    def test_a_short_value_inside_a_longer_run_is_asked(self) -> None:
        # Shorter than the keep check's floor: almost any text spells it somewhere.
        (found,) = stated_value_violations(_identifiers("NameAlpha", "ev_0012"), _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_value_that_cuts_a_number_is_asked(self) -> None:
        (found,) = stated_value_violations(
            _identifiers("ExampleCounter12345678", "ev_0012"), _texts()
        )

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_value_continued_by_punctuation_is_asked(self) -> None:
        # ``.bak`` runs on through a dot: a longer name, not a run of letters.
        (found,) = stated_value_violations(_identifiers("ExampleCache.dat", "ev_0012"), _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_cell_whose_literals_are_held_or_inside_is_recorded(self) -> None:
        cell = "ExampleNoteFile-READ.txt, loaded by LoadLibraryA"

        (found,) = stated_value_violations(_items(cell, "ev_0010", "ev_0012"), _texts())

        assert found.code == STATED_VALUE_INSIDE_A_TOKEN_CODE

    def test_a_cell_whose_whole_text_runs_on_is_recorded(self) -> None:
        # ``--beta`` alone runs on through a dot; the cell's whole text is read
        # out of the longer run.
        cell = "Error: --alpha cannot be combined with --beta."

        (found,) = stated_value_violations(_items(cell, "ev_0012"), _texts())

        assert found.code == STATED_VALUE_INSIDE_A_TOKEN_CODE

    def test_the_reader_of_one_text(self) -> None:
        text = "txtexamplenotefile-read.txtservicenamealpha"
        assert inside_a_longer_token("examplenotefile-read.txt", text)
        assert not inside_a_longer_token("examplenotefile-read.txt", "examplenotefile-read.txt")
        assert not inside_a_longer_token("counter12", "counter123")
        # A digit of the value against a digit of the text cuts a number.
        assert not inside_a_longer_token("1counterx", "91counterx ")
        assert inside_a_longer_token("1counterx", "a1counterx ")
        assert inside_a_longer_token("x1counter", "9x1counter ")


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), verdict="Malware"
    )


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
    def test_a_row_read_out_of_a_longer_run_opens_no_turn_and_is_recorded(self) -> None:
        from langchain_core.messages import HumanMessage

        answer = json.dumps(_identifiers("ExampleNoteFile-READ.txt", "ev_0012"))
        llm = _RawLLM(answer)
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        comp._entries = _texts()
        comp._citable = ["ev_0010", "ev_0011", "ev_0012"]
        comp._report = _report()
        with patch(
            "malspark.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            result = asyncio.run(
                comp._invoke(
                    [HumanMessage(content="write it")],
                    _HostIdentifiersOut,
                    section="host_identifiers",
                    validators=[lambda p: stated_value_violations(p, comp._entries)],
                )
            )

        assert len(llm.sent) == 1
        assert result is not None and result.identifiers[0].value == "ExampleNoteFile-READ.txt"
        (row,) = comp.validation_tally.unresolved
        assert row["code"] == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert row["asked"] == "false"
        assert "Not asked: it first appeared" not in row["message"]
        assert comp.validation_tally.by_code[STATED_VALUE_INSIDE_A_TOKEN_CODE] == 1


class TestLargeInput:
    def test_a_long_path_cell_is_read_in_linear_time(self) -> None:
        texts = EntryTexts.from_ledger([_entry("ev_0040", "strings", "a b c " * 2000)])
        cell = "\\".join(["a", "b", "c"] * 3000) + ", then LoadLibraryA"

        def check() -> None:
            texts._runs.clear()
            assert stated_value_violations(_items(cell, "ev_0040"), texts)

        assert_under(check, 10, what="a 9,000-component path in one cell")
