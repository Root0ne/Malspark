"""A configuration cell is held span by span; a value standing only inside a longer run is asked.

A configuration cell often states several values in one sentence: a module, a
fallback and the call that loads them, or a hive written beside its handle.
The check read the whole cell as one value, and almost every such cell was
asked about although each value it states stands in an entry the row cites.
The model was then told to write the value as the entry records it, and wrote
C escapes and sign-extended handles into the report.

The rule now:

- a configuration cell of several spans is held when every span of it is held
  by a cited entry. Only list punctuation is not a span: no span is skipped
  for its shape, its case or its length, and no word is known to the check. A
  span holding a backslash or a slash runs to the end of its part, and a
  number is held only with the span before it. A cell of one span, and an
  identifier row, are read whole;
- a doubled backslash, as a C string writes it, and a 32-bit constant
  sign-extended to 64 bits are spellings of the same value. A leading registry
  hive is held by its other name or its predefined handle only where that
  stands before the rest of the path on the same line of the entry, with no
  other hive's spelling between;
- a value a cited entry holds only inside a longer run of letters or digits is
  asked once under its own code, with the run shown and the two ends that pass;
  a short one, or one that cuts a number, is asked as any value no entry holds;
- the question names the spans no cited entry holds and, for a path, the whole
  leading part of it a cited entry holds, where every string of that sentence
  prints as it is.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from malspark.agents._indicator_denylists import inside_a_longer_token
from malspark.pipeline import validation
from malspark.pipeline.events import safe_finding_value
from malspark.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    STATED_VALUE_INSIDE_A_TOKEN_CODE,
    STATED_VALUE_UNHELD_CODE,
    EntryTexts,
    Violation,
    asked_in_this_mode,
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
# A run-together string pool: values written with no separator.
_POOL = "txtExampleNoteFile-READ.txtServiceNameAlpha"


def _entry(entry_id: str, tool: str, output: str) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="pipeline", server="pipeline", tool=tool, output=output)


def _strings(entry_id: str, *values: str) -> LedgerEntry:
    return _entry(entry_id, "strings", json.dumps({"strings": list(values)}))


def _code(entry_id: str, source: str) -> LedgerEntry:
    return _entry(entry_id, "batch_decompile", json.dumps({"code": source}))


def _texts() -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _code("ev_0010", _CODE),
            _strings("ev_0011", "wsock32.dll", "GetProcAddress", "C:\\Users\\Public"),
            _strings(
                "ev_0012",
                _POOL,
                "ExampleCounter123456789",
                "ExampleCache.dat.bak",
                "evil.exe",
                "usageError: --alpha cannot be combined with --gamma, or --beta.zz",
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


def _one(payload: dict[str, Any], texts: EntryTexts | None = None) -> Violation:
    (found,) = stated_value_violations(payload, texts or _texts())
    return found


class TestACompositeCell:
    def test_a_composite_cell_is_held_when_every_span_it_states_is_held(self) -> None:
        cell = "ws2_32.dll, wsock32.dll; LoadLibraryA"

        assert stated_value_violations(_items(cell, "ev_0010", "ev_0011"), _texts()) == []

    def test_a_composite_cell_with_one_unheld_span_is_still_asked(self) -> None:
        found = _one(_items("ws2_32.dll (primary), LoadLibraryA", "ev_0010", "ev_0011"))

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert found.asked
        assert "holds 'primary'." in found.message

    def test_no_span_is_skipped_for_its_shape_case_or_length(self) -> None:
        texts = EntryTexts.from_ledger(
            [_code("ev_0020", "CryptEncrypt(h, 0, 1, 0, buf, &n, n); // ChaCha20\n")]
        )

        found = _one(_items("CryptEncrypt with RSA, AES", "ev_0020"), texts)

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert "holds 'with', 'RSA', 'AES'." in found.message

    def test_a_joining_word_is_a_span_like_any_other(self) -> None:
        found = _one(_items("ws2_32.dll and wsock32.dll", "ev_0010", "ev_0011"))

        assert "holds 'and'." in found.message

    def test_a_path_runs_to_the_end_of_its_part(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _strings(
                    "ev_0021",
                    "LogonTrigger",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Icons",
                )
            ]
        )
        cell = "LogonTrigger; Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"

        found = _one(_items(cell, "ev_0021"), texts)

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert "Explorer\\\\Shell Folders'" in found.message

    def test_a_path_with_a_space_is_held_whole(self) -> None:
        texts = EntryTexts.from_ledger(
            [_strings("ev_0022", "GetTempPathW", "Software\\Vendor\\Shell Folders")]
        )

        assert (
            stated_value_violations(
                _items("GetTempPathW, Software\\Vendor\\Shell Folders", "ev_0022"), texts
            )
            == []
        )
        found = _one(_items("GetTempPathW, Software\\Vendor\\Shell Icons", "ev_0022"), texts)
        assert "holds 'Software\\\\Vendor\\\\Shell Icons'." in found.message

    def test_a_path_is_held_only_whole_never_by_its_components(self) -> None:
        found = _one(_items("C:\\Users\\Public\\evil.exe", "ev_0011", "ev_0012"))

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_path_with_a_part_after_it_names_that_part(self) -> None:
        texts = EntryTexts.from_ledger([_strings("ev_0023", "C:\\Temp\\a.exe")])

        found = _one(_items("C:\\Temp\\a.exe (dropped)", "ev_0023"), texts)

        assert "holds 'dropped'." in found.message

    def test_quotes_around_a_span_are_no_part_of_it(self) -> None:
        texts = EntryTexts.from_ledger([_code("ev_0024", 'FindWindowA("Pageant", "Pageant");\n')])

        assert stated_value_violations(_items('FindWindowA, "Pageant"', "ev_0024"), texts) == []

    def test_a_number_is_held_only_with_the_span_before_it(self) -> None:
        texts = EntryTexts.from_ledger(
            [_entry("ev_0050", "decoder", json.dumps({"seed": "0x5a17c0de", "first_key": "0x2b"}))]
        )
        found = _one(_items("first_key 0x5a17c0de; seed 0x5a17c0de", "ev_0050"), texts)
        assert "'first_key 0x5a17c0de'" in found.message
        assert (
            stated_value_violations(_items("first_key 0x2b; seed 0x5a17c0de", "ev_0050"), texts)
            == []
        )
        # A small number after a list comma is still the span before it's.
        texts = EntryTexts.from_ledger([_strings("ev_0051", "WSAStartup", "99")])
        assert _one(_items("WSAStartup, 99", "ev_0051"), texts).code == STATED_VALUE_UNHELD_CODE

    def test_a_cell_of_one_span_is_read_whole(self) -> None:
        assert stated_value_violations(_items("0x80000001", "ev_0010"), _texts()) == []
        found = _one(_items("primary", "ev_0010"))
        assert "is in none of the entries it cites" in found.message

    def test_an_identifier_row_is_never_split(self) -> None:
        found = _one(_identifiers("ws2_32.dll and LoadLibraryA", "ev_0010"))

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert "is in none of the entries it cites" in found.message


class TestTheSpellings:
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

    def test_a_registry_hive_is_held_by_its_handle_before_the_path_on_its_line(self) -> None:
        key = "HKCU\\Software\\ExampleVendor\\Tool\\Hosts"
        assert stated_value_violations(_identifiers(key, "ev_0010"), _texts()) == []
        # Another hive's name is not held by this hive's handle.
        other = "HKLM\\Software\\ExampleVendor\\Tool\\Hosts"
        assert _codes(stated_value_violations(_identifiers(other, "ev_0010"), _texts())) == [
            STATED_VALUE_UNHELD_CODE
        ]

    def test_a_registry_hive_is_held_by_its_other_name(self) -> None:
        texts = EntryTexts.from_ledger(
            [_strings("ev_0030", "HKEY_CURRENT_USER\\Software\\Vendor\\App")]
        )

        assert (
            stated_value_violations(_identifiers("HKCU\\Software\\Vendor\\App", "ev_0030"), texts)
            == []
        )

    @pytest.mark.parametrize(
        "entry",
        [
            # The path under another hive, this hive with another path.
            _strings("ev_0031", "HKLM\\Software\\Vendor", "HKCU\\Software\\Other"),
            # The key opened under another hive's handle, this one's elsewhere.
            _code("ev_0031", 'x = 0x80000001;\nRegOpenKeyExA(0x80000002, "Software\\\\Vendor");\n'),
            # The handle's number as a status constant on its own line.
            _code("ev_0031", 'if (status == 0x80000001) return;\ns = "Software\\\\Vendor";\n'),
            # The hive's name in a comment lines away.
            _code("ev_0031", '// HKCU is checked\nx = 1;\ny = 2;\ns = "Software\\\\Vendor";\n'),
        ],
    )
    def test_a_hive_spelt_elsewhere_in_the_entry_holds_nothing(self, entry: LedgerEntry) -> None:
        texts = EntryTexts.from_ledger([entry])

        found = _one(_identifiers("HKCU\\Software\\Vendor", "ev_0031"), texts)

        assert found.code == STATED_VALUE_UNHELD_CODE


class TestThePathNote:
    def test_the_whole_leading_part_an_entry_holds_is_said(self) -> None:
        texts = EntryTexts.from_ledger([_strings("ev_0040", "Software\\Vendor\\Tool\\Other")])

        found = _one(_identifiers("Software\\Vendor\\Tool\\Evil\\Run", "ev_0040"), texts)

        assert (
            "ev_0040 (strings) holds 'Software\\\\Vendor\\\\Tool' of "
            "'Software\\\\Vendor\\\\Tool\\\\Evil\\\\Run', not the whole path." in found.message
        )

    def test_a_path_the_printer_shortens_is_not_said(self) -> None:
        # The printer keeps a user folder's path out of a finding: a sentence
        # about what the entry holds would print other text than it read.
        texts = EntryTexts.from_ledger([_strings("ev_0044", "C:\\Users\\Public\\Documents")])

        found = _one(_identifiers("C:\\Users\\Public\\evil\\drop.exe", "ev_0044"), texts)

        assert " holds '" not in found.message

    def test_a_part_of_one_component_is_not_said(self) -> None:
        texts = EntryTexts.from_ledger([_strings("ev_0041", "C:\\Other")])

        found = _one(_identifiers("C:\\Users\\evil.exe", "ev_0041"), texts)

        assert " holds '" not in found.message

    def test_a_part_after_the_hive_is_no_leading_part(self) -> None:
        texts = EntryTexts.from_ledger([_strings("ev_0042", "SOFTWARE\\Vendor\\Tool")])

        found = _one(_identifiers("HKLM\\SOFTWARE\\Vendor\\Tool\\InstallDir", "ev_0042"), texts)

        assert " holds '" not in found.message

    def test_a_path_the_printer_would_shorten_is_not_said(self) -> None:
        held = "C:\\Users\\Public\\" + "\\".join(f"dir{n}" for n in range(60))
        texts = EntryTexts.from_ledger([_strings("ev_0043", held)])

        found = _one(_identifiers(held + "\\drop.exe", "ev_0043"), texts)

        assert " holds '" not in found.message


class TestTheQuestion:
    def test_feedback_names_the_spans_no_cited_entry_holds(self) -> None:
        cell = "ws2_32.dll, LoadLibraryExW, FreeLibraryX"

        found = _one(_items(cell, "ev_0010"))

        assert "none of the entries it cites (ev_0010 (batch_decompile)) holds " in found.message
        assert "holds 'LoadLibraryExW', 'FreeLibraryX'." in found.message
        assert "write the value as that entry records it" not in found.message
        assert "Cite an entry that holds each value the row states" in found.message

    def test_one_wrong_span_beside_one_inside_a_run_is_asked(self) -> None:
        found = _one(_items("ExampleNoteFile-READ.txt, LoadLibraryExW", "ev_0010", "ev_0012"))

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert "'LoadLibraryExW'" in found.message


class TestInsideALongerToken:
    def test_a_value_standing_only_inside_a_longer_run_is_asked_with_the_run(self) -> None:
        found = _one(_identifiers("ExampleNoteFile-READ.txt", "ev_0012"))

        assert found.code == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert found.asked
        assert asked_in_this_mode([found]) == [found]
        assert found.message.startswith(
            "identifier 1 (string: 'ExampleNoteFile-READ.txt') stands in ev_0012 (strings) only "
            f"inside a longer run of text: '{_POOL}'."
        )
        assert "keep the row as written" in found.message
        assert "write the token the entry holds" in found.message
        assert found.statements == ("identifiers.0.value",)

    def test_the_code_is_an_ordinary_asked_code(self) -> None:
        assert STATED_VALUE_INSIDE_A_TOKEN_CODE == "report.value_inside_a_longer_token"
        assert STATED_VALUE_INSIDE_A_TOKEN_CODE in KEPT_WITH_A_FINDING
        assert not hasattr(validation, "ASKED_BY_NO_TURN")

    @pytest.mark.parametrize(
        ("held", "value"),
        [
            (
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            ),
            ("Global\\MsWinZonesCacheCounterMutexA", "Global\\MsWinZonesCacheCounterMutex"),
            ("http://evil.example.net/gate.php5", "http://evil.example.net/gate.php"),
            ("notevil-site.example.com", "evil-site.example.com"),
            ("C:\\Users\\Public\\payload.exe", "C:\\Users\\Public\\payload.ex"),
            ("WinDefendUpdaterSvc", "WinDefendUpdater"),
        ],
    )
    def test_a_prefix_of_another_value_is_asked_with_the_run(self, held: str, value: str) -> None:
        texts = EntryTexts.from_ledger([_strings("ev_0060", held)])

        found = _one(_identifiers(value, "ev_0060"), texts)

        assert found.code == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert found.asked
        assert repr(safe_finding_value(held)) in found.message

    def test_the_run_shown_goes_on_through_a_path_s_backslashes(self) -> None:
        pool = "HKLM\\Software\\Vendor\\RunHKCU\\Software\\Vendor\\Runtime"
        texts = EntryTexts.from_ledger([_strings("ev_0062", pool)])

        found = _one(_identifiers("HKCU\\Software\\Vendor\\Run", "ev_0062"), texts)

        assert f"only inside a longer run of text: {pool!r}." in found.message

    def test_a_short_value_inside_a_longer_run_is_asked_as_not_held(self) -> None:
        found = _one(_identifiers("NameAlpha", "ev_0012"))

        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_value_that_cuts_a_number_is_asked_as_not_held(self) -> None:
        assert _one(_identifiers("ExampleCounter12345678", "ev_0012")).code == (
            STATED_VALUE_UNHELD_CODE
        )
        texts = EntryTexts.from_ledger([_strings("ev_0061", "d41d8cd98f00b204e9800998ecf8427e")])
        found = _one(_identifiers("d41d8cd98f00b204e9800998ec", "ev_0061"), texts)
        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_value_continued_by_punctuation_is_asked_as_not_held(self) -> None:
        assert _one(_identifiers("ExampleCache.dat", "ev_0012")).code == STATED_VALUE_UNHELD_CODE

    def test_a_cell_whose_whole_text_runs_on_is_asked_with_the_run(self) -> None:
        cell = "Error: --alpha cannot be combined with --gamma, or --beta."

        found = _one(_items(cell, "ev_0012"))

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
        # A value of hexadecimal digits against a hexadecimal digit cuts a number.
        assert not inside_a_longer_token("deadbeefcafe", "deadbeefcafeb ")
        assert not inside_a_longer_token("deadbeefcafe", " adeadbeefcafe")
        assert inside_a_longer_token("deadbeefcafe", "xdeadbeefcafe ")


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


def _composed(*answers: str) -> tuple[Any, _RawLLM, ReportComposer]:
    from langchain_core.messages import HumanMessage

    llm = _RawLLM(*answers)
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
    return result, llm, comp


class TestTheComposer:
    def test_a_row_kept_after_the_run_was_shown_is_recorded_as_asked(self) -> None:
        answer = json.dumps(_identifiers("ExampleNoteFile-READ.txt", "ev_0012"))

        result, llm, comp = _composed(answer, answer)

        assert len(llm.sent) == 2
        assert _POOL in str(llm.sent[1][-1].content)
        assert result is not None and result.identifiers[0].value == "ExampleNoteFile-READ.txt"
        (row,) = comp.validation_tally.unresolved
        assert row["code"] == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert "asked" not in row

    def test_a_row_first_raised_by_the_retry_is_recorded_as_not_asked(self) -> None:
        first = json.dumps(_identifiers("primary", "ev_0012"))
        retry = json.dumps(_identifiers("ExampleNoteFile-READ.txt", "ev_0012"))

        _result, llm, comp = _composed(first, retry)

        assert len(llm.sent) == 2
        (row,) = comp.validation_tally.unresolved
        assert row["code"] == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert row["asked"] == "false"


class TestLargeInput:
    def test_a_long_path_cell_is_read_in_linear_time(self) -> None:
        texts = EntryTexts.from_ledger([_entry("ev_0040", "strings", "a b c " * 2000)])
        cell = "\\".join(["a", "b", "c"] * 3000) + ", then LoadLibraryA"

        def check() -> None:
            texts._runs.clear()
            assert stated_value_violations(_items(cell, "ev_0040"), texts)

        assert_under(check, 10, what="a 9,000-component path in one cell")
