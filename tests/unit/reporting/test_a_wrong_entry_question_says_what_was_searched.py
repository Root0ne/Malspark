"""A question about a value cited to an entry it was not found whole in says what was searched.

The check knows only that a search for the whole value, in a fixed set of
spellings, found it or did not. Its question says exactly that, for every
state of the cited entry: the entries read, whether the sentence or its record
cites them, the spellings read (a code listing stored as JSON also as a C
string literal inside it writes the value), and the entries the value was found
whole in. It never says an entry lacks the value. A cited entry with no text is
named as one the check does not read, and a cited entry known not to be the
whole answer asks nothing. A value a cited entry holds only inside a longer run
is asked with that run and the two ends that pass, preferring neither. The
instruction offers both ends: cite an entry that holds the value as the text
states it, or keep the citation and say the entry writes it in another
spelling.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline.validation import (
    INSIDE_A_TOKEN_ENDS,
    EntryTexts,
    wrong_entry_citations,
)
from malspark.schemas.evidence import LedgerEntry

ENDS = (
    "Cite an entry that holds the value as the text states it, or, where the cited entry "
    "writes it in another spelling, keep the citation and say so in the text."
)
PLAIN = "read as written, as JSON writes it or as the triage pack quotes it"
LITERAL = f"{PLAIN}, or as a C string literal inside JSON writes it"


def _entry(entry_id: str, tool: str, output: str, **over: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent="static", server="static", tool=tool, output=output, **over
    )


def _ledger(*extra: LedgerEntry, truncated: bool = False) -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _entry(
                "ev_0004",
                "pe_info",
                json.dumps({"imports": ["KERNEL32.dll"], "blob": "pow10del /f /q"}),
                truncated=truncated,
            ),
            _entry(
                "ev_0012",
                "floss",
                json.dumps({"strings": ["advapi32.dll", "del /f /q", "Local\\examplegate"]}),
            ),
            _entry("ev_0030", "pe_info", ""),
            *extra,
        ]
    )


def _asked(sentence: str, texts: EntryTexts | None = None) -> list[Any]:
    return wrong_entry_citations({"body": sentence}, texts or _ledger(), prose=("body",))


class TestEachStateOfTheCitedEntry:
    def test_a_whole_entry_searched_without_a_find(self) -> None:
        (found,) = _asked("The sample loads `advapi32.dll` [ev_0004].")

        assert found.message == (
            f"'advapi32.dll' was not found as a whole value in the answer of ev_0004 (pe_info), "
            f"which the sentence cites, {PLAIN}; it was found whole in ev_0012 (floss). {ENDS}"
        )

    def test_a_shortened_or_cut_entry_asks_nothing(self) -> None:
        assert _asked("The sample loads `advapi32.dll` [ev_0004].", _ledger(truncated=True)) == []

    def test_a_blank_entry_is_named_as_one_not_read(self) -> None:
        (found,) = _asked("The sample loads `advapi32.dll` [ev_0004, ev_0030].")

        assert found.message == (
            f"'advapi32.dll' was not found as a whole value in the answer of ev_0004 (pe_info), "
            f"which the sentence cites, {PLAIN}; it was found whole in ev_0012 (floss). "
            f"ev_0030, also cited, holds no text this check reads. {ENDS}"
        )

    def test_only_blank_entries_ask_nothing(self) -> None:
        assert _asked("The sample loads `advapi32.dll` [ev_0030].") == []

    def test_a_value_in_another_spelling_names_the_spellings_read(self) -> None:
        listing = _entry(
            "ev_0010",
            "batch_decompile",
            json.dumps({"0x401000": 'CreateMutexA(0, 0, "Local\\x5cexamplegate");'}),
        )

        (found,) = _asked("It creates `Local\\examplegate` [ev_0010].", _ledger(listing))

        assert found.message == (
            "'Local\\\\examplegate' was not found as a whole value in the answer of ev_0010 "
            f"(batch_decompile), which the sentence cites, {LITERAL}; it was found whole in "
            f"ev_0012 (floss). {ENDS}"
        )

    def test_a_value_only_in_the_call_s_arguments_is_said_of_the_answer(self) -> None:
        call = _entry(
            "ev_0001",
            "identify_file",
            json.dumps({"type": "PE32 executable"}),
            args={"path": "C:\\samples\\advapi32.dll"},
        )

        (found,) = _asked("The file is `advapi32.dll` [ev_0001].", _ledger(call))

        assert found.message.startswith(
            "'advapi32.dll' was not found as a whole value in the answer of ev_0001 "
            "(identify_file), which the sentence cites,"
        )

    def test_a_value_inside_a_longer_run_is_asked_with_the_run_and_both_ends(self) -> None:
        (found,) = _asked("The script runs `del /f /q` [ev_0004].")

        assert found.message == (
            "'del /f /q' stands in the answer of ev_0004 (pe_info), which the sentence cites, "
            "only inside a longer run of text: 'pow10del /f /q'; it was found whole in "
            f"ev_0012 (floss). {INSIDE_A_TOKEN_ENDS}"
        )


class TestWhatTheQuestionNames:
    def test_a_record_s_citation_is_named_as_its_record_s(self) -> None:
        payload = {"rows": [{"value": "advapi32.dll", "evidence_refs": ["ev_0004"]}]}

        (found,) = wrong_entry_citations(payload, _ledger())

        assert "in the answer of ev_0004 (pe_info), which its record cites," in found.message

    def test_several_values_are_said_together(self) -> None:
        (found,) = _asked("It loads `advapi32.dll` and keeps `Local\\examplegate` [ev_0004].")

        assert found.message.startswith(
            "'advapi32.dll', 'Local\\\\examplegate' were not found as whole values in the "
            "answer of ev_0004 (pe_info), which the sentence cites, read as written, as JSON "
            "writes them or as the triage pack quotes them; they were found whole in ev_0012"
        )

    def test_a_listing_among_the_cited_entries_is_named_with_its_spelling(self) -> None:
        listing = _entry("ev_0010", "batch_decompile", json.dumps({"0x401000": "return 0;"}))

        (found,) = _asked("The sample loads `advapi32.dll` [ev_0004, ev_0010].", _ledger(listing))

        assert (
            "in the answers of ev_0004 (pe_info), ev_0010 (batch_decompile), which the sentence "
            f"cites, {PLAIN}, or, in ev_0010 (batch_decompile), as a C string literal inside "
            "JSON writes it; it was found whole in ev_0012 (floss)."
        ) in found.message

    def test_no_question_says_an_entry_lacks_the_value(self) -> None:
        for sentence in (
            "The sample loads `advapi32.dll` [ev_0004].",
            "The sample loads `advapi32.dll` [ev_0004, ev_0030].",
            "The script runs `del /f /q` [ev_0004].",
        ):
            (found,) = _asked(sentence)
            assert " is not in " not in found.message
            assert "evidence holds" not in found.message

    def test_the_mark_says_where_it_was_not_found_and_where_it_was(self) -> None:
        (found,) = _asked("The sample loads `advapi32.dll` [ev_0004].")

        assert found.labels == (
            '"advapi32.dll" was not found whole in ev_0004; it was found whole in ev_0012 (floss)',
        )
