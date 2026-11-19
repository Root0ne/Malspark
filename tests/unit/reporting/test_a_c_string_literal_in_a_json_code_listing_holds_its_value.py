"""A code listing stored as JSON holds a value its code writes as a C string literal.

A decompiler writes a path as a C string literal, each backslash doubled and
each double quote escaped, and a tool that answers in JSON escapes that
literal once more. Only an entry whose tool declares a code-listing kind, and
whose every text is a JSON document, is also asked the value two escape levels
deep; every check that asks whether an entry holds a value reads the same
spellings, and so does the export's lookup. A listing printed as plain text is
asked the spellings it was asked before, so a literal whose run-time string
doubles its backslashes is not read as the value. An entry of a tool that
declares no kind is searched at full strength in the value's other spellings,
whatever its name or its answer's shape; a question about it names the
spellings that were read and says nothing the search cannot know.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.agents.run_evidence_corpus import RunEvidenceCorpus
from malspark.pipeline.validation import (
    VALUE_ONLY_IN_CALL_ARGUMENTS_CODE,
    EntryTexts,
    cited_id_violations,
    echoed_argument_citations,
    ledger_absence_contradictions,
    stated_value_violations,
    wrong_entry_citations,
)
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.stated_host_values import held_in_cited, with_held_in
from malspark.schemas.evidence import LedgerEntry

# Invented values: a registry path, its parent key, a mutex name.
PATH = "Software\\ExampleVendor\\Tool"
PARENT = "Software\\ExampleVendor"
MUTEX = "Global\\examplegate"
# What the plain spellings ask, and what a code listing stored as JSON is also asked.
PLAIN = "read as written, as JSON writes it or as the triage pack quotes it;"
LITERAL = (
    "read as written, as JSON writes it or as the triage pack quotes it, or as a C string "
    "literal inside JSON writes it;"
)


def _entry(entry_id: str, tool: str, output: str, **over: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent="static", server="static", tool=tool, output=output, **over
    )


def _c(value: str) -> str:
    """``value`` as a C string literal writes it, quotes included."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _listing(code: str, tool: str = "batch_decompile", **over: Any) -> LedgerEntry:
    return _entry("ev_0010", tool, json.dumps({"0x401000": code}), **over)


def _strings(*values: str, entry_id: str = "ev_0012") -> LedgerEntry:
    return _entry(entry_id, "floss", json.dumps({"strings": list(values)}))


def _texts(*entries: LedgerEntry) -> EntryTexts:
    return EntryTexts.from_ledger(list(entries))


def _cited(value: str, texts: EntryTexts, ref: str = "ev_0010") -> list[Any]:
    return wrong_entry_citations(
        {"body": f"The sample opens `{value}` [{ref}]."}, texts, prose=("body",)
    )


def _host(kind: str, value: str, use: str, *refs: str) -> HostIdentifier:
    return HostIdentifier(kind=kind, value=value, use=use, evidence_refs=list(refs))


class TestADeclaredJsonListingHoldsTheLiteral:
    def test_the_citation_stands(self) -> None:
        texts = _texts(_listing(f"p = {_c(PATH)};"), _strings(PATH))

        assert texts.holds("ev_0010", PATH)
        assert _cited(PATH, texts) == []

    def test_a_row_id_cited_to_it_stands(self) -> None:
        texts = _texts(_listing(f"p = {_c(PATH)};"), _strings(PATH))
        rows = {"commands": [{"id": PATH, "name": "open", "evidence_refs": ["ev_0010"]}]}

        assert cited_id_violations(rows, texts) == []

    def test_every_holder_list_names_it(self) -> None:
        texts = _texts(_listing(f"p = {_c(PATH)};"), _strings(PATH))

        assert texts.holding(PATH, fields=True) == ["ev_0010", "ev_0012"]

    def test_an_absence_it_contradicts_is_asked_with_it(self) -> None:
        texts = _texts(_listing(f"p = {_c(PATH)};"))

        (found,) = ledger_absence_contradictions(
            {"body": f"`{PATH}` is not confirmed by the decompiled output [ev_0010]."}, texts
        )
        assert "is not confirmed by the entry it cites" in found.message

    def test_an_escaped_quote_and_a_wide_literal_are_held(self) -> None:
        command = 'cmd /c "del example.tmp"'
        texts = _texts(_listing(f"system({_c(command)}); w = L{_c(PATH)};"))

        assert texts.holds("ev_0010", command)
        assert texts.holds("ev_0010", PATH)

    def test_a_disassembly_listing_is_one_too(self) -> None:
        texts = _texts(_listing(f"push offset {_c(PATH)}", tool="disassemble_function"))

        assert texts.holds("ev_0010", PATH)


class TestThePlainSpellingsAreTheOnlyOnesAskedElsewhere:
    def test_a_plain_text_listing_holds_the_one_level_literal_as_before(self) -> None:
        texts = _texts(_entry("ev_0010", "decompile_function", f"p = {_c(PATH)};"))

        assert texts.holds("ev_0010", PATH)

    def test_a_plain_text_literal_whose_string_doubles_its_backslashes_is_not_the_value(
        self,
    ) -> None:
        doubled = PATH.replace("\\", "\\\\")
        texts = _texts(_entry("ev_0010", "decompile_function", f"regcomp(&r, {_c(doubled)}, 0);"))

        assert not texts.holds("ev_0010", PATH)

    def test_a_tool_declaring_no_kind_is_read_in_the_plain_spellings_whatever_its_name(
        self,
    ) -> None:
        for tool in ("source_view", "decompile_fn"):
            texts = _texts(_listing(f"p = {_c(PATH)};", tool=tool), _strings(PATH))

            assert "ev_0010" not in texts.code_listings
            (found,) = _cited(PATH, texts)
            assert f"in the answer of ev_0010 ({tool}), which the sentence cites, {PLAIN}" in (
                found.message
            )
            assert "C string literal" not in found.message
            assert " is not in " not in found.message

    def test_an_undeclared_answer_listing_self_named_functions_is_no_listing_here(self) -> None:
        answer = json.dumps(
            {
                "FUN_00401000": f"void FUN_00401000(void) {{ open({_c(PATH)}); }}",
                "FUN_00401100": "void FUN_00401100(void) { return; }",
            }
        )
        texts = _texts(_entry("ev_0010", "lift_all", answer), _strings(PATH))

        assert "ev_0010" not in texts.code_listings
        (found,) = _cited(PATH, texts)
        assert PLAIN in found.message

    def test_a_declared_kind_that_lists_no_code_is_read_in_the_plain_spellings(self) -> None:
        texts = _texts(
            _entry("ev_0010", "floss", json.dumps({"0x401000": f"p = {_c(PATH)};"})),
            _strings(PATH),
        )

        (found,) = _cited(PATH, texts)
        assert f"in the answer of ev_0010 (floss), which the sentence cites, {PLAIN}" in (
            found.message
        )

    def test_a_search_answer_holding_the_value_only_as_its_pattern_is_never_a_holder(
        self,
    ) -> None:
        pattern = "CurrentVersion\\\\Run"
        search = _entry(
            "ev_0010",
            "search_strings",
            json.dumps({"pattern": pattern, "matches": []}),
            args={"pattern": pattern},
        )
        texts = _texts(search, _strings("Software\\Example\\CurrentVersion\\Run"))

        assert "ev_0010" not in texts.holding("CurrentVersion\\Run", fields=True)

    def test_a_listing_read_in_pages_is_read_in_the_plain_spellings(self) -> None:
        listing = _listing(f"p = {_c(PATH)};")
        corpus = RunEvidenceCorpus(10_000_000)
        corpus.remember("ev_0010", "batch_decompile", listing.output.lower())
        corpus.remember("ev_0010@0+40", "read_evidence", f"p = {_c(PATH)};".lower())
        texts = EntryTexts.from_ledger([listing], corpus)

        assert "ev_0010" not in texts.code_listings


class TestALiteralInAnotherConventionIsNotHeld:
    def test_a_hex_escape_and_a_doubled_quote_are_asked_with_the_spellings_named(self) -> None:
        for code, value in (
            ('CreateMutexA(0, 0, "Local\\x5cexamplegate");', "Local\\examplegate"),
            ('Shell "cmd /c ""example.exe"""', 'cmd /c "example.exe"'),
        ):
            texts = _texts(_listing(code), _strings(value))

            (found,) = _cited(value, texts)
            assert (
                f"was not found as a whole value in the answer of ev_0010 (batch_decompile), "
                f"which the sentence cites, {LITERAL}"
            ) in found.message


class TestARepeatReadsAsItsListing:
    def test_a_repeat_and_a_read_of_the_entry_hold_what_the_listing_holds(self) -> None:
        texts = _texts(
            _listing(f"p = {_c(PATH)};"),
            _entry("ev_0020", "batch_decompile", "same call", repeated_of="ev_0010"),
            _entry("ev_0021", "read_evidence", "read again", repeated_of="ev_0010"),
        )

        assert {"ev_0010", "ev_0020", "ev_0021"} <= texts.code_listings
        assert texts.holds("ev_0020", PATH)
        assert texts.holds("ev_0021", PATH)


class TestTheEchoCheckReadsTheListingAsTheCheckDoes:
    def test_a_literal_the_call_s_arguments_also_hold_is_not_only_in_the_arguments(self) -> None:
        command = 'run examplegate "now"'
        asked = f"{command} creator"
        listing = _entry(
            "ev_0010",
            "batch_decompile",
            json.dumps({"filter": asked, "0x401000": f"system({_c(command)});"}),
            args={"filter": asked},
        )
        texts = _texts(listing)
        found = echoed_argument_citations(
            {"body": f"The routine runs '{command}' [ev_0010]."}, texts, prose=("body",)
        )

        assert texts.holds("ev_0010", command)
        assert [v.code for v in found if v.code == VALUE_ONLY_IN_CALL_ARGUMENTS_CODE] == []


class TestAParentKeyIsHeldAsAStringsEntryHoldsIt:
    def test_under_the_checks_and_the_export(self) -> None:
        listing = _listing(f"RegOpenKeyExA(HKEY_LOCAL_MACHINE, {_c(PATH)}, 0, 1, &k);")
        texts = _texts(listing, _strings(PATH, entry_id="ev_0012"))

        assert texts.holds("ev_0012", PARENT)
        assert texts.holds("ev_0010", PARENT)
        row = _host("registry key", PARENT, "reads/checks", "ev_0010", "ev_0012")
        assert held_in_cited(texts, row) == ["ev_0010", "ev_0012"]


class TestTheExportReadsTheSameSpellings:
    def test_a_value_cited_only_to_a_decompilation_is_held_and_exported(self) -> None:
        texts = _texts(_listing(f"h = CreateMutexA(0, 1, {_c(MUTEX)});"))
        rows = with_held_in([_host("mutex", MUTEX, "creates/writes", "ev_0010")], texts)
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64)),
            verdict="Malware",
            overall_confidence=0.9,
            technical_analysis=TechnicalAnalysis(host_identifiers=rows),
        )

        assert rows[0].held_in == ["ev_0010"]
        (exported,) = [row for row in build_consolidated_iocs(report) if row.source == "analysis"]
        assert exported.value == MUTEX
        assert exported.published.startswith(
            "yes: stated by the analysis (mutex, creates/writes), found whole in ev_0010"
        )

    def test_an_entry_declaring_no_kind_is_read_in_the_plain_spellings(self) -> None:
        texts = _texts(_listing(f"h = CreateMutexA(0, 1, {_c(MUTEX)});", tool="source_view"))

        assert held_in_cited(texts, _host("mutex", MUTEX, "creates/writes", "ev_0010")) == []

    def test_a_value_s_own_escapes_are_still_not_read(self) -> None:
        texts = _texts(_listing(f"p = {_c(PATH)};"))

        assert (
            held_in_cited(texts, _host("registry key", PATH + "\\x5c", "reads/checks", "ev_0010"))
            == []
        )


class TestTheStatedValueCheckIsUnchanged:
    def test_a_backslash_value_is_held_by_a_one_level_literal_in_any_entry(self) -> None:
        texts = _texts(_entry("ev_0012", "floss", json.dumps({"code": f"p = {_c(PATH)};"})))
        rows = {
            "identifiers": [{"kind": "registry key", "value": PATH, "evidence_refs": ["ev_0012"]}]
        }

        assert stated_value_violations(rows, texts) == []
