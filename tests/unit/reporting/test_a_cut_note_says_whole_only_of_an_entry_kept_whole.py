"""A note under a cut value says "whole" only of an entry kept whole (T-776).

At build time the entry is at hand: the text cut to the report's room is said
carried whole only where the entry reading keeps the entry whole; otherwise
the note says where the entry is held, and that the job's store holds the
answer whole where the reading says so. At render time the report's index
row is the one record of a cut: a section citing an entry whose row says it
was cut says only where the entry is held, and any other keeps its words.
Every tool name and value here is a neutral synthetic value.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.reporting.builder import evidence_index_row
from malspark.reporting.ledger_report import build_sections
from malspark.reporting.models import EvidenceSection, FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.markdown import MarkdownRenderer, cites_a_cut_entry
from malspark.schemas.evidence import LedgerEntry

PROSE = "word " * 1_200
_SPILLED = {"part": "answer", "key": "jobs/1/answer", "sha256": "0" * 64, "bytes": 9_000}


def _prose(**kw: Any) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0040", tool="read_notes", agent="reader_one", args={}, output=PROSE, **kw
    )


def _text(entry: LedgerEntry) -> str:
    return next(s.text for s in build_sections([entry]) if "ev_0040" in s.evidence_ids)


def test_a_text_cut_from_an_entry_kept_whole_is_carried_whole() -> None:
    assert _text(_prose()).endswith("; the evidence endpoint carries it whole under ev_0040.")


def test_a_text_cut_from_an_entry_cut_says_where_the_entry_is_held() -> None:
    said = _text(_prose(truncated=True, chars_dropped=4_000))

    assert said.endswith("; the evidence endpoint carries the entry under ev_0040.")
    assert "whole" not in said.rsplit("\n", 1)[-1]


def test_a_text_cut_from_an_entry_cut_names_the_store_s_copy_where_one_is_held() -> None:
    said = _text(_prose(truncated=True, chars_dropped=4_000, spilled=[_SPILLED]))

    assert said.endswith(
        "; the evidence endpoint carries the entry under ev_0040; the store holds the answer whole."
    )


CUT = "http://example.invalid/" + "A" * 280
ANSWER = {
    "strings": [CUT, "short"],
    "shortened": {"/strings/0": {"kept_chars": len(CUT), "omitted_chars": 4_700}},
    "truncated": True,
}


def _appendix(entry: LedgerEntry) -> str:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        evidence_index=[evidence_index_row(entry)],
        sections=build_sections([entry]),
    )
    markdown = MarkdownRenderer().render(report)
    return markdown[markdown.index("Appendix A") : markdown.index("Appendix B")]


def _hashes(**kw: Any) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0001",
        tool="hashes",
        agent="reader_one",
        args={},
        output=json.dumps(ANSWER),
        structured=ANSWER,
        **kw,
    )


def test_a_value_of_an_entry_its_index_row_says_was_cut_is_not_said_whole() -> None:
    appendix = _appendix(_hashes(truncated=True))

    assert "is cut to fit the page" in appendix
    assert "carries it whole" not in appendix
    assert (
        "no code is cut to fit it); the evidence ledger holds the entry under ev_0001._"
    ) in appendix


def test_a_value_of_an_entry_kept_whole_keeps_its_words() -> None:
    whole = {"strings": [CUT, "short"]}
    entry = LedgerEntry(
        id="ev_0001",
        tool="hashes",
        agent="reader_one",
        args={},
        output=json.dumps(whole),
        structured=whole,
    )

    assert (
        "no code is cut to fit it); the evidence ledger carries it whole under ev_0001._"
    ) in _appendix(entry)


def test_a_stored_index_row_is_read_as_the_model_s() -> None:
    rows = [{"id": "ev_0001", "truncated": True}, {"id": "ev_0002", "truncated": False}]

    assert cites_a_cut_entry(["ev_0001"], rows)
    assert not cites_a_cut_entry(["ev_0002"], rows)
    assert not cites_a_cut_entry([], rows)


def test_a_text_cut_from_an_entry_that_holds_only_its_output_in_the_store_is_not_said_whole() -> (
    None
):
    output = {**_SPILLED, "part": "output"}
    said = _text(_prose(truncated=True, chars_dropped=4_000, spilled=[output]))

    assert said.endswith(
        "; the evidence endpoint carries the entry under ev_0040; the store holds the entry's "
        "output."
    )


def test_a_text_cut_from_a_failed_entry_says_where_the_entry_is_held() -> None:
    failed = LedgerEntry(
        id="ev_0040",
        tool="read_notes",
        agent="reader_one",
        args={},
        output=json.dumps({"error": "1 of 2 failed", "notes": PROSE}),
    )

    assert _text(failed).endswith("; the evidence endpoint carries the entry under ev_0040.")


def test_a_text_cut_from_a_repeat_says_where_the_entry_is_held() -> None:
    repeat = _prose(repeated_of="ev_0039")

    assert _text(repeat).endswith("; the evidence endpoint carries the entry under ev_0040.")


def _value_report(*entries: LedgerEntry) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        evidence_index=[evidence_index_row(entry) for entry in entries],
        sections=[
            EvidenceSection(
                key="tool_values",
                title="Values",
                kind="kv",
                columns=["Field", "Value"],
                rows=[["value", CUT]],
                evidence_ids=[entry.id for entry in entries],
                source="tool:hashes",
            )
        ],
    )


def _rendered(report: MalwareReport) -> str:
    markdown = MarkdownRenderer().render(report)
    return markdown[markdown.index("Appendix A") : markdown.index("Appendix B")]


def test_a_value_of_a_section_citing_a_cut_and_a_whole_entry_is_not_said_whole() -> None:
    whole = LedgerEntry(id="ev_0002", tool="hashes", agent="reader_one", args={}, output="x")
    appendix = _rendered(_value_report(_hashes(truncated=True), whole))

    assert "carries it whole" not in appendix
    assert "no code is cut to fit it); the evidence ledger holds the entries cited below._" in (
        appendix
    )


BODY = "int FUN_00401000(int a)\n{\n" + "  a = a + 1;\n" * 40 + "  return a;\n}\n"


def test_a_listing_the_report_holds_cut_of_a_cut_entry_is_not_said_whole() -> None:
    listing = LedgerEntry(
        id="ev_0007",
        tool="lift_many",
        agent="reader_one",
        args={"functions": "0x401000"},
        output=json.dumps({"0x401000": BODY[:300]}),
        truncated=True,
        chars_dropped=900,
        facts={"v": 1, "kind": "decompile_batch", "reader": "listing"},
    )
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        evidence_index=[evidence_index_row(listing)],
        sections=[
            EvidenceSection(
                key="tool_functions",
                title="Functions",
                kind="kv",
                columns=["Field", "Value"],
                rows=[["0x401000", BODY[:300] + "…"]],
                evidence_ids=["ev_0007"],
                source="tool:lift_many",
            )
        ],
    )

    assert (
        "_The report was built with this listing cut at the …; the evidence ledger holds the "
        "entry under ev_0007._"
    ) in _rendered(report)


def test_an_index_row_stored_before_the_cut_was_recorded_keeps_its_words() -> None:
    entry = _hashes(truncated=True)
    stored = _value_report(entry).model_dump(mode="json")
    for row in stored["evidence_index"]:
        del row["truncated"]

    assert not cites_a_cut_entry([entry.id], stored["evidence_index"])
    assert (
        "no code is cut to fit it); the evidence ledger carries it whole under ev_0001._"
    ) in _rendered(MalwareReport.model_validate(stored))
