"""A numbered claim heading whose emphasis and note stand in either order before a dot is read.

Revision answers wrote every claim whole, with its EVIDENCE, CONFIDENCE and
TECHNIQUE lines, under headings such as ``**CLAIM 1** (revises claim 2). …``,
``**CLAIM 1 (revised, decoder).** …`` and ``CLAIM 1 (upstream: …). Outcome: …``.
The heading rule read a note only right after the number and a heading only
at a colon or a dash, so each answer read as no claim at all and the
revision was not made. A numbered heading's note may now stand after the
emphasis that closes its label, and a dot after a numbered heading's note is
its delimiter, as a colon is.

What stays unread: a heading with no number or no note before the dot
(``CLAIM 1. …``, ``**CLAIM** (new). …``), labels other than ``CLAIM``
(``**C1 [KEPT] …**``, ``**R1. …**``, ``**U1. …**``), prose that names a claim,
and lines that quote one inside a DISPUTES section or a mediator's line. A
numbered heading ended by a dot with no note, its next written line a claim
field line, is a claim begun and not read: counted as begun, so the shortfall
sentence and the cut-answer question name it. A heading ended by a dot under
a DISPUTES section opens no claim block there and does not end the section.
Every answer the rule read before reads exactly as it did, and a line costs
time linear in its length however its marks and brackets are written.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from malspark.agents import claim_headings
from malspark.agents.base_agent import answer_is_isr, claims_unread_sentence, read_claim_blocks
from malspark.agents.claim_headings import (
    CLAIM_HEAD_RE,
    LINE_PREFIX,
    besides_claims,
    claim_blocks,
    count_claims_after_disputes,
    count_claims_begun,
    disputes_section,
    heading_note,
    heading_number,
    heading_sentence,
)
from malspark.agents.repeat_watch import ClaimRepeatReader
from malspark.pipeline.retry_merge import read_withdrawals
from malspark.pipeline.validation import analyst_cut_violation
from tests.claim_block_counts import begun_and_distinct
from tests.linear_cost import assert_scales, assert_under, cpu_seconds

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "claims"

# The heading rule before this change, verbatim, for the comparisons below.
_BEFORE_HEAD_RE = re.compile(
    r"^" + LINE_PREFIX + r"CLAIM(?:(?:[ \t]++#?(?P<label>[A-Za-z]++)|[ \t]*+#?)(?P<number>\d++))?"
    r"(?:[ \t]*+(?P<note>\([^)\n]*+\)|\[[^\]\n]*+\]))?[ \t]*+(?:\*\*)?[ \t]*+"
    r"(?:(?P<delim>:|—|–|-(?=\s))[ \t]*+(?:\*\*)?[ \t]*+|(?(note)$|(?!)))"
)


class TestTheHeadingsNowRead:
    @pytest.mark.parametrize(
        ("line", "number", "note", "sentence"),
        [
            (
                "**CLAIM 1** (revises round-0 claim 2). The imports are two.",
                "1",
                "(revises round-0 claim 2)",
                "The imports are two.",
            ),
            (
                "**CLAIM 2 (revised, decoder).** The decoder is a rolling XOR.",
                "2",
                "(revised, decoder)",
                "The decoder is a rolling XOR.",
            ),
            (
                "**CLAIM 3 (UNCHANGED, now verified).** The file is a DLL.",
                "3",
                "(UNCHANGED, now verified)",
                "The file is a DLL.",
            ),
            (
                "CLAIM 4 (upstream: decoded text, routine 0x1400). Outcome: **Confirmed.** It is.",
                "4",
                "(upstream: decoded text, routine 0x1400)",
                "Outcome: **Confirmed.** It is.",
            ),
            ("**CLAIM 5** [KEPT]: It reads a file.", "5", "[KEPT]", "It reads a file."),
            ("**CLAIM 6** [KEPT] — It reads a file.", "6", "[KEPT]", "It reads a file."),
            ("CLAIM 7 [new]. It reads a file.", "7", "[new]", "It reads a file."),
            ("- **CLAIM 8** (new). It reads a file.", "8", "(new)", "It reads a file."),
            ("CLAIM R9 (kept). It reads a file.", "R9", "(kept)", "It reads a file."),
        ],
    )
    def test_the_heading_gives_its_number_note_and_sentence(
        self, line: str, number: str, note: str, sentence: str
    ) -> None:
        heading = CLAIM_HEAD_RE.match(line)

        assert heading is not None
        assert heading_number(heading) == number
        assert heading_note(heading) == note
        assert heading_sentence(line, heading) == sentence

    def test_a_note_after_the_emphasis_alone_on_its_line_is_its_sentence(self) -> None:
        line = "**CLAIM 3** (REVISED — not observed)"
        heading = CLAIM_HEAD_RE.match(line)

        assert heading is not None
        assert heading_number(heading) == "3"
        assert heading_note(heading) is None
        assert heading_sentence(line, heading) == "(REVISED — not observed)"


class TestTheLinesThatStayUnread:
    @pytest.mark.parametrize(
        "line",
        [
            # No number before the dot.
            "**CLAIM** (new). It reads a key.",
            "CLAIM (a). It reads a key.",
            # Labels other than CLAIM.
            "**C1 [UNCHANGED] Identity.** The sample is a DLL.",
            "**C1 (UNCHANGED).** The sample is a DLL.",
            "**R1. The sample is a DLL.**",
            "**U1. capa PEB access (ev_0008) — CONFIRMED.** It reads the PEB.",
            "**Claim 1 (revises my 1).** The sample launches a DLL.",
            # Prose that names a claim, and a heading with no delimiter.
            "Claim 3 (static). The claim is wrong.",
            "As CLAIM 3 (static). says, the key is read.",
            "CLAIM 3 (static) is wrong because the flag is a Rich header.",
            "**CLAIM 3** (static) is wrong because the flag is a Rich header.",
            "CLAIM 3 (static)(network). It reads a key.",
            # A mediator's line, as an answer may quote it.
            "L1 [new] STATIC CLAIM 3 (packer). The packer flag rests on one rule.",
            "- (standing: blocking) L2 [carried: L1] CLAIM 3 (static). The flag stands.",
        ],
    )
    def test_the_line_is_no_heading(self, line: str) -> None:
        assert CLAIM_HEAD_RE.match(line) is None
        assert count_claims_begun(line + "\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5") == 0


# A revision read in part: two headings read, and a third claim written whole
# under a heading ended by a dot with no note.
_READ_IN_PART = """CLAIM 1 (kept). Routine 0x3ae78 decodes the string table with a rolling XOR key.
EVIDENCE: [ev_0001]
CONFIDENCE: 0.9
TECHNIQUE: T1140

CLAIM 2 (revised). Routine 0x46f48 downloads a file over WinINet and writes it to disk.
EVIDENCE: [ev_0002]
CONFIDENCE: 0.85
TECHNIQUE: T1105

---

CLAIM 3. Routine 0x43868 passes the decoded name to CreateMutexW, so the mutex is named.
EVIDENCE: [ev_0003], [ev_0138]
CONFIDENCE: 0.8
TECHNIQUE: NONE
"""


class TestALineBegunAsAHeadingAndNotRead:
    @pytest.mark.parametrize(
        "line",
        [
            "CLAIM 3. Routine 0x1400 opens a mutex.",
            "**CLAIM 3.** Routine 0x1400 opens a mutex.",
            "**CLAIM 3**. Routine 0x1400 opens a mutex.",
            "- CLAIM 3. Routine 0x1400 opens a mutex.",
            "### CLAIM R3. Routine 0x1400 opens a mutex.",
            "CLAIM #3 . Routine 0x1400 opens a mutex.",
        ],
    )
    @pytest.mark.parametrize("between", ["\n", "\n\n"], ids=["next-line", "after-a-blank"])
    def test_a_field_line_beneath_makes_it_a_claim_begun_and_not_read(
        self, line: str, between: str
    ) -> None:
        text = line + between + "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n"
        read = read_claim_blocks(text)

        assert CLAIM_HEAD_RE.match(line) is None
        assert count_claims_begun(text) == read.begun == 1
        assert read.claims == [] and read.unread == 1
        assert not answer_is_isr(text)

    @pytest.mark.parametrize(
        "text",
        [
            "CLAIM 3. Routine 0x1400 opens a mutex.",
            "CLAIM 3. Routine 0x1400 opens a mutex.\nIt does so twice.\nEVIDENCE: [ev_0003]",
            "**CLAIM 3.** The routine is prose.\n\nThe next paragraph is prose too.",
            "CLAIM 3. Routine 0x1400 opens a mutex.\n---\nEVIDENCE: [ev_0003]",
            # No number, or a note before the dot (read as a heading).
            "CLAIM. Routine 0x1400 opens a mutex.\nEVIDENCE: [ev_0003]",
            "Claim 3. Routine 0x1400 opens a mutex.\nEVIDENCE: [ev_0003]",
            "CLAIM 3: is read.\nCLAIM 3.5 of the spec.\nCONFIDENCE: 0.5",
        ],
        ids=["alone", "prose-beneath", "paragraphs", "separator", "no-number", "lowercase", "read"],
    )
    def test_with_no_field_line_beneath_it_counts_nothing(self, text: str) -> None:
        read = read_claim_blocks(text)

        assert (
            count_claims_begun(text)
            == read.begun
            == len([line for line in text.splitlines() if CLAIM_HEAD_RE.match(line)])
        )
        assert not read.unread

    def test_a_revision_read_in_part_names_the_claim_not_read(self) -> None:
        read = read_claim_blocks(_READ_IN_PART, require_evidence=True)

        assert [c.number for c in read.claims] == ["1", "2"]
        assert (read.begun, read.read, read.unread) == (3, 2, 1)
        assert answer_is_isr(_READ_IN_PART)
        sentence = claims_unread_sentence("reverser", read, 2)
        assert "began 3 claim(s), and 2 were read; 1 could not be read as a claim" in sentence
        question = analyst_cut_violation(4096, _READ_IN_PART)
        assert "began 3 CLAIM block(s)" in question.message
        # Not read as a claim: the repeat check keys the two blocks read.
        assert begun_and_distinct(_READ_IN_PART) == (2, 2)
        streamed = _streamed(_READ_IN_PART)
        assert (streamed.begun, streamed.distinct) == (2, 2)

    def test_under_a_disputes_section_it_is_not_counted(self) -> None:
        text = (
            "CLAIM 1: The sample is a DLL.\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.9\n\n"
            "DISPUTES:\nCLAIM 3. The packer flag rests on a Rich header.\nEVIDENCE: [ev_0004]\n"
        )
        read = read_claim_blocks(text)

        assert count_claims_begun(text) == read.begun == 1
        assert count_claims_after_disputes(text) == read.after_disputes == 0
        assert not read.unread


# A revision answer in the shapes above: the emphasis before the note, then a
# DISPUTES section quoting a peer's claims in the same shape, bulleted, quoted
# and on a line of its own, each with a field line after it.
_EMPHASIS_THEN_NOTE = """## Round 1 revision

**CLAIM 1** (confirms round-0 claims 1 and 4). The sample is an unsigned 64-bit DLL.
EVIDENCE: [ev_0003], [ev_0004]
CONFIDENCE: 0.95
TECHNIQUE: NONE

**CLAIM 2** (revises round-0 claim 2). The categorised imports are two.
EVIDENCE: [ev_0004]
CONFIDENCE: 0.85
TECHNIQUE: T1106

DISPUTES:
- **CLAIM 3** (static analyst). The packer flag rests on a Rich header alone.
  EVIDENCE: [ev_0004]
> **CLAIM 9** (network analyst). The beacon interval is not shown.
SUMMARY: two claims stand.
"""

# The note inside the emphasis, and the plain form with prose after the dot.
_NOTE_THEN_EMPHASIS = """**ROUND 1 REVISIONS.** Claims 22 and 23 are withdrawn; the rest stand.

---

**CLAIM 1 (revised, decoder).** The string decoder at 0x1400 is a rolling XOR.
EVIDENCE: [ev_0007] (0x1400 listing)
CONFIDENCE: 0.90
TECHNIQUE: T1140, T1027

**CLAIM 2 (new, dispatcher).** Routine 0x1800 switches on a numeric code.
EVIDENCE: [ev_0009]
CONFIDENCE: 0.80
TECHNIQUE: NONE

CLAIM 3 (upstream: the mutex name). Outcome: **Confirmed.** The guard opens a mutex.
EVIDENCE: [ev_0011]
CONFIDENCE: 0.85
TECHNIQUE: NONE
"""


class TestWholeAnswers:
    def test_the_emphasis_before_the_note_reads_each_claim_and_no_dispute(self) -> None:
        read = read_claim_blocks(_EMPHASIS_THEN_NOTE, require_evidence=True)

        assert answer_is_isr(_EMPHASIS_THEN_NOTE)
        assert read.begun == count_claims_begun(_EMPHASIS_THEN_NOTE) == 2
        assert read.after_disputes == count_claims_after_disputes(_EMPHASIS_THEN_NOTE) == 0
        assert read.blocks_read == 2 and not read.unread
        assert [(c.number, c.heading_note, c.claim) for c in read.claims] == [
            ("1", "(confirms round-0 claims 1 and 4)", "The sample is an unsigned 64-bit DLL."),
            ("2", "(revises round-0 claim 2)", "The categorised imports are two."),
        ]
        # The peer's claims quoted under DISPUTES stay disputes.
        assert "**CLAIM 3** (static analyst)" in disputes_section(_EMPHASIS_THEN_NOTE)
        assert "**CLAIM 9** (network analyst)" in disputes_section(_EMPHASIS_THEN_NOTE)
        assert "packer flag" in besides_claims(_EMPHASIS_THEN_NOTE)
        assert "unsigned 64-bit DLL" not in besides_claims(_EMPHASIS_THEN_NOTE)

    def test_a_dot_heading_with_a_field_line_under_disputes_leaves_the_section_whole(
        self,
    ) -> None:
        text = (
            "CLAIM 1: The sample is an unsigned 64-bit DLL.\nEVIDENCE: [ev_0003]\n"
            "CONFIDENCE: 0.95\n\nDISPUTES:\n"
            "- **CLAIM 3** (static analyst). The packer flag rests on a Rich header alone.\n"
            "CLAIM 4 (STATIC's). I reject the reading; the bytes show otherwise.\n"
            "EVIDENCE: [ev_0009] shows the bytes.\n"
            "I also dispute the network analyst's interval.\n"
            "SUMMARY: done.\n"
        )
        read = read_claim_blocks(text)
        section = disputes_section(text)

        assert [c.number for c in read.claims] == ["1"]
        assert count_claims_after_disputes(text) == read.after_disputes == 0
        assert section is not None
        assert "CLAIM 4 (STATIC's). I reject the reading" in section
        assert "I also dispute the network analyst's interval." in section
        assert "SUMMARY" not in section

    def test_the_note_inside_the_emphasis_reads_each_claim(self) -> None:
        read = read_claim_blocks(_NOTE_THEN_EMPHASIS, require_evidence=True)

        assert read.begun == 3 and read.blocks_read == 3 and not read.unread
        assert read.after_disputes == count_claims_after_disputes(_NOTE_THEN_EMPHASIS) == 0
        by_number = {c.number: c for c in read.claims}
        assert by_number["1"].claim == "The string decoder at 0x1400 is a rolling XOR."
        assert {c.technique_id for c in read.claims if c.number == "1"} == {"T1140", "T1027"}
        assert by_number["3"].heading_note == "(upstream: the mutex name)"
        assert by_number["3"].claim.startswith("Outcome: **Confirmed.** The guard")
        assert "withdrawn" in besides_claims(_NOTE_THEN_EMPHASIS)
        # The prose that opens the answer withdraws by no WITHDRAW line.
        assert not read_withdrawals(_NOTE_THEN_EMPHASIS)

    @pytest.mark.parametrize("text", [_EMPHASIS_THEN_NOTE, _NOTE_THEN_EMPHASIS])
    @pytest.mark.parametrize("piece", [1, 3, 64])
    def test_the_streaming_reader_counts_them_as_the_check_does(
        self, text: str, piece: int
    ) -> None:
        reader = ClaimRepeatReader(None)
        for at in range(0, len(text), piece):
            reader.feed(text[at : at + piece])
            count = reader.count()
            assert (count.begun, count.distinct) == begun_and_distinct(text[: at + piece])
        assert begun_and_distinct(text) == (len(claim_blocks(text)),) * 2


def _strings(value: Any, where: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(where, value)] if "CLAIM" in value else []
    if isinstance(value, dict):
        return [row for key, item in value.items() for row in _strings(item, f"{where}/{key}")]
    if isinstance(value, list):
        return [row for n, item in enumerate(value) for row in _strings(item, f"{where}/{n}")]
    return []


def _fixture_answers() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for path in sorted(FIXTURES.iterdir()):
        raw = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            out.extend(_strings(json.loads(raw), path.name))
        else:
            out.append((path.name, raw))
    return out


def _every_reading(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for strict in (False, True):
        read = read_claim_blocks(text, require_evidence=strict)
        out[f"claims{strict}"] = [
            (c.model_dump(mode="json"), c.number, c.heading_note) for c in read.claims
        ]
        out[f"rest{strict}"] = (
            read.without_confidence,
            read.begun,
            read.after_disputes,
            read.confidence_unreadable,
            read.blocks_read,
        )
    out["begun"] = count_claims_begun(text)
    out["after"] = count_claims_after_disputes(text)
    out["blocks"] = claim_blocks(text)
    out["besides"] = besides_claims(text)
    out["disputes"] = disputes_section(text)
    out["isr"] = answer_is_isr(text)
    out["counts"] = begun_and_distinct(text)
    return out


class TestWhatWasReadBeforeReadsTheSame:
    LINES = [
        "CLAIM: It reads a file.",
        "CLAIM 3: It reads a file.",
        "CLAIM R3: It reads a file.",
        "**CLAIM 4 (REVISED):** It reads a file.",
        "CLAIM 2 [REVISED — retracts claim 5]: It reads a file.",
        "CLAIM 5 [KEPT] — It reads a file.",
        "CLAIM 6 (REVISED — not observed)",
        "**CLAIM 7 [KEPT]** ",
        "- CLAIM [it reads a file] **",
        "**CLAIM 1**: It reads a file.",
        "> CLAIM #7: It reads a file.",
        "1. CLAIM — It reads a file.",
        "CLAIM - It reads a file.",
        "CLAIM (new): It reads a file.",
        "CLAIM 3 (a). b: c",
        "CLAIM 3 (a) - b",
    ]

    @pytest.mark.parametrize("line", LINES)
    def test_a_line_read_before_is_read_with_the_same_parts(self, line: str) -> None:
        before = _BEFORE_HEAD_RE.match(line)
        now = CLAIM_HEAD_RE.match(line)

        if before is None:
            # Read now only as one of the forms this change adds.
            assert now is None or now.group("delim") == "."
            return
        assert now is not None
        assert now.span() == before.span()
        assert now.groupdict() == before.groupdict()

    def test_every_fixture_answer_reads_as_it_did(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answers = _fixture_answers()
        assert len(answers) >= 20
        for where, text in answers:
            now = _every_reading(text)
            with monkeypatch.context() as patched:
                patched.setattr(claim_headings, "CLAIM_HEAD_RE", _BEFORE_HEAD_RE)
                before = _every_reading(text)
            assert now == before, where


# Hostile lines: long emphasis runs, nested and unclosed brackets, a dot and a
# note repeated, each a head and one unit repeated to ``size`` characters.
_HOSTILE_PARTS = {
    "unclosed note after the emphasis": ("**CLAIM 1** (", "a", ""),
    "emphasis run before the note": ("**CLAIM 1 ", "*", " (a). b"),
    "emphasis and spaces after the number": ("CLAIM 1", " **", "(a). b"),
    "nested round brackets": ("**CLAIM 1** ", "(", "a). b"),
    "nested mixed brackets": ("**CLAIM 1** ", "[(", ""),
    "notes and dots repeated": ("", "**CLAIM 1** (a).", ""),
    "headings repeated on one line": ("", "**CLAIM 1** (a). b ", ""),
}
# The shapes a heading's match reads to their end; on the others it stops
# within a few characters, so its time does not grow and has no ratio.
_READ_TO_THE_END = {
    "unclosed note after the emphasis",
    "nested round brackets",
    "nested mixed brackets",
}


def _hostile(shape: str, size: int) -> str:
    head, unit, tail = _HOSTILE_PARTS[shape]
    return head + unit * max(1, size // len(unit)) + tail


def _streamed(text: str) -> Any:
    reader = ClaimRepeatReader(None)
    for at in range(0, len(text), 4096):
        reader.feed(text[at : at + 4096])
    return reader.count()


_READERS = {
    "heading": lambda text: CLAIM_HEAD_RE.match(text),
    "count_claims_begun": count_claims_begun,
    "claim_blocks": claim_blocks,
    "read_claim_blocks": read_claim_blocks,
    "streaming": _streamed,
}


def _small_size(shape: str, read: Any) -> int:
    """The line length whose read takes a few milliseconds, so a ratio can be read from it."""
    size = 20_000
    while size < 4_000_000:
        text = _hostile(shape, size)
        if cpu_seconds(lambda text=text: read(text)) >= 0.004:
            break
        size *= 2
    return size


class TestTheCostStaysLinear:
    @pytest.mark.parametrize("shape", sorted(_HOSTILE_PARTS))
    @pytest.mark.parametrize("reader", sorted(_READERS))
    def test_a_megabyte_line_is_read_in_bounded_time(self, shape: str, reader: str) -> None:
        text, read = _hostile(shape, 1 << 20), _READERS[reader]

        assert count_claims_begun(text) in (0, 1)
        assert_under(lambda: read(text), 2.0, what=f"{reader} over a megabyte of {shape}")

    @pytest.mark.parametrize(
        ("shape", "reader"),
        [
            (shape, reader)
            for shape in sorted(_HOSTILE_PARTS)
            for reader in sorted(_READERS)
            if reader != "heading" or shape in _READ_TO_THE_END
        ],
    )
    def test_four_times_the_line_costs_about_four_times_as_much(
        self, shape: str, reader: str
    ) -> None:
        read = _READERS[reader]
        small = _small_size(shape, read)
        assert_scales(lambda size: _hostile(shape, size), small, read, factor=4)
