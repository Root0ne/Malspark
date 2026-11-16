"""A kept closing sentence whose quote stands in the body is not lost to a word test (T-705).

The agreement round lets the report model keep a sentence of the conclusion, the
limitations, a value cell or a capability bullet by quoting the words of a source that
state the same. Whether the quote is about what the sentence denies something of was read
off words: two words of what stands before the sentence's first negation, and what a denied
item is. An active-voice denial ("The sandbox run did not exercise the gated branch"), a
relative clause ("The decodings that no code refers to were not examined"), a pronoun or a
paraphrase put the quote's words elsewhere, so true sentences whose quote stands word for
word in a section 5 passage were refused, and after the retry left out.

Such a sentence is now replaced, where its quote fails that word test alone, by the
source's own sentence holding the quote, whole with its own citations; the replacement is
recorded with the model's sentence whole. Every other refusal ends as before: a quote
standing in no source it names, one stating no absence, one of a passage written without
the code, which its refusal now names as the reason, and one no single sentence of the
source holds. A sentence left out or replaced is recorded whole, however long. The texts
quote one stored run's sentences as examples; the second shape is made up.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Any

import pytest

from malspark.pipeline.validation import ValidationTally
from malspark.reporting.models import (
    CapabilityBullet,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    AGREEMENT_PRODUCER,
    DROPPED_CODE,
    FACT,
    KEEP_UNQUOTED_CODE,
    KEPT_IN_SOURCE_WORDS_CODE,
    QUALIFIED_CODE,
    Passage,
    agreement_violations,
    apply_rows,
    passages_of,
)

# A section 5 passage the code's reading backs, and two closing sentences it states in
# other words (one stored run's limitations).
BRANCH = (
    "Both sandbox detonations ran the bare executable, and no option-gated or argument-gated "
    "branch was exercised [ev_0028]."
)
C2 = f"The sample reads its command line at start [ev_0003]. {BRANCH} It writes a note [ev_0004]."
GATED = (
    "The sandbox run did not exercise the gated branch: file encryption and ransom-note "
    "creation were not seen at run time [ev_0028]."
)
DECODINGS = "A further 968 decodings are referenced by no code and were not reviewed [ev_0021]."
UNEXAMINED = "The 968 decodings that no code refers to were not examined [ev_0021]."
# A made-up shape: a capability bullet whose quote names the record, not the block.
STORED = (
    "The settings record of 512 bytes is stored in clear, and no cipher routine reads it [ev_0011]."
)
RESOLUTION = f"The import table names 46 functions [ev_0004]. {DECODINGS} {STORED}"
CLEAR = "The configuration block is not encrypted."
# A closing sentence whose quote passes the word test as it is.
REVIEWED = "The 968 decodings were not reviewed [ev_0021]."
CLAIMED = "Persistence: the analysts hold that no service was ever created on the host."


def _report(limitations: str = f"{GATED} {UNEXAMINED}", bullet: str = "") -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_type="PE32 executable"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(title="C2", body=C2, evidence_refs=["ev_0028"]),
            string_resolution=TechnicalSubsection(
                title="Resolution", body=RESOLUTION, evidence_refs=["ev_0004"]
            ),
            packing_obfuscation=TechnicalSubsection(title="Packing", body=CLAIMED),
            capability_summary=[CapabilityBullet(text=bullet)],
            analyst_limitations=TechnicalSubsection(title="Limitations", body=limitations),
        ),
    )


def _keep(passage: str, sentence: str, source: str, quote: str) -> dict[str, Any]:
    return {
        "passage": passage,
        "sentence": sentence,
        "decision": "keep",
        "sources": [source],
        "quote": quote,
    }


def _applied(report: MalwareReport, *rows: dict[str, Any]) -> list[Any]:
    _counts, found = apply_rows({"sentences": list(rows)}, passages_of(report))
    return found


def _limitations(report: MalwareReport) -> str:
    ta = report.technical_analysis
    assert ta is not None and ta.analyst_limitations is not None
    return ta.analyst_limitations.body


def _refusal(report: MalwareReport, row: dict[str, Any]) -> str:
    found = agreement_violations({"sentences": [row]}, passages_of(report))
    (refused,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
    return refused.message


@pytest.mark.parametrize(
    ("sentence", "quote", "printed"),
    [
        # An active-voice denial: the check read the actor ("run", "sandbox").
        (
            GATED,
            "and no option-gated or argument-gated branch was exercised",
            BRANCH,
        ),
        # A relative clause: the check read "refers" alone.
        (UNEXAMINED, "referenced by no code and were not reviewed", DECODINGS),
    ],
)
def test_a_keep_refused_only_for_its_words_prints_the_source_s_sentence(
    sentence: str, quote: str, printed: str
) -> None:
    report = _report()
    source = "command_and_control" if printed == BRANCH else "string_resolution"
    row = _keep("limitations", sentence, source, quote)
    # Refused for its words alone, as before.
    assert "shares too few of the words" in _refusal(report, row)
    found = _applied(report, row)
    # Not left out: the source's own sentence, whole with its citation, stands in its place.
    assert printed in _limitations(report)
    assert sentence not in _limitations(report)
    assert DROPPED_CODE not in [v.code for v in found]
    (record,) = [v for v in found if v.code == KEPT_IN_SOURCE_WORDS_CODE]
    assert record.stood == sentence
    assert source in record.message and record.subject == ""


def test_a_bullet_keep_refused_only_for_its_words_prints_the_source_s_sentence() -> None:
    report = _report(bullet=CLEAR)
    row = _keep("capability_summary.1", CLEAR, "string_resolution", "no cipher routine reads it")
    assert "of the words" in _refusal(report, row) or "names none of" in _refusal(report, row)
    found = _applied(report, row)
    ta = report.technical_analysis
    assert ta is not None
    assert ta.capability_summary[0].text == STORED
    assert [v.code for v in found] == [KEPT_IN_SOURCE_WORDS_CODE]


def test_the_other_sentences_of_the_passage_stand_as_written() -> None:
    report = _report()
    quote = "no option-gated or argument-gated branch was exercised"
    _applied(report, _keep("limitations", GATED, "command_and_control", quote))
    assert _limitations(report) == f"{BRANCH} {UNEXAMINED}"


@pytest.mark.parametrize(
    ("source", "quote", "said"),
    [
        # Standing in no source it names.
        ("command_and_control", "no gated branch ran in any guest", "does not stand in a source"),
        # Stating no absence, while the sentence states one.
        ("command_and_control", "Both sandbox detonations ran the bare executable", "states no"),
        # A passage written without the code backs no closing keep.
        ("packing_obfuscation", "no service was ever created on the host", "written without"),
        # Shorter than the floor.
        ("command_and_control", "no branch", "is shorter than"),
    ],
)
def test_every_other_refusal_leaves_the_sentence_out_as_before(
    source: str, quote: str, said: str
) -> None:
    report = _report()
    row = _keep("limitations", GATED, source, quote)
    assert said in _refusal(report, row)
    found = _applied(report, row)
    assert GATED not in _limitations(report) and BRANCH not in _limitations(report)
    assert [v.code for v in found] == [DROPPED_CODE]


def test_a_quote_no_single_sentence_of_the_source_holds_leaves_the_sentence_out() -> None:
    # The quote stands in two sentences of the source: which one states the sentence is not
    # known, so neither is printed in its place.
    report = _report()
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    ta.string_resolution.body = (
        f"{RESOLUTION} The heap was not reviewed by any tool [ev_0005]. The stack was not "
        "reviewed by any tool [ev_0006]."
    )
    quote = "was not reviewed by any tool"
    row = _keep("limitations", UNEXAMINED, "string_resolution", quote)
    assert "of the words" in _refusal(report, row) or "names none of" in _refusal(report, row)
    found = _applied(report, row)
    assert [v.code for v in found] == [DROPPED_CODE]
    assert _limitations(report) == GATED


def test_a_source_sentence_already_standing_in_the_passage_is_printed_once() -> None:
    paths = "The destructive paths were not exercised in the sandbox run [ev_0028]."
    report = _report(limitations=f"{GATED} {paths}")
    quote = "no option-gated or argument-gated branch was exercised"
    found = _applied(
        report,
        _keep("limitations", GATED, "command_and_control", quote),
        _keep("limitations", paths, "command_and_control", quote),
    )
    assert _limitations(report) == BRANCH
    assert [v.code for v in found] == [KEPT_IN_SOURCE_WORDS_CODE, DROPPED_CODE]
    assert "the sentence of command_and_control holding its quote already stands here" in (
        found[1].message
    )


def test_a_keep_that_passes_stands_as_written() -> None:
    report = _report(limitations=f"{GATED} {REVIEWED}")
    row = _keep(
        "limitations",
        REVIEWED,
        "string_resolution",
        "A further 968 decodings are referenced by no code and were not reviewed",
    )
    assert KEEP_UNQUOTED_CODE not in [
        v.code for v in agreement_violations({"sentences": [row]}, passages_of(report))
    ]
    found = _applied(report, row)
    assert _limitations(report) == f"{GATED} {REVIEWED}"
    assert KEPT_IN_SOURCE_WORDS_CODE not in [v.code for v in found]


# -- the refusal names the reason (Ruling 3) ----------------------------------------------


def test_a_quote_of_a_passage_written_without_the_code_is_told_so() -> None:
    report = _report()
    row = _keep(
        "limitations", GATED, "packing_obfuscation", "no service was ever created on the host"
    )
    said = _refusal(report, row)
    assert (
        "but its quote stands only in packing_obfuscation, a passage written without the "
        "code, which backs no keep of this sentence:"
    ) in said
    assert "does not stand in a source it names" not in said


def test_a_quote_standing_nowhere_is_still_told_it_stands_in_no_source() -> None:
    report = _report()
    row = _keep("limitations", GATED, "packing_obfuscation", "no gated branch ran in any guest")
    said = _refusal(report, row)
    assert "but its quote does not stand in a source it names:" in said
    assert "written without the code" not in said


# -- the record holds what was left out, whole (Ruling 2) ---------------------------------


def test_a_sentence_left_out_is_recorded_whole_however_long() -> None:
    long = (
        "The sandbox run did not exercise the gated branch: file encryption, ransom-note "
        "creation, the security product changes, the shadow copy deletion, the event log "
        "clearing and the service-based persistence were not seen at run time, and the "
        "encryption algorithm was not established [ev_0028]."
    )
    assert len(long) > 200
    report = _report(limitations=f"{long} {UNEXAMINED}")
    found = _applied(report, _keep("limitations", long, "command_and_control", "no branch"))
    tally = ValidationTally()
    tally.record_unresolved(AGREEMENT_PRODUCER, found)
    (row,) = [r for r in tally.unresolved if r["code"] == DROPPED_CODE]
    assert row["stood"] == long
    # The message keeps its bound.
    assert long not in row["message"]


def test_a_sentence_replaced_is_recorded_whole_however_long() -> None:
    long = (
        "The 968 decodings that no code refers to, among them the long runs of wide text, the "
        "format strings, the paths under the program data folder and the names of the "
        "services the file stops, were not examined [ev_0021]."
    )
    assert len(long) > 200
    report = _report(limitations=f"{GATED} {long}")
    quote = "referenced by no code and were not reviewed"
    found = _applied(report, _keep("limitations", long, "string_resolution", quote))
    tally = ValidationTally()
    tally.record_unresolved(AGREEMENT_PRODUCER, found)
    (row,) = [r for r in tally.unresolved if r["code"] == KEPT_IN_SOURCE_WORDS_CODE]
    assert row["stood"] == long
    assert _limitations(report) == f"{GATED} {DECODINGS}"


@pytest.mark.parametrize("registered", [False, True])
def test_the_whole_record_is_masked_but_never_cut(
    monkeypatch: pytest.MonkeyPatch, registered: bool
) -> None:
    from malspark.pipeline import events

    monkeypatch.setattr(events, "_SECRET_SCOPES", {})
    monkeypatch.setattr(events, "_SHORT_SECRETS", {})
    monkeypatch.setattr(events, "_FAILED_SCOPES", set())
    monkeypatch.setattr(events, "_CONFIGURED_PATTERN", None)
    value = "operator-value-of-this-job-" + "q" * 8
    if registered:
        events.remember_secret_values([value], scope="job")
    text = f"The run read {value} and " + "then a long list of other places " * 12 + "too."
    whole = events.safe_finding_value(text, whole=True)
    assert len(text) > 200 and whole.endswith("too.")
    assert len(events.safe_finding_value(text)) < len(whole)
    assert (value not in whole) is registered


def test_a_quote_also_refused_on_an_item_a_source_speaks_of_leaves_the_sentence_out() -> None:
    # A made-up shape: the quote speaks of who owns the launches, and another section 5
    # passage says who started them, which the sentence also denies.
    owned = "Which process owns the two launches, and who started them, was not established."
    attributes = "Nothing in the entries attributes the launches to a parent [ev_0012]."
    report = _report(limitations=owned)
    ta = report.technical_analysis
    assert ta is not None
    ta.command_and_control = TechnicalSubsection(
        title="C2", body=f"The sandbox recorded two launches of the sample [ev_0012]. {attributes}"
    )
    ta.discovery = TechnicalSubsection(
        title="Discovery",
        body="The service host started the launches at boot, by the parent process list [ev_0013].",
    )
    row = _keep("limitations", owned, "command_and_control", attributes.split(" [")[0])
    assert "shares too few of the words" in _refusal(report, row)
    found = _applied(report, row)
    assert [v.code for v in found] == [DROPPED_CODE]
    assert _limitations(report) == ""


# -- one sentence, and prose (Ruling 8) ---------------------------------------------------


def _resolution(report: MalwareReport, body: str) -> MalwareReport:
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    ta.string_resolution.body = body
    return report


@pytest.mark.parametrize(
    ("body", "quote"),
    [
        # A review's case: the quote runs from one sentence of the source into the next.
        (RESOLUTION, "no code and were not reviewed [ev_0021]. The settings record"),
        # A made-up shape: the same, with no citation between the two.
        (
            "The import table names 46 functions. A further 968 decodings are referenced by "
            "no code and were not reviewed. The settings record is clear.",
            "were not reviewed. The settings record",
        ),
    ],
)
def test_a_quote_running_across_two_sentences_leaves_the_sentence_out(
    body: str, quote: str
) -> None:
    report = _resolution(_report(), body)
    row = _keep("limitations", UNEXAMINED, "string_resolution", quote)
    assert "shares too few of the words" in _refusal(report, row)
    found = _applied(report, row)
    assert [v.code for v in found] == [DROPPED_CODE]
    assert _limitations(report) == GATED


@pytest.mark.parametrize(
    "body",
    [
        # A list item, its marker and its emphasis with it.
        f"The import table names 46 functions [ev_0004].\n- **Decodings**: {DECODINGS}\n- Next.",
        # A made-up shape: a numbered list item, whose marker stands apart from its words.
        f"The import table names 46 functions [ev_0004].\n1. {DECODINGS}\n2. {STORED}",
        # A table row.
        f"| What | Seen |\n|---|---|\n| decodings | {DECODINGS} |",
        # A review's case: a table's column bar inside the sentence.
        "The import table names 46 functions [ev_0004]. A further 968 decodings are "
        "referenced by no code and were not reviewed | as listed [ev_0021].",
        # A sentence broken over two lines.
        "The import table names 46 functions [ev_0004]. A further 968 decodings are "
        "referenced by no\ncode and were not reviewed [ev_0021].",
        # A line opening a list, which ends on no sentence's mark.
        "The import table names 46 functions [ev_0004]. A further 968 decodings are "
        "referenced by no code and were not reviewed, among them:\n- the wide ones.",
    ],
)
def test_a_source_sentence_that_is_no_prose_is_not_moved(body: str) -> None:
    report = _resolution(_report(), body)
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    assert "shares too few of the words" in _refusal(report, row)
    found = _applied(report, row)
    assert [v.code for v in found] == [DROPPED_CODE]
    assert _limitations(report) == GATED


def test_a_source_sentence_holding_an_abbreviation_is_moved_whole() -> None:
    # Words after an abbreviation open no sentence (T-719): the sentence holding them, from
    # its first word, is the source's sentence, and it reads as prose.
    said = (
        "The import table names 46 functions, e.g. the 968 decodings are referenced by no "
        "code and were not reviewed [ev_0021]."
    )
    report = _resolution(_report(), said)
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    found = _applied(report, row)
    assert [v.code for v in found] == [KEPT_IN_SOURCE_WORDS_CODE]
    assert said in _limitations(report)


@pytest.mark.parametrize(
    "quote",
    [
        # A review's case: it starts and ends inside a word.
        "eferenced by no code and were not revie",
        "eferenced by no code and were not reviewed",
        # A made-up shape: it ends inside a citation's id.
        "referenced by no code and were not reviewed [ev_00",
    ],
)
def test_a_quote_cut_inside_a_word_leaves_the_sentence_out(quote: str) -> None:
    report = _report()
    row = _keep("limitations", UNEXAMINED, "string_resolution", quote)
    assert "shares too few of the words" in _refusal(report, row)
    found = _applied(report, row)
    assert [v.code for v in found] == [DROPPED_CODE]
    assert _limitations(report) == GATED


# -- a sentence that points outside itself is not moved (Ruling 9) ------------------------


@pytest.mark.parametrize(
    "said",
    [
        "It lists 968 decodings that are referenced by no code and were not reviewed [ev_0021].",
        "Its 968 decodings are referenced by no code and were not reviewed [ev_0021].",
        "They hold 968 decodings that are referenced by no code and were not reviewed [ev_0021].",
        "Their 968 decodings are referenced by no code and were not reviewed [ev_0021].",
        "These 968 decodings are referenced by no code and were not reviewed [ev_0021].",
        "This leaves 968 decodings that are referenced by no code and were not reviewed [ev_0021].",
        "Those 968 decodings are referenced by no code and were not reviewed [ev_0021].",
        "Such decodings are referenced by no code and were not reviewed [ev_0021].",
        "Which of them matter is open: 968 are referenced by no code and were not reviewed "
        "[ev_0021].",
    ],
)
def test_a_source_sentence_opening_on_a_word_that_points_back_is_not_moved(said: str) -> None:
    report = _resolution(_report(), f"The import table names 46 functions [ev_0004]. {said}")
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    assert "shares too few of the words" in _refusal(report, row)
    found = _applied(report, row)
    assert [v.code for v in found] == [DROPPED_CODE]
    assert _limitations(report) == GATED


def test_a_source_sentence_opening_on_both_is_moved() -> None:
    # "Both" names its two items itself ("Both sandbox detonations ran…").
    said = "Both decoding tables are referenced by no code and were not reviewed [ev_0021]."
    report = _resolution(_report(), f"The import table names 46 functions [ev_0004]. {said}")
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    found = _applied(report, row)
    assert [v.code for v in found] == [KEPT_IN_SOURCE_WORDS_CODE]
    assert _limitations(report) == f"{GATED} {said}"


# -- what the round removed is not reprinted (Ruling 10) ----------------------------------


def _with(report: MalwareReport, pid: str, **changed: Any) -> list[Passage]:
    return [dataclasses.replace(p, **changed) if p.id == pid else p for p in passages_of(report)]


def test_a_source_sentence_the_round_leaves_out_is_not_printed_in_its_place() -> None:
    # The decodings' sentence is held by the ledger's lines and no row answers it: the round
    # leaves it out of section 5, after the row keeping the limitations' sentence is read.
    report = _report()
    passages = _with(report, "string_resolution", ledger_named=((DECODINGS, ("ev_0021",)),))
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    counts, found = apply_rows({"sentences": [row]}, passages)
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert DECODINGS not in ta.string_resolution.body
    assert _limitations(report) == GATED
    assert [v.code for v in found] == [DROPPED_CODE, DROPPED_CODE]
    assert counts["dropped"] == 2 and counts["replaced"] == 0


def test_a_source_sentence_the_round_qualifies_is_not_printed_in_its_place() -> None:
    # A made-up shape: the decodings' sentence calls code not read that an entry lists, so
    # the platform adds the ledger's fact to it once every row is in.
    report = _report()
    fact = Passage(
        id="listed.1",
        label="fact",
        text="The ledger lists the code of the routine at 0x2800 [ev_0003].",
        kind=FACT,
        qualifier="the ledger lists the code of the routine at 0x2800 [ev_0003]",
    )
    unread = ((DECODINGS, ("listed.1",), ("listed.1",)),)
    passages = [*_with(report, "string_resolution", unread_listed=unread), fact]
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    counts, found = apply_rows({"sentences": [row]}, passages)
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert "the ledger lists the code" in ta.string_resolution.body
    assert _limitations(report) == GATED
    assert [v.code for v in found] == [QUALIFIED_CODE, DROPPED_CODE]
    assert counts["qualified"] == 1 and counts["dropped"] == 1 and counts["replaced"] == 0
    assert "left out or changed by this round" in found[1].message


# -- counted and logged (Ruling 11) -------------------------------------------------------


def test_a_replacement_is_counted_as_one_and_not_as_a_drop() -> None:
    report = _report()
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    counts, _found = apply_rows({"sentences": [row]}, passages_of(report))
    assert counts["replaced"] == 1 and counts["dropped"] == 0 and counts["kept"] == 0


# -- each test of the rule holds (Ruling 13) ----------------------------------------------


def test_a_closing_text_printed_in_its_writer_s_own_words_is_never_reworded() -> None:
    report = _report()
    passages = _with(report, "limitations", verbatim="analyst")
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    _counts, found = apply_rows({"sentences": [row]}, passages)
    assert KEPT_IN_SOURCE_WORDS_CODE not in [v.code for v in found]
    assert DECODINGS not in _limitations(report)


def test_a_quote_naming_none_of_what_is_denied_prints_the_source_s_sentence() -> None:
    # A made-up shape: the quote shares two words of the sentence, but not what the denied
    # item is ("routine"), the second word test.
    key = "No cipher key for the 968 decodings was found in the file [ev_0021]."
    denied = "The decodings' cipher routine was not found."
    report = _resolution(
        _report(limitations=denied), f"The import table names 46 functions [ev_0004]. {key}"
    )
    row = _keep("limitations", denied, "string_resolution", key.split(" in the file")[0])
    assert "names none of what the sentence denies something of" in _refusal(report, row)
    found = _applied(report, row)
    assert [v.code for v in found] == [KEPT_IN_SOURCE_WORDS_CODE]
    assert _limitations(report) == key


def test_a_source_sentence_already_standing_with_other_spacing_is_printed_once() -> None:
    report = _report(limitations=f"{GATED} {UNEXAMINED}\n\n{DECODINGS.replace(' are ', '  are ')}")
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    found = _applied(report, row)
    assert [v.code for v in found] == [DROPPED_CODE]
    assert _limitations(report).count("were not reviewed") == 1


def test_a_quote_standing_in_a_passage_shown_as_a_source_only_is_not_called_unchecked() -> None:
    report = _report()
    passages = _with(report, "string_resolution", source_only=True)
    row = _keep(
        "limitations",
        UNEXAMINED,
        "string_resolution",
        "referenced by no code and were not reviewed",
    )
    (refused,) = [
        v.message
        for v in agreement_violations({"sentences": [row]}, passages)
        if v.code == KEEP_UNQUOTED_CODE
    ]
    assert "does not stand in a source it names" in refused
    assert "written without the code" not in refused


def test_a_quote_also_standing_in_another_named_passage_is_not_said_to_stand_only_there() -> None:
    report = _report()
    ta = report.technical_analysis
    assert ta is not None and ta.packing_obfuscation is not None
    ta.packing_obfuscation.body = f"{CLAIMED} {DECODINGS}"
    passages = _with(report, "string_resolution", source_only=True)
    row = {
        **_keep(
            "limitations",
            UNEXAMINED,
            "string_resolution",
            "referenced by no code and were not reviewed",
        ),
        "sources": ["packing_obfuscation", "string_resolution"],
    }
    (refused,) = [
        v.message
        for v in agreement_violations({"sentences": [row]}, passages)
        if v.code == KEEP_UNQUOTED_CODE
    ]
    assert (
        "but its quote stands in packing_obfuscation, a passage written without the code, "
        "which backs no keep of this sentence:"
    ) in refused
    assert "stands only in" not in refused
