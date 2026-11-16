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
    KEEP_UNQUOTED_CODE,
    KEPT_IN_SOURCE_WORDS_CODE,
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
