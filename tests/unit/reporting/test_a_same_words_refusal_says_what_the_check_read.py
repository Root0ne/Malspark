"""A refusal of a rewrite read as keeping its sentence says what the check read.

The agreement round reads a rewrite as keeping its sentence where each holds most of the
other's words, a bare number never counted (:func:`section_agreement.repeats_sentence`), and
then asks the keep's checks of it. Its refusal said the rewrite put the sentence "into the
same words" where a count, a negation or a qualifier had changed, called every name the row
gave a source, a name the round refuses as no source among them, and, where no source was
named, read "the best sentence of those sources no sentence of the sources it names states
it". Now the refusal says what the check read: the share of the sentence's own words the
rewrite repeats, and what is not counted; it names as sources only the facts, section 5
passages and debate rounds the round holds, and where the row names none, it says so in
whole words (T-895). Every sentence, name and id here is made up.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

import pytest

from malspark.reporting import section_agreement
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    KEEP_UNQUOTED_CODE,
    UNKNOWN_SOURCE_CODE,
    agreement_violations,
    passages_of,
    repeats_sentence,
)

DOCKS = "The courier opens three pipes to its relay host [ev_0061]."
NOWHERE = "parcel_marker"
# Each sentence, and a rewrite of it the round reads as keeping it.
SHAPES = {
    "a count changed": (
        "The courier opens two pipes to its relay host, and the parcel it fetches was not seen "
        "unpacking [ev_0061].",
        "The courier opens three pipes to its relay host, and the parcel it fetches was not "
        "seen unpacking [ev_0061].",
    ),
    "a negation added": (
        "The courier opens its relay pipe, and the parcel it fetches was not seen unpacking "
        "[ev_0061].",
        "The courier opens no relay pipe, and the parcel it fetches was not seen unpacking "
        "[ev_0061].",
    ),
    "a qualifier added": (
        "The parcel the courier fetches from its relay host was not seen unpacking [ev_0061].",
        "The parcel the courier fetches from its relay host was not seen fully unpacking "
        "[ev_0061].",
    ),
    "word for word": (
        "The parcel the courier fetches from its relay host was not seen unpacking [ev_0061].",
        "The parcel the courier fetches from its relay host was not seen unpacking [ev_0061].",
    ),
}
READ_AS_KEPT = (
    "repeating at least 80% of its words, at most 20% of the rewrite's words being new (words "
    "under three characters, stop words, entry ids and bare numbers not counted), which the "
    "round reads as keeping it"
)
# The ends the refusal offers, before the sources the platform found that speak of it.
ENDS = "rewrite it to what the sources state, or drop it."


def _refusals(sentence: str, rewrite: str, sources: list[str]) -> list[tuple[str, str]]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_type="PE32 executable"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(
                title="C2", body=DOCKS, evidence_refs=["ev_0061"]
            ),
            analyst_conclusion=TechnicalSubsection(title="Conclusion", body=sentence),
        ),
    )
    row = {
        "passage": "conclusion",
        "sentence": sentence,
        "decision": "rewrite",
        "sources": sources,
        "rewrite": rewrite,
        "reason": "",
        "quote": "",
    }
    found = agreement_violations({"sentences": [row]}, passages_of(report), ["ev_0061"])
    return [(v.code, v.message) for v in found]


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_refusal_says_the_share_of_words_it_read_and_names_only_held_sources(
    shape: str,
) -> None:
    sentence, rewrite = SHAPES[shape]
    assert repeats_sentence(sentence, rewrite)
    for sources in (["command_and_control"], ["command_and_control", NOWHERE]):
        found = _refusals(sentence, rewrite, sources)
        (kept,) = [message for code, message in found if code == KEEP_UNQUOTED_CODE]
        assert kept.startswith(
            f"row 1: conclusion rewrites {sentence!r} {READ_AS_KEPT}, on command_and_control, "
            "but the best sentence of those sources states no absence, while the sentence "
            f"states one: {ENDS}"
        )
        # A name the round does not hold is called no source in any line of the row: only the
        # refusal of that name names it.
        assert [code for code, message in found if NOWHERE in message] == (
            [UNKNOWN_SOURCE_CODE] if NOWHERE in sources else []
        )


@pytest.mark.parametrize("shape", list(SHAPES))
def test_a_row_naming_no_held_source_is_told_so_in_whole_words(shape: str) -> None:
    sentence, rewrite = SHAPES[shape]
    for sources in ([NOWHERE], [NOWHERE, "introduction"], []):
        (kept,) = [m for c, m in _refusals(sentence, rewrite, sources) if c == KEEP_UNQUOTED_CODE]
        assert kept.startswith(
            f"row 1: conclusion rewrites {sentence!r} {READ_AS_KEPT}, but it names none of the "
            f"facts, section 5 passages and debate rounds listed: {ENDS}"
        )


def test_no_refusal_says_a_rewrite_is_in_the_same_words() -> None:
    source = inspect.getsource(section_agreement)
    assert "into the same words" not in source
    assert "best sentence of those sources no sentence" not in source
