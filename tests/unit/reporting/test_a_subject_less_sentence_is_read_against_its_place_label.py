"""A sentence with no subject of its own is read against its place's label, and only that.

A sentence whose only content words are what an absence denies, or words generic to the run
("Not established for this sample."), has no subject of its own: it is read against the
label of its place, and a place offering none keeps it on no quote. A record's own name is
part of its label only where no other record of its list shares it, so two channels of one
name differ by their index. A technique id names a place only as a whole id: a sub-technique
names no parent (T-613). Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from malspark.reporting.models import (
    C2Channel,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import Passage, _quote_problem, passages_of

_SOURCE = Passage(
    id="command_and_control",
    label="5",
    text=(
        "The key schedule is not shown. Beacon encryption is not established. "
        "Channel 2 encryption is not established. T1059.001 is not established. "
        "T1059 is not established."
    ),
    kind="section 5",
)
_GENERIC = frozenset({"sample", "analysed", "material"})
_CHANNEL_1 = (("encryption",), ("channel 1",))


def test_a_sentence_whose_only_content_words_are_generic_is_read_against_its_place() -> None:
    for sentence in (
        "Not established for this sample.",
        "Not established in the analysed material.",
    ):
        assert _quote_problem(
            sentence, "The key schedule is not shown", [_SOURCE], _GENERIC, place=_CHANNEL_1
        ).startswith("does not name the place the sentence stands in")
        assert (
            _quote_problem(
                sentence,
                "Channel 2 encryption is not established",
                [_SOURCE],
                _GENERIC,
                place=(("encryption",), ("channel 2",)),
            )
            == ""
        )


def test_a_place_offering_no_label_keeps_no_subject_less_sentence_on_a_quote() -> None:
    assert _quote_problem(
        "Not established.", "The key schedule is not shown", [_SOURCE], _GENERIC, place=()
    ) == ("backs no sentence with no subject of its own where its place names none")


def test_a_technique_id_names_a_place_only_as_a_whole_id() -> None:
    parent = (("T1059",),)

    assert _quote_problem(
        "Not established.", "T1059.001 is not established", [_SOURCE], _GENERIC, place=parent
    ).startswith("does not name the place")
    assert (
        _quote_problem(
            "Not established.", "T1059 is not established", [_SOURCE], _GENERIC, place=parent
        )
        == ""
    )


def _named(*names: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ef" * 32), file_name="sample.dll"),
        verdict="Malware",
        c2_channels=[C2Channel(name=name, encryption="Not established.") for name in names],
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(
                title="Command and control", body=_SOURCE.text, evidence_refs=["ev_0021"]
            )
        ),
    )


def test_a_name_two_records_share_is_no_part_of_their_labels() -> None:
    labels = {p.id: p.place_label for p in passages_of(_named("Beacon", "Beacon")) if p.place_label}

    assert labels["communications.1.encryption"] == (("encryption",), ("channel 1",))
    assert labels["communications.2.encryption"] == (("encryption",), ("channel 2",))


def test_a_name_no_other_record_shares_is_part_of_its_label() -> None:
    labels = {p.id: p.place_label for p in passages_of(_named("Beacon", "Relay")) if p.place_label}

    assert labels["communications.1.encryption"] == (("encryption",), ("Beacon", "channel 1"))
    assert labels["communications.2.encryption"] == (("encryption",), ("Relay", "channel 2"))
