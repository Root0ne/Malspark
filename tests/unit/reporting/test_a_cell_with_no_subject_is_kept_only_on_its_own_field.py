"""A sentence with no subject of its own is kept only on a quote naming the place it stands in.

A cell's sentence may say nothing of what it denies ("Not established.", "None."): its place
is its subject. Read alone, any negated quote of the right length would pass for it. Such a
sentence is read against the label of its place: for a value cell, the field's own name, every
word of which the quote holds, and what names its record (the record's name or its index in
its list, so two channels differ; what the record is, for a record of its own); for a text
printed in its writer's own words, the technique it stands under or the judge's field it is.
A place offering no label keeps no such sentence on a quote. A sentence with a subject of its
own is read by its own words (T-613). Every address, entry and name here is a neutral
synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.models import (
    C2Channel,
    EncryptionScheme,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    KEEP_UNQUOTED_CODE,
    agreement_violations,
    passages_of,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

_CELL = "communications.1.encryption"
_NONE = "Not established."
_OWN = "No decryption shows that the key is applied to the channel's traffic [ev_0023]."
_PATH = "The request path beyond the base URL is not established from the analysed material"
_FIRST = "The encryption of the HTTP channel is not established from the analysed material"
_SECOND = "The encryption of the DNS channel is not established from the analysed material"
_SCHEME = "The encryption scheme of the second stage is not established from the code read"
_LIBRARY = "The encryption scheme names no library the cipher routine is loaded from"
_C2 = (
    f"Routine 0x5030 adds the form header and sends the body with HttpSendRequestA [ev_0021]. "
    f"{_PATH} [ev_0021]. {_FIRST} [ev_0023]. {_SECOND} [ev_0023]. {_SCHEME} [ev_0023]. "
    f"{_LIBRARY} [ev_0023]."
)


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="cd" * 32), file_name="sample.dll"),
        verdict="Malware",
        c2_channels=[
            C2Channel(name="HTTP channel", encryption=f"{_NONE} {_OWN}"),
            C2Channel(name="DNS channel", encryption=_NONE),
        ],
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(
                title="Command and control", body=_C2, evidence_refs=["ev_0021", "ev_0023"]
            ),
            encryption_scheme=EncryptionScheme(cipher="RC4", library="None."),
        ),
    )


def _refusals(passage: str, sentence: str, quote: str, report: Any = None) -> list[Any]:
    report = report if report is not None else _report()
    source = "command_and_control" if report.c2_channels else "string_resolution"
    row = {
        "passage": passage,
        "sentence": sentence,
        "decision": "keep",
        "sources": [source],
        "quote": quote,
    }
    found = agreement_violations({"sentences": [row]}, passages_of(report))
    return [v for v in found if v.path.startswith("sentences.")]


def test_each_cell_carries_the_label_of_its_place() -> None:
    cells = {p.id: p.place_label for p in passages_of(_report()) if p.place_label is not None}

    assert cells[_CELL] == (("encryption",), ("HTTP channel", "channel 1"))
    assert cells["communications.2.encryption"] == (("encryption",), ("DNS channel", "channel 2"))
    assert cells["encryption_scheme.library"] == (("library",), ("encryption scheme",))


def test_a_keep_on_a_negated_sentence_about_another_field_is_refused() -> None:
    found = _refusals(_CELL, _NONE, _PATH)

    assert [v.code for v in found] == [KEEP_UNQUOTED_CODE]
    assert "its quote does not name the place the sentence stands in (encryption; " in (
        found[0].message
    )


def test_a_keep_on_a_sentence_about_its_own_field_and_record_passes() -> None:
    assert _refusals(_CELL, _NONE, _FIRST) == []
    assert _refusals("communications.2.encryption", _NONE, _SECOND) == []


def test_a_quote_about_another_channel_of_the_same_field_is_refused() -> None:
    found = _refusals("communications.2.encryption", _NONE, _FIRST)

    assert [v.code for v in found] == [KEEP_UNQUOTED_CODE]
    assert "(encryption; DNS channel or channel 2)" in found[0].message


def test_the_record_s_words_alone_back_no_field_of_it() -> None:
    # "encryption scheme" names the record, not its library.
    found = _refusals("encryption_scheme.library", "None.", _SCHEME)

    assert [v.code for v in found] == [KEEP_UNQUOTED_CODE]
    assert "(library; encryption scheme)" in found[0].message
    assert _refusals("encryption_scheme.library", "None.", _LIBRARY) == []


def test_a_cell_sentence_with_a_subject_of_its_own_is_read_by_its_own_words() -> None:
    found = _refusals(_CELL, _OWN, _PATH)

    assert [v.code for v in found] == [KEEP_UNQUOTED_CODE]
    assert "shares too few of the words the sentence denies something of" in found[0].message


def _verbatim_none() -> MalwareReport:
    """The report, its claim sentence for T1622 one saying nothing of what it denies."""
    report = report_of()
    for cell in report.capability_matrix:
        if cell.technique_id == "T1622":
            cell.evidence = ["Not established [ev_0103]."]
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    ta.string_resolution.body += (
        " The process list routine is not established from the code read [ev_0103]."
        " The debugger evasion of routine 0x5b20 is not established past its flag read [ev_0103]."
    )
    return report


def test_a_verbatim_sentence_with_no_subject_is_kept_only_on_a_quote_naming_its_place() -> None:
    report = _verbatim_none()
    label = {p.id: p.place_label for p in passages_of(report) if p.verbatim}

    assert label["attack_claim.T1622"] == (("T1622", "Debugger Evasion"),)
    assert label["judge.business_impact"] == (("business impact",),)
    found = _refusals(
        "attack_claim.T1622",
        "Not established.",
        "The process list routine is not established from the code read",
        report,
    )
    assert [v.code for v in found] == [KEEP_UNQUOTED_CODE]
    assert "(T1622 or Debugger Evasion)" in found[0].message
    assert (
        _refusals(
            "attack_claim.T1622",
            "Not established.",
            "The debugger evasion of routine 0x5b20 is not established past its flag read",
            report,
        )
        == []
    )
