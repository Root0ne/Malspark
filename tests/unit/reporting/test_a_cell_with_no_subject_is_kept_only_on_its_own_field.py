"""A value cell's sentence with no subject of its own is kept only on a quote about its field.

A cell's sentence may say nothing of what it denies ("Not established.", "None."): the cell's
field is its subject. Read alone, any negated quote of the right length passed for it: a
channel's "Encryption: Not established." was kept on a sentence about the request path. Such
a sentence is read with the cell's own field label as its subject ("channel encryption"), so
a keep's quote holds two of the label's words; a cell sentence with a subject of its own is
read as before (T-613). Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.models import (
    C2Channel,
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

_CELL = "communications.1.encryption"
_NONE = "Not established."
_OWN = "No decryption shows that the key is applied to the channel's traffic [ev_0023]."
_PATH = "The request path beyond the base URL is not established from the analysed material"
_CHANNEL = "The channel encryption is not established from the analysed material"
_C2 = (
    f"Routine 0x5030 adds the form header and sends the body with HttpSendRequestA [ev_0021]. "
    f"{_PATH} [ev_0021]. {_CHANNEL} [ev_0023]."
)


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="cd" * 32), file_name="sample.dll"),
        verdict="Malware",
        c2_channels=[C2Channel(name="HTTP channel", encryption=f"{_NONE} {_OWN}")],
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(
                title="Command and control", body=_C2, evidence_refs=["ev_0021", "ev_0023"]
            )
        ),
    )


def _refusals(sentence: str, quote: str) -> list[Any]:
    row = {
        "passage": _CELL,
        "sentence": sentence,
        "decision": "keep",
        "sources": ["command_and_control"],
        "quote": quote,
    }
    found = agreement_violations({"sentences": [row]}, passages_of(_report()))
    return [v for v in found if v.path.startswith("sentences.")]


def test_the_cell_carries_its_field_label() -> None:
    cell = {p.id: p for p in passages_of(_report())}[_CELL]

    assert cell.field == "channel encryption"


def test_a_keep_on_a_negated_sentence_about_another_field_is_refused() -> None:
    found = _refusals(_NONE, _PATH)

    assert [v.code for v in found] == [KEEP_UNQUOTED_CODE]
    assert "shares too few of the words of the field the cell fills (channel encryption)" in (
        found[0].message
    )


def test_a_keep_on_a_sentence_about_the_field_passes() -> None:
    assert _refusals(_NONE, _CHANNEL) == []


def test_a_cell_sentence_with_a_subject_of_its_own_is_read_as_before() -> None:
    found = _refusals(_OWN, _PATH)

    assert [v.code for v in found] == [KEEP_UNQUOTED_CODE]
    assert "shares too few of the words the sentence denies something of" in found[0].message
