"""The console marks a value cell kept on its quote as the report does, from one fixture of cases.

A sentence the agreement round kept as written on its quote prints with the platform's mark
beside it, drawn from the round's own record when the report is rendered
(``section_agreement.KEPT_ON_ITS_QUOTE_MARK``), and a cell a record names that holds none of
its sentence prints nothing (a cell never prints the passage note). The console prints the value
cells (a channel's protocol, encryption and packet layout; the encryption scheme's cipher, mode,
library and IV), and reads the same records by the same rules in
``apps/web/src/lib/keptOnItsQuote.ts``: the record's label and sentence
(``kept_on_its_quote_named``), the label a value cell is shown under, whether a bounded label
names a passage's, and whether a printed cell holds a recorded sentence (``holds_kept``). The
fixture is written from the report's functions, and this test holds it to their output; the
console's test holds the console's functions to the same fixture, so the two cannot drift
(T-881). Every sentence, quote and id is made up. Regenerate it with ``python
tests/unit/reporting/test_the_console_marks_a_kept_cell_as_the_report_does.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malspark.pipeline.events import FINDING_VALUE_LIMIT
from malspark.reporting.models import (
    C2Channel,
    EncryptionScheme,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.section_agreement import (
    _LIMITATIONS_HELD_LABEL,
    CLAIM_LED,
    KEPT_ON_ITS_QUOTE_MARK,
    SECTION_5,
    AgreementRow,
    Passage,
    _closing_places,
    _kept_on_its_quote,
    _label_names,
    holds_kept,
    kept_on_its_quote_named,
)

FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "reporting" / "kept_on_its_quote_cases.json"
)

# A long sentence a record bounds, and one whose cut falls among characters outside the
# basic plane, which a code point counts once.
LONG = (
    "The rotating session key that the relay module derives from the host clock and the "
    "volume serial was not recovered from memory, and no decoded buffer in the ledger shows "
    "the expanded schedule that the stream routine consumes at start-up [ev_0041]."
)
WIDE = "Marker \U0001f9ed" * 30 + " was not decoded."


def _written(label: str, source: str, quote: str, sentence: str) -> dict[str, Any]:
    """One record as the round writes it, and what the inputs were."""
    passage = Passage(id="p", label=label, text=sentence, kind=CLAIM_LED)
    origin = Passage(id=source, label=source, text=quote, kind=SECTION_5)
    row = AgreementRow(
        passage="p", sentence=sentence, decision="keep", sources=[source], quote=quote
    )
    message = _kept_on_its_quote(passage, "sentences.0", sentence, row, origin).message
    named = kept_on_its_quote_named(message)
    return {"message": message, "named": list(named) if named else None}


def _messages() -> list[dict[str, Any]]:
    written = [
        _written(
            "7. Conclusion",
            "string_resolution",
            "no outbound socket was opened",
            "Network beaconing was not observed in the run [ev_0012].",
        ),
        _written(
            "5. Technical analysis, channel row 2, encryption",
            "command_and_control",
            "the relay key was never shown",
            "The value \"q\\w\" and the word 'it' were not decoded.",
        ),
        _written(
            "11. Limitations",
            "evasion_antiforensics",
            "x (agreement.keep_unquoted): 'y' was not traced",
            "Nothing (agreement.keep_unquoted): 'z' was traced at run time.",
        ),
        _written("11. Limitations", "payloads", "the bell was not rung", "Bell\x07 not read."),
        _written("1. Executive summary, capability bullet 3", "discovery", "never ran", LONG),
        _written("7. Conclusion", "discovery", "never ran", "The \U0001f9ed tag was not found."),
        _written(_LIMITATIONS_HELD_LABEL, "payloads", "no dropper was seen", "No drop seen."),
        _written("7. Conclusion", "discovery", "never ran", WIDE),
    ]
    head = "The agreement question keeps a sentence of 7. Conclusion as written on s, quoting 'q'"
    tail = ", which stands whole in one sentence there, though the keep was refused only on "
    forged = [
        "",
        head + " stands as written.",
        head + tail + "(agreement.keep_unquoted): 'open stands as written.",
        head + tail + "(agreement.keep_unquoted): 'a' 'b' stands as written.",
        head + tail + "(agreement.keep_unquoted): '\\x4' stands as written.",
        head + tail + "(agreement.keep_unquoted): '\\U00110000' stands as written.",
        head + tail + "(agreement.keep_unquoted): '\\q' stands as written.",
        "Another record: 'x' stands as written.",
    ]
    return written + [
        {"message": message, "named": list(n) if (n := kept_on_its_quote_named(message)) else None}
        for message in forged
    ]


def _cell_inputs() -> list[tuple[str, list[str]]]:
    cut = LONG[: FINDING_VALUE_LIMIT - 1] + "\u2026"
    return [
        ("AES in counter mode, keyed per host.", ["AES in counter mode, keyed per host."]),
        ("Plain. AES in counter mode was not seen. Done.", ["AES in counter mode was not seen."]),
        ("AES in\ncounter\xa0mode  was not seen.", ["AES in counter mode was not seen."]),
        ("AES in\ufeffcounter mode was not seen.", ["AES in counter mode was not seen."]),
        (f"Lead. {LONG} Tail.", [cut]),
        (LONG[:150], [cut]),
        ("RC4 was named.", ["AES in counter mode was not seen."]),
        ("RC4 was named.", []),
        ("Lead " + WIDE, [WIDE[: FINDING_VALUE_LIMIT - 1] + "\u2026"]),
        (WIDE[:200], [WIDE[:150] + "\u2026"]),
        ("A text with no words recorded.", [""]),
    ]


def _labels() -> list[dict[str, str]]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_type="PE32 executable"),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            encryption_scheme=EncryptionScheme(cipher="X1", mode="M1", library="L1", iv="I1")
        ),
        c2_channels=[
            C2Channel(name="one", protocol="P1", encryption="E1", packet_layout="F1"),
            C2Channel(name="two", protocol="P2", encryption="E2", packet_layout="F2"),
        ],
    )
    return [{"id": p.id, "label": p.label} for p in _closing_places(report)]


def _label_pairs() -> list[dict[str, Any]]:
    pairs = [
        ("7. Conclusion", "7. Conclusion"),
        ("7. Conclusion", "11. Limitations"),
        ("1. Executive summary, capability bullet 1", "1. Executive summary, capability bullet 10"),
        (_LIMITATIONS_HELD_LABEL[:199] + "\u2026", _LIMITATIONS_HELD_LABEL),
        (_LIMITATIONS_HELD_LABEL[:199] + "\u2026", "11. Limitations"),
        ("11. Limitations\u2026", "11. Limitations"),
    ]
    return [
        {"written": written, "label": label, "names": _label_names(written, label)}
        for written, label in pairs
    ]


def cases() -> dict[str, Any]:
    return {
        "about": (
            "A sentence the agreement round kept as written on its quote: the mark's words, the "
            "record's label and sentence, the label of each value cell, whether a bounded label "
            "names a passage's, "
            "and whether a printed cell holds a recorded sentence "
            "(reporting.section_agreement); written from those functions by "
            "tests/unit/reporting/test_the_console_marks_a_kept_cell_as_the_report_does.py and "
            "read by the console's test (apps/web)."
        ),
        "mark": KEPT_ON_ITS_QUOTE_MARK,
        "bound": FINDING_VALUE_LIMIT,
        "records": _messages(),
        "cells": [
            {"text": text, "said": said, "holds": holds_kept(text, said)}
            for text, said in _cell_inputs()
        ],
        "labels": _labels(),
        "label_pairs": _label_pairs(),
    }


def test_the_fixture_is_what_the_report_s_functions_give() -> None:
    assert json.loads(FIXTURE.read_text(encoding="utf-8")) == cases()


def test_the_fixture_holds_every_shape_the_rules_tell_apart() -> None:
    held = cases()
    named = [row["named"] for row in held["records"]]
    assert named[0] == ["7. Conclusion", "Network beaconing was not observed in the run [ev_0012]."]
    assert named[2] is not None and named[2][1].startswith("Nothing (agreement.keep_unquoted)")
    assert named[4] is not None and named[4][1].endswith("\u2026")
    assert named[6] is not None and named[6][0].endswith("\u2026")
    assert all(name is None for name in named[8:])
    holds = [row["holds"] for row in held["cells"]]
    assert holds == [True, True, True, False, True, False, False, False, True, False, False]
    assert {row["id"] for row in held["labels"]} == {
        "encryption_scheme.cipher",
        "encryption_scheme.mode",
        "encryption_scheme.library",
        "encryption_scheme.iv",
        *(f"communications.{n}.{f}" for n in (1, 2) for f in ("protocol", "encryption")),
        "communications.1.packet_layout",
        "communications.2.packet_layout",
    }
    assert [row["names"] for row in held["label_pairs"]] == [True, False, False, True, False, False]


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(cases(), indent=2) + "\n", encoding="utf-8")
