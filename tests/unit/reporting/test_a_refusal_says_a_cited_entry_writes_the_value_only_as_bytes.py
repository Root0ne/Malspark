"""A refused host value a cited entry writes only as bytes is refused with words saying so.

The export does not read bytes: a host value no cited entry's text holds whole
is not published, whatever the bytes the entries write. Where a cited entry's
bytes hold the value (the citation check's one byte reading, under the
platform's chance bound), the refusal says that the entry writes its whole value
only as bytes, which the export does not read as a host value, in place of
saying the value is in none of the entries the row cites. The decision is the
same; one more case of what a refusal says, in a fixed order, each sentence true
of one cited entry.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline.validation import EntryTexts, stated_value_violations
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers.stix_renderer import publishes
from malspark.reporting.stated_host_values import (
    AS_BYTES,
    NOT_IN_THE_CITED,
    UNHELD_WORDS,
    identifier_answers,
    scan_cited,
    with_held_in,
)
from malspark.schemas.evidence import LedgerEntry

MUTEX = "Global\\ExampleMutex"


def _read(entry_id: str, data: bytes) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        agent="static",
        server="static",
        tool="t",
        output=json.dumps({"address": "0x401000", "hex": data.hex()}),
        args={"address": "0x401000", "length": len(data)},
    )


def _row(*cited: str) -> HostIdentifier:
    return HostIdentifier(
        kind="mutex", value=MUTEX, use="creates/writes", evidence_refs=list(cited or ["ev_0001"])
    )


def _answer(entries: EntryTexts, row: HostIdentifier) -> str:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="ransomware",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in([row], entries)),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    ((_, said),) = identifier_answers(report)
    return said


class TestBytesAreSaidNotRead:
    def test_the_row_is_refused_with_the_bytes_named(self) -> None:
        entries = EntryTexts.from_ledger([_read("ev_0001", MUTEX.encode())])

        said = _answer(entries, _row())

        assert not publishes(said)
        assert said == f"no: {UNHELD_WORDS[AS_BYTES]}"
        assert NOT_IN_THE_CITED not in said

    def test_the_stated_value_check_does_not_ask_the_row(self) -> None:
        entries = EntryTexts.from_ledger([_read("ev_0001", MUTEX.encode())])
        payload = {"identifiers": [{"kind": "Mutex", "value": MUTEX, "evidence_refs": ["ev_0001"]}]}

        assert stated_value_violations(payload, entries) == []

    def test_the_words(self) -> None:
        assert UNHELD_WORDS[AS_BYTES] == (
            "a cited entry writes its whole value only as bytes, which the export does not read "
            "as a host value"
        )

    def test_bytes_that_do_not_hold_it_keep_the_earlier_words(self) -> None:
        entries = EntryTexts.from_ledger([_read("ev_0001", b"\x00\x11\x22\x33\x44\x55")])

        assert _answer(entries, _row()) == f"no: {NOT_IN_THE_CITED}"

    def test_an_entry_whose_text_holds_it_between_spaces_is_said_by_its_text(self) -> None:
        text = json.dumps({"note": f"opens {MUTEX} now", "hex": MUTEX.encode().hex()}).lower()
        scan = scan_cited(EntryTexts(texts={"ev_0001": text}), _row())

        assert scan.unheld_as != AS_BYTES

    def test_held_as_text_by_another_cited_entry_it_is_published(self) -> None:
        held: Any = LedgerEntry(
            id="ev_0002",
            agent="static",
            server="static",
            tool="t",
            output=json.dumps({"mutexes": [MUTEX]}),
        )
        entries = EntryTexts.from_ledger([_read("ev_0001", MUTEX.encode()), held])

        assert publishes(_answer(entries, _row("ev_0001", "ev_0002")))
