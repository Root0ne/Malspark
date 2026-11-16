"""A recovered name is asked the capitalisation question in its tool's own spelling.

An emulator's stack string ``time.Date(`` — a language runtime's identifier —
was read as the domain ``time.date`` (``.date`` is a top-level domain) and
published as a value the sample hid. The string sweep's e-mail path already
asks whether a name reads as a host in the bytes: an identifier capitalises
what it reaches into, and a host name never does. A recovered name is asked
the same question of the spelling its recovering tool wrote.

And a value only a recovering tool read is held out when it is also a plain
string in the file. Where no strings entry listed every plain string, that
holdout read a partial record and kept the value; it reads the sample's own
bytes instead, when the build has them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.stix_renderer import (
    emulation_from_ledger,
    emulation_kwargs,
    publish_answer,
    publishes,
)
from malspark.schemas.evidence import LedgerEntry

HIDDEN = "relay7.badhost.top"


def _floss(*strings: str) -> LedgerEntry:
    rows = [{"kind": "stack", "string": text, "encoding": "ASCII"} for text in strings]
    return LedgerEntry(
        id="ev_0019",
        agent="pipeline",
        tool="floss",
        structured={"total": len(rows), "strings": rows, "truncated": False},
    )


def _paged_strings(*texts: str) -> LedgerEntry:
    """A strings listing that holds a page only: the plain-string record is partial."""
    rows = [{"enc": "ascii", "text": text, "offset": 16 * i} for i, text in enumerate(texts)]
    return LedgerEntry(
        id="ev_0005",
        agent="pipeline",
        tool="strings",
        structured={"total": 14384, "strings": rows, "truncated": True},
    )


def _report(ledger: list[LedgerEntry], **record: Any) -> MalwareReport:
    return MalwareReport(
        verdict="Malware",
        overall_confidence=0.8,
        identity=SampleIdentity(hashes=FileHashes(sha256="f" * 64)),
        emulated_strings=emulation_from_ledger(ledger, **record),
        executive_summary="",
    )


def _answer(report: MalwareReport, value: str) -> str:
    return publish_answer("domain", value, "strings", **emulation_kwargs(report, "domain", value))


class TestTheSpellingIsAsked:
    def test_a_runtime_identifier_is_no_hidden_host(self) -> None:
        report = _report([_floss("time.Date(", HIDDEN)])

        answer = _answer(report, "time.date")
        assert not publishes(answer), answer
        assert "time.Date" in answer

    def test_a_made_up_member_access_of_another_shape(self) -> None:
        report = _report([_floss("cfg.Online")])

        assert not publishes(_answer(report, "cfg.online"))

    def test_a_name_spelled_in_lower_case_stays_hidden_and_published(self) -> None:
        report = _report([_floss("time.Date(", HIDDEN)])

        assert publishes(_answer(report, HIDDEN))

    def test_a_url_s_host_is_asked_the_same(self) -> None:
        report = _report([_floss("https://Cfg.Online/gate")])

        answer = publish_answer(
            "url",
            "https://cfg.online/gate",
            "strings",
            **emulation_kwargs(report, "url", "https://cfg.online/gate"),
        )
        assert not publishes(answer), answer


class TestThePlainHoldoutReadsTheFile:
    def test_a_value_the_file_holds_as_plain_text_is_held_out(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"MZ\x00\x00" + b"\x00" * 64 + b"call relay7.badhost.top now\x00" * 1)
        ledger = [_paged_strings("GetProcAddress"), _floss(HIDDEN)]

        record = emulation_from_ledger(ledger, sample=str(sample))

        assert HIDDEN not in record.values
        assert HIDDEN in record.plain
        assert not publishes(_answer(_report(ledger, sample=str(sample)), HIDDEN))

    def test_a_value_the_file_hides_stays_and_the_record_is_whole(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"MZ\x00\x00" + bytes(range(256)) * 4)
        ledger = [_paged_strings("GetProcAddress"), _floss(HIDDEN)]

        record = emulation_from_ledger(ledger, sample=str(sample))

        assert HIDDEN in record.values
        # The holdout read every plain string of the file.
        assert "plain string" not in record.partial

    def test_without_the_sample_the_partial_record_is_said(self) -> None:
        record = emulation_from_ledger([_paged_strings("GetProcAddress"), _floss(HIDDEN)])

        assert HIDDEN in record.values
        assert "plain string" in record.partial
