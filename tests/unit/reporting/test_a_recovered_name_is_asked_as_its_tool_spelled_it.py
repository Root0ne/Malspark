"""A recovered name its tool spelled in the shape of a code identifier is no hidden host.

An emulator's stack string ``time.Date(`` is a language runtime's identifier,
not the domain ``time.date``: a lower-case label followed by a member that
begins with a capital, as the recovering tool wrote it, reads as code.
Capitals as such say nothing — a host written ``Evil-C2.com`` or ``EVIL.COM``,
or a URL's host past its user part and its port, keeps its standing, and a
bracketed host is an address.

A value only a recovering tool read is held out when it is also a plain
string in the file. Where no strings entry listed every plain string, the
holdout reads the sample's text through the readers' boundary, bounded: a
file over the bound is not read, and the record says so.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.stix_renderer import (
    _spelled_as_code,
    _spelled_name,
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
        # The reason first, the clause the composer is quoted; the recovery after it.
        assert answer.split(";", 1)[0] == (
            "no: its tool spells it time.Date, which reads as code, not as a host"
        )

    def test_a_made_up_member_access_of_another_shape(self) -> None:
        report = _report([_floss("cfg.Online")])

        assert not publishes(_answer(report, "cfg.online"))

    def test_a_name_spelled_in_lower_case_stays_hidden_and_published(self) -> None:
        report = _report([_floss("time.Date(", HIDDEN)])

        assert publishes(_answer(report, HIDDEN))

    def test_a_url_s_host_is_asked_the_same(self) -> None:
        report = _report([_floss("https://cfg.Online:8443/gate")])

        answer = publish_answer(
            "url",
            "https://cfg.online:8443/gate",
            "strings",
            **emulation_kwargs(report, "url", "https://cfg.online:8443/gate"),
        )
        assert not publishes(answer), answer

    def test_a_host_written_with_capitals_keeps_its_standing(self) -> None:
        report = _report([_floss("https://Relay7.BadHost.top/gate")])

        answer = publish_answer(
            "url",
            "https://relay7.badhost.top/gate",
            "strings",
            **emulation_kwargs(report, "url", "https://relay7.badhost.top/gate"),
        )
        assert publishes(answer), answer


class TestOnlyAnIdentifierShapeIsCode:
    """A lower-case label followed by a member that begins with a capital; not capitals as such."""

    @pytest.mark.parametrize(
        ("kind", "written"),
        [
            ("domain", "Evil-C2.com"),
            ("domain", "EVIL.COM"),
            ("domain", "update.MicrosoftOnline-cdn.net"),
            ("domain", "xn--80ak6aa92e.com"),
            ("domain", "XN--80AK6AA92E.COM"),
            ("domain", "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444"),
            ("domain", "My-Host.example.org."),
            ("domain", "evil.com:443"),
            ("url", "http://Evil.com:8080/a/B?x=1"),
            ("url", "https://user@EVIL.com/x"),
            ("url", "HTTP://evil.com/A"),
            ("url", "http://evil.com:/x"),
            ("url", "http://[::1]:80/x"),
            ("url", "http://[2001:db8::7]/gate"),
            ("url", "http://10.0.0.1:8080/"),
            # A capitalised label a further label follows is a host's label.
            ("domain", "cdn.Microsoft.com"),
            ("domain", "login.Live.com"),
            ("url", "https://api.Telegram.org/bot/x"),
        ],
    )
    def test_a_host_keeps_its_standing(self, kind: str, written: str) -> None:
        assert not _spelled_as_code(_spelled_name(kind, written))

    @pytest.mark.parametrize(
        ("kind", "written"),
        [
            ("domain", "time.Date"),
            ("domain", "cfg.Online"),
            ("domain", "os.Getenv"),
            ("url", "http://cfg.Online:8080/gate"),
            ("url", "https://user@runtime.GOROOT/x"),
            # The shape of ``time.Date``: a name whose last label opens with a
            # capital reads as code, whatever its last label is.
            ("domain", "evil.Com"),
        ],
    )
    def test_an_identifier_reads_as_code(self, kind: str, written: str) -> None:
        assert _spelled_as_code(_spelled_name(kind, written))

    def test_a_bracketed_address_is_read_as_an_address(self) -> None:
        assert _spelled_name("url", "http://[2001:db8::7]:443/gate") == ""


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


class TestTheHoldoutReadsThroughTheReaders:
    """The holdout's read of the sample is a reading of the readers' boundary, bounded."""

    def test_it_is_a_reading_of_the_boundary(self) -> None:
        from malspark.tools.readers import READERS

        assert READERS["file_text"].stands_for == "strings"

    def test_a_file_over_the_bound_is_not_read_and_the_record_says_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.tools import strings

        monkeypatch.setattr(strings, "FILE_TEXT_MAX_BYTES", 64)
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x00" * 64 + b"call relay7.badhost.top now\x00")

        record = emulation_from_ledger(
            [_paged_strings("GetProcAddress"), _floss(HIDDEN)], sample=str(sample)
        )

        # The value keeps the standing it has without the read.
        assert HIDDEN in record.values
        assert "the sample's own text was not read" in record.partial
        assert "over the 64" in record.partial

    def test_what_the_reading_holds_is_bounded_by_the_file(self, tmp_path: Path) -> None:
        from malspark.tools.strings import file_text_reading
        from tests.linear_cost import peak_bytes

        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"GetProcAddress\x00relay7.badhost.top\x00" * 120_000)
        size = sample.stat().st_size

        held = peak_bytes(lambda: file_text_reading(str(sample), [HIDDEN, "other.example"]))
        assert held < 4 * size, (held, size)
