"""An entry holding a value only in the echo of its own call holds nothing on the publish route.

A tool's answer may repeat the call it answers (a search's pattern, a lookup's
path). The publish route's one scan of a row's cited entries
(``stated_host_values.scan_cited``) finds a value whole in a text; an entry
whose text holds it whole only where the answer repeats an argument of its own
call — whole on its text written again with nothing taken out, whole nowhere
once the echo is out — is no holder: not for the decision, not in the published
reason, not in the row's evidence ids. The one exception: where the entry's
echo-free text holds a spelling of the value at a place no letter, digit or
``_`` of the run around it touches, read decoded, the entry holds it as the
scan found. An entry nothing echoes never changes.

A row no cited entry holds whole is refused with what the scan found: an entry
holding it whole only in its call's echo says so, and where its echo-free text
holds the value's text only inside a longer run, that too. The cases of what a
refusal says still partition every row no cited entry holds, in a fixed order,
each true of one cited entry.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.builder import build_consolidated_iocs, full_ioc_list
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers.stix_renderer import publishes
from malspark.reporting.stated_host_values import (
    INSIDE_A_LONGER_RUN,
    NOWHERE,
    ONLY_IN_ITS_CALL,
    ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE,
    UNHELD_WORDS,
    identifier_answers,
    scan_cited,
    stated_reason,
    with_held_in,
)
from malspark.schemas.evidence import LedgerEntry

NAME = "tasks.cfg"
PATH = "C:\\Users\\Public\\tasks.cfg"
MUTEX = "Global\\ExampleMutex"
KEY = "HKCU\\Software\\Example\\Run1"


def _entry(entry_id: str, answer: Any, args: dict[str, Any] | None) -> LedgerEntry:
    output = answer if isinstance(answer, str) else json.dumps(answer)
    return LedgerEntry(
        id=entry_id, agent="static", server="static", tool="t", output=output, args=args or {}
    )


def _texts(*entries: tuple[str, Any, dict[str, Any] | None]) -> EntryTexts:
    return EntryTexts.from_ledger([_entry(*entry) for entry in entries])


def _row(kind: str, value: str, *cited: str) -> HostIdentifier:
    return HostIdentifier(
        kind=kind, value=value, use="creates/writes", evidence_refs=list(cited or ["ev_0001"])
    )


def _report(row: HostIdentifier, entries: EntryTexts) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="ransomware",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in([row], entries)),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _answer(kind: str, value: str, answer: Any, args: dict[str, Any] | None) -> str:
    report = _report(_row(kind, value), _texts(("ev_0001", answer, args)))
    ((_, said),) = identifier_answers(report)
    return said


# An answer that holds the value whole only in its echo of the call's argument.
ECHO_ONLY = [
    # A search with no row.
    ("file name", NAME, {"pattern": NAME, "matches": []}, {"pattern": NAME}),
    ("file path", PATH, {"pattern": PATH, "matches": [], "total": 0}, {"pattern": PATH}),
    ("mutex", MUTEX, {"pattern": MUTEX, "matches": []}, {"pattern": MUTEX}),
    # An existence lookup answering false, and answering true: by shape the same.
    ("file path", PATH, {"path": PATH, "exists": False}, {"path": PATH}),
    ("file path", PATH, {"path": PATH, "exists": True}, {"path": PATH}),
    # A registry query that did not find the key, and one listing the key's values.
    ("registry key", KEY, {"key": KEY, "found": False}, {"key": KEY}),
    (
        "registry key",
        KEY,
        {"key": KEY, "values": [{"name": "sync", "data": "c:\\data\\sync7.exe"}]},
        {"key": KEY},
    ),
    # Rows that write the path in another spelling than the value's.
    (
        "file path",
        "C:\\Temp\\a7.exe",
        {"pattern": "C:\\Temp\\a7.exe", "matches": [{"text": "C:/Temp/a7.exe"}]},
        {"pattern": "C:\\Temp\\a7.exe"},
    ),
]

# An answer that holds the value whole only in its echo, and elsewhere only inside a run.
ECHO_THEN_INSIDE = [
    # The rows hold it only inside a longer run.
    (
        "file name",
        NAME,
        {"pattern": NAME, "matches": [{"text": f"x{NAME}"}]},
        {"pattern": NAME},
    ),
    # A single result repeating the pattern with an offset, and a context holding a run.
    (
        "file name",
        NAME,
        {"pattern": NAME, "result": {"pattern": NAME, "offset": 4096}, "ctx": f"a{NAME}"},
        {"pattern": NAME},
    ),
    # A nested argument object echoed.
    (
        "file name",
        NAME,
        {"opts": {"pattern": NAME}, "matches": [{"text": f"a{NAME}"}]},
        {"opts": {"pattern": NAME}},
    ),
    # A path's last component echoed.
    (
        "file name",
        NAME,
        {"file": NAME, "imports": [f"a{NAME}"]},
        {"file": f"C:\\T\\{NAME}"},
    ),
]

# An answer that holds the value outside its echo: held as the scan reads it.
HELD = [
    # A row holding it whole.
    ("file name", NAME, {"pattern": NAME, "matches": [{"text": NAME}]}, {"pattern": NAME}),
    # A row holding it whole beside one holding it inside a run.
    (
        "file name",
        NAME,
        {"pattern": NAME, "matches": [{"text": f"xx{NAME}"}, {"text": NAME}]},
        {"pattern": NAME},
    ),
    # A row equal to the argument: a list item is a row of the answer.
    ("file name", NAME, {"pattern": NAME, "strings": [NAME]}, {"pattern": NAME}),
    # A row bounded by a NUL: no letter or digit of the decoded run touches it.
    (
        "file name",
        NAME,
        {"pattern": NAME, "matches": [{"text": f"\u0000{NAME}"}]},
        {"pattern": NAME},
    ),
    # A one-character and a two-character argument beside a row holding the value.
    ("file name", NAME, {"pattern": "e", "matches": [{"text": NAME}]}, {"pattern": "e"}),
    ("file name", NAME, {"sep": "\\\\", "matches": [{"text": NAME}]}, {"sep": "\\\\"}),
    # An echo the reading does not tell apart stays as it was: a list argument
    # echoed as a list, an echo inside a list item, plain text.
    (
        "file name",
        NAME,
        {"patterns": [NAME, "x"], "matches": [{"text": f"a{NAME}"}]},
        {"patterns": [NAME, "x"]},
    ),
    ("file name", NAME, {"rows": [{"pattern": NAME}]}, {"pattern": NAME}),
    ("mutex", MUTEX, f"Searching for '{MUTEX}'...\nNo matches found.", {"pattern": MUTEX}),
]


class TestAnEchoAloneIsNoHolder:
    @pytest.mark.parametrize(("kind", "value", "answer", "args"), ECHO_ONLY)
    def test_the_row_is_refused_and_says_where_the_entry_holds_it(
        self, kind: str, value: str, answer: Any, args: dict[str, Any]
    ) -> None:
        assert _answer(kind, value, answer, args) == f"no: {UNHELD_WORDS[ONLY_IN_ITS_CALL]}"

    @pytest.mark.parametrize(("kind", "value", "answer", "args"), ECHO_THEN_INSIDE)
    def test_an_echo_beside_a_run_says_both(
        self, kind: str, value: str, answer: Any, args: dict[str, Any]
    ) -> None:
        said = _answer(kind, value, answer, args)

        assert said == f"no: {UNHELD_WORDS[ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE]}"

    @pytest.mark.parametrize(("kind", "value", "answer", "args"), HELD)
    def test_a_holding_outside_the_echo_stands(
        self, kind: str, value: str, answer: Any, args: dict[str, Any]
    ) -> None:
        said = _answer(kind, value, answer, args)

        assert publishes(said), said

    def test_an_entry_nothing_echoes_is_read_as_before(self) -> None:
        entries = EntryTexts(texts={"ev_0001": json.dumps({"pattern": NAME}).lower()})

        assert scan_cited(entries, _row("file name", NAME)).held == ("ev_0001",)


class TestTheEchoLeavesEveryPublishedSurface:
    def _report(self) -> MalwareReport:
        entries = _texts(
            ("ev_0001", {"pattern": NAME, "matches": [{"text": f"x{NAME}"}]}, {"pattern": NAME}),
            ("ev_0002", {"strings": [NAME]}, {"path": "s.bin"}),
        )
        return _report(_row("file name", NAME, "ev_0002", "ev_0001"), entries)

    def test_the_reason_and_the_evidence_name_only_the_true_holder(self) -> None:
        report = self._report()

        ((stated, said),) = identifier_answers(report)
        assert stated.held_in == ("ev_0002",)
        assert publishes(said)
        assert stated_reason(stated).endswith("found whole in ev_0002")
        (listed,) = [row for row in full_ioc_list(report) if row.value == NAME]
        assert "ev_0001" not in (listed.evidence_ids or [])

    def test_a_refused_row_offers_no_echo_as_its_evidence(self) -> None:
        entries = _texts(("ev_0001", {"pattern": NAME, "matches": []}, {"pattern": NAME}))
        report = _report(_row("file name", NAME), entries)

        (row,) = report.technical_analysis.host_identifiers  # type: ignore[union-attr]
        assert row.held_in == []
        assert row.unheld_as == ONLY_IN_ITS_CALL


class TestTheRefusalsStillPartitionEveryUnheldRow:
    def test_the_words(self) -> None:
        assert UNHELD_WORDS[ONLY_IN_ITS_CALL] == (
            "a cited entry holds it whole only where its answer repeats what its call asked for"
        )
        assert UNHELD_WORDS[ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE] == (
            "a cited entry holds it whole only where its answer repeats what its call asked "
            "for; elsewhere only inside a longer run of text"
        )

    def test_an_echo_is_said_before_another_entry_s_run(self) -> None:
        entries = _texts(
            ("ev_0001", {"pattern": NAME, "matches": []}, {"pattern": NAME}),
            ("ev_0002", {"strings": [f"pool{NAME}pool"]}, {"path": "s.bin"}),
        )

        scan = scan_cited(entries, _row("file name", NAME, "ev_0002", "ev_0001"))
        assert scan.held == ()
        assert scan.unheld_as == ONLY_IN_ITS_CALL

    def test_a_run_without_an_echo_keeps_its_words(self) -> None:
        entries = _texts(("ev_0002", {"strings": [f"pool{NAME}pool"]}, {"path": "s.bin"}))

        scan = scan_cited(entries, _row("file name", NAME, "ev_0002"))
        assert scan.unheld_as == INSIDE_A_LONGER_RUN

    def test_no_text_anywhere_keeps_its_words(self) -> None:
        entries = _texts(("ev_0002", {"strings": ["other"]}, {"path": "s.bin"}))

        assert scan_cited(entries, _row("file name", NAME, "ev_0002")).unheld_as == NOWHERE
