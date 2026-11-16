"""A path or a registry key cut out of a longer token is recorded as a cut where it is cut.

The path pattern stops at the first character it does not take: it reads
``/cpu/classes/total`` in a language runtime's metric table
(``…allocs:bytes/cpu/classes/total:cpu-seconds…``) and ``/f /q C`` in
``del /f /q C:\\…``, neither of them a whole path. What ends a value is
the token it was cut from, the run's text between two whitespace characters:
a match that a word character continues on either side within its token is a
cut, and the run's record says so (``cut_from``, the token, of which no more
than the quoted form's eighty characters are kept). Marks around a value that
hold no word character (a quote, a bracket, a comma) do not make it a cut.

The cut lives in the record only: no tool answer carries it, so what a model
reads of the indicator tools is what it read before. The test is one pass over
the text that knows the token bounds, linear whatever the matches.
"""

from __future__ import annotations

import base64
import random
from pathlib import Path

from malspark.reporting.builder import MalwareReportBuilder
from malspark.schemas.evidence import LedgerEntry
from malspark.tools.ioc_spans import string_iocs_with_spans
from malspark.tools.strings import iocs_from_file, iocs_from_text, iter_string_iocs, token_cuts
from tests.linear_cost import assert_scales

# This run's examples: a runtime metric table and a deletion command.
METRICS = b"\x00/gc/heap/allocs:bytes/cpu/classes/total:cpu-seconds/gc/pauses:seconds\x00"
COMMAND = b"\x00del /f /q C:\\ProgramData\\Vendor\\Support\\*.*\x00"


def _rows(blob: bytes, kind: str) -> dict[str, dict[str, object]]:
    rows = iter_string_iocs(blob, cuts=True)
    return {str(row["value"]): row for row in rows if row["kind"] == kind}


def test_a_path_a_word_continues_is_recorded_as_cut_from_its_token() -> None:
    rows = _rows(METRICS, "path")

    assert rows["/cpu/classes/total"]["cut_from"] == (
        "/gc/heap/allocs:bytes/cpu/classes/total:cpu-seconds/gc/pauses:seconds"
    )


def test_a_command_s_switches_are_a_cut_of_the_command() -> None:
    rows = _rows(COMMAND, "path")

    assert rows["/f /q C"]["cut_from"] == "/f /q C:\\ProgramData\\Vendor\\Support\\*.*"


def test_a_path_standing_whole_beside_a_cut_one_is_no_cut() -> None:
    blob = b"\x00C:\\Users\\Public\\Libraries\\relay.dll\x00" + METRICS

    rows = _rows(blob, "path")
    assert "cut_from" not in rows["C:\\Users\\Public\\Libraries\\relay.dll"]
    assert rows["/cpu/classes/total"]["cut_from"]


def test_quotes_around_a_path_do_not_make_it_a_cut() -> None:
    blob = b'\x00start "C:\\Users\\Public\\relay.dll", -k "C:\\Users\\Public\\relay.dllx"\x00'

    rows = _rows(blob, "path")
    assert "cut_from" not in rows["C:\\Users\\Public\\relay.dll"]
    assert rows["C:\\Users\\Public\\relay.dllx"].get("cut_from") is None
    assert _rows(b"\x00(C:\\Temp\\drop\\x.exe)z\x00", "path")["C:\\Temp\\drop\\x.exe"]["cut_from"]


def test_any_whitespace_ends_a_token() -> None:
    text = "x=1\tC:\\Relay\\agent.exe\nnext"
    start = text.index("C:")

    assert token_cuts(text, [(start, start + len("C:\\Relay\\agent.exe"))]) == [""]
    assert token_cuts(text.replace("\t", ""), [(start - 1, start - 1 + 18)]) == [
        "x=1C:\\Relay\\agent.exe"
    ]


def test_each_of_two_tokens_in_one_run_is_answered_by_its_own_token() -> None:
    """A later match past the current token's end is read in the token it stands in."""
    text = "ab/cd:e fg/hi:j"

    assert token_cuts(text, [(2, 5), (10, 13)]) == ["ab/cd:e", "fg/hi:j"]
    blob = b"\x00/gc/heap/allocs:bytes/cpu/classes/total:cpu-seconds /sched/cpu/classes/user:s\x00"
    rows = _rows(blob, "path")
    assert rows["/cpu/classes/total"]["cut_from"] == (
        "/gc/heap/allocs:bytes/cpu/classes/total:cpu-seconds"
    )
    assert rows["/sched/cpu/classes/user"]["cut_from"] == "/sched/cpu/classes/user:s"


def test_a_registry_key_a_word_continues_is_a_cut_too() -> None:
    """A made-up key of another shape: the rule is the token's, not a kind's list."""
    blob = b"\x00HKCU\\Software\\Vendor\\Relay{0A1B2C3D}\x00"

    assert _rows(blob, "registry")["HKCU\\Software\\Vendor\\Relay"]["cut_from"] == (
        "HKCU\\Software\\Vendor\\Relay{0A1B2C3D}"
    )


def test_a_value_that_also_stands_whole_is_whole() -> None:
    blob = b"\x00/opt/relay/bin/agent:x\x00\x00\x00/opt/relay/bin/agent\x00"

    assert "cut_from" not in _rows(blob, "path")["/opt/relay/bin/agent"]


def test_a_path_glued_to_the_text_before_it_is_a_cut() -> None:
    """This run's glued value: ``C:\\Temp`` + ``is a directory`` + ``ComputerNameEx``."""
    blob = b"\x00SAPHostControlshare$=C:\\Tempis a directoryComputerNameEx\x00"

    assert _rows(blob, "path")["C:\\Tempis a directoryComputerNameEx"]["cut_from"] == (
        "SAPHostControlshare$=C:\\Tempis a directoryComputerNameEx"
    )


def test_a_digit_continues_a_value_too() -> None:
    blob = b"\x00/opt/relay/bin/agent:9000\x00"

    assert _rows(blob, "path")["/opt/relay/bin/agent"]["cut_from"] == "/opt/relay/bin/agent:9000"


def test_what_is_kept_of_a_long_token_is_bounded() -> None:
    token = "/opt/relay/bin/agent:" + "x" * 10_000
    blob = b"\x00" + token.encode() + b"\x00"

    kept = str(_rows(blob, "path")["/opt/relay/bin/agent"]["cut_from"])
    assert kept == token[:80] + "…"


class TestNoToolAnswerCarriesIt:
    def test_the_indicator_tools_answer_as_before(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.bin"
        sample.write_bytes(METRICS + COMMAND)

        for answer in (iocs_from_text((METRICS + COMMAND).decode()), iocs_from_file(str(sample))):
            assert answer["iocs"]
            assert all(set(row) == {"kind", "value", "notes", "source"} for row in answer["iocs"])

    def test_the_span_path_answers_as_the_scan_does(self) -> None:
        for blob in (METRICS, COMMAND):
            keys = ("kind", "value", "notes", "source")
            spans = [{k: r[k] for k in keys} for r in string_iocs_with_spans(blob)]
            assert spans == iter_string_iocs(blob)


class TestTheBuildRecordsTheCut:
    """The record reads the cut from the sample's own text, as the sweep cuts it."""

    def _built(self, sample: Path | None, value: str) -> object:
        entry = LedgerEntry(
            id="ev_0005",
            agent="pipeline",
            tool="iocs_from_file",
            structured={
                "iocs": [{"kind": "path", "value": value, "notes": None, "source": "strings"}],
                "kinds": ["path"],
            },
        )
        report = MalwareReportBuilder(
            file_hash="e" * 64,
            file_name="sample.bin",
            sample_path=str(sample) if sample else None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.8,
            evidence_ledger=[entry],
        ).build_deterministic()
        assert report.static is not None
        return {row.value: row.cut_from for row in report.static.interesting_strings}

    def test_a_switch_cut_from_a_command(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.bin"
        sample.write_bytes(COMMAND)

        assert self._built(sample, "/f /q C") == {
            "/f /q C": "/f /q C:\\ProgramData\\Vendor\\Support\\*.*"
        }

    def test_a_made_up_path_standing_whole(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x00C:\\Users\\Public\\relay.dll\x00")

        assert self._built(sample, "C:\\Users\\Public\\relay.dll") == {
            "C:\\Users\\Public\\relay.dll": None
        }

    def test_without_the_sample_nothing_is_marked(self) -> None:
        assert self._built(None, "/f /q C") == {"/f /q C": None}


def _scan_with_cuts(blob: bytes) -> object:
    return iter_string_iocs(blob, cuts=True)


class TestTheCutTestIsLinear:
    def test_many_cuts_in_one_long_token(self) -> None:
        assert_scales(lambda n: b"C:\\a\\b;" * n, 2_000, _scan_with_cuts)

    def test_a_long_run_of_encoded_text(self) -> None:
        def build(n: int) -> bytes:
            return base64.b64encode(random.Random(1).randbytes(n))

        assert_scales(build, 24_000, _scan_with_cuts)
