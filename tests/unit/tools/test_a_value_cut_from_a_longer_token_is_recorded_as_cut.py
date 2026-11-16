"""A path or a registry key cut out of a longer token is recorded as a cut where it is cut.

The path pattern stops at the first character it does not take, so it lifted
``/cpu/classes/total`` out of a language runtime's metric table
(``…allocs:bytes/cpu/classes/total:cpu-seconds…``) and ``/f /q C`` out of
``del /f /q C:\\…``, and each row read as a whole path. What ends a value is
the token it was cut from, the run's text between two whitespace characters:
a match that a word character continues on either side within its token is a
cut, and its row says so (``cut_from``, the token). Marks around a value that
hold no word character (a quote, a bracket, a comma) do not make it a cut.
"""

from __future__ import annotations

from malspark.tools.ioc_spans import string_iocs_with_spans
from malspark.tools.strings import iter_string_iocs

# This run's examples: a runtime metric table and a deletion command.
METRICS = b"\x00/gc/heap/allocs:bytes/cpu/classes/total:cpu-seconds/gc/pauses:seconds\x00"
COMMAND = b"\x00del /f /q C:\\ProgramData\\Vendor\\Support\\*.*\x00"


def _rows(blob: bytes, kind: str) -> dict[str, dict[str, object]]:
    return {str(row["value"]): row for row in iter_string_iocs(blob) if row["kind"] == kind}


def test_a_path_a_word_continues_is_recorded_as_cut_from_its_token() -> None:
    rows = _rows(METRICS, "path")

    assert rows["/cpu/classes/total"]["cut_from"] == (
        "/gc/heap/allocs:bytes/cpu/classes/total:cpu-seconds/gc/pauses:seconds"
    )


def test_a_command_s_switches_are_a_cut_of_the_command() -> None:
    rows = _rows(COMMAND, "path")

    assert rows["/f /q C"]["cut_from"] == "/f /q C:\\ProgramData\\Vendor\\Support\\*.*"


def test_a_path_standing_whole_is_no_cut() -> None:
    blob = b"\x00C:\\Users\\Public\\Libraries\\relay.dll\x00"

    assert "cut_from" not in _rows(blob, "path")["C:\\Users\\Public\\Libraries\\relay.dll"]


def test_quotes_around_a_path_do_not_make_it_a_cut() -> None:
    blob = b'\x00start "C:\\Users\\Public\\relay.dll", -k\x00'

    assert "cut_from" not in _rows(blob, "path")["C:\\Users\\Public\\relay.dll"]


def test_a_registry_key_a_word_continues_is_a_cut_too() -> None:
    """A made-up key of another shape: the rule is the token's, not a kind's list."""
    blob = b"\x00HKCU\\Software\\Vendor\\Relay{0A1B2C3D}\x00"

    assert _rows(blob, "registry")["HKCU\\Software\\Vendor\\Relay"]["cut_from"] == (
        "HKCU\\Software\\Vendor\\Relay{0A1B2C3D}"
    )


def test_a_value_that_also_stands_whole_is_whole() -> None:
    blob = b"\x00/opt/relay/bin/agent:x\x00\x00\x00/opt/relay/bin/agent\x00"

    assert "cut_from" not in _rows(blob, "path")["/opt/relay/bin/agent"]


def test_the_span_path_records_the_same_cuts() -> None:
    for blob in (METRICS, COMMAND):
        spans = string_iocs_with_spans(blob)
        keys = ("kind", "value", "notes", "source", "cut_from")
        assert [{k: r[k] for k in keys if k in r} for r in spans] == iter_string_iocs(blob)
