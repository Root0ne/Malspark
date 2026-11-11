"""A string read from a stored run is shown on a terminal, never obeyed by it.

A stored run's tool names, recorded reasons and names come from the run, so a
control sequence in one could rewrite what the operator reads. The replay's
terminal output shows every unprintable character as a visible escape and
leaves printable text as it was; the ``--json`` record keeps the raw text.
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import limitation_inventory
from scripts.replay.output import render_diff, render_record, terminal_safe

from malspark.reporting.limitation_inventory import build_inventory
from malspark.reporting.models import InventoryTool
from malspark.schemas.evidence import LedgerEntry
from tests.unit.reporting.test_the_limitations_inventory_is_written_by_code import (
    _DECOMPILE,
    _ledger,
    _report,
)

ESCAPE = "\x1b[31mred\x1b[0m"
OSC = "\x1b]0;owned\x07"


def _unprintable(text: str) -> list[str]:
    return [c for c in text if unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"} and c != "\n"]


@pytest.mark.parametrize(
    "text",
    ["", "plain text 123 []{}", "naïve café – İstanbul ğüşıöç", "日本語 Привет"],
)
def test_printable_text_comes_through_unchanged(text: str) -> None:
    assert terminal_safe(text, encoding="utf-8") == text


def test_an_escape_sequence_is_shown_as_visible_escapes() -> None:
    assert terminal_safe(ESCAPE) == "\\x1b[31mred\\x1b[0m"


def test_an_osc_sequence_is_shown_as_visible_escapes() -> None:
    shown = terminal_safe(f"a{OSC}b")
    assert shown == "a\\x1b]0;owned\\x07b"
    assert not _unprintable(shown)


def test_a_carriage_return_and_a_backspace_are_shown_as_visible_escapes() -> None:
    assert terminal_safe("safe\rfake") == "safe\\x0dfake"
    assert terminal_safe("ab\x08\x08xy") == "ab\\x08\\x08xy"
    assert terminal_safe("del\x7fx\x9bx") == "del\\x7fx\\x9bx"


def test_a_bidirectional_override_and_a_zero_width_mark_are_shown_as_visible_escapes() -> None:
    assert terminal_safe("exe‮txt.​") == "exe\\u202etxt.\\u200b"
    assert terminal_safe("a b c") == "a\\u2028b\\u2029c"


def test_a_newline_in_a_value_is_shown_as_one_visible_escape() -> None:
    assert terminal_safe("one\ntwo") == "one\\ntwo"


def test_no_caller_can_keep_a_newline_of_a_value() -> None:
    with pytest.raises(TypeError):
        terminal_safe("one\ntwo", keep_newlines=True)  # type: ignore[call-arg]


def test_a_long_run_of_unprintable_characters_is_read_in_linear_time() -> None:
    assert terminal_safe("\x1b" * 200_000).count("\\x1b") == 200_000


def _hostile_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = _ledger() + [
        LedgerEntry(
            id="ev_0007",
            tool=f"lift{OSC}_routine",
            args={"address": "0x1"},
            ok=False,
            error="gone\rfake",
            facts=_DECOMPILE,
            agent="reader",
        )
    ]
    report = _report(ledger, build=False)
    report.limitation_inventory = build_inventory(report, ledger)
    report.limitation_inventory.not_offered.append(
        InventoryTool(tool=f"evil{ESCAPE}", reason="x‮y\x08z")
    )
    monkeypatch.setattr(
        limitation_inventory, "stored_inventory", lambda _run: (report, report.limitation_inventory)
    )


def test_the_inventory_script_prints_no_raw_control_character_and_json_keeps_the_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _hostile_inventory(monkeypatch)
    out_json = tmp_path / "out.json"
    run = tmp_path / f"run{ESCAPE}"
    assert limitation_inventory.main([str(run), "--json", str(out_json)]) == 0
    printed = capsys.readouterr().out
    assert not _unprintable(printed)
    assert "\\x1b]0;owned\\x07" in printed and "\\x1b[31m" in printed
    assert "\\u202e" in printed and "\\x08" in printed
    kept: list[dict[str, Any]] = json.loads(out_json.read_text(encoding="utf-8"))
    assert kept[0]["run"] == f"run{ESCAPE}"
    assert any(OSC in t for t in kept[0]["printed"] + kept[0]["not_printed"])
    assert any(ESCAPE in t for t in kept[0]["not_printed"] + kept[0]["printed"])


def _windows_text_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make a file opened without an explicit encoding use cp1252, as on Windows."""
    real = Path.write_text

    def write_text(self: Path, data: str, encoding: str | None = None, **kw: Any) -> int:
        return real(self, data, encoding=encoding or "cp1252", **kw)

    monkeypatch.setattr(Path, "write_text", write_text)


def test_the_json_and_golden_files_are_written_as_utf_8_where_the_default_is_a_code_page(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _hostile_inventory(monkeypatch)
    _windows_text_encoding(monkeypatch)
    out_json, golden = tmp_path / "out.json", tmp_path / "golden"
    args = [str(tmp_path / "run"), "--json", str(out_json), "--golden", str(golden)]
    assert limitation_inventory.main(args) == 0
    capsys.readouterr()
    kept = json.loads(out_json.read_text(encoding="utf-8"))
    assert any("\u202e" in t for t in kept[0]["not_printed"] + kept[0]["printed"])
    assert "\u202e" in (golden / "run.json").read_text(encoding="utf-8")


def test_a_letter_the_stream_cannot_carry_is_shown_as_an_escape_not_raised() -> None:
    shown = terminal_safe("naïve ğ 日本", encoding="cp1252")
    assert shown == "naïve \\u011f \\u65e5\\u672c"
    shown.encode("cp1252")
    assert terminal_safe("naïve ğ 日本", encoding="utf-8") == "naïve ğ 日本"


FORGED = "Report: MALICIOUS"


def _record(name: str, claim: str) -> dict[str, Any]:
    flag = {"code": "unsupported", "claim": claim, "message": claim}
    return {
        "run": name,
        "analysts": {"reader": {"answers": [{"answer": "a1", "replayed": True, "flags": [flag]}]}},
    }


def test_a_run_name_with_a_newline_prints_as_one_line_with_a_visible_escape() -> None:
    lines = render_record(_record(f"run\n{FORGED}", "x")).split("\n")
    assert lines[0] == f"Replay of run\\n{FORGED}"
    assert FORGED not in lines


def test_a_claim_or_message_with_a_newline_cannot_start_an_output_line() -> None:
    lines = render_record(_record("run", f"first\n{FORGED}\n  ERROR: forged")).split("\n")
    assert FORGED not in lines and "  ERROR: forged" not in lines
    assert f"        claim: first\\n{FORGED}\\n  ERROR: forged" in lines


def test_the_line_count_of_a_record_does_not_depend_on_a_newline_in_a_value() -> None:
    with_newline = render_record(_record("run\nname", "a\nb"))
    without = render_record(_record("runname", "ab"))
    assert with_newline.count("\n") == without.count("\n")


def test_a_name_or_reason_with_a_newline_cannot_forge_a_line_of_the_comparison() -> None:
    diff = {
        "run": f"run\n{FORGED}",
        "errors": {"a": [{"part": "judge", "why": "boom\n  no difference"}], "b": []},
        "codes_gained": [
            {"code": "c1", "count": 1, "part": "narrative", "path": "p\nCompare forged: A = x"}
        ],
        "tool": {"calls": {"a": "1\nforged", "b": 2}},
    }
    shown = render_diff(diff, "ref\nA", "refB")
    lines = shown.split("\n")
    assert lines[0] == f"Compare run\\n{FORGED}: A = ref\\nA, B = refB"
    assert FORGED not in lines and "  no difference" not in lines
    assert not any(line.startswith("Compare forged") for line in lines)
    same = render_diff(
        {
            **diff,
            "run": "runX",
            "errors": {"a": [{"part": "judge", "why": "boom"}], "b": []},
            "codes_gained": [{"code": "c1", "count": 1, "part": "narrative", "path": "p"}],
            "tool": {"calls": {"a": "1forged", "b": 2}},
        },
        "refA",
        "refB",
    )
    assert shown.count("\n") == same.count("\n")
