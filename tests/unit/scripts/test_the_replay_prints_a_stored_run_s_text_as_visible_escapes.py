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
from scripts.replay.output import terminal_safe

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
    assert terminal_safe(text) == text


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
    assert terminal_safe("one\ntwo", keep_newlines=True) == "one\ntwo"


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
    kept: list[dict[str, Any]] = json.loads(out_json.read_text())
    assert kept[0]["run"] == f"run{ESCAPE}"
    assert any(OSC in t for t in kept[0]["printed"] + kept[0]["not_printed"])
    assert any(ESCAPE in t for t in kept[0]["not_printed"] + kept[0]["printed"])
