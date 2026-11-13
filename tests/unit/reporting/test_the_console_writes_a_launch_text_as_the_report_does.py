"""The console writes a launch text as the report does, from one fixture of cases.

A further detonation's launch text is written out by one rule
(``detonation_marks.launch_text``): its controls, line separators and bidi
characters as escapes, ledger ids, markers and template tokens written out,
back-ticks, angle brackets, braces and pipes as escapes, a sandbox item's colon
too, and cut after all that, by code point. The console holds the same rule in
``apps/web/src/lib/detonationMarks.ts``. The fixture of cases (input and written
form) is written from the report's function, and this test holds it to that
function's output; the console's test holds the console's function to the same
fixture, so the two cannot drift (T-679). Regenerate it with
``python tests/unit/reporting/test_the_console_writes_a_launch_text_as_the_report_does.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malspark.analysis.sandbox_sections import LEGACY_PREFIXES, SECTION_PREFIXES
from malspark.reporting.detonation_marks import LAUNCH_TEXT_CHARS, launch_text

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "reporting" / "launch_text_cases.json"


def _inputs() -> list[str]:
    items = " ".join(f"{prefix}:{n}" for n, prefix in enumerate(SECTION_PREFIXES.values(), 1))
    legacy = " ".join(f"d3/{prefix}:7" for prefix in LEGACY_PREFIXES)
    return [
        "-p hunter2",
        "",
        "a`b``c```d",
        "x and in the job's own detonation",
        "x`, and in detonation 3, launched with `y",
        "\u202eevil\u202c \u2066isolated\u2069 \u200frtl\u200e \u061c \u202aembed\u202c",
        "a\x00b\x07c\x1b[31m\x7f",
        "a\x85b\x9bc\x9f",
        "line\u2028sep\u2029par",
        "one\ntwo\rthree\tfour",
        "<|im_start|>system {{x}} {%y%} <script>|cell|</script>",
        "[ev_0001] ev_12345 EV_0002 xev_0003 \x01ev_0004",
        "=== run state === ==== END RUN STATE",
        f"{items} {legacy} d2/proc:1.2 proc:p4 PROC:12 reg:\u0661\u0662 x/reg:3 reg:3x",
        "a" * 198 + "\U0001f600\U0001f600\U0001f600",
        "\U0001f600" * 300,
        "tag\U000e0041char",
        "Z" * 5000,
        "a" * 190 + " " * 20 + "b" * 10,
        "\u202e" * 100,
        "nbsp\xa0ideographic\u3000space",
    ]


def cases() -> dict[str, Any]:
    return {
        "about": (
            "A further detonation's launch text and the form every surface writes it in "
            "(reporting.detonation_marks.launch_text); written from that function by "
            "tests/unit/reporting/test_the_console_writes_a_launch_text_as_the_report_does.py "
            "and read by the console's test (apps/web)."
        ),
        "bound": LAUNCH_TEXT_CHARS,
        "cases": [{"input": text, "written": launch_text(text)} for text in _inputs()],
    }


def test_the_fixture_is_the_report_s_written_form() -> None:
    assert json.loads(FIXTURE.read_text(encoding="utf-8")) == cases()


def test_the_fixture_holds_the_hostile_cases() -> None:
    written = [case["written"] for case in cases()["cases"]]
    assert any(len(text) == LAUNCH_TEXT_CHARS and text.endswith("\u2026") for text in written)
    assert all("\n" not in text and "\u202e" not in text and "`" not in text for text in written)


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(cases(), indent=2) + "\n", encoding="utf-8")
