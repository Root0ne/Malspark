"""A string read from a stored run is shown on a terminal, never obeyed by it.

A stored run's tool names, recorded reasons and names come from the run, so a
control sequence in one could rewrite what the operator reads. The replay's
terminal output shows every unprintable character as a visible escape and
leaves printable text as it was; the ``--json`` record keeps the raw text.
"""

from __future__ import annotations

import copy
import io
import json
import re
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import agreement_names, limitation_inventory, remerge_revisions
from scripts.replay.compare import diff_records
from scripts.replay.output import render_diff, render_record, terminal_safe, write_json
from scripts.replay.rules import replay_run
from scripts.replay.stored import read_run

from malspark.reporting.limitation_inventory import build_inventory
from malspark.reporting.models import InventoryTool
from malspark.schemas.evidence import LedgerEntry
from tests.unit.reporting.test_the_limitations_inventory_is_written_by_code import (
    _DECOMPILE,
    _ledger,
    _report,
)
from tests.unit.scripts._replay_tiny import FIXTURE

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


def _windows_text_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make a file opened as text without an explicit encoding or newline behave as on Windows.

    The encoding is cp1252 and each ``\\n`` written becomes ``\\r\\n``.
    """
    real = io.open

    def windows_open(file: Any, mode: str = "r", *args: Any, **kw: Any) -> Any:
        if "b" not in mode:
            names = ("buffering", "encoding", "errors", "newline")
            kw.update(zip(names, args, strict=False))
            args = ()
            if kw.get("encoding") in (None, "locale"):
                kw["encoding"] = "cp1252"
            if kw.get("newline") is None and set(mode) & set("wax+"):
                kw["newline"] = "\r\n"
        return real(file, mode, *args, **kw)

    monkeypatch.setattr(io, "open", windows_open)
    monkeypatch.setattr("builtins.open", windows_open)


def test_the_windows_defaults_stand_in_translates_a_text_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _windows_text_defaults(monkeypatch)
    (tmp_path / "t").write_text("ğ\n", encoding="utf-8")
    assert (tmp_path / "t").read_bytes() == "ğ\r\n".encode()
    with pytest.raises(UnicodeEncodeError):
        (tmp_path / "t").write_text("ğ")


def test_the_json_and_golden_files_are_written_as_utf_8_where_the_default_is_a_code_page(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _hostile_inventory(monkeypatch)
    _windows_text_defaults(monkeypatch)
    out_json, golden = tmp_path / "out.json", tmp_path / "golden"
    args = [str(tmp_path / "run"), "--json", str(out_json), "--golden", str(golden)]
    assert limitation_inventory.main(args) == 0
    capsys.readouterr()
    kept = json.loads(out_json.read_text(encoding="utf-8"))
    assert any("\u202e" in t for t in kept[0]["not_printed"] + kept[0]["printed"])
    assert "\u202e" in (golden / "run.json").read_text(encoding="utf-8")
    assert b"\r" not in out_json.read_bytes() + (golden / "run.json").read_bytes()


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


HOSTILE = "v\n\r\x1b[2K\u202e  \x85\ud800X"
_BARE = {"Cc", "Cf", "Zl", "Zp", "Cs"}


class _Keyed(dict):  # type: ignore[type-arg]
    """A mapping whose keys are marked while a lookup by the original key still works.

    The renderer reads a record's structure by literal key and shows its data
    keys by iterating: marking every key keeps the first and tests the second.
    """

    def __init__(self, marked: dict[str, Any], original: dict[str, str]) -> None:
        super().__init__(marked)
        self._original = original

    def _key(self, key: Any) -> Any:
        return self._original.get(key, key)

    def __getitem__(self, key: Any) -> Any:
        return super().__getitem__(self._key(key))

    def get(self, key: Any, default: Any = None) -> Any:
        return super().get(self._key(key), default)

    def __contains__(self, key: object) -> bool:
        return super().__contains__(self._key(key))


def _marked(value: Any, mark: Callable[[str], str], ids: dict[str, int] | None = None) -> Any:
    """``value`` with every string and every dict key (but ``a`` and ``b``) marked.

    A key is numbered once for the whole record, so the same key is the same mark
    in every dict and two keys never share one.
    """
    ids = {} if ids is None else ids
    if isinstance(value, str):
        return mark(value)
    if isinstance(value, dict):
        keys = {
            k: k if k in {"a", "b"} else f"{mark(k)}#{ids.setdefault(k, len(ids))}" for k in value
        }
        return _Keyed({keys[k]: _marked(v, mark, ids) for k, v in value.items()}, keys)
    if isinstance(value, list):
        return [_marked(item, mark, ids) for item in value]
    if isinstance(value, tuple):
        return tuple(_marked(item, mark, ids) for item in value)
    return value


def _hostile(text: str) -> str:
    return HOSTILE


def _benign(text: str) -> str:
    return "v"


def _bare(shown: str) -> list[str]:
    return [c for c in shown if unicodedata.category(c) in _BARE and c != "\n"]


def _full_record() -> dict[str, Any]:
    """The tiny run's replay, with the fields a clean replay leaves empty filled in."""
    record = replay_run(read_run(FIXTURE), show_text=True)
    record["environment"]["settings_refused"] = {"a.setting": "why"}
    record["environment"]["doors_this_tree_lacks"] = ["a.door"]
    record["analysts"]["static"]["in_force"]["not_valid"] = ["T0001"]
    record["not_replayed"].append({"part": "judge", "why": "boom", "error": True})
    cause = {"part": "narrative", "why": "a cause"}
    record["against_stored"] = {
        "compared": True,
        "values": {"severity": {"stored": "Low", "replayed": "High"}},
        "techniques": {"only_stored": ["T1"], "only_replayed": ["T2"]},
        "sections": {
            "only_stored": [{"section": "s1", "cause": cause}],
            "moved": [{"section": "s2"}],
            "contents": [
                {"section": "s3", "field": "f", "reordered": True, "cause": cause},
                {"section": "s4", "field": "f", "row": 2, "merged": 3},
                {"section": "s5", "field": "f", "stored": {"digest": "d", "text": "t"}},
            ],
        },
        "indicators": {
            "only_stored": [{"indicator": "i1"}],
            "changed": [{"indicator": "i2", "stored": "yes", "replayed": "no", "cause": cause}],
        },
        "export": [{"type": "indicator", "stored": 1, "replayed": 2, "cause": cause}],
        "not_compared": ["severity"],
    }
    return record


def _full_diff(record: dict[str, Any]) -> dict[str, Any]:
    moved = copy.deepcopy(record)
    moved["report"]["severity"] = "High"
    moved["judge"]["flags"].append({"code": "stix.malformed_hash", "path": "objects[9]"})
    moved["environment"]["settings_refused"] = {"b.setting": "why"}
    diff = diff_records(record, moved)
    diff.update(
        errors={"a": [{"part": "judge", "why": "boom"}], "b": [{"part": "tool", "why": "bang"}]},
        schema={"a": 1, "b": 2},
        not_compared={"a": ["p"], "b": ["q"], "differently": ["r"]},
        codes_lost=[
            {"code": "c", "count": 1, "part": "x", "owner": "o", "path": "p", "subject": "s"}
        ],
        replayed={"a": ["x"], "b": ["y"]},
        not_replayed={"only_a": {"k": "v"}, "only_b": ["w"], "deep": {"a": 1, "b": {"c": "d"}}},
    )
    return diff


@pytest.mark.parametrize("build", [_full_record, lambda: _full_diff(_full_record())])
def test_every_field_and_key_of_a_record_or_a_comparison_prints_on_the_lines_the_renderer_gives(
    build: Callable[[], dict[str, Any]],
) -> None:
    source = build()

    def render(mark: Callable[[str], str] | None) -> str:
        data = source if mark is None else _marked(source, mark)
        refs = ("ref-a", "ref-b") if mark is None else (mark("ref-a"), mark("ref-b"))
        return render_record(data) if "analysts" in source else render_diff(data, *refs)

    shown, plain = render(_hostile), render(_benign)
    # The marker hides no section: the marked benign text has the unmarked text's lines.
    assert plain.count("\n") == render(None).count("\n")
    assert not _bare(shown)
    assert shown.count("\n") == plain.count("\n")
    # The marks reach the text: the test would pass vacuously on an empty rendering.
    assert shown.count("\\x1b[2K") > 30


def test_the_renderer_marks_reach_the_names_the_record_keeps_as_keys() -> None:
    shown = render_record(_marked(_full_record(), _hostile))
    assert "\\x1b[2K\\u202e" in shown and "\\ud800X#" in shown


def test_every_value_agreement_names_prints_stays_on_its_own_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    read: dict[str, Any] = {
        "run": "r",
        "passages": 1,
        "facts_before": 2,
        "facts_after": 3,
        "names_chars": 4,
        "limitation_chars": 5,
        "answered": [("E1", "E2", True), ("E3", "E4", False)],
        "names": [
            {
                "passage": "p",
                "name": "n",
                "outcome": "o",
                "sentence": "s",
                "facts": [{"id": "i", "cites": ["c1", "c2"], "text": "t"}],
            }
        ],
        "failed": [
            {
                "held_before": True,
                "outcome": "o",
                "redone": ["r1", "r2"],
                "cite": ["c1", "c2"],
                "sentence": "s",
            }
        ],
    }

    def printed(mark: Callable[[str], str]) -> str:
        agreement_names._print(_marked(read, mark))
        return capsys.readouterr().out

    shown, plain = printed(_hostile), printed(_benign)
    assert not _bare(shown)
    assert shown.count("\n") == plain.count("\n")
    assert shown.count("\\x1b[2K") > 10


def test_the_remerge_script_prints_every_value_of_a_record_on_its_own_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rule = {
        "restated": ["x"],
        "added": 1,
        "carried": ["x"],
        "beside": [],
        "withdrawn": [],
        "withdrawn_by_rule": [],
        "dropped_claims": 0,
        "dropped_values": 0,
    }
    record: dict[str, Any] = {
        "run": "r",
        "mediations": [3, 9],
        "revisions": [
            {
                "round": "1",
                "analyst": "a",
                "in_force": "2",
                "revision_blocks": "3",
                "logged": "l",
                "earlier_rule": rule,
                "this_rule": rule,
                "kept_in_force_now": [
                    {"claim": "4", "now": "n", "nearest_share": 0.5, "sentence": "s"}
                ],
            }
        ],
    }

    def printed(mark: Callable[[str], str]) -> str:
        remerge_revisions._print(_marked(record, mark))
        return capsys.readouterr().out

    shown, plain = printed(_hostile), printed(_benign)
    assert not _bare(shown)
    assert shown.count("\n") == plain.count("\n")
    assert shown.count("\\x1b[2K") > 5


def test_the_line_the_remerge_script_says_for_unread_lines_quotes_no_raw_character() -> None:
    said = remerge_revisions._not_read(HOSTILE, ValueError(HOSTILE))
    assert not _bare(said) and "\n" not in said
    assert said.count("\\x1b[2K") == 2 and "ValueError" in said


def test_a_backslash_n_and_a_newline_are_told_apart_and_the_text_is_reversible() -> None:
    assert terminal_safe("a\nb") == "a\\nb"
    assert terminal_safe("a\\nb") == "a\\\\nb"
    value = "x\\n\\\ny\x1b"
    shown = terminal_safe(value)
    back = (
        shown.replace("\\\\", "\0")
        .replace("\\n", "\n")
        .replace("\\x1b", "\x1b")
        .replace("\0", "\\")
    )
    assert back == value


def test_a_quoted_string_is_escaped_once_and_reads_as_python_writes_it() -> None:
    row = {"digest": "d", "text": "it's a\\b"}
    from scripts.replay.output import _show

    assert _show(row["text"]) == '"it\'s a\\\\b"'
    assert _show(["a'b\"", ("t",), None, 3]) == "['a\\'b\"', ('t',), None, 3]"


def test_a_lone_surrogate_is_escaped_where_the_stream_names_no_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdout", io.StringIO())
    shown = terminal_safe(HOSTILE)
    assert not _bare(shown) and "\\ud800X" in shown


def test_a_shown_text_is_escaped_once_not_once_by_repr_and_once_by_the_escaper() -> None:
    from scripts.replay.output import _said

    assert _said({"digest": "d", "text": "a\\b\x1b\n"}) == "d 'a\\\\b\\x1b\\n'"


def test_an_error_the_runner_says_quotes_a_stored_name_without_a_raw_character(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from scripts.replay import run as replay_cli

    with pytest.raises(SystemExit) as stopped:
        replay_cli._error("no stored run at {}", HOSTILE)
    assert stopped.value.code == 2
    said = capsys.readouterr().err
    assert not _bare(said.rstrip("\n")) and said.count("\n") == 1


@pytest.mark.parametrize("ascii_only", [True, False])
def test_a_json_file_holding_a_lone_surrogate_is_written_and_loads_back_the_same(
    tmp_path: Path, ascii_only: bool
) -> None:
    value = {"k\ud800": ["a\udfffb", "naïve 日本", "x\n"]}
    target = tmp_path / "out.json"
    write_json(target, value, indent=2, ensure_ascii=ascii_only, newline=True)
    assert json.loads(target.read_text(encoding="utf-8")) == value
    plain = {"k": ["naïve 日本", "x\n"]}
    write_json(target, plain, indent=2, ensure_ascii=ascii_only, newline=True)
    assert (
        target.read_bytes()
        == (json.dumps(plain, indent=2, ensure_ascii=ascii_only) + "\n").encode()
    )


def test_the_inventory_script_writes_its_json_and_golden_for_a_text_with_a_lone_surrogate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    report = _report(_ledger(), build=False)
    report.limitation_inventory = build_inventory(report, _ledger())
    report.limitation_inventory.not_offered.append(InventoryTool(tool="t\ud800", reason="r"))
    monkeypatch.setattr(
        limitation_inventory, "stored_inventory", lambda _run: (report, report.limitation_inventory)
    )
    out_json, golden = tmp_path / "out.json", tmp_path / "golden"
    args = [str(tmp_path / "run"), "--json", str(out_json), "--golden", str(golden)]
    assert limitation_inventory.main(args) == 0
    capsys.readouterr()
    kept = json.loads(out_json.read_text(encoding="utf-8"))
    assert any("\ud800" in t for t in kept[0]["not_printed"] + kept[0]["printed"])
    assert json.loads((golden / "run.json").read_text(encoding="utf-8")) == kept[0]


@pytest.mark.parametrize("ascii_only", [True, False])
def test_a_json_file_holds_the_same_bytes_where_text_writes_translate_line_ends(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ascii_only: bool
) -> None:
    _windows_text_defaults(monkeypatch)
    value = {"k": ["naïve 日本", "x\n"], "l": [1, 2]}
    target = tmp_path / "out.json"
    write_json(target, value, indent=2, ensure_ascii=ascii_only, newline=True)
    expected = json.dumps(value, indent=2, ensure_ascii=ascii_only) + "\n"
    assert target.read_bytes() == expected.encode()


def _back(shown: str) -> str:
    """The value a shown text was made from: every escape turned back into its character."""
    return re.sub(
        r"\\(\\|n|x[0-9a-f]{2}|u[0-9a-f]{4}|U[0-9a-f]{8})",
        lambda m: "\\" if m[1] == "\\" else "\n" if m[1] == "n" else chr(int(m[1][1:], 16)),
        shown,
    )


def _draws_over(char: str) -> bool:
    return unicodedata.combining(char) == 1 or unicodedata.category(char) == "Me"


_MARKS = [chr(c) for c in range(0x110000) if unicodedata.category(chr(c)).startswith("M")]
_OVER = [chr(c) for c in range(0x110000) if _draws_over(chr(c))]


def test_no_overlay_or_enclosing_mark_of_the_database_is_shown_raw() -> None:
    assert len(_OVER) > 20 and "\u0338" in _OVER and "\u20dd" in _OVER
    for char in _OVER:
        for value in (char, f"ab{char}cd", f"e\u0301{char}x"):
            shown = terminal_safe(value, encoding="utf-8")
            assert not any(_draws_over(c) for c in shown), hex(ord(char))
            assert _back(shown) == value


def test_a_mark_that_starts_a_value_never_attaches_to_the_label_before_it() -> None:
    assert len(_MARKS) > 2000
    for char in _MARKS:
        value = f"{char}x"
        shown = terminal_safe(value, encoding="utf-8")
        assert not unicodedata.category(shown[0]).startswith("M"), hex(ord(char))
        line = "label: " + shown
        assert not unicodedata.category(line[len("label: ")]).startswith("M")
        assert _back(shown) == value


@pytest.mark.parametrize("before", ["\x1b", "\n", "\u202e", "\ud800", "\u0338"])
def test_a_mark_after_a_character_shown_as_an_escape_is_shown_as_an_escape(before: str) -> None:
    for char in ("\u0301", "\u093e", "\u05b8", "\ufe0f"):
        value = f"a{before}{char}b"
        shown = terminal_safe(value, encoding="utf-8")
        assert f"\\u{ord(char):04x}b" in shown and char not in shown
        assert _back(shown) == value


def test_a_mark_after_a_letter_the_stream_cannot_carry_is_shown_as_an_escape() -> None:
    value = "\u65e5\u0301x"
    shown = terminal_safe(value, encoding="cp1258")
    assert shown == "\\u65e5\\u0301x"
    assert _back(shown) == value
    assert terminal_safe("a\u0301", encoding="cp1258") == "a\u0301"


@pytest.mark.parametrize("count", [31, 32, 200])
def test_no_more_marks_than_the_stream_safe_limit_stay_on_one_base(count: int) -> None:
    for mark in ("\u0301", "\u0951", "\u0e49"):
        value = "x" + mark * count + "y" + mark * 30
        shown = terminal_safe(value, encoding="utf-8")
        assert shown.startswith("x" + mark * 30 + f"\\u{ord(mark):04x}")
        assert shown.count(mark) == 60 and shown.endswith("y" + mark * 30)
        assert _back(shown) == value


@pytest.mark.parametrize(
    "word",
    [
        "cafe\u0301 nai\u0308ve",  # Latin, decomposed
        "\u0645\u064f\u062d\u064e\u0645\u0651\u064e\u062f",  # Arabic with vowel marks
        "\u0939\u093f\u0928\u094d\u0926\u0940",  # Devanagari, vowel signs (Mc) and virama
        "\u05e9\u05c1\u05b8\u05dc\u05d5\u05b9\u05dd",  # Hebrew with points
        "\u0e20\u0e32\u0e29\u0e32\u0e44\u0e17\u0e22\u0e48",  # Thai with a tone mark
        "\u1f00\u0313\u0342 \u03b1\u0301",  # Greek, decomposed
        "\u2764\ufe0f \u845b\U000e0100",  # variation selectors after a base
        "\u0995\u09cb\u09a8",  # Bengali, a vowel sign (Mc)
    ],
)
def test_a_decomposed_word_in_any_script_comes_through_unchanged(word: str) -> None:
    assert terminal_safe(word, encoding="utf-8") == word
    assert terminal_safe(unicodedata.normalize("NFD", word), encoding="utf-8") == (
        unicodedata.normalize("NFD", word)
    )


def test_a_long_run_of_marks_is_read_in_linear_time() -> None:
    shown = terminal_safe("x" + "\u0301" * 200_000, encoding="utf-8")
    assert shown.count("\\u0301") == 200_000 - 30


MARK = "\u0301"


def _leading_mark(text: str) -> str:
    return f"{MARK}v"


def _raw_marks(shown: str) -> list[str]:
    """Each combining mark shown as itself: with only the values starting with one, none may be."""
    return [c for c in shown if unicodedata.category(c).startswith("M")]


@pytest.mark.parametrize("build", [_full_record, lambda: _full_diff(_full_record())])
def test_no_value_that_starts_with_a_mark_draws_it_on_the_renderer_s_words(
    build: Callable[[], dict[str, Any]],
) -> None:
    source = _marked(build(), _leading_mark)
    if "analysts" in source:
        shown = render_record(source)
    else:
        shown = render_diff(source, _leading_mark("a"), _leading_mark("b"))
    assert not _raw_marks(shown)
    assert shown.count(f"\\u{ord(MARK):04x}v") > 30


def test_no_line_the_scripts_print_draws_a_value_s_leading_mark_on_their_words(
    capsys: pytest.CaptureFixture[str],
) -> None:
    read: dict[str, Any] = {
        "run": "r",
        "passages": 1,
        "facts_before": 2,
        "facts_after": 3,
        "names_chars": 4,
        "limitation_chars": 5,
        "answered": [("E1", "E2", True)],
        "names": [
            {
                "passage": "p",
                "name": "n",
                "outcome": "o",
                "sentence": "s",
                "facts": [{"id": "i", "cites": ["c1", "c2"], "text": "t"}],
            }
        ],
        "failed": [
            {
                "held_before": True,
                "outcome": "o",
                "redone": ["r1", "r2"],
                "cite": ["c1", "c2"],
                "sentence": "s",
            }
        ],
    }
    agreement_names._print(_marked(read, _leading_mark))
    limitation_inventory._print(
        _marked({"run": "r", "printed": ["a", "b"], "not_printed": ["c"]}, _leading_mark)
    )
    rule = {
        "restated": [],
        "added": "1",
        "carried": [],
        "beside": [],
        "withdrawn": [],
        "withdrawn_by_rule": [],
        "dropped_claims": "0",
        "dropped_values": "0",
    }
    remerge_revisions._print(
        _marked(
            {
                "run": "r",
                "mediations": "3",
                "revisions": [
                    {
                        "round": "1",
                        "analyst": "a",
                        "in_force": "2",
                        "revision_blocks": "3",
                        "logged": "l",
                        "earlier_rule": rule,
                        "this_rule": rule,
                        "kept_in_force_now": [
                            {"claim": "4", "now": "n", "nearest_share": 0.5, "sentence": "s"}
                        ],
                    }
                ],
            },
            _leading_mark,
        )
    )
    said = remerge_revisions._not_read(_leading_mark("r"), ValueError(_leading_mark("e")))
    shown = capsys.readouterr().out + said
    assert not _raw_marks(shown)
    assert shown.count(f"\\u{ord(MARK):04x}v") > 25


def test_the_runner_s_stderr_lines_draw_no_leading_mark_on_their_words(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from scripts.replay import run as replay_cli

    record = _marked(_full_record(), _leading_mark)
    monkeypatch.setattr(replay_cli, "_replay", lambda _runs, _show: [record])
    assert replay_cli.main([str(tmp_path)]) == 2
    printed = capsys.readouterr()
    assert " raised: " in printed.err and not _raw_marks(printed.out + printed.err)

    monkeypatch.chdir(tmp_path)
    (tmp_path / f"{MARK}d").mkdir()
    for argv in (
        [f"{MARK}nowhere"],
        [f"{MARK}d", "--json", f"{MARK}d/out.json"],
    ):
        with pytest.raises(SystemExit) as stopped:
            replay_cli.main(argv)
        assert stopped.value.code == 2
        said = capsys.readouterr().err
        assert said.startswith("replay: ") and f"\\u{ord(MARK):04x}" in said
        assert not _raw_marks(said)
