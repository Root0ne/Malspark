"""The replay re-runs the platform's deterministic rules over a stored run, and only reads it.

A tiny stored run (``tests/fixtures/replay/tiny``) is replayed in this process
and each producer's codes are the ones its answers raise under today's rules:
the analysts' answers and claims in force, the judge's bundle, the narrative,
a composer section, a tool call and the report linter. The claims in force
carry notes the run decided (a technique id marked not valid, an absence claim
not yet noted); the replay resets them and decides them again, so a change to
a check reaches what the report publishes, and a test changes one check and
sees a technique and an indicator move. The stored degradation reasons the
verdict decides are decided again, and a finding the stored summary says its
producer was not shown leaves no note. The replay is the same twice, leaves
every file of the run as it was, reaches no network, carries no value from the
run unless asked for the text, names what it could not replay, says what the
rebuilt report does not share with the stored one, and ends with status 2 when
a part raised. Two records of one run are told apart by every code they gained
or lost and every report value that moved, and two of different schemas make a
partial comparison.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import json
import os
import re
import shutil
import socket
import sys
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from scripts.replay import compare
from scripts.replay import rules as replay_rules
from scripts.replay import run as replay_cli
from scripts.replay.compare import diff_records, differs, has_errors, is_partial
from scripts.replay.database import (
    JobRows,
    StoredRunExists,
    export_jobs,
    jsonable,
    with_sample,
    write_run,
)
from scripts.replay.guard import ReplayRefused, replay_environment
from scripts.replay.output import render_diff, render_record
from scripts.replay.record import REPLAY_SCHEMA, digest, errors, value_free_subject
from scripts.replay.rules import replay_run
from scripts.replay.stored import (
    StoredRun,
    StoredRunChanged,
    check_unchanged,
    digests,
    read_run,
)

from malspark.pipeline import validation
from tests.linear_cost import assert_ratio
from tests.unit.scripts._replay_tiny import EXPECTED_TOTALS, FIXTURE

# Sentences the analysts wrote in the tiny run: none is printed without the text.
CLAIM_SENTENCES = (
    "Its configuration strings are XOR-encoded",
    "Process injection is not present",
    "It registers a scheduled task named Updater",
    "The file has four sections",
)
# A literal quoted in a STIX pattern.
_QUOTED = re.compile(r"'((?:[^'\\]|\\.)+)'")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


@pytest.fixture(scope="module")
def record() -> dict[str, Any]:
    return replay_run(read_run(FIXTURE))


def _flags(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Each finding without its words or their digest."""
    return [
        {k: v for k, v in flag.items() if k not in ("message", "words")} for flag in entry["flags"]
    ]


def _without_words(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in row.items() if k != "words"} for row in rows]


def _copy_run(tmp_path: Path, **edits: Callable[[dict[str, Any]], None]) -> Path:
    """The tiny run copied, with each named file's JSON edited (``report_json=...``)."""
    target = tmp_path / "tiny"
    shutil.copytree(FIXTURE, target)
    for name, edit in edits.items():
        path = target / name.replace("_json", ".json").replace("_", "-")
        data = json.loads(path.read_text(encoding="utf-8"))
        edit(data)
        path.write_text(json.dumps(data), encoding="utf-8")
    return target


def test_the_tiny_run_replays_to_its_expected_codes(record: dict[str, Any]) -> None:
    assert record["schema"] == REPLAY_SCHEMA
    assert record["totals"] == EXPECTED_TOTALS
    assert errors(record) == []

    static = record["analysts"]["static"]
    (answer,) = [a for a in static["answers"] if a["replayed"]]
    assert (answer["answer"], answer["source"], answer["in_force"]) == (
        "round 1",
        "agent_reports",
        True,
    )
    assert answer["claims"] == 6
    flagged = _flags(answer)
    # An entry the analyst's own call made after this answer was written is
    # not one the answer could cite.
    assert {
        "code": "isr.ungrounded_technique",
        "path": "static.claims[5]",
        "subject": "T1140",
        "entries": ["ev_0004"],
    } in flagged
    # The claim of T1027 cites no entry, and the analyst's findings, read back
    # from the stored Findings table, cite one for T1027: it is not asked.
    assert answer["findings"] == 2
    assert not [f for f in flagged if f.get("path") == "static.claims[1]"]
    assert {
        "code": "attck.unknown_id",
        "path": "static.claims[2]",
        "subject": "T9999",
        "entries": ["ev_0002"],
    } in flagged
    assert {
        "code": "attck.absence_claim",
        "path": "static.claims[3]",
        "subject": "T1055",
        "entries": ["ev_0002"],
    } in flagged
    assert _flags(static["in_force"]) == [
        {
            "code": "attck.claim_does_not_describe",
            "path": "static.claims[2]",
            "subject": "T1105",
            "entries": ["ev_0001"],
        },
        {
            "code": "attck.absence_claim",
            "path": "static.claims[3]",
            "subject": "T1055",
            "entries": ["ev_0002"],
        },
    ]

    assert record["judge"]["indicators_dropped"] == 1
    assert record["tool"]["flags"] == [
        {
            "code": "tool.argument_names_its_parameter",
            "entries": ["ev_0002"],
            "tool": "strings",
            "arguments": ["pattern"],
        }
    ]

    report = record["report"]
    assert (report["verdict"], report["severity"], report["confidence"]) == (
        "Malware",
        "Medium",
        0.8,
    )
    assert report["category"] == f"sha256:{digest('loader')}"
    published = {tid: row["published"] for tid, row in report["techniques"].items()}
    assert published == {"T1027": True, "T1055": True, "T1105": True, "T9998": False}
    assert report["export"]["attack_patterns"] == ["T1027", "T1055", "T1105"]
    # The narrative breaks its schema under these rules: the round would keep none, and the
    # deterministic summary discusses none of the claims in force.
    assert record["narrative"]["kept"] is False
    assert report["claims_not_discussed"] == {"network": [1], "static": [1, 2, 3, 4]}
    assert report["detection_rules"] == {"suricata": 1, "yara": 1}
    # The URL the decoder recovered, its host and the sample's own digest, by
    # kind and digest, each answer by its head and a digest of its words.
    assert {key.split(":")[0]: row["published"] for key, row in report["indicators"].items()} == {
        "domain": "yes",
        "hash": "yes",
        "url": "yes",
    }
    assert all(set(row) == {"kind", "published", "answer"} for row in report["indicators"].values())
    assert report["degraded"] is True
    assert report["degradation"] == {"decided": 0, "stored_decided_again": 0, "kept_as_stored": 2}


def test_the_stored_claim_notes_are_decided_again(record: dict[str, Any]) -> None:
    # The run stored T1105's id as not valid and T1055's absence claim as not
    # kept when asked; neither is taken from the record.
    in_force = record["analysts"]["static"]["in_force"]
    assert in_force["not_valid"] == []
    assert in_force["kept_after_absence_question"] == ["T1055"]
    assert record["report"]["techniques"]["T1105"] == {"published": True}
    named = {row["part"]: row["why"] for row in record["not_replayed"]}
    assert "run summary" in named and "rebuilt from the replayed findings" in named["run summary"]


def test_a_validator_change_moves_what_is_published(
    record: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    known = validation._technique_is_known
    monkeypatch.setattr(
        validation,
        "_technique_is_known",
        lambda tid, attck: tid != "T1105" and known(tid, attck),
    )
    stricter = replay_run(read_run(FIXTURE))
    monkeypatch.undo()
    monkeypatch.setattr(validation, "_indicator_problem", lambda *_a, **_k: "")
    looser = replay_run(read_run(FIXTURE))

    technique = diff_records(record, stricter)
    assert technique["report"]["techniques"]["changed"]["T1105"]["b"]["published"] is False
    assert technique["report"]["exported_techniques"] == {"only_a": ["T1105"], "only_b": []}
    assert stricter["analysts"]["static"]["in_force"]["not_valid"] == ["T1105"]

    indicator = diff_records(record, looser)
    assert _without_words(indicator["codes_lost"]) == [
        {
            "part": "judge",
            "path": "objects[3] 'indicator--1'",
            "code": "stix.ungrounded_indicator",
            "count": 1,
            "in_a": 1,
            "in_b": 0,
        }
    ]
    [dropped] = [f for f in record["judge"]["flags"] if f["code"] == "stix.ungrounded_indicator"]
    assert indicator["codes_lost"][0]["words"] == dropped["words"]
    assert list(indicator["report"]["indicators"]["only_b"]) == ["domain:2d5a0519f25d"]
    assert indicator["judge"] == {"indicators_dropped": {"a": 1, "b": 0}}


def test_what_the_stored_run_cannot_give_is_named(record: dict[str, Any]) -> None:
    named = {(row["part"], row["why"]) for row in record["not_replayed"]}
    assert ("analyst network round 1", "stored truncated at 111 characters") in named
    assert (
        "analyst static round 0",
        "stored as the platform's summary of its claims, not as the analyst wrote it",
    ) in named
    parts = {part for part, _why in named}
    assert {
        "analysts",
        "judge",
        "composer",
        "judge evidence",
        "ledger",
        "identity",
        "report",
        "run summary",
    } <= parts
    whys = " ".join(why for _part, why in named)
    for named_input in (
        "isr.retry_dropped",
        "nudge",
        "byte budget",
        "keeps no key order",
        "routed file type",
        "shown",
        "agent_stats",
    ):
        assert named_input in whys
    network = record["analysts"]["network"]["answers"]
    assert [(a["answer"], a["replayed"]) for a in network] == [
        ("round 0", False),
        ("round 1", False),
        ("round 2", True),
    ]


def test_a_part_that_raises_is_an_error_and_the_command_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("a check that breaks")

    monkeypatch.setattr(validation, "parse_violations", _raise)
    broken = replay_run(read_run(FIXTURE))
    raised = errors(broken)
    assert [row["part"] for row in raised] == ["analyst static answers", "analyst network answers"]
    assert all(row["why"].startswith("RuntimeError at ") for row in raised)
    assert "ERROR: analyst static answers raised" in render_record(broken)

    out = tmp_path / "broken.json"
    assert replay_cli.main([str(FIXTURE), "--json", str(out), "--quiet"]) == 2
    assert "raised: RuntimeError" in capsys.readouterr().err

    monkeypatch.undo()
    whole = replay_run(read_run(FIXTURE))
    diff = diff_records(broken, whole)
    assert has_errors(diff)
    same = diff_records(broken, copy.deepcopy(broken))
    assert has_errors(same) and not differs(same)
    text = render_diff(same, "A-ref", "B-ref")
    assert "ERROR under A" in text and "no difference" not in text


def test_a_replay_is_deterministic_and_leaves_the_run_unchanged(record: dict[str, Any]) -> None:
    before = digests(FIXTURE)
    again = replay_run(read_run(FIXTURE))
    assert json.dumps(again, sort_keys=True) == json.dumps(record, sort_keys=True)
    assert digests(FIXTURE) == before


def test_a_run_changed_during_the_replay_fails_it() -> None:
    before = {"evidence.json": "a" * 64, "job.json": "b" * 64}
    check_unchanged(before, dict(before))
    with pytest.raises(StoredRunChanged, match=r"changed: evidence\.json"):
        check_unchanged(before, {**before, "evidence.json": "c" * 64})
    with pytest.raises(StoredRunChanged, match=r"added: notes\.txt"):
        check_unchanged(before, {**before, "notes.txt": "d" * 64})


def test_the_command_writes_its_record_and_never_inside_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "tiny.json"
    before = digests(FIXTURE)
    assert replay_cli.main([str(FIXTURE), "--json", str(out), "--quiet"]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["totals"] == EXPECTED_TOTALS
    assert written["stored"]["files"] == before
    for flag, inside in (("--json", "record.json"), ("--work", "trees"), ("--job-dir", "jobs")):
        with pytest.raises(SystemExit) as ended:
            replay_cli.main([str(FIXTURE), flag, str(FIXTURE / inside), "--quiet"])
        assert ended.value.code == 2
        assert "inside the stored run" in capsys.readouterr().err
        assert not (FIXTURE / inside).exists()
    for timeout in ("0", "-1"):
        with pytest.raises(SystemExit) as ended:
            replay_cli.main([str(FIXTURE), "--compare", "A", "B", "--timeout", timeout])
        assert ended.value.code == 2
        assert "--timeout takes a number of seconds above 0" in capsys.readouterr().err
    assert digests(FIXTURE) == before


def test_no_claim_text_is_printed_unless_asked(record: dict[str, Any]) -> None:
    quiet = json.dumps(record) + render_record(record)
    assert not [s for s in CLAIM_SENTENCES if s in quiet]
    assert not any("message" in flag for flag in record["judge"]["flags"])

    shown = replay_run(read_run(FIXTURE), show_text=True)
    static = next(a for a in shown["analysts"]["static"]["answers"] if a["replayed"])
    unknown = next(f for f in static["flags"] if f["code"] == "attck.unknown_id")
    assert "T9999" in unknown["message"]
    assert unknown["claim"].startswith("It registers a scheduled task named Updater")
    assert all("message" in flag for flag in shown["judge"]["flags"])
    assert shown["report"]["category_text"] == "loader"


def _strings(value: Any) -> Iterator[str]:
    """Every key and every text of a record, nested ones included."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key)
            yield from _strings(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _strings(inner)
    elif value is not None:
        yield str(value)


def _values_of(run: Path, shown: dict[str, Any]) -> set[str]:
    """Every indicator value the run holds: its IOC table's, the stored report's and the judge's."""
    values = {str(row["value"]) for row in shown["report"]["indicators"].values()}
    stored = run / "report.json"
    if stored.is_file():
        report = json.loads(stored.read_text(encoding="utf-8"))
        values.update(
            str(row.get("value"))
            for row in report.get("consolidated_iocs") or []
            if isinstance(row, dict) and row.get("value")
        )
    judge = run / "stix-judge.json"
    if judge.is_file():
        # A judge that answered no bundle stored none.
        bundle = json.loads(judge.read_text(encoding="utf-8")).get("bundle") or {}
        for obj in bundle.get("objects") or []:
            if obj.get("type") == "indicator":
                values.update(_QUOTED.findall(str(obj.get("pattern") or "")))
        for obj in bundle.get("objects") or []:
            # The judge's own names for its objects, and the id parts that are not a
            # number or a UUID: a path quotes the label.
            if obj.get("type") == "malware" and obj.get("name"):
                values.add(str(obj["name"]))
            ident = str(obj.get("id") or "")
            rest = ident.partition("--")[2]
            if rest and not rest.isdigit() and not _UUID.match(rest):
                values.add(ident)
    for flag in _all_flags(shown):
        if flag.get("subject_text"):
            values.add(str(flag["subject_text"]).partition(":")[2] or str(flag["subject_text"]))
    # The judge's category words, and each detection draft's name and body, which carry them
    # and the run's values.
    if shown["report"].get("category_text"):
        values.add(str(shown["report"]["category_text"]))
    for draft in shown["report"].get("detection_drafts") or []:
        values.update(str(draft[key]) for key in ("name_text", "body_text") if draft.get(key))
    return {value for value in values if len(value) >= 4}


def _all_flags(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for agent in record["analysts"].values():
        for answer in agent["answers"]:
            yield from answer.get("flags") or []
        yield from (agent.get("in_force") or {}).get("flags") or []
    for part in ("judge", "narrative", "tool", "fp_linter"):
        yield from (record.get(part) or {}).get("flags") or []
    for section in (record.get("composer") or {}).get("sections", {}).values():
        yield from section.get("flags") or []


# What a word is stripped of at either end, and the length from which one word alone is
# searched.
_PUNCTUATION = ".,;:!?()[]{}<>\"'`"
_LONG_WORD = 8
_PHRASES = (3, 4)
# A word that reads as a value whatever source holds it: one with a digit or a dot extension
# (``ws2_32.dll``), or one of six characters or more with a capital after its first letter and
# a small letter in it (``RegSetValueExA``).
_VALUE_WORD = re.compile(r"\d|\w\.[A-Za-z0-9]{1,4}$")
_MIXED_CASE = re.compile(r"^(?=.*[a-z]).+[A-Z]")
_MIXED_FROM = 6
# Where a clause ends: no phrase spans one.
_CLAUSE = re.compile(r"[;:\n()\[\]{}]|\.(?=\s|$)")


def _words(text: str) -> list[str]:
    """``text`` lower case, split at white space, each word without punctuation at its ends."""
    return [w for w in (raw.strip(_PUNCTUATION) for raw in text.lower().split()) if w]


def _text_only(shown: Any, quiet: Any) -> Iterator[tuple[str, str]]:
    """Every text the record made with the text holds where the one without it holds nothing:
    the words, the ``*_text`` fields, a claim's sentence, an argument's values, at any depth.
    Each comes with the words of the value-free fields beside it (a finding's path, subject,
    code, entries), which the record without the text holds by design. A ``*_text`` field
    equal to its value-free twin (a path that quotes no value) adds nothing."""
    if isinstance(shown, dict) and isinstance(quiet, dict):
        flat = [
            v for v in quiet.values() if isinstance(v, str | int | float | list) and v is not True
        ]
        beside = " ".join(" ".join(_words(text)) for text in _strings(flat))
        for key, inner in shown.items():
            if key in quiet:
                yield from _text_only(inner, quiet[key])
            elif key.endswith("_text") and quiet.get(key.removesuffix("_text")) == inner:
                continue
            else:
                yield from ((s, f" {beside} ") for s in _strings(inner) if s != str(key))
    elif isinstance(shown, list) and isinstance(quiet, list):
        for inner_shown, inner_quiet in zip(shown, quiet, strict=False):
            yield from _text_only(inner_shown, inner_quiet)


def _stored_texts(run: Path) -> Iterator[str]:
    """Every text value of every JSON file the stored run holds: what its models and its
    tools wrote, and what the platform wrote from them."""
    for path in sorted(run.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        stack = [data]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
            elif isinstance(value, str):
                yield value


@functools.cache
def _platform_words() -> tuple[frozenset[str], str]:
    """The platform's own source (its package and the replay): its words, and its clauses as
    lines of words, so a phrase found in it never spans a clause."""
    root = Path(__file__).resolve().parents[3]
    words: set[str] = set()
    lines: list[str] = []
    for tree in (root / "src", root / "scripts" / "replay"):
        for path in sorted(tree.rglob("*.py")):
            text = path.read_text(encoding="utf-8", errors="replace")
            words.update(_words(text))
            for clause in _clauses(text):
                words.update(clause)
                lines.append(f" {' '.join(clause)} ")
    return frozenset(words), "\n".join(lines)


def _clauses(text: str) -> list[list[str]]:
    """``text``'s clauses (cut at ``;``, ``:``, a full stop, a line break, a bracket), each as
    its words (:func:`_words`)."""
    return [words for part in _CLAUSE.split(text) if (words := _words(part))]


def _grams(text: str) -> Iterator[str]:
    """Every run of three and of four consecutive words inside one clause of ``text``
    (:data:`_PHRASES`), and every word of :data:`_LONG_WORD` characters or more."""
    for words in _clauses(text):
        for size in _PHRASES:
            yield from (" ".join(words[i : i + size]) for i in range(len(words) - size + 1))
    yield from (w for w in _words(text) if len(w) >= _LONG_WORD)


def _value_words(text: str) -> set[str]:
    """The words of ``text`` that read as a value, lower case: one with a digit or a dot
    extension (:data:`_VALUE_WORD`), or one of :data:`_MIXED_FROM` characters or more with a
    capital after its first letter beside a small letter (:data:`_MIXED_CASE`)."""
    raw = (w.strip(_PUNCTUATION) for w in text.split())
    return {
        w.lower()
        for w in raw
        if w and (_VALUE_WORD.search(w) or (len(w) >= _MIXED_FROM and _MIXED_CASE.match(w)))
    }


def _an_id(word: str) -> bool:
    """Whether a word is an id the record writes as it is (an ATT&CK id, a ledger entry, a
    STIX id whose id part is a number or a UUID): an id, not a value."""
    from scripts.replay.record import value_free_label

    return value_free_subject(word) == word or ("--" in word and value_free_label(word) == word)


def _names(record: Any) -> set[str]:
    """The names a record keys or lists its parts by, lower case: every key at any depth and
    every whole one-word element of a list (an agent, a report section, a code)."""
    found: set[str] = set()
    stack = [record]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            found.update(str(key).lower() for key in value)
            stack.extend(value.values())
        elif isinstance(value, list):
            found.update(v.lower() for v in value if isinstance(v, str) and len(v.split()) == 1)
            stack.extend(v for v in value if isinstance(v, dict | list))
    return found


def _leaks(run: Path) -> list[str]:
    """What of the run's own words its record made without the text holds (:func:`_leaked`)."""
    return _leaked(run, replay_run(read_run(run), show_text=True), replay_run(read_run(run)))


def _leaked(run: Path, shown: dict[str, Any], quiet: dict[str, Any]) -> list[str]:
    """What of the run's own words ``quiet``, the record made without the text, holds, sorted.

    The haystack is ``quiet`` (its keys and values, but not the bookkeeping that names
    where it was made) and its printed form. Words are compared lower case, split at white
    space, with punctuation at a word's ends removed. The needles, all read from the run
    and none from a list of words:

    1. every whole value of :func:`_values_of` (indicator values, the judge's names, a
       subject's value, the category, each draft's name and body), found as a substring;
    2. every text the record made with the text adds (:func:`_text_only`), whole, found
       word-bounded;
    3. every phrase of three or four consecutive words inside one clause (cut at ``;``,
       ``:``, a full stop, a line break, a bracket: no phrase spans a clause), and every word
       of eight characters or more, of each text of 1 and 2 and of every text value of the
       stored run's JSON files (:func:`_stored_texts`), found when one clause of the
       haystack holds it word-bounded;
    4. every word of those texts that reads as a value (:func:`_value_words`: a digit or a
       dot extension, or six characters or more with a capital after the first letter beside
       a small one), found word-bounded, counted even where the platform's source holds it
       (an API or module name standing alone). A word under six characters with no digit
       and no extension is never a value by itself.

    A hit of 4 is not counted only when it is an id or a name as below, or held beside its
    text. A hit of 2 or 3 is not counted when one clause of the platform's own source
    (``src`` and ``scripts/replay``, cut the same way) holds it word-bounded (the
    platform's wording, not the run's), when
    every word of it is an id the record writes as it is (:func:`_an_id`), a name the
    record keys or lists its parts by (:func:`_names`), a word without a letter, or a path
    made of such pieces and the platform's words; when it holds at least one such word and
    every other word of it is a word of the platform's source (the platform's wording around
    an id or a name it writes); or, for a text of 2, when the value-free fields beside that
    text hold it (a finding's message quoting the finding's own path).

    What it cannot see: a run's single word that the platform's source also holds and that
    has no digit, no dot extension and no mixed case of six characters or more (``loader``);
    a run's phrase the platform also writes in one clause of its source; a phrase the run's
    text and the record cut at different clause marks; a value the record writes
    value-free by design (an id, a key, a one-word list element).
    """
    from scripts.replay.record import BOOKKEEPING_KEYS

    values = _values_of(run, shown)
    kept = {k: v for k, v in quiet.items() if k not in BOOKKEEPING_KEYS}
    texts = [text.lower() for text in [*_strings(kept), render_record(quiet)]]
    leaked = {v for v in values if any(v.lower() in text for text in texts)}
    hay = " ".join(f" {' '.join(_words(text))} " for text in texts)
    held = {gram for text in texts for gram in _grams(text)}
    held_words = {word for text in texts for word in _words(text)}
    own_words, own = _platform_words()
    names = _names(kept)

    def a_name(word: str) -> bool:
        """An id, a name, a word without a letter, or a path made of them and the platform's
        words that indexes a list, starts at a name or ends at an id (``objects[2``,
        ``steps[1].action``, ``<agent>.claims[4``, ``capability_matrix.t1059.004``); a file name
        (``advapi32.dll``) is none of them."""
        if _an_id(word) or word in names or not any(c.isalpha() for c in word):
            return True
        pieces = [p for p in re.split(r"[.\[\]]", word) if p]
        a_path = (
            "[" in word
            or "]" in word
            or pieces[0] in names
            or _an_id(pieces[-1])
            or _an_id(word.partition(".")[2])
        )
        return (
            a_path
            and len(pieces) > 1
            and all(p.isdigit() or _an_id(p) or p in names or p in own_words for p in pieces)
        )

    def counted(needle: str, beside: str = " ") -> bool:
        bounded = f" {needle} "
        words = needle.split()
        named = [a_name(word) for word in words]
        return not (
            bounded in beside
            or needle in own_words
            or bounded in own
            or all(named)
            # The platform's own words around an id or a name it writes.
            or (any(named) and all(n or w in own_words for n, w in zip(named, words, strict=True)))
        )

    def a_value(word: str, beside: str = " ") -> bool:
        """A word that reads as a value counts even where the platform's source holds it."""
        return f" {word} " not in beside and not a_name(word)

    for text, beside in _text_only(shown, quiet):
        words = _words(text)
        if len(text) >= 4 and words and f" {' '.join(words)} " in hay:
            if counted(" ".join(words), beside):
                leaked.add(" ".join(words))
        leaked.update(g for g in _grams(text) if g in held and counted(g, beside))
        leaked.update(w for w in _value_words(text) if w in held_words and a_value(w, beside))
    for text in [*values, *_stored_texts(run)]:
        leaked.update(g for g in _grams(text) if g in held and counted(g))
        leaked.update(w for w in _value_words(text) if w in held_words and a_value(w))
    return sorted(leaked)


def test_the_leak_scan_finds_a_phrase_or_a_word_of_the_run_inside_a_longer_value() -> None:
    """The scan reads its needles from the run: a phrase of a claim's sentence or one long word
    of it inside a longer value is found; the platform's own wording around it is not."""
    shown = replay_run(read_run(FIXTURE), show_text=True)
    quiet = replay_run(read_run(FIXTURE))
    assert _leaked(FIXTURE, shown, quiet) == []
    sentence = "It registers a scheduled task named Updater"
    assert any(sentence in text for text, _beside in _text_only(shown, quiet))
    for inside, found in (
        (f"the judge dropped it ({sentence.lower()} at boot)", "registers a scheduled task"),
        ("the judge dropped it (it registers xorshift-encoded updaters)", None),
    ):
        moved = copy.deepcopy(quiet)
        moved["report"]["techniques"]["T1105"] = {"published": False, "why": inside}
        said = _leaked(FIXTURE, shown, moved)
        assert "the judge dropped it" not in said
        if found is None:
            assert said == []
        else:
            assert found in said and "scheduled task named updater" in said
    # One long word of the run alone, inside a longer sentence, that the platform never writes.
    own_words = _platform_words()[0]
    long_word = min(
        w
        for text, _beside in _text_only(shown, quiet)
        for w in _words(text)
        if len(w) >= _LONG_WORD and w not in own_words
    )
    moved = copy.deepcopy(quiet)
    moved["report"]["techniques"]["T1105"] = {"published": False, "why": f"names {long_word} here"}
    assert _leaked(FIXTURE, shown, moved) == [long_word]
    # A word of the run that reads as a value counts even where the platform's source holds it.
    value_word = min(
        w
        for text, _beside in _text_only(shown, quiet)
        for w in _value_words(text)
        if any(c.isalpha() for c in w) and not _an_id(w) and w in own_words
    )
    moved["report"]["techniques"]["T1105"]["why"] = f"names {value_word} here"
    assert value_word in _leaked(FIXTURE, shown, moved)
    # And three words of the run's sentence inside a longer value are a phrase of it.
    words = _words(sentence)
    three = next(
        " ".join(words[i : i + 3])
        for i in range(len(words) - 2)
        if f" {' '.join(words[i : i + 3])} " not in _platform_words()[1]
    )
    moved["report"]["techniques"]["T1105"]["why"] = f"first: {three}, then"
    assert three in _leaked(FIXTURE, shown, moved)


def test_no_value_of_the_run_is_in_the_record_without_the_text() -> None:
    runs = [FIXTURE]
    extra = os.environ.get("MALSPARK_REPLAY_RUN")
    if extra:
        runs.append(Path(extra))
    for run in runs:
        shown = replay_run(read_run(run), show_text=True)
        quiet = replay_run(read_run(run))
        assert _values_of(run, shown), run
        assert _leaked(run, shown, quiet) == [], run
        # The same value-free fields either way: the text only adds fields.
        assert {k: v for k, v in shown["report"].items() if not k.endswith("_text")}.keys() == (
            quiet["report"].keys()
        )
    # The tiny run's IOC answers quote a value, so the scan has one to find.
    shown = replay_run(read_run(FIXTURE), show_text=True)
    # Each draft's name is in the scan, and the record without the text holds its digest.
    drafts = shown["report"]["detection_drafts"]
    assert drafts and all(draft["name_text"] in _values_of(FIXTURE, shown) for draft in drafts)
    assert [d["name"] for d in replay_run(read_run(FIXTURE))["report"]["detection_drafts"]] == [
        digest(d["name_text"]) for d in drafts
    ]
    answers = [str(row.get("answer_text") or "") for row in shown["report"]["indicators"].values()]
    assert any("https://cdn.stage-two-host.net/live/" in answer for answer in answers)
    # And a finding's path quotes a judge's label that names its object.
    paths = [str(flag.get("path_text") or "") for flag in shown["judge"]["flags"]]
    assert any("attack-pattern--fake" in path for path in paths)


def test_a_subject_and_its_path_carry_no_value() -> None:
    from scripts.replay.compare import _failure_named
    from scripts.replay.rules import _flag

    from malspark.pipeline.validation import Violation

    finding = Violation(
        code="stix.indicator_unattributed_flow",
        message="the indicator names host.example.net",
        path="objects.domain:host.example.net",
        subject="domain:host.example.net",
    )
    quiet = _flag(finding, show_text=False)
    assert quiet["subject"] == f"domain:{digest('host.example.net')}"
    assert quiet["path"] == f"objects.domain:{digest('host.example.net')}"
    assert "host.example.net" not in json.dumps(quiet)
    shown = _flag(finding, show_text=True)
    assert shown["subject"] == quiet["subject"]
    assert shown["subject_text"] == "domain:host.example.net"
    assert shown["path_text"] == "objects.domain:host.example.net"

    # The judge's own label for an object, whatever the subject's case.
    family = Violation(
        code="stix.is_family_missing",
        message="m",
        path="objects[0] 'malware--some-family'",
        subject="Some-Family",
    )
    named = _flag(family, show_text=False)
    assert named["path"] == f"objects[0] 'malware--{digest('some-family')}'"
    assert "some-family" not in json.dumps(named).lower()
    plain = _flag(
        Violation(code="c", message="m", path="objects[3] 'indicator--1'"), show_text=False
    )
    assert plain["path"] == "objects[3] 'indicator--1'"

    # An id stays as it is; a value does not pass for its shape.
    for kept in ("T1055.001", "t1055", "ev_0003"):
        assert value_free_subject(kept) == kept
    from malspark.analysis.sandbox_sections import is_item_id

    assert value_free_subject("proc:84", is_item_id) == "proc:84"
    assert value_free_subject("port:4444", is_item_id) == f"port:{digest('4444')}"
    assert value_free_subject("0123456789ab") == f"sha256:{digest('0123456789ab')}"
    assert value_free_subject("domain:0123456789ab") == f"domain:{digest('0123456789ab')}"
    assert value_free_subject("Some Family") == f"sha256:{digest('Some Family')}"

    # A harness that crashed is named by its failure's class and place, never its message.
    said = b"Traceback\nreplay failed: KeyError at rules.py:12 (_judge)\n"
    assert _failure_named(said, 2) == "replay failed: KeyError at rules.py:12 (_judge)"
    older = b"replay failed: ValueError: host.example.net is not a host\n"
    assert _failure_named(older, 2) == "replay failed: ValueError"
    assert _failure_named(b"Segmentation fault\n", 139) == "exit status 139"


def test_a_cell_keeps_its_key_value_pairs_and_merged_rows_carry_the_key_order() -> None:
    from scripts.replay.rules import _row_key, _Run, _section_content

    assert _row_key(["malicious=52, suspicious=0"]) != _row_key(["malicious=0, suspicious=52"])
    assert _row_key(["outer=b=2, c=3"]) == _row_key(["outer=c=3, b=2"])
    assert _row_key(["a=1, b=2, c=3\u2026"]) != _row_key(["c=3, a=1, b=2\u2026"])
    assert _row_key(["a=1, b\u2026"], loose=True) == _row_key(["c=3, a\u2026"], loose=True)

    run = _Run(stored=read_run(FIXTURE), show_text=False)
    run.name("ledger", replay_rules._NO_KEY_ORDER)
    cut_one, cut_two = ["data", "a=1, b=2, c\u2026"], ["data", "c=3, a=1, b\u2026"]
    stored = {"key": "tool_x", "rows": [cut_one, ["k", "v"], cut_two]}
    replayed = {"key": "tool_x", "rows": [cut_one, ["k", "v"]]}
    rows = _section_content(run, "tool_x", stored, replayed)
    assert rows == [
        {
            "section": "tool_x",
            "field": "rows",
            "merged": 1,
            "cause": {"part": "ledger", "why": replay_rules._NO_KEY_ORDER},
        }
    ]
    swapped = {"key": "tool_x", "rows": [["malicious=0, suspicious=52"]]}
    differ = _section_content(
        run, "tool_x", {"key": "tool_x", "rows": [["malicious=52, suspicious=0"]]}, swapped
    )
    assert [r.get("row") for r in differ] == [0, 0] and all("cause" not in r for r in differ)


def test_the_replay_reaches_no_network_and_puts_every_door_back() -> None:
    from malspark.memory import attck_loader

    connect, lookup, by_name = socket.create_connection, socket.getaddrinfo, socket.gethostbyname
    cache = attck_loader.ATTCK_CACHE_DIR
    with replay_environment({}) as env:
        with pytest.raises(ReplayRefused):
            socket.create_connection(("127.0.0.1", 9))
        with pytest.raises(ReplayRefused):
            socket.getaddrinfo("localhost", 80)
        with pytest.raises(ReplayRefused):
            socket.gethostbyname("localhost")
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram,
            pytest.raises(ReplayRefused),
        ):
            datagram.sendto(b"x", ("127.0.0.1", 9))
        assert attck_loader.ATTCK_CACHE_DIR == env.cache_dir
        assert env.cache_dir != Path.home() / ".cache" / "malspark" / "attck"
    assert socket.create_connection is connect
    assert socket.getaddrinfo is lookup
    assert socket.gethostbyname is by_name
    assert "sendto" not in vars(socket.socket)
    assert attck_loader.ATTCK_CACHE_DIR == cache


def test_the_event_loop_s_socket_pair_is_made_where_the_system_has_no_native_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows makes the pair by a loopback connection; only that one is let through."""
    monkeypatch.setattr(socket, "socketpair", socket._fallback_socketpair)  # type: ignore[attr-defined]

    async def answered() -> str:
        return "ran"

    with replay_environment({}) as env:
        first, second = socket.socketpair()
        with first, second:
            first.sendall(b"wake")
            assert second.recv(4) == b"wake"
        assert asyncio.run(answered()) == "ran"
        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream,
            pytest.raises(ReplayRefused),
        ):
            stream.connect(("127.0.0.1", 9))
    assert socket.socketpair is socket._fallback_socketpair  # type: ignore[attr-defined]
    assert "connect" not in vars(socket.socket)
    assert not [door for door in env.missing if door.startswith("socket.")]


def test_a_connection_through_the_event_loop_is_refused() -> None:
    """An IP literal needs no lookup; Windows' proactor connects past the socket's methods."""

    async def connect() -> None:
        await asyncio.open_connection("127.0.0.1", 9)

    async def datagram() -> None:
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=("127.0.0.1", 9))

    with replay_environment({}):
        with pytest.raises(ReplayRefused):
            asyncio.run(connect())
        with pytest.raises(ReplayRefused):
            asyncio.run(datagram())


def test_the_completion_port_s_doors_are_closed_where_there_is_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The proactor's own connect, sendto and connect_pipe, put back after the block."""
    import types

    class IocpProactor:
        def connect(self, *_args: Any) -> None: ...
        def sendto(self, *_args: Any) -> None: ...
        def connect_pipe(self, *_args: Any) -> None: ...

    held = dict(vars(IocpProactor))
    module = types.ModuleType("asyncio.windows_events")
    module.IocpProactor = IocpProactor  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "asyncio.windows_events", module)
    monkeypatch.setattr(asyncio, "windows_events", module, raising=False)
    with replay_environment({}) as env:
        for name in ("connect", "sendto", "connect_pipe"):
            with pytest.raises(ReplayRefused):
                getattr(IocpProactor(), name)(("127.0.0.1", 9))
    for name in ("connect", "sendto", "connect_pipe"):
        assert vars(IocpProactor)[name] is held[name]
    assert not [door for door in env.missing if door.startswith("IocpProactor.")]


def test_a_door_the_host_s_socket_module_lacks_is_not_a_door_the_tree_lacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows' sockets have no sendmsg: nothing to close, and nothing the tree is missing."""

    class HostSocket:
        def connect(self, *_args: Any) -> None: ...
        def connect_ex(self, *_args: Any) -> int: ...
        def sendto(self, *_args: Any) -> int: ...

    sendto = vars(HostSocket)["sendto"]
    monkeypatch.setattr(socket, "socket", HostSocket)
    with replay_environment({}) as env, pytest.raises(ReplayRefused):
        HostSocket().sendto(b"x", ("127.0.0.1", 9))
    assert not [door for door in env.missing if door.startswith("socket.")]
    assert vars(HostSocket)["sendto"] is sendto


def test_two_records_are_told_apart_by_what_moved(record: dict[str, Any]) -> None:
    assert not differs(diff_records(record, copy.deepcopy(record)))

    moved = copy.deepcopy(record)
    answer = next(a for a in moved["analysts"]["static"]["answers"] if a["replayed"])
    answer["flags"] = [f for f in answer["flags"] if f["code"] != "attck.unknown_id"]
    moved["judge"]["flags"].append({"code": "stix.malformed_hash", "path": "objects[9]"})
    moved["report"]["techniques"]["T1105"] = {"published": False, "why": "a reason"}
    moved["report"]["severity"] = "High"
    diff = diff_records(record, moved)

    assert differs(diff) and not has_errors(diff) and not is_partial(diff)
    assert _without_words(diff["codes_lost"]) == [
        {
            "part": "analyst answer",
            "owner": "static round 1",
            "path": "static.claims[2]",
            "subject": "T9999",
            "code": "attck.unknown_id",
            "fields": {"entries": ["ev_0002"]},
            "count": 1,
            "in_a": 1,
            "in_b": 0,
        }
    ]
    assert diff["codes_gained"] == [
        {
            "part": "judge",
            "path": "objects[9]",
            "code": "stix.malformed_hash",
            "count": 1,
            "in_a": 0,
            "in_b": 1,
        }
    ]
    assert diff["report"]["severity"] == {"a": "Medium", "b": "High"}
    assert diff["report"]["techniques"]["changed"]["T1105"]["b"]["published"] is False
    text = render_diff(diff, "A-ref", "B-ref")
    assert "attck.unknown_id" in text and "stix.malformed_hash" in text


def test_the_judge_s_drops_and_each_tree_s_refusals_are_compared(record: dict[str, Any]) -> None:
    moved = copy.deepcopy(record)
    moved["judge"]["indicators_dropped"] = 0
    moved["environment"]["settings_refused"] = {
        "validation.weak_alignment": "refused by this tree's settings model"
    }
    moved["environment"]["doors_this_tree_lacks"] = ["attck_index.load_all_domains"]
    diff = diff_records(record, moved)
    assert diff["judge"] == {"indicators_dropped": {"a": 1, "b": 0}}
    assert diff["environment"] == {
        "settings_refused": {
            "only_b": {"validation.weak_alignment": "refused by this tree's settings model"}
        },
        "doors_this_tree_lacks": {"only_a": [], "only_b": ["attck_index.load_all_domains"]},
    }
    assert differs(diff) and not is_partial(diff)
    text = render_diff(diff, "A-ref", "B-ref")
    assert "indicators_dropped" in text and "validation.weak_alignment" in text


def _older(record: dict[str, Any]) -> dict[str, Any]:
    """The record as a schema-1 harness wrote it: no schema, no notes, no degradation."""
    older = copy.deepcopy(record)
    del older["schema"]
    older["format"] = 1
    for agent in older["analysts"].values():
        for key in ("not_valid", "kept_after_absence_question"):
            agent.get("in_force", {}).pop(key, None)
    del older["report"]["degraded"]
    del older["report"]["degradation"]
    del older["against_stored"]
    return older


def test_two_schemas_make_a_partial_comparison(record: dict[str, Any]) -> None:
    diff = diff_records(_older(record), record)
    assert diff["schema"] == {"a": 1, "b": REPLAY_SCHEMA}
    assert diff["not_compared"] == {
        "b": [
            "claims in force: kept_after_absence_question",
            "claims in force: not_valid",
            "findings: the fields beside code, path and subject",
            "findings: words",
            "report.degradation",
            "report.degraded",
        ],
        "differently": ["report.techniques: why"],
    }
    assert is_partial(diff) and not differs(diff)
    text = render_diff(diff, "A-ref", "B-ref")
    assert "PARTIAL COMPARISON" in text
    assert "not compared, defined only under B (B-ref): claims in force" in text
    assert "no difference" not in text


def test_a_partial_comparison_ends_with_status_2(
    record: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    older = _older(record)
    monkeypatch.setattr(compare, "materialise", lambda _repo, _ref, into: into)
    monkeypatch.setattr(
        compare,
        "replay_under",
        lambda _tree, _runs, out, **_kwargs: [older if out.name.startswith("a-") else record],
    )
    argv = [str(FIXTURE), "--compare", "A-ref", "B-ref", "--repo", str(tmp_path)]
    assert replay_cli.main([*argv, "--work", str(tmp_path / "work")]) == 2
    printed = capsys.readouterr().out
    assert "PARTIAL COMPARISON" in printed and "no difference" not in printed


def test_a_section_one_tree_alone_composes_is_not_compared(
    record: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lacking = copy.deepcopy(record)
    sections = lacking["composer"]["sections"]
    quiet_section = next(name for name, entry in sections.items() if not entry["flags"])
    del sections[quiet_section]
    diff = diff_records(record, lacking)
    assert diff["not_compared"] == {"a": [f"composer section: {quiet_section}"]}
    assert is_partial(diff) and not differs(diff)

    moved = copy.deepcopy(record)
    moved["tool"]["calls"] += 1
    moved["composer"]["not_written"] = moved["composer"]["not_written"][1:]
    moved["environment"]["settings_from_run"] = []
    diff = diff_records(record, moved)
    assert diff["tool"] == {
        "calls": {"a": record["tool"]["calls"], "b": record["tool"]["calls"] + 1}
    }
    assert diff["composer"]["not_written"]["only_a"] == record["composer"]["not_written"][:1]
    assert diff["environment"]["settings_from_run"]["only_b"] == []

    monkeypatch.setattr(compare, "materialise", lambda _repo, _ref, into: into)
    monkeypatch.setattr(
        compare,
        "replay_under",
        lambda _tree, _runs, out, **_kwargs: [record if out.name.startswith("a-") else lacking],
    )
    argv = [str(FIXTURE), "--compare", "A-ref", "B-ref", "--repo", str(tmp_path)]
    assert replay_cli.main([*argv, "--work", str(tmp_path / "work")]) == 2
    printed = capsys.readouterr().out
    assert "PARTIAL COMPARISON" in printed and quiet_section in printed


def _flagged_answer(n: int) -> tuple[list[Any], Any]:
    """An answer of ``n`` claims, each the subject of one finding."""
    from malspark.pipeline.validation import Violation
    from malspark.schemas.isr_models import AgentISR, ClaimEvidence

    claims = [
        ClaimEvidence(claim=f"claim {i}", evidence_ref=f"[ev_{i + 1:04d}]", confidence=0.5)
        for i in range(n)
    ]
    found = [
        Violation(code="isr.empty_evidence", message="m", path=f"static.claims[{i}]")
        for i in range(n)
    ]
    return found, AgentISR(agent_id="static", domain="static", claims=claims)


def _record_of(n: int, code: str) -> dict[str, Any]:
    flags = [{"code": code, "path": f"static.claims[{i}]"} for i in range(n)]
    return {
        "schema": REPLAY_SCHEMA,
        "run": "hostile",
        "analysts": {"static": {"answers": [{"answer": "round 1", "flags": flags}]}},
        "report": {
            "techniques": {f"T{1000 + i % 9000}.{i:03d}": {"published": True} for i in range(n)}
        },
    }


def _summaries_of(agents: int) -> StoredRun:
    """A stored run of ``agents`` analysts, each with ten messages the replay names and skips."""
    transcript = [
        {
            "speaker": f"agent{a}",
            "role": "analyst" if m == 0 else "reviser",
            "round": m,
            "report": "CLAIM 1: x" if m == 0 else "",
            "claims": [{"claim": "x"}] if m == 0 else [],
        }
        for a in range(agents)
        for m in range(10)
    ]
    reports = {f"agent{a}": "" for a in range(agents)}
    return StoredRun(
        name="hostile",
        root=FIXTURE,
        byjob={"agent_reports": reports, "transcript": transcript},
    )


def _unshown_run(n: int) -> Any:
    """A run whose summary records ``n`` findings the judge was never shown."""
    from scripts.replay.rules import _Run

    rows = [
        {"agent": "judge", "code": "stix.x", "subject": f"s{i}", "message": "m", "asked": "false"}
        for i in range(n)
    ]
    stored = StoredRun(
        name="hostile", root=FIXTURE, run_summary={"validation": {"unresolved": rows}}
    )
    return _Run(stored=stored, show_text=False)


def test_the_replay_s_own_bookkeeping_stays_linear() -> None:
    from scripts.replay.rules import _analysts, _claim_flags, _Run, _shown_to

    from malspark.pipeline.validation import Violation

    # Ten times the input in about ten times the time; a step that walked the
    # whole of it for each of its items would be a hundred.
    small, large = _flagged_answer(5_000), _flagged_answer(50_000)
    _claim_flags(*small, show_text=False)
    assert_ratio(
        lambda: _claim_flags(*small, show_text=True),
        lambda: _claim_flags(*large, show_text=True),
        20,
        what="50,000 flagged claims",
    )

    pairs = {n: (_record_of(n, "a.code"), _record_of(n, "b.code")) for n in (2_000, 20_000)}
    # Each pair is compared three times so the small run is measurable while
    # the large records stay at twenty thousand flags.
    assert_ratio(
        lambda: [diff_records(*pairs[2_000]) for _ in range(3)],
        lambda: [diff_records(*pairs[20_000]) for _ in range(3)],
        20,
        what="20,000 flags of a record",
    )
    assert len(diff_records(*pairs[20_000])["codes_gained"]) == 20_000

    def _name(n: int) -> None:
        # A part is named in a fraction of a microsecond: a run names its
        # parts thirty times over so the small run is measurable.
        for _ in range(30):
            run = _Run(stored=StoredRun(name="hostile", root=FIXTURE), show_text=False)
            for i in range(n):
                run.name("part", f"why {i}")
            assert len(run.not_replayed) == n

    assert_ratio(lambda: _name(2_000), lambda: _name(20_000), 20, what="20,000 named parts")

    stores = {n: _summaries_of(n) for n in (200, 2_000)}

    def _read_analysts(n: int) -> None:
        # Each store is read fifteen times so the small run is measurable
        # without holding hundreds of thousands of messages.
        for _ in range(15):
            _analysts(_Run(stored=stores[n], show_text=False))

    assert_ratio(
        lambda: _read_analysts(200), lambda: _read_analysts(2_000), 20, what="2,000 analysts"
    )
    assert len(_analysts(_Run(stored=stores[2_000], show_text=False))) == 2_000

    found = {
        n: [
            Violation(code="stix.x", message="m", subject=f"s{i}" if i % 2 else f"t{i}")
            for i in range(n)
        ]
        for n in (5_000, 50_000)
    }
    assert_ratio(
        lambda: _shown_to(_unshown_run(5_000), "judge", found[5_000]),
        lambda: _shown_to(_unshown_run(50_000), "judge", found[50_000]),
        20,
        what="50,000 unshown findings",
    )
    assert len(_shown_to(_unshown_run(50_000), "judge", found[50_000])) == 25_000


def test_stored_degradation_reasons_are_decided_again_or_named(tmp_path: Path) -> None:
    from malspark.agents.judge_agent import VERDICT_FALLBACK_REASON
    from malspark.pipeline.outcome import unrecognised_verdict_reason

    unreadable = unrecognised_verdict_reason(
        SimpleNamespace(x_malspark_assessment=SimpleNamespace(verdict="Maybe"))
    )

    def _decided(report: dict[str, Any]) -> None:
        report["degradation_reasons"] = [VERDICT_FALLBACK_REASON, unreadable]
        report["degraded_mode"] = True

    # Neither reason is one these rules give over the tiny run: both go, and
    # the run is no longer degraded.
    decided = replay_run(read_run(_copy_run(tmp_path / "decided", report_json=_decided)))
    assert decided["report"]["degraded"] is False
    assert decided["report"]["degradation"] == {
        "decided": 0,
        "stored_decided_again": 2,
        "kept_as_stored": 0,
    }

    def _kept(report: dict[str, Any]) -> None:
        report["degradation_reasons"] = ["analyst failures: network"]
        report["degraded_mode"] = True

    kept = replay_run(read_run(_copy_run(tmp_path / "kept", report_json=_kept)))
    assert kept["report"]["degraded"] is True
    assert kept["report"]["degradation"]["kept_as_stored"] == 1
    assert any(
        row["part"] == "report" and row["why"].startswith("1 stored degradation reason(s) are kept")
        for row in kept["not_replayed"]
    )


def test_a_stored_operator_choice_is_moved_to_the_choices_and_named(tmp_path: Path) -> None:
    """T-338: a run stored with a withheld tool among its reasons replays with it listed apart."""
    from malspark.providers.sample_open import UNCOVERED, withheld_unpinned

    withheld = withheld_unpinned(
        "remote http://localhost:8089 (backend 1)", "open_project", UNCOVERED
    )

    def _stored(report: dict[str, Any]) -> None:
        report["degradation_reasons"] = [withheld]
        report["degraded_mode"] = True

    moved = replay_run(read_run(_copy_run(tmp_path / "moved", report_json=_stored)))
    assert moved["report"]["degraded"] is False
    assert moved["report"]["degradation"] == {
        "decided": 0,
        "stored_decided_again": 0,
        "kept_as_stored": 0,
        "moved_to_choices": 1,
    }
    assert any(
        row["part"] == "report"
        and row["why"].startswith("1 stored degradation reason(s) are the operator's choice")
        for row in moved["not_replayed"]
    )


def test_a_finding_the_analyst_was_not_shown_leaves_no_absence_note(tmp_path: Path) -> None:
    def _unshown(summary: dict[str, Any]) -> None:
        summary["validation"] = {
            "unresolved": [
                {
                    "agent": "static",
                    "code": "attck.absence_claim",
                    "subject": "T1055",
                    "message": "an absence claim never put to the analyst",
                    "asked": "false",
                }
            ]
        }

    replayed = replay_run(read_run(_copy_run(tmp_path, run_summary_json=_unshown)))
    in_force = replayed["analysts"]["static"]["in_force"]
    assert in_force["kept_after_absence_question"] == []
    absence = next(f for f in in_force["flags"] if f["code"] == "attck.absence_claim")
    assert absence["asked"] is False
    describe = next(f for f in in_force["flags"] if f["code"] == "attck.claim_does_not_describe")
    assert "asked" not in describe


def test_the_analysts_are_taken_in_the_order_the_run_held_them(tmp_path: Path) -> None:
    def _held(summary: dict[str, Any]) -> None:
        summary["agent_stats"] = [{"agent_id": "network"}, {"agent_id": "static"}]

    replayed = replay_run(read_run(_copy_run(tmp_path, run_summary_json=_held)))
    assert list(replayed["analysts"]) == ["network", "static"]
    assert not [row for row in replayed["not_replayed"] if "agent_stats" in row["why"]]


def test_the_record_says_what_differs_from_the_stored_report(
    record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    block = record["against_stored"]
    assert block["compared"] is True
    assert block["not_compared"] == [
        "severity",
        "confidence",
        "category",
        "techniques",
        "indicators",
        "export",
    ]
    assert [row["section"] for row in block["sections"]["only_replayed"]] == [
        "identity",
        "tool_pe_info",
        "tool_strings",
        "tool_pcap_summary",
        "tool_decode_string_blobs",
        "tool_decode_string_blobs_results",
    ]
    # The stored Findings table says T1055 was not published; these rules publish it.
    rows = block["sections"]["contents"]
    assert [(r["section"], r["field"], r["row"]) for r in rows] == [
        ("findings", "rows", 1),
        ("findings", "rows", 1),
    ]
    assert all("cause" not in r and "text" not in (r["stored"] or r["replayed"]) for r in rows)

    # The stored report as the rebuilt one, two sections swapped and one row
    # written in another order, and an export with the sandbox's processes.
    seen: dict[str, Any] = {}
    against = replay_rules._against_stored

    def _capture(run: Any, built: Any, values: Any) -> Any:
        seen["sections"] = [s.model_dump(mode="json") for s in built.report.sections]
        return against(run, built, values)

    monkeypatch.setattr(replay_rules, "_against_stored", _capture)
    replay_run(read_run(FIXTURE))
    sections = copy.deepcopy(seen["sections"])
    sections[1], sections[2] = sections[2], sections[1]
    table = next(s for s in sections if len(s.get("rows") or []) > 1)
    table["rows"] = list(reversed(table["rows"]))

    def _stored(report: dict[str, Any]) -> None:
        report["sections"] = sections
        report["dynamic"] = {"process_tree": [{"pid": 1}, {"pid": 2}]}
        report["stix_bundle_extended"] = {
            "objects": [
                {"type": "process", "id": "process--1"},
                {"type": "process", "id": "process--2"},
            ]
        }

    replayed = replay_run(read_run(_copy_run(tmp_path, report_json=_stored)))
    block = replayed["against_stored"]
    moved = [row["section"] for row in block["sections"]["moved"]]
    assert moved == [seen["sections"][2]["key"], seen["sections"][1]["key"]]
    reordered = [r for r in block["sections"]["contents"] if "reordered" in r]
    assert [(r["section"], r["field"]) for r in reordered] == [(table["key"], "rows")]
    assert reordered[0]["cause"]["part"] == "ledger"
    process = next(row for row in block["export"] if row["type"] == "process")
    assert (process["stored"], process["replayed"]) == (2, 0)
    assert process["cause"]["why"].startswith("the sandbox report is not in the stored record")
    text = render_record(replayed)
    assert "Against the stored report" in text and "export process objects: stored 2" in text


def test_a_job_read_from_the_database_is_written_in_the_stored_layout(tmp_path: Path) -> None:
    job_id = uuid.UUID("00000000-0000-4000-8000-000000000001")
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    assert jsonable({"id": job_id, "at": stamp, "seconds": Decimal("1.5")}) == {
        "id": str(job_id),
        "at": stamp.isoformat(),
        "seconds": 1.5,
    }
    job = with_sample(
        {"id": str(job_id), "sample_id": "s1"}, {"sha256": "0" * 64, "original_filename": "x.bin"}
    )
    assert (job["sample_sha256"], job["sample_filename"]) == ("0" * 64, "x.bin")
    gone = with_sample({"id": str(job_id)}, None)
    assert (gone["sample_sha256"], gone["sample_row"]) == (None, "absent")

    rows = JobRows(
        job=job,
        report={
            "id": "r1",
            "agent_reports": {"static": "CLAIM: x"},
            "run_summary": {"settings_snapshot": {}},
            "malware_report": {"verdict": "Benign"},
            "judge_stix_bundle": {"bundle": {"objects": []}, "as_written": True},
        },
        findings=[{"agent_name": "static", "claims": []}],
        transcript=[{"seq": 2, "speaker": "static"}, {"seq": 1, "speaker": "static"}],
        evidence=[{"entry_id": "ev_0002", "seq": 2}, {"entry_id": "ev_0001", "seq": 1}],
        events=[{"seq": 1, "type": "completed", "payload": {}}],
    )
    target = tmp_path / str(job_id)
    written, cleared = write_run(rows, target)
    assert cleared == []
    stored = read_run(written)
    assert [e["entry_id"] for e in stored.evidence] == ["ev_0001", "ev_0002"]
    assert stored.agent_reports == {"static": "CLAIM: x"}
    assert [m["seq"] for m in stored.transcript] == [1, 2]
    assert stored.report == {"verdict": "Benign"}
    assert stored.judge == {"bundle": {"objects": []}, "as_written": True}
    assert stored.job is not None and stored.job["sample_sha256"] == "0" * 64

    # A second export into a directory that holds a stored run is refused and
    # writes nothing; with overwrite, a job with no judge answer clears the
    # first one's, and leaves a file of the operator's own alone.
    (target / "notes.txt").write_text("mine", encoding="utf-8")
    rows.report = {**(rows.report or {}), "judge_stix_bundle": None}
    before = digests(target)
    with pytest.raises(StoredRunExists, match="overwrite"):
        write_run(rows, target)
    assert digests(target) == before
    _written, cleared = write_run(rows, target, overwrite=True)
    assert "stix-judge.json" in cleared
    assert not (target / "stix-judge.json").exists()
    assert (target / "notes.txt").read_text(encoding="utf-8") == "mine"


def test_a_job_export_over_a_stored_run_is_refused_before_the_database_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts.replay import database

    job_id = "00000000-0000-4000-8000-000000000002"
    held = tmp_path / job_id
    held.mkdir()
    (held / "evidence.json").write_text('{"items": []}', encoding="utf-8")
    before = digests(held)

    async def never(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("the database was read")

    monkeypatch.setattr(database, "read_jobs", never)
    with pytest.raises(StoredRunExists, match="overwrite"):
        export_jobs([job_id], tmp_path, database_url="postgresql+asyncpg://x/y")
    with pytest.raises(SystemExit) as ended:
        replay_cli.main(["--job", job_id, "--job-dir", str(tmp_path), "--quiet"])
    assert ended.value.code == 2
    assert "--overwrite" in capsys.readouterr().err
    assert digests(held) == before


@pytest.mark.posix
def test_a_dangling_link_of_the_layout_counts_as_a_stored_run(tmp_path: Path) -> None:
    target = tmp_path / "run"
    target.mkdir()
    (target / "report.json").symlink_to(tmp_path / "gone.json")
    rows = JobRows(job={"id": "j"}, report=None, findings=[], transcript=[], evidence=[],
                   events=[])  # fmt: skip
    with pytest.raises(StoredRunExists, match="report.json"):
        write_run(rows, target)
    assert (target / "report.json").is_symlink()


def test_a_job_named_twice_is_exported_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.replay import database

    job_id = "00000000-0000-4000-8000-000000000003"
    asked: list[list[str]] = []

    async def read(ids: list[str], _url: str) -> list[JobRows]:
        asked.append(list(ids))
        return [JobRows(job={"id": i}, report=None, findings=[], transcript=[], evidence=[],
                        events=[]) for i in ids]  # fmt: skip

    monkeypatch.setattr(database, "read_jobs", read)
    written = export_jobs([job_id, job_id.upper()], tmp_path, database_url="postgresql://x/y")
    assert asked == [[job_id]]
    assert [path for path, _cleared in written] == [tmp_path / job_id]
