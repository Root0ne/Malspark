"""The benchmark's public numbers are one set of numbers.

The benchmark page holds the key, the per-group rows and the list of facts
beyond the key as data, and states the totals beside them; the README, the docs
home and the known-answer gate's example repeat them. A number changed in one
place only must fail here: the row counts of the arrays, the verdicts in them,
the per-group rows, the lists of missed and partly facts, the examples of facts
beyond the key, the reading of each fact beyond the key against the eight
analyses, the headline totals, the cost and the pages that quote them have to
agree.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "apps" / "docs" / "content" / "docs" / "benchmark" / "index.mdx"
README = ROOT / "README.md"
DOCS_HOME = ROOT / "apps" / "docs" / "content" / "docs" / "index.mdx"
GATE = ROOT / "apps" / "docs" / "content" / "docs" / "known-answer-gate.mdx"

_TOKEN = re.compile(r"'((?:\\.|[^'\\])*)'|(-?\d+)")


def _row(line: str) -> list[str | int]:
    """One bracketed row: single-quoted strings (unescaped) and numbers."""
    return [
        re.sub(r"\\(.)", r"\1", m[0]) if m[1] == "" else int(m[1]) for m in _TOKEN.findall(line)
    ]


def _array_rows(text: str, name: str, indent: int) -> list[list[str | int]]:
    """The rows of ``export const <name> = [``, one bracketed row per line."""
    start = text.index(f"export const {name} = [\n")
    body = text[text.index("\n", start) + 1 :]
    body = body[: body.index("\n];")]
    return [_row(line) for line in body.splitlines() if line.startswith(" " * indent + "[")]


def _run_block(text: str) -> str:
    start = text.index("export const run = {")
    return text[start : text.index("\n};", start)]


def _run_numbers(text: str) -> dict[str, int]:
    return {m[0]: int(m[1]) for m in re.findall(r"^  (\w+): (\d+),$", _run_block(text), re.M)}


def _run_audit(text: str) -> dict[str, int]:
    line = re.search(r"^  audit: \{(.*)\},$", _run_block(text), re.M)
    assert line, "the run has no audit counts"
    return {k: int(v) for k, v in re.findall(r"(\w+): (\d+)", line.group(1))}


def _run_groups(text: str) -> list[list[str | int]]:
    block = _run_block(text)
    start = block.index("  groups: [\n")
    block = block[start : block.index("\n  ],", start)]
    return [_row(line) for line in block.splitlines() if line.startswith("    [")]


def _run_rows(text: str, name: str) -> list[list[str | int]]:
    """The bracketed rows of ``run.<name>``."""
    block = _run_block(text)
    start = block.index(f"  {name}: [\n")
    block = block[start : block.index("\n  ],", start)]
    return [_row(line) for line in block.splitlines() if line.startswith("    [")]


def _run_list(text: str, name: str) -> list[str]:
    """The single-quoted lines of ``run.<name>``, a list of sentences."""
    block = _run_block(text)
    start = block.index(f"  {name}: [\n")
    block = block[start : block.index("\n  ],", start)]
    return [line for line in block.splitlines() if line.startswith("    '")]


ORIGINS = {"core", "sharpened", "added", "completion"}
_EIGHT = {"in part": "partly", "none, family": "noneFamily", "none, this file": "noneFile"}
# The facts beyond the key that no analysis prints even in part; every other one
# is printed in part. Pinned by id, so two readings swapped are caught too.
_UNPRINTED = {
    ("A", "34"): "none, family",
    ("B", "30"): "none, family",
    ("B", "N9"): "none, family",
    ("B", "#39"): "none, family",
    ("B", "N1"): "none, family",
    ("B", "N20"): "none, family",
    ("A", "27"): "none, this file",
    ("B", "N8"): "none, this file",
    ("C", "1"): "none, this file",
    ("C", "26"): "none, this file",
    ("C", "51"): "none, this file",
    ("C", "N10"): "none, this file",
}


def _verdict_kind(verdict: str) -> str:
    """found, partlyBody, partlyDump, missed or wrong; ``found (…)`` counts as found."""
    if verdict.startswith("found"):
        return "found"
    return {
        "partly": "partlyBody",
        "partly, bundle": "partlyDump",
        "missed": "missed",
        "wrong": "wrong",
    }[verdict]


def problems(page: str, readme: str, docs_home: str, gate: str) -> list[str]:
    """Every place where the public numbers disagree; empty when they agree."""
    found: list[str] = []
    run = _run_numbers(page)
    key = _array_rows(page, "keyItems", 2)
    beyond = _array_rows(page, "beyondFacts", 2)
    groups = _run_groups(page)

    if len(key) != run["items"]:
        found.append(f"keyItems has {len(key)} rows, run.items says {run['items']}")
    counts = {name: 0 for name in ("found", "partlyBody", "partlyDump", "missed", "wrong")}
    for row in key:
        counts[_verdict_kind(str(row[3]))] += 1
    for name, count in counts.items():
        if count != run[name]:
            found.append(f"keyItems holds {count} {name}, run.{name} says {run[name]}")
    if len({(row[1], row[2]) for row in key}) != len(key):
        found.append("two keyItems rows share an id and a fact")
    if {str(row[6]) for row in key} - ORIGINS:
        found.append(f"keyItems names an origin outside {sorted(ORIGINS)}")
    missed = _run_list(page, "missedItems")
    partly = _run_list(page, "partlyItems")
    if len(missed) != run["missed"]:
        found.append("run.missedItems does not list every missed fact")
    if len(partly) != run["partlyBody"] + run["partlyDump"]:
        found.append("run.partlyItems does not list every partly fact")
    if len(set(missed)) != len(missed) or len(set(partly)) != len(partly):
        found.append("run.missedItems or run.partlyItems lists one fact twice")

    totals = [0] * 6
    for group in groups:
        rows = [row for row in key if row[0] == group[0]]
        want = [len(rows)] + [sum(_verdict_kind(str(r[3])) == n for r in rows) for n in counts]
        if list(group[2:]) != want:
            found.append(f"the {group[0]} row says {group[2:]}, keyItems gives {want}")
        totals = [a + b for a, b in zip(totals, group[2:], strict=True)]
    if totals != [
        run["items"],
        run["found"],
        run["partlyBody"],
        run["partlyDump"],
        run["missed"],
        run["wrong"],
    ]:
        found.append(f"the group rows add up to {totals}, not to the run's totals")
    if {row[0] for row in key} != {group[0] for group in groups}:
        found.append("keyItems and the group rows name different groups")

    if len(beyond) != run["beyondKey"]:
        found.append(f"beyondFacts has {len(beyond)} rows, run.beyondKey says {run['beyondKey']}")
    if len({(row[0], row[1]) for row in beyond}) != len(beyond):
        found.append("two beyondFacts rows share a class and a number")
    audit = _run_audit(page)
    if sum(n for k, n in audit.items() if k not in ("noneFamily", "noneFile")) != run["beyondKey"]:
        found.append("the audit counts do not add up to run.beyondKey")
    if audit["noneFamily"] + audit["noneFile"] != audit["none"]:
        found.append("the unprinted facts do not split into family and file")
    eight = {name: 0 for name in _EIGHT.values()}
    for row in beyond:
        if len(row) != 7 or row[6] not in _EIGHT:
            found.append(f"beyondFacts row {row[:2]} has no reading against the eight analyses")
            continue
        eight[_EIGHT[str(row[6])]] += 1
        if row[6] != _UNPRINTED.get((str(row[0]), str(row[1])), "in part"):
            found.append(f"beyondFacts row {row[:2]} reads {row[6]!r} against the eight analyses")
    for name, count in eight.items():
        if count != audit.get(name):
            found.append(
                f"beyondFacts reads {count} facts as {name}, run.audit says {audit.get(name)}"
            )
    out = re.search(r"export const outOfStrict = '([^']*)';", page)
    strict_drop = 1 if out and any(row[1] == out.group(1) for row in beyond) else 0
    entries = {(str(row[0]), str(row[1])): row[3] for row in beyond}
    examples = _run_rows(page, "beyondExamples")
    for example in examples:
        fact = (str(example[2]), str(example[3])) if len(example) == 4 else None
        if fact not in entries or (out and fact[1] == out.group(1)):
            found.append(f"the example {example[0]!r} is not a fact on the strict list")
        elif entries[fact] != example[1]:
            found.append(f"the example {example[0]!r} cites other entries than fact {fact}")
    if len({(str(e[2]), str(e[3])) for e in examples if len(e) == 4}) != len(examples):
        found.append("two examples name the same fact beyond the key")
    if run["beyondKeyStrict"] != run["beyondKey"] - strict_drop:
        found.append(
            "run.beyondKeyStrict is not beyondKey less the fact outside the strict reading"
        )

    recovered = run["found"] + run["partlyBody"] + run["partlyDump"]
    usd = re.search(r"^  usd: '([\d.]+)',$", _run_block(page), re.M)
    cost = (usd.group(1) if usd else None, run["calls"], (run["seconds"] + 30) // 60)
    row = re.search(
        r"\| \*\*(\d+) of (\d+)\*\* \((\d+) found, (\d+) partly\) "
        r"\| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \| "
        r"\*\*([\d.]+) USD\*\* \((\d+) model calls, (\d+) minutes\) \|",
        readme,
    )
    if not row:
        found.append("the README has no benchmark row")
    else:
        want = (
            recovered,
            run["items"],
            run["found"],
            run["partlyBody"] + run["partlyDump"],
            run["wrong"],
            run["beyondKey"],
        )
        if tuple(int(n) for n in row.groups()[:6]) != want:
            found.append(f"the README row says {row.groups()[:6]}, the page gives {want}")
        said = (row.group(7), int(row.group(8)), int(row.group(9)))
        if said != cost:
            found.append(f"the README gives the cost as {said}, the page gives {cost}")
    sentence = re.search(
        r"recovered (\d+) of (\d+) facts.*?got (none|\d+) wrong.*?(\d+) verified",
        docs_home,
        re.S,
    )
    gives = (recovered, run["items"], run["wrong"], run["beyondKey"])
    if not sentence:
        found.append("the docs home has no benchmark sentence")
    elif tuple(0 if n == "none" else int(n) for n in sentence.groups()) != gives:
        found.append(f"the docs home says {sentence.groups()}, the page gives {gives}")
    line = re.search(
        r"(\d+) found / (\d+) partly \(body\) /\s*(\d+) partly \(dump\) / "
        r"(\d+) missed / (\d+) wrong; credited (\d+) of (\d+)",
        gate,
    )
    gives = (
        run["found"],
        run["partlyBody"],
        run["partlyDump"],
        run["missed"],
        run["wrong"],
        recovered,
        run["items"],
    )
    if not line:
        found.append("the known-answer gate has no example totals line")
    elif tuple(int(n) for n in line.groups()) != gives:
        found.append(
            f"the known-answer gate's example says {line.groups()}, the page gives {gives}"
        )
    return found


def _texts() -> tuple[str, str, str, str]:
    return (
        PAGE.read_text(encoding="utf-8"),
        README.read_text(encoding="utf-8"),
        DOCS_HOME.read_text(encoding="utf-8"),
        GATE.read_text(encoding="utf-8"),
    )


def test_the_published_benchmark_numbers_agree_with_one_another() -> None:
    assert problems(*_texts()) == []


@pytest.mark.parametrize(
    ("target", "old", "new"),
    [
        ("page", "  found: 55,", "  found: 54,"),
        ("page", "  items: 88,", "  items: 89,"),
        ("page", "  partlyBody: 23,", "  partlyBody: 22,"),
        ("page", "  beyondKey: 38,", "  beyondKey: 39,"),
        ("page", "  beyondKeyStrict: 37,", "  beyondKeyStrict: 38,"),
        ("page", "  audit: { partly: 26,", "  audit: { partly: 27,"),
        ("page", "none: 12, noneFamily: 6,", "none: 12, noneFamily: 7,"),
        (
            "page",
            "    ['K6', 'Command and control', 10, 4, 6, 0, 0, 0],",
            "    ['K6', 'Command and control', 10, 5, 5, 0, 0, 0],",
        ),
        ("page", "'Link to IcedID', 'partly',", "'Link to IcedID', 'found',"),
        ("page", "'completion'],", "'extension'],"),
        ("page", "    'K1: the family’s other names", "    // 'K1: the family’s other names"),
        ("page", "    'K9: update_data.dat is named", "    // 'K9: update_data.dat is named"),
        ("page", "'none, family'],", "'in part'],"),
        ("readme", "**83 of 88** (55 found, 28 partly)", "**82 of 88** (55 found, 27 partly)"),
        ("readme", "| **38** |", "| **37** |"),
        ("docs", "recovered 83 of 88", "recovered 84 of 88"),
        ("docs", "stated 38 verified", "stated 37 verified"),
        ("docs", "got none wrong", "got 1 wrong"),
        ("readme", "**8.24 USD**", "**9.24 USD**"),
        ("readme", "(129 model calls,", "(130 model calls,"),
        ("readme", "calls, 84 minutes)", "calls, 83 minutes)"),
        ("gate", "`55 found / 23 partly (body) /", "`54 found / 23 partly (body) /"),
        ("gate", "credited 83 of 88`", "credited 83 of 89`"),
        # An example that is no longer a fact beyond the key: K1.6 now holds it.
        (
            "page",
            "    ['The VirusTotal score at analysis time, 56 of 75', 'ev_0018', 'C', '26'],",
            "    ['The export directory’s own name, UpdaterTag.dll', 'ev_0004', 'C', '26'],",
        ),
        # An example of the fact outside the strict reading.
        ("page", "'ev_0018', 'C', '26'],", "'ev_0069', 'B', '10'],"),
        # Two readings against the eight analyses swapped; the counts stay equal.
        (
            "page",
            "'process-tree detection', 'none, this file'],\n"
            "  ['A', '34', 'First beacon after 1800 × 100 ms ≈ 180 s', 'ev_0067', "
            "'§4 step 9, §6.1', 'sandbox timeout, hunting window', 'none, family'],",
            "'process-tree detection', 'none, family'],\n"
            "  ['A', '34', 'First beacon after 1800 × 100 ms ≈ 180 s', 'ev_0067', "
            "'§4 step 9, §6.1', 'sandbox timeout, hunting window', 'none, this file'],",
        ),
        # A missed item replaced by a second copy of another.
        (
            "page",
            "    'K10: file and directory discovery (T1083). The desktop listing of command 2 is "
            "described, but the technique is not mapped.',",
            "    'K10: exfiltration over the C2 channel (T1041). It is not mapped.',",
        ),
        (
            "page",
            "    'K9: update_data.dat is named with its role, but without its directory.',",
            "    'K1: the file is named as x86-64, but the architecture check is not in the "
            "report body.',",
        ),
    ],
)
def test_a_number_changed_in_one_place_only_is_caught(target: str, old: str, new: str) -> None:
    page, readme, docs_home, gate = _texts()
    texts = {"page": page, "readme": readme, "docs": docs_home, "gate": gate}
    text = texts[target]
    assert old in text, old
    text = text.replace(old, new, 1)
    texts[target] = text
    assert problems(texts["page"], texts["readme"], texts["docs"], texts["gate"]) != []
