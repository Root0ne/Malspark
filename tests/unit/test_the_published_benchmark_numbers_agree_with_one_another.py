"""The benchmark's public numbers are one set of numbers.

The benchmark page holds the key, the per-group rows and the list of facts
beyond the key as data, and states the totals beside them; the README and the
docs home repeat the headline. A number changed in one place only must fail
here: the row counts of the arrays, the verdicts in them, the per-group rows,
the headline totals and the two pages that quote them have to agree.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "apps" / "docs" / "content" / "docs" / "benchmark" / "index.mdx"
README = ROOT / "README.md"
DOCS_HOME = ROOT / "apps" / "docs" / "content" / "docs" / "index.mdx"

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


def problems(page: str, readme: str, docs_home: str) -> list[str]:
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
    if audit["same"] + audit["partly"] + audit["screenshot"] + audit["none"] != run["beyondKey"]:
        found.append("the audit counts do not add up to run.beyondKey")
    if audit["noneFamily"] + audit["noneFile"] != audit["none"]:
        found.append("the unprinted facts do not split into family and file")
    out = re.search(r"export const outOfStrict = '([^']*)';", page)
    strict_drop = 1 if out and any(row[1] == out.group(1) for row in beyond) else 0
    if run["beyondKeyStrict"] != run["beyondKey"] - strict_drop:
        found.append(
            "run.beyondKeyStrict is not beyondKey less the fact outside the strict reading"
        )

    recovered = run["found"] + run["partlyBody"] + run["partlyDump"]
    row = re.search(
        r"\| \*\*(\d+) of (\d+)\*\* \((\d+) found, (\d+) partly\) "
        r"\| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|",
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
        if tuple(int(n) for n in row.groups()) != want:
            found.append(f"the README row says {row.groups()}, the page gives {want}")
    sentence = re.search(
        r"recovered (\d+) of (\d+) facts.*?stated\s+(\d+) verified", docs_home, re.S
    )
    if not sentence:
        found.append("the docs home has no benchmark sentence")
    elif tuple(int(n) for n in sentence.groups()) != (recovered, run["items"], run["beyondKey"]):
        gives = (recovered, run["items"], run["beyondKey"])
        found.append(f"the docs home says {sentence.groups()}, the page gives {gives}")
    return found


def _texts() -> tuple[str, str, str]:
    return (
        PAGE.read_text(encoding="utf-8"),
        README.read_text(encoding="utf-8"),
        DOCS_HOME.read_text(encoding="utf-8"),
    )


def test_the_published_benchmark_numbers_agree_with_one_another() -> None:
    assert problems(*_texts()) == []


@pytest.mark.parametrize(
    ("target", "old", "new"),
    [
        ("page", "  found: 55,", "  found: 54,"),
        ("page", "  items: 75,", "  items: 76,"),
        ("page", "  beyondKey: 53,", "  beyondKey: 54,"),
        ("page", "  beyondKeyStrict: 52,", "  beyondKeyStrict: 53,"),
        ("page", "  audit: { same: 4,", "  audit: { same: 5,"),
        (
            "page",
            "    ['K6', 'Command and control', 10, 8, 2, 0, 0, 0],",
            "    ['K6', 'Command and control', 10, 9, 1, 0, 0, 0],",
        ),
        ("page", "'Link to IcedID', 'partly',", "'Link to IcedID', 'found',"),
        ("readme", "**71 of 75** (55 found, 16 partly)", "**70 of 75** (54 found, 16 partly)"),
        ("readme", "| **53** |", "| **58** |"),
        ("docs", "recovered 71 of 75", "recovered 72 of 75"),
        ("docs", "stated 53 verified", "stated 54 verified"),
    ],
)
def test_a_number_changed_in_one_place_only_is_caught(target: str, old: str, new: str) -> None:
    page, readme, docs_home = _texts()
    texts = {"page": page, "readme": readme, "docs": docs_home}
    text = texts[target]
    assert old in text, old
    text = text.replace(old, new, 1)
    texts[target] = text
    assert problems(texts["page"], texts["readme"], texts["docs"]) != []
