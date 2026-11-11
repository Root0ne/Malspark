"""The benchmark's public numbers are one set of numbers.

The benchmark page holds the key, the per-group rows and the list of facts
beyond the key as data, and states the totals beside them; the README, the docs
home and the known-answer gate's example repeat them. A number changed in one
place only must fail here: the row counts of the arrays, the verdicts in them,
the per-group rows, the lists of missed and partly facts, the examples of facts
beyond the key and their wording, the items that entered through the check of the
run's facts, the reading of each fact beyond the key against the eight
analyses, the headline totals, the cost and the pages that quote them have to
agree. The model and effort the page states for each agent are the ones the
reference configuration it links (``all-tools-reference-run.json``) sets.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "apps" / "docs" / "content" / "docs" / "benchmark" / "index.mdx"
README = ROOT / "README.md"
DOCS_HOME = ROOT / "apps" / "docs" / "content" / "docs" / "index.mdx"
EVIDENCE = ROOT / "apps" / "docs" / "public" / "assets" / "benchmark" / "evidence.json"
GATE = ROOT / "apps" / "docs" / "content" / "docs" / "known-answer-gate.mdx"
REFERENCE = ROOT / "docs" / "examples" / "profiles" / "all-tools-reference-run.json"
REFERENCE_LINK = "/examples/profiles/all-tools-reference-run.json"

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


def _run_text(text: str, name: str) -> str:
    """The single-quoted value of ``run.<name>``."""
    line = re.search(rf"^  {name}: '((?:\\.|[^'\\])*)',$", _run_block(text), re.M)
    assert line, f"the run has no {name}"
    return re.sub(r"\\(.)", r"\1", line.group(1))


# Who each noun of ``run.effort`` names: the agents of the team's stages of a
# kind, or a role entry of ``llm.agents`` no stage names.
_EFFORT_NOUNS = {
    "analysts": ("stage", "analysis"),
    "judge": ("stage", "verdict"),
    "reporter": ("stage", "report"),
    "mediator": ("entry", "mediator"),
    "summariser": ("entry", "summarizer"),
}


def stated_models(page: str, team: dict[str, list[str]]) -> dict[str, tuple[str, str | None]]:
    """``{agent: (model id, effort)}`` as ``run.model`` and ``run.effort`` state them.

    ``team`` maps a stage kind to the agents the team's stages of that kind
    name. The model's id is its name in lower case with spaces and dots as
    hyphens (Claude Haiku 5.5 is ``claude-haiku-5-5``); ``run.effort`` is
    ``<level> for <nouns>`` clauses, one per level, separated by ``;``.
    """
    model = re.sub(r"[ .]+", "-", _run_text(page, "model").strip().lower())
    out: dict[str, tuple[str, str | None]] = {}
    for clause in _run_text(page, "effort").split(";"):
        level, _, nouns = clause.strip().partition(" for ")
        for noun in re.split(r",\s*|\s+and\s+", nouns):
            kind, name = _EFFORT_NOUNS[noun.strip().removeprefix("the ")]
            for agent in team.get(name, []) if kind == "stage" else [name]:
                out[agent] = (model, level)
    return out


def _reference_problems(page: str, reference: str) -> list[str]:
    """Where the reference configuration and the page's model and effort disagree."""
    found: list[str] = []
    if REFERENCE_LINK not in page:
        found.append(f"the page does not link {REFERENCE_LINK}")
    values = json.loads(reference)["values"]
    team: dict[str, list[str]] = {}
    for stage in values["core.agents.profiles"][str(_run_text(page, "team"))]["stages"]:
        team.setdefault(stage["kind"], []).extend(stage.get("agents", []))
    try:
        stated = stated_models(page, team)
    except KeyError as exc:
        return [*found, f"run.effort names {exc}, which is no agent of the team"]
    entries = values["core.llm.agents"]
    for agent, (model, effort) in stated.items():
        entry = entries.get(agent) or {}
        if (entry.get("model"), entry.get("effort")) != (model, effort):
            found.append(
                f"the page gives {agent} {model} at {effort}, the reference configuration "
                f"{entry.get('model')} at {entry.get('effort')}"
            )
    for agent in sorted(set(entries) - set(stated)):
        found.append(f"the reference configuration sets {agent}, which the page does not state")
    return found


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


_NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7}


def _words_of(text: str) -> set[str]:
    return {w.lower() for w in re.findall(r"[^\W\d_]{4,}", text)}


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


def _evidence_ids() -> set[str]:
    """The ids of the published evidence ledger."""
    ledger = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    return {entry["entry_id"] for entry in ledger["items"]}


def problems(page: str, readme: str, docs_home: str, gate: str, reference: str) -> list[str]:
    """Every place where the public numbers disagree; empty when they agree."""
    found: list[str] = _reference_problems(page, reference)
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
    if any("contradicted" in str(row[3]) for row in key):
        found.append("a verdict shown in keyItems says contradicted")
    if len({(row[1], row[2]) for row in key}) != len(key):
        found.append("two keyItems rows share an id and a fact")
    if {str(row[6]) for row in key} - ORIGINS:
        found.append(f"keyItems names an origin outside {sorted(ORIGINS)}")
    for row in key:
        kind = _verdict_kind(str(row[3]))
        if kind in ("found", "partlyBody", "partlyDump") and not str(row[4]).strip():
            found.append(f"{row[1]} is {row[3]} but lists no ledger entry")
        if kind in ("missed", "wrong") and str(row[4]).strip():
            found.append(f"{row[1]} is {row[3]} but lists ledger entries")
    unknown = set(re.findall(r"ev_\d+", page)) - _evidence_ids()
    if unknown:
        found.append(f"the page cites entries the published evidence lacks: {sorted(unknown)}")
    missed = _run_list(page, "missedItems")
    partly = _run_list(page, "partlyItems")
    check_items = re.search(r"^  checkItems: \[(.*)\],$", _run_block(page), re.M)
    check = re.findall(r"'([^']*)'", check_items.group(1)) if check_items else []
    completion = {str(row[1]) for row in key if row[6] == "completion"}
    if not check or len(set(check)) != len(check) or not set(check) <= completion:
        found.append("run.checkItems is not a list of distinct completion rows of keyItems")
    for pattern in (r"\b(\w+)\s+more items\b", r"\b(\w+)\s+when the run’s facts were checked"):
        said = re.search(pattern, page, re.I)
        if not said or _NUMBER_WORDS.get(said.group(1).lower()) != len(check):
            found.append(f"the page's {pattern!r} does not say {len(check)}")
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
    entries_text = {(str(row[0]), str(row[1])): row[2] for row in beyond}
    examples = _run_rows(page, "beyondExamples")
    for example in examples:
        fact = (str(example[2]), str(example[3])) if len(example) == 4 else None
        if fact not in entries or (out and fact[1] == out.group(1)):
            found.append(f"the example {example[0]!r} is not a fact on the strict list")
        elif entries[fact] != example[1]:
            found.append(f"the example {example[0]!r} cites other entries than fact {fact}")
        else:
            said, fact_text = str(example[0]), str(entries_text[fact])
            for token in re.findall(r"0x[0-9a-fA-F]+|\d+", said):
                if token.lower() not in fact_text.lower():
                    found.append(f"the example {said!r} has {token}, which fact {fact} lacks")
            if not _words_of(said) & _words_of(fact_text):
                found.append(f"the example {said!r} shares no word with fact {fact}")
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


def _texts() -> tuple[str, str, str, str, str]:
    return (
        PAGE.read_text(encoding="utf-8"),
        README.read_text(encoding="utf-8"),
        DOCS_HOME.read_text(encoding="utf-8"),
        GATE.read_text(encoding="utf-8"),
        REFERENCE.read_text(encoding="utf-8"),
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
        (
            "page",
            "'PEB BeingDebugged check', 'found',",
            "'PEB BeingDebugged check', 'found (contradicted)',",
        ),
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
        # A recovered fact without its entries, a missed one with entries, and an
        # entry the published evidence does not hold.
        (
            "page",
            "'Role: loader (downloader / backdoor)', 'found', 'ev_0014',",
            "'Role: loader (downloader / backdoor)', 'found', '',",
        ),
        (
            "page",
            "which is itself one of the encrypted strings', 'partly', 'ev_0021, ev_0019, ev_0025',",
            "which is itself one of the encrypted strings', 'partly', '',",
        ),
        (
            "page",
            "'Link to IcedID', 'partly', 'ev_0018',",
            "'Link to IcedID', 'partly', '',",
        ),
        (
            "page",
            "'T1055 Process injection', 'missed', '',",
            "'T1055 Process injection', 'missed', 'ev_0014',",
        ),
        (
            "page",
            "'Family: Latrodectus', 'found', 'ev_0014,",
            "'Family: Latrodectus', 'found', 'ev_9999,",
        ),
        # An example that is no longer a fact beyond the key: K1.6 now holds it.
        (
            "page",
            "    ['The VirusTotal score at analysis time, 56 of 75', 'ev_0018', 'C', '26'],",
            "    ['The export directory’s own name, UpdaterTag.dll', 'ev_0004', 'C', '26'],",
        ),
        # The list of items that came through the check cut to three, a count word
        # changed, and an id that is not a completion row.
        (
            "page",
            "['K1.6', 'K1.7', 'K1.11', 'K1.12', 'K7.21']",
            "['K1.6', 'K1.7', 'K1.11']",
        ),
        ("page", "Five more items", "Three more items"),
        ("page", "five\nwhen the run’s facts", "three\nwhen the run’s facts"),
        ("page", "'K1.12', 'K7.21']", "'K1.12', 'K7.1']"),
        # An example worded for another fact than the one it points at.
        (
            "page",
            "    ['The compile time stamp, 2024-03-25 15:54:25 UTC', 'ev_0004', 'C', '1'],",
            "    ['The export directory’s own name, UpdaterTag.dll', 'ev_0004', 'C', '1'],",
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
        # The model and effort the page states and the reference configuration
        # sets: a level, an agent or the model changed on one side only, and
        # the link to the configuration dropped.
        ("reference", '"effort": "medium"', '"effort": "high"'),
        ("reference", '"model": "claude-haiku-5-5"', '"model": "claude-haiku-4-5"'),
        (
            "page",
            "medium for the mediator, the summariser and the reporter",
            "medium for the mediator and the summariser",
        ),
        ("page", "model: 'Claude Haiku 5.5',", "model: 'Claude Haiku 5.6',"),
        ("page", "high for the analysts and the judge;", "high for the analysts;"),
        ("page", "(/examples/profiles/all-tools-reference-run.json)", "(/docs/configuration/)"),
    ],
)
def test_a_number_changed_in_one_place_only_is_caught(target: str, old: str, new: str) -> None:
    page, readme, docs_home, gate, reference = _texts()
    texts = {
        "page": page,
        "readme": readme,
        "docs": docs_home,
        "gate": gate,
        "reference": reference,
    }
    text = texts[target]
    assert old in text, old
    text = text.replace(old, new, 1)
    texts[target] = text
    assert (
        problems(texts["page"], texts["readme"], texts["docs"], texts["gate"], texts["reference"])
        != []
    )
