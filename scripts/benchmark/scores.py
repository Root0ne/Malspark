"""Scored runs read back as item verdicts, whichever way they were scored.

Three sources are read, never written:

- **a key score** (``score.md``): the table that opens the section headed "Item
  by item", the scored run's verdicts being its first column that holds a
  verdict word (found, partly (body), partly (dump), missed, wrong; a bare
  ``partly`` is ``partly (body)``, as the scoring brief writes a body partly),
  every cell of which must be one (a later column is another run's and is never
  read in its place), and the numbered list of the section headed "Beyond the human reports". The
  file's own sentences are checked against what was counted: the ``**Totals:**``
  line and the "N facts more than the human analyst" line, when it has them. A
  file that disagrees with itself is refused, naming both numbers. Each item's
  row, as written, is followed back to the ledger entries that credited it,
  where the stored run lies beside the file (``scripts.benchmark.provenance``),
  and its run summary says whether the run started without an earlier run's
  memory of its sample (``scripts.benchmark.earlier_runs``);
- **a blind score sheet** with its sealed map (``scripts/blind``): one scored
  run per arm, named by the map;
- **a calibration score** (``scripts/calibration/run.py score --json`` or
  ``gate --json``): each case's facts on the fact scale, its traps and absent
  capabilities on the claim scale (a trap is only ever false or not claimed; a
  part the run did not store is unknown). The calibration scorer's ``beyond``
  counts publications no manifest names, not proven facts, so it is not read as
  a beyond-human count.

A key score or a blind sheet is read by the words of **scoring rules** when it
is given a declared table of them (``ScoringRules``, ``load_rules``): the verdict
words from worst to best, the lowest one the totals credit, the words of the
states that are no verdict and leave the denominator (an item under
adjudication, one that does not hold for the file), and the spellings that mean
a verdict word. Without a table the reader is the one the rest of this
paragraph describes, unchanged. A table may also declare annotations: words that
may follow a verdict in a cell (a statement found only in the evidence bundle). The run keeps them
beside the item and counts, per annotation, the credited items that carry it; an undeclared word
after a verdict is still refused. A word the table does not hold is refused,
naming the row and the word, and never mapped to another.

Every verdict sits on a **scale**, a tuple of words from worst to best, so that
two verdicts of one item can be ordered and nothing else is compared. An item is
keyed by its code (``K3.2``, ``K7 17``, ``K10 T1027``), or, where the label has
no code, by its whole label in one case, without emphasis or backticks, its runs
of spaces read as one and the spaces around a ``/`` dropped, so the same item
spelt ``a / b`` in one file and ``a/b`` in another is one item, while ``task
Updater`` and ``taskUpdater`` stay two. A file with no Totals line is read, and
the output says its totals were unchecked; a Totals line that cannot be read is
refused, naming the line, as is a stated beyond-human count with no list.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

from scripts.benchmark import earlier_runs
from scripts.benchmark.provenance import ItemProvenance, attribute_all

KEY, FACT, CLAIM = "key", "fact", "claim"
# Each scale's words, worst first: a verdict's rank is its index.
SCALES: dict[str, tuple[str, ...]] = {
    KEY: ("wrong", "missed", "partly (dump)", "partly (body)", "found"),
    FACT: ("missed", "mentioned", "partial", "found"),
    CLAIM: ("false", "not claimed"),
}
# The lowest word of a scale that the totals credit ("found + partly"); a scale
# absent here credits nothing.
CREDITED: dict[str, str] = {KEY: "partly (dump)", FACT: "partial"}
KEY_ALIASES: dict[str, str] = {"partly": "partly (body)"}
# A scale's states that are no verdict and leave the denominator, by scale; a
# declared table registers its own (``ScoringRules.register``).
OUTSIDE: dict[str, tuple[str, ...]] = {}
# A calibration trap's or absence's status, on the claim scale; None: unknown.
CLAIM_STATUSES: dict[str, str | None] = {
    "false": "false",
    "clear": "not claimed",
    "withheld": "not claimed",
    "mentioned": "not claimed",
    "not recorded": None,
}
SCORE_FILE = "score.md"
ITEM_SECTION = re.compile(r"^(#+)\s.*\bitem by item\b", re.IGNORECASE)
BEYOND_SECTION = re.compile(r"^(#+)\s+(?:\d+\.\s+)?beyond the human reports\b", re.IGNORECASE)
_HEADING = re.compile(r"^(#+)\s")
_LISTED = re.compile(r"^(\d+)\.\s")
_STATED_BEYOND = re.compile(
    r"\*\*(\d+) facts? (?:more than the human analyst|beyond the human reports)"
)
_TOTALS_LINE = "**Totals:"
_STATED_TOTALS = re.compile(
    r"\*\*Totals:\s*(\d+) found / (\d+) partly \((\d+) body \+ (\d+) dump\) / "
    r"(\d+) missed / (\d+) wrong"
)
# What may stand between a verdict and the annotations written after it.
_JOINERS = " ,;:()+-"
_CELL_SPLIT = re.compile(r"(?<!\\)\|")
_SEPARATOR = re.compile(r"^\|[\s:|-]+\|$")
_DOTTED_CODE = re.compile(r"^K\d+\.\w+$")
_GROUP = re.compile(r"^K\d+$")
_SUB_CODE = re.compile(r"^(\d+|T\d{4}(\.\d{3})?)$")
_EMPHASIS = re.compile(r"[*`]")
_SPACE = re.compile(r"\s+")
_AROUND_SLASH = re.compile(r" ?/ ?")


class ScoreFileError(RuntimeError):
    """A scored run cannot be read; the message names the file and why."""


@dataclass(frozen=True)
class ScoringRules:
    """A key's declared scoring rules: the words a scored sheet may hold and what each means."""

    name: str
    # The verdict words, worst first; a verdict's rank is its index.
    scale: tuple[str, ...]
    # The lowest word the totals credit; None credits nothing.
    credited_from: str | None = None
    # States that are no verdict: the item leaves the denominator.
    outside: tuple[str, ...] = ()
    # A spelling -> the verdict word it means.
    aliases: dict[str, str] = field(default_factory=dict)
    # Words that may follow a verdict in a cell and are kept beside it, never read as a verdict:
    # each with the verdicts it may follow (after any other word it is refused).
    annotations: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # The verdict words that play a role a statistic needs ("missed", "wrong"); a role the
    # rules lack is not applicable, and no statistic names a word for it.
    roles: dict[str, str] = field(default_factory=dict)
    # The rest of the table (key folder, digest, quotes): never read by the reader.
    extra: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def scale_id(self) -> str:
        """The scale's name in ``SCALES``: ``key`` for the built-in rules."""
        return KEY if self.name == KEY else f"{KEY}:{self.name}"

    @property
    def words(self) -> tuple[str, ...]:
        """Every word a sheet may hold, verdicts then outside states."""
        return (*self.scale, *self.outside)

    def word(self, cell: str) -> str | None:
        """A cell as one of the rules' words (an alias resolved, annotations set aside), or None."""
        found = self.split(cell)
        return None if found is None else found[0]

    def split(self, cell: str) -> tuple[str, tuple[str, ...]] | None:
        """A cell as ``(word, annotations)``: a word of the rules, then declared annotations."""
        text = _plain(cell).casefold()
        if (whole := self.aliases.get(text, text)) in self.words:
            return whole, ()
        if not self.annotations:
            return None
        spellings = sorted((*self.scale, *self.aliases), key=len, reverse=True)
        for spelling in spellings:
            if not text.startswith(spelling) or text[len(spelling) :][:1].isalnum():
                continue
            verdict = self.aliases.get(spelling, spelling)
            rest, held = text[len(spelling) :].strip(_JOINERS), []
            while rest:
                note = next(
                    (
                        a
                        for a in sorted(self.annotations, key=len, reverse=True)
                        if rest.startswith(a) and not rest[len(a) :][:1].isalnum()
                    ),
                    None,
                )
                # an annotation stands only after the verdicts the table names for it, once
                if note is None or note in held or verdict not in self.annotations[note]:
                    return None
                held.append(note)
                rest = rest[len(note) :].strip(_JOINERS)
            if held:
                return verdict, tuple(held)
        return None

    def why(self, cell: str) -> str:
        """Why a cell is refused when a verdict is followed by a declared annotation, else ''."""
        text = _plain(cell).casefold()
        for spelling in sorted((*self.scale, *self.aliases), key=len, reverse=True):
            if not text.startswith(spelling) or text[len(spelling) :][:1].isalnum():
                continue
            verdict = self.aliases.get(spelling, spelling)
            rest, held = text[len(spelling) :].strip(_JOINERS), []
            while rest:
                note = next(
                    (
                        a
                        for a in sorted(self.annotations, key=len, reverse=True)
                        if rest.startswith(a) and not rest[len(a) :][:1].isalnum()
                    ),
                    None,
                )
                if note is None:
                    return ""
                if note in held:
                    return f"the annotation {note!r} is repeated"
                if verdict not in self.annotations[note]:
                    return (
                        f"the annotation {note!r} may follow only "
                        f"{', '.join(self.annotations[note])}, not {verdict!r}"
                    )
                held.append(note)
                rest = rest[len(note) :].strip(_JOINERS)
        return ""

    def register(self) -> None:
        """Make the scale known to ``SCALES``, ``CREDITED`` and ``OUTSIDE``.

        A name is registered once: the same name with any other content is refused, and the
        name of the built-in scale belongs to the built-in rules.
        """
        held = _REGISTERED.setdefault(self.scale_id, self.as_dict())
        if held != self.as_dict():
            raise ScoreFileError(f"scoring rules {self.name!r} are declared twice, differently")
        SCALES.setdefault(self.scale_id, self.scale)
        OUTSIDE.setdefault(self.scale_id, self.outside)
        if self.credited_from is not None:
            CREDITED.setdefault(self.scale_id, self.credited_from)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "verdicts": list(self.scale),
            "credited_from": self.credited_from,
            "outside_denominator": list(self.outside),
            "aliases": dict(self.aliases),
            "annotations": {a: list(v) for a, v in self.annotations.items()},
            "roles": dict(self.roles),
        }


KEY_RULES = ScoringRules(
    KEY,
    SCALES[KEY],
    CREDITED[KEY],
    (),
    KEY_ALIASES,
    roles={"missed": "missed", "wrong": "wrong"},
)
# The registered scales' tables by scale id; the built-in scale is registered as it stands.
_REGISTERED: dict[str, dict[str, Any]] = {KEY: KEY_RULES.as_dict()}


def _words(where: str, value: Any, what: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(w, str) and w.strip() for w in value):
        raise ScoreFileError(f"{where}: {what} is not a list of words")
    return tuple(_plain(w).casefold() for w in value)


def rules_from_dict(data: Any, where: str = "scoring rules") -> ScoringRules:
    """Scoring rules from their declared table; refused, naming ``where``, when it is not sound."""
    if not isinstance(data, dict) or not isinstance(data.get("name"), str) or not data["name"]:
        raise ScoreFileError(f"{where}: not a scoring-rules table (an object with a name)")
    scale = _words(where, data.get("verdicts"), "'verdicts'")
    outside = _words(where, data.get("outside_denominator", []), "'outside_denominator'")
    if len(scale) < 2:
        raise ScoreFileError(f"{where}: 'verdicts' holds fewer than two words")
    every = (*scale, *outside)
    if len(set(every)) != len(every):
        twice = sorted({w for w in every if every.count(w) > 1})
        raise ScoreFileError(f"{where}: a word is declared twice: {', '.join(twice)}")
    credited = data.get("credited_from")
    if credited is not None:
        credited = _plain(str(credited)).casefold()
        if credited not in scale:
            raise ScoreFileError(f"{where}: 'credited_from' {credited!r} is not a verdict word")
    aliases = data.get("aliases") or {}
    if not isinstance(aliases, dict):
        raise ScoreFileError(f"{where}: 'aliases' is not an object")
    folded = {_plain(str(k)).casefold(): _plain(str(v)).casefold() for k, v in aliases.items()}
    for spelling, meant in folded.items():
        if meant not in scale or spelling in every:
            raise ScoreFileError(
                f"{where}: the alias {spelling!r} -> {meant!r} must name a verdict word "
                "and may not be a word itself"
            )
    declared = data.get("annotations") or {}
    if not isinstance(declared, dict):
        raise ScoreFileError(f"{where}: 'annotations' is not an object of verdict lists")
    notes: dict[str, tuple[str, ...]] = {}
    for note, after in declared.items():
        word = _plain(str(note)).casefold()
        follows = _words(where, after, f"the verdicts annotation {note!r} may follow")
        if word in every or word in notes or not follows or not set(follows) <= set(scale):
            raise ScoreFileError(
                f"{where}: annotation {note!r} is a word of the rules, is declared twice, or "
                "names no verdict of the table it may follow"
            )
        notes[word] = follows
    roles = data.get("roles") or {}
    if not isinstance(roles, dict) or not set(roles) <= {"missed", "wrong"}:
        raise ScoreFileError(f"{where}: 'roles' is an object of 'missed' and 'wrong'")
    held = {k: _plain(str(v)).casefold() for k, v in roles.items()}
    if not set(held.values()) <= set(scale):
        raise ScoreFileError(f"{where}: a role names a word that is no verdict of the table")
    known = {
        "name",
        "verdicts",
        "credited_from",
        "outside_denominator",
        "aliases",
        "annotations",
        "roles",
    }
    return ScoringRules(
        data["name"],
        scale,
        credited,
        outside,
        folded,
        notes,
        held,
        {k: v for k, v in data.items() if k not in known},
    )


def load_rules(path: Path) -> ScoringRules:
    """The scoring rules a JSON table declares."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ScoreFileError(f"{path}: not JSON ({exc})") from exc
    return rules_from_dict(data, str(path))


@dataclass
class ScoredRun:
    """One scored run: each item's scale and verdict, and its beyond-human count."""

    name: str
    source: str
    # item key -> (scale, verdict); a verdict of None is unknown.
    verdicts: dict[str, tuple[str, str | None]]
    labels: dict[str, str] = field(default_factory=dict)
    beyond: int | None = None
    # Why ``beyond`` is None, or where it was read.
    beyond_note: str = ""
    # The table column the verdicts were read from, for a key score.
    column: str | None = None
    # Whether the file's own totals were checked against its table, and how.
    totals_note: str = ""
    # item key -> which entries credited it, own analysis or lookup
    # (``scripts.benchmark.provenance``); empty, with the reason, where none was read.
    provenance: dict[str, ItemProvenance] = field(default_factory=dict)
    provenance_note: str = ""
    # Whether the run started without an earlier run's memory of its sample
    # (``scripts.benchmark.earlier_runs``): its status and why; empty for a
    # score with no stored run to read.
    earlier_runs: str = ""
    earlier_runs_note: str = ""
    # The declared rules the run was read by; None for the built-in scales.
    rules: ScoringRules | None = None
    # item key -> the declared annotations its cell carried (only items that carried any).
    annotations: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @cached_property
    def outside(self) -> dict[str, str]:
        """Each item that is no verdict and leaves the denominator, with its state (read once)."""
        states = self.rules.outside if self.rules else ()
        return {k: v for k, (_, v) in self.verdicts.items() if v in states and v is not None}

    @property
    def denominator(self) -> int:
        """The items the run is scored over: every item but those that left it."""
        return len(self.verdicts) - len(self.outside)

    def annotation_counts(self) -> dict[str, int]:
        """Per declared annotation, how many credited items carry it; empty without a table."""
        if self.rules is None:
            return {}
        out = dict.fromkeys(self.rules.annotations, 0)
        for item, notes in self.annotations.items():
            if self.credited(item):
                for note in notes:
                    out[note] += 1
        return out

    def credited(self, item: str) -> bool:
        """Whether the item's verdict is one the rules credit."""
        word = self.verdicts[item][1]
        rules = self.rules
        if rules is None or rules.credited_from is None or word not in rules.scale:
            return False
        return rules.scale.index(word) >= rules.scale.index(rules.credited_from)

    def counts(self) -> dict[str, int]:
        """Items per word, in the rules' order, the words held by no item as 0."""
        held = Counter(v for _, v in self.verdicts.values() if v is not None)
        words = self.rules.words if self.rules else SCALES[KEY]
        return {w: held.get(w, 0) for w in words}


def rank(scale: str, word: str | None) -> int | None:
    """A verdict's rank on its scale; None for an unknown verdict or a state outside it."""
    if word is None or word in OUTSIDE.get(scale, ()):
        return None
    return SCALES[scale].index(word)


def _plain(text: str) -> str:
    return _SPACE.sub(" ", _EMPHASIS.sub("", text)).strip()


def item_key(label: str) -> str:
    """The item a label names: its code, or the folded label when it has none."""
    words = _plain(label).split(" ")
    if _DOTTED_CODE.match(words[0]):
        return words[0]
    if _GROUP.match(words[0]) and len(words) > 1 and _SUB_CODE.match(words[1]):
        return f"{words[0]} {words[1]}"
    if len(words) == 1:
        return words[0]
    return words[0] + " " + _AROUND_SLASH.sub("/", " ".join(words[1:]).casefold())


def key_verdict(cell: str, rules: ScoringRules | None = None) -> str | None:
    """A table cell as a verdict (or a declared outside state) of the rules, or None."""
    if rules is not None:
        return rules.word(cell)
    word = _plain(cell).casefold()
    word = KEY_ALIASES.get(word, word)
    return word if word in SCALES[KEY] else None


def _cells(line: str) -> list[str]:
    return [c.strip() for c in _CELL_SPLIT.split(line.strip().strip("|"))]


def _section(lines: list[str], heading: re.Pattern[str]) -> list[str] | None:
    """The lines under the first heading ``heading`` matches, up to one of its level or above."""
    for start, line in enumerate(lines):
        found = heading.match(line)
        if not found:
            continue
        level = len(found.group(1))
        body: list[str] = []
        for following in lines[start + 1 :]:
            other = _HEADING.match(following)
            if other and len(other.group(1)) <= level:
                break
            body.append(following)
        return body
    return None


def _first_table(body: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in body:
        if line.startswith("|"):
            rows.append(_cells(line))
        elif rows:
            break
    return rows


def _name(path: Path) -> str:
    return path.parent.name if path.name == SCORE_FILE else path.stem


def read_key_score(path: Path, rules: ScoringRules | None = None) -> ScoredRun:
    """A key score file's item verdicts and beyond-human count, checked against its own totals.

    With ``rules`` the verdict column is the first one that holds a word of the
    rules, every cell of which must then be one; the totals line, which the rules
    do not describe, is not checked; and the run carries the rules, so its
    denominator and counts follow them.
    """
    path = Path(path)
    if rules is not None:
        rules.register()
    scale = KEY if rules is None else rules.scale_id
    lines = path.read_text(encoding="utf-8").splitlines()
    body = _section(lines, ITEM_SECTION)
    if body is None:
        raise ScoreFileError(f"{path}: no section headed 'Item by item'")
    table = _first_table(body)
    raw = [line for line in body if line.startswith("|")]
    if len(table) < 3 or not _SEPARATOR.match(raw[1].strip()):
        raise ScoreFileError(f"{path}: the 'Item by item' section opens with no item table")
    header, rows = table[0], table[2:]
    column = next(
        (
            j
            for j in range(1, len(header))
            if any(len(r) > j and key_verdict(r[j], rules) for r in rows)
        ),
        None,
    )
    if column is None:
        raise ScoreFileError(f"{path}: no column of the item table holds a verdict")
    for row in rows:
        if len(row) <= column or not key_verdict(row[column], rules):
            cell = row[column] if len(row) > column else ""
            reason = rules.why(cell) if rules is not None else ""
            raise ScoreFileError(
                f"{path}: the scored column {_plain(header[column])!r} is not a verdict "
                f"for {_plain(row[0])!r}: {cell!r}" + (f" ({reason})" if reason else "")
            )
    verdicts: dict[str, tuple[str, str | None]] = {}
    labels: dict[str, str] = {}
    written: dict[str, str] = {}
    noted: dict[str, tuple[str, ...]] = {}
    for row in rows:
        key = item_key(row[0])
        if key in verdicts:
            raise ScoreFileError(
                f"{path}: item {key} is scored twice ({labels[key]!r}, {row[0]!r})"
            )
        verdicts[key] = (scale, key_verdict(row[column], rules))
        if rules is not None and (split := rules.split(row[column])) and split[1]:
            noted[key] = split[1]
        labels[key] = _plain(row[0])
        written[key] = " | ".join(row)
    provenance, provenance_note = attribute_all(path, written)
    independence, independence_note = earlier_runs.check(path, lines)
    run = ScoredRun(
        name=_name(path),
        source=str(path),
        verdicts=verdicts,
        labels=labels,
        column=_plain(header[column]),
        provenance=provenance,
        provenance_note=provenance_note,
        earlier_runs=independence,
        earlier_runs_note=independence_note,
        rules=rules,
        annotations=noted,
    )
    if rules is None:
        _check_totals(path, lines, run)
    else:
        run.totals_note = "the declared rules state no Totals line: totals unchecked"
    _read_beyond(path, lines, run)
    return run


def _check_totals(path: Path, lines: list[str], run: ScoredRun) -> None:
    line = next((x for x in lines if _TOTALS_LINE in x), None)
    if line is None:
        run.totals_note = "no Totals line: totals unchecked"
        return
    stated = _STATED_TOTALS.search(line)
    if stated is None:
        raise ScoreFileError(f"{path}: the Totals line cannot be read: {line.strip()!r}")
    words = [v for _, v in run.verdicts.values()]
    counted = {
        "found": words.count("found"),
        "partly": words.count("partly (body)") + words.count("partly (dump)"),
        "body": words.count("partly (body)"),
        "dump": words.count("partly (dump)"),
        "missed": words.count("missed"),
        "wrong": words.count("wrong"),
    }
    said = dict(zip(counted, (int(g) for g in stated.groups()), strict=True))
    differ = [
        f"{k} {said[k]} stated, {counted[k]} in the table" for k in counted if said[k] != counted[k]
    ]
    if differ:
        raise ScoreFileError(
            f"{path}: the Totals line disagrees with the item table: {'; '.join(differ)}"
        )
    run.totals_note = "Totals line checked against the table"


def _read_beyond(path: Path, lines: list[str], run: ScoredRun) -> None:
    stated = next((int(m.group(1)) for m in map(_STATED_BEYOND.search, lines) if m), None)
    body = _section(lines, BEYOND_SECTION)
    if body is None:
        if stated is not None:
            raise ScoreFileError(
                f"{path}: {stated} beyond-human facts stated, and no section headed "
                "'Beyond the human reports' lists them"
            )
        run.beyond_note = "no section headed 'Beyond the human reports'"
        return
    numbers = [int(m.group(1)) for m in map(_LISTED.match, body) if m]
    if numbers != list(range(1, len(numbers) + 1)):
        raise ScoreFileError(
            f"{path}: the beyond-human list is not numbered 1 to {len(numbers)} in order"
        )
    if stated is not None and stated != len(numbers):
        raise ScoreFileError(f"{path}: {stated} beyond-human facts stated, {len(numbers)} listed")
    run.beyond = len(numbers)
    run.beyond_note = f"{len(numbers)} listed" + ("" if stated is None else ", as stated")


def read_blind(sheet: Path, sealed: Path, rules: ScoringRules | None = None) -> list[ScoredRun]:
    """One scored run per arm of a filled blind score sheet, named by its sealed map.

    The sheet is read by ``rules``, else by the rules its sealed map holds, else
    by the built-in key scale.
    """
    from scripts.blind.prepare import BlindError
    from scripts.blind.reveal import reveal

    try:
        revealed = reveal(sheet, sealed, rules)
    except BlindError as exc:
        raise ScoreFileError(f"{sheet}: {exc}") from exc
    declared = revealed.rules
    if declared is not None:
        declared.register()
    scale = KEY if declared is None else declared.scale_id
    runs: list[ScoredRun] = []
    for arm, given in revealed.verdicts.items():
        verdicts: dict[str, tuple[str, str | None]] = {}
        labels: dict[str, str] = {}
        noted: dict[str, tuple[str, ...]] = {}
        for item, word in given.items():
            key = item_key(item)
            if key in verdicts:
                raise ScoreFileError(f"{sheet}: items {labels[key]!r} and {item!r} are one item")
            if revealed.annotations[arm].get(item):
                noted[key] = revealed.annotations[arm][item]
            verdicts[key] = (scale, KEY_ALIASES.get(word, word) if declared is None else word)
            labels[key] = item
        runs.append(
            ScoredRun(
                name=arm,
                source=f"{sheet} ({arm})",
                verdicts=verdicts,
                labels=labels,
                beyond=revealed.beyond[arm],
                beyond_note="the sheet's beyond_human row",
                provenance_note="not read: a blind score sheet cites no evidence",
                rules=declared,
                annotations=noted,
            )
        )
    return runs


def _calibration_items(score: dict[str, Any], where: Path) -> dict[str, tuple[str, str | None]]:
    case = str(score.get("case") or "")
    if not case:
        raise ScoreFileError(f"{where}: a calibration score names no case")
    items: dict[str, tuple[str, str | None]] = {}
    for fact in score.get("facts") or []:
        status = str(fact.get("status"))
        if status not in SCALES[FACT]:
            raise ScoreFileError(f"{where}: {case}/{fact.get('id')} has the status {status!r}")
        items[f"{case}/{fact['id']}"] = (FACT, status)
    for claim in [*(score.get("traps") or []), *(score.get("absent") or [])]:
        status = str(claim.get("status"))
        if status not in CLAIM_STATUSES:
            raise ScoreFileError(f"{where}: {case}/{claim.get('id')} has the status {status!r}")
        items[f"{case}/{claim['id']}"] = (CLAIM, CLAIM_STATUSES[status])
    if not items:
        raise ScoreFileError(f"{where}: the score of {case} has no fact, trap or absent entry")
    return items


def read_calibration(path: Path) -> ScoredRun:
    """A calibration score, or a calibration gate result (every held-out case it scored)."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ScoreFileError(f"{path}: not JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ScoreFileError(f"{path}: not a calibration score")
    found = data.get("scores")
    gate_result = isinstance(found, list)
    scores: list[Any] = found if isinstance(found, list) else [data]
    verdicts: dict[str, tuple[str, str | None]] = {}
    for score in scores:
        if not isinstance(score, dict) or "facts" not in score:
            raise ScoreFileError(f"{path}: not a calibration score")
        verdicts.update(_calibration_items(score, path))
    name = path.stem if gate_result else str(data.get("run") or path.stem)
    return ScoredRun(
        name=name,
        source=str(path),
        verdicts=verdicts,
        labels={k: k for k in verdicts},
        beyond_note=(
            "not read: the calibration scorer's beyond counts publications no manifest "
            "names, not proven facts"
        ),
        provenance_note="not read: a calibration score cites no evidence",
    )


def read_scored(path: Path, rules: ScoringRules | None = None) -> ScoredRun:
    """A key score (``.md``, read by ``rules`` when given) or a calibration score (``.json``)."""
    path = Path(path)
    if path.suffix.lower() == ".md":
        return read_key_score(path, rules)
    if path.suffix.lower() == ".json":
        return read_calibration(path)
    raise ScoreFileError(f"{path}: neither a key score (.md) nor a calibration score (.json)")
