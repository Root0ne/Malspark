"""The rows an entry a sentence cites records for what the sentence names (T-580).

haiku13's limitations kept "The injection target and the parent of sandbox
processes 83 and 88 are not established [ev_0012]" on the answer that no
source states the parent, while ev_0012, the entry the sentence cites, holds
``pid 83, ppid 56`` and ``pid 88, ppid 82``. A keep on no source is now read
against the entries the sentence cites: where one of them records a row for a
value the sentence names in a clause that denies something, that row could
say otherwise of it, and the keep is asked again with the row shown.

Nothing here reads a tool's or a field's name: a row is any object standing in
a list of the entry's structured answer (or of its output, read as JSON), and
it names a value where one of its own fields holds that value whole. Which
field answers the sentence, if any, is the model's to read.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from malspark.reporting.absence_answers import content_words, negated_clauses

# A value a sentence names: a number of two digits or more (a single digit is part of
# too much prose) that counts no word written after it ("processes 83 and 88 are", not
# "15 external conversations"), is no part of a grouped number ("14,000") and not written as a date,
# or a quoted text of three characters or more, its quotes standing apart from words
# (no "sample's own 'launch'" span). An address is held by what the facts about it
# state, never here.
_NUMBER = re.compile(r"(?<![\w.])(?<!\d,)(\d{2,})(?![\w.]|,\d)(?:\s+([A-Za-z][\w'-]*))?")
_GROUPED = re.compile(r"\d+(?:,\d{3})+(?:\.\d+)?")
# A four-digit number written as a date: after "in", "since", "during", "year" or a
# month's name, or before "-" and a month's number ("2026-11"). A pid of 2040 names one.
_DATED = re.compile(
    r"\b(?:in|since|during|year|jan\w*|feb\w*|mar\w*|apr\w*|may|jun\w*|jul\w*|aug\w*|"
    r"sep\w*|oct\w*|nov\w*|dec\w*)\s+(\d{4})\b|\b(\d{4})-\d\d\b",
    re.IGNORECASE,
)
_QUOTED = re.compile(r"(?<!\w)[\"'“‘`]([^\"'”’`\n]{3,120})[\"'”’`](?!\w)")
_HEX = re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE)
# How many nodes of an entry's answer are read at most: the walk stays linear and
# bounded on any answer. Rows past it are not read, and the fact says so.
_NODE_LIMIT = 20_000


@dataclass(frozen=True)
class NamedRows:
    """The rows of one entry naming a value a sentence names: each row with its place
    among the entry's rows, and whether the walk stopped before the end of the answer."""

    entry: str
    tool: str
    values: tuple[str, ...]
    rows: tuple[tuple[int, dict[str, Any]], ...]
    cut: bool = False


def _form(value: Any) -> str | None:
    """A scalar value in the one spelling both sides are compared in, or ``None``."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if _HEX.match(text):
        return str(int(text, 16))
    if text.isdigit():
        return str(int(text))
    return text.lower() or None


def named_values(sentence: str) -> dict[str, str]:
    """The values the clauses of a sentence that deny something name, by their compared
    spelling, each with the spelling the sentence writes."""
    out: dict[str, str] = {}
    # A grouped number is read whole before the clauses are cut at its commas.
    dated = {d for pair in _DATED.findall(sentence) for d in pair if d}
    for clause in negated_clauses(_GROUPED.sub("grouped", sentence)):
        numbers = [
            n for n, after in _NUMBER.findall(clause) if not content_words(after) and n not in dated
        ]
        for found in (*numbers, *_QUOTED.findall(clause)):
            form = _form(found)
            if form is not None:
                out.setdefault(form, found)
    return out


def _answer(entry: Any) -> Any:
    """The entry's structured answer, else its output read as JSON, else ``None``."""
    data = getattr(entry, "structured", None)
    if isinstance(data, (dict, list)):
        return data
    text = str(getattr(entry, "output", "") or "").strip()
    if text[:1] in "{[":
        try:
            return json.loads(text)
        except (ValueError, RecursionError):
            return None
    return None


def _rows(data: Any) -> tuple[list[dict[str, Any]], bool]:
    """Every object standing in a list of ``data``, in order, within :data:`_NODE_LIMIT`
    nodes, and whether nodes were left unread at that limit. Never more is pushed than
    can still be read."""
    stack: list[tuple[Any, bool]] = [(data, False)]
    seen = 0
    cut = False
    out: list[dict[str, Any]] = []
    while stack and seen < _NODE_LIMIT:
        node, in_list = stack.pop()
        seen += 1
        if isinstance(node, dict):
            if in_list:
                out.append(node)
            children = [(value, False) for value in node.values()]
        elif isinstance(node, list):
            children = [(value, True) for value in node]
        else:
            continue
        room = max(_NODE_LIMIT - seen - len(stack), 0)
        if len(children) > room:
            cut = True
            children = children[:room]
        stack.extend(reversed(children))
    return out, cut or bool(stack)


def rows_naming(
    entry: Any, values: dict[str, str], answers: dict[str, Any] | None = None
) -> NamedRows | None:
    """The rows of ``entry`` one of whose own fields holds a value of ``values`` whole,
    or ``None``. ``answers`` keeps each entry's rows, read once, by its id."""
    if not values:
        return None
    key = str(getattr(entry, "id", "") or "").lower()
    read = answers.get(key) if answers is not None else None
    if read is None:
        data = _answer(entry)
        read = _rows(data) if data is not None else ([], False)
        if answers is not None:
            answers[key] = read
    found, cut = read
    rows: list[tuple[int, dict[str, Any]]] = []
    named: dict[str, str] = {}
    for at, row in enumerate(found):
        hit = [
            values[form]
            for value in row.values()
            if (form := _form(value)) is not None and form in values
        ]
        if hit:
            rows.append((at, row))
            for value in hit:
                named.setdefault(value, value)
    if not rows:
        return None
    return NamedRows(
        entry=str(getattr(entry, "id", "") or ""),
        tool=str(getattr(entry, "tool", "") or ""),
        values=tuple(named),
        rows=tuple(rows),
        cut=cut,
    )


def cited_rows(
    sentence: str,
    entries: dict[str, Any],
    cited: Sequence[str],
    answers: dict[str, Any] | None = None,
) -> list[NamedRows]:
    """For each entry ``sentence`` cites (``cited``, as written), the rows it records for a
    value the sentence names in a clause denying something; ``entries`` by lowered id,
    ``answers`` each entry's rows once read (:func:`rows_naming`)."""
    values = named_values(sentence)
    if not values:
        return []
    out: list[NamedRows] = []
    for entry_id in cited:
        entry = entries.get(entry_id.lower())
        found = rows_naming(entry, values, answers) if entry is not None else None
        if found is not None:
            out.append(found)
    return out
