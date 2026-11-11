"""The branches of a decompiled function that end it with a constant on a condition.

A reverser read the routine that gated the whole sample: each of its checks
handed back ``-1`` when it failed, and no claim said what any of them checked.
The routine was named, so the question about the functions no claim names
(``validation.decompiled_not_described_violation``) did not ask about it. The
branches are read here off the analyst's own listings, by their shape alone,
and the ones no claim names together with their function join that question.

What a listing says:

* **A readable listing** is a function body in C form: a signature ending in
  ``)``, an opening brace, balanced braces and statements ended by ``;``. A
  body with a label (``name:`` where a statement starts) or a ``goto`` says
  nothing, because a path's condition is then no longer the blocks around it;
  so does a body that does not parse, prose and JSON. A comment, a string and
  the text around the body are no part of it.
* **An exit** is a statement inside at least one condition (``if``, ``else``,
  a loop, ``switch``) that returns a constant (a number, negated or cast, or
  ``true``/``false``), or gives a constant to a variable some ``return v;`` of
  the function returns. An unguarded return is no branch.
* **Its terms** are read from the innermost condition alone: the functions it
  calls (a decompiler's generic name, by the prefixes every source declares),
  the slots it calls through (a datum's label, by the declared data prefixes,
  called through a pointer, or one the run's function index resolved), and its
  constants of :data:`LEAST_CONSTANT` or more. Each variable of the condition
  adds the functions and slots of the nearest statement before it on its path
  that mentions the variable and calls one (:data:`HOP_DEPTH`); a variable the
  condition assigns itself takes none. An exit with no term says nothing.

An exit is covered when one claim names both its function and one of its
terms. The uncovered ones are ranked (a function a claim already names first,
then the term the fewest of the analyst's listings call, then the function
with the most exits handing back that value) and at most :data:`EXITS_LISTED`
are listed. They are a question, never a finding: they join a validation turn
that is asked anyway (``validation.with_exit_branches``) and are left out of
what any record keeps of it. Read in time linear in the listing: one
tokenising pass, an
explicit stack, and the statements a variable was last mentioned in kept in a
dict with an undo log, so no path is ever copied.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from malspark.core.undeclared_tools import declared_auto_name_pattern, declared_labels
from malspark.pipeline.events import safe_finding_value
from malspark.schemas.evidence import answer_not_shown

# The most exits one question lists, the rest counted: the measured gates of a
# gate routine ranked within the first eight, and each line costs a claim.
EXITS_LISTED = 8
# The least absolute value a constant of a condition is a term at: a smaller
# one (0, 1, a count of a few) is written by accident in any sentence.
LEAST_CONSTANT = 10
# How many statements back a variable of a condition is followed: the one that
# last mentioned it calling something, which is where its value came from.
HOP_DEPTH = 1


# One token of a listing. A comment or a string left open runs to the end of
# the text or of its line, so no position is read twice. A number is a
# constant up to 16 hex or 20 decimal digits; a longer run is one token that
# is no constant (``long``), never cut into one.
_TOKEN = re.compile(
    r"(?P<space>\s+)"
    r"|(?P<comment>/\*.*?(?:\*/|\Z)|//[^\n]*)"
    r"|(?P<string>\"[^\"\\\n]*(?:\\.[^\"\\\n]*)*\"?|'[^'\\\n]*(?:\\.[^'\\\n]*)*'?)"
    r"|(?P<number>0[xX][0-9a-fA-F]{1,16}(?![0-9a-fA-F])|\d{1,20}(?![\dxX]))[uUlL]*"
    r"|(?P<long>0[xX][0-9a-fA-F]+|\d+)[uUlL]*"
    r"|(?P<name>[A-Za-z_$][\w$]*(?:\.[\w$]+)*)"
    r"|(?P<mark>->|\+\+|--|<<=|>>=|==|!=|<=|>=|&&|\|\||[^\s\w])",
    re.DOTALL,
)
_KEYWORDS = frozenset(
    {
        "if",
        "else",
        "while",
        "for",
        "switch",
        "do",
        "return",
        "case",
        "default",
        "break",
        "continue",
        "goto",
        "sizeof",
        "true",
        "false",
    }
)
_CONDITIONS = frozenset({"if", "while", "for", "switch"})
# What a cast may stand before: an operand.
_OPERAND_MARKS = frozenset({"(", "&", "*", "-", "!", "~"})
_NAME, _NUMBER, _MARK = "name", "number", "mark"
# The frames of the reader's stack: a block, an if's two branches, a loop's or
# switch's body, and a do's body.
_BLOCK, _THEN, _ELSE, _BODY, _DO = range(5)
# A word of a claim, read for a resolved API name.
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True, eq=False)
class _Part:
    """Terms of one condition or one statement it hops to, shared by every exit under it."""

    callees: frozenset[int]
    slots: frozenset[int]
    constants: frozenset[int]


@dataclass(frozen=True)
class ExitSite:
    """One branch that ends a decompiled function with a constant on a condition.

    ``function`` is the function as :func:`validation.decompiled_functions`
    names one (its address, the names it was given, the entry that holds the
    listing). ``fan_in`` is the fewest of the analyst's listings that call one
    of its functions or slots (``None`` with only constants), ``same_value``
    how many exits of its function hand back the same value.
    """

    function: Any
    value: int
    written: str
    parts: tuple[_Part, ...] = field(compare=False)
    fan_in: int | None
    same_value: int
    apis: Mapping[int, str] = field(compare=False, repr=False)

    @property
    def callees(self) -> tuple[int, ...]:
        return tuple(sorted({a for p in self.parts for a in p.callees}))

    @property
    def slots(self) -> tuple[int, ...]:
        return tuple(sorted({a for p in self.parts for a in p.slots}))

    @property
    def constants(self) -> tuple[int, ...]:
        return tuple(sorted({c for p in self.parts for c in p.constants}))


# ---------------------------------------------------------------------------
# One listing
# ---------------------------------------------------------------------------


def _tokens(text: str) -> tuple[list[str], list[str]]:
    """The listing's tokens, comments and strings aside: ``(kinds, texts)``."""
    kinds: list[str] = []
    texts: list[str] = []
    for match in _TOKEN.finditer(text):
        kind = match.lastgroup
        if kind in ("space", "comment"):
            continue
        if kind == "number":
            kinds.append(_NUMBER)
            texts.append(match.group("number"))
        elif kind == "string":
            kinds.append("string")
            texts.append('""')
        elif kind == "long":
            kinds.append("long")
            texts.append("#")
        else:
            kinds.append(str(kind))
            texts.append(match.group(0))
    return kinds, texts


def _number_value(text: str) -> int:
    return int(text, 16) if text[:2].lower() == "0x" else int(text)


class _Labels:
    """The declared generic function names and datum labels, read once per reading."""

    def __init__(self) -> None:
        self.function = declared_auto_name_pattern()
        joined = "|".join(re.escape(p) for p in declared_labels().data)
        self.data = (
            re.compile(r"_*(?i:" + joined + r")(?:0x)?([0-9a-fA-F]{4,16})") if joined else None
        )

    def callee(self, name: str) -> int | None:
        found = self.function.fullmatch(name)
        return int(found.group(1), 16) if found is not None else None

    def datum(self, name: str) -> int | None:
        found = self.data.fullmatch(name) if self.data is not None else None
        return int(found.group(1), 16) if found is not None else None


class _Reader:
    """One listing's exits: an explicit stack, guards and the hop dicts with their undo log."""

    def __init__(
        self, kinds: list[str], texts: list[str], labels: _Labels, slots: Mapping[int, str]
    ) -> None:
        self.kinds, self.texts, self.n = kinds, texts, len(texts)
        self.labels, self.slots = labels, slots
        self.last: list[dict[str, _Part]] = [{} for _ in range(HOP_DEPTH)]
        self.undo: list[tuple[int, str, _Part | None]] = []
        self.guards: list[tuple[_Part, ...]] = []
        self.parts: dict[tuple[frozenset[int], ...], _Part] = {}
        self.exits: list[tuple[tuple[_Part, ...], int, str]] = []
        self.pending: list[tuple[str, tuple[_Part, ...], int, str]] = []
        self.returned: set[str] = set()

    # -- terms -------------------------------------------------------------

    def _part(self, callees: set[int], slots: set[int], constants: set[int]) -> _Part | None:
        if not (callees or slots or constants):
            return None
        key = (frozenset(callees), frozenset(slots), frozenset(constants))
        held = self.parts.get(key)
        if held is None:
            held = self.parts[key] = _Part(*key)
        return held

    def _direct(self, a: int, b: int, *, constants: bool) -> _Part | None:
        """The functions, slots and (``constants``) constants tokens ``a`` to ``b`` name."""
        kinds, texts = self.kinds, self.texts
        callees: set[int] = set()
        slots: set[int] = set()
        values: set[int] = set()
        for k in range(a, b):
            if kinds[k] == _NAME:
                address = self.labels.callee(texts[k])
                if address is not None:
                    callees.add(address)
                    continue
                address = self.labels.datum(texts[k])
                if address is not None and (
                    address in self.slots
                    or (k >= a + 2 and texts[k - 1] == "*" and texts[k - 2] == "(")
                ):
                    slots.add(address)
            elif constants and kinds[k] == _NUMBER:
                value = _number_value(texts[k])
                if value < LEAST_CONSTANT:
                    continue
                unary = (
                    k > a
                    and texts[k - 1] == "-"
                    and (k - 1 == a or (kinds[k - 2] == _MARK and texts[k - 2] not in (")", "]")))
                )
                values.add(-value if unary else value)
        return self._part(callees, slots, values)

    def _variables(self, a: int, b: int) -> list[str]:
        """The variables tokens ``a`` to ``b`` mention, once each, in order."""
        kinds, texts = self.kinds, self.texts
        found: dict[str, None] = {}
        for k in range(a, b):
            if kinds[k] != _NAME:
                continue
            name = texts[k]
            if name in _KEYWORDS or (k + 1 < b and texts[k + 1] == "("):
                continue
            if k > a and texts[k - 1] in ("->", "."):
                continue
            if k >= a + 2 and texts[k - 1] == "*" and texts[k - 2] == "(":
                continue
            if self.labels.callee(name) is not None:
                continue
            datum = self.labels.datum(name)
            if datum is None and not name[0].islower() and name[0] not in "_$":
                continue
            if datum is not None and datum in self.slots:
                continue
            if k > a and texts[k - 1] == "(" and self._casts(k, b):
                continue
            found[name] = None
        return list(found)

    def _casts(self, k: int, b: int) -> bool:
        """Whether the name at ``k`` is a cast's type: ``( name *… )`` before an operand."""
        texts, kinds = self.texts, self.kinds
        j = k + 1
        while j < b and texts[j] == "*":
            j += 1
        if j + 1 >= b or texts[j] != ")":
            return False
        after = j + 1
        return kinds[after] in (_NAME, _NUMBER) or texts[after] in _OPERAND_MARKS

    def _set(self, level: int, name: str, part: _Part) -> None:
        held = self.last[level]
        self.undo.append((level, name, held.get(name)))
        held[name] = part

    def _restore(self, mark: int) -> None:
        undo = self.undo
        while len(undo) > mark:
            level, name, part = undo.pop()
            if part is None:
                self.last[level].pop(name, None)
            else:
                self.last[level][name] = part

    def _register(self, a: int, b: int, direct: _Part | None, names: list[str]) -> None:
        """Keep tokens ``a`` to ``b`` as the last statement mentioning each of ``names``."""
        reach = (
            self._part(set(direct.callees), set(direct.slots), set())
            if direct is not None
            else None
        )
        for level in range(HOP_DEPTH):
            if level:
                callees = set(reach.callees) if reach is not None else set()
                slots = set(reach.slots) if reach is not None else set()
                for name in names:
                    hop = self.last[level - 1].get(name)
                    if hop is not None:
                        callees |= hop.callees
                        slots |= hop.slots
                reach = self._part(callees, slots, set())
            if reach is None:
                continue
            for name in names:
                self._set(level, name, reach)

    def _guard(self, a: int, b: int) -> tuple[_Part, ...]:
        """The parts of the condition ``a`` to ``b``, kept as the last mention of its variables."""
        direct = self._direct(a, b, constants=True)
        names = self._variables(a, b)
        texts = self.texts
        assigned = {texts[k] for k in range(a, b - 1) if texts[k + 1] == "="}
        parts: dict[int, _Part] = {}
        if direct is not None:
            parts[id(direct)] = direct
        for name in names:
            if name in assigned:
                continue
            hop = self.last[HOP_DEPTH - 1].get(name)
            if hop is not None:
                parts.setdefault(id(hop), hop)
        self._register(a, b, direct, names)
        return tuple(parts.values())

    # -- statements --------------------------------------------------------

    def _stripped(self, a: int, b: int) -> tuple[int, int] | None:
        """Tokens ``a`` to ``b`` past their casts and opening parentheses: ``(start, opened)``.

        ``None`` when what follows the one operand left is anything but the
        parentheses that close the ones opened.
        """
        texts, kinds = self.texts, self.kinds
        opened = 0
        while a < b and texts[a] == "(":
            j = a + 1
            while j < b and kinds[j] == _NAME:
                j += 1
            while j < b and texts[j] == "*":
                j += 1
            if j > a + 1 and kinds[a + 1] == _NAME and j + 1 < b and texts[j] == ")":
                a = j + 1
            else:
                opened += 1
                a += 1
        operand = a + 1 if a < b and texts[a] != "-" else a + 2
        if operand > b or b - operand != opened:
            return None
        if any(texts[k] != ")" for k in range(operand, b)):
            return None
        return a, opened

    def _constant(self, a: int, b: int) -> tuple[int, str] | None:
        """``(value, as written)`` when tokens ``a`` to ``b`` are a constant, cast or not."""
        stripped = self._stripped(a, b)
        if stripped is None:
            return None
        texts, kinds = self.texts, self.kinds
        at = stripped[0]
        sign = ""
        if texts[at] == "-":
            sign, at = "-", at + 1
        if kinds[at] == _NUMBER:
            value = _number_value(texts[at])
            return (-value if sign else value), sign + texts[at]
        if texts[at] in ("true", "false") and not sign:
            return (1 if texts[at] == "true" else 0), texts[at]
        return None

    def _returned_name(self, a: int, b: int) -> str | None:
        """The variable tokens ``a`` to ``b`` return, cast or in parentheses, or ``None``."""
        stripped = self._stripped(a, b)
        if stripped is None or self.texts[stripped[0]] == "-":
            return None
        at = stripped[0]
        if self.kinds[at] != _NAME or self.texts[at] in _KEYWORDS:
            return None
        return self.texts[at]

    def _simple(self, a: int, b: int) -> None:
        """One statement, tokens ``a`` to ``b`` (its ``;`` aside)."""
        texts, kinds = self.texts, self.kinds
        guard = self.guards[-1] if self.guards else ()
        if texts[a] == "return":
            constant = self._constant(a + 1, b)
            if constant is not None:
                if guard:
                    self.exits.append((guard, *constant))
            else:
                name = self._returned_name(a + 1, b)
                if name is not None:
                    self.returned.add(name)
        elif guard and kinds[a] == _NAME and a + 1 < b and texts[a + 1] == "=":
            constant = self._constant(a + 2, b)
            if constant is not None:
                self.pending.append((texts[a], guard, *constant))
        self._register(a, b, self._direct(a, b, constants=False), self._variables(a, b))

    def _matching(self, i: int) -> int | None:
        """The ``)`` that closes the ``(`` at ``i``."""
        depth = 0
        texts = self.texts
        for j in range(i, self.n):
            if texts[j] == "(":
                depth += 1
            elif texts[j] == ")":
                depth -= 1
                if depth == 0:
                    return j
            elif texts[j] in ("{", "}", ";") and texts[i - 1] != "for":
                return None
        return None

    def body(self) -> int | None:
        """Where the first function body opens: a ``{`` right after a signature's ``)``."""
        try:
            opening = self.texts.index("{")
        except ValueError:
            return None
        return opening if opening and self.texts[opening - 1] == ")" else None

    def read(self) -> list[tuple[tuple[_Part, ...], int, str]] | None:
        """The exits of the first function body, or ``None`` when it does not parse."""
        texts, n = self.texts, self.n
        opening = self.body()
        if opening is None:
            return None
        # A frame: [kind, guard parts or None, undo mark].
        stack: list[list[Any]] = [[_BLOCK, None, len(self.undo)]]
        i = opening + 1
        done = False
        while stack:
            if done:
                top = stack[-1]
                kind = top[0]
                if kind == _BLOCK:
                    done = False
                    continue
                self._close(top)
                if kind == _THEN and i < n and texts[i] == "else":
                    top[0] = _ELSE
                    self._open(top)
                    i += 1
                    done = False
                    continue
                stack.pop()
                if kind == _DO:
                    if i + 1 >= n or texts[i] != "while" or texts[i + 1] != "(":
                        return None
                    closing = self._matching(i + 1)
                    if closing is None or closing + 1 >= n or texts[closing + 1] != ";":
                        return None
                    self._guard(i + 2, closing)
                    i = closing + 2
                continue
            if i >= n:
                return None
            word = texts[i]
            if word == "}":
                top = stack[-1]
                if top[0] != _BLOCK:
                    return None
                self._close(top)
                stack.pop()
                i += 1
                done = True
                if not stack:
                    break
                continue
            if word == "{":
                frame: list[Any] = [_BLOCK, None, 0]
                self._open(frame)
                stack.append(frame)
                i += 1
                continue
            if word == ";":
                i += 1
                done = True
                continue
            if word in ("goto", "else"):
                return None
            if word in _CONDITIONS and i + 1 < n and texts[i + 1] == "(":
                closing = self._matching(i + 1)
                if closing is None:
                    return None
                parts = self._guard(i + 2, closing)
                frame = [_THEN if word == "if" else _BODY, parts, 0]
                self._open(frame)
                stack.append(frame)
                i = closing + 1
                continue
            if word == "do":
                frame = [_DO, None, 0]
                self._open(frame)
                stack.append(frame)
                i += 1
                continue
            if word in ("case", "default"):
                j = i
                while j < n and texts[j] != ":":
                    j += 1
                if j >= n:
                    return None
                i = j + 1
                done = True
                continue
            if (
                self.kinds[i] == _NAME
                and i + 1 < n
                and texts[i + 1] == ":"
                and (i + 2 >= n or texts[i + 2] != ":")
            ):
                # A label where a statement starts.
                return None
            j, depth = i, 0
            while j < n:
                mark = texts[j]
                if mark in ("(", "["):
                    depth += 1
                elif mark in (")", "]"):
                    depth -= 1
                elif depth <= 0 and mark in (";", "{", "}"):
                    break
                j += 1
            if j >= n:
                return None
            self._simple(i, j)
            i = j + 1 if texts[j] == ";" else j
            done = True
        exits = list(self.exits)
        exits.extend(
            (guard, value, written)
            for name, guard, value, written in self.pending
            if name in self.returned
        )
        return exits

    def _open(self, frame: list[Any]) -> None:
        frame[2] = len(self.undo)
        if frame[1] is not None:
            self.guards.append(frame[1])

    def _close(self, frame: list[Any]) -> None:
        self._restore(frame[2])
        if frame[1] is not None:
            self.guards.pop()

    def called(self) -> set[tuple[str, int]]:
        """Every function and slot the whole listing calls, as ``("c"|"s", address)``."""
        part = self._direct(0, self.n, constants=False)
        if part is None:
            return set()
        return {("c", a) for a in part.callees} | {("s", a) for a in part.slots}


def listing_exits(
    text: str, slots: Mapping[int, str] | None = None
) -> list[tuple[int, str, tuple[int, ...], tuple[int, ...], tuple[int, ...]]] | None:
    """One listing's exits as ``(value, as written, callees, slots, constants)``.

    ``None`` when the listing says nothing (a label, a ``goto``, a body that
    does not parse, no body). ``slots`` are the slot addresses the run's
    function index resolved, with their names.
    """
    found = _read(text, _Labels(), slots or {})
    if found is None or found[0] is None:
        return None
    terms: dict[int, tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]] = {}
    out = []
    for parts, value, written in found[0]:
        # Once per condition: every exit under it shares its parts.
        if id(parts) not in terms:
            site = ExitSite(None, value, written, parts, None, 0, slots or {})
            terms[id(parts)] = (site.callees, site.slots, site.constants)
        out.append((value, written, *terms[id(parts)]))
    return out


def _read(
    text: str, labels: _Labels, slots: Mapping[int, str]
) -> tuple[list[tuple[tuple[_Part, ...], int, str]] | None, set[tuple[str, int]]] | None:
    """``(exits, called)`` of a listing, or ``None`` for a text with no function body.

    ``exits`` is ``None`` when the listing says nothing; ``called`` is every
    function and slot it calls, which a listing that says nothing still calls.
    """
    kinds, texts = _tokens(text)
    reader = _Reader(kinds, texts, labels, slots)
    if reader.body() is None:
        return None
    called = reader.called()
    return reader.read(), called


# ---------------------------------------------------------------------------
# An analyst's listings
# ---------------------------------------------------------------------------


def resolved_slots(
    names: Mapping[tuple[str, int], tuple[str, str] | None], bases: Sequence[int] = ()
) -> dict[int, str]:
    """The sample's slots the function index resolved, by offset and by each base's address.

    ``names`` is ``analysis.slot_names.slot_names``; a slot two names fill is
    a slot with no name (``""``).
    """
    out: dict[int, str] = {}
    for (where, offset), held in names.items():
        if where:
            continue
        name = held[0] if held is not None else ""
        for address in (offset, *(offset + base for base in bases)):
            out[address] = name
    return out


def _listings(entry: Any) -> list[tuple[Any, str]]:
    """``(function, listing)`` of each function one entry's answer lists."""
    from malspark.pipeline import validation as v

    output = str(getattr(entry, "output", "") or "")
    entry_id = str(getattr(entry, "id", "") or "")
    shown, batch = v._batch_listings(output)
    if shown:
        return [
            (v.DecompiledFunction(address, tuple(v._named(None, text, args={})), (entry_id,)), text)
            for address, text in batch.items()
        ]
    text = v._listing_text(output)
    if "{" not in text:
        return []
    functions = v._entry_functions(entry)
    if len(functions) != 1:
        return []
    address, names = functions[0]
    if address is None and not names:
        return []
    return [(v.DecompiledFunction(address, tuple(names), (entry_id,)), text)]


@dataclass(frozen=True)
class ListingsRead:
    """What an analyst's own listings hold: how many were read, and their exits."""

    listings: int
    exits: tuple[ExitSite, ...]


def exit_branches(entries: Iterable[Any], slots: Mapping[int, str]) -> list[ExitSite]:
    """The exits of every function the analyst's own entries list (:func:`read_listings`)."""
    return list(read_listings(entries, slots).exits)


def read_listings(entries: Iterable[Any], slots: Mapping[int, str]) -> ListingsRead:
    """The exits of every function the analyst's own entries list, read by shape.

    Every entry that answered and was shown is read, whatever its tool: the
    listing's shape decides (a repeat the guard answered holds no listing, and
    a text with no function body is none). A function listed twice is read
    once, from the first listing that says something: a cut listing, or one
    with a label, does not hide a later whole one. ``slots``:
    :func:`resolved_slots`.
    """
    labels = _Labels()
    read: dict[Any, tuple[Any, list[tuple[tuple[_Part, ...], int, str]]]] = {}
    # What each function's listing calls, once per function: the one read,
    # or the first that said nothing for a function no listing was read of.
    calls: dict[Any, set[tuple[str, int]]] = {}
    for entry in entries:
        if not getattr(entry, "ok", True) or answer_not_shown(entry):
            continue
        if getattr(entry, "repeated_of", None):
            continue
        for function, text in _listings(entry):
            key = function.address if function.address is not None else function.names[0]
            if key in read:
                continue
            found = _read(text, labels, slots)
            if found is None:
                continue
            exits, called = found
            if exits is None:
                calls.setdefault(key, called)
                continue
            read[key] = (function, exits)
            calls[key] = called
    fan: dict[tuple[str, int], int] = {}
    for called in calls.values():
        for term in called:
            fan[term] = fan.get(term, 0) + 1
    out: list[ExitSite] = []
    least: dict[int, int | None] = {}
    # Keyed once per condition, whose parts every exit under it shares: an
    # exit's own cost does not grow with the width of its condition.
    keys: dict[int, tuple[int, ...]] = {}
    fans: dict[int, int | None] = {}
    for function, exits in read.values():
        unique: dict[tuple[tuple[int, ...], int], tuple[tuple[_Part, ...], int, str]] = {}
        for parts, value, written in exits:
            if id(parts) not in keys:
                keys[id(parts)] = tuple(sorted(id(p) for p in parts))
            unique.setdefault((keys[id(parts)], value), (parts, value, written))
        same: dict[int, int] = {}
        for _parts, value, _written in unique.values():
            same[value] = same.get(value, 0) + 1
        for parts, value, written in unique.values():
            if id(parts) not in fans:
                known = [f for f in (_least_fan(p, fan, least) for p in parts) if f is not None]
                fans[id(parts)] = min(known) if known else None
            out.append(
                ExitSite(
                    function=function,
                    value=value,
                    written=written,
                    parts=parts,
                    fan_in=fans[id(parts)],
                    same_value=same[value],
                    apis=slots,
                )
            )
    return ListingsRead(listings=len(read), exits=tuple(out))


def _least_fan(
    part: _Part, fan: Mapping[tuple[str, int], int], held: dict[int, int | None]
) -> int | None:
    if id(part) not in held:
        counts = [fan.get(("c", a), 0) for a in part.callees]
        counts += [fan.get(("s", a), 0) for a in part.slots]
        held[id(part)] = min(counts) if counts else None
    return held[id(part)]


# ---------------------------------------------------------------------------
# Which exits a claim names
# ---------------------------------------------------------------------------


class _Claim:
    """What one claim's sentence and evidence line write: addresses, numbers, words."""

    def __init__(self, text: str, labels: _Labels) -> None:
        from malspark.pipeline import validation as v

        self.text = text
        self.addresses = set(v._addresses_written(text))
        runs = [m.group(1) for m in v._DIGIT_RUN.finditer(text)]
        self.digits = {run.lstrip("0") for run in runs}
        self.numbers = {int(run) for run in runs}
        self.numbers |= {int(m.group(1), 16) for m in v._HEX_ADDRESS.finditer(text)}
        self.words = set(_WORD.findall(text))
        # A slot named by its datum's label, as the listing writes it.
        for word in self.words:
            address = labels.datum(word)
            if address is not None:
                self.addresses.add(address)

    def names_address(self, address: int, bases: Sequence[int]) -> bool:
        """An address written as ``validation._named_by`` reads one, in constant time per base.

        With no image base known, an address 64 KiB away is not read as this
        one: a term is no function a claim names, and a claim naming only its
        function would name every callee a multiple of 64 KiB from it.
        """
        if address in self.addresses:
            return True
        if any(address + b in self.addresses or address - b in self.addresses for b in bases):
            return True
        spelled = f"{address:x}"
        return spelled.isdigit() and spelled.lstrip("0") in self.digits

    def names_api(self, name: str) -> bool:
        if not name:
            return False
        if _WORD.fullmatch(name):
            return name in self.words
        return re.search(r"(?<![\w])" + re.escape(name) + r"(?![\w])", self.text) is not None


def _part_named(part: _Part, claim: _Claim, apis: Mapping[int, str], bases: Sequence[int]) -> bool:
    return (
        any(claim.names_address(a, bases) for a in part.callees)
        or any(
            claim.names_address(a, bases) or claim.names_api(apis.get(a, "")) for a in part.slots
        )
        or any(abs(c) in claim.numbers for c in part.constants)
    )


def uncovered_exits(
    isr: Any, exits: Sequence[ExitSite], image_bases: Sequence[int] = ()
) -> list[ExitSite]:
    """The exits no one claim of ``isr`` names with their function, ranked.

    A claim names the function as ``validation.undescribed_decompiles`` reads
    it, and a term by an address written the same ways (a slot also by the API
    name the run resolved for it), or a constant by its value in hex with
    ``0x`` or in decimal. Ranked: a function some claim names first, then the
    fewest listings calling a term, then the most exits handing back the
    value, then the function and its entry.
    """
    if not exits:
        return []
    from malspark.pipeline import validation as v

    texts = [
        f"{getattr(claim, 'claim', '') or ''} {getattr(claim, 'evidence_ref', '') or ''}"
        for claim in (getattr(isr, "claims", None) or [])
    ]
    labels = _Labels()
    claims = [_Claim(text, labels) for text in texts]
    naming: dict[Any, frozenset[int]] = {}
    parts: dict[int, frozenset[int]] = {}
    conditions: dict[int, frozenset[int]] = {}
    left: list[tuple[tuple[Any, ...], int, ExitSite]] = []
    for order, site in enumerate(exits):
        function = site.function
        key = (function.address, function.names)
        if key not in naming:
            naming[key] = frozenset(
                i for i, text in enumerate(texts) if v._named_by(text, function, image_bases)
            )
        named = naming[key]
        # The claims naming a term of the condition, once per condition.
        if id(site.parts) not in conditions:
            claimed: set[int] = set()
            for part in site.parts:
                if id(part) not in parts:
                    parts[id(part)] = frozenset(
                        i
                        for i, claim in enumerate(claims)
                        if _part_named(part, claim, site.apis, image_bases)
                    )
                claimed |= parts[id(part)]
            conditions[id(site.parts)] = frozenset(claimed)
        if conditions[id(site.parts)] & named:
            continue
        rank = (
            0 if named else 1,
            site.fan_in if site.fan_in is not None else float("inf"),
            -site.same_value,
            function.address if function.address is not None else -1,
            function.names,
            function.entries,
        )
        left.append((rank, order, site))
    left.sort(key=lambda row: (row[0], row[1]))
    return [site for _rank, _order, site in left]


# ---------------------------------------------------------------------------
# The question
# ---------------------------------------------------------------------------


def _hex(value: int) -> str:
    return f"-{-value:#x}" if value < 0 else f"{value:#x}"


def _function_head(function: Any) -> str:
    """``0x… (a name; ev_0003)``: the function by its address, its own names and entries."""
    generic = declared_auto_name_pattern()
    said = [n for n in function.names if not generic.fullmatch(n)]
    head = hex(function.address) if function.address is not None else function.names[0]
    if function.address is None:
        said = said[1:] if said and said[0] == function.names[0] else said
    where = "; ".join([*said, *function.entries])
    return f"{safe_finding_value(head)}{f' ({where})' if where else ''}"


def _terms(site: ExitSite) -> str:
    """``calls 0x…, slot 0x… (Api), constant 0x…``: the terms of an exit's condition."""
    terms = [f"calls {_hex(a)}" for a in site.callees]
    for address in site.slots:
        api = site.apis.get(address, "")
        terms.append(f"slot {_hex(address)}" + (f" ({safe_finding_value(api)})" if api else ""))
    terms += [f"constant {_hex(c)}" for c in site.constants]
    return ", ".join(terms)


def exit_line(site: ExitSite) -> str:
    """``0x… (ev_0003) hands back -1 on a condition over calls 0x…, slot 0x… (Api)``."""
    head = _function_head(site.function)
    return f"{head} hands back {site.written} on a condition over {_terms(site)}"


def _listed(shown: Sequence[ExitSite]) -> list[str]:
    """The exits listed, grouped by function in the rank of each function's first.

    One piece per exit, each a value of its own bound: ``0x… (ev_0003) hands
    back -1 on [calls 0x…]``, then ``, 0 on [constant 0x…]`` for the same
    function and ``; 0x… hands back …`` for the next.
    """
    grouped: dict[Any, list[ExitSite]] = {}
    for site in shown:
        grouped.setdefault(site.function, []).append(site)
    pieces: list[str] = []
    for function, sites in grouped.items():
        for k, site in enumerate(sites):
            said = f"{site.written} on [{_terms(site)}]"
            if k:
                pieces.append(f", {said}")
            else:
                pieces.append(
                    f"{'; ' if pieces else ''}{_function_head(function)} hands back {said}"
                )
    return pieces


def exits_question(exits: Sequence[ExitSite]) -> str:
    """The exit part of the decompiled-functions question, for ``exits`` ranked.

    The ones listed are grouped by function, in the rank of each function's
    first. Each name is bounded as a finding value is: a tool wrote it.
    """
    shown = list(exits[:EXITS_LISTED])
    more = len(exits[EXITS_LISTED:])
    return (
        f"Of the functions you decompiled, {len(exits)} branch(es) end one with a constant on "
        "a condition, and no one claim names that function together with a term of the "
        "condition. Ranked, functions a claim names first, then by how few of your listings "
        "call the terms: "
        f"{''.join(safe_finding_value(piece) for piece in _listed(shown))}"
        f"{f'; and {more} more' if more else ''}. For each that "
        "matters, write one claim naming the function (by a name the decompiler gave it, or "
        "its address or offset from the image base in hex: with 0x, a trailing h, as bare hex "
        "digits, or inside the decompiler's generic name) and one of its terms (an address "
        "written the same ways or inside a data label, a slot's API name, or a constant in hex "
        "with 0x or in decimal), saying what the condition checks and what the function does "
        "when it holds. A branch that only handles a failed call or allocation, or that this "
        "analysis does not need, may stay undescribed."
    )
