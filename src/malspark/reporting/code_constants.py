"""The 32-bit values the sample stores in its own bytes that the run's tools read and named.

A drafted YARA rule that matches on the published indicators matches nothing
when the sample keeps them encoded: the strings are in the decoded text, not in
the file, and the rule then matches its sample by its hash alone, which says
nothing a hash lookup does not. What the file does hold, as it is, are the
values its code works with, and two kinds of answer state such values with the
places they stand (the consumer ``code_constants`` of
``core.builtin_declarations.CONSUMER_KINDS``):

* **A decoder's seed** (kind ``decoded_strings``, declared value ``seed``). A
  result decoded under a seed-and-length header states the seed, which the
  header stores in front of each encoded text. One seed is read once, with the
  number of results that state it.
* **A name hash** (kind ``api_hash_resolution``, declared values ``value``,
  ``algorithm``, ``name`` and ``set``). Each hit is a value stored in the file
  that equals a hash of a name under one or more algorithms, with every place
  it stands (``occurrences``). Its meaning says the set each reading was
  resolved in (``exports``, ``modules``) in the tool's own word, and says none
  when the row states none.

A meaning says what the tool reported, in the reader's voice and from the
answer's own fields, never what the value is: the tool's stated name, then for
a seed how many results state it and under which schemes, and for a hash the
algorithm, the names, the set words and how many values the tool matched under
that algorithm in the same answer.

How far an answer's own figures hold a value (T-872), which decides whether a
drafted rule matches on it (:func:`held`):

* a seed, where :data:`LEAST_RESULTS_PER_SEED` or more results of its answer
  state it;
* a hash, where the chance of its algorithm's count of matched values arising
  by chance, over the algorithms tried, is under :data:`CHANCE_BOUND`
  (:func:`chance_of_matches`), by the answer's figures of candidates tested and
  names tried (declared values ``candidates_tested``, ``names_tried`` and
  ``algorithms_tried``, read in the whole answer, not a row). An answer that
  leaves either of the first two figures out is held by the test below alone,
  of two values under one algorithm; one that states no algorithms tried is
  read as having tried the algorithms its rows state. A figure is a whole
  number given as a number or as text, or a list counted by its length; a
  pointer naming several numbers gives their sum (:func:`_count`). A figure
  too large to compute with gives the chance 1.

That standing is one test for the platform (T-850): :func:`hash_standing` gives
each value an answer of the ``api_hash_resolution`` kind matched its chance and
whether it is held, computed over every value the answer matched under each
algorithm, and the draft (:func:`held`), the triage pack's hand-off of names to
the API catalogue and the report's count of names resolved at runtime all read
it. It works from an answer, which always holds its figures; refusing a value
read back from a stored report is the draft's rule alone.

The chance, and the mark that the value was read from its answer in this
process, are kept on the value for the draft built in the same process and are
never written to the report document, which carries the words only. A hash read
back from a stored report keeps neither, so a draft does not match on it and
says why; what a stored draft left out is read from that draft's own closing
comment (``detection_signatures.stored_left_out``).

Each answer's rows and values are read where its declaration points them, and
where it points none, where the built-in tool of that kind keeps them; never by
a tool's name.

What is not read:

* an answer about a file the run carved out of the sample (the ``carved``
  argument its tool declares): it is about another file;
* a failed call, or an answer that states an error;
* a hash hit none of whose algorithms resolves a second distinct value in the
  same answer: a program that resolves functions by hash uses one algorithm for
  many, and a value alone under its algorithm is a chance match. The resolver's
  own ``lone_hits`` are not read either;
* a hit stated with no place in the file;
* a value too plain to tell one file from another: below 0x10000, or of fewer
  than three distinct bytes.

A name hash says how a program finds its imports, which many programs
share; it is drafted only together with a seed (``detection_signatures``). Each
value is kept once, at the first answer that states it, seeds first and then
hashes, each in the order of the ledger.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from malspark.core.tool_declarations import EVERY, ToolFacts, parse_path, select
from malspark.reporting import tool_kinds
from malspark.reporting.call_bindings import _field, _file_of
from malspark.reporting.models import CodeConstant

# The consumer whose declared kinds are read here, and the two of them.
_CONSUMER = "code_constants"
_DECODED = "decoded_strings"
_HASHES = "api_hash_resolution"
# Where the built-in tool of each kind keeps its rows and values, read where a
# declaration names none.
_DEFAULT_ROWS = {_DECODED: "/results/*", _HASHES: "/hits/*"}
_SEED = "/parameters/seed"
_VALUE = "/value"
_ALGORITHM = "/readings/*/algorithm"
_NAME = "/readings/*/name"
_SET = "/readings/*/set"
_OFFSETS = "/occurrences/*/offset"
_ROW_OFFSET = "/offset"
_SCHEME = "/scheme"
# Where the built-in resolver states, in its whole answer, how many candidate
# values it tested, how many names it hashed and which algorithms it tried.
_CANDIDATES_TESTED = "/candidates/scanned"
_NAMES_TRIED = "/names/names"
_ALGORITHMS_TRIED = "/algorithms"

# The fewest results of its answer that state a seed for a draft to match on it.
LEAST_RESULTS_PER_SEED = 2
# The chance, by its answer's own figures, under which a hash's reading is held
# for a draft to match on it. Measured on stored answers of two kinds: an
# answer whose matches chance explains (a chance near one in four) and one
# whose matches it does not (far under one in a million); the decision is the
# same for every bound from one in a million to one in ten.
CHANCE_BOUND = 0.001
# How many 32-bit values there are: one equals a given hash with a chance of
# one in this many.
_VALUES = float(1 << 32)
# How many terms a tail past the mean is summed over at most; past the mean
# each term is smaller than the last, and the sum stops once one adds nothing.
_TAIL_TERMS = 100_000

# A value below this is a count, a size or a flag far more often than a seed.
_LEAST = 0x10000
# The fewest distinct bytes a value keeps to tell one file from another.
_LEAST_DISTINCT_BYTES = 3
# How many distinct values one algorithm resolves in an answer before a hit
# under it is read.
_LEAST_PER_ALGORITHM = 2
# How many names, sets or algorithms one hash's meaning lists, and the longest
# word it prints.
_NAMES_SAID = 3
# The characters a word never carries: format characters (a bidi override, a
# zero-width joiner) and line and paragraph separators.
_DROPPED = frozenset({"Cf", "Zl", "Zp"})
_WORD_CHARS = 64
# A count stated as text: decimal digits, or ``0x``-prefixed hexadecimal.
_DECIMAL_RE = re.compile(r"[0-9]+")
#: Text of more digits, decimal or hexadecimal, is past what the chance is computed
#: with (and past what the interpreter converts from decimal text); such a figure is
#: read by one lower bound, whatever its length.
_DIGITS_READ = 400
_PAST_READING = 10**_DIGITS_READ
_HEX_RE = re.compile(r"0x[0-9a-f]+")


def code_constants_from_ledger(ledger: Iterable[Any] | None) -> list[CodeConstant]:
    """Every distinct 32-bit value the sample stores that a decoder or a hash resolver states."""
    seeds: list[CodeConstant] = []
    hashes: list[CodeConstant] = []
    seen: set[int] = set()
    for entry in ledger or ():
        if not bool(_field(entry, "ok")) or not tool_kinds.is_of(entry, _CONSUMER):
            continue
        facts = tool_kinds.facts_of(entry)
        if facts is None or _file_of(entry, facts):
            continue
        data = _field(entry, "structured")
        if not isinstance(data, Mapping) or data.get("error"):
            continue
        rows = [
            row
            for row in select(data, facts.rows or _DEFAULT_ROWS.get(facts.kind, ""))
            if isinstance(row, Mapping)
        ]
        values = facts.values or {}
        said = _Said(
            entry=str(_field(entry, "entry_id") or _field(entry, "id") or ""),
            tool=tool_kinds.stated_name(entry, facts),
            called=tool_kinds.tool_of(entry),
        )
        if facts.kind == _DECODED:
            seeds.extend(_seeds(rows, str(values.get("seed") or _SEED), said, seen))
        elif facts.kind == _HASHES:
            value_path = str(values.get("value") or _VALUE)
            algorithm_path = str(values.get("algorithm") or _ALGORITHM)
            hashes.extend(
                _hashes(
                    rows,
                    value_path,
                    algorithm_path,
                    str(values.get("name") or _NAME),
                    str(values.get("set") or _SET),
                    said,
                    seen,
                    _standing(rows, value_path, algorithm_path, _figures(data, values)),
                )
            )
    for constant in (*seeds, *hashes):
        constant.built = True
    return [*seeds, *hashes]


def held(constant: CodeConstant) -> bool:
    """Whether its answer's own figures hold a value for a drafted rule to match on.

    A seed where :data:`LEAST_RESULTS_PER_SEED` or more results state it
    (``places``); a hash read from its answer in this process where its chance
    is under :data:`CHANCE_BOUND`, or where none was kept because its answer
    states no figures. A hash read back from a stored report is not held: the
    report does not keep its answer's figures (:func:`read_back`).
    """
    if constant.role == "seed":
        return constant.places >= LEAST_RESULTS_PER_SEED
    if read_back(constant):
        return False
    # The chance is its answer's standing (:func:`hash_standing`); a drafted
    # hash stands under an algorithm that resolves a second value it reads.
    return _holds(constant.chance, paired=True)


def read_back(constant: CodeConstant) -> bool:
    """Whether a hash was read back from a stored report rather than from its answer."""
    return constant.role == "hash" and not constant.built


@dataclass(frozen=True)
class Standing:
    """How far its answer's own figures hold a value, or an algorithm's count of matches.

    ``chance`` is the chance of the algorithm's count of matched values
    arising by chance, over the algorithms tried (:func:`chance_of_matches`):
    for a value, the least of its algorithms'; ``None`` where the answer
    states no candidates tested or no names tried. ``held`` is whether it is
    under :data:`CHANCE_BOUND`, and with no figures whether the algorithm
    matched a second distinct value.
    """

    chance: float | None
    held: bool


@dataclass(frozen=True)
class HashStanding:
    """The standing of every value one hash resolution matched, and of each algorithm.

    ``matched`` is how many distinct values the answer matched under each
    algorithm, the count each chance is computed on.
    """

    values: Mapping[int, Standing]
    algorithms: Mapping[str, Standing]
    matched: Mapping[str, int]

    def of(self, value: Any) -> Standing | None:
        """The standing of a value as a row states it (int, ``0x`` text or decimal text)."""
        number = _number(value)
        return None if number is None else self.values.get(number)

    def holds(self, value: Any) -> bool:
        """Whether a value as a row states it is held; ``False`` for one the answer matched not."""
        standing = self.of(value)
        return standing is not None and standing.held

    def reads(self, value: Any, algorithm: Any) -> bool:
        """Whether a value as a row states it is held under the algorithm one reading names.

        Each algorithm keeps its own names: a value held under one algorithm
        does not carry a name another algorithm reads at chance.
        """
        stood = self.algorithms.get(_word(algorithm))
        return self.of(value) is not None and stood is not None and stood.held


def hash_standing(entry: Any) -> HashStanding | None:
    """Each value an answer of the ``api_hash_resolution`` kind matched, with its standing.

    The one held test of a hash value for the platform. Read from the
    entry's answer where its declaration points (rows, ``value``,
    ``algorithm``, and the figures ``candidates_tested``, ``names_tried`` and
    ``algorithms_tried``), where it points none where the built-in resolver
    keeps them; never by a tool's name. ``None`` for a failed call, an answer
    that states an error, or an entry of another kind.
    """
    if not bool(_field(entry, "ok")):
        return None
    facts = tool_kinds.facts_of(entry)
    if facts is None or facts.kind != _HASHES:
        return None
    data = _field(entry, "structured")
    if not isinstance(data, Mapping) or data.get("error"):
        return None
    return answer_standing(data, facts)


def answer_standing(data: Mapping[str, Any], facts: ToolFacts | None = None) -> HashStanding:
    """:func:`hash_standing` of one answer, read where ``facts`` points.

    With no ``facts``, where the built-in resolver keeps its rows, values and
    figures: for a line that renders that resolver's own answer.
    """
    values = (facts.values if facts is not None else None) or {}
    rows_path = (facts.rows if facts is not None else None) or _DEFAULT_ROWS[_HASHES]
    rows = [row for row in select(data, rows_path) if isinstance(row, Mapping)]
    return _standing(
        rows,
        str(values.get("value") or _VALUE),
        str(values.get("algorithm") or _ALGORITHM),
        _figures(data, values),
    )


def _holds(chance: float | None, *, paired: bool) -> bool:
    """The held test: a chance under :data:`CHANCE_BOUND`; with none, a second value paired."""
    return paired if chance is None else chance < CHANCE_BOUND


def _figures(data: Mapping[str, Any], values: Mapping[str, Any]) -> _Figures:
    """The figures a hash answer states of its scan, where its declaration points them."""
    return _Figures(
        candidates=_count(data, str(values.get("candidates_tested") or _CANDIDATES_TESTED)),
        names=_count(data, str(values.get("names_tried") or _NAMES_TRIED)),
        algorithms=_count(data, str(values.get("algorithms_tried") or _ALGORITHMS_TRIED)),
    )


def _standing(
    rows: list[Mapping[str, Any]], value_path: str, algorithm_path: str, figures: _Figures
) -> HashStanding:
    """Every distinct value matched under each algorithm, read or not, and its standing.

    An algorithm's chance is that of its count of matched values; a value's,
    the least of its algorithms'. A value its row states under no algorithm
    is matched under none and is not held.
    """
    matched: dict[str, set[int]] = {}
    of_value: dict[int, set[str]] = {}
    for row in rows:
        number = _first_number(row, value_path)
        if number is None:
            continue
        algorithms = {_word(a) for a in select(row, algorithm_path)} - {""}
        of_value.setdefault(number, set()).update(algorithms)
        for algorithm in algorithms:
            matched.setdefault(algorithm, set()).add(number)
    by_algorithm: dict[str, Standing] = {}
    for algorithm, numbers in matched.items():
        chance = figures.chance(len(numbers), len(matched))
        paired = len(numbers) >= _LEAST_PER_ALGORITHM
        by_algorithm[algorithm] = Standing(chance, _holds(chance, paired=paired))
    by_value: dict[int, Standing] = {}
    for number, algorithms in of_value.items():
        stood = [by_algorithm[a] for a in sorted(algorithms)]
        known = [s.chance for s in stood if s.chance is not None]
        by_value[number] = Standing(min(known) if known else None, any(s.held for s in stood))
    return HashStanding(by_value, by_algorithm, {a: len(n) for a, n in matched.items()})


def chance_of_matches(matched: int, candidates: int, names: int, algorithms: int) -> float:
    """The chance that ``matched`` or more values match one algorithm by chance, over all tried.

    Each of ``candidates`` 32-bit values equals one of ``names`` hashes under
    one algorithm with the chance ``names / 2**32``, so the count of values one
    algorithm matches by chance is close to Poisson with the mean
    ``lam = candidates * names / 2**32``, and the chance of ``matched`` or more
    is the tail ``P(X >= matched) = 1 - sum(exp(-lam) * lam**i / i! for i < matched)``.
    The chance that any of ``algorithms`` reaches it is at most ``algorithms``
    times that tail (the union bound, which holds whatever the algorithms share),
    and is capped at 1. A tail far past the mean is summed term by term from
    ``matched`` up, each term in logarithms, so it is not lost to rounding. A
    figure too large to compute with gives 1: such a scan explains any count.
    """
    if matched <= 0:
        return 1.0
    try:
        lam = float(max(0, candidates)) * float(max(0, names)) / _VALUES
        tried = float(max(1, algorithms))
    except OverflowError:
        return 1.0
    if not math.isfinite(lam):
        return 1.0
    if lam == 0.0:
        return 0.0

    def term(i: int) -> float:
        return math.exp(-lam + i * math.log(lam) - math.lgamma(i + 1))

    if matched > lam:
        # Past the mean each term is lam / (i + 1) of the last, under one.
        tail = 0.0
        for i in range(matched, matched + _TAIL_TERMS):
            step = term(i)
            tail += step
            if step <= tail * 1e-17:
                break
    else:
        tail = max(0.0, 1.0 - sum(term(i) for i in range(matched)))
    chance = tried * tail
    return min(1.0, chance) if math.isfinite(chance) else 1.0


def little_endian(value: Any) -> bytes | None:
    """The four bytes a value is stored as, little-endian; ``None`` for no 32-bit value."""
    number = _number(value)
    if number is None:
        return None
    return number.to_bytes(4, "little")


class _Said:
    """The answer a value is read from: its entry, its tool's stated name and the name called."""

    def __init__(self, entry: str, tool: str, called: str = "") -> None:
        self.entry = entry
        self.tool = tool
        self.called = called

    @property
    def subject(self) -> str:
        """The tool a meaning opens with: its stated name, else the name its entry records.

        One clean, capped word either way.
        """
        return _word(self.tool) or _word(self.called) or "the tool"


class _Figures:
    """What a hash answer states of its scan: candidates tested, names and algorithms tried."""

    def __init__(self, candidates: int | None, names: int | None, algorithms: int | None) -> None:
        self.candidates = candidates
        self.names = names
        self.algorithms = algorithms

    def chance(self, matched: int, algorithms_stated: int) -> float | None:
        """The chance of ``matched`` values under one algorithm; ``None`` without both figures."""
        if not self.candidates or not self.names:
            return None
        tried = max(self.algorithms or 0, algorithms_stated, 1)
        return chance_of_matches(matched, self.candidates, self.names, tried)


def _seeds(
    rows: list[Mapping[str, Any]], path: str, said: _Said, seen: set[int]
) -> list[CodeConstant]:
    """The seeds a decoder's results state, each once, with how many results state it."""
    counted: dict[int, list[Mapping[str, Any]]] = {}
    for row in rows:
        number = _first_number(row, path)
        if number is None or not _telling(number) or number in seen:
            continue
        counted.setdefault(number, []).append(row)
    out: list[CodeConstant] = []
    for number, stating in counted.items():
        seen.add(number)
        schemes = sorted({_word(_first(row, _SCHEME)) for row in stating} - {""})
        under = f" ({', '.join(schemes)})" if schemes else ""
        count = len(stating)
        out.append(
            CodeConstant(
                value=f"{number:#010x}",
                role="seed",
                meaning=(
                    f"{said.subject} read it as the seed in the header of {count} encoded "
                    f"string{'s' if count != 1 else ''} it decoded{under}"
                ),
                entry=said.entry,
                tool=said.tool,
                first_offset=_word(_first(stating[0], _ROW_OFFSET)),
                places=count,
            )
        )
    return out


def _hashes(
    rows: list[Mapping[str, Any]],
    value_path: str,
    algorithm_path: str,
    name_path: str,
    set_path: str,
    said: _Said,
    seen: set[int],
    standing: HashStanding,
) -> list[CodeConstant]:
    """The values a hash resolver's hits state under an algorithm that resolves two or more.

    Each with its chance from the answer's standing (:func:`_standing`),
    whose count of every distinct value matched under each algorithm, read or
    not, is also the count a meaning states.
    """
    read: list[tuple[int, list[str], list[Any], Mapping[str, Any]]] = []
    resolved: dict[str, set[int]] = {}
    # Only a value that is read at all counts toward its algorithm's two: a
    # plain value, or one stated with no place, is no second resolution.
    for row in rows:
        number = _first_number(row, value_path)
        if number is None:
            continue
        algorithms = sorted({_word(a) for a in select(row, algorithm_path)} - {""})
        if not _telling(number):
            continue
        offsets = [o for o in select(row, _OFFSETS) if o not in (None, "")]
        if not offsets:
            continue
        for algorithm in algorithms:
            resolved.setdefault(algorithm, set()).add(number)
        read.append((number, algorithms, offsets, row))
    out: list[CodeConstant] = []
    for number, algorithms, offsets, row in read:
        if not any(len(resolved[a]) >= _LEAST_PER_ALGORITHM for a in algorithms):
            continue
        if number in seen:
            continue
        seen.add(number)
        names = _names(select(row, name_path))
        # The set each reading was resolved in, in the tool's own word: a list of sets is
        # read as its words, and they are said as the names are, the rest counted.
        sets = _sets(select(row, set_path))
        counts = [(a, standing.matched[a]) for a in algorithms]
        meaning = _hash_meaning(said.subject, counts, names, sets)
        if len(counts) > 1:
            readings = _by_algorithm(row, algorithm_path, name_path, set_path)
            if readings is not None:
                meaning = _readings_meaning(said.subject, counts, readings)
        constant = CodeConstant(
            value=f"{number:#010x}",
            role="hash",
            meaning=meaning,
            entry=said.entry,
            tool=said.tool,
            first_offset=_word(offsets[0]),
            places=len(offsets),
        )
        constant.chance = standing.values[number].chance
        out.append(constant)
    return out


def _hash_meaning(
    subject: str, counts: list[tuple[str, int]], names: list[str], sets: list[str]
) -> str:
    """``<tool> read it as the <algorithm> hash of <names> (set <sets>), one of <n> values …``.

    Said from the hit's own row and its answer: its algorithms with how many
    values the tool matched under each, its names and the sets it was resolved
    in, each list cut at :data:`_NAMES_SAID` with the rest counted. Under
    several algorithms whose readings cannot be told apart
    (:func:`_by_algorithm`), the row's names are said once for all of them.
    """
    listed = _listed(names)
    said_in = f" (set {_listed(sets)})" if sets else ""
    if len(counts) == 1:
        ((algorithm, count),) = counts
        reading = _reading(algorithm, names, sets)
        return f"{subject} read it as {reading}, {_among(count)} under that algorithm"
    under = [f"{a} ({_among(count)} under it)" for a, count in counts[:_NAMES_SAID]]
    if len(counts) > _NAMES_SAID:
        algorithms = f"{', '.join(under)} and {len(counts) - _NAMES_SAID} more"
    else:
        algorithms = f"{', '.join(under[:-1])} and {under[-1]}"
    reading = f"a hash of {listed}{said_in}" if listed else f"a hash with no name stated{said_in}"
    return f"{subject} read it as {reading} under {algorithms}"


def _readings_meaning(
    subject: str,
    counts: list[tuple[str, int]],
    readings: Mapping[str, tuple[list[str], list[str]]],
) -> str:
    """``<tool> read it as the <a> hash of <names> …, and as the <b> hash of <names> …``.

    Each algorithm with its own names and sets and how many values the tool
    matched under it, the algorithms cut at :data:`_NAMES_SAID` with the rest
    counted; names its row states under no algorithm are said last as such.
    """
    parts = []
    for algorithm, count in counts[:_NAMES_SAID]:
        names, sets = readings.get(algorithm, ([], []))
        parts.append(f"{_reading(algorithm, names, sets)}, {_among(count)} under that algorithm")
    said = ", and as ".join(parts)
    if len(counts) > _NAMES_SAID:
        rest = len(counts) - _NAMES_SAID
        said += f", and under {rest} more algorithm{'s' if rest != 1 else ''}"
    names, sets = readings.get("", ([], []))
    if names:
        said_in = f" (set {_listed(sets)})" if sets else ""
        said += f", and as a hash of {_listed(names)}{said_in} with no algorithm stated"
    return f"{subject} read it as {said}"


def _reading(algorithm: str, names: list[str], sets: list[str]) -> str:
    """``the <algorithm> hash of <names> (set <sets>)``, or ``a <algorithm> hash …`` with none."""
    listed = _listed(names)
    said_in = f" (set {_listed(sets)})" if sets else ""
    if listed:
        return f"the {algorithm} hash of {listed}{said_in}"
    return f"a {algorithm} hash with no name stated{said_in}"


def _by_algorithm(
    row: Mapping[str, Any], algorithm_path: str, name_path: str, set_path: str
) -> dict[str, tuple[list[str], list[str]]] | None:
    """Each algorithm's own names and sets in a hit's row, read reading by reading.

    Where the algorithm, name and set paths name fields of the same readings
    (they share their path down to a ``*``), each reading's names and sets go
    with its own algorithms, and names a reading states under no algorithm
    under ``""``. ``None`` where the paths share no such reading: the row then
    does not say which name went with which algorithm.
    """
    try:
        paths = [parse_path(p, in_row=True) for p in (algorithm_path, name_path, set_path)]
    except ValueError:
        return None
    shared = 0
    for i, parts in enumerate(zip(*paths, strict=False)):
        if len(set(parts)) != 1:
            break
        if parts[0] == EVERY:
            shared = i + 1
    if not shared:
        return None
    read: dict[str, tuple[list[Any], list[Any]]] = {}
    for reading in select(row, paths[0][:shared]):
        algorithms = sorted({_word(a) for a in _under(reading, paths[0][shared:])} - {""})
        for algorithm in algorithms or [""]:
            names, sets = read.setdefault(algorithm, ([], []))
            names.extend(_under(reading, paths[1][shared:]))
            sets.extend(_under(reading, paths[2][shared:]))
    return {a: (_names(names), _sets(sets)) for a, (names, sets) in read.items()}


def _under(node: Any, rest: tuple[Any, ...]) -> list[Any]:
    """What the rest of a path names under one reading; the reading itself for no rest."""
    return select(node, rest) if rest else [node]


def _names(stated: list[Any]) -> list[str]:
    """The names stated, each as one clean word, once, in the row's order."""
    names: list[str] = []
    for name in stated:
        word = _word(name)
        if word and word not in names:
            names.append(word)
    return names


def _sets(stated: list[Any]) -> list[str]:
    """The set words stated, a list of sets read as its words, sorted, each once."""
    flat = [w for value in stated for w in (value if isinstance(value, list) else [value])]
    return sorted({_word(w) for w in flat} - {""})


def _listed(words: list[str]) -> str:
    """``a, b, c`` and the rest counted past :data:`_NAMES_SAID`."""
    listed = ", ".join(words[:_NAMES_SAID])
    if len(words) > _NAMES_SAID:
        listed += f" and {len(words) - _NAMES_SAID} more"
    return listed


def _among(count: int) -> str:
    """``one of <n> values it matched``, or ``the only value it matched`` for one."""
    return "the only value it matched" if count == 1 else f"one of {count} values it matched"


def _count(data: Mapping[str, Any], path: str) -> int | None:
    """A figure the answer states at ``path``: a whole number, or the length of a list.

    A pointer naming one list gives its length; naming several values, their
    sum where every one is a whole number (:func:`_whole`), and none where one
    is not. ``None`` where the answer states none, or no number above zero.
    """
    found = select(data, path)
    if len(found) == 1 and isinstance(found[0], list):
        return len(found[0]) or None
    numbers = [_whole(value) for value in found]
    if not numbers or any(number is None for number in numbers):
        return None
    total = sum(number for number in numbers if number is not None)
    return total if total > 0 else None


def _whole(value: Any) -> int | None:
    """A count as it is stated: an int, a finite float with no fraction, or digits as text.

    ``None`` for anything else: a bool, a negative number, NaN or infinity, a
    fraction, or other text. Text may be decimal or ``0x``-prefixed hexadecimal,
    of any length: it is never refused for its length.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        number = int(value)
    elif isinstance(value, str):
        text = value.strip().lower()
        if _DECIMAL_RE.fullmatch(text):
            digits, base = text.lstrip("0") or "0", 10
        elif _HEX_RE.fullmatch(text):
            digits, base = text[2:].lstrip("0") or "0", 16
        else:
            return None
        # Past that many digits the figure is read by one lower bound, already
        # too large to compute with, as the figure itself is.
        number = _PAST_READING if len(digits) > _DIGITS_READ else int(digits, base)
    else:
        return None
    return number if number >= 0 else None


def _first(row: Mapping[str, Any], path: str) -> Any:
    found = select(row, path)
    return found[0] if found else None


def _first_number(row: Mapping[str, Any], path: str) -> int | None:
    return _number(_first(row, path))


def _number(value: Any) -> int | None:
    """A 32-bit value given as an int, as ``0x``-prefixed hexadecimal or as decimal text."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip().lower()
        try:
            number = int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError:
            return None
    else:
        return None
    return number if 0 <= number <= 0xFFFFFFFF else None


def _telling(number: int) -> bool:
    """Whether a value can tell one file from another: not small, and of three distinct bytes."""
    stored = number.to_bytes(4, "little")
    return number >= _LEAST and len(set(stored)) >= _LEAST_DISTINCT_BYTES


def _word(value: Any) -> str:
    """A tool's word on one line: whitespace collapsed, markup and separators replaced, capped."""
    flat = " ".join(str(value if value is not None else "").split())
    kept = "".join(c for c in flat if unicodedata.category(c) not in _DROPPED)
    return "".join("_" if c in '`|<>*[]{}\\"/' or c < " " else c for c in kept)[:_WORD_CHARS]
