"""The bytes a text writes, read by their shape, and whether they hold a value.

A tool may answer with the bytes it read rather than the text they are: a hex
string, a column of hex pairs, a list of numbers, a C literal of ``\\xNN``
escapes. A value a model wrote from such an answer is in those bytes and in no
spelling of the text. This module reads the bytes a text writes by its shape
alone, never by a tool, a field name or an entry's kind, so a tool nobody
declared is read the same way, and says whether they hold a value whole and
whether chance explains that. It spells no value, and no search but the one
that asks it reads it.

Read (:func:`byte_runs`):

* a token of hex pairs, unspaced (an even number of digits, two or more pairs,
  no letter, digit or ``_`` before or after it) or spaced (two-digit pairs, each
  one space from the next), in either case;
* a JSON array of two or more whole numbers, each 0-255;
* a run of two or more ``\\xNN`` escapes written at a byte-escape level: in a
  JSON text, where the string it stands in, read, writes one backslash before
  the ``x`` (backslash parity counted), and in other text where an odd run of
  backslashes stands before it;
* in a JSON text, a whole number written in decimal digits, read as a token.

Not read (a value written so is not found, never found by mistake): ``0x2f``
lists, brace arrays, octal, percent and entity escapes, UTF-16BE, base64 (its
shape cannot be told from words, and a lower-cased text cannot be decoded), and
a value split across two strings.

A run's bytes are decoded as UTF-8 and as UTF-16LE at either byte alignment,
a byte that decodes to nothing becoming a replacement character, which bounds
a value. A run's own end bounds a value only where the run ends its JSON
string or array, or the text; a line break, a column gap, or the split of one
run between a list's consecutive rows, at any depth below them, bounds
nothing: there the value must be bounded by a byte of the run. The end of
what a tool returned bounds a value, as the end of a text does.

The chance (:func:`chance_in`) is that of the runs spelling the value at one
place or more at random, each run over the symbols its token is written with:
a token of decimal digits alone writes one of a hundred bytes per pair, every
other shape one of 256. The arithmetic is the platform's one chance
(``reporting.code_constants.chance_of_spelling``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from typing import Any


@dataclass(frozen=True)
class ByteRun:
    """The bytes one run of a text writes, the symbols each was drawn from, and its ends.

    ``opens`` and ``closes`` say whether the run's first and last byte stand
    at an end that bounds a value: the start or the end of its JSON string or
    array, or of the text.
    """

    data: bytes
    symbols: int
    opens: bool
    closes: bool


# A token of hex digits, and a whole number of decimal digits.
_HEX_TOKEN_RE = re.compile(r"(?<![0-9a-z_])[0-9a-f]+(?![0-9a-z_])")
_DECIMAL_RE = re.compile(r"[0-9]+")
# A run of ``\xNN`` escapes, each with the backslashes written before it: a
# match begins only where no backslash stands before it, so a run of
# backslashes is read once, never again from each of its backslashes.
_BYTE_ESCAPE_RE = re.compile(r"(?<!\\)(\\+)x([0-9a-f]{2})")
# The fewest bytes a run is read with.
_LEAST_BYTES = 2
# The symbols a byte is one of: any, or the hundred two decimal digits write.
_ANY_BYTE = 256
_DECIMAL_BYTE = 100


def byte_runs(text: str) -> list[ByteRun]:
    """Every byte run ``text`` writes, by shape; read through its JSON where it is JSON.

    In a JSON text each string, each array of numbers and each whole number is
    read on its own, its ends being the ends of the string or the array; a run
    that ends one row of a list where the same place of the next row (the same
    key or list item, at any depth) begins with one is split between them, and
    those two ends bound nothing. Any other
    text is read as one string, its ends being the text's.
    """
    lowered = str(text or "").lower()
    try:
        parsed: Any = json.loads(lowered)
    except (ValueError, TypeError, RecursionError):
        parsed = None
    if isinstance(parsed, bool) or not isinstance(parsed, dict | list | str | int):
        return _runs_of_string(lowered)
    found: list[ByteRun] = []
    try:
        _read_node(parsed, found)
    except RecursionError:
        # Nested past what can be walked: read as text, its ends the text's.
        return _runs_of_string(lowered)
    return found


def _read_node(node: Any, found: list[ByteRun]) -> Any:
    """Read one JSON value's runs into ``found``; where they stand there, for its list to join.

    A string, a whole number and a list of numbers give the span of their runs
    in ``found``; an object gives its members' spans by key, any other list
    its items' in order; anything else gives nothing.
    """
    if isinstance(node, str):
        start = len(found)
        found.extend(_runs_of_string(node))
        return (start, len(found))
    if isinstance(node, int) and not isinstance(node, bool):
        start = len(found)
        found.extend(_runs_of_number(node))
        return (start, len(found))
    if isinstance(node, dict):
        return {key: _read_node(item, found) for key, item in node.items()}
    if not isinstance(node, list):
        return None
    numbers = _numbers_of(node)
    if numbers is not None:
        found.append(ByteRun(bytes(numbers), _ANY_BYTE, True, True))
        return (len(found) - 1, len(found))
    rows = [_read_node(item, found) for item in node]
    for row, following in zip(rows, rows[1:], strict=False):
        for one, other in _same_places(row, following):
            _split(found, one, other)
    return rows


def _same_places(row: Any, following: Any) -> Iterator[tuple[tuple[int, int], tuple[int, int]]]:
    """The places two consecutive rows of a list share, at any depth.

    The rows themselves, a member's key, and an item's place in a list, each
    compared again below it as the rows are: a run split between two rows one
    object or list down is split as one at the top.
    """
    if isinstance(row, tuple) and isinstance(following, tuple):
        yield row, following
    elif isinstance(row, dict) and isinstance(following, dict):
        for key in row:
            if key in following:
                yield from _same_places(row[key], following[key])
    elif isinstance(row, list) and isinstance(following, list):
        for one, other in zip(row, following, strict=False):
            yield from _same_places(one, other)


def _split(found: list[ByteRun], one: tuple[int, int], other: tuple[int, int]) -> None:
    """Where a run ends one row and a run begins the next at the same place, one run split:
    neither of the two ends bounds a value."""
    if one[1] <= one[0] or other[1] <= other[0]:
        return
    last, first = found[one[1] - 1], found[other[0]]
    if last.closes and first.opens:
        found[one[1] - 1] = replace(last, closes=False)
        found[other[0]] = replace(first, opens=False)


def _numbers_of(node: Any) -> list[int] | None:
    """A list of two or more whole numbers each 0-255, or ``None``."""
    if not isinstance(node, list) or len(node) < _LEAST_BYTES:
        return None
    if all(
        isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255 for item in node
    ):
        return list(node)
    return None


def _runs_of_number(number: int) -> list[ByteRun]:
    """A whole number written in decimal digits, read as a token of them."""
    if number < 0:
        return []
    digits = str(number)
    if len(digits) % 2 or len(digits) < 2 * _LEAST_BYTES:
        return []
    return [ByteRun(bytes.fromhex(digits), _DECIMAL_BYTE, True, True)]


def _runs_of_string(text: str) -> list[ByteRun]:
    """The hex-pair and ``\\xNN`` runs one string writes, its own ends bounding a value."""
    first = len(text) - len(text.lstrip())
    last = len(text.rstrip())
    runs: list[tuple[int, int, bytes, int]] = []
    tokens = list(_HEX_TOKEN_RE.finditer(text))
    at = 0
    while at < len(tokens):
        token = tokens[at]
        digits = token.group()
        if len(digits) == 2:
            # Two-digit pairs, each one space from the next: one column of bytes.
            end = at
            while (
                end + 1 < len(tokens)
                and len(tokens[end + 1].group()) == 2
                and tokens[end + 1].start() == tokens[end].end() + 1
                and text[tokens[end].end()] == " "
            ):
                end += 1
            if end > at:
                pairs = "".join(t.group() for t in tokens[at : end + 1])
                span = (token.start(), tokens[end].end())
                runs.append((*span, bytes.fromhex(pairs), _symbols(pairs)))
            at = end + 1
            continue
        if len(digits) % 2 == 0 and len(digits) >= 2 * _LEAST_BYTES:
            runs.append((token.start(), token.end(), bytes.fromhex(digits), _symbols(digits)))
        at += 1
    runs.extend(_escape_runs(text))
    return [
        ByteRun(data, symbols, opens=start <= first, closes=end >= last)
        for start, end, data, symbols in sorted(runs, key=lambda run: run[0])
    ]


def _escape_runs(text: str) -> Iterator[tuple[int, int, bytes, int]]:
    """The runs of ``\\xNN`` escapes written at a byte-escape level, one after the other.

    ``text`` is a JSON string as read or a text as written: either way an odd
    run of backslashes before the ``x`` writes a byte, and an even one writes
    backslashes and the letters after them. An escape joins the run before it
    only where nothing stands between them.
    """
    start = end = -1
    data = bytearray()
    digits = ""
    for match in _BYTE_ESCAPE_RE.finditer(text):
        slashes = len(match.group(1))
        if slashes % 2 == 0:
            continue
        if match.start() == end and slashes == 1:
            data.append(int(match.group(2), 16))
            digits += match.group(2)
        else:
            if len(data) >= _LEAST_BYTES:
                yield start, end, bytes(data), _symbols(digits)
            start = match.end(1) - 1
            data, digits = bytearray([int(match.group(2), 16)]), match.group(2)
        end = match.end()
    if len(data) >= _LEAST_BYTES:
        yield start, end, bytes(data), _symbols(digits)


def _symbols(digits: str) -> int:
    """The bytes a token's digits can write: a hundred for decimal digits alone, else 256."""
    return _DECIMAL_BYTE if _DECIMAL_RE.fullmatch(digits) else _ANY_BYTE


def _readings(run: ByteRun) -> Iterator[tuple[str, bool, bool]]:
    """Each text a run decodes to: UTF-8, then UTF-16LE at each alignment, with its ends.

    A UTF-16LE reading that starts one byte in, or stops a byte short of the
    run's end, begins or ends inside a character, and that end bounds nothing.
    """
    yield run.data.decode("utf-8", errors="replace").lower(), run.opens, run.closes
    for alignment in (0, 1):
        units = (len(run.data) - alignment) // 2
        if units < 1:
            continue
        cut = run.data[alignment : alignment + 2 * units]
        whole_end = alignment + 2 * units == len(run.data)
        yield (
            cut.decode("utf-16-le", errors="replace").lower(),
            run.opens and alignment == 0,
            run.closes and whole_end,
        )


def readings_of(runs: Iterable[ByteRun]) -> tuple[tuple[str, bool, bool], ...]:
    """Every text ``runs`` decode to, with whether each end bounds a value, in order.

    What :func:`holds_whole` reads: decoded once, it is read for any number of values.
    """
    return tuple(reading for run in runs for reading in _readings(run))


def holds_whole(
    runs: Iterable[ByteRun],
    spellings: Iterable[str],
    *,
    readings: Iterable[tuple[str, bool, bool]] | None = None,
) -> bool:
    """Whether a run decodes to text holding one of ``spellings`` whole.

    Whole by :func:`~malspark.agents._indicator_denylists.whole_value_in`'s own
    bound, a decoded text's end counting as an end only where the run's end
    bounds a value (:class:`ByteRun`). ``readings``, where given, are the
    runs' own decoded texts (:func:`readings_of`), read in place of decoding
    them again.
    """
    from malspark.agents._indicator_denylists import whole_value_starts

    wanted = [str(spelling).lower() for spelling in spellings if spelling]
    if readings is None:
        readings = (reading for run in runs for reading in _readings(run))
    for decoded, opens, closes in readings:
        for spelling in wanted:
            for start in whole_value_starts(spelling, decoded):
                if start == 0 and not opens:
                    continue
                if start + len(spelling) == len(decoded) and not closes:
                    continue
                return True
    return False


def chance_in(runs: Iterable[ByteRun], value: str, spellings: Iterable[str] = ()) -> float:
    """The chance that ``runs`` spell ``value``, or one of ``spellings``, at random.

    Every place of every run is counted, in UTF-8 and in UTF-16LE at both
    alignments, each over the symbols its run is written with; a character
    with two cases (its lower and upper forms differ) is spelt in either.
    """
    from malspark.reporting.code_constants import chance_of_spelling

    said = list(dict.fromkeys([str(value).lower(), *(str(s).lower() for s in spellings)]))
    readings: list[tuple[int, int, int, int]] = []
    for run in runs:
        for spelling in said:
            ways = 2 ** sum(1 for ch in spelling if ch.lower() != ch.upper())
            narrow = len(spelling.encode("utf-8"))
            wide = len(spelling.encode("utf-16-le")) // 2
            readings.append((len(run.data) - narrow + 1, ways, narrow, run.symbols))
            for alignment in (0, 1):
                units = (len(run.data) - alignment) // 2
                readings.append((units - wide + 1, ways, wide, run.symbols**2))
    return chance_of_spelling(readings)


def has_a_place(runs: Iterable[ByteRun], spellings: Iterable[str]) -> bool:
    """Whether a run is long enough to hold one of ``spellings``: the reading had a place."""
    shortest = min((len(str(s).encode("utf-8")) for s in spellings if s), default=0)
    return bool(shortest) and any(len(run.data) >= shortest for run in runs)
