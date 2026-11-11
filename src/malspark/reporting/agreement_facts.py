"""The ledger's own facts the agreement round is shown beside the bound values.

Section 5 is written from the code and the tool answers, and the round asked a
section 5 sentence only against the decoded texts bound to an API argument: a
sentence that called a behaviour absent while the routine behind a read gate
was never read (T-404), or that blamed "two decompile failures" for a routine
a later call decompiled (T-396), had no fact to be asked against; nor had a
sentence that called a routine's body "not read" or "not in this evidence"
while an entry lists its code (T-494). Three more are read here, from the
ledger alone:

* **An unread callee** (``agents.function_callees``): a routine a read routine
  calls, by a decompiled listing or a function index answer, that no entry
  reads.
* **A listed routine** (``agents.function_callees.read_routines``): a routine
  whose code an entry lists (decompiled or disassembled), with those entries.
* **A failed call answered later**: a call for an address that failed, and the
  later call that redid it for that address (``redone_calls.redo_map``, the map
  the run summary names its redone calls by, T-600); for a call no later call
  redid, the first later call that answered for the same address, of the same
  tool or, for a call that lists code, any later listing of that function.

Each is stated in the platform's words, with the entries it rests on; which
sentence it bears on is the model's call. Linear in the ledger.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from malspark.agents.function_callees import (
    UnreadCallee,
    call_edges,
    listing_is_error,
    read_routines,
    unread_callees,
)
from malspark.agents.function_map import build_function_map, one_spelling
from malspark.core.undeclared_tools import (
    entry_address_arguments,
    entry_decompiles,
    entry_lists_any_code,
)
from malspark.pipeline.validation import (
    _ADDRESS_LIST_ARGUMENTS,
    _address_list,
    _address_value,
    _entry_functions,
)
from malspark.reporting.redone_calls import Redo, redo_map
from malspark.schemas.evidence import answer_not_shown

__all__ = [
    "AnsweredLater",
    "LedgerFacts",
    "ListedRoutine",
    "answered_addresses",
    "answered_later",
    "asked_addresses",
    "ledger_facts",
    "spelled",
]


@dataclass(frozen=True)
class AnsweredLater:
    """A call for ``address`` that failed, and the later call that redid it there, else the
    first later call that answered for it."""

    address: int
    failed: str
    failed_tool: str
    answered: str
    answered_tool: str
    # Whether the answering call lists code (decompiled or disassembled).
    answered_lists_code: bool = False
    # Whether the answering call redid the failed one (``redone_calls.redo_map``).
    redone: bool = False


@dataclass(frozen=True)
class ListedRoutine:
    """A routine at ``address`` whose code the entries ``listed_in`` list."""

    address: int
    listed_in: tuple[str, ...]


@dataclass(frozen=True)
class LedgerFacts:
    """The facts read off one ledger, and the image bases its answers stated."""

    unread: tuple[UnreadCallee, ...] = ()
    answered: tuple[AnsweredLater, ...] = ()
    image_bases: tuple[int, ...] = ()
    listed: tuple[ListedRoutine, ...] = ()
    # The failed calls later calls redid, read once: what ``answered`` and the
    # limitation facts both name (``redone_calls.redo_map``); ``None`` where not read.
    redone: tuple[Redo, ...] | None = None


def asked_addresses(entry: Any) -> list[int]:
    """The addresses a call was given, by its address arguments and its address lists."""
    args = getattr(entry, "args", None) or {}
    found: list[int] = []
    for name in entry_address_arguments(entry):
        if name in args:
            value = _address_value(args[name])
            if value is not None:
                found.append(value)
    for name in _ADDRESS_LIST_ARGUMENTS:
        if name in args:
            found.extend(_address_list(args[name]))
    return list(dict.fromkeys(found))


def answered_addresses(entry: Any) -> list[int]:
    """The addresses a call answered for: a listing's functions, else what it was asked.

    A code listing whose one answer is error text answered for none, as a
    batch's ``Error`` key is no listing (``function_callees.listing_is_error``).
    """
    if entry_lists_any_code(entry) and listing_is_error(entry):
        return []
    if entry_decompiles(entry):
        held = [address for address, _names in _entry_functions(entry) if address is not None]
        if held:
            return list(dict.fromkeys(held))
    return asked_addresses(entry)


def _groups(entry: Any) -> tuple[tuple[str, str], ...]:
    """What a call answers as: its own tool, and a listing of code when it lists code."""
    tool = ("tool", str(getattr(entry, "tool", "") or ""))
    return (tool, ("code", "")) if entry_lists_any_code(entry) else (tool,)


def answered_later(
    entries: Iterable[Any],
    image_bases: Sequence[int] = (),
    redone: Sequence[Redo] | None = None,
) -> list[AnsweredLater]:
    """Each failed call for an address, linked to the later call that redid it there, else
    to the first later call that answered for it, in the answering calls' ledger order.

    A failed call later calls redid (``redone``, read off the entries when not
    given: ``redone_calls.redo_map``, the map the run summary reads) is linked,
    for each address, to the call that redid it there, never to an earlier
    call that only answered for the address. Any other is read in ledger order:
    a failed call waits under each address it was asked for, as what it is (its
    tool; a listing of code); a later call that answered, was shown and is no
    repeat takes every call waiting under an address it answered for, as what
    it is. A failed repeat waits as its own call. An offset and its virtual
    address are one address when exactly one image base was read: ``image_bases``,
    or, when none are given, the bases the ledger's function map reads, the
    same for the redo map and every lookup in it.
    """
    entries = list(entries)
    if not image_bases:
        image_bases = tuple(build_function_map(entries, None, ()).image_bases)
    if redone is None:
        redone = redo_map(entries, image_bases)
    redid = {redo.entry_id: dict(redo.by_address) for redo in redone if redo.by_address}
    at_of = {str(getattr(entry, "id", "") or ""): at for at, entry in enumerate(entries)}
    waiting: dict[tuple[int, tuple[str, str]], list[Any]] = {}
    found: list[tuple[int, AnsweredLater]] = []
    linked: set[tuple[int, int]] = set()
    for at, entry in enumerate(entries):
        if not getattr(entry, "ok", True):
            failed_id = str(getattr(entry, "id", "") or "")
            by = redid.get(failed_id) if not getattr(entry, "repeated_of", None) else None
            if by is not None:
                # Redone: each address is linked to the call that redid it there.
                for address in dict.fromkeys(
                    one_spelling(a, image_bases) for a in asked_addresses(entry)
                ):
                    answering = at_of.get(by.get(address, ""))
                    if answering is None:
                        continue
                    found.append(
                        (answering, _link(address, entry, entries[answering], redone=True))
                    )
                continue
            for address in asked_addresses(entry):
                for group in _groups(entry):
                    waiting.setdefault((one_spelling(address, image_bases), group), []).append(
                        entry
                    )
            continue
        if answer_not_shown(entry) or getattr(entry, "repeated_of", None):
            continue
        for address in answered_addresses(entry):
            key = one_spelling(address, image_bases)
            for group in _groups(entry):
                for failed in waiting.pop((key, group), ()):
                    # A call waits as its tool and as a listing: linked once.
                    if (id(failed), key) in linked:
                        continue
                    linked.add((id(failed), key))
                    found.append((at, _link(key, failed, entry)))
    found.sort(key=lambda pair: pair[0])
    return [link for _at, link in found]


def _link(address: int, failed: Any, answering: Any, *, redone: bool = False) -> AnsweredLater:
    """The fact that ``answering`` answered for ``address`` after ``failed`` failed."""
    return AnsweredLater(
        address=address,
        failed=str(getattr(failed, "id", "") or ""),
        failed_tool=str(getattr(failed, "tool", "") or ""),
        answered=str(getattr(answering, "id", "") or ""),
        answered_tool=str(getattr(answering, "tool", "") or ""),
        answered_lists_code=entry_lists_any_code(answering),
        redone=redone,
    )


def ledger_facts(entries: Iterable[Any]) -> LedgerFacts:
    """The unread callees, the failed calls answered later, the listed routines and the
    failed calls later calls redid, read off ``entries``; the redo map is read once."""
    entries = list(entries)
    found = build_function_map(entries, None, ())
    bases = tuple(found.image_bases)
    edges = call_edges(entries)
    redone = tuple(redo_map(entries, bases))
    return LedgerFacts(
        unread=tuple(unread_callees(entries, found, edges)),
        answered=tuple(answered_later(entries, bases, redone)),
        image_bases=bases,
        redone=redone,
        listed=tuple(
            ListedRoutine(address=address, listed_in=tuple(listed))
            for address, listed in sorted(read_routines(entries, found, edges).items())
        ),
    )


def spelled(address: int, bases: Sequence[int]) -> str:
    """An address as a fact writes it: the virtual address, and its offset by the one base read."""
    if len(bases) == 1 and address >= bases[0]:
        return f"{hex(address)} (offset {hex(address - bases[0])})"
    return hex(address)
