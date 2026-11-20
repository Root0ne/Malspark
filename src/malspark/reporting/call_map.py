"""The call map the console draws: the functions the run's code reading touched.

Read from the stored ledger alone, so a run stored before the map existed
draws it too, and nothing the run stored changes:

* **Read** functions are the function map's visited functions (``agents.
  function_map.build_function_map``) and every function a code listing of any
  kind lists (``agents.function_callees.call_edges``), each with the entries
  a call listed it in (see below). A listing is read as the entry holds it:
  what the analyst was handed, never a part kept outside the row.
* **Calls** are the calls those listings make and the calls a function index
  answer about the sample states (``call_edges``); a function a call names
  whose code no entry lists is *named, not read*.
* **What each listing keeps** is the entry reading's (``schemas.
  entry_reading``), never a reading of its own. ``listed_in`` names every
  entry a call listed the function in, whatever the ledger keeps of it now.
  The function is ``read`` where a model was shown some of its listing: an
  entry keeps text of it, or the byte budget blanked the entry after its
  model read it; not where the listing was left out before any model read
  it. ``read_by`` are the agents of the entries it was read in. What the
  ledger keeps is said in ``notes`` alone, entry by entry with its id: a
  listing kept in part, at no character, with no recorded extent or not in
  the ledger's text (a function a cut answer keyed by address holds no
  member of), and an answer that also reads as a failure; each note says
  where the job's store holds the answer whole, or only the output of an
  entry already cut. A listing kept whole says nothing.
* **Roots** are the functions nothing in the map calls, in address order; a
  part of the map every function of which is called from inside it (a cycle)
  is entered at its lowest address.

One spelling per function: the virtual address, where the one image base the
run read makes one (``function_map.one_spelling``). Nothing here reads a
tool's name: the listings and the index are read by the tools' declared kinds.
Linear in the ledger and in the calls: each is read once.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from malspark.agents.function_callees import call_edges
from malspark.agents.function_map import build_function_map, one_spelling, same_function
from malspark.core.undeclared_tools import function_address
from malspark.pipeline.validation import _one_function, generic_function_name
from malspark.schemas import entry_reading as reading
from malspark.schemas.evidence import repeat_holders

__all__ = ["call_map"]


@dataclass
class _Function:
    address: int | None
    names: list[str] = field(default_factory=list)
    listed_in: list[str] = field(default_factory=list)
    calls: set[int] = field(default_factory=set)
    called_by: set[int] = field(default_factory=set)


def _own_names(names: Iterable[str], address: int | None, bases: tuple[int, ...]) -> list[str]:
    """The names a function was given, the decompiler's own name for its address aside.

    The own name may spell the address as an offset or as a virtual address;
    either is the decompiler's name for it (``function_map.one_spelling``).
    """
    generic = generic_function_name()
    out: list[str] = []
    for name in names:
        name = str(name or "").strip()
        named = generic.fullmatch(name)
        if not name or name in out:
            continue
        if (
            named is not None
            and address is not None
            and one_spelling(int(named.group(1), 16), bases) == address
        ):
            continue
        out.append(name)
    return out


_NOT_IN_TEXT = "not in the ledger's text"
_NOT_RECORDED = "extent not recorded"
_KEPT_EMPTY = "kept at 0 characters"
_FAILED = "the answer also reads as a failure"
# The entries a listing may be cut in, and those that keep no text of it, each
# with its note and whether a model read the answer before it was left out.
_CUT = frozenset({reading.SHORTENED, reading.CUT_AS_TEXT})
_LEFT_OUT = {
    reading.NOT_SHOWN: (f"{_NOT_IN_TEXT}: the conversation had no room for it", False),
    reading.BLANKED_UNREAD: (
        f"{_NOT_IN_TEXT}: the byte budget left it out before any model read it",
        False,
    ),
    reading.BLANKED_READ: (
        f"{_NOT_IN_TEXT}: the byte budget left it out after a model read it",
        True,
    ),
}
# What the job's store holds of an answer: the answer whole, or only the
# output of an entry already cut before the budget blanked it.
_STORED = "the store holds the answer whole"
_STORED_OUTPUT = "the store holds the entry's output"


def _stored(read: reading.EntryReading) -> str:
    """The words for the store's copy of the answer of ``read`` (or its holder's), or ``""``."""
    readings = (read, *((read.holder_reading,) if read.holder_reading else ()))
    if any(held.answer_stored_whole for held in readings):
        return _STORED
    if any("output" in held.stored for held in readings):
        return _STORED_OUTPUT
    return ""


def _kept(
    read: reading.EntryReading,
    address: int | None,
    names: list[str],
    bases: tuple[int, ...],
    *,
    alone: bool = False,
) -> tuple[bool, str | None]:
    """Whether a model was shown some of one function's listing in ``read``, and its note.

    The note is ``None`` for a listing the entry keeps whole. The function is
    the member whose key writes its address or one of its names. In a cut
    entry whose members are each keyed by an address, a function no member can
    be was shown to no model (with no image base read, a member the
    platform's one-function test joins to it may be it: its extent is not
    recorded); an entry with no such container keeps the listing
    as it keeps its text, in part by the entry's own count where the listing
    is ``alone`` in it (the only function the entry lists). Every note names
    the store's copy where the reading says one is held.
    """
    note: str | None
    states = set(read.states)
    if read.state in (reading.REPEAT, reading.ABSENT) and read.holder_reading is None:
        # Nothing of the answer is read here: its extent is not known.
        shown, note = True, _NOT_RECORDED
    elif left_out := next((_LEFT_OUT[s] for s in _LEFT_OUT if s in states), None):
        note, shown = left_out
    elif reading.FAILED in states:
        shown, note = True, _FAILED
    else:
        shown, note = _member_note(read, states, address, names, bases, alone)
    if note is None:
        return shown, None
    stored = _stored(read)
    return shown, f"{note}; {stored}" if stored else note


def _member_note(
    read: reading.EntryReading,
    states: set[str],
    address: int | None,
    names: list[str],
    bases: tuple[int, ...],
    alone: bool,
) -> tuple[bool, str | None]:
    """``_kept`` of an entry that keeps text: by the function's member, else by the entry."""
    member = next(
        (
            held
            for held in read.members
            if held.key in names or same_function(function_address(held.key), address, bases)
        ),
        None,
    )
    if member is None:
        if not states & _CUT:
            return True, None
        keyed = [function_address(held.key) for held in read.members]
        known = [key for key in keyed if key is not None]
        if keyed and len(known) == len(keyed):
            if address is not None and not bases and any(_one_function(k, address) for k in known):
                # With no image base read, a member may be this function by its other address.
                return True, _NOT_RECORDED
            # The answer's members are its functions, and this one is none of them.
            return False, _NOT_IN_TEXT
        if alone and reading.CUT_AS_TEXT in states and read.text_extent is not None:
            kept, total = read.text_extent
            return True, f"in part: {kept:,} of {total:,} {reading.CHARACTERS}"
        return True, _NOT_RECORDED
    if member.state == reading.MEMBER_WHOLE:
        return True, None
    if member.state == reading.MEMBER_UNMEASURED:
        return True, _NOT_RECORDED
    if member.state == reading.MEMBER_IN_PART:
        return True, f"in part: {member.kept:,} of {member.total:,} {member.unit}"
    if member.state == reading.MEMBER_EMPTY:
        return False, _KEPT_EMPTY
    return False, _NOT_IN_TEXT


def _entry_readings(entries: list[Any]) -> Callable[[str], reading.EntryReading | None]:
    """The reading of an entry by its id: each read once, a repeat through its answer's holder."""
    by_id = {str(getattr(e, "id", "") or "").strip().lower(): e for e in entries}
    holders = repeat_holders(entries)
    readings: dict[str, reading.EntryReading] = {}

    def _reading(entry_id: str) -> reading.EntryReading | None:
        key = entry_id.strip().lower()
        if key not in readings and key in by_id:
            holder = by_id.get(holders.get(key) or "")
            readings[key] = reading.entry_reading(by_id[key], holder=holder)
        return readings.get(key)

    return _reading


def _roots(functions: dict[int, _Function]) -> list[int]:
    """The functions nothing calls, then the lowest address of each part none of them reaches."""
    roots = sorted(a for a, f in functions.items() if not (f.called_by - {a}))
    reached: set[int] = set()

    def _walk(start: int) -> None:
        stack = [start]
        while stack:
            at = stack.pop()
            if at in reached:
                continue
            reached.add(at)
            stack.extend(c for c in functions[at].calls if c not in reached)

    for root in roots:
        _walk(root)
    for address in sorted(functions):
        if address not in reached:
            roots.append(address)
            _walk(address)
    return roots


def call_map(entries: Iterable[Any]) -> dict[str, Any]:
    """The call map of ``entries`` as the console reads it.

    ``functions`` in address order, each with its ``address`` (hex), its
    ``offset`` from the one image base read (or ``None``), the ``names`` it
    was given beyond the decompiler's own, the entries a call listed it in
    (``listed_in``), whether a model was shown some of its listing
    (``read``) and the agents of the entries it was (``read_by``), the
    addresses it ``calls`` and is ``called_by``, and, where an entry keeps
    its listing other than whole, the ``notes`` saying how (see the
    module). A function listed under a
    name alone joins the row at an address that carries the same name; with
    none, it has no address and no calls. ``roots`` are where the tree
    starts (see the module).
    """
    entries = list(entries)
    found = build_function_map(entries, None, ())
    bases = tuple(found.image_bases)
    agents = {str(getattr(e, "id", "") or ""): str(getattr(e, "agent", "") or "") for e in entries}
    by_address: dict[int, _Function] = {}
    by_name: dict[str, _Function] = {}

    def _at(address: int) -> _Function:
        key = one_spelling(address, bases)
        return by_address.setdefault(key, _Function(address=key))

    def _listed(into: _Function, ids: Iterable[str]) -> None:
        into.listed_in.extend(i for i in ids if i and i not in into.listed_in)

    for visit in found.visited:
        if visit.address is None:
            name = next((n for n in visit.names if n), "")
            if not name:
                continue
            into = by_name.setdefault(name, _Function(address=None))
        else:
            into = _at(visit.address)
        into.names.extend(n for n in visit.names if n not in into.names)
        _listed(into, (*visit.decompiled, *visit.listed))
    edges = call_edges(entries)
    for address, ids in edges.listed.items():
        _listed(_at(address), ids)
    for caller, callees in edges.calls.items():
        for callee in callees:
            if same_function(caller, callee, bases):
                continue
            _at(caller).calls.add(one_spelling(callee, bases))
            _at(callee).called_by.add(one_spelling(caller, bases))
    # A function listed under a name alone is the function at an address
    # that carries the same name, where one does: its listing joins that row.
    named_at: dict[str, _Function] = {}
    for address in sorted(by_address):
        for name in by_address[address].names:
            named_at.setdefault(name, by_address[address])
    for name in list(by_name):
        held = named_at.get(name)
        if held is not None:
            alone = by_name.pop(name)
            held.names.extend(n for n in alone.names if n not in held.names)
            _listed(held, alone.listed_in)

    _reading = _entry_readings(entries)
    # How many functions each entry lists: a listing alone in its entry is its text.
    listing: dict[str, int] = {}
    for function in [*by_address.values(), *by_name.values()]:
        for entry_id in function.listed_in:
            listing[entry_id] = listing.get(entry_id, 0) + 1
    base = bases[0] if len(bases) == 1 else None
    rows: list[dict[str, Any]] = []
    for function in [*(by_address[a] for a in sorted(by_address)), *by_name.values()]:
        at = function.address
        shown_in: list[str] = []
        notes: list[str] = []
        for entry_id in function.listed_in:
            read = _reading(entry_id)
            shown, note = (
                (True, None)
                if read is None
                else _kept(read, at, function.names, bases, alone=listing[entry_id] == 1)
            )
            if note is not None:
                notes.append(f"{note} ({entry_id})")
            if shown:
                shown_in.append(entry_id)
        row: dict[str, Any] = {
            "address": hex(at) if at is not None else None,
            "offset": (
                hex(at - base) if at is not None and base is not None and at >= base else None
            ),
            "names": _own_names(function.names, at, bases),
            "read": bool(shown_in),
            "listed_in": list(function.listed_in),
            "read_by": sorted({agents[i] for i in shown_in if agents.get(i)}),
            "calls": [hex(a) for a in sorted(function.calls)],
            "called_by": [hex(a) for a in sorted(function.called_by)],
        }
        if notes:
            row["notes"] = notes
        rows.append(row)
    return {
        "image_base": hex(base) if base is not None else None,
        "functions": rows,
        "roots": [hex(a) for a in _roots(by_address)],
    }
