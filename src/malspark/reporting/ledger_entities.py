"""The names a run's ledger holds, and what it states of each, for the agreement round.

A sentence of the report that denies something of an API, an export or a
decoded text names a thing the run's own answers state: the function index
lists which routine calls an API through which slot, and which names a routine
resolves or imports; the format answer lists the exports by address; the
index lists the texts a routine refers to (T-600). Read here, once per
ledger, by the answers' own keys, never by a tool's name:

* **The APIs**: each name a row of the function index (the last index read)
  calls through a slot or an import (``slot_calls``, ``imports``) or
  resolves (``resolved``), with the routines that call it and the entries
  naming it, and each name an answer lists among its ``imports``.
* **The exports**: each ``export_rows`` row an answer holds, by address, with
  the entries listing them.
* **The texts**: each decoded or plain string the index ties to a routine
  (``decoded_strings``, ``plain_strings``), with the routines, the entries it
  rests on and the keys it is listed under.
* **The calls**: each routine's callees as the index lists them, and each
  slot's API name (``slot_calls``, ``resolved_slots``), which a listing's line
  is read by.

An answer's export rows and imports are read only where the answer is about the
sample: its call read no file the run produced, and the program or path it names,
if any, is the sample's. Another file's are none of the sample's.

Which sentence a fact bears on, and whether a sentence it names is
contradicted, is read in ``section_agreement``. Linear in the ledger.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from malspark.agents.function_map import function_artefacts, one_spelling

__all__ = [
    "RELATION_KEYS",
    "ApiCall",
    "ApiHeld",
    "ExportHeld",
    "RunNames",
    "TextHeld",
    "run_names",
]

# The keys the run's answers hold each relation under: the words a sentence
# denying that relation writes are read off these, never off a list of verbs
# (``section_agreement.relation_of``). A decoded text and a plain one are two
# relations: the index lists each under its own key.
RELATION_KEYS: dict[str, tuple[str, ...]] = {
    "called": ("slot_calls", "callees", "callers"),
    "resolved": ("resolved",),
    "imported": ("imports",),
    "exported": ("exports", "export_rows"),
    "decoded": ("decoded_strings", "text"),
    "plain": ("plain_strings", "text"),
}
# A name shorter than this is never read as one the run holds: a word of
# ordinary prose is as long.
NAME_FLOOR = 4
# The declared argument roles that name the file a call read: set, they must name
# the sample for its export rows to be the sample's (``agents.image_range``).
_SUBJECT_ROLES = ("path", "program")


def _hex(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    try:
        return int(str(value).strip(), 16)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class ApiCall:
    """A routine the function index lists calling an API, through ``slot`` (none for an
    import), and the entries naming the slot."""

    routine: int
    slot: int | None
    named_by: tuple[str, ...] = ()


@dataclass
class ApiHeld:
    """An API the run holds: the routines calling it, and the entries naming it resolved
    or imported."""

    name: str
    calls: list[ApiCall] = field(default_factory=list)
    resolved: dict[str, None] = field(default_factory=dict)
    imported: dict[str, None] = field(default_factory=dict)
    # The routines whose index row names it resolved.
    resolved_in: dict[int, None] = field(default_factory=dict)


@dataclass(frozen=True)
class ExportHeld:
    """The exports at one address, and the entries listing them."""

    names: tuple[str, ...]
    address: int
    entries: tuple[str, ...]


@dataclass
class TextHeld:
    """A string the function index ties to routines, and the entries it rests on."""

    text: str
    routines: dict[int, None] = field(default_factory=dict)
    sources: dict[str, None] = field(default_factory=dict)
    # The index keys it is listed under ("decoded_strings", "plain_strings"): a denial
    # of a relation it is not held under is no denial of what the ledger states.
    held_as: dict[str, None] = field(default_factory=dict)


@dataclass
class RunNames:
    """What the ledger holds by name: its APIs, exports and texts, the index's callees by
    routine and its slots by address, and the bases an address is spelled by."""

    apis: dict[str, ApiHeld] = field(default_factory=dict)
    # By the name as the export table writes it: "run" is no "Run" key.
    exports: dict[str, ExportHeld] = field(default_factory=dict)
    by_address: dict[int, ExportHeld] = field(default_factory=dict)
    texts: dict[str, TextHeld] = field(default_factory=dict)
    callees: dict[int, tuple[int, ...]] = field(default_factory=dict)
    slots: dict[int, str] = field(default_factory=dict)
    rows: frozenset[int] = frozenset()
    index_entry: str = ""
    # Whether the index was read whole: only then does a routine it lists no call
    # in call nothing it lists.
    index_whole: bool = False
    bases: tuple[int, ...] = ()

    def api(self, name: str) -> ApiHeld | None:
        """The API the run holds under ``name`` (case aside), or ``None``."""
        return self.apis.get(name.lower())


def _api(names: RunNames, name: str) -> ApiHeld | None:
    plain = str(name or "").rpartition("!")[2].strip()
    if len(plain) < NAME_FLOOR:
        return None
    return names.apis.setdefault(plain.lower(), ApiHeld(name=plain))


def _sources(cell: Mapping[str, Any]) -> list[str]:
    found = cell.get("sources")
    return [str(s) for s in found if s] if isinstance(found, list) else []


def _index(names: RunNames, data: Mapping[str, Any], entry_id: str) -> None:
    """The function index's rows: each routine's calls, names, texts and callees."""
    spell = names.bases
    rows: set[int] = set()
    for row in data.get("rows") or []:
        if not isinstance(row, Mapping):
            continue
        start = _hex(row.get("function"))
        if start is None:
            continue
        routine = one_spelling(start, spell)
        rows.add(routine)
        callees = [one_spelling(a, spell) for a in map(_hex, row.get("callees") or []) if a]
        names.callees[routine] = tuple(dict.fromkeys(callees))
        for cell in row.get("slot_calls") or []:
            if not isinstance(cell, Mapping):
                continue
            held = _api(names, str(cell.get("name") or ""))
            slot = _hex(cell.get("slot"))
            if held is None:
                continue
            at = one_spelling(slot, spell) if slot is not None else None
            held.calls.append(ApiCall(routine, at, tuple(_sources(cell))))
            held.resolved.update(dict.fromkeys([entry_id, *_sources(cell)]))
            if at is not None:
                names.slots.setdefault(at, held.name)
        for cell in row.get("imports") or []:
            held = _api(names, str(cell.get("name") or "")) if isinstance(cell, Mapping) else None
            if held is not None:
                held.calls.append(ApiCall(routine, None, tuple(_sources(cell))))
                held.imported[entry_id] = None
        for cell in row.get("resolved") or []:
            held = _api(names, str(cell.get("name") or "")) if isinstance(cell, Mapping) else None
            if held is not None:
                held.resolved.update(dict.fromkeys([entry_id, *_sources(cell)]))
                held.resolved_in[routine] = None
        for key in ("decoded_strings", "plain_strings"):
            for cell in row.get(key) or []:
                text = str(cell.get("text") or "") if isinstance(cell, Mapping) else ""
                if len(text.strip()) < NAME_FLOOR:
                    continue
                found = names.texts.setdefault(text.strip().lower(), TextHeld(text=text.strip()))
                found.routines[routine] = None
                found.sources.update(dict.fromkeys(_sources(cell)))
                found.held_as[key] = None
    # Every slot the index names, called or not: what a listing's line is read by.
    resolved = data.get("resolved_slots")
    for address, name in resolved.items() if isinstance(resolved, Mapping) else ():
        at = _hex(address)
        if at is not None and name:
            names.slots.setdefault(one_spelling(at, spell), str(name))
    others = data.get("other_callees")
    if isinstance(others, Mapping):
        for address, called in others.items():
            start = _hex(address)
            if start is None or not isinstance(called, list):
                continue
            routine = one_spelling(start, spell)
            names.callees.setdefault(
                routine,
                tuple(dict.fromkeys(one_spelling(a, spell) for a in map(_hex, called) if a)),
            )
    names.rows = frozenset(rows)
    names.index_entry = entry_id


def _about_the_sample(entry: Any, sample: Callable[[], tuple[str, ...]]) -> bool:
    """Whether an answer is about the sample: its call read no file the run produced
    (``function_callees._about_the_sample``), and the program or path its declared
    arguments name, where one is set, is one of the sample's own names (``sample``,
    read once and only when asked)."""
    from malspark.agents.function_callees import _about_the_sample as reads_the_sample
    from malspark.agents.image_range import same_program
    from malspark.core.declared_reading import kind_free_facts

    if not reads_the_sample(entry):
        return False
    roles = getattr(kind_free_facts(entry), "arguments", None)
    args = getattr(entry, "args", None)
    if not isinstance(roles, Mapping) or not isinstance(args, Mapping):
        return True
    for role in _SUBJECT_ROLES:
        value = args.get(str(roles.get(role) or "")) if roles.get(role) else None
        if value in (None, ""):
            continue
        if not any(same_program(str(value), name) for name in sample()):
            return False
    return True


def _format_rows(names: RunNames, entry: Any, data: Mapping[str, Any]) -> None:
    """An answer's export rows and import names, read by their keys."""
    entry_id = str(getattr(entry, "id", "") or "")
    by_address: dict[int, list[str]] = {}
    for row in data.get("export_rows") or []:
        if not isinstance(row, Mapping):
            continue
        address = _hex(row.get("rva") or row.get("address"))
        name = str(row.get("name") or "").strip()
        if address is None or not name:
            continue
        by_address.setdefault(one_spelling(address, names.bases), []).append(name)
    for address, listed in by_address.items():
        held = names.by_address.get(address)
        merged = tuple(dict.fromkeys([*(held.names if held else ()), *listed]))
        entries = tuple(dict.fromkeys([*(held.entries if held else ()), entry_id]))
        export = ExportHeld(names=merged, address=address, entries=entries)
        names.by_address[address] = export
        for name in merged:
            names.exports[name] = export
    for row in data.get("imports") or []:
        name = str(row.get("function") or "") if isinstance(row, Mapping) else ""
        api = _api(names, name)
        if api is not None:
            api.imported[entry_id] = None


def run_names(entries: Iterable[Any], bases: Sequence[int] = ()) -> RunNames:
    """What the ledger holds by name, read once: the function index's rows (the last index
    read whole), and each answer's export rows and import names where the answer is about
    the sample (:func:`_about_the_sample`). ``bases`` are the image
    bases the run read, which an address is spelled by (``function_map.one_spelling``)."""
    entries = list(entries)
    names = RunNames(bases=tuple(bases))
    held: list[tuple[str, ...]] = []

    def _sample() -> tuple[str, ...]:
        # The sample's own file names by the pipeline's pack answers, read once.
        if not held:
            from malspark.agents.image_range import _sample_names
            from malspark.pipeline.triage_pack import pack_entries

            held.append(_sample_names(pack_entries(entries)))
        return held[0]

    found = function_artefacts(entries)
    data = found.index_data
    if isinstance(data, Mapping):
        _index(names, data, str(found.index_entry or ""))
        names.index_whole = not found.index_cut and isinstance(data.get("other_callees"), Mapping)
    for entry in entries:
        if not getattr(entry, "ok", True):
            continue
        data = getattr(entry, "structured", None)
        if not isinstance(data, Mapping) or ("export_rows" not in data and "imports" not in data):
            continue
        if _about_the_sample(entry, _sample):
            # Another file's exports and imports are none of the sample's.
            _format_rows(names, entry, data)
    return names
