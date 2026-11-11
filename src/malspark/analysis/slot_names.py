"""The names a run's function index gives the slots the code calls through.

A function index entry (declared kind ``function_index``, read by the
``call_bindings`` consumer) states the slots it resolved to an API
(``resolved_slots``) and the ones two names fill (``ambiguous_slots``), each by
its address, with the image base the index read them at. The report binds a
decoded text to the API a slot names (``reporting.call_bindings``), and an
analyst's validation turn names the slot a condition calls through
(``pipeline.exit_branches``); both read the slots here, by the entry's
declared kind, never by its tool's name.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from malspark.reporting import tool_kinds

# The consumer whose declared kinds are read here
# (``core.builtin_declarations.CONSUMER_KINDS``), and the function index's kind.
_CONSUMER = "call_bindings"
_INDEX = "function_index"
# The declared argument role a tool reads a produced file under, as a kind is
# declaration vocabulary (``analysis.coverage.LAYER_ROLE``).
_CARVED_ROLE = "carved"
_CARVED_ARGUMENT = "carved_path"


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, Mapping) else getattr(obj, name, None)


def _number(text: Any) -> int | None:
    try:
        return int(str(text), 16)
    except (TypeError, ValueError):
        return None


def file_of(entry: Any, facts: Any) -> str:
    """The produced file an entry's call read, ``""`` for the sample itself."""
    arguments = getattr(facts, "arguments", None) or {}
    name = str(arguments.get(_CARVED_ROLE) or _CARVED_ARGUMENT)
    args = _field(entry, "args")
    return str(args.get(name) or "") if isinstance(args, Mapping) else ""


def slot_names(ledger: Iterable[Any]) -> dict[tuple[str, int], tuple[str, str] | None]:
    """``{(file, slot RVA): (name, entry)}`` index entries name; ``None`` where they disagree."""
    names: dict[tuple[str, int], tuple[str, str] | None] = {}
    for entry in ledger:
        if not tool_kinds.is_of(entry, _CONSUMER) or tool_kinds.kind_of(entry) != _INDEX:
            continue
        structured = _field(entry, "structured")
        if not isinstance(structured, Mapping):
            continue
        base = _number(structured.get("image_base"))
        resolved = structured.get("resolved_slots")
        if base is None or not isinstance(resolved, Mapping):
            continue
        where = file_of(entry, tool_kinds.facts_of(entry))
        entry_id = str(_field(entry, "id") or _field(entry, "entry_id") or "")
        ambiguous = structured.get("ambiguous_slots")
        for address in ambiguous if isinstance(ambiguous, Mapping) else ():
            at = _number(address)
            if at is not None:
                names[(where, at - base)] = None
        for address, name in resolved.items():
            at = _number(address)
            if at is None or not name:
                continue
            key = (where, at - base)
            held = names.get(key, ...)
            if held is ...:
                names[key] = (str(name), entry_id)
            elif held is not None and held[0] != str(name):
                names[key] = None
    return names
