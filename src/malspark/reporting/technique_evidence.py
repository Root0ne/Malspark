"""The evidence of a published technique: one set, read once, for every surface.

The capability matrix builder records, per technique, the entries cited by
the statements that name it (``CapabilityCell.evidence_ids`` and
``TTPMapping.evidence_ids``).
Every surface that shows a technique prints that set and nothing in its place:
the Markdown and analyst ATT&CK tables, the STIX ``uses`` edge, the MISP
technique attribute, the ATT&CK Navigator layer, the ATT&CK defence rows and
the API's technique list, each with the sandbox items among the technique's
sources beside the set, named apart (:data:`SANDBOX_ITEMS_LABEL`). The sources
every statement naming it cites to state an absence (``absence_sources``) are
neither: every surface names them after its evidence, under their own label
(:data:`ABSENCE_LABEL`, :func:`absence_words`) — in its words, its note, or a
list of their own — and so does the judge's evidence summary. A technique
whose statements cite no entry and that has no sandbox item says so in each
surface's own form, worded here once (:data:`NO_LEDGER_ENTRY`); a row stored
before the set was recorded, whose sources and statements name no entry,
says nothing either way. Other ids a
surface shows beside it, such as the entries of the rules that matched it or
the sandbox items among its sources, are named for what they are and are not
part of the set.

Nothing is asked of a model and nothing is read again per surface: each reads
the row through :func:`technique_evidence_ids`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from malspark.schemas.evidence import ENTRY_ID_RE

# What a surface states for a technique whose statements cite no ledger entry.
NO_LEDGER_ENTRY = "no ledger entry"

# How a surface names the sandbox items among a technique's sources.
SANDBOX_ITEMS_LABEL = "sandbox items"

# How a surface names the sources a technique's statements cite to state an
# absence: cited, and no evidence of the behaviour.
ABSENCE_LABEL = "cited for an absence"

# What a text surface prints for a row stored before the set was recorded
# whose sources and statements name no entry: nothing is known either way.
NOT_RECORDED = "-"


def _field(row: Any, name: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(name)
    return getattr(row, name, None)


def _entries(ids: Iterable[Any]) -> list[str]:
    return list(
        dict.fromkeys(
            str(raw).strip().lower() for raw in ids if ENTRY_ID_RE.fullmatch(str(raw).strip())
        )
    )


def _absent(row: Any) -> set[str]:
    return {str(raw).strip().lower() for raw in _field(row, "absence_sources") or ()}


class SandboxItems(list[str]):
    """A technique's sandbox items, with the sources it cites for an absence beside them
    (``absence``), which :func:`evidence_words` prints apart."""

    absence: tuple[str, ...] = ()


def technique_evidence_ids(row: Any) -> list[str] | None:
    """The entries cited by the statements that name one technique, read off its row or dump.

    The row's recorded ``evidence_ids``; ``[]`` is a technique whose
    statements cite no entry. A row stored before the set was recorded
    carries none, and reads as the entries among its ``sources`` and then
    those its statements write (``evidence_quotes`` on a published technique,
    ``evidence`` on a matrix cell), once each; ``None`` where those name no
    entry, since such a row does not say that its statements cite none.
    An entry the row's statements cite only to state an absence
    (``absence_sources``) is left out.
    """
    absent = _absent(row)
    recorded = _field(row, "evidence_ids")
    if recorded is not None:
        return [eid for eid in _entries(recorded) if eid not in absent]
    statements = _field(row, "evidence_quotes")
    if statements is None:
        statements = _field(row, "evidence")
    written = [eid for text in statements or () for eid in ENTRY_ID_RE.findall(str(text))]
    return [
        eid for eid in _entries([*(_field(row, "sources") or ()), *written]) if eid not in absent
    ] or None


def technique_absence_ids(row: Any) -> list[str]:
    """The sources one technique row's statements cite only to state an absence, once each."""
    return list(
        dict.fromkeys(
            str(raw).strip() for raw in _field(row, "absence_sources") or () if str(raw).strip()
        )
    )


def absence_words(sources: Iterable[Any]) -> str:
    """The sources cited only to state an absence, as every surface names them; ``""`` for none."""
    shown = ", ".join(str(i) for i in sources if str(i).strip())
    return f"{ABSENCE_LABEL}: {shown}" if shown else ""


def technique_sandbox_items(row: Any) -> list[str]:
    """The sources of one technique row that are sandbox items, not ledger entries.

    An item cited only to state an absence is left out; those sources, entries
    and items, ride along as ``absence`` (:class:`SandboxItems`).
    """
    absent = _absent(row)
    items = SandboxItems(
        dict.fromkeys(
            str(raw).strip()
            for raw in _field(row, "sources") or ()
            if str(raw).strip()
            and not ENTRY_ID_RE.fullmatch(str(raw).strip())
            and str(raw).strip().lower() not in absent
        )
    )
    items.absence = tuple(technique_absence_ids(row))
    return items


def evidence_words(
    ids: Iterable[Any] | None, items: Iterable[Any] = (), absence: Iterable[Any] | None = None
) -> str:
    """A technique's evidence as a text surface prints it.

    The entries comma-separated, then the sandbox items among its sources,
    named apart. With no entry, the items alone; with neither,
    :data:`NO_LEDGER_ENTRY`, or :data:`NOT_RECORDED` for ``None`` (a stored
    row that records no set). The sources cited only to state an absence
    (``absence``, or ``items.absence`` from :func:`technique_sandbox_items`)
    follow (:func:`absence_words`).
    """
    listed = ", ".join(str(i) for i in ids or () if str(i).strip())
    shown = ", ".join(str(i) for i in items if str(i).strip())
    if shown:
        named = f"{SANDBOX_ITEMS_LABEL}: {shown}"
        words = f"{listed}; {named}" if listed else named
    elif listed:
        words = listed
    else:
        words = NOT_RECORDED if ids is None else NO_LEDGER_ENTRY
    apart = absence_words(getattr(items, "absence", ()) if absence is None else absence)
    return f"{words}; {apart}" if apart else words


def evidence_note(ids: Iterable[Any] | None, items: Iterable[Any] = ()) -> str:
    """What a surface that carries a technique's entries in a field of their own notes beside them.

    The sandbox items among its sources, named apart, or, with neither entry
    nor item, :data:`NO_LEDGER_ENTRY`; then the sources cited only to state an
    absence (``items.absence``, :func:`absence_words`). ``""`` when there is
    nothing to note.
    """
    shown = ", ".join(str(i) for i in items if str(i).strip())
    parts = [f"{SANDBOX_ITEMS_LABEL}: {shown}"] if shown else []
    if not shown and not any(str(i).strip() for i in ids or ()):
        parts.append(NO_LEDGER_ENTRY)
    apart = absence_words(getattr(items, "absence", ()))
    if apart:
        parts.append(apart)
    return "; ".join(parts)


def technique_evidence_words(row: Any) -> str:
    """:func:`evidence_words` for one technique row."""
    return evidence_words(technique_evidence_ids(row), technique_sandbox_items(row))
