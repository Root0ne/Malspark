"""The evidence of a published technique: one set, read once, for every surface.

The capability matrix builder records, per technique, the entries cited by
the statements that name it (``CapabilityCell.evidence_ids`` and
``TTPMapping.evidence_ids``).
Every surface that shows a technique prints that set and nothing in its place:
the Markdown and analyst ATT&CK tables, the STIX ``uses`` edge, the MISP
technique attribute, the ATT&CK Navigator layer, the ATT&CK defence rows and
the API's technique list. A technique whose statements cite no entry says so
in each surface's own form, worded here once (:data:`NO_LEDGER_ENTRY`); a row stored
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


def technique_evidence_ids(row: Any) -> list[str] | None:
    """The entries cited by the statements that name one technique, read off its row or dump.

    The row's recorded ``evidence_ids``; ``[]`` is a technique whose
    statements cite no entry. A row stored before the set was recorded
    carries none, and reads as the entries among its ``sources`` and then
    those its statements write (``evidence_quotes`` on a published technique,
    ``evidence`` on a matrix cell), once each; ``None`` where those name no
    entry, since such a row does not say that its statements cite none.
    """
    recorded = _field(row, "evidence_ids")
    if recorded is not None:
        return _entries(recorded)
    statements = _field(row, "evidence_quotes")
    if statements is None:
        statements = _field(row, "evidence")
    written = [eid for text in statements or () for eid in ENTRY_ID_RE.findall(str(text))]
    return _entries([*(_field(row, "sources") or ()), *written]) or None


def technique_sandbox_items(row: Any) -> list[str]:
    """The sources of one technique row that are sandbox items, not ledger entries."""
    return list(
        dict.fromkeys(
            str(raw).strip()
            for raw in _field(row, "sources") or ()
            if str(raw).strip() and not ENTRY_ID_RE.fullmatch(str(raw).strip())
        )
    )


def evidence_words(ids: Iterable[Any] | None, items: Iterable[Any] = ()) -> str:
    """A technique's evidence as a text surface prints it.

    The entries comma-separated, or :data:`NO_LEDGER_ENTRY`, or
    :data:`NOT_RECORDED` for ``None`` (a stored row that records no set);
    the sandbox items among its sources after them, named.
    """
    if ids is None:
        listed = NOT_RECORDED
    else:
        listed = ", ".join(str(i) for i in ids if str(i).strip()) or NO_LEDGER_ENTRY
    shown = ", ".join(str(i) for i in items if str(i).strip())
    return f"{listed}; {SANDBOX_ITEMS_LABEL}: {shown}" if shown else listed


def technique_evidence_words(row: Any) -> str:
    """:func:`evidence_words` for one technique row."""
    return evidence_words(technique_evidence_ids(row), technique_sandbox_items(row))
