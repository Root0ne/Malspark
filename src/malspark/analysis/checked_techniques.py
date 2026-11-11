"""The technique ids a run's agents checked or its tools named, read from the ledger alone.

An agent that validates or looks up a technique id writes it in the call's
arguments; a tool whose answer names techniques declares where
(``ToolFacts.techniques``). An id seen either way and carried by no final
claim, finding or bundle object left the run without a record: the report
states the behaviour and no technique list names it. This module lists those
ids with where each was seen, so the judge's post-verdict technique question
can put them to the judge (``extractors.capability_matrix``).

Whatever the tool: every entry's arguments are searched for technique ids
(``analysis.technique_ids.technique_ids_in`` over every string they hold), and
an answer is read only where its tool's declaration names a technique field
(``core.declared_reading.facts_of``, read through ``ids_in_field``), never by
a tool's name or one tool's field names. Linear in the size of the ledger:
each entry's arguments and answer are visited once.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Iterator, Mapping
from typing import Any, NamedTuple

from malspark.analysis.technique_ids import ids_in_field, technique_ids_in

# Where in an entry an id was seen: written in the call's arguments, or named
# in the answer's declared technique field.
IN_ARGUMENTS = "arguments"
IN_ANSWER = "answer"


class CheckedMention(NamedTuple):
    """One place a technique id was seen: the agent whose call it was, the entry, and where."""

    agent: str
    entry_id: str
    place: str


def _strings(value: Any) -> Iterator[str]:
    """Every string ``value`` holds as a value, at any depth; a mapping's keys are not values."""
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, Mapping):
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, list | tuple):
            stack.extend(reversed(item))


def argument_technique_ids(entry: Any) -> list[str]:
    """The technique ids an entry's call arguments write, first seen first."""
    return technique_ids_in(list(_strings(getattr(entry, "args", None))))


def answer_technique_ids(entry: Any) -> list[str]:
    """The technique ids an entry's answer names where its tool declares a technique field.

    An entry whose tool declares none names none here, whatever its answer
    holds.
    """
    from malspark.core.declared_reading import facts_of
    from malspark.core.tool_declarations import select

    facts = facts_of(entry)
    if facts is None or not facts.techniques:
        return []
    structured = getattr(entry, "structured", None)
    if structured is None:
        return []
    found: list[str] = []
    for field in facts.techniques:
        for value in select(structured, field.path):
            for tid in ids_in_field(value, field.format):
                if tid not in found:
                    found.append(tid)
    return found


def checked_techniques(
    ledger: Iterable[Any] | None, carried: Collection[str]
) -> dict[str, list[CheckedMention]]:
    """Each technique id the ledger holds that ``carried`` does not, with every place it was seen.

    ``carried`` is the run's ids on a final claim, a finding or a bundle
    object, upper-cased. Ids are compared exactly: a parent and its
    sub-technique are two ids, each listed and decided on its own. The
    ids come in the order first seen, each place once, in ledger order.
    """
    held = {str(tid).strip().upper() for tid in carried}
    out: dict[str, list[CheckedMention]] = {}
    for entry in ledger or ():
        entry_id = str(getattr(entry, "id", "") or "").strip().lower()
        if not entry_id:
            continue
        agent = str(getattr(entry, "agent", "") or "")
        for place, ids in (
            (IN_ARGUMENTS, argument_technique_ids(entry)),
            (IN_ANSWER, answer_technique_ids(entry)),
        ):
            # Each reader gives an id once, so each place of each entry is listed once.
            for tid in ids:
                if tid not in held:
                    out.setdefault(tid, []).append(CheckedMention(agent, entry_id, place))
    return out


def claim_entries(isr_reports: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """Per agent, the ledger entries its final claims cite, in the order first cited."""
    from malspark.schemas.evidence import ENTRY_ID_RE

    out: dict[str, list[str]] = {}
    for agent_name, isr in (isr_reports or {}).items():
        agent = str(getattr(isr, "agent_id", "") or agent_name)
        seen = out.setdefault(agent, [])
        held = set(seen)
        for claim in getattr(isr, "claims", None) or []:
            for found in ENTRY_ID_RE.findall(str(getattr(claim, "evidence_ref", "") or "")):
                entry_id = found.lower()
                if entry_id not in held:
                    held.add(entry_id)
                    seen.append(entry_id)
    return out
