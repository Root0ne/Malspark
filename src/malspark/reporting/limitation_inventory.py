"""What the run could not do, measured once from the ledger: the limitations inventory.

Section 11 of the analyst report was one paragraph the report model wrote from
the run's recorded limitations and its open questions, and the platform's own
sentences after it each read a different record: the partial count read the
run summary's redone rows, which a stored run wrote before the one redo map
existed, so "4 of 158 tool calls failed and were not redone" stood beside a
ledger whose failed calls were all redone. Here the inventory is read once,
before the report's prose is written, and stored on the report
(``MalwareReport.limitation_inventory``):

* **Failed calls**: each call that ran and failed, with the later calls that
  redid it by the one redo map (``redone_calls.redo_map``), else each address a
  later call answered for (``limitation_facts.failed_calls``).
* **Code read**: how many routines have listed code, how many routines they
  call have none (``agreement_facts.ledger_facts``), and the first of those on
  the path from a start the run's answers state, by the rank the analysts'
  unread-callees question uses (``callees_question.callees_to_read``), never by
  how many routines call one.
* **Recorded limitations**: the tools the run could not offer with the reason
  it recorded, the tools the job's configuration withheld (the operator's
  choice), and every other limitation the run recorded.
* **Sandbox**: whether a sandbox recorded the sample, and the sections of the
  sandbox report's index (the entry of the declared kind ``sandbox_sections``):
  each one's item count, or whether the report lists it as unavailable from its
  sandbox or does not carry it.
* **Capture**: the window and packet count of the capture an entry of the
  declared kind ``pcap`` read.
* **Open questions**: each one filed, with the listings of the routines it
  names; a question every routine of which has listed code is marked so, and
  "after it was filed" where each listing came after its analyst's last entry.
  The mark is a fact; whether the listing closes the question is the model's.

Every reader prints or shows what the record holds from the fixed templates of
:func:`inventory_rows`, each row citing its entries: counts, entry ids,
addresses, tool names, the sandbox's own section names, durations and the
reasons the run recorded. No row says what a routine does, why a call failed or
whether a question is answered, and no row edits a sentence a model wrote.
Built in one pass over the ledger and the report, plus the readings it reuses.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from malspark.reporting.models import (
    InventoryCall,
    InventoryCapture,
    InventoryQuestion,
    InventorySection,
    InventoryTool,
    LimitationInventory,
    MalwareReport,
)

logger = logging.getLogger(__name__)

__all__ = [
    "LIST_LABEL",
    "InventoryRow",
    "build_inventory",
    "failed_counts",
    "inventory_rows",
    "printed_rows",
    "question_lines",
    "redone_rows",
]

# The label the analyst report's section 11 prints its list under.
LIST_LABEL = "What the run could not do (measured):"
# The declared kinds the sandbox and the capture rows are read by.
CAPTURE_KIND = "pcap"
# How many failed calls a printed row names; the rest are counted.
_CALLS_NAMED = 3
# How many unread callees on the start path a row names.
_FIRST_UNREAD = 2
# How many marked questions the agreement round's row names by address.
_MARKS_NAMED = 12

# The parts of the inventory, in the order the rows are written.
FAILED = "failed"
REDONE = "redone"
CODE = "code"
RECORDED = "recorded"
WITHHELD = "withheld"
RECORDED_EACH = "recorded_each"
SANDBOX_HELD = "sandbox_held"
SANDBOX = "sandbox"
CAPTURE = "capture"
QUESTIONS = "questions"
MARKS = "marks"
CLAIMS = "claims"


@dataclass(frozen=True)
class InventoryRow:
    """One row of the inventory: its part, its text, the entries it cites, and whether the
    analyst report's section 11 prints it (it states a limit) or only the bundle does."""

    part: str
    text: str
    cites: tuple[str, ...] = ()
    printed: bool = False


def _plain_quote(text: str) -> str:
    """A reason the run recorded, as a printed row quotes it."""
    return f'"{" ".join(str(text).split())}"'


def _joined(names: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    names = list(names)
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def _plural(count: int, one: str, many: str) -> str:
    return one if count == 1 else many


def _number(value: int) -> str:
    return f"{value:,}"


def _hexes(addresses: Iterable[int], bases: Sequence[int]) -> str:
    """Addresses by their offsets where the one image base read makes them offsets, else as
    written, as the agreement round's facts spell them."""
    addresses = list(addresses)
    if len(bases) == 1 and all(a >= bases[0] for a in addresses):
        return f"{_plural(len(addresses), 'offset', 'offsets')} " + ", ".join(
            hex(a - bases[0]) for a in addresses
        )
    return ", ".join(hex(a) for a in addresses)


# -- building the record ------------------------------------------------------


def build_inventory(report: MalwareReport, entries: Iterable[Any]) -> LimitationInventory:
    """The inventory of ``report``'s run, read off its ledger ``entries`` and the report
    as built (its recorded limitations, its open questions table, its sandbox blocks)."""
    from malspark.agents.function_map import one_spelling
    from malspark.reporting.agreement_facts import ledger_facts
    from malspark.reporting.evidence_bundles import sandbox_recorded
    from malspark.reporting.limitation_facts import limitation_facts

    entries = list(entries)
    found = ledger_facts(entries)
    bases = tuple(found.image_bases)
    read = limitation_facts(report, entries, found.answered, bases, found.redone)
    unread = {one_spelling(callee.address, bases) for callee in found.unread}
    listed = {routine.address: list(routine.listed_in) for routine in found.listed}
    return LimitationInventory(
        entries=len(entries),
        image_bases=list(bases),
        failed=[
            InventoryCall(
                entry=call.entry,
                tool=call.tool,
                error=call.error,
                asked=list(call.asked),
                answered=list(call.answered),
                redone_by=list(call.redone_by),
            )
            for call in read.failed
        ],
        listed=len(listed),
        unread=len(unread),
        unread_first=_first_on_the_start_path(entries, unread, bases),
        not_offered=[InventoryTool(tool=t.tool, reason=t.reason) for t in read.not_run],
        withheld=read.withheld,
        recorded=list(read.recorded),
        sandbox_observed=sandbox_recorded(report),
        **_sandbox_index(entries),
        capture=_capture(entries),
        questions=_questions(read.questions, listed, entries),
    )


def _first_on_the_start_path(
    entries: Sequence[Any], unread: set[int], bases: Sequence[int]
) -> list[int]:
    """The first unread callees on the path from a start the run's answers state, as the
    analysts' unread-callees question ranks them; none where no answer states a start."""
    if not unread:
        return []
    from malspark.agents.callees_question import STARTS_STATED, callees_to_read
    from malspark.agents.function_map import one_spelling
    from malspark.pipeline.triage_pack import pack_entries

    try:
        # No claim is read: the starts are the ones the answers state.
        found = callees_to_read((), entries, pack_entries(entries))
    except Exception as exc:  # noqa: BLE001 — the count stands without the rank
        logger.warning("limitation inventory: the start path was not read (%s).", exc)
        return []
    if found.starts != STARTS_STATED:
        return []
    first: list[int] = []
    for callee in found.ranked:
        address = one_spelling(callee.address, bases)
        if callee.on_path and address in unread and address not in first:
            first.append(address)
        if len(first) == _FIRST_UNREAD:
            break
    return first


def _sandbox_index(entries: Sequence[Any]) -> dict[str, Any]:
    """The sandbox report's index entry (declared kind ``sandbox_sections``) and its sections."""
    from malspark.analysis.sandbox_sections import index_entry, listed_unavailable

    entry = index_entry(entries)
    if entry is None:
        return {"sandbox_entry": "", "sandbox_sections": []}
    sections = getattr(entry, "structured", None) or {}
    out: list[InventorySection] = []
    for name, row in (sections.get("sections") or {}).items():
        if not isinstance(row, Mapping):
            continue
        if "no" in row:
            out.append(
                InventorySection(name=str(name), unavailable=listed_unavailable(str(row["no"])))
            )
        elif isinstance(row.get("items"), int):
            out.append(InventorySection(name=str(name), items=int(row["items"])))
    return {"sandbox_entry": str(getattr(entry, "id", "") or ""), "sandbox_sections": out}


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _capture(entries: Sequence[Any]) -> InventoryCapture | None:
    """The first capture an entry of the declared kind ``pcap`` read whole enough to time."""
    from malspark.reporting.tool_kinds import kind_of

    for entry in entries:
        if not getattr(entry, "ok", True) or kind_of(entry) != CAPTURE_KIND:
            continue
        held = getattr(entry, "structured", None)
        if not isinstance(held, Mapping):
            continue
        duration = held.get("duration_s")
        if not isinstance(duration, int | float) or isinstance(duration, bool):
            continue
        return InventoryCapture(
            entry=str(getattr(entry, "id", "") or ""),
            duration_s=float(duration),
            packets=_count(held.get("packets_in_capture")),
            packets_read=_count(held.get("packets_read")),
        )
    return None


def _questions(
    questions: Sequence[Any], listed: Mapping[int, list[str]], entries: Sequence[Any]
) -> list[InventoryQuestion]:
    """Each open question with the listings of the routines it names, and whether each came
    after the last entry of the analyst that filed it."""
    at_of = {str(getattr(e, "id", "") or ""): at for at, e in enumerate(entries)}
    last: dict[str, int] = {}
    for at, entry in enumerate(entries):
        agent = str(getattr(entry, "agent", "") or "")
        if agent:
            last[agent] = at
    out: list[InventoryQuestion] = []
    for question in questions:
        found = [(a, listed[a]) for a in question.addresses if a in listed]
        filed = last.get(question.agent)
        after = (
            bool(found)
            and len(found) == len(question.addresses)
            and filed is not None
            and all(any(at_of.get(i, -1) > filed for i in ids) for _a, ids in found)
        )
        out.append(
            InventoryQuestion(
                agent=question.agent,
                question=question.question,
                reason=question.reason,
                cites=list(question.cites),
                addresses=list(question.addresses),
                listed=[(a, list(ids)) for a, ids in found],
                listed_after=after,
            )
        )
    return out


# -- what the readers read ------------------------------------------------------


def failed_counts(inv: LimitationInventory) -> tuple[int, int]:
    """The failed calls, and how many of them a later call redid."""
    return len(inv.failed), sum(1 for call in inv.failed if call.redone_by)


def redone_rows(inv: LimitationInventory) -> list[dict[str, Any]]:
    """The failed calls a later call redid, in the run summary's ``evidence.redone`` shape."""
    return [
        {"entry_id": call.entry, "tool": call.tool, "answered_by": list(call.redone_by)}
        for call in inv.failed
        if call.redone_by
    ]


def _call(call: InventoryCall, bases: Sequence[int], name: Callable[[str], str]) -> str:
    """A failed call as a row names it: its tool, the addresses it asked for, its entry."""
    asked = f" for {_hexes(call.asked, bases)}" if call.asked else ""
    later = ", ".join(dict.fromkeys(entry for _address, entry in call.answered))
    if later:
        return (
            f"{name(call.tool)}{asked} ({call.entry}; a later call for the same address: {later})"
        )
    return f"{name(call.tool)}{asked} ({call.entry})"


def _failed_rows(inv: LimitationInventory, name: Callable[[str], str]) -> list[InventoryRow]:
    left = [call for call in inv.failed if not call.redone_by]
    redone = [call for call in inv.failed if call.redone_by]
    out: list[InventoryRow] = []
    if left:
        named = "; ".join(_call(call, inv.image_bases, name) for call in left[:_CALLS_NAMED])
        more = len(left) - _CALLS_NAMED
        text = (
            f"Tool calls: {len(left)} of {_number(inv.entries)} failed and "
            f"{_plural(len(left), 'was', 'were')} not redone: {named}"
            + (f"; and {more} more, listed in the bundle" if more > 0 else "")
            + (
                f". {len(redone)} other failed {_plural(len(redone), 'call was', 'calls were')} "
                "redone by a later call asking the same question"
                if redone
                else ""
            )
            + "."
        )
        cites = [i for call in left for i in (call.entry, *(e for _a, e in call.answered))]
        out.append(InventoryRow(FAILED, text, tuple(dict.fromkeys(cites)), printed=True))
    if redone:
        pairs = "; ".join(
            f"{name(call.tool)}"
            + (f" for {_hexes(call.asked, inv.image_bases)}" if call.asked else "")
            + f" ({call.entry}) by {', '.join(call.redone_by)}"
            for call in redone
        )
        text = (
            f"Tool calls redone: {len(redone)} of {_number(inv.entries)} failed and "
            f"{_plural(len(redone), 'was', 'were')} redone by a later call asking the same "
            f"question: {pairs}."
        )
        cites = [i for call in redone for i in (call.entry, *call.redone_by)]
        out.append(InventoryRow(REDONE, text, tuple(dict.fromkeys(cites))))
    return out


def _code_row(inv: LimitationInventory) -> list[InventoryRow]:
    if not inv.listed and not inv.unread:
        return []
    listed = (
        f"Code read: {_number(inv.listed)} {_plural(inv.listed, 'routine has', 'routines have')} "
        "listed code"
    )
    if not inv.unread:
        text = f"{listed}; no routine they call is without one."
    else:
        text = (
            f"{listed}; {_number(inv.unread)} {_plural(inv.unread, 'routine', 'routines')} they "
            f"call {_plural(inv.unread, 'has', 'have')} none"
            + (
                f", first on the start path: {_hexes(inv.unread_first, inv.image_bases)}"
                if inv.unread_first
                else ""
            )
            + "."
        )
    return [InventoryRow(CODE, text, printed=inv.unread > 0)]


def _recorded_rows(
    inv: LimitationInventory, quote: Callable[[str], str], name: Callable[[str], str]
) -> list[InventoryRow]:
    out: list[InventoryRow] = []
    said: list[str] = []
    if inv.not_offered:
        by_reason: dict[str, list[str]] = {}
        for tool in inv.not_offered:
            by_reason.setdefault(tool.reason, []).append(name(tool.tool))
        said.append(
            "Tools the run could not offer: "
            + "; ".join(
                f"{', '.join(dict.fromkeys(tools))} ({quote(reason)})"
                for reason, tools in by_reason.items()
            )
        )
    count = len(inv.recorded)
    if count:
        said.append(
            f"{count} other {_plural(count, 'limitation', 'limitations')} the run recorded, "
            f"with {_plural(count, 'its', 'their')} reason and remedy in the bundle"
        )
    if said:
        out.append(InventoryRow(RECORDED, ". ".join(said) + ".", printed=True))
    if inv.withheld:
        out.append(
            InventoryRow(
                WITHHELD,
                f"Tools withheld: {inv.withheld} {_plural(inv.withheld, 'tool', 'tools')} a "
                "server offers, withheld from the agents by the job's configuration (the "
                "operator's choice, listed in the bundle).",
            )
        )
    out.extend(
        InventoryRow(RECORDED_EACH, f"Limitation the run recorded: {quote(reason)}.")
        for reason in inv.recorded
    )
    return out


def _sandbox_rows(inv: LimitationInventory) -> list[InventoryRow]:
    out: list[InventoryRow] = []
    entry = inv.sandbox_entry
    held = [s for s in inv.sandbox_sections if s.items is not None]
    if entry and held:
        out.append(
            InventoryRow(
                SANDBOX_HELD,
                f"Sandbox report [{entry}]: holds "
                + ", ".join(f"{s.name} ({_number(s.items or 0)})" for s in held)
                + ".",
                (entry,),
            )
        )
    unavailable = [s.name for s in inv.sandbox_sections if s.items is None and s.unavailable]
    absent = [s.name for s in inv.sandbox_sections if s.items is None and not s.unavailable]
    said: list[str] = []
    if not inv.sandbox_observed:
        said.append("no sandbox observation of the sample is recorded in this run")
    if entry and unavailable:
        said.append(
            f"{_joined(unavailable)} {_plural(len(unavailable), 'is', 'are')} unavailable from "
            "the sandbox"
        )
    if entry and absent:
        said.append(f"{_joined(absent)} {_plural(len(absent), 'is', 'are')} not in the report")
    if said:
        head = f"Sandbox report [{entry}]" if entry and (unavailable or absent) else "Sandbox"
        out.append(
            InventoryRow(SANDBOX, f"{head}: {'; '.join(said)}.", (entry,) if entry else (), True)
        )
    return out


def _capture_row(inv: LimitationInventory) -> list[InventoryRow]:
    capture = inv.capture
    if capture is None:
        return []
    packets = ""
    if capture.packets is not None:
        packets = f", {_number(capture.packets)} {_plural(capture.packets, 'packet', 'packets')}"
        if capture.packets_read is not None and capture.packets_read != capture.packets:
            packets += f" ({_number(capture.packets_read)} read)"
    return [
        InventoryRow(
            CAPTURE,
            f"Packet capture [{capture.entry}]: {capture.duration_s:.1f} s{packets}.",
            (capture.entry,),
            printed=True,
        )
    ]


def _question_rows(inv: LimitationInventory) -> list[InventoryRow]:
    questions = inv.questions
    if not questions:
        return []
    by_reason: dict[str, int] = {}
    for question in questions:
        by_reason[question.reason] = by_reason.get(question.reason, 0) + 1
    reasons = ", ".join(
        f"{reason} {n}" for reason, n in sorted(by_reason.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    marked = [q for q in questions if q.all_listed]
    after = sum(1 for q in marked if q.listed_after)
    text = (
        f"Open questions: {len(questions)} filed ({reasons})"
        + (
            f"; {len(marked)} {_plural(len(marked), 'names', 'name')} only routines that have "
            "listed code"
            + (f", {after} of them listed after the question was filed" if after else "")
            if marked
            else ""
        )
        + ". All are in the bundle."
    )
    out = [InventoryRow(QUESTIONS, text, printed=True)]
    if marked:
        shown: dict[int, tuple[list[str], bool]] = {}
        for question in marked:
            for address, ids in question.listed:
                held_ids, was_after = shown.get(address, ([], False))
                shown[address] = (
                    list(dict.fromkeys([*held_ids, *ids])),
                    was_after or question.listed_after,
                )
        named = list(shown.items())[:_MARKS_NAMED]
        more = len(shown) - len(named)
        out.append(
            InventoryRow(
                MARKS,
                f"Open questions naming only routines that have listed code: {len(marked)}; "
                "the routines: "
                + "; ".join(
                    f"{_hexes([address], inv.image_bases)} in {', '.join(ids)}"
                    + (" (after it was filed)" if was else "")
                    for address, (ids, was) in named
                )
                + (f"; and {more} more" if more > 0 else "")
                + ".",
                tuple(dict.fromkeys(i for _a, (ids, _w) in named for i in ids)),
            )
        )
    return out


def inventory_rows(
    inv: LimitationInventory,
    *,
    quote: Callable[[str], str] = _plain_quote,
    name: Callable[[str], str] = str,
    claims_not_discussed: int | None = None,
) -> list[InventoryRow]:
    """Every row of the inventory, in a fixed order, each from its fixed template.

    ``quote`` writes a reason the run recorded (a tool's or a server's words), ``name`` a
    tool's name (a server's word);
    ``claims_not_discussed``, the count of analyst claims in force the report's body
    neither cites nor discusses, adds the row saying so (read after the body is
    written, so only the renderers know it).
    """
    rows = [
        *_failed_rows(inv, name),
        *_code_row(inv),
        *_recorded_rows(inv, quote, name),
        *_sandbox_rows(inv),
        *_capture_row(inv),
        *_question_rows(inv),
    ]
    if claims_not_discussed:
        n = claims_not_discussed
        rows.append(
            InventoryRow(
                CLAIMS,
                f"{n} analyst {_plural(n, 'claim', 'claims')} in force "
                f"{_plural(n, 'is', 'are')} not discussed in this report and "
                f"{_plural(n, 'is', 'are')} printed whole in the bundle.",
                printed=True,
            )
        )
    return rows


def printed_rows(
    inv: LimitationInventory, *, claims_not_discussed: int | None = None
) -> list[InventoryRow]:
    """The rows section 11 prints: each one that states a limit, at most seven."""
    return [
        row for row in inventory_rows(inv, claims_not_discussed=claims_not_discussed) if row.printed
    ]


def question_lines(
    inv: LimitationInventory,
    quote: Callable[[str], str] = _plain_quote,
    name: Callable[[str], str] = str,
) -> tuple[list[str], list[str]]:
    """The open questions as the limitations' writer is shown them: those every routine of
    which has listed code, with the listings, and the others; each with its analyst, why
    it was filed and the entries it cites."""
    marked: list[str] = []
    other: list[str] = []
    for question in inv.questions:
        head = (
            f"{quote(question.question)} (filed by {name(question.agent) or 'an analyst'} as "
            f"{question.reason}"
            + (f"; cites {', '.join(question.cites)}" if question.cites else "")
            + ")"
        )
        if question.all_listed:
            marked.append(
                f"{head}: every routine it names has listed code: "
                + "; ".join(
                    f"{_hexes([a], inv.image_bases)} in {', '.join(ids)}"
                    for a, ids in question.listed
                )
                + (" (after it was filed)" if question.listed_after else "")
            )
        else:
            other.append(head)
    return marked, other
