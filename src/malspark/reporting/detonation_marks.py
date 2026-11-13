"""Under which detonation of the sample each row of the report was observed.

A further detonation an agent asked for (``providers.detonation``: ``d2``,
``d3``…) is read by the platform as the job's own is
(``pipeline.detonations.platform_reads``), and the ledger projection marks
each network, signature, dropped-file and mutex row with the detonations
that observed it (``ledger_projection.observed_mark``); the evidence index
marks each entry that is such a read (``EvidenceIndexRow.observed_in``). This
module carries the marks onto the values the report publishes: an IOC-table
row by its value and by the reads it rests on, and a published technique by
the sandbox signatures that tag it and by the reads behind it, whatever the
kind of the value. It also words a mark, once, for every surface that states
it.

A row only the job's own detonation observed carries no mark (its
``observed_in`` is empty and left out of a dump), so a run with one
detonation reads, dumps and exports exactly as it did.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from malspark.reporting.ledger_projection import (
    FIRST_DETONATION,
    marks_of,
    stated_marks,
    value_key,
)
from malspark.reporting.models import (
    ConsolidatedIOC,
    EvidenceIndexRow,
    MalwareReport,
    ObservedIn,
    TTPMapping,
)


def value_marks(report: MalwareReport) -> dict[tuple[str, str], list[ObservedIn]]:
    """Each value a further detonation observed, by IOC-table kind and folded value, with its marks.

    Read from the report's network rows, and from the files written and the
    mutexes of its dynamic block. A value several rows hold carries every
    detonation any of them states. Empty where no row states a mark.
    """
    out = {key: stated_marks(marks) for key, marks in _value_held(report).items()}
    return {key: marks for key, marks in out.items() if marks}


def _value_held(report: MalwareReport) -> dict[tuple[str, str], list[ObservedIn]]:
    """Every detonation each value of :func:`value_marks` was observed in, the job's own too."""
    held: dict[tuple[str, str], list[ObservedIn]] = {}

    def _note(kind: str, value: Any, row: Any) -> None:
        text = str(value or "").strip()
        if text:
            held.setdefault((kind, value_key(kind, text)), []).extend(marks_of(row))

    network = report.network
    for domain in network.domains if network else []:
        _note("domain", domain.fqdn, domain)
    for ip in network.ips if network else []:
        _note("ip", ip.address, ip)
    for url in network.urls if network else []:
        _note("url", url.url, url)
    dynamic = report.dynamic
    for op in dynamic.file_operations if dynamic else []:
        if not isinstance(op, dict):
            continue
        if op.get("operation") == "write":
            _note("hash", op.get("sha256"), op)
            _note("path", op.get("path"), op)
        elif op.get("operation") == "mutex":
            _note("mutex", op.get("name"), op)
    return held


def entry_marks(ids: Iterable[Any], report: MalwareReport) -> list[ObservedIn]:
    """The detonations the reads ``ids`` name observed, where a further one is among them.

    An id the evidence index holds is the read it indexes: a further
    detonation's read is marked on its index row (``EvidenceIndexRow.observed_in``,
    from the entry by ``ledger_projection.observed_mark``), and a read of the
    same declared kind as such a read among ``ids`` that is no further
    detonation's is the job's own detonation's. A sandbox item names its
    detonation by its qualifier (``d2/reg:3``; an item with none is the job's
    own), with the launch the index marks that detonation's reads with. Any
    other read, a static tool's, observed no detonation. ``[]`` where no
    further detonation is among them.
    """
    from malspark.analysis.sandbox_sections import ITEM_ID_RE, split_qualifier
    from malspark.reporting import tool_kinds

    index = {row.id: row for row in report.evidence_index or ()}
    launches: dict[str, ObservedIn] = {}
    for row in index.values():
        for mark in row.observed_in:
            launches.setdefault(mark.detonation, mark)
    if not launches:
        return []
    marks: list[ObservedIn] = []
    later_kinds: set[str] = set()
    others: list[EvidenceIndexRow] = []
    for held in ids or ():
        ref = str(held or "").strip()
        found = index.get(ref)
        if found is not None:
            row = found
            if row.observed_in:
                marks.extend(row.observed_in)
                later_kinds.add(_kind_of(row, tool_kinds))
            else:
                others.append(row)
        elif ITEM_ID_RE.fullmatch(ref):
            detonation, _ = split_qualifier(ref)
            if not detonation:
                marks.append(ObservedIn(detonation=FIRST_DETONATION))
            elif detonation in launches:
                marks.append(launches[detonation])
    later_kinds.discard("")
    marks.extend(
        ObservedIn(detonation=FIRST_DETONATION)
        for row in others
        if _kind_of(row, tool_kinds) in later_kinds
    )
    return stated_marks(marks)


def _kind_of(row: EvidenceIndexRow, tool_kinds: Any) -> str:
    facts = tool_kinds.facts_of(row)
    return str(facts.kind or "") if facts is not None else ""


def with_value_marks(rows: list[ConsolidatedIOC], report: MalwareReport) -> list[ConsolidatedIOC]:
    """The IOC table with each row a further detonation observed marked with its detonations.

    A row's own mark, from the reads it rests on (:func:`entry_marks`), and
    the marks of the report's rows of its value (:func:`value_marks`), as one.
    """
    held = _value_held(report)
    out: list[ConsolidatedIOC] = []
    for row in rows:
        kind = str(row.kind or "")
        found = [*held.get((kind, value_key(kind, row.value)), ()), *row.observed_in]
        marks = stated_marks(found)
        out.append(
            row if marks == row.observed_in else row.model_copy(update={"observed_in": marks})
        )
    return out


def _tags(technique_id: str, tagged: str) -> bool:
    """Whether a signature's technique id ``tagged`` is ``technique_id`` or one under it."""
    wanted, said = technique_id.strip().upper(), tagged.strip().upper()
    return bool(wanted) and (said == wanted or said.startswith(f"{wanted}."))


def with_technique_marks(mappings: list[TTPMapping], report: MalwareReport) -> None:
    """Each published technique a further detonation observed, marked in place.

    Marked with every detonation whose signatures tag it (the job's own too,
    where its signatures do) and every detonation the reads behind it
    observed (``TTPMapping.sources``, :func:`entry_marks`), and only where a
    further detonation is among them.
    """
    signatures = list(report.dynamic.sandbox_signatures) if report.dynamic else []
    tagged = any(signature.observed_in for signature in signatures)
    for mapping in mappings:
        marks = [
            mark
            for signature in (signatures if tagged else ())
            if any(_tags(mapping.technique_id, tid) for tid in signature.technique_ids)
            for mark in marks_of(signature)
        ]
        behind = entry_marks(mapping.sources, report)
        if tagged or behind:
            mapping.observed_in = stated_marks([*marks, *behind])


# The longest launch text a surface writes; the record keeps the whole.
LAUNCH_TEXT_CHARS = 200

# The characters a launch text may not hold as they are on any surface: one
# that would close a code span, open a tag or a template, or end a table cell.
_INERT = {
    "`": "\\x60",
    "<": "\\x3c",
    ">": "\\x3e",
    "|": "\\x7c",
    "{": "\\x7b",
    "}": "\\x7d",
}


def launch_text(arguments: Any) -> str:
    """A further detonation's launch arguments as every surface writes them.

    The arguments an agent chose are text of the run, not of the platform: on
    one line, its control characters, ledger ids and template tokens written
    out (``sample_written_out``, ``template_tokens_written_out``), each
    back-tick, angle bracket, brace and table pipe written as its escape, the
    colon of anything that reads as a sandbox item id (``d3/proc:1``) too, so
    it cites no item, and cut at :data:`LAUNCH_TEXT_CHARS` with the cut mark.
    A surface sets the result as its own escaping sets text (a Markdown code
    span, a JSON string).
    """
    from malspark.analysis.sandbox_sections import ITEM_ID_RE
    from malspark.utils.marked_cut import marked_cut
    from malspark.utils.written_forms import sample_written_out, template_tokens_written_out

    text = template_tokens_written_out(sample_written_out(str(arguments or "")))
    text = ITEM_ID_RE.sub(lambda found: found.group(0).replace(":", "\\x3a"), text)
    return marked_cut("".join(_INERT.get(ch, ch) for ch in text), LAUNCH_TEXT_CHARS)


def detonation_named(name: Any) -> str:
    """``name`` where it is a detonation's (``d1``, or a later one in the citation checks' form)."""
    from malspark.analysis.sandbox_sections import QUALIFIER_RE

    text = str(name or "")
    if text == FIRST_DETONATION or QUALIFIER_RE.fullmatch(f"{text}/") is not None:
        return text.lower()
    return ""


def observed_words(
    marks: Sequence[ObservedIn] | Iterable[Any], code: Callable[[str], str] | None = None
) -> str:
    """A row's marks as one clause: ``observed in detonation 2, launched with `<arguments>```.

    The job's own detonation is named so where a further one observed the row
    too; a further one's arguments are written out as the Sandbox sentence
    writes them, set as ``code`` sets them (a one-backtick span where none is
    given). ``""`` for no mark.
    """
    parts: list[str] = []
    for held in marks:
        # A dict row of the dynamic block holds its marks dumped.
        mark = ObservedIn.model_validate(dict(held)) if isinstance(held, Mapping) else held
        # A stored row's mark is read only where it names a detonation.
        name = detonation_named(getattr(mark, "detonation", ""))
        if not name:
            continue
        if name == FIRST_DETONATION:
            parts.append("the job's own detonation")
            continue
        arguments = launch_text(getattr(mark, "launched_with", ""))
        number = name[1:] if name.startswith("d") else name
        said = code(arguments) if code is not None else f"`{arguments}`"
        parts.append(f"detonation {number}, launched with {said}")
    return f"observed in {' and in '.join(parts)}" if parts else ""


def later_only_words(marks: Sequence[ObservedIn] | Iterable[Any]) -> str:
    """A row's marks in :func:`observed_words`'s words, where only further detonations observed it.

    ``""`` where the job's own detonation observed the row too, or no mark is
    stated: what a surface that names only a later detonation's rows writes
    (the drafted rules).
    """
    held = list(marks or ())
    names = {
        detonation_named(
            mark.get("detonation") if isinstance(mark, Mapping) else getattr(mark, "detonation", "")
        )
        for mark in held
    }
    if not held or FIRST_DETONATION in names:
        return ""
    return observed_words(held)


def observed_property(marks: Sequence[ObservedIn]) -> list[dict[str, Any]] | None:
    """A row's marks as an export's property holds them; ``None`` (left out) for no mark."""
    return [mark.model_dump() for mark in marks if detonation_named(mark.detonation)] or None
