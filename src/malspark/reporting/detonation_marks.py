"""Under which detonation of the sample each row of the report was observed.

A further detonation an agent asked for (``providers.detonation``: ``d2``,
``d3``…) is read by the platform as the job's own is
(``pipeline.detonations.platform_reads``), and the ledger projection marks
each network, signature, dropped-file and mutex row with the detonations
that observed it (``ledger_projection.observed_mark``). This module carries
the marks onto the rows the report derives from them: the IOC table's rows by
value, and the published techniques a detonation's sandbox signatures tag.
It also words a mark, once, for every surface that states it.

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
from malspark.reporting.models import ConsolidatedIOC, MalwareReport, ObservedIn, TTPMapping


def value_marks(report: MalwareReport) -> dict[tuple[str, str], list[ObservedIn]]:
    """Each value a further detonation observed, by IOC-table kind and folded value, with its marks.

    Read from the report's network rows, and from the files written and the
    mutexes of its dynamic block. A value several rows hold carries every
    detonation any of them states. Empty where no row states a mark.
    """
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
    out = {key: stated_marks(marks) for key, marks in held.items()}
    return {key: marks for key, marks in out.items() if marks}


def with_value_marks(rows: list[ConsolidatedIOC], report: MalwareReport) -> list[ConsolidatedIOC]:
    """The IOC table with each row a further detonation observed marked with its detonations."""
    marks = value_marks(report)
    if not marks:
        return rows
    out: list[ConsolidatedIOC] = []
    for row in rows:
        kind = str(row.kind or "")
        found = marks.get((kind, value_key(kind, row.value)))
        out.append(row.model_copy(update={"observed_in": list(found)}) if found else row)
    return out


def _tags(technique_id: str, tagged: str) -> bool:
    """Whether a signature's technique id ``tagged`` is ``technique_id`` or one under it."""
    wanted, said = technique_id.strip().upper(), tagged.strip().upper()
    return bool(wanted) and (said == wanted or said.startswith(f"{wanted}."))


def with_technique_marks(mappings: list[TTPMapping], report: MalwareReport) -> None:
    """Each published technique a further detonation's sandbox signatures tag, marked in place.

    Marked with every detonation whose signatures tag it (the job's own too,
    where its signatures do), and only where a further detonation's do.
    """
    signatures = list(report.dynamic.sandbox_signatures) if report.dynamic else []
    if not any(signature.observed_in for signature in signatures):
        return
    for mapping in mappings:
        marks = [
            mark
            for signature in signatures
            if any(_tags(mapping.technique_id, tid) for tid in signature.technique_ids)
            for mark in marks_of(signature)
        ]
        mapping.observed_in = stated_marks(marks)


# The longest launch text a surface writes; the record keeps the whole.
LAUNCH_TEXT_CHARS = 200

# The characters a launch text may not hold as they are on any surface: one
# that would close a code span, open a tag or end a table cell.
_INERT = {"`": "\\x60", "<": "\\x3c", ">": "\\x3e", "|": "\\x7c"}


def launch_text(arguments: Any) -> str:
    """A further detonation's launch arguments as every surface writes them.

    The arguments an agent chose are text of the run, not of the platform: on
    one line, its control characters, ledger ids and template tokens written
    out (``sample_written_out``, ``template_tokens_written_out``), each
    back-tick, angle bracket and table pipe written as its escape, and cut at
    :data:`LAUNCH_TEXT_CHARS` with the cut mark. A surface sets the result as
    its own escaping sets text (a Markdown code span, a JSON string).
    """
    from malspark.utils.marked_cut import marked_cut
    from malspark.utils.written_forms import sample_written_out, template_tokens_written_out

    text = template_tokens_written_out(sample_written_out(str(arguments or "")))
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


def observed_property(marks: Sequence[ObservedIn]) -> list[dict[str, Any]] | None:
    """A row's marks as an export's property holds them; ``None`` (left out) for no mark."""
    return [mark.model_dump() for mark in marks if detonation_named(mark.detonation)] or None
