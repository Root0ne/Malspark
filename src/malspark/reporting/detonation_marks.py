"""Under which detonation of the sample each row of the report was observed.

A further detonation an agent asked for (``providers.detonation``: ``d2``,
``d3``…) is read by the platform as the job's own is
(``pipeline.detonations.platform_reads``), and the ledger projection marks
each network, signature, dropped-file and mutex row with the detonations
that observed it (``ledger_projection.observed_mark``); the evidence index
marks each entry that is such a read (``EvidenceIndexRow.observed_in``). This
module carries the marks onto the values the report publishes: an IOC-table
row by its value and by the reads it rests on, whatever the kind of the
value, and a published technique by the sandbox signatures that tag it and by
nothing else. It also words a mark, once, for every surface that states it:
an indicator's by what observed it (:func:`observed_words`), a technique's by
what the sandbox's signatures tag (:func:`technique_words`).

A row only the job's own detonation observed carries no mark (its
``observed_in`` is empty and left out of a dump), so a run with one
detonation reads, dumps and exports exactly as it did.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from malspark.analysis.technique_ids import ID_BODY
from malspark.reporting.ledger_projection import (
    FIRST_DETONATION,
    marks_of,
    stated_marks,
    value_key,
)
from malspark.reporting.models import (
    ConsolidatedIOC,
    MalwareReport,
    ObservedIn,
    TaggingSignature,
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
    from the entry by ``ledger_projection.observed_mark``), and the platform's
    read of the job's own detonation is the first detonation's
    (``detonation_reads.own_detonation_read``). A sandbox item names its
    detonation by its qualifier (``d2/reg:3``; an item with none is the job's
    own), with the launch the index marks that detonation's reads with. Any
    other read, a static tool's, and an id the index does not hold observed no
    detonation. ``[]`` where no further detonation is among them.
    """
    from malspark.analysis.detonation_reads import own_detonation_read
    from malspark.analysis.sandbox_sections import ITEM_ID_RE, split_qualifier

    index = {row.id: row for row in report.evidence_index or ()}
    launches: dict[str, ObservedIn] = {}
    for row in index.values():
        for mark in row.observed_in:
            launches.setdefault(mark.detonation, mark)
    if not launches:
        return []
    marks: list[ObservedIn] = []
    for held in ids or ():
        ref = str(held or "").strip()
        found = index.get(ref)
        if found is not None:
            if found.observed_in:
                marks.extend(found.observed_in)
            elif own_detonation_read(found):
                marks.append(ObservedIn(detonation=FIRST_DETONATION))
        elif ITEM_ID_RE.fullmatch(ref):
            detonation, _ = split_qualifier(ref)
            if not detonation:
                marks.append(ObservedIn(detonation=FIRST_DETONATION))
            elif detonation in launches:
                marks.append(launches[detonation])
    return stated_marks(marks)


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


# An ATT&CK technique id as a signature's tag must be written to credit a
# technique: an id of another form names nothing the table can relate.
_TECHNIQUE_ID_RE = re.compile(ID_BODY)

# How a credited signature's tag stands to the technique's id, closest first.
_SAME, _SUB, _PARENT = "same", "sub-technique", "parent"
_RELATIONS = (_SAME, _SUB, _PARENT)


def _relation(technique_id: str, tagged: str) -> str | None:
    """How the id ``tagged`` stands to ``technique_id``: the same, a sub-technique, its parent."""
    wanted, said = technique_id.strip().upper(), tagged.strip().upper()
    if not _TECHNIQUE_ID_RE.fullmatch(wanted) or not _TECHNIQUE_ID_RE.fullmatch(said):
        return None
    if said == wanted:
        return _SAME
    if said.startswith(f"{wanted}."):
        return _SUB
    if wanted.startswith(f"{said}."):
        return _PARENT
    return None


def _tagging(technique_id: str, name: str, tagged: Iterable[str]) -> TaggingSignature | None:
    """The signature ``name`` as it credits ``technique_id`` by its own ids ``tagged``, or ``None``.

    An id credits where it is the technique's, a sub-technique's or its
    parent's, or where the vendored ATT&CK table says it was revoked in favour
    of one of these (``attck_loader.revoked_by``); of several, the closest
    (that order, an id as tagged before a revoked one), each in the
    signature's own order.
    """
    from malspark.memory.attck_loader import revoked_by

    held = [str(tid or "").strip().upper() for tid in tagged]
    for relation in _RELATIONS:
        for tid in held:
            if _relation(technique_id, tid) == relation:
                return TaggingSignature(name=name, technique_id=tid)
    for relation in _RELATIONS:
        for tid in held:
            successor = revoked_by(tid) if _TECHNIQUE_ID_RE.fullmatch(tid) else None
            if successor and _relation(technique_id, successor) == relation:
                return TaggingSignature(name=name, technique_id=tid, revoked_by=successor)
    return None


def with_technique_marks(mappings: list[TTPMapping], report: MalwareReport) -> None:
    """Each published technique a further detonation's sandbox signatures tag, marked in place.

    Marked with every detonation one of whose signatures carries in its own
    technique ids the technique's id, a sub-technique's, its parent's, or an
    id ATT&CK revoked in favour of one of these (:func:`_tagging`); each mark
    lists those signatures with the id each tags. The job's own detonation is
    among them where its signatures tag it, and a mark is stated only where a
    further detonation is among them. The reads a technique cites and the
    items it names credit no detonation: a read of a detonation holds what
    that detonation recorded, which is not the technique's behaviour by being
    cited. A sandbox whose signatures carry no technique ids credits none.
    """
    signatures = list(report.dynamic.sandbox_signatures) if report.dynamic else []
    if not any(signature.observed_in for signature in signatures):
        return
    for mapping in mappings:
        launches: dict[str, ObservedIn] = {}
        tagging: dict[str, list[TaggingSignature]] = {}
        for signature in signatures:
            found = _tagging(mapping.technique_id, signature.name, signature.technique_ids)
            if found is None:
                continue
            for mark in marks_of(signature):
                launches.setdefault(mark.detonation, mark)
                listed = tagging.setdefault(mark.detonation, [])
                if found not in listed:
                    listed.append(found)
        mapping.observed_in = stated_marks(
            ObservedIn(
                detonation=name,
                launched_with=mark.launched_with,
                signatures=tagging[name],
            )
            for name, mark in launches.items()
        )


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


def signatures_listed(marks: Sequence[ObservedIn] | Iterable[Any]) -> bool:
    """Whether a technique's marks list the signatures that tag it (a mark stored before
    they were recorded lists none)."""
    return any(
        (held.get("signatures") if isinstance(held, Mapping) else getattr(held, "signatures", None))
        for held in marks or ()
    )


def _tag_words(technique_id: str, signature: TaggingSignature, code: Callable[[str], str]) -> str:
    """What a signature's tag is to ``technique_id``: ``this technique``, ``this technique's
    parent T1222``…

    An id of another form than ATT&CK's is written out as a launch text is
    and set as ``code`` sets it.
    """

    def _id(value: str) -> str:
        text = value.strip().upper()
        return text if _TECHNIQUE_ID_RE.fullmatch(text) else code(launch_text(value))

    def _to(value: str) -> str:
        relation = _relation(technique_id, value)
        if relation == _SAME:
            return "this technique"
        if relation == _SUB:
            return f"this technique's sub-technique {_id(value)}"
        if relation == _PARENT:
            return f"this technique's parent {_id(value)}"
        return _id(value)

    said = _to(signature.technique_id)
    if signature.revoked_by:
        return f"{said} (revoked by ATT&CK in favour of {_to(signature.revoked_by)})"
    return said


def _listed(items: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} and {items[-1]}"


def technique_words(
    technique_id: str,
    marks: Sequence[ObservedIn] | Iterable[Any],
    code: Callable[[str], str] | None = None,
) -> str:
    """A published technique's marks as one clause: what each detonation's signatures tag.

    ``in detonation 2, launched with `<arguments>`, the sandbox signatures
    `A` and `B` tag this technique``: per detonation (the job's own named
    so), each signature that tags the technique by name, and the id it tags
    where that is not the technique's (``this technique's sub-technique
    T1070.004``, ``this technique's parent T1222``, a revoked id said to be
    revoked and in favour of what). It states what the sandbox tagged, never that the behaviour was
    observed. A launch text and a signature name are written out as
    :func:`launch_text` writes them and set as ``code`` sets them (a
    one-backtick span where none is given). Marks stored before their
    signatures were recorded keep the words they were written in
    (:func:`observed_words`). ``""`` for no mark.
    """
    held = [
        ObservedIn.model_validate(dict(mark)) if isinstance(mark, Mapping) else mark
        for mark in marks or ()
    ]
    if not signatures_listed(held):
        return observed_words(held, code)
    setting = code if code is not None else (lambda text: f"`{text}`")
    parts: list[str] = []
    for mark in held:
        name = detonation_named(getattr(mark, "detonation", ""))
        # A mark the builder writes always lists its signatures: one that
        # lists none, or names no detonation, has nothing these words state.
        if not name or not getattr(mark, "signatures", None):
            continue
        if name == FIRST_DETONATION:
            where = "the job's own detonation"
        else:
            number = name[1:] if name.startswith("d") else name
            where = f"detonation {number}, launched with {setting(launch_text(mark.launched_with))}"
        groups: dict[str, list[str]] = {}
        for signature in mark.signatures:
            written = launch_text(signature.name)
            named = setting(written) if written else "(no name)"
            listed = groups.setdefault(_tag_words(technique_id, signature, setting), [])
            if named not in listed:
                listed.append(named)
        said = [
            f"the sandbox signature {names[0]} tags {tag}"
            if len(names) == 1
            else f"the sandbox signatures {_listed(names)} tag {tag}"
            for tag, names in groups.items()
        ]
        parts.append(f"in {where}, {' and '.join(said)}")
    return ", and ".join(parts)


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
