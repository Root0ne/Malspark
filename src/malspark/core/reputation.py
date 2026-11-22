"""A reputation answer, read once through its tool's declared paths into one record.

Any server whose tool declares ``kind: reputation`` (``ToolFacts.kind``) is a
reputation source: the triage pack asks it when it also declares the argument
it takes a hash in (``arguments.hash``), the judge counts it as a lookup tool
and as a source asked, and its answer is read by the paths its declaration
gives (``ToolFacts.reputation``: counts, labels, detections, dates, link,
summary, prose patterns) into one typed record, :class:`ReputationRecord`.

**The writer** (:func:`record_at_write`). The record is read when the entry is
written (``schemas.evidence.build_entry``), from the facts the entry stores
(``core.declared_reading.facts_record``), and stored beside them
(``LedgerEntry.reputation``); the report carries every record
(``MalwareReport.reputation``). A re-render, the API and the console read the
record as stored, never the reading process's settings.

**The reader** (:func:`reputation_of`). The record an entry stored; for an
entry that stored none (written before records were, or a test's), the same
reading of its answer through the facts it stored, or, for an entry with no
source and no facts, the facts the platform ships for its tool's name
(``core.declared_reading.facts_of``). Nothing here reads a tool by its name or
an answer by one service's shape: a lookup is read by the paths its
declaration gives (the threat-intel sidecar declares its own), and a lookup
read from its server's listing (``core.derived_declarations``), which names
the shape reader, by the shape every reputation answer has
(:func:`read_shape`): its engine counts, labels, detections, dates and link.

**The lookups** (:func:`pack_lookups`, :func:`lookup_servers`,
:func:`is_lookup_tool`) are read from the live declarations, where nothing
persisted depends on the answer: which call the pack makes, and which tools
the judge holds.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from malspark.core.tool_declarations import ReputationFacts, ToolDeclarations, ToolFacts

# The kind a reputation lookup about the sample declares.
REPUTATION_KIND = "reputation"
# The version of the stored record's shape.
RECORD_VERSION = 1
# The argument role a lookup takes the sample's hash in (``ToolFacts.arguments``).
HASH_ARGUMENT = "hash"
# The argument roles a network indicator is given to a tool in, and every role
# that carries an indicator: the sample's hash and those.
NETWORK_INDICATOR_ARGUMENTS: tuple[str, ...] = ("domain", "ip", "url")
INDICATOR_ARGUMENTS: tuple[str, ...] = (HASH_ARGUMENT, *NETWORK_INDICATOR_ARGUMENTS)
# Per network indicator role, the words of an argument's name and the schema
# formats that say it takes one: the one copy a proposal
# (``declaration_proposals``) and a listing's reading
# (``derived_declarations``) read an argument's role by.
INDICATOR_ROLE_WORDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "ip": (frozenset({"ip", "ipv4", "ipv6"}), frozenset({"ipv4", "ipv6"})),
    "domain": (frozenset({"domain", "hostname", "fqdn"}), frozenset({"hostname", "idn-hostname"})),
    "url": (frozenset({"url", "uri"}), frozenset({"uri", "iri"})),
}
# The kinds a lookup about an indicator declares, beside a reputation lookup
# about the sample: a service's report on an indicator, and its reputation.
INDICATOR_LOOKUP_KINDS: tuple[str, ...] = ("indicator_report", "indicator_reputation")
# The role a tool server declares when it answers reputation lookups
# (``MCPServerConfig.roles``), as the built-in lookup servers do.
REPUTATION_ROLE = "reputation"
# The rank a lookup whose declaration names none is asked at.
DEFAULT_RANK = 100


class ReputationRecord(BaseModel):
    """What one reputation answer said about the sample, as its declaration reads it.

    ``service`` is the name the answer is attributed to. ``malicious``,
    ``suspicious`` and ``total`` are engine counts, ``engines`` the engine
    count the service gave beside them, ``stats`` the whole-number counts of
    the answer's counts object as written. ``labels`` are the threat labels
    in the order they were read, ``detections`` the per-engine result labels.
    ``first_seen`` and ``last_seen`` are dates (ISO-8601 as written, or from
    whole seconds since the epoch), ``link`` a URL the answer carried, and
    ``summary`` the service's own sentence. A field the answer did not give
    is ``None`` or empty: a record never holds a value its answer did not.

    Stored beside the values when the record is written, and read by no
    decision: ``names``, per count field (``stats``, ``malicious``,
    ``suspicious``, ``engines``, ``total``), the keys of the answer it was
    read under (:func:`key_path`), held only where every count of the record
    was read under a key; ``unread``, how many members of the counts object
    are no whole number and were not read; ``not_whole``, the count fields
    whose key held a value that is no whole number. A record written before
    them holds none of the three.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    v: int = RECORD_VERSION
    service: str = ""
    malicious: int | None = None
    suspicious: int | None = None
    total: int | None = None
    engines: int | None = None
    stats: dict[str, int] = Field(default_factory=dict)
    labels: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    link: str | None = None
    summary: str = ""
    names: dict[str, str] = Field(default_factory=dict)
    unread: int | None = None
    not_whole: list[str] = Field(default_factory=list)

    def says_something(self) -> bool:
        """Whether the answer established anything: a count, a label or the service's words."""
        return bool(
            self.malicious is not None
            or self.total is not None
            or self.engines is not None
            or self.labels
            or self.detections
            or self.summary
        )

    def engine_count(self) -> int | None:
        """How many engines the answer counted: the count it gave, else its total."""
        return self.engines if self.engines is not None else self.total

    def stored(self) -> dict[str, Any]:
        """The stored form: the version and every field the answer gave."""
        dumped = self.model_dump(mode="json", exclude_defaults=True)
        return {"v": RECORD_VERSION, **{k: v for k, v in dumped.items() if k != "v"}}


# The record's fields stored for the ledger's lines alone: the report carries
# none of them (``reporting.models.ReputationAnswer``).
LEDGER_ONLY = ("names", "unread", "not_whole")
# The words the counts line uses as labels of its own (:func:`counts_line`).
COUNT_LABELS = frozenset({"malicious", "suspicious", "engines", "total"})
_PLAIN_NAME = re.compile(r"[A-Za-z0-9_.-]+")


def member_name(name: str, labels: Iterable[str] = COUNT_LABELS) -> str:
    """A counts object's member name as a line or a row prints it.

    As the answer wrote it where it is a plain token (letters, digits, ``_``,
    ``.``, ``-``) that is none of the ``labels`` the platform prints beside
    it; otherwise as a quoted JSON string, so a reader sees it is the
    answer's own key and no name reads as a count or a label it is not.
    """
    if _PLAIN_NAME.fullmatch(name) and name not in labels:
        return name
    return json.dumps(name, ensure_ascii=False)


_KEY_TOKEN = re.compile(r"[A-Za-z0-9_-]+")
# The words a count is said with whose value the record's key held as no whole number.
NOT_WHOLE = "not read as a whole number"


def key_path(keys: Iterable[str | int]) -> str:
    """The keys of an answer a value was read under, as a line prints them.

    Each key as written where it is a plain token (letters, digits, ``_``,
    ``-``), otherwise as a quoted JSON string, joined by ``.``; an item of a
    list by its place, in brackets (``data[0].stats``). ``""`` for no key.
    """
    out = ""
    for key in keys:
        if isinstance(key, int):
            out += f"[{key}]"
            continue
        word = key if _KEY_TOKEN.fullmatch(key) else json.dumps(key, ensure_ascii=False)
        out = f"{out}.{word}" if out else word
    return out


def counts_line(
    record: ReputationRecord,
    *,
    unnamed: str = "Reputation lookup",
    written: Callable[[str], str] = str,
    every_member: bool = False,
    between: Sequence[str] = (),
) -> str:
    """The counts a record holds, as the platform prints them, or ``""`` when it holds none.

    Each count under the record's own name for it: the flagged count
    (``malicious``) always, or that the record holds none where its counts
    object holds no member of that name either; then each member of the
    answer's counts object (``stats``) that is not zero, in the order
    of ``stats`` as handed in (the answer's order where the record was read
    from the answer; a report read back from storage holds the members in
    the order storage gave them, which is then the order printed), under
    the name the answer wrote it under
    (:func:`member_name`: quoted where it is no plain token or is one of
    the line's own labels); the engine count the service gave beside them
    (``engines``); and the total, unless it is the sum of the members (a
    sum is never a count the answer gave). The member of the flagged or the
    suspicious name is left out only where it equals the record's field of
    that name, whose figure it then is (``suspicious`` printed in its
    place); where the two differ, or the record has no field of that name,
    the member is printed quoted, also a zero. ``suspicious`` the object
    does not hold is printed where it is not zero. A count field whose key
    held a value that is no whole number (``not_whole``: ``2.5``, a boolean,
    a digit string that does not convert) is said to be one where the line
    has a count to state, never as not counted. Never a fraction and no
    "of": the line names whose counts they are and claims no tally is whole.
    ``written`` writes the service's name and each member's name, the
    answer's words, for the surface.

    ``every_member`` is the line a model reads, which a later cut may
    shorten: every member, zeros too, with the flagged count and the engine
    count first and the members last, so a cut loses members and never
    those two; ``between`` (the caller's words about the same answer, its
    labels) stands after the record's own figures and before the members. A record that
    stores the keys its counts were read under (``names``) is then said
    under them (:func:`_read_under_keys`); one that stores none, every
    record written before they were, is said under the record's own names,
    as the record's.
    """
    if every_member and _keyed(record):
        return _read_under_keys(record, unnamed=unnamed, written=written, between=between)
    fields = {"malicious": record.malicious, "suspicious": record.suspicious}
    members: list[str] = []
    for name, value in record.stats.items():
        field_value = fields.get(name)
        if name in fields and value == field_value:
            if name == "suspicious" and (value or every_member):
                members.append(f"suspicious {value}")
            continue
        if value != 0 or name in fields or every_member:
            members.append(f"{written(member_name(name))} {value}")
    held = record.stats.get("suspicious")
    if (
        record.suspicious is not None
        and held != record.suspicious
        and (record.suspicious or held is not None or every_member)
    ):
        members.append(f"suspicious {record.suspicious}")
    engines: list[str] = []
    if record.engines is not None:
        engines.append(f"engines {record.engines}")
    total: list[str] = []
    summed = bool(record.stats) and record.total == sum(record.stats.values())
    if record.total is not None and not summed:
        total.append(f"total {record.total}")
    if not members and not engines and not total and record.malicious is None:
        return ""
    unreadable = [name for name in record.not_whole if name not in ("malicious", "engines")]
    members.extend(f"{written(member_name(name, ()))} {NOT_WHOLE}" for name in unreadable)
    if record.engines is None and "engines" in record.not_whole:
        engines.append(f"engines {NOT_WHOLE}")
    flagged: list[str] = []
    if record.malicious is not None:
        flagged.append(f"malicious {record.malicious}")
    elif "malicious" in record.not_whole:
        flagged.append(f"malicious {NOT_WHOLE}")
    elif "malicious" not in record.stats:
        flagged.append("malicious not counted")
    if every_member:
        parts = [*flagged, *engines, *total, *between, ", ".join(members)]
        said = "; ".join(part for part in parts if part)
    else:
        said = "; ".join([", ".join([*flagged, *members]), *engines, *total])
    return f"{written(record.service or unnamed)}, counts in the lookup's record: {said}"


def _keyed(record: ReputationRecord) -> bool:
    """Whether the record stores the key of every count it holds (``names``).

    A total with no key is the reader's sum of the members, never printed.
    """
    names = record.names
    if not names:
        return False
    held = [
        name
        for name, value in (
            ("malicious", record.malicious),
            ("suspicious", record.suspicious),
            ("engines", record.engines),
        )
        if value is not None
    ]
    held.extend(record.not_whole)
    if record.stats:
        held.append("stats")
    if record.total is not None and not (
        names.get("total") or (record.stats and record.total == sum(record.stats.values()))
    ):
        return False
    return all(names.get(name) for name in held)


def _read_under_keys(
    record: ReputationRecord,
    *,
    unnamed: str,
    written: Callable[[str], str],
    between: Sequence[str] = (),
) -> str:
    """A record's counts under the keys of the answer they were read under (``names``).

    The flagged count first under its keys, or that none was read; the engine
    count; a suspicious count and a total read under keys of their own (a
    total the reader summed has no key and is never printed); the caller's
    ``between``; then every member of the counts object, zeros too, said to
    be read from it, the one
    the flagged count is left out where it is that member's figure; then how
    many of its members are no whole number and were not read. A count whose
    key held a value that is no whole number is said to be one.
    """
    names = record.names
    counts = names.get("stats", "")

    def member_of_counts(field: str) -> str | None:
        """The member of the counts object ``field`` was read as, if it was."""
        name = names.get(field, "")
        for key in record.stats:
            if counts and name == f"{counts}.{key_path([key])}":
                return key
        return None

    def said(field: str, value: int | None) -> str:
        if value is not None:
            return f"{written(names[field])} {value}"
        if field in record.not_whole:
            return f"{written(names[field])} {NOT_WHOLE}"
        return ""

    flagged_member = member_of_counts("malicious")
    parts = [said("malicious", record.malicious) or "no flagged count read"]
    parts.append(said("engines", record.engines))
    suspicious_member = member_of_counts("suspicious")
    if suspicious_member is None or record.stats.get(suspicious_member) != record.suspicious:
        parts.append(said("suspicious", record.suspicious))
    if "total" in names:
        parts.append(said("total", record.total))
    parts.extend(between)
    members = [
        f"{written(member_name(key, ()))} {value}"
        for key, value in record.stats.items()
        if not (key == flagged_member and value == record.malicious)
    ]
    if members:
        parts.append(f"counts read from {written(counts)}: {', '.join(members)}")
    if record.unread:
        plural = record.unread != 1
        parts.append(
            f"{record.unread} member{'s' if plural else ''} of {written(counts)} "
            f"not read as {'whole numbers' if plural else 'a whole number'}"
        )
    said_parts = "; ".join(part for part in parts if part)
    return f"{written(record.service or unnamed)}, read from the lookup's answer: {said_parts}"


def is_lookup(facts: ToolFacts | None) -> bool:
    """Whether a tool's facts declare a reputation lookup about the sample."""
    from malspark.core.builtin_declarations import REPUTATION_KINDS

    return facts is not None and facts.kind in REPUTATION_KINDS


def asks_about_an_indicator(facts: ToolFacts | None) -> bool:
    """Whether a tool's facts declare that it asks a service about the sample or an indicator.

    A reputation lookup (:func:`is_lookup`), a tool of an indicator lookup kind
    (:data:`INDICATOR_LOOKUP_KINDS`), or a tool that declares an argument
    carrying an indicator (:data:`INDICATOR_ARGUMENTS`), whatever its kind.
    """
    if facts is None:
        return False
    return (
        is_lookup(facts)
        or facts.kind in INDICATOR_LOOKUP_KINDS
        or any(role in facts.arguments for role in INDICATOR_ARGUMENTS)
    )


def kinds_of_capability(capability: str) -> frozenset[str]:
    """The tool kinds a ``ToolRef(kind="capability")`` names: the kind itself.

    ``reputation`` also names the kinds a stored server row may still declare
    its lookup under (``core.legacy_reputation``), so a row saved then keeps
    reaching the agents.
    """
    from malspark.core.builtin_declarations import REPUTATION_KINDS

    return frozenset(REPUTATION_KINDS) if capability == REPUTATION_KIND else frozenset({capability})


# ---------------------------------------------------------------------------
# Reading an answer
# ---------------------------------------------------------------------------


def _whole(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _first_whole(document: Any, path: str) -> int | None:
    from malspark.core.tool_declarations import select

    for found in select(document, path):
        whole = _whole(found)
        if whole is not None:
            return whole
    return None


def _moment(value: Any) -> str | None:
    """A date as the record holds it: ISO-8601 text as written, or from epoch seconds."""
    if isinstance(value, str):
        return value.strip() or None
    whole = _whole(value)
    if whole is None and isinstance(value, float) and not isinstance(value, bool):
        if not math.isfinite(value):
            return None
        whole = int(value)
    if whole is None or whole <= 0:
        return None
    try:
        return datetime.fromtimestamp(whole, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _first_moment(document: Any, paths: Iterable[str]) -> str | None:
    from malspark.core.tool_declarations import select

    for path in paths:
        for found in select(document, path):
            moment = _moment(found)
            if moment:
                return moment
    return None


def _first_link(document: Any, paths: Iterable[str]) -> str | None:
    from malspark.core.tool_declarations import select

    for path in paths:
        for found in select(document, path):
            if isinstance(found, str) and found.strip().lower().startswith(("http://", "https://")):
                return found.strip()
    return None


def _texts(document: Any, paths: Iterable[str]) -> list[str]:
    """Every text the paths name, a list's texts one by one, in order."""
    from malspark.core.tool_declarations import select

    out: list[str] = []
    for path in paths:
        for found in select(document, path):
            items = found if isinstance(found, list) else [found]
            out.extend(item.strip() for item in items if isinstance(item, str) and item.strip())
    return out


def _detections(document: Any, path: str) -> list[str]:
    """The per-engine labels: the first list the path names, each label's blanks squeezed.

    One label per engine, so they are counted, not merged: a label two
    engines gave is held twice.
    """
    from malspark.core.tool_declarations import select

    if not path:
        return []
    for found in select(document, path):
        if isinstance(found, list):
            return [" ".join(i.split()) for i in found if isinstance(i, str) and i.strip()]
    return []


def _once(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _document(output: str, structured: Any) -> Any:
    if isinstance(structured, dict | list):
        return structured
    text = (output or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        # An answer nested past the decoder's depth is read as no document.
        return None
    return parsed if isinstance(parsed, dict | list) else None


def read_answer(
    facts: ToolFacts, *, output: str, structured: Any = None, server: str | None = None
) -> ReputationRecord:
    """One reputation answer read through ``facts``' declared paths.

    Counts come from the declared paths; a count no path gave is looked for
    in the answer's text by the declared patterns. Linear in the size of the
    answer (``tool_declarations.select``, RE2 patterns). A lookup that names
    the shape reader (:data:`SHAPE_READER`: one read from its server's
    listing, ``core.derived_declarations``) is read by the answer's shape
    (:func:`read_shape`) when its declaration names no path, and only such a
    lookup: a stored entry's facts that name no reader read as they always
    did, and a declared path is always read.
    """
    from malspark.core.tool_declarations import ReputationFacts, first

    if facts.reader == SHAPE_READER and not declares_paths(facts.reputation):
        return _read_by_shape(facts, output=output, structured=structured, server=server)
    declared: ReputationFacts = facts.reputation or ReputationFacts()
    document = _document(output, structured)
    stats_found = first(document, declared.stats) if declared.stats else None
    stats = (
        {str(k): v for k, v in stats_found.items() if _whole(v) is not None}
        if isinstance(stats_found, Mapping)
        else {}
    )
    malicious = _first_whole(document, declared.malicious) if declared.malicious else None
    suspicious = _first_whole(document, declared.suspicious) if declared.suspicious else None
    total = _first_whole(document, declared.total) if declared.total else None
    engines = _first_whole(document, declared.engines) if declared.engines else None
    # The keys each count was read under, before a sum or the text adds one.
    keyed = {
        name: path
        for name, path, value in (
            ("malicious", declared.malicious, malicious),
            ("suspicious", declared.suspicious, suspicious),
            ("total", declared.total, total),
            ("engines", declared.engines, engines),
        )
        if value is not None
    }
    not_whole = [
        name
        for name, path in (
            ("malicious", declared.malicious),
            ("suspicious", declared.suspicious),
            ("total", declared.total),
            ("engines", declared.engines),
        )
        if name not in keyed and path and _holds_other_than_whole(document, path)
    ]
    from_text = False
    if total is None and stats:
        total = sum(stats.values())
    if malicious is None and declared.text_patterns:
        counted = declared.counts_in_text(str(output or ""))
        if counted is not None:
            from_text = True
            malicious, said_total, said_suspicious = counted
            total = total if total is not None else said_total
            suspicious = suspicious if suspicious is not None else said_suspicious
    names: dict[str, str] = {}
    unread: int | None = None
    if not from_text and (keyed or not_whole or stats):
        paths = {name: getattr(declared, name) for name in (*keyed, *not_whole)}
        if isinstance(stats_found, Mapping):
            paths["stats"] = declared.stats
        names = {name: _declared_keys(path) for name, path in paths.items()}
        if all(names.values()):
            if isinstance(stats_found, Mapping):
                unread = len(stats_found) - len(stats)
        else:
            names = {}
    if declared.summary and document is not None:
        summary = next(iter(_texts(document, [declared.summary])), "")
    else:
        # An answer written in prose is its own summary, also for a lookup
        # whose declared summary path reads its JSON answers.
        summary = "" if document is not None else str(output or "").strip()
    return ReputationRecord(
        service=declared.service or facts.display_name or str(server or ""),
        malicious=malicious,
        suspicious=suspicious,
        total=total,
        engines=engines,
        stats=stats,
        labels=_once(_texts(document, declared.labels)),
        detections=_detections(document, declared.detections),
        first_seen=_first_moment(document, declared.first_seen),
        last_seen=_first_moment(document, declared.last_seen),
        link=_first_link(document, declared.link),
        summary=summary,
        names=names,
        unread=unread,
        not_whole=not_whole,
    )


def _holds_other_than_whole(document: Any, path: str) -> bool:
    """Whether ``path`` names a value in ``document`` that is no whole number and not null."""
    from malspark.core.tool_declarations import select

    return any(found is not None and _whole(found) is None for found in select(document, path))


def _declared_keys(path: str) -> str:
    """The keys a declared path ends in, after its last wildcard or place, as :func:`key_path`.

    The keys any value the path names was read under: a ``*``, a ``**`` or a
    segment of digits (a list's place or a key, which the path does not say)
    leaves only the keys after it. ``""`` where none follows.
    """
    from malspark.core.tool_declarations import EVERY, parse_path

    keys: list[str] = []
    for segment in parse_path(path):
        if isinstance(segment, str) and segment != EVERY and not segment.isdigit():
            keys.append(segment)
        else:
            keys = []
    return key_path(keys)


# ---------------------------------------------------------------------------
# Reading an answer by its shape
# ---------------------------------------------------------------------------

# How deep the shape reading looks into an answer, and how many of its nodes
# it visits at most: a reputation answer holds its counts near the top.
SHAPE_DEPTH = 8
SHAPE_NODES = 20_000
# How many whole numbers an object of engine counts holds at least: an engine
# tally counts several verdicts, where a vote counts two.
TALLY_COUNTS = 3
# The verdicts an engine tally counts engines under: of two objects that hold
# a malicious count, the one counting more of them is the tally.
_VERDICT_KEYS = (
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "clean",
    "unrated",
    "timeout",
    "failure",
    "type-unsupported",
)
# The words of a key whose object is a vote, never an engine tally.
_VOTE_WORDS = frozenset({"vote", "votes"})
# The reader a lookup read from its server's listing names: its answer is read
# by its shape (:func:`read_shape`), not by paths.
SHAPE_READER = "reputation_shape"
# The count an object of engine counts is found by, and the counts read in it.
_MALICIOUS_KEYS = ("malicious", "positives")
_SUSPICIOUS_KEYS = ("suspicious",)
# The keys beside the counts that name the service the counts are attributed to.
_SERVICE_KEYS = ("source", "service", "provider", "vendor")
# The words of a key that say it holds a threat label, in the order the
# classes of label are read: a label or family itself, then threat names, then
# threat categories.
_LABEL_WORDS = frozenset({"label", "labels", "family", "families"})
_THREAT_NAME_WORDS = frozenset({"name", "names"})
_THREAT_CATEGORY_WORDS = frozenset({"category", "categories", "class", "classes"})
# The member of a label object that holds its text.
_LABEL_MEMBERS = ("value", "name", "label")
# The words of a key that say it holds when the sample was seen.
_WHEN_WORDS = frozenset({"seen", "submission", "submitted", "analysis", "scan", "scanned"})
_DATE_WORDS = frozenset({"date", "time", "timestamp"})
# The words of a key that say it holds a link to the service's report.
_LINK_WORDS = frozenset({"link", "permalink"})
_REPORT_LINK_WORDS = frozenset({"report", "gui", "html", "web", "page"})


def _key_words(key: str) -> frozenset[str]:
    """A key's words: split at ``_``, ``-`` and spaces, camelCase split, lowercased."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return frozenset(part for part in re.split(r"[_\-\s]+", spaced.lower()) if part)


@dataclass
class _Node:
    key: str
    value: Any
    depth: int
    parent: Any
    # The keys (and a list item's place) from the answer's top to this member.
    path: tuple[str | int, ...] = ()


def _shape_nodes(document: Any) -> list[_Node]:
    """Every keyed member of ``document`` within :data:`SHAPE_DEPTH`, shallowest first.

    Breadth first, each object's members in their order; a list's items are
    walked, never keyed. At most :data:`SHAPE_NODES` are visited, so the time
    is linear in the answer and bounded.
    """
    out: list[_Node] = []
    queue: list[tuple[Any, int, tuple[str | int, ...]]] = [(document, 0, ())]
    at = 0
    while at < len(queue) and len(out) < SHAPE_NODES:
        value, depth, path = queue[at]
        at += 1
        if depth >= SHAPE_DEPTH:
            continue
        if isinstance(value, Mapping):
            for key, member in value.items():
                if len(out) >= SHAPE_NODES:
                    break
                keyed = (*path, str(key))
                out.append(_Node(str(key), member, depth + 1, value, keyed))
                if isinstance(member, Mapping | list) and len(queue) < SHAPE_NODES:
                    queue.append((member, depth + 1, keyed))
        elif isinstance(value, list):
            for place, item in enumerate(value):
                if len(queue) >= SHAPE_NODES:
                    break
                if isinstance(item, Mapping | list):
                    queue.append((item, depth, (*path, place)))
    return out


def _wholes(held: Mapping[str, Any]) -> int:
    """How many of an object's first :data:`SHAPE_NODES` members are whole numbers."""
    count = 0
    for at, value in enumerate(held.values()):
        if at >= SHAPE_NODES:
            break
        if _whole(value) is not None:
            count += 1
    return count


def _label_class(words: frozenset[str]) -> int | None:
    if words & _LABEL_WORDS:
        return 0
    if "threat" in words and words & _THREAT_NAME_WORDS:
        return 1
    if "threat" in words and words & _THREAT_CATEGORY_WORDS:
        return 2
    return None


def _label_texts(value: Any) -> list[str]:
    """A label field's texts: a text, a list of texts, or the text member of each object."""
    items = value if isinstance(value, list) else [value]
    out: list[str] = []
    for item in items:
        if isinstance(item, Mapping):
            item = next((item[k] for k in _LABEL_MEMBERS if isinstance(item.get(k), str)), None)
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return out


def _sortable(moment: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(moment.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _extreme(moments: list[str], *, latest: bool) -> str | None:
    """The earliest (or latest) of ``moments`` that can be read as a time, else the first."""
    if not moments:
        return None
    timed = [(when, moment) for moment in moments if (when := _sortable(moment)) is not None]
    if not timed:
        return moments[0]
    pick = max if latest else min
    return pick(timed, key=lambda pair: pair[0])[1]


@dataclass
class ShapeReading:
    """What a reputation answer says, found by its shape (:func:`read_shape`)."""

    service: str = ""
    stats: dict[str, int] = field(default_factory=dict)
    malicious: int | None = None
    suspicious: int | None = None
    engines: int | None = None
    labels: list[str] = field(default_factory=list)
    detections: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    link: str | None = None
    # The keys each count was read under (``ReputationRecord.names``), and
    # how many members of the counts object are no whole number.
    names: dict[str, str] = field(default_factory=dict)
    unread: int | None = None


def read_shape(document: Any) -> ShapeReading:
    """A reputation answer read by its shape, for a lookup that declares no paths.

    By what any reputation answer holds, never by one service's field names:

    * the **counts**: the object whose ``malicious`` (or ``positives``) is a
      whole number and that holds at least :data:`TALLY_COUNTS` whole numbers,
      under a key that does not say vote (an engine tally, never a vote); of
      several, the one counting the most verdicts (malicious, suspicious,
      harmless, undetected …), then the most whole numbers; its whole numbers
      are ``stats``, its ``suspicious`` the
      suspicious count, and the ``source``, ``service``, ``provider`` or
      ``vendor`` text in it or beside it the service the counts are
      attributed to;
    * the **engine count**: the first whole number under a key whose words
      hold ``engines``;
    * the **detections**: the first list of texts under a key whose words hold
      ``detections``;
    * the **labels**: texts under a key that says label or family, then threat
      names, then threat categories, each class in the answer's order, a list
      of objects read by each one's ``value``, ``name`` or ``label``;
    * the **dates**: under a key that says ``first`` and when it was seen,
      submitted, analysed or scanned, the earliest; under one that says
      ``last`` (or names an analysis or scan date alone), the latest;
    * the **link**: the first ``http(s)`` text under a key that says link or
      permalink, or a URL of the report, its page or its interface.

    Shallowest first, within :data:`SHAPE_DEPTH`; linear in the answer.
    """
    out = ShapeReading()
    nodes = _shape_nodes(document)
    tally: tuple[int, int, int, int] | None = None
    tally_node: _Node | None = None
    labels: dict[int, list[str]] = {0: [], 1: [], 2: []}
    first: list[str] = []
    last: list[str] = []
    for order, node in enumerate(nodes):
        words = _key_words(node.key)
        if isinstance(node.value, Mapping) and not words & _VOTE_WORDS:
            count = next((node.value.get(k) for k in _MALICIOUS_KEYS if k in node.value), None)
            wholes = _wholes(node.value) if _whole(count) is not None else 0
            if wholes >= TALLY_COUNTS:
                verdicts = sum(1 for k in _VERDICT_KEYS if _whole(node.value.get(k)) is not None)
                rank = (verdicts, wholes, -node.depth, -order)
                if tally is None or rank > tally:
                    tally, tally_node = rank, node
        if out.engines is None and "engines" in words and _whole(node.value) is not None:
            out.engines = _whole(node.value)
            out.names["engines"] = key_path(node.path)
        if not out.detections and "detections" in words and isinstance(node.value, list):
            out.detections = [
                " ".join(i.split()) for i in node.value if isinstance(i, str) and i.strip()
            ]
        label_class = _label_class(words)
        if label_class is not None:
            labels[label_class].extend(_label_texts(node.value))
        if words & _WHEN_WORDS or words & _DATE_WORDS:
            moment = _moment(node.value)
            if moment and "first" in words and words & _WHEN_WORDS:
                first.append(moment)
            elif moment and (
                ("last" in words and words & _WHEN_WORDS)
                or ("first" not in words and words & {"analysis", "scan"} and words & _DATE_WORDS)
            ):
                last.append(moment)
        if out.link is None and isinstance(node.value, str):
            text = node.value.strip()
            names_a_link = bool(words & _LINK_WORDS) or (
                bool(words & {"url", "uri"}) and bool(words & _REPORT_LINK_WORDS)
            )
            if names_a_link and text.lower().startswith(("http://", "https://")):
                out.link = text
    if tally_node is not None:
        held = tally_node.value
        out.stats = {str(k): v for k, v in held.items() if _whole(v) is not None}
        out.unread = len(held) - len(out.stats)
        flagged = next(k for k in _MALICIOUS_KEYS if k in held)
        out.malicious = _whole(held[flagged])
        out.names["stats"] = key_path(tally_node.path)
        out.names["malicious"] = key_path((*tally_node.path, flagged))
        suspicious = next((k for k in _SUSPICIOUS_KEYS if _whole(held.get(k)) is not None), None)
        if suspicious is not None:
            out.suspicious = _whole(held[suspicious])
            out.names["suspicious"] = key_path((*tally_node.path, suspicious))
        for around in (held, tally_node.parent):
            named = next(
                (around[k].strip() for k in _SERVICE_KEYS if isinstance(around.get(k), str)),
                "",
            )
            if named:
                out.service = named
                break
    out.labels = _once([label for cls in (0, 1, 2) for label in labels[cls]])
    out.first_seen = _extreme(first, latest=False)
    out.last_seen = _extreme(last, latest=True)
    return out


def declares_paths(declared: ReputationFacts | None) -> bool:
    """Whether a lookup's declaration says where its answer holds anything (a path or pattern)."""
    if declared is None:
        return False
    return bool(
        declared.stats
        or declared.malicious
        or declared.suspicious
        or declared.total
        or declared.labels
        or declared.detections
        or declared.engines
        or declared.first_seen
        or declared.last_seen
        or declared.link
        or declared.summary
        or declared.text_patterns
    )


def _read_by_shape(
    facts: ToolFacts, *, output: str, structured: Any = None, server: str | None = None
) -> ReputationRecord:
    """One reputation answer read by its shape: a lookup that names :data:`SHAPE_READER`."""
    declared = facts.reputation
    document = _document(output, structured)
    shape = read_shape(document) if document is not None else ShapeReading()
    total = sum(shape.stats.values()) if shape.stats else None
    return ReputationRecord(
        service=(declared.service if declared is not None else "")
        or facts.display_name
        or shape.service
        or str(server or ""),
        malicious=shape.malicious,
        suspicious=shape.suspicious,
        total=total,
        engines=shape.engines,
        stats=shape.stats,
        labels=shape.labels,
        detections=shape.detections,
        first_seen=shape.first_seen,
        last_seen=shape.last_seen,
        link=shape.link,
        summary="" if document is not None else str(output or "").strip(),
        names=shape.names,
        unread=shape.unread,
    )


# ---------------------------------------------------------------------------
# The writer and the reader
# ---------------------------------------------------------------------------


def record_at_write(
    facts_record: Mapping[str, Any] | None,
    *,
    ok: bool,
    output: str,
    structured: Any = None,
    server: str | None = None,
    source: str | None = None,
) -> dict[str, Any] | None:
    """The stored record of an answer whose entry stored ``facts_record``, or ``None``.

    ``None`` for a call that did not answer and for a tool that is not a
    declared reputation lookup. Called once, when the entry is written. A
    lookup whose facts name no service is attributed to its tool server by
    the server's display name (``MCPServerConfig.label``), read now from the
    source the entry is recorded under (``source``), else by its key.
    """
    if not ok or not isinstance(facts_record, Mapping):
        return None
    from malspark.core.declared_reading import facts_of

    facts = facts_of({"facts": facts_record})
    if not is_lookup(facts):
        return None
    assert facts is not None
    try:
        # Read off the stored record itself: both are names, not readings.
        declared = facts_record.get("reputation")
        named = facts_record.get("display_name") or (
            declared.get("service") if isinstance(declared, Mapping) else ""
        )
        if not str(named or "").strip():
            server = server_label(source, server)
        return read_answer(facts, output=output, structured=structured, server=server).stored()
    except Exception as exc:  # noqa: BLE001 — a record is never worth a lost entry
        from malspark.core.logger import logger

        logger.debug("reputation record not written (%s).", type(exc).__name__)
        return None


def server_label(source: str | None, server: str | None) -> str | None:
    """The display name of the tool server ``source`` names (``mcp:<key>``), else ``server``.

    The label the operator gave the server's block; a server with none, a
    source that is not a tool server's, or settings that cannot be read give
    ``server`` back unchanged.
    """
    kind, _, key = str(source or "").partition(":")
    if kind != "mcp" or not key:
        return server
    try:
        from malspark.core.declared_reading import declarations

        held = declarations().source(f"mcp:{key}")
    except Exception as exc:  # noqa: BLE001 — a name is never worth a lost record
        from malspark.core.logger import logger

        logger.debug("the label of tool server %s was not read (%s).", key, type(exc).__name__)
        return server
    label = str(getattr(held, "label", "") or "").strip()
    return label or server


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def stored_record(held: Any) -> ReputationRecord | None:
    """A stored record as a record; ``None`` for one that is absent or cannot be read."""
    if not isinstance(held, Mapping):
        return None
    try:
        return ReputationRecord.model_validate(dict(held))
    except ValueError:
        return None


def holds_a_service_answer(entry: Any) -> bool:
    """Whether an entry's output is the service's own answer, read from its flags alone.

    Not a call that failed (``ok`` false), not a repeat (``repeated_of``: its
    output points at the earlier entry), and not an answer the platform cut or
    replaced (``truncated`` with an output left: the answer the conversation
    had no room for, or one cut to a prefix). An entry the byte budget blanked
    keeps no output and nothing to read, so it reads as nothing either way.
    """
    if _field(entry, "ok") is False or _field(entry, "repeated_of"):
        return False
    return not (_field(entry, "truncated") and str(_field(entry, "output") or ""))


def reputation_of(entry: Any) -> ReputationRecord | None:
    """The reputation record of an entry, or ``None`` when it holds no reputation answer.

    The record the entry stored when it was written. An entry that stored
    none and answered is read the same way now, through the facts it stored
    (an entry with no source and no facts through the facts shipped for its
    tool's name); never through the reading process's settings.
    """
    held = stored_record(_field(entry, "reputation"))
    if held is not None:
        return held
    if not holds_a_service_answer(entry):
        return None
    from malspark.core.declared_reading import facts_of

    facts = facts_of(entry)
    if not is_lookup(facts):
        return None
    assert facts is not None
    return read_answer(
        facts,
        output=str(_field(entry, "output") or ""),
        structured=_field(entry, "structured"),
        server=_field(entry, "server"),
    )


def is_lookup_entry(entry: Any) -> bool:
    """Whether an entry is a call to a reputation lookup, answered or not."""
    from malspark.core.declared_reading import facts_of

    return is_lookup(facts_of(entry))


def asked(rows: Iterable[Any] | None) -> bool:
    """Whether any entry of a ledger is a call to a reputation lookup.

    A row that cannot be read (not an entry, not a mapping) is passed over:
    one malformed row must not cost the answer.
    """
    for row in rows or ():
        if not isinstance(row, Mapping) and not hasattr(row, "tool"):
            continue
        if is_lookup_entry(row):
            return True
    return False


# ---------------------------------------------------------------------------
# The live lookups
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Lookup:
    """One reputation lookup the pack may ask: its server, tool and hash argument."""

    server: str
    tool: str
    hash_argument: str
    rank: int
    enabled: bool


def _shipped_rank(server: str, tool: str) -> int | None:
    """The rank built-in ``server``'s lookup ``tool`` declares as it ships, or ``None``.

    Its shipped block's, else what its server declares of itself
    (``declared_reading.builtin_tools``).
    """
    from malspark.core.declared_reading import builtin_tools

    shipped = builtin_tools(server).get(tool)
    declared = shipped.reputation if shipped is not None else None
    if declared is None or "rank" not in declared.model_fields_set:
        return None
    return declared.rank


def _rank(server: str, tool: str, facts: ToolFacts, cfg: Any = None) -> int:
    """A lookup's rank: as declared; else the shipped rank; else its server's; else 100.

    A server row stored with an edited ``tool_facts`` block written before
    ranks were declared keeps its place in the order the platform ships. A
    lookup whose declaration names no rank takes the rank its server block
    says of the service as a whole (``reputation_service.rank``).
    """
    declared = facts.reputation
    if declared is not None and "rank" in declared.model_fields_set:
        return declared.rank
    shipped = _shipped_rank(server, tool)
    if shipped is not None:
        return shipped
    service_rank = getattr(getattr(cfg, "reputation_service", None), "rank", None)
    return service_rank if isinstance(service_rank, int) else DEFAULT_RANK


def pack_lookups(servers: Mapping[str, Any], declared: ToolDeclarations) -> list[Lookup]:
    """Every server's declared reputation lookup that takes a hash, in the order the pack asks.

    ``servers`` is ``mcp.servers`` in its configured order; a server's
    ``tools`` list, where it names one, holds the only tools of it the pack may
    ask (an unticked tool is never the pack's call). The lowest
    ``rank`` first; lookups of one rank in their servers' order, and a
    server's own lookups in their declaration's order.
    """
    found: list[Lookup] = []
    for key, cfg in servers.items():
        held = declared.source(f"mcp:{key}")
        if held is None:
            continue
        # The block's tick list, where it names one: only a ticked tool is
        # ever the pack's own call.
        ticked = getattr(cfg, "tools", None)
        for name, facts in held.tools.items():
            if ticked is not None and str(name) not in set(ticked):
                continue
            argument = facts.arguments.get(HASH_ARGUMENT, "")
            if is_lookup(facts) and argument:
                found.append(
                    Lookup(
                        server=str(key),
                        tool=str(name),
                        hash_argument=argument,
                        rank=_rank(str(key), str(name), facts, cfg),
                        enabled=bool(getattr(cfg, "enabled", False)),
                    )
                )
    return sorted(found, key=lambda lookup: lookup.rank)


def lookup_servers(declared: ToolDeclarations) -> set[str]:
    """The keys of every tool server that declares a reputation lookup."""
    return {
        d.source.key
        for d in declared.sources()
        if d.source.kind == "mcp" and any(is_lookup(f) for f in d.tools.values())
    }


def is_lookup_tool(declared: ToolDeclarations, server: str, tool: str) -> bool:
    """Whether ``server``'s tool ``tool`` is a reputation lookup.

    ``tool`` is the name the server declares it under (for a tool the request
    holds, ``agents.tool_pinning.declared_name_of``), looked up exactly: a
    ``<server>__`` prefix is never taken off by the name alone.
    """
    return bool(server) and is_lookup(declared.declaration_for((f"mcp:{server}", tool), exact=True))
