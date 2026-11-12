"""Host values the analysis states, checked value by value before any surface exports one.

The report model lists the identifiers a responder could look a host up by
(``TechnicalAnalysis.host_identifiers``): it types each one with the closed
vocabulary of ``data/host_identifier_kinds_v1.json`` and says what the evidence
shows the sample doing with it (``use``). The model decides what a value is;
this module checks, in code, whether the platform may export it. A row is
exported, as source ``analysis`` ("stated by the analysis"), only when every
one of these holds:

* **A typed kind with an object on some surface.** A mutex, a file path, a
  file name, a folder, a registry key or value, a scheduled task, a service, a
  named pipe or an alternate data stream. ``string`` and ``template`` name no
  host object; a free-text kind (a report stored before the vocabulary) is read
  and printed as written and never exported.
* **Created or written.** The model says the evidence shows the sample creating
  or writing it (``creates/writes``); a value it only reads or checks is every
  host's (a known folder's name, a key Windows keeps).
* **Whole in an entry it cites.** Code found the value whole in at least one of
  the ledger entries the row cites, when the composer applied the section
  (:func:`held_in_cited`, recorded as ``HostIdentifier.held_in``); a value only
  part of a longer one, or held only by an entry the row does not cite, is not.
  A folder or a file name counts as whole where it is a whole component of a
  path the entry writes.
* **Not a template.** A value holding a format placeholder (``%x``, ``%s``,
  ``{0}``) is a pattern the code fills in, which no log records whole.
* **Not every host's.** Not a known folder, a program Windows installs, a key
  every Windows installation has or a word of a task definition
  (``data/host_benign_locations_v1.json``, declared data about Windows itself),
  and not the sandbox's own copy of the sample (a file named by its digest).
* **A verdict that publishes.** Not Benign, and stated with a confidence, as a
  call binding's value is asked.

A name ordinary software also gives its own tasks, services and files (the
catalogue's ``generic_names``) is exported with a note that it may match
ordinary software, and never forms a Sigma selection.

Bounds: at most :data:`MAX_STATED_ROWS` rows of a report are read, at most
:data:`MAX_CITED` cited entries of a row, and a value longer than
:data:`MAX_VALUE_CHARS` is refused unread. The checks are linear in the value;
the whole-value check reads only the cited entries the run's text index says
may hold the value, each once.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from malspark.core.paths import resolve_data

DEFAULT_KINDS = "data/host_identifier_kinds_v1.json"
DEFAULT_CATALOGUE = "data/host_benign_locations_v1.json"

# The source an IOC row of a value the analysis states is recorded under.
ANALYSIS_SOURCE = "analysis"
# The one use that is exported.
CREATES_OR_WRITES = "creates/writes"

# How many rows of a report's identifier table are read, how many cited
# entries of one row, and the longest value checked. A Windows path may be
# longer than this, but no host value a responder searches for is.
MAX_STATED_ROWS = 256
MAX_CITED = 16
MAX_VALUE_CHARS = 1024

# The note an exported generic name carries on every surface.
GENERIC_NOTE = (
    "a name ordinary software also uses, so expect false positives; never selected on alone"
)
# What an exported value of a kind STIX has no object for says.
NO_STIX_OBJECT = "no STIX object for this kind; carried by /iocs, MISP and Sigma"


@dataclass(frozen=True)
class HostKind:
    """One word of the host-identifier vocabulary and what the IOC table makes of it."""

    word: str
    table_kind: str
    label: str
    shape: str
    words: str


@lru_cache(maxsize=4)
def host_kinds(path: str = DEFAULT_KINDS) -> dict[str, HostKind]:
    """``{word: kind}`` from the vocabulary, in its order."""
    document = json.loads(resolve_data(path).read_text(encoding="utf-8"))
    return {
        str(word): HostKind(
            word=str(word),
            table_kind=str(spec.get("table_kind") or ""),
            label=str(spec.get("label") or ""),
            shape=str(spec.get("shape") or ""),
            words=str(spec.get("words") or ""),
        )
        for word, spec in (document.get("kinds") or {}).items()
    }


@lru_cache(maxsize=4)
def host_uses(path: str = DEFAULT_KINDS) -> dict[str, str]:
    """``{use: words}`` from the vocabulary, in its order."""
    document = json.loads(resolve_data(path).read_text(encoding="utf-8"))
    return {str(use): str(words) for use, words in (document.get("uses") or {}).items()}


def kind_words() -> tuple[str, ...]:
    """The vocabulary's kind words, in its order: the schema's enum and the instruction's list."""
    return tuple(host_kinds())


def use_words() -> tuple[str, ...]:
    """The vocabulary's use words, in its order."""
    return tuple(host_uses())


def typed_kind(written: Any) -> HostKind | None:
    """The vocabulary kind a row is typed with, or ``None`` for a free-text kind.

    Read case-insensitively with runs of white space as one space, so
    ``Scheduled  Task`` is the word; nothing else is read as one (a
    ``Scheduled task name`` is free text).
    """
    word = " ".join(str(written or "").lower().split())
    return host_kinds().get(word)


def _written_use(written: Any) -> str:
    return " ".join(str(written or "").lower().split())


@dataclass(frozen=True)
class Catalogue:
    """The declared benign-location catalogue, folded to lower case."""

    known_folders: frozenset[str]
    known_folder_prefixes: tuple[str, ...]
    environment_folders: frozenset[str]
    system_folders: frozenset[str]
    system_binaries: frozenset[str]
    registry_keys: frozenset[str]
    task_definition_words: frozenset[str]
    generic_names: frozenset[str]


@lru_cache(maxsize=4)
def benign_catalogue(path: str = DEFAULT_CATALOGUE) -> Catalogue:
    """The catalogue of host values every Windows system holds, from its data file."""
    document = json.loads(resolve_data(path).read_text(encoding="utf-8"))

    def _set(key: str) -> frozenset[str]:
        return frozenset(str(word).lower() for word in document.get(key) or () if word)

    return Catalogue(
        known_folders=_set("known_folders"),
        known_folder_prefixes=tuple(sorted(_set("known_folder_prefixes"))),
        environment_folders=_set("environment_folders"),
        system_folders=_set("system_folders"),
        system_binaries=_set("system_binaries"),
        registry_keys=_set("registry_keys"),
        task_definition_words=_set("task_definition_words"),
        generic_names=_set("generic_names"),
    )


# An environment variable a path is written with (``%APPDATA%``): two or more
# characters between the signs, so ``%s%d`` is two placeholders, not a variable.
_ENVIRONMENT_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_()]{1,40}%")
# A printf conversion (a literal ``%%`` is matched so it is skipped), and a
# composite format item (``{0}``, ``{1:x}``). Every quantifier is bounded, so
# a value of any length is read in one linear pass.
_CONVERSION_RE = re.compile(
    r"%(?:%|[-+ #0]{0,5}(?:\d{1,4}|\*)?(?:\.(?:\d{1,4}|\*))?"
    r"(?:hh|h|ll|l|L|I64|I32|I|w|z|j|t)?[diouxXeEfgGaAcCsSpn])"
    r"|\{\d{1,3}(?:[,:][^{}]{0,32})?\}"
)


def is_template(value: Any) -> bool:
    """Whether a value holds a format placeholder: a pattern the code fills in, not a value."""
    text = _ENVIRONMENT_RE.sub(" ", str(value or ""))
    return any(match.group(0) != "%%" for match in _CONVERSION_RE.finditer(text))


_DRIVE_RE = re.compile(r"[a-z]:")


def _components(value: str) -> list[str]:
    """A path's components, lower case, ``/`` read as ``\\`` and no empty one."""
    text = value.strip().strip("\"'").replace("/", "\\")
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return [part for part in text.lower().split("\\") if part]


def _known_component(part: str, previous: str, catalogue: Catalogue) -> bool:
    return (
        part in catalogue.known_folders
        or part in catalogue.environment_folders
        or part.startswith(catalogue.known_folder_prefixes)
        or _DRIVE_RE.fullmatch(part) is not None
        # The profile's own name, which every user's folder carries.
        or previous == "users"
    )


def _all_known(parts: Sequence[str], catalogue: Catalogue) -> bool:
    return bool(parts) and all(
        _known_component(part, parts[at - 1] if at else "", catalogue)
        for at, part in enumerate(parts)
    )


def past_known_folders(value: str) -> str:
    """The part of a path a log writes the same on every host: past its known folders.

    The leading drive, environment folders, known folders and profile name
    are dropped (``%APPDATA%\\Vendor\\run.dll`` is ``Vendor\\run.dll``), in the
    case written, joined by ``\\``; ``""`` when nothing is left.
    """
    catalogue = benign_catalogue()
    text = value.strip().strip("\"'").replace("/", "\\")
    parts = [part for part in text.split("\\") if part]
    at = 0
    while at < len(parts) and _known_component(
        parts[at].lower(), parts[at - 1].lower() if at else "", catalogue
    ):
        at += 1
    return "\\".join(parts[at:])


def _sample_digests(report: Any) -> frozenset[str]:
    hashes = getattr(getattr(report, "identity", None), "hashes", None)
    return frozenset(
        str(getattr(hashes, name, "") or "").strip().lower()
        for name in ("sha256", "sha1", "md5")
        if str(getattr(hashes, name, "") or "").strip()
    )


def benign_reason(kind: HostKind, value: str, sample_digests: frozenset[str] = frozenset()) -> str:
    """Why a value of ``kind`` is every host's, in the rule's words, or ``""``.

    Read against the catalogue (:func:`benign_catalogue`) by the value's shape:
    a word of a task definition for any bare value; a key Windows keeps for a
    registry key or value; a known folder, or a program Windows installs that
    is written bare or in Windows' own system folders, for a folder, a file
    path or a file name; and the sandbox's copy of the sample, a file named by the
    sample's own digest.
    """
    catalogue = benign_catalogue()
    if kind.shape == "key":
        from malspark.reporting.detection_signatures import hiveless_key

        if hiveless_key(value, value_suffix=False).lower() in catalogue.registry_keys:
            return "a registry key every Windows installation has"
        return ""
    parts = _components(value)
    if not parts:
        return ""
    if len(parts) == 1 and parts[0].lstrip(":") in catalogue.task_definition_words:
        return "a word of the Task Scheduler's task definition, which every task carries"
    if kind.shape not in ("path", "file_name", "folder"):
        return ""
    if _all_known(parts, catalogue):
        return "a Windows known folder"
    if kind.shape == "folder":
        return ""
    name = parts[-1]
    if name in catalogue.system_binaries and all(
        part in catalogue.system_folders or _DRIVE_RE.fullmatch(part) is not None
        for part in parts[:-1]
    ):
        return "a program Windows installs, in the folder Windows keeps it in"
    stem = name.rsplit(".", 1)[0]
    if stem in sample_digests:
        return "the sandbox's copy of the sample itself, named by its digest"
    return ""


def _name_of(kind: HostKind, value: str) -> str:
    """The name a generic-name check reads: a path's last component, a stream without its colon."""
    parts = _components(value)
    name = parts[-1] if parts else value.strip().lower()
    return name.lstrip(":") if kind.shape == "name" else name


def is_generic(kind: HostKind, value: str) -> bool:
    """Whether a value is a name ordinary software also uses (the catalogue's ``generic_names``).

    A file's name is read with and without its extension; a path or a folder
    with a folder of its own past the known folders is not generic, whatever
    its last name.
    """
    generic = benign_catalogue().generic_names
    if kind.shape in ("path", "folder") and "\\" in past_known_folders(value).strip("\\"):
        return False
    name = _name_of(kind, value)
    return name in generic or (
        kind.shape in ("path", "file_name") and name.rsplit(".", 1)[0] in generic
    )


@dataclass(frozen=True)
class StatedHostValue:
    """One identifier row as the rule reads it: the model's typing and code's findings."""

    kind: HostKind | None
    use: str
    # The value as the row writes it, and the value the export carries: the
    # same, except a file name, which is carried without the separators
    # written before it.
    stated: str
    value: str
    held_in: tuple[str, ...] | None
    beyond_rows: bool = False
    # The sample's own digests, which a file the sandbox named after it carries.
    sample_digests: frozenset[str] = frozenset()

    @property
    def table_kind(self) -> str:
        return self.kind.table_kind if self.kind is not None else ""

    @property
    def label(self) -> str:
        return self.kind.label if self.kind is not None else ""


def exported_value(kind: HostKind | None, stated: str) -> str:
    """The value the export carries for a stated one: a file name without leading separators."""
    text = str(stated or "").strip()
    if kind is not None and kind.shape == "file_name":
        return text.lstrip("\\/")
    return text


def read_stated(item: Any, report: Any = None, *, beyond_rows: bool = False) -> StatedHostValue:
    """One ``HostIdentifier`` row of ``report`` as the rule reads it."""
    kind = typed_kind(getattr(item, "kind", ""))
    stated = str(getattr(item, "value", "") or "").strip()
    held = getattr(item, "held_in", None)
    return StatedHostValue(
        kind=kind,
        use=_written_use(getattr(item, "use", "")),
        stated=stated,
        value=exported_value(kind, stated),
        held_in=tuple(str(ref) for ref in held) if held is not None else None,
        beyond_rows=beyond_rows,
        sample_digests=_sample_digests(report),
    )


def stated_refusal(stated: StatedHostValue, verdict: Any) -> str:
    """Why the rule refuses a value the analysis states, or ``""`` when it exports it.

    The checks in the order the module states them; the first that fails is
    the reason.
    """
    from malspark.reporting.renderers.stix_renderer import UNSTATED_VERDICT, path_names_a_file

    kind = stated.kind
    if kind is None:
        return (
            "the analysis wrote it under a free-text kind, not one of the typed host kinds, "
            "so it is not exported"
        )
    if not stated.use:
        return (
            "the row states no use, as a report stored before the typed kinds writes it, "
            "so it is not exported"
        )
    if not kind.table_kind:
        if kind.word == "template":
            return "the analysis typed it a template, which no log records whole"
        return "the analysis typed it a string, which names no host object"
    if stated.use != CREATES_OR_WRITES:
        if stated.use == "reads/checks":
            return "the analysis says the sample only reads or checks it, which every host may do"
        return "the analysis does not show the sample creating or writing it"
    if stated.beyond_rows:
        return f"beyond the first {MAX_STATED_ROWS} identifier rows, which are the rows checked"
    if len(stated.stated) > MAX_VALUE_CHARS:
        return f"longer than {MAX_VALUE_CHARS} characters, longer than any host value checked"
    if str(verdict or "").strip().lower() == "benign":
        return "the verdict is Benign, which publishes no malicious indicator"
    if verdict == UNSTATED_VERDICT:
        return "the judge stated no verdict with a confidence"
    if stated.held_in is None:
        return "no whole-value check against its cited entries is recorded for this row"
    if not stated.held_in:
        return "its whole value is in none of the entries it cites"
    if is_template(stated.stated):
        return "it holds a format placeholder, so it is a template no log records whole"
    if kind.shape == "path" and not path_names_a_file(stated.value):
        return "names a directory or a root, not a file"
    if kind.shape == "file_name" and (
        not stated.value or "\\" in stated.value or "/" in stated.value
    ):
        return "written with a folder, it is not a file name"
    benign = benign_reason(kind, stated.value, stated.sample_digests)
    if benign:
        return benign
    return ""


def stated_reason(stated: StatedHostValue) -> str:
    """Why an exported value stands: the analysis's statement and the entries holding it."""
    kind = stated.kind
    word = kind.word if kind is not None else ""
    said = (
        f"stated by the analysis ({word}, {stated.use}), "
        f"found whole in {', '.join(stated.held_in or ())}"
    )
    if kind is not None and kind.table_kind not in _STIX_TABLE_KINDS:
        said += f"; {NO_STIX_OBJECT}"
    if kind is not None and is_generic(kind, stated.value):
        said += f"; {GENERIC_NOTE}"
    return said


# The IOC-table kinds a stated value is carried in STIX under: a mutex, a file
# (a path naming a file, or a file's name) and a registry key.
_STIX_TABLE_KINDS = frozenset({"mutex", "path", "registry"})


def analysis_kwargs(report: Any, item: Any, *, beyond_rows: bool = False) -> dict[str, Any]:
    """The rule's arguments for one identifier row: what it states and the verdict asked."""
    from malspark.reporting.renderers.stix_renderer import UNSTATED_VERDICT

    confident = getattr(report, "overall_confidence", None) is not None
    return {
        "stated": read_stated(item, report, beyond_rows=beyond_rows),
        "verdict": getattr(report, "verdict", None) if confident else UNSTATED_VERDICT,
    }


def identifier_answers(report: Any) -> list[tuple[StatedHostValue, str]]:
    """``(stated value, the rule's answer)`` for each identifier row, in the table's order.

    The answer is :func:`~malspark.reporting.renderers.stix_renderer.publish_answer`'s,
    asked under source ``analysis``: the IOC table adds a row for each one it
    publishes, and the identifier table prints every one beside its row.
    """
    from malspark.reporting.renderers.stix_renderer import publish_answer

    ta = getattr(report, "technical_analysis", None)
    rows = list(getattr(ta, "host_identifiers", None) or []) if ta is not None else []
    out: list[tuple[StatedHostValue, str]] = []
    for index, item in enumerate(rows):
        kwargs = analysis_kwargs(report, item, beyond_rows=index >= MAX_STATED_ROWS)
        stated = kwargs["stated"]
        out.append(
            (stated, publish_answer(stated.table_kind, stated.value, ANALYSIS_SOURCE, **kwargs))
        )
    return out


# What continues one label of a value, and the escape letters a JSON text
# writes after a backslash (``agents._indicator_denylists``' own reading).
_CONTINUES_A_LABEL_RE = re.compile(r"[A-Za-z0-9._\-@+%~]")
_ESCAPE_LETTERS = frozenset('nrt"\\/bf')
_SEPARATORS = "\\/"


def component_in(name: str, text: str) -> bool:
    """Whether ``name`` is a whole component of a path ``text`` writes.

    Bounded by a path separator on one side at least, and on each side by a
    separator, a character that ends a label, or the text's end. A backslash
    before a name opening with an escape letter is read as a separator only
    where it is doubled (JSON writes a separator as two). One pass over the
    occurrences of the name.
    """
    if not name or not text:
        return False
    start = text.find(name)
    while start != -1:
        end = start + len(name)
        before = text[start - 1] if start else ""
        after = text[end] if end < len(text) else ""
        sep_before = before == "/" or (
            before == "\\"
            and (name[0] not in _ESCAPE_LETTERS or (start >= 2 and text[start - 2] == "\\"))
        )
        sep_after = after in _SEPARATORS and bool(after)
        ends_before = sep_before or not before or not _CONTINUES_A_LABEL_RE.match(before)
        ends_after = sep_after or not after or not _CONTINUES_A_LABEL_RE.match(after)
        if (sep_before or sep_after) and ends_before and ends_after:
            return True
        start = text.find(name, start + 1)
    return False


def held_in_cited(entries: Any, item: Any) -> list[str]:
    """The entries a row cites that hold its value whole, as the row cites them.

    The value is read in every spelling a run's texts write it in
    (:func:`encodings`) and found whole (``whole_value_in``); a folder or
    a file name also as a whole component of a path (:func:`component_in`).
    Only the cited entries the text index says may hold the value are read
    (``EntryTexts.may_hold``), at most :data:`MAX_CITED` of them.
    """
    from malspark.agents._indicator_denylists import whole_value_in

    value = str(getattr(item, "value", "") or "").strip()
    if not value or len(value) > MAX_VALUE_CHARS or entries is None:
        return []
    kind = typed_kind(getattr(item, "kind", ""))
    lowered = value.lower()
    forms = encodings(lowered)
    names: list[str] = []
    if kind is not None and kind.shape in ("folder", "file_name"):
        bare = lowered.strip("\\/")
        if bare and "\\" not in bare and "/" not in bare:
            names = [bare]
    cited = _cited(getattr(item, "evidence_refs", None) or [])
    candidates: set[str] = set()
    for form in [*forms, *names]:
        candidates |= set(entries.may_hold(form))
    out: list[str] = []
    for ref in cited:
        if ref.lower() not in candidates and not _is_item(entries, ref):
            continue
        text = entries.text_of(ref)
        if not text:
            continue
        if any(whole_value_in(form, text) for form in forms) or any(
            component_in(form, text) for name in names for form in encodings(name)
        ):
            out.append(ref)
    return out


def encodings(value: str) -> list[str]:
    """How a run's texts write ``value`` itself: as written, as JSON, as the pack quotes it.

    Never what the value's own escapes would spell: a value written
    ``\\Machine\\x5c`` is not held by a text that writes ``\\Machine\\``.
    """
    from malspark.utils.written_forms import pack_escaped

    forms: list[str] = []
    for form in (
        value,
        json.dumps(value, ensure_ascii=False)[1:-1],
        json.dumps(value)[1:-1],
        pack_escaped(value),
        pack_escaped(value, delimiters=True),
        pack_escaped(value, ids=True),
        pack_escaped(value, delimiters=True, ids=True),
    ):
        if form and form not in forms:
            forms.append(form)
    return forms


def _cited(refs: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for ref in refs:
        text = str(ref or "").strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
        if len(out) >= MAX_CITED:
            break
    return out


def _is_item(entries: Any, ref: str) -> bool:
    """Whether a citation names a sandbox item, which no text index of entries offers."""
    return ref.lower() not in getattr(entries, "texts", {}) and bool(entries.text_of(ref))


def with_held_in(rows: list[Any], entries: Any) -> list[Any]:
    """The rows with ``held_in`` written by code: the cited entries holding each value whole.

    ``None`` on every row when the run holds no entry text to check against,
    and on each row past :data:`MAX_STATED_ROWS`; whatever a model wrote there
    is replaced.
    """
    for index, item in enumerate(rows):
        item.held_in = (
            held_in_cited(entries, item)
            if entries is not None and index < MAX_STATED_ROWS
            else None
        )
    return rows
