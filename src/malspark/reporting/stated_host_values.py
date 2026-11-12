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
  A name, a folder or a file name counts only where both its ends are a value
  delimiter (:func:`delimited_in`): never a word of running text, never a
  URL's path; a path component and a stream after its file's name count.
* **Not a template.** A value holding a format placeholder (``%x``, ``%s``,
  ``{0}``) is a pattern the code fills in, which no log records whole.
* **Not every host's.** Not a known folder, a file Windows ships, a key or
  value every installation has, Windows' own service, pipe or stream, an
  object namespace or a word of a task definition
  (``data/host_benign_locations_v1.json``, declared data about Windows itself,
  each list with its criterion), and not the sample as the sandbox holds it (a
  file named by its digest or by the name it was submitted under).
* **A verdict that publishes.** Not Benign, and stated with a confidence, as a
  call binding's value is asked.

A name ordinary software also gives its own tasks, services and files (the
catalogue's ``generic_names``) is exported with a note that it may match
ordinary software (:func:`listed_only`): listed, and never a matcher on its
own.

Bounds: at most :data:`MAX_STATED_ROWS` rows of a report are read, at most
:data:`MAX_CITED` cited entries of a row, and a value longer than
:data:`MAX_VALUE_CHARS` is refused unread. The checks are linear in the value;
the whole-value check reads only the cited entries the run's text index says
may hold the value, each once; a URL is looked for at most
``_URL_LOOKBACK`` characters before an occurrence.
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

# The note an exported generic name carries on every surface: it is listed
# (``/iocs``, MISP with ``to_ids`` off) and never becomes a matcher on its own
# (no YARA string, Sigma selection, Suricata content or STIX indicator).
GENERIC_NOTE = (
    "a name ordinary software also uses, so expect false positives; listed, never matched on alone"
)


def listed_only(answer: Any) -> bool:
    """Whether a published row is listed only: its answer carries :data:`GENERIC_NOTE`.

    Every consumer that turns a published value into a matcher asks this and
    leaves such a row out.
    """
    return GENERIC_NOTE in str(answer or "")


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
    object_namespaces: frozenset[str]
    windows_streams: frozenset[str]
    windows_services: frozenset[str]
    windows_pipes: frozenset[str]
    registry_keys: frozenset[str]
    registry_values: frozenset[str]
    task_definition_words: frozenset[str]
    generic_names: frozenset[str]
    # The 8.3 short-name stems of the known folders whose long names do not
    # fit 8.3 (``progra`` of ``Program Files``), derived from the list above.
    short_stems: frozenset[str]


@lru_cache(maxsize=4)
def benign_catalogue(path: str = DEFAULT_CATALOGUE) -> Catalogue:
    """The catalogue of host values every Windows system holds, from its data file."""
    document = json.loads(resolve_data(path).read_text(encoding="utf-8"))

    def _set(key: str) -> frozenset[str]:
        # Each list is ``{"criterion", "source", "entries"}``.
        listed = document.get(key) or {}
        entries = listed.get("entries") if isinstance(listed, dict) else listed
        return frozenset(str(word).lower() for word in entries or () if word)

    known = _set("known_folders")
    system = _set("system_folders")
    return Catalogue(
        known_folders=known,
        known_folder_prefixes=tuple(sorted(_set("known_folder_prefixes"))),
        environment_folders=_set("environment_folders"),
        system_folders=system,
        system_binaries=_set("system_binaries"),
        object_namespaces=_set("object_namespaces"),
        windows_streams=_set("windows_streams"),
        windows_services=_set("windows_services"),
        windows_pipes=_set("windows_pipes"),
        registry_keys=_set("registry_keys"),
        registry_values=_set("registry_values"),
        task_definition_words=_set("task_definition_words"),
        generic_names=_set("generic_names"),
        short_stems=frozenset(
            squeezed[:6]
            for name in known | system
            if not name.startswith("%")
            for squeezed in [name.replace(" ", "").replace(".", "")]
            if len(squeezed) > 8 or squeezed != name
        ),
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
# An 8.3 short name: up to six characters, a tilde and a digit.
_SHORT_NAME_RE = re.compile(r"([^~]{1,6})~[1-9]")


def _components(value: str) -> list[str]:
    """A path's components, lower case, ``/`` read as ``\\``, each trimmed as Windows trims it.

    Windows ignores the dots and spaces a component ends with, so ``Windows. `` is
    ``windows``; an empty component is dropped.
    """
    text = value.strip().strip("\"'").replace("/", "\\")
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return [part for part in (raw.rstrip(". ") for raw in text.lower().split("\\")) if part]


def _known_component(part: str, previous: str, catalogue: Catalogue) -> bool:
    short = _SHORT_NAME_RE.fullmatch(part)
    return (
        part in catalogue.known_folders
        or part in catalogue.environment_folders
        or part in catalogue.system_folders
        or part.startswith(catalogue.known_folder_prefixes)
        or _DRIVE_RE.fullmatch(part) is not None
        or (short is not None and short.group(1) in catalogue.short_stems)
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
    parts = [part for part in (raw.rstrip(". ") for raw in text.split("\\")) if part]
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


def _sample_name(report: Any) -> str:
    """The name the sample was submitted under, its last component, lower case; ``""`` if none."""
    name = str(getattr(getattr(report, "identity", None), "file_name", "") or "")
    parts = _components(name)
    return parts[-1] if parts else ""


def _hiveless(value: str) -> str:
    from malspark.reporting.detection_signatures import hiveless_key

    return "\\".join(_components(hiveless_key(value, value_suffix=False)))


def benign_reason(
    kind: HostKind,
    value: str,
    sample_digests: frozenset[str] = frozenset(),
    sample_name: str = "",
) -> str:
    """Why a value of ``kind`` is every host's, in the rule's words, or ``""``.

    Read against the catalogue (:func:`benign_catalogue`) by the value's shape:
    a key or value every installation has (a key under the Services key named
    after a Windows service among them) for a registry key or value; an object
    namespace, a word of a task definition, and Windows' own stream, service or
    pipe for a name; a known folder, or a program Windows ships written bare
    or in its system folders, for a folder, a file path or a file name; and
    the sample itself as the sandbox holds it: a file named by the sample's
    digest or by the name it was submitted under.
    """
    catalogue = benign_catalogue()
    if kind.shape == "key":
        key = _hiveless(value)
        parent, _, last = key.rpartition("\\")
        if key in catalogue.registry_keys or key in catalogue.registry_values:
            return "a registry key or value every Windows installation has"
        if parent in _SERVICES_KEYS and last in catalogue.windows_services:
            return "the registry key of a service Windows installs"
        return ""
    parts = _components(value)
    if not parts:
        return ""
    if kind.shape == "name":
        name = _bare_name(kind, value)
        if not name or name in catalogue.object_namespaces:
            return "a namespace of Windows' object manager, not a name"
        if name in catalogue.task_definition_words:
            return "a word of the Task Scheduler's task definition, which every task carries"
        own = {
            "ads": catalogue.windows_streams,
            "service": catalogue.windows_services,
            "named_pipe": catalogue.windows_pipes,
        }.get(kind.table_kind, frozenset())
        if name in own:
            return f"a {kind.label.lower()} Windows itself has on every installation"
        return ""
    if len(parts) == 1 and parts[0] in catalogue.task_definition_words:
        return "a word of the Task Scheduler's task definition, which every task carries"
    if _all_known(parts, catalogue):
        return "a Windows known folder"
    if kind.shape == "folder":
        return ""
    name = parts[-1]
    if name in catalogue.system_binaries and all(
        part in catalogue.system_folders or _DRIVE_RE.fullmatch(part) is not None
        for part in parts[:-1]
    ):
        return "a file Windows ships, in the folder Windows keeps it in"
    stem = name.rsplit(".", 1)[0]
    if stem in sample_digests:
        return "the sandbox's copy of the sample itself, named by its digest"
    if sample_name and name == sample_name:
        return "the sample's own file name, as it was submitted"
    return ""


# The Services key, under which each service has a key of its own name.
_SERVICES_KEYS = frozenset(
    {"system\\currentcontrolset\\services", "system\\controlset001\\services"}
)


def _bare_name(kind: HostKind, value: str) -> str:
    """A name without the object namespace or pipe root it is written under, lower case.

    ``Global\\x`` is ``x``, ``\\\\.\\pipe\\x`` is ``x``, a stream ``:x`` (or
    ``:x:$DATA``) is ``x``; a name of a namespace alone is the namespace.
    """
    catalogue = benign_catalogue()
    parts = _components(value)
    while len(parts) > 1 and (parts[0] in catalogue.object_namespaces or parts[0] == "."):
        parts = parts[1:]
    name = "\\".join(parts)
    if kind.table_kind == "ads":
        name = name.lstrip(":").split(":", 1)[0]
    return name


def is_generic(kind: HostKind, value: str) -> bool:
    """Whether a value is a name ordinary software also uses (the catalogue's ``generic_names``).

    A name is read past its object namespace; a file's name with and without
    its extension; a path or a folder with a folder of its own past the known
    folders is not generic, whatever its last name; a registry key or value is
    generic only when its last name is and it stands right under a key every
    installation has (a Run key's ``Updater``), not under a vendor's own key.
    """
    catalogue = benign_catalogue()
    generic = catalogue.generic_names
    if kind.shape == "key":
        parent, _, last = _hiveless(value).rpartition("\\")
        return last in generic and parent in catalogue.registry_keys
    if kind.shape in ("path", "folder") and "\\" in past_known_folders(value).strip("\\"):
        return False
    if kind.shape == "name":
        return _bare_name(kind, value) in generic
    parts = _components(value)
    name = parts[-1] if parts else ""
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
    # The sample's own digests and the name it was submitted under, which the
    # sandbox's copy of it carries.
    sample_digests: frozenset[str] = frozenset()
    sample_name: str = ""

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
        sample_name=_sample_name(report),
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
    benign = benign_reason(kind, stated.value, stated.sample_digests, stated.sample_name)
    if benign:
        return benign
    return ""


def stated_reason(stated: StatedHostValue) -> str:
    """Why an exported value stands: the analysis's statement and the entries holding it.

    A value STIX has no object for (a bare folder name, a task, a service, a
    stream, a pipe) says so; a mutex, a file, a rooted folder and a registry
    key or value are STIX indicators.
    """
    from malspark.reporting.renderers.stix_renderer import indicator_pattern

    kind = stated.kind
    word = kind.word if kind is not None else ""
    said = (
        f"stated by the analysis ({word}, {stated.use}), "
        f"found whole in {', '.join(stated.held_in or ())}"
    )
    if kind is not None and indicator_pattern(kind.table_kind, stated.value) is None:
        said += f"; {NO_STIX_OBJECT}"
    if kind is not None and is_generic(kind, stated.value):
        said += f"; {GENERIC_NOTE}"
    return said


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


# What a delimited value may stand between. Before it: a quote, a line break
# (as written or as its escape), a path separator, or the ``=`` / ``:`` of a
# key-value pair. After it: the same. Never a space, a comma or a full stop:
# those are running text, and a word of a tool's prose is no value.
_QUOTES = "\"'"
_LINE_BREAKS = "\n\r\t"
_ESCAPED_BREAKS = ("\\n", "\\r", "\\t")
_SEPARATORS = "\\/"
_PAIR_MARKS = "=:"
# What ends the token a URL is written in, and how far back a token is read:
# a URL is read only within this many characters before an occurrence, so a
# text of many occurrences costs its length times a constant.
_TOKEN_ENDS = " \t\n\r\"'<>()[]{},"
_URL_LOOKBACK = 2048


def _in_a_url(text: str, start: int) -> bool:
    """Whether the occurrence at ``start`` stands inside a URL token (``scheme://…``)."""
    low = max(0, start - _URL_LOOKBACK)
    cut = max(text.rfind(end, low, start) for end in _TOKEN_ENDS)
    return "://" in text[max(cut + 1, low) : start]


def _opens(text: str, start: int, separators: bool) -> bool:
    if start == 0:
        return True
    before = text[start - 1]
    if before in _QUOTES or before in _LINE_BREAKS or (separators and before in _SEPARATORS):
        return True
    if before in _PAIR_MARKS:
        return True
    # ``key: value`` and ``key = value``: one space after the mark.
    if before == " " and start >= 2 and text[start - 2] in _PAIR_MARKS:
        return True
    return text[max(0, start - 2) : start] in _ESCAPED_BREAKS


def _closes(text: str, end: int, separators: bool) -> bool:
    if end >= len(text):
        return True
    after = text[end]
    if after in _QUOTES or after in _LINE_BREAKS or after in _PAIR_MARKS:
        return True
    if separators and after in _SEPARATORS:
        return True
    # An escaped quote or line break after it (``\\"``, ``\\n``) ends a JSON string.
    return after == "\\" and text[end + 1 : end + 2] in ('"', "n", "r", "t")


def delimited_in(
    name: str, text: str, *, after_colon: bool = False, separators: bool = True
) -> bool:
    """Whether ``name`` stands in ``text`` as a value of its own, delimited at both ends.

    Both ends must be a value delimiter: a quote or the start or end of the
    text, a line break or its escape, a path separator, or the ``=`` / ``:`` of
    a key-value pair — never a space, a comma or a full stop of running text,
    so ``{"text": "updater"}`` holds ``updater`` and "installs an updater, which
    runs" does not. A path separator delimits only with ``separators`` (a
    folder's or a file's name is a path component; a mutex's, a task's or a
    service's name inside a path is that path's, not the name). An occurrence
    inside a URL is never a host value: a URL's path names no folder or file
    on a host. ``after_colon`` asks for a stream name, which follows the ``:``
    that ends its file's name (``a.exe:x``). One pass over the occurrences.
    """
    if not name or not text:
        return False
    start = text.find(name)
    while start != -1:
        end = start + len(name)
        opened = (
            (start > 0 and text[start - 1] == ":")
            if after_colon
            else _opens(text, start, separators)
        )
        if opened and _closes(text, end, separators) and not _in_a_url(text, start):
            return True
        start = text.find(name, start + 1)
    return False


def component_in(name: str, text: str) -> bool:
    """Whether ``name`` is a whole component of a path ``text`` writes (:func:`delimited_in`)."""
    return delimited_in(name, text)


def _delimited_shape(kind: HostKind | None) -> bool:
    """Whether a value of ``kind`` is held only where delimited: a name, a folder, a file name."""
    return kind is not None and kind.shape in ("name", "folder", "file_name")


def held_in_cited(entries: Any, item: Any) -> list[str]:
    """The entries a row cites that hold its value whole, as the row cites them.

    The value is read in every spelling a run's texts write it in
    (:func:`encodings`). A name, a folder or a file name counts only where it
    is delimited at both ends (:func:`delimited_in`): a quote, a line break, a
    key-value mark or, for a folder or a file name, a path separator; never
    running text and never a URL; a
    file name or folder written with leading separators is also read bare, as
    a path component; a stream is read as the name after its file's colon. A
    file path and a registry key or value are found whole as any value is
    (``whole_value_in``). Only the cited entries the text index says may hold
    the value are read (``EntryTexts.may_hold``), at most :data:`MAX_CITED`.
    """
    from malspark.agents._indicator_denylists import whole_value_in

    value = str(getattr(item, "value", "") or "").strip()
    if not value or len(value) > MAX_VALUE_CHARS or entries is None:
        return []
    kind = typed_kind(getattr(item, "kind", ""))
    lowered = value.lower()
    forms = encodings(lowered)
    stream = ""
    names: list[str] = []
    if kind is not None and kind.table_kind == "ads":
        stream = lowered.lstrip(":")
    elif kind is not None and kind.shape in ("folder", "file_name"):
        bare = lowered.strip("\\/")
        if bare and bare != lowered:
            names = encodings(bare)
    cited = _cited(getattr(item, "evidence_refs", None) or [])
    candidates: set[str] = set()
    for form in [*forms, *names, *([stream] if stream else [])]:
        candidates |= set(entries.may_hold(form))
    out: list[str] = []
    for ref in cited:
        if ref.lower() not in candidates and not _is_item(entries, ref):
            continue
        text = entries.text_of(ref)
        if not text:
            continue
        paths = kind is not None and kind.shape in ("folder", "file_name")
        if stream:
            held = any(delimited_in(form, text, separators=False) for form in forms) or any(
                delimited_in(form, text, after_colon=True, separators=False)
                for form in encodings(stream)
            )
        elif _delimited_shape(kind):
            held = any(delimited_in(form, text, separators=paths) for form in [*forms, *names])
        else:
            held = any(whole_value_in(form, text) for form in forms)
        if held:
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
