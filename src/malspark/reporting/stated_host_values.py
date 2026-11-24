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
* **Not every host's.** Not a path made only of drives, names Windows gives
  its own folders and a profile name, a file Windows ships, a key or value
  every installation has, a service's settings subkey, Windows' own service,
  pipe or stream, an object namespace or a word of a task definition
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
    # The object namespaces a name of this kind is written under
    # (``global\\`` for a mutex, ``\\\\.\\pipe\\`` for a pipe), lower case.
    namespaces: tuple[str, ...] = ()
    # The kinds the sandbox records a value of this kind under (a registry
    # value's path as a ``registry`` key's), each asked by the placement check.
    sandbox_kinds: tuple[str, ...] = ()


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
            namespaces=tuple(str(ns).lower() for ns in spec.get("namespaces") or () if ns),
            sandbox_kinds=tuple(str(sk) for sk in spec.get("sandbox_kinds") or () if sk),
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
    # The known folders written as more than one component (``microsoft\\windows``),
    # each as its components: known only as that sequence.
    known_sequences: tuple[tuple[str, ...], ...]
    # The folders such a sequence must directly follow, each as its components.
    sequence_parents: tuple[tuple[str, ...], ...]
    known_folder_prefixes: tuple[str, ...]
    environment_folders: frozenset[str]
    system_folders: frozenset[str]
    # The forms a path names the system root by (``windows``,
    # ``%systemdrive%\\windows``), each as its components.
    system_roots: tuple[tuple[str, ...], ...]
    system_binaries: frozenset[str]
    object_namespaces: frozenset[str]
    windows_streams: frozenset[str]
    windows_services: frozenset[str]
    windows_pipes: frozenset[str]
    registry_keys: frozenset[str]
    registry_values: frozenset[str]
    # The names Windows gives the subkeys it keeps a service's settings in.
    service_settings_subkeys: frozenset[str]
    submission_roots: frozenset[str]
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

    listed_known = _set("known_folders")
    known = frozenset(name for name in listed_known if "\\" not in name)
    # The .NET Framework's folders and tools stand in the same chain as
    # Windows' own, each list with its own criterion.
    system = _set("system_folders") | _set("dotnet_framework_folders")
    return Catalogue(
        known_folders=known,
        known_sequences=tuple(
            tuple(part for part in name.split("\\") if part)
            for name in sorted(listed_known - known)
        ),
        sequence_parents=tuple(
            tuple(part for part in name.split("\\") if part)
            for name in sorted(_set("known_sequence_parents"))
        ),
        known_folder_prefixes=tuple(sorted(_set("known_folder_prefixes"))),
        environment_folders=_set("environment_folders"),
        system_folders=system,
        system_roots=tuple(
            tuple(part for part in root.split("\\") if part)
            for root in sorted(_set("system_roots"))
        ),
        system_binaries=_set("system_binaries") | _set("dotnet_framework_tools"),
        object_namespaces=_set("object_namespaces"),
        windows_streams=_set("windows_streams"),
        windows_services=_set("windows_services"),
        windows_pipes=_set("windows_pipes"),
        registry_keys=_set("registry_keys"),
        registry_values=_set("registry_values"),
        service_settings_subkeys=_set("service_settings_subkeys"),
        submission_roots=_set("submission_roots"),
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


def _system_chain(parts: Sequence[str], catalogue: Catalogue) -> list[bool]:
    """Which of a path's components stand in the %SystemRoot% chain.

    The chain starts at a declared form of the system root (the catalogue's
    ``system_roots``) written where the path starts or right after a drive,
    and runs on through the system folders that follow it, one under another;
    a root's name anywhere else (``%APPDATA%\\Windows``) starts nothing.
    """
    flags = [False] * len(parts)
    start = 1 if parts and _DRIVE_RE.fullmatch(parts[0]) is not None else 0
    for root in catalogue.system_roots:
        if tuple(parts[start : start + len(root)]) == root:
            at = start + len(root)
            flags[start:at] = [True] * len(root)
            while at < len(parts) and parts[at] in catalogue.system_folders:
                flags[at] = True
                at += 1
            break
    return flags


def _known_sequences(parts: Sequence[str], catalogue: Catalogue) -> list[bool]:
    """Which of a path's components stand in a multi-component known folder, matched whole
    and directly after one of the folders it is declared under (``sequence_parents``)."""
    flags = [False] * len(parts)
    for sequence in catalogue.known_sequences:
        size = len(sequence)
        for at in range(len(parts) - size + 1):
            if tuple(parts[at : at + size]) == sequence and any(
                0 < len(parent) <= at and tuple(parts[at - len(parent) : at]) == parent
                for parent in catalogue.sequence_parents
            ):
                flags[at : at + size] = [True] * size
    return flags


def _known_chain(parts: Sequence[str], catalogue: Catalogue) -> list[bool]:
    """The components the system chain or a multi-component known folder accounts for."""
    return [
        system or listed
        for system, listed in zip(
            _system_chain(parts, catalogue), _known_sequences(parts, catalogue), strict=True
        )
    ]


def _known_component(part: str, previous: str, catalogue: Catalogue, chained: bool) -> bool:
    short = _SHORT_NAME_RE.fullmatch(part)
    return (
        part in catalogue.known_folders
        or part in catalogue.environment_folders
        or chained
        or part.startswith(catalogue.known_folder_prefixes)
        or _DRIVE_RE.fullmatch(part) is not None
        or (short is not None and short.group(1) in catalogue.short_stems)
        # The profile's own name, which every user's folder carries.
        or previous == "users"
    )


def _all_known(parts: Sequence[str], catalogue: Catalogue) -> bool:
    chain = _known_chain(parts, catalogue)
    return bool(parts) and all(
        _known_component(
            part, "users" if _in_the_users_folder(parts, at) else "", catalogue, chain[at]
        )
        for at, part in enumerate(parts)
    )


# The environment names Windows defines for a drive (the catalogue's
# ``environment_folders`` hold them), which stand where a drive letter does.
_DRIVE_NAMES = frozenset({"%systemdrive%", "%homedrive%"})


def _in_the_users_folder(parts: Sequence[str], at: int) -> bool:
    """Whether component ``at`` stands where a profile's name does: right after a ``users``
    component that is the users folder, directly under a drive (a letter or an environment
    name for one) or the first component of a path written without one (``Users\\x``, as
    the catalogue read it before). ``C:\\Temp\\Users\\x`` holds no profile's name."""
    if at < 1 or parts[at - 1] != "users":
        return False
    if at == 1:
        return True
    under = parts[at - 2]
    return at == 2 and (_DRIVE_RE.fullmatch(under) is not None or under in _DRIVE_NAMES)


def past_known_folders(value: str) -> str:
    """The part of a path a log writes the same on every host: past its known folders.

    The leading drive, environment folders, known folders and profile name
    are dropped (``%APPDATA%\\Vendor\\run.dll`` is ``Vendor\\run.dll``), in the
    case written, joined by ``\\``; ``""`` when nothing is left.
    """
    catalogue = benign_catalogue()
    text = value.strip().strip("\"'").replace("/", "\\")
    parts = [part for part in (raw.rstrip(". ") for raw in text.split("\\")) if part]
    chain = _known_chain([part.lower() for part in parts], catalogue)
    at = 0
    while at < len(parts) and _known_component(
        parts[at].lower(), parts[at - 1].lower() if at else "", catalogue, chain[at]
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


# Why a key exactly one level below the key of a service Windows installs is
# every host's, where its name is one the catalogue lists for the subkeys a
# service's settings are kept in. True of the key as written: the catalogue
# knows the service and the name, not which service has which subkey.
SERVICE_SUBKEY_REASON = (
    "a key under the registry key of a service Windows installs, named as Windows names "
    "the subkeys it keeps a service's settings in"
)
# Why a rule's selection is left out that a service's settings subkey matches
# under the selection's operator (:func:`shipped_match`), by the operator: the
# reason is the subject, its clause closed by a comma before the verb.
SHIPPED_SUBKEY_REASON = {
    "endswith": f"{SERVICE_SUBKEY_REASON}, ends with it",
    "contains": f"{SERVICE_SUBKEY_REASON}, holds it",
    "": f"it is {SERVICE_SUBKEY_REASON}",
}
# Why a path is every host's whose every component the catalogue reads by its
# name (:func:`_all_known`): a drive, a name Windows gives one of its own
# folders (a known folder, a folder of the system chain, its environment form,
# its 8.3 short name, a known-folder constant) or the profile name in the
# users folder (:func:`_in_the_users_folder`). It says what was matched, not
# that the path is a known folder:
# a drive's ``Temp`` is a folder named as one of Windows' own.
KNOWN_NAMES_REASON = (
    "every component is a drive, a name Windows gives one of its own folders, "
    "or a user's profile name"
)


def benign_reason(
    kind: HostKind,
    value: str,
    sample_digests: frozenset[str] = frozenset(),
    sample_name: str = "",
) -> str:
    """Why a value of ``kind`` is every host's, in the rule's words, or ``""``.

    Read against the catalogue (:func:`benign_catalogue`) by the value's shape:
    a key or value every installation has (a key under the Services key named
    after a Windows service among them), and a key exactly one level below
    such a service's key named as the catalogue's ``service_settings_subkeys``
    (:data:`SERVICE_SUBKEY_REASON`; a key or value below it is not one), for a
    registry key or value; an object namespace, a word of a task definition,
    and Windows' own stream, service or pipe for a name; a path every
    component of which is a name the catalogue reads (:data:`KNOWN_NAMES_REASON`),
    or a program Windows ships written bare or in its system folders, for a
    folder, a file path or a file name; and
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
        if _a_service_settings_subkey(key, catalogue):
            return SERVICE_SUBKEY_REASON
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
            return f"{_article(kind.label.lower())} Windows itself has on every installation"
        return ""
    if len(parts) == 1 and parts[0] in catalogue.task_definition_words:
        return "a word of the Task Scheduler's task definition, which every task carries"
    if _all_known(parts, catalogue):
        return KNOWN_NAMES_REASON
    if kind.shape == "folder":
        return ""
    name = parts[-1]
    chain = _system_chain(parts[:-1], catalogue)
    if name in catalogue.system_binaries and all(
        _DRIVE_RE.fullmatch(part) is not None or chain[at] for at, part in enumerate(parts[:-1])
    ):
        return "a file Windows ships, in the folder Windows keeps it in"
    stem = name.rsplit(".", 1)[0]
    if stem in sample_digests:
        return "the sandbox's copy of the sample itself, named by its digest"
    if sample_name and name == sample_name and _a_submission_place(parts[:-1], catalogue):
        return "the sample's own file name, where a submitted file is placed"
    return ""


# How a selection matches a value, by the operator its field is written with:
# a field with no operator holds the value whole.
ENDSWITH = "endswith"
CONTAINS = "contains"
WHOLE = ""


@dataclass(frozen=True)
class _ShippedPaths:
    """The paths Windows ships, as the catalogue gives them: a program it ships, in the system
    root or in any run of the system folders under it, the root written with a drive or by
    an environment name; and every key and value every installation has, the key of each
    service Windows installs and each subkey named as the catalogue's
    ``service_settings_subkeys`` under it. Lower case.

    The files are a language, not a list (the system folders nest without a bound), held as
    the words each of its four parts is written with, ``\\`` closing each word that names a
    folder: an optional drive, a root, any run of system folders, a program's name.
    """

    drives: tuple[str, ...]
    roots: tuple[str, ...]
    folders: tuple[str, ...]
    names: tuple[str, ...]
    keys: tuple[str, ...]


# The parts of a shipped file's path, in order, and which may follow which.
_DRIVE, _ROOT, _FOLDER, _NAME = range(4)
_FOLLOWING = {_DRIVE: (_ROOT,), _ROOT: (_FOLDER, _NAME), _FOLDER: (_FOLDER, _NAME), _NAME: ()}


@lru_cache(maxsize=1)
def _shipped_paths() -> _ShippedPaths:
    """The shipped paths, derived once from the catalogue's names and folders."""
    catalogue = benign_catalogue()
    keys = [f"\\{key}\\" for key in catalogue.registry_keys]
    keys += [f"\\{value}" for value in catalogue.registry_values]
    keys += [
        f"\\{services}\\{service}\\"
        for services in sorted(_SERVICES_KEYS)
        for service in sorted(catalogue.windows_services)
    ]
    # A service's settings subkeys are asked after every other key, so a value
    # a key above matches is answered by that key, as before they were listed.
    subkeys = [
        f"\\{services}\\{service}\\{subkey}\\"
        for services in sorted(_SERVICES_KEYS)
        for service in sorted(catalogue.windows_services)
        for subkey in sorted(catalogue.service_settings_subkeys)
    ]
    return _ShippedPaths(
        drives=tuple(f"{letter}:\\" for letter in "abcdefghijklmnopqrstuvwxyz"),
        roots=tuple(
            sorted(
                ("\\".join(root) + "\\" for root in catalogue.system_roots),
                key=lambda root: (root.startswith("%"), root),
            )
        ),
        folders=tuple(sorted(f"{folder}\\" for folder in catalogue.system_folders)),
        names=tuple(sorted(catalogue.system_binaries)),
        keys=(*sorted(keys), *subkeys),
    )


# A place in a shipped path: the part, the word and how much of it is read.
_Place = tuple[int, str, int]


def shipped_match(shape: str, operator: str, value: str) -> str:
    """A path (or key) Windows ships that a selection of ``value`` matches, or ``""``.

    Asked the way the rule matches: under ``endswith`` a shipped path ends
    with the value, under ``contains`` it holds the value anywhere, even
    inside a name (``host.exe`` of ``svchost.exe``), and with no operator it
    is the value. A registry key (``shape`` ``key``) is asked of the keys and
    values every installation has, the key of each service Windows installs
    and each settings subkey named under it, each with the subkeys under it,
    the settings subkeys last; a file
    path or a folder of the files Windows ships (:class:`_ShippedPaths`).
    Case-insensitive, ``/`` read as ``\\``. The answer is one such path,
    written whole, which the reason a value is left out names.
    """
    text = value.strip().lower().replace("/", "\\")
    if not text or shape not in ("key", "path", "folder"):
        return ""
    shipped = _shipped_paths()
    if shape == "key":
        for key in shipped.keys:
            if (
                (operator == CONTAINS and text in key)
                or (operator == ENDSWITH and key.rstrip("\\").endswith(text))
                or (operator == WHOLE and key.rstrip("\\") == text)
            ):
                return key.rstrip("\\")
        return ""
    return _shipped_file(shipped, operator, text)


def _shipped_file(shipped: _ShippedPaths, operator: str, text: str) -> str:
    """A shipped file's path a selection of ``text`` matches under ``operator``, or ``""``.

    The value is read along the paths' language one character at a time,
    from every place in it (``contains``, ``endswith``) or from a path's
    start (no operator); each place read keeps the place it started at, so
    the path the answer names is built around the value.
    """
    words = (shipped.drives, shipped.roots, shipped.folders, shipped.names)
    if operator == WHOLE:
        starts = [(part, word, 0) for part in (_DRIVE, _ROOT) for word in words[part]]
    else:
        starts = [
            (part, word, at)
            for part, listed in enumerate(words)
            for word in listed
            for at in range(len(word))
        ]
    places: dict[_Place, _Place] = {place: place for place in starts}
    for char in text:
        read: dict[_Place, _Place] = {}
        for (part, word, at), start in places.items():
            if at < len(word):
                if word[at] == char:
                    read.setdefault((part, word, at + 1), start)
                continue
            for following in _FOLLOWING[part]:
                for other in words[following]:
                    if other[0] == char:
                        read.setdefault((following, other, 1), start)
        places = read
        if not places:
            return ""
    for (part, word, at), start in sorted(places.items()):
        whole = part == _NAME and at == len(word)
        if operator == CONTAINS or whole:
            return _written_around(shipped, start, text, (part, word, at))
    return ""


def _written_around(shipped: _ShippedPaths, start: _Place, text: str, end: _Place) -> str:
    """A shipped path holding ``text`` read from ``start`` to ``end``: the drive and the root
    before it, and a system folder and a program's name after it, where it needs them."""
    part, word, at = start
    before = {
        _DRIVE: "",
        _ROOT: "" if word.startswith("%") else "c:\\",
        _FOLDER: "c:\\windows\\",
        _NAME: "c:\\windows\\system32\\",
    }[part]
    last, ended, read = end
    after = ended[read:]
    if last == _DRIVE:
        after += "windows\\"
    if last != _NAME:
        after += shipped.names[0]
    return before + word[:at] + text + after


def _a_submission_place(folders: Sequence[str], catalogue: Catalogue) -> bool:
    """Whether a file's folders are where a submitted file is placed: none, a drive's root,
    a declared submission root (the temporary folder, the desktop, the downloads folder, the
    profile, by name or environment form) or the profile folder itself (``Users\\<name>``)."""
    if not folders:
        return True
    last = folders[-1]
    return (
        (len(folders) == 1 and _DRIVE_RE.fullmatch(last) is not None)
        or last in catalogue.submission_roots
        or (len(folders) >= 2 and folders[-2] == "users")
    )


# The Services key, under which each service has a key of its own name.
_SERVICES_KEYS = frozenset(
    {"system\\currentcontrolset\\services", "system\\controlset001\\services"}
)


def _a_service_settings_subkey(key: str, catalogue: Catalogue) -> bool:
    """Whether a hiveless key, folded, is exactly one level below the key of a service
    Windows installs and is named as the catalogue's ``service_settings_subkeys``."""
    parent, _, last = key.rpartition("\\")
    services, _, service = parent.rpartition("\\")
    return (
        services in _SERVICES_KEYS
        and service in catalogue.windows_services
        and last in catalogue.service_settings_subkeys
    )


def _article(noun: str) -> str:
    """``noun`` with the indefinite article its first sound takes (by its first letter)."""
    return f"{'an' if noun[:1] in 'aeiou' else 'a'} {noun}"


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
    # The kind as the row writes it, which types a row of no vocabulary kind.
    written_kind: str = ""
    # What the cited entries hold of a value none holds whole
    # (``HostIdentifier.unheld_as``: :data:`NOWHERE` or one of :data:`UNHELD_WORDS`'
    # keys), or ``""`` where the record holds no such word.
    unheld_as: str = ""
    # How many distinct entries the row cites, of which the check reads the
    # first :data:`MAX_CITED`.
    cited: int = 0

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
        written_kind=" ".join(str(getattr(item, "kind", "") or "").split()),
        unheld_as=str(getattr(item, "unheld_as", None) or ""),
        cited=len(_cited(getattr(item, "evidence_refs", None) or [], bound=None)),
    )


def _unheld_refusal(stated: StatedHostValue) -> str:
    """Why a row no cited entry holds whole is refused: what the scan that wrote ``held_in``
    found, in its words (:data:`UNHELD_WORDS`, :data:`NOT_IN_THE_CITED`), the count it read
    of the entries cited where it read fewer than all; and, where the record holds no word
    of what the scan found (a report stored before it recorded one), what the record holds
    (:data:`NOT_RECORDED_AS_HELD`)."""
    read = min(stated.cited, MAX_CITED)
    fewer = stated.cited > read
    if stated.unheld_as == NOWHERE:
        if fewer:
            return NOT_IN_THE_READ.format(read=read, cited=stated.cited)
        return NOT_IN_THE_CITED
    words = UNHELD_WORDS.get(stated.unheld_as, "")
    if not words:
        return NOT_RECORDED_AS_HELD
    if fewer:
        return f"{words} ({READ_OF_THE_CITED.format(read=read, cited=stated.cited)})"
    return words


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
        return _unheld_refusal(stated)
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

    A statement adds a source where the value's other records are only weak
    (the file's strings, an analyst's listing, a sandbox row of the sample's
    tree the judge did not name), never where a record places the value
    elsewhere: a value the sandbox recorded from a process it does not
    attribute to the sample's tree, and the judge did not keep, is answered
    with that refusal, here, so every surface reads the one answer. The
    sandbox is asked under each kind the vocabulary declares a value of the
    row's kind recorded under (``HostKind.sandbox_kinds``): a registry value
    the sandbox holds as a key is the same value.
    """
    from malspark.reporting.renderers.stix_renderer import (
        publish_answer,
        publishes,
        sandbox_host_kwargs,
    )

    ta = getattr(report, "technical_analysis", None)
    rows = list(getattr(ta, "host_identifiers", None) or []) if ta is not None else []
    out: list[tuple[StatedHostValue, str]] = []
    for index, item in enumerate(rows):
        kwargs = analysis_kwargs(report, item, beyond_rows=index >= MAX_STATED_ROWS)
        stated = kwargs["stated"]
        answer = publish_answer(stated.table_kind, stated.value, ANALYSIS_SOURCE, **kwargs)
        for sandbox_kind in stated.kind.sandbox_kinds if stated.kind is not None else ():
            if not publishes(answer):
                break
            placed: dict[str, Any] = dict(sandbox_host_kwargs(report, sandbox_kind, stated.value))
            if placed.get("unattributed"):
                refused = publish_answer(sandbox_kind, stated.value, "sandbox", **placed)
                if not publishes(refused):
                    answer = refused
        out.append((stated, answer))
    return out


# What a delimited value may stand between. A strong delimiter at either end:
# the text's start or end, a quote (one that a ``:`` follows closes a key, not
# a value), a line break as written or as its escape, and for a folder's or a
# file's name a path separator. A structural one: an opening ``(`` or ``[``
# written right after a name (a call, ``CreateMutexW(``), a ``=`` or ``:``
# written right before the value, and a closing ``)``, ``]``, ``,`` or ``;``;
# those count only where the other end is a quote, such a bracket or such a
# ``=`` / ``:``, and after a quote only where a quote, a closing bracket, a
# line break or the text's end follows the mark (a space allowed). Never a
# space or a full stop: those are running text, and a word of a tool's prose
# is no value; nor a bracket of prose, "the loader (explorer) then".
_QUOTES = "\"'"
_LINE_BREAKS = "\n\r\t"
_ESCAPED_BREAKS = ("\\n", "\\r", "\\t")
_SEPARATORS = "\\/"
_PAIR_MARKS = "=:"
_OPEN_BRACKETS = "(["
_LIST_CLOSERS = ")],;"
# What ends the token a URL is written in, and how far back a token is read:
# a URL is read only within this many characters before an occurrence, so a
# text of many occurrences costs its length times a constant; an occurrence
# whose token began further back is refused, since it may be a URL's.
_TOKEN_ENDS = " \t\n\r\"'<>()[]{},"
_URL_LOOKBACK = 2048

# The ends a value may stand between, by strength (see above).
_STRONG = "strong"
_QUOTE = "quote"
_BRACKET = "bracket"
_PAIR = "pair"
_LIST = "list"
_BREAK = "break"


def _in_a_url(text: str, start: int) -> bool:
    """Whether the occurrence at ``start`` stands, or may stand, inside a URL token.

    The token is read back to its start, at most :data:`_URL_LOOKBACK`
    characters; a token that began further back is not read and is taken as
    a URL's, so nothing past the window is accepted unread.
    """
    low = max(0, start - _URL_LOOKBACK)
    cut = max(text.rfind(end, low, start) for end in _TOKEN_ENDS)
    if cut < 0 and low > 0:
        return True
    return "://" in text[cut + 1 : start]


def _opening(text: str, start: int, separators: bool, prefixes: Sequence[str]) -> str:
    """What stands before an occurrence, as a delimiter class, or ``""``."""
    if start == 0:
        return _STRONG
    before = text[start - 1]
    if before in _QUOTES:
        return _QUOTE
    if before in _LINE_BREAKS or text[max(0, start - 2) : start] in _ESCAPED_BREAKS:
        return _BREAK
    if separators and before in _SEPARATORS:
        return _STRONG
    if any(text.endswith(prefix, 0, start) for prefix in prefixes):
        return _STRONG
    if before in _OPEN_BRACKETS:
        # Only a call's bracket: a name character right before it.
        return _BRACKET if start >= 2 and _is_name_char(text[start - 2]) else ""
    if before in _PAIR_MARKS:
        return _PAIR
    return ""


def _is_name_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _a_list_ends(text: str, end: int) -> bool:
    """Whether the list mark at ``end`` closes a quoted value: what follows it, past one
    space, is a quote (as written or escaped), a closing bracket, a line break (as
    written or escaped) or the text's end."""
    rest = text[end + 1 : end + 4]
    if rest.startswith(" "):
        rest = rest[1:]
    return (
        not rest
        or rest[0] in _QUOTES
        or rest[0] in ")]"
        or rest[0] in _LINE_BREAKS
        or rest[:2] in ('\\"', *_ESCAPED_BREAKS)
    )


def _closing(text: str, end: int, separators: bool) -> str:
    """What stands after an occurrence, as a delimiter class, or ``""``."""
    if end >= len(text):
        return _STRONG
    after = text[end]
    if after in _QUOTES:
        # A quote a ``:`` follows closes a key: ``{"explorer": 1}``.
        rest = text[end + 1 : end + 8].lstrip(" ")
        return "" if rest.startswith(":") else _QUOTE
    if after in _LINE_BREAKS:
        return _BREAK
    if separators and after in _SEPARATORS:
        return _STRONG
    if after == "\\" and text[end + 1 : end + 2] in ('"', "n", "r", "t"):
        # An escaped quote or line break after it ends a JSON string; the
        # same key test holds for an escaped quote.
        if text[end + 1 : end + 2] == '"' and text[end + 2 : end + 9].lstrip(" ").startswith(":"):
            return ""
        return _QUOTE if text[end + 1 : end + 2] == '"' else _BREAK
    if after in _LIST_CLOSERS:
        return _LIST
    return ""


# Which closing class each opening class admits: a strong or a quoted end
# takes any end but a bare list mark after a strong one; a bracket or a
# ``=`` / ``:`` needs a structural end, never the text's end or running text.
_ADMITS = {
    _STRONG: frozenset({_STRONG, _QUOTE, _BREAK}),
    _BREAK: frozenset({_STRONG, _QUOTE, _BREAK}),
    _QUOTE: frozenset({_STRONG, _QUOTE, _BREAK, _LIST}),
    _BRACKET: frozenset({_QUOTE, _LIST}),
    _PAIR: frozenset({_QUOTE, _BREAK, _LIST}),
}


def delimited_in(
    name: str,
    text: str,
    *,
    after_colon: bool = False,
    separators: bool = True,
    prefixes: Sequence[str] = (),
) -> bool:
    """Whether ``name`` stands in ``text`` as a value of its own, delimited at both ends.

    Both ends must be delimiters that pair (:data:`_ADMITS`): a quote, the
    text's start or end, a line break or its escape and, with ``separators``,
    a path separator take each other; an opening bracket written right after
    a name, or a ``=`` / ``:`` right before the value, takes only a quote or a
    closing ``)``, ``]``, ``,`` or ``;``, and a quote takes such a mark only
    where a quote, a closing bracket, a line break or the end follows it
    (:func:`_a_list_ends`). Never a space or a full stop of running text, and never a
    quote a ``:`` follows (a key): ``{"text": "updater"}``,
    ``CreateMutexW(abc123)`` and ``name=abc123,`` hold their value, and
    "installs an updater, which runs", ``{"updater": 1}``, ``updater: a task``
    and ``target=explorer`` do not. A path separator delimits only with
    ``separators`` (a folder's or a file's name is a path component; a
    mutex's, a task's or a service's name inside a path is that path's).
    ``prefixes`` are the kind's own namespaces (``global\\``), which open a
    name written under them. An occurrence inside a URL is never a host value.
    ``after_colon`` asks for a stream name, which follows the ``:`` that ends
    its file's name (``a.exe:x``). One pass over the occurrences.
    """
    if not name or not text:
        return False
    start = text.find(name)
    while start != -1:
        end = start + len(name)
        if after_colon:
            opened = _STRONG if start > 0 and text[start - 1] == ":" else ""
        else:
            opened = _opening(text, start, separators, prefixes)
        closed = _closing(text, end, separators) if opened else ""
        if (
            opened
            and closed in _ADMITS[opened]
            and (opened != _QUOTE or closed != _LIST or _a_list_ends(text, end))
            and not _in_a_url(text, start)
        ):
            return True
        start = text.find(name, start + 1)
    return False


def component_in(name: str, text: str) -> bool:
    """Whether ``name`` is a whole component of a path ``text`` writes (:func:`delimited_in`)."""
    return delimited_in(name, text)


def _delimited_shape(kind: HostKind | None) -> bool:
    """Whether a value of ``kind`` is held only where delimited: a name, a folder, a file name."""
    return kind is not None and kind.shape in ("name", "folder", "file_name")


# What a refusal says of a value no cited entry holds whole, by what the one scan
# that wrote ``held_in`` found (:class:`HeldScan`): the value whole only where a
# cited entry's answer repeats its own call (and, where that answer shows it,
# elsewhere only inside a longer run of text), the text only inside a longer run
# of letters or digits, only between spaces, or somewhere this check does not
# count as the value's whole. A value whose text no cited entry holds in any
# spelling (:data:`NOWHERE`) keeps :data:`NOT_IN_THE_CITED`; a row whose record
# holds no word of what the scan found (a report stored before the scan recorded
# it) says only what its record holds (:data:`NOT_RECORDED_AS_HELD`).
ONLY_IN_ITS_CALL = "only_in_its_call"
ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE = "only_in_its_call_elsewhere_inside"
AS_BYTES = "as_bytes"
INSIDE_A_LONGER_RUN = "inside_a_longer_run"
BETWEEN_SPACES = "between_spaces"
NOT_WHOLE = "not_whole"
NOWHERE = "nowhere"
NOT_IN_THE_CITED = "its whole value is in none of the entries it cites"
NOT_RECORDED_AS_HELD = "no cited entry is recorded as holding its whole value"
# A row citing more entries than the check reads (:data:`MAX_CITED`) says so: in
# place of :data:`NOT_IN_THE_CITED`, and after any other finding's words.
NOT_IN_THE_READ = (
    "its whole value is in none of the first {read} of the {cited} entries it cites, "
    "which are the entries this check reads"
)
READ_OF_THE_CITED = "this check reads the first {read} of the {cited} entries it cites"
# What a cited entry holds whole only in its answer's echo of its own call.
ONLY_IN_ITS_CALL_WORDS = (
    "a cited entry holds it whole only where its answer repeats what its call asked for"
)
UNHELD_WORDS = {
    ONLY_IN_ITS_CALL: ONLY_IN_ITS_CALL_WORDS,
    ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE: (
        f"{ONLY_IN_ITS_CALL_WORDS}; elsewhere only inside a longer run of text"
    ),
    AS_BYTES: (
        "a cited entry writes its whole value only as bytes, which the export does not read as "
        "a host value"
    ),
    INSIDE_A_LONGER_RUN: (
        "a cited entry holds its text only inside a longer run of letters or digits"
    ),
    BETWEEN_SPACES: (
        "the cited entries hold it only between spaces, which this check does not count as "
        "a value's ends"
    ),
    NOT_WHOLE: "a cited entry holds its text, but nowhere this check counts as the whole value",
}


@dataclass(frozen=True)
class HeldScan:
    """What one scan of a row's cited entries found: the entries holding its value whole, and,
    where none does, what they hold of it instead (a key of :data:`UNHELD_WORDS`, or
    :data:`NOWHERE` where no cited entry it read holds its text in any spelling; ``""`` where
    the value was not read)."""

    held: tuple[str, ...] = ()
    unheld_as: str = ""


def held_in_cited(entries: Any, item: Any) -> list[str]:
    """The entries a row cites that hold its value whole, as the row cites them.

    :func:`scan_cited`'s entries.
    """
    return list(scan_cited(entries, item).held)


def scan_cited(entries: Any, item: Any) -> HeldScan:
    """One scan of the entries a row cites: which hold its value whole, and what the others hold.

    The value is read in every spelling a run's texts write it in
    (:func:`encodings`). A name, a folder or a file name counts only where it
    is delimited at both ends (:func:`delimited_in`): a quote, a line break, a
    key-value mark or, for a folder or a file name, a path separator; never
    running text and never a URL; a
    file name or folder written with leading separators is also read bare, as
    a path component; a stream is read as the name after its file's colon. Such
    a value is also held where it is one whole argument of a process's command
    line the entry records in the platform's sandbox document
    (:func:`command_line_arguments`: a process row stating its id, its parent's
    and its command line): a field of the platform's own document, whose
    arguments white space separates. A
    file path and a registry key or value are found whole as any value is
    (``whole_value_in``). Only the cited entries the text index says may hold
    the value are read for a delimited value (``EntryTexts.may_hold``), at most
    :data:`MAX_CITED`.
    A cited entry the index reads as a code listing stored as JSON
    (``EntryTexts.code_listings``) is also read in the spellings a C string
    literal inside it writes (``written_forms.code_literal_forms``), under the
    same delimiting.

    A cited entry this reading finds the value whole in only in the echo of
    its own call (``validation.held_only_in_its_echo``: whole in a text with
    nothing taken out, in none once what repeats the call's arguments is out)
    holds nothing here — a model's own question echoed back is no record of
    the value — unless its echo-free text holds a spelling of the value at a
    place no letter, digit or ``_`` of the run around it touches, read decoded,
    where the entry holds it as this reading found.

    Where no cited entry holds it whole, the same reading says what they hold
    (:func:`_held_as`): an entry holding it whole only in its call's echo says
    so, with, where its echo-free text holds the value's text only inside a
    longer run, that too; an entry whose text holds the value's text nowhere,
    or only inside a longer run, and whose bytes hold it
    (``EntryTexts.holds_as_bytes``, read for these words alone: the export
    reads no bytes) writes it whole only as bytes; an entry whose every place
    of the text has a letter or a digit running on at an end holds it only
    inside a longer run; where every
    place in every entry has a space at both ends, outside any recorded command
    line that holds the text, they hold it only between spaces; any other place
    is somewhere this check does not count as the whole value; and where no entry
    read holds its text in any spelling, :data:`NOWHERE`.
    """
    from malspark.agents._indicator_denylists import whole_value_in
    from malspark.pipeline.validation import ECHO_FREE_HOLDS_IT, ECHO_FREE_HOLDS_IT_INSIDE

    value = str(getattr(item, "value", "") or "").strip()
    if not value or len(value) > MAX_VALUE_CHARS or entries is None:
        return HeldScan()
    kind = typed_kind(getattr(item, "kind", ""))
    lowered = value.lower()
    stream = ""
    bare = ""
    if kind is not None and kind.table_kind == "ads":
        stream = lowered.lstrip(":")
    elif kind is not None and kind.shape in ("folder", "file_name"):
        bare = lowered.strip("\\/")
        if bare == lowered:
            bare = ""
    # Each text read in the spellings of :func:`encodings`, a code listing
    # stored as JSON in its literal's too.
    spelt = {listing: _Spellings(lowered, bare, stream, kind, listing) for listing in (False, True)}
    listings: frozenset[str] = getattr(entries, "code_listings", frozenset())
    cited = _cited(getattr(item, "evidence_refs", None) or [])
    candidates: set[str] = set()
    plain = spelt[False]
    for form in [*plain.forms, *plain.names, *([stream] if stream else [])]:
        candidates |= set(entries.may_hold(form))
    # A command line's argument is compared with the value as itself, not as a
    # text spells it: the document's field is read back into its own string.
    arguments = {lowered, *([bare] if bare else [])}
    out: list[str] = []
    found: list[str] = []
    for ref in cited:
        text = entries.text_of(ref)
        if not text:
            continue
        read = spelt[ref.lower() in listings]
        paths = kind is not None and kind.shape in ("folder", "file_name")
        forms = [*read.forms, *read.names, *read.stream]

        def _whole_in(text: str, read: _Spellings = read, paths: bool = paths) -> bool:
            # The value whole in one text, delimited where its kind is.
            if stream:
                return any(
                    delimited_in(form, text, separators=False) for form in read.forms
                ) or any(
                    delimited_in(form, text, after_colon=True, separators=False)
                    for form in read.stream
                )
            if _delimited_shape(kind):
                return any(
                    delimited_in(form, text, separators=paths, prefixes=read.prefixes)
                    for form in [*read.forms, *read.names]
                )
            return any(whole_value_in(form, text) for form in read.forms)

        def _held_in_one(text: str, forms: list[str] = forms) -> bool:
            # This scan's whole test of one text: the value whole, or one whole
            # argument of a command line the text records.
            if _whole_in(text):
                return True
            return (
                _delimited_shape(kind)
                and any(form in text for form in forms)
                and any(
                    argument in arguments
                    for line in command_line_arguments(text)
                    for argument in line
                )
            )

        held = False
        if ref.lower() in candidates or _is_item(entries, ref):
            held = _whole_in(text)
        lines: list[tuple[str, ...]] = []
        if not held and _delimited_shape(kind) and any(form in text for form in forms):
            lines = _command_lines_of(entries, ref)
            held = any(argument in arguments for line in lines for argument in line)
        echo = _echo_holding(entries, ref, _held_in_one, forms) if held else ""
        if echo and echo != ECHO_FREE_HOLDS_IT:
            # Held only in the echo of the entry's own call: no holder.
            held = False
        if held:
            out.append(ref)
        elif not out:
            # What this entry holds of the text, read only while no entry holds it.
            if echo == ECHO_FREE_HOLDS_IT_INSIDE:
                found.append(ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE)
                continue
            if echo:
                found.append(ONLY_IN_ITS_CALL)
                continue
            in_a_line = any(
                any(value_text in argument for argument in line)
                for line in lines
                for value_text in arguments
            )
            what = _held_as(text, forms, in_a_line)
            if what in ("", INSIDE_A_LONGER_RUN) and _writes_as_bytes(entries, ref, value):
                # Its text holds no whole value, its bytes do: said, never exported.
                what = AS_BYTES
            found.append(what)
    if out:
        return HeldScan(held=tuple(out))
    return HeldScan(unheld_as=_unheld_as(found) or NOWHERE)


# The escapes a text writes a line break with, which open a value as the break does.
_ESCAPED_ENDS = ("\\n", "\\r", "\\t")


def _held_as(text: str, forms: Sequence[str], in_a_line: bool) -> str:
    """What one entry holds of a value it does not hold whole: ``""`` for nothing, else
    :data:`INSIDE_A_LONGER_RUN` where a letter or a digit runs on at an end of every place
    of its text, :data:`BETWEEN_SPACES` where a space stands at both ends of every place
    (and no recorded command line of the entry holds the text), else :data:`NOT_WHOLE`."""
    seen: set[str] = set()
    for form in dict.fromkeys(form for form in forms if form):
        start = text.find(form)
        while start != -1:
            end = start + len(form)
            before = text[start - 1] if start else ""
            if text[max(0, start - 2) : start] in _ESCAPED_ENDS:
                before = "\n"
            after = text[end] if end < len(text) else ""
            if before.isalnum() or after.isalnum():
                seen.add(INSIDE_A_LONGER_RUN)
            elif before == " " and after == " " and not in_a_line:
                seen.add(BETWEEN_SPACES)
            else:
                seen.add(NOT_WHOLE)
            if NOT_WHOLE in seen:
                return NOT_WHOLE
            start = text.find(form, start + 1)
    if len(seen) == 1:
        return seen.pop()
    return NOT_WHOLE if seen else ""


def _writes_as_bytes(entries: Any, ref: str, value: str) -> bool:
    """Whether a cited entry's text writes ``value`` as bytes chance does not explain
    (``EntryTexts.holds_as_bytes``, the citation check's one byte reading): read only to say
    so in a refusal, never to export the value."""
    holds = getattr(entries, "holds_as_bytes", None)
    return callable(holds) and bool(holds(ref, value))


def _echo_holding(entries: Any, ref: str, held: Any, forms: Sequence[str]) -> str:
    """What a cited entry holds of a value this scan's own test (``held``) finds whole only
    in the echo of the entry's call (``validation.held_only_in_its_echo``); ``""`` where it
    is held elsewhere too, or the entries tell no echo apart."""
    if not callable(getattr(entries, "echo_free_parts", None)):
        return ""
    from malspark.pipeline.validation import held_only_in_its_echo

    return held_only_in_its_echo(entries, ref, held, forms)


# What one entry's reading says of a value no cited entry holds whole, in the fixed
# order :func:`_unheld_as` picks among them: each says what one cited entry holds, so
# the first found is true of the row whatever the others hold.
_UNHELD_ORDER = (
    ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE,
    ONLY_IN_ITS_CALL,
    AS_BYTES,
    INSIDE_A_LONGER_RUN,
)


def _unheld_as(found: Sequence[str]) -> str:
    """What the cited entries hold of a value none holds whole, from each entry's reading:
    the first reading of :data:`_UNHELD_ORDER` an entry gives (an entry holding it whole
    only in the echo of its own call, then one writing it whole only as bytes, then one
    holding it only inside a longer run); every
    entry that holds it holding it only between spaces says that; nothing held says
    ``""``."""
    held = [what for what in found if what]
    if not held:
        return ""
    for what in _UNHELD_ORDER:
        if what in held:
            return what
    if all(what == BETWEEN_SPACES for what in held):
        return BETWEEN_SPACES
    return NOT_WHOLE


def _command_lines_of(entries: Any, ref: str) -> list[tuple[str, ...]]:
    """The arguments of every process command line a cited entry's texts record, each text
    read on its own (``EntryTexts.parts_of``, else its whole text)."""
    parts_of = getattr(entries, "parts_of", None)
    parts = parts_of(ref) if parts_of is not None else (entries.text_of(ref),)
    return [line for part in parts for line in command_line_arguments(part)]


@lru_cache(maxsize=64)
def command_line_arguments(text: str) -> tuple[tuple[str, ...], ...]:
    """The arguments of each process command line ``text`` records as the platform's sandbox
    document writes a process row, in order; ``()`` for a text that records none.

    A text is read only as a JSON document. A process row is one object stating
    its own process id under one of the document's id fields
    (``sandbox_document.PROCESS_ID_KEYS``), its parent's id under one of its
    parent fields (``PROCESS_PARENT_KEYS``) and its command line under one of
    its command-line fields (``PROCESS_COMMAND_LINE_PATHS``), the field names
    compared case-insensitively, at any depth: where a tool's answer holds such
    rows the field is the document's, whatever the tool, declared or not. An
    object with an id and a command line and no parent is no process row (a
    configuration's entry, a tool's echo of its own arguments). Nothing else is
    a command line: a launch argument the document records beside the rows, a
    signature's text, a strings entry. A command line is split as Windows
    splits one (:func:`_arguments`).
    """
    from malspark.schemas.sandbox_document import (
        PROCESS_COMMAND_LINE_PATHS,
        PROCESS_ID_KEYS,
        PROCESS_PARENT_KEYS,
    )

    try:
        document = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return ()
    ids = {key.lower() for key in PROCESS_ID_KEYS}
    parents = {key.lower() for key in PROCESS_PARENT_KEYS}
    paths = [tuple(step.lower() for step in path) for path in PROCESS_COMMAND_LINE_PATHS]
    out: list[tuple[str, ...]] = []
    stack: list[Any] = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        folded = {str(key).lower(): held for key, held in node.items()}
        if ids & folded.keys() and parents & folded.keys():
            for path in paths:
                held: Any = folded
                for step in path:
                    held = (
                        {str(k).lower(): v for k, v in held.items()}.get(step)
                        if isinstance(held, dict)
                        else None
                    )
                if isinstance(held, str) and held.strip():
                    out.append(_arguments(held.lower()))
        stack.extend(reversed(list(node.values())))
    return tuple(out)


def _arguments(line: str) -> tuple[str, ...]:
    """A command line's arguments, as Windows splits one (``CommandLineToArgvW``).

    White space outside quotes separates arguments; a double quote opens or
    closes a quoted part, which is one argument with its spaces; ``2n``
    backslashes before a quote are ``n`` and the quote is a mark, ``2n + 1``
    are ``n`` and a quote of the text; ``""`` inside a quoted part is a quote.
    One pass over the line.
    """
    out: list[str] = []
    word: list[str] = []
    started = quoted = False
    slashes = 0
    at = 0
    while at < len(line):
        char = line[at]
        if char == "\\":
            slashes += 1
            started = True
        elif char == '"':
            word.append("\\" * (slashes // 2))
            if slashes % 2:
                word.append('"')
            elif quoted and line[at + 1 : at + 2] == '"':
                word.append('"')
                at += 1
            else:
                quoted = not quoted
            slashes = 0
            started = True
        else:
            word.append("\\" * slashes)
            slashes = 0
            if char.isspace() and not quoted:
                if started:
                    out.append("".join(word))
                word, started = [], False
            else:
                word.append(char)
                started = True
        at += 1
    word.append("\\" * slashes)
    if started:
        out.append("".join(word))
    return tuple(out)


class _Spellings:
    """The spellings :func:`held_in_cited` reads one row in, for one kind of text.

    The value, its bare name, its stream and its kind's namespaces, each in
    every spelling of :func:`encodings`; with ``listing``, each also as a C
    string literal inside a JSON code listing writes it
    (``written_forms.code_literal_forms``).
    """

    def __init__(self, value: str, bare: str, stream: str, kind: Any, listing: bool) -> None:
        self.forms = _spelt(value, listing)
        self.names = _spelt(bare, listing) if bare else []
        self.stream = _spelt(stream, listing) if stream else []
        # The kind's own namespaces, in every spelling a text writes them in.
        self.prefixes = [
            form
            for prefix in (kind.namespaces if kind is not None else ())
            for form in _spelt(prefix, listing)
        ]


def _spelt(value: str, listing: bool) -> list[str]:
    """:func:`encodings` of ``value``, and with ``listing`` its code literal's spellings."""
    from malspark.utils.written_forms import code_literal_forms

    forms = encodings(value)
    if listing:
        forms.extend(form for form in code_literal_forms(value) if form not in forms)
    return forms


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


def _cited(refs: Iterable[Any], bound: int | None = MAX_CITED) -> list[str]:
    """The distinct entries a row cites, in its order, the first ``bound`` (all for ``None``)."""
    seen: set[str] = set()
    out: list[str] = []
    for ref in refs:
        text = str(ref or "").strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
        if bound is not None and len(out) >= bound:
            break
    return out


def _is_item(entries: Any, ref: str) -> bool:
    """Whether a citation names a sandbox item, which no text index of entries offers."""
    return ref.lower() not in getattr(entries, "texts", {}) and bool(entries.text_of(ref))


def with_held_in(rows: list[Any], entries: Any) -> list[Any]:
    """The rows with ``held_in`` written by code: the cited entries holding each value whole.

    And ``unheld_as``, from the same scan (:func:`scan_cited`): what the cited
    entries hold of a value none holds whole. ``None`` on every row when the
    run holds no entry text to check against, and on each row past
    :data:`MAX_STATED_ROWS`; whatever a model wrote there is replaced.
    """
    for index, item in enumerate(rows):
        scan = (
            scan_cited(entries, item) if entries is not None and index < MAX_STATED_ROWS else None
        )
        item.held_in = list(scan.held) if scan is not None else None
        # What the same scan found where nothing holds it whole: the refusal's words.
        item.unheld_as = (scan.unheld_as or None) if scan is not None else None
    return rows
