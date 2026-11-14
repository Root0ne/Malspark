"""The neutral sandbox report every sandbox reader produces.

``SandboxReport`` is the one form every consumer reads, whichever sandbox
produced the report: the target and its hashes, the processes and their tree,
the behaviour and API calls, the signatures (with the scale their format
declares), the network flows, DNS and HTTP, the dropped files, the extracted
configurations and payloads, the memory and process dumps, the IDS alerts,
the sections the sandbox cannot produce, and the ``channels`` and ``extras``
for anything with no declared place of its own. The readers that fill it are
registered (``providers.sandbox.readers``); the document every consumer reads
is laid out from it by ``schemas.sandbox_document``.

Every model here is deliberately permissive: ``model_config =
ConfigDict(extra="ignore")`` so an unexpected sandbox field never breaks
ingestion, and every collection defaults to empty rather than ``None`` so a
consumer can iterate a fresh ``SandboxReport()`` without a null check.
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_serializer,
)

from malspark.core.legacy_tool_tables import STORED_LINEAGE_MARKER_FORMAT
from malspark.core.report_formats import SignatureScale, reader_display_name
from malspark.schemas.sandbox_document import (
    GROUP_ROWS_KEY,
    LAUNCHER_ATTRIBUTION_KEY,
    LAUNCHER_FILES_KEY,
    LAUNCHER_SIGNATURES_CHANNEL,
    LINEAGE_KEY,
    MEMBER_FACT_KEY,
    UNATTRIBUTED_SIGNATURES_KEY,
    UNPLACED_MEMBER_FILES_KEY,
    UNSETTLED_LAUNCHER_FILES_KEY,
    kept_source,
    pid_of,
    signature_pids,
)
from malspark.schemas.sandbox_document import (
    SUMMARY_KEYS as _DOCUMENT_SUMMARY_KEYS,
)


def _int(value: Any) -> int:
    """Best-effort int coercion; malformed sandbox data becomes ``0``, never a crash."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _rows(value: Any) -> list[dict[str, Any]]:
    """Keep only the dict entries of a possibly-mixed sandbox-report array."""
    return [row for row in _list(value) if isinstance(row, dict)]


def _list(value: Any) -> list[Any]:
    """``value`` when it is a list, else nothing: a block of the wrong shape holds no rows."""
    return value if isinstance(value, list) else []


def _as_str_list(value: Any) -> list[str]:
    """Coerce a sandbox field that is sometimes a list, sometimes a scalar, to ``list[str]``."""
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if value else []


def _dict_identity_or_validate(value: Any, handler: ValidatorFunctionWrapHandler) -> dict[str, Any]:
    """Return ``value`` unchanged when it is already a dict; otherwise validate normally.

    This is the narrow fix a bare ``SkipValidation[dict[str, Any]]`` does not
    give: a source's own blocks are held by identity (a report's ``raw``, the
    parts a reader keeps as published), but ``SkipValidation`` accepts
    *anything* — a string, a list, ``None`` — and would hand it on as if it
    were a report. A dict still passes through untouched (same object, no
    pydantic-core rebuild); anything else still goes through the ordinary
    ``dict[str, Any]`` validator and still raises ``ValidationError``.
    """
    if isinstance(value, dict):
        return value
    return cast("dict[str, Any]", handler(value))


def _without_empty(
    model: BaseModel, handler: SerializerFunctionWrapHandler, fields: tuple[str, ...]
) -> Any:
    """The model's dump without the ``fields`` that hold nothing.

    The places a reader fills only for some sandboxes: a report stored before
    they existed, and a report from a reader that never fills them, dump as
    they always did.
    """
    dumped = handler(model)
    if isinstance(dumped, dict):
        for name in fields:
            if name in dumped and not dumped[name]:
                del dumped[name]
    return dumped


class SandboxTarget(BaseModel):
    """The sample identity a sandbox detonated."""

    model_config = ConfigDict(extra="ignore")

    sha256: str = ""
    md5: str = ""
    name: str = ""
    file_type: str = ""
    mime_type: str = ""
    size: int = 0
    # The other digests a sandbox computed for the sample, where it says.
    sha1: str = ""
    sha512: str = ""
    ssdeep: str = ""

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, ("sha1", "sha512", "ssdeep"))


class SandboxProcess(BaseModel):
    """One process in the sandbox's flat process list (parent/child ids only)."""

    model_config = ConfigDict(extra="ignore")

    pid: int = 0
    ppid: int = 0
    name: str = ""
    command_line: str = ""
    first_seen: str = ""
    calls: list[dict[str, Any]] = Field(default_factory=list)
    # The fields the sandbox wrote on the process that the fields above do not
    # hold, under the sandbox's own names: read, never dropped.
    extra: dict[str, Any] = Field(default_factory=dict)

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, ("extra",))


class SandboxSignatureRow(BaseModel):
    """One sandbox signature hit, marks carried through unprocessed."""

    model_config = ConfigDict(extra="ignore")

    name: str = ""
    description: str = ""
    # ``None`` where the sandbox gave a severity no number or declared rung
    # reads (its word is then kept in ``extra``): unknown, never 0.
    severity: int | None = None
    marks: list[Any] = Field(default_factory=list)
    ttp_tags: list[str] = Field(default_factory=list)
    # The processes the hit was seen in, as pid texts, where the reader's
    # source names them by a field the marks' own process id is not read from
    # (``schemas.sandbox_document.signature_pids`` reads those). Empty where
    # it names none, and then left out of the dump.
    pids: list[str] = Field(default_factory=list)
    # The signature's other fields, under the sandbox's own names.
    extra: dict[str, Any] = Field(default_factory=dict)

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, ("pids", "extra"))


class SandboxDnsRequest(BaseModel):
    """One DNS request a sandbox recorded asking one or more names: the structural form.

    A reader that saw one DNS message ask several names fills one of these (in
    ``SandboxNetwork.dns_requests``) rather than writing a row per name and
    linking them itself: the document's one chokepoint
    (``schemas.sandbox_document.dns_rows``) writes the request's rows, the
    request's answers and other fields once on its first name's row, and mints
    the links between them. Each name then reads the answers for its own name
    and alias chain, and every answer that names no name
    (``schemas.sandbox_document.DnsAnswers``), so a request grouped wrongly can
    never credit a named answer to another name.

    ``questions`` holds each asked name as its row's own fields (``request``,
    the name, and ``type``, the record type asked for); ``answers`` the
    request's answers as the reader writes them (each ``data``, and the
    ``name`` it answers and its ``type`` where the sandbox says); ``extra`` the
    request's other fields.
    """

    model_config = ConfigDict(extra="ignore")

    questions: list[dict[str, Any]] = Field(default_factory=list)
    answers: list[Any] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class SandboxNetwork(BaseModel):
    """Network IOC rows, carried through close to their sandbox shape.

    ``domains`` is ``list[str | dict[str, Any]]`` rather than a strict
    ``list[dict]`` because a CAPE report emits both shapes for that one array
    (a bare hostname string, or a ``{"domain": ...}`` row).
    """

    model_config = ConfigDict(extra="ignore")

    dns: list[dict[str, Any]] = Field(default_factory=list)
    http: list[dict[str, Any]] = Field(default_factory=list)
    tcp: list[dict[str, Any]] = Field(default_factory=list)
    udp: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    domains: list[str | dict[str, Any]] = Field(default_factory=list)
    tls: list[dict[str, Any]] = Field(default_factory=list)
    # ICMP is rarer than the rest and is exactly why it is modelled: a sample
    # whose only outbound traffic is an ICMP probe used to render as a sample
    # with no network activity at all.
    icmp: list[dict[str, Any]] = Field(default_factory=list)
    pcap_local_path: str | None = None
    # The DNS requests a reader expresses structurally (:class:`SandboxDnsRequest`),
    # written into the document's DNS rows after ``dns`` by its chokepoint.
    dns_requests: list[SandboxDnsRequest] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, ("dns_requests",))


class SandboxReport(BaseModel):
    """The sandbox-agnostic report. ``provider``/``source_format`` are the one
    thing every reader needs and nothing can infer, so they are the two
    required fields; everything else defaults to empty.

    ``source_format`` is the id of the registered reader that read the report
    (``providers.sandbox.readers``)."""

    model_config = ConfigDict(extra="ignore")

    provider: str
    source_format: str = Field(min_length=1)
    task_id: str = ""
    target: SandboxTarget = Field(default_factory=SandboxTarget)
    processes: list[SandboxProcess] = Field(default_factory=list)
    apistats: dict[str, dict[str, int]] = Field(default_factory=dict)
    generic_events: list[dict[str, Any]] = Field(default_factory=list)
    signatures: list[SandboxSignatureRow] = Field(default_factory=list)
    network: SandboxNetwork = Field(default_factory=SandboxNetwork)
    dropped_files: list[dict[str, Any]] = Field(default_factory=list)
    # list[str], not list[dict]: the real shape is behavior.summary.keys, a
    # flat array of registry-path strings (confirmed against every one of the
    # 97 real reports under data/cape_reports/ — 139,056 string entries, zero
    # dicts). A dict-only filter here would silently drop all of it, the same
    # mistake ``file_writes`` had below.
    registry: list[str] = Field(default_factory=list)
    # Everything a sandbox reports that this schema has no field for, kept
    # rather than dropped. ``registry`` above is the Windows-only channel this
    # project grew first; a Linux guest publishes systemd units and syscalls,
    # an Android one permissions and receivers, a macOS one launchd jobs, and
    # none of those had anywhere to land. Keys are namespaced by platform
    # ("android.permissions", "linux.systemd", "macos.launchd") so two
    # sandboxes cannot collide on a bare word, and rows stay close to the
    # shape the sandbox published them in.
    # Each channel's rows, or one block a reader keeps whole (a mapped
    # report's unnamed block), held as the sandbox published it.
    channels: dict[str, Any] = Field(default_factory=dict)
    screenshots: list[dict[str, Any]] = Field(default_factory=list)
    cti: dict[str, Any] = Field(default_factory=dict)
    # The sections this sandbox structurally cannot produce, by the platform's
    # own section ids (``SECTION_IDS``: ``api_calls``, ``events``,
    # ``registry`` …), never a sandbox's own words; a report stored before
    # the ids were normalised is read through ``LEGACY_SECTION_IDS``.
    unavailable: list[str] = Field(default_factory=list)
    # The run-time limit the sandbox set for the task, in seconds, as its own
    # report says (Triage's task ``timeout``): the limit, not a measured
    # duration, and never the value this platform asked for. ``None`` where the
    # report says nothing.
    run_limit_seconds: int | None = None
    # What the reader read, where it reads less than the whole of what a
    # sandbox can give: ``"overview"`` for a Triage report read from its
    # overview alone (no behavioural task report was read), ``"tasks"`` for
    # one read with them. Empty where the reader reads one body. Held for the
    # run in hand (``reader_of``) and left out of a dump, so a stored or golden
    # report reads as it always did.
    read_from: str = Field(default="", exclude=True)
    # True when no sandbox ran at all and this report stands in for one. A real
    # run that observed nothing is not synthetic: its emptiness is a finding.
    synthetic: bool = Field(default=False)
    raw: dict[str, Any] = Field(default_factory=dict)
    _validate_raw = field_validator("raw", mode="wrap")(_dict_identity_or_validate)
    # Ruled in during the pre-flight scan, beyond the brief's own field list:
    # an agent hunting Linux persistence reads both of these directly
    # (``behavior.summary.{files,write_files,modified_files,wrote_files}`` and
    # the top-level ``file_writes``/``files_written`` arrays) and keep only
    # the string entries of each (its own ``isinstance(p, str)`` guard) — a
    # dict-shaped entry is not richer data, it is a shape the consumer already
    # discards, so both are coerced to ``list[str]`` here rather than filtered
    # to dicts only.
    summary: dict[str, list[str]] = Field(default_factory=dict)
    file_writes: list[str] = Field(default_factory=list)
    # The places a reader fills where its sandbox has them. ``process_tree``
    # is the process tree as the sandbox nests it (each node's ``children``);
    # ``resolved_apis`` the API names the sample resolved at run time;
    # ``extracted`` the configurations and payloads the sandbox extracted, a
    # list, or lists by name, as the sandbox groups them; ``procdumps`` the
    # process dumps; ``memory`` the regions of process memory the sandbox
    # recorded; ``ids_alerts`` the alerts an intrusion detection engine raised
    # on the run's traffic.
    # Rows as the sandbox published them, held by reference: never copied
    # or wrapped row by row.
    process_tree: list[Any] = Field(default_factory=list)
    resolved_apis: list[Any] = Field(default_factory=list)
    extracted: list[Any] | dict[str, Any] = Field(default_factory=list)
    procdumps: list[Any] = Field(default_factory=list)
    memory: list[Any] = Field(default_factory=list)
    ids_alerts: list[Any] = Field(default_factory=list)
    # Every block the reader read that has no place above, under the source's
    # own name and nested as the source nests it in the document's sections
    # (``schemas.sandbox_document``): kept, never dropped, and read by the
    # section tool and the whole-report slice. Held for the run in hand (the
    # document carries it) and left out of a dump.
    extras: dict[str, Any] = Field(default_factory=dict, exclude=True)
    # True for a report the mock sandbox read from a recorded fixture: an
    # observation of some earlier detonation, not of this run
    # (``pipeline.sandbox_status``).
    recorded_fixture: bool = False
    # What a signature's severity number means in this report: the scale the
    # report's format declares, set by the reader that read it. Held for the
    # run in hand and left out of a dump.
    signature_scale: SignatureScale | None = Field(default=None, exclude=True)
    # A reader that keeps its source's own arrangement (``schemas.
    # sandbox_document.decompose``): each place as the source published it, and
    # the order of the keys of each of the document's sections. ``None``: the
    # document is laid out from the fields above. Held for the run in hand and
    # left out of a dump.
    published: dict[str, Any] = Field(default_factory=dict, exclude=True)
    arrangement: dict[str, list[str]] | None = Field(default=None, exclude=True)

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, _FILLED_ONLY)


# The fields a report dumps only where they hold something.
_FILLED_ONLY: tuple[str, ...] = (
    "process_tree",
    "resolved_apis",
    "extracted",
    "procdumps",
    "memory",
    "ids_alerts",
    "recorded_fixture",
)


class SandboxRun(BaseModel):
    """One sandbox job's outcome: the neutral report plus the job's own status.

    ``report`` has no safe empty value — a run without a report is not a run —
    so it is the one field with no default.
    """

    model_config = ConfigDict(extra="ignore")

    task_id: str
    sample_sha256: str = ""
    sample_name: str = ""
    status: str = "reported"
    report: SandboxReport
    # Same wrap-validator identity fix as SandboxReport.raw above, and for the
    # same reason: a sandbox provider's ``fetch()`` sets both
    # ``SandboxRun.raw`` and ``SandboxReport.raw`` to the very same
    # client-returned dict, and ``test_fetch_keeps_the_raw_report_by_identity``
    # depends on ``run.raw is <that dict>`` holding exactly as it does for the
    # report — a plain ``dict[str, Any]`` field does not hold that (confirmed
    # empirically: pydantic-core rebuilds the container even when every value
    # already validates), so this field needs the same protection.
    raw: dict[str, Any]
    _validate_raw = field_validator("raw", mode="wrap")(_dict_identity_or_validate)
    error: str = ""
    # Each raw part of the report as the provider read it, in reading order:
    # its name as the provider names it, and the SHA-256 and byte length of
    # its bytes (``loaders.sandbox_client.report_part``). Empty where the
    # provider read none or does not say. Held for the run in hand and left
    # out of a dump.
    report_parts: list[dict[str, Any]] = Field(default_factory=list, exclude=True)
    # What the report's parts state about the sandbox run, read by the provider
    # while it held them, with the format it read the report as and the other
    # parts it read beside it (``ReportReader.run_facts``). ``None`` where the
    # provider did not read them so; held for the run in hand and left out of
    # a dump.
    run_facts: dict[str, Any] | None = Field(default=None, exclude=True)


# The behaviour summary's lists the model holds, as the document names them
# (``schemas.sandbox_document.SUMMARY_KEYS``): the file, mutex, command and
# service lists an agent hunting persistence and host artefacts reads, and the
# read, write and delete lists beside them.
_SUMMARY_KEYS: tuple[str, ...] = _DOCUMENT_SUMMARY_KEYS

# Blocks a CAPE guest other than Windows publishes, and the namespaced channel
# each one lands in. ``behavior.processes`` is shared across every guest and
# already has a field of its own, so it is not repeated here. A block CAPE did
# not emit produces no channel at all — an absent channel and an empty one say
# different things, and only one of them means the sandbox looked.
_CAPE_CHANNEL_SOURCES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("linux.strace", ("strace",)),
    ("linux.syscalls", ("syscalls",)),
    ("linux.systemd", ("systemd",)),
    ("android.permissions", ("permissions",)),
    ("android.receivers", ("receivers",)),
    ("android.services", ("services",)),
    ("android.activities", ("activities",)),
    ("macos.launchd", ("launchd",)),
)


def _channel_rows(value: Any) -> list[dict[str, Any]]:
    """One channel's rows, with a bare string wrapped so every row is a mapping."""
    if isinstance(value, dict):
        return [{"name": str(k), "value": v} for k, v in value.items()]
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for entry in value:
        if isinstance(entry, dict):
            rows.append(entry)
        elif entry not in (None, ""):
            rows.append({"value": entry})
    return rows


def _cape_channels(
    raw: dict[str, Any], behavior: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    """The non-Windows blocks a CAPE report carries, namespaced by platform.

    CAPE's Linux and Android packages publish beside the shared
    ``behavior.processes`` rather than instead of it, and nothing downstream
    could see any of it. Each block is looked for at the top level and under
    ``behavior``, since CAPE places them in both depending on the package.
    """
    channels: dict[str, list[dict[str, Any]]] = {}
    for channel, keys in _CAPE_CHANNEL_SOURCES:
        for key in keys:
            rows = _channel_rows(raw.get(key))
            if not rows:
                rows = _channel_rows(behavior.get(key))
            if rows:
                channels[channel] = rows
                break
    # Anything the operator's own sandbox already namespaced is taken as-is.
    declared = raw.get("channels")
    if isinstance(declared, dict):
        for name, value in declared.items():
            rows = _channel_rows(value)
            if rows:
                channels[str(name)] = rows
    return channels


# The section ids a report's ``unavailable`` list names, as the sandbox
# sections read them (``analysis.sandbox_sections.SECTION_PREFIXES``), and the
# words an earlier report or a sandbox's own list used for two of them.
SECTION_IDS: tuple[str, ...] = ("api_calls", "apistats", "events", "registry", "screenshots")
LEGACY_SECTION_IDS: dict[str, str] = {"calls": "api_calls", "generic_events": "events"}


def section_id(name: Any) -> str:
    """A section named in an ``unavailable`` list, as the platform's own id.

    The id itself, lower-cased; a word an earlier report used for one
    (``calls``, ``generic_events``) is read as the id it meant.
    """
    word = str(name or "").strip().lower()
    return LEGACY_SECTION_IDS.get(word, word)


# The list fields of the model a normaliser may fill, as one vocabulary: what
# each reader below declares it can fill, and what the sandbox sections read
# (``analysis.sandbox_sections``) to tell a list the reader never fills, which
# says nothing, from one the sandbox left empty, which is a finding.
REPORT_LIST_FIELDS: tuple[str, ...] = (
    "processes",
    "processes.calls",
    "apistats",
    "generic_events",
    "signatures",
    "network.dns",
    "network.http",
    "network.tcp",
    "network.udp",
    "network.hosts",
    "network.domains",
    "network.tls",
    "network.icmp",
    "dropped_files",
    "registry",
    "channels",
    "screenshots",
    *(f"summary.{key}" for key in _SUMMARY_KEYS),
    "file_writes",
    "process_tree",
    "resolved_apis",
    "extracted",
    "procdumps",
    "memory",
    "ids_alerts",
)

# What :func:`cape_report_to_sandbox_report` can fill: every list field, each
# read from the report's own block of that name.
CAPE_NORMALISER_FILLS: frozenset[str] = frozenset(REPORT_LIST_FIELDS)


def report_fills(report: SandboxReport) -> frozenset[str]:
    """The list fields of ``report`` that hold at least one row."""
    from malspark.schemas.sandbox_document import dns_requests_have_place

    network = report.network
    # The structural requests fill ``network.dns`` only where the document can
    # hold their rows.
    requests = network.dns_requests if dns_requests_have_place(report) else ()
    held: dict[str, Any] = {
        "processes": report.processes,
        "processes.calls": any(p.calls for p in report.processes),
        "apistats": report.apistats,
        "generic_events": report.generic_events,
        "signatures": report.signatures,
        "dropped_files": report.dropped_files,
        "registry": report.registry,
        "channels": report.channels,
        "screenshots": report.screenshots,
        "file_writes": report.file_writes,
        **{
            f"network.{kind}": getattr(network, kind)
            for kind in ("dns", "http", "tcp", "udp", "hosts", "domains", "tls", "icmp")
        },
        "network.dns": network.dns or requests,
        **{f"summary.{key}": report.summary.get(key) for key in _SUMMARY_KEYS},
        "process_tree": report.process_tree,
        "resolved_apis": report.resolved_apis,
        "extracted": report.extracted,
        "procdumps": report.procdumps,
        "memory": report.memory,
        "ids_alerts": report.ids_alerts,
    }
    return frozenset(name for name, value in held.items() if value)


@dataclass(frozen=True)
class Reading:
    """What one reader can fill, and how its report reaches the sections."""

    fills: frozenset[str]
    # How the reader read less than the whole of what its sandbox can give,
    # as the clause a section's ``no:`` sentence says it in (``read from its
    # overview alone``); empty where it read everything.
    partial: str = ""
    # Laid out from the form's own fields (``schemas.sandbox_document``), where
    # a pid or parent of 0 is the form's "not stated", rather than as the
    # source published its rows.
    rendered: bool = True
    # The fields of a dropped file's row that hold the file's path in the
    # guest, as the reader's source declares them; empty where the source
    # names no such field (a field of the same name may hold a path on the
    # sandbox's own host, which is never shown).
    guest_path_fields: tuple[str, ...] = ()


# What a report read by a reader that keeps its source's arrangement reached
# its readers as (``reader_of``): as its source published it, or laid out from
# the form's fields, when the report was built without a source.
READ_FROM_RAW = "raw"
READ_FROM_MODEL = "model"
# What the Triage reader read (``SandboxReport.read_from``).
READ_FROM_OVERVIEW = "overview"
READ_FROM_TASKS = "tasks"


def reader_of(report: SandboxReport) -> tuple[str, str, str]:
    """``(provider, source_format, read_from)`` of the reader behind ``report``.

    ``read_from`` is the report's own where its reader set it; for a reader
    that keeps its source's arrangement, whether the report reaches its
    readers as its source published it (``raw``) or laid out from the form
    (``model``, a report built with no source).
    """
    read_from = report.read_from
    if not read_from:
        if keeps_its_source(report):
            read_from = READ_FROM_RAW
        else:
            from malspark.providers.sandbox.readers import report_reader

            reader = report_reader(report.source_format)
            if reader is not None and reader.keeps_source_arrangement:
                read_from = READ_FROM_MODEL
    return report.provider, report.source_format, read_from


def keeps_its_source(report: SandboxReport) -> bool:
    """Whether ``report``'s document is its source's own arrangement: a source with any block."""
    return bool(report.arrangement and report.arrangement.get(""))


def normaliser_reading(
    source_format: str, provider: str = "", read_from: str = ""
) -> Reading | None:
    """What the registered reader ``source_format`` names can fill, or ``None`` when unknown.

    Each reader declares it (``ReportReader.reading``), by what it read
    (``read_from``) and, where that is not said, by the provider.
    """
    from malspark.providers.sandbox.readers import report_reader

    reader = report_reader(str(source_format or "").strip().lower())
    if reader is None:
        return None
    return reader.reading(str(read_from or "").strip().lower(), str(provider or "").strip().lower())


# The words a CAPE report gives four of its blocks, and the document's word
# for each (``schemas.sandbox_document.PLACES``): the CAPE reader's
# declaration, read by its reader and nowhere else.
CAPE_RENAMES: dict[str, str] = {
    "CAPE": "extracted",
    "procdump": "procdumps",
    "procmemory": "memory",
    "suricata": "ids",
}


# The words a document laid out before the parts' words were declared used for
# the four renamed blocks: every such document was CAPE's shape, whichever
# sandbox produced it, so a part missing under the document's word is read
# under the word it had then (:func:`stored_place`).
STORED_DOCUMENT_WORDS: dict[str, str] = {new: old for old, new in CAPE_RENAMES.items()}


def stored_place(document: Any, name: str, default: Any = None) -> Any:
    """The part ``name`` of ``document``, read under its earlier word where the new one is absent.

    A document checkpointed before the parts were renamed is read as what it
    holds rather than stated as holding nothing.
    """
    from malspark.schemas.sandbox_document import PLACES, place

    found = place(document, name, _ABSENT)
    if found is not _ABSENT:
        return found
    path = PLACES[name]
    earlier = STORED_DOCUMENT_WORDS.get(path[0])
    if earlier is None or not isinstance(document, Mapping) or path[0] in document:
        return default
    node: Any = document.get(earlier, _ABSENT)
    for key in path[1:]:
        if not isinstance(node, Mapping) or key not in node:
            return default
        node = node[key]
    return default if node is _ABSENT else node


_ABSENT = object()


def _block(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _extracted(value: Any) -> list[Any] | dict[str, Any]:
    if isinstance(value, dict):
        return value
    return list(value) if isinstance(value, list) else []


def _traffic_process_stated(
    rows: list[dict[str, Any]], fields: tuple[str, ...]
) -> list[dict[str, Any]]:
    """``rows``, each naming its process under one of ``fields`` given :data:`TRAFFIC_PROCESS_KEY`.

    In place: the rows are the report's own, which the document holds by
    reference. A row naming none, or under a value that cannot be an id, is
    left as it is.
    """
    for row in rows if fields else []:
        procid = next((pid for field in fields if (pid := pid_of(row.get(field)))), "")
        if procid:
            row[TRAFFIC_PROCESS_KEY] = procid
    return rows


def cape_report_to_sandbox_report(
    raw: dict[str, Any],
    *,
    provider: str,
    source_format: str,
    task_id: str = "",
    keep_arrangement: bool = True,
    renames: Mapping[str, str] | None = None,
    traffic_process_fields: tuple[str, ...] = (),
) -> SandboxReport:
    """Read a CAPE/Cuckoo-shaped report into the neutral form.

    ``traffic_process_fields`` are the fields a flow's or an HTTP request's
    row names its process under, as the reader declares them: the first one
    holding an id is written beside them under :data:`TRAFFIC_PROCESS_KEY`,
    on the row itself, which the document keeps by reference.

    ``source_format`` is the id of the registered reader that read it, which
    the report records (``SandboxReport.source_format``); never assumed.

    Every place the form names is filled from the report's own block of that
    name. With ``keep_arrangement`` (the CAPE, Cuckoo and mock readers) the
    report also keeps its source's arrangement: each place as the report
    published it, every block with no place under its own name, and the order
    of both (``schemas.sandbox_document.decompose``), so the document laid out
    from the form is the report itself, its four renamed blocks
    (:data:`CAPE_RENAMES`) under the document's words. The original dict is
    carried whole in ``raw``.
    """
    behavior_field, net_field, target_field = (
        raw.get("behavior"),
        raw.get("network"),
        raw.get("target"),
    )
    behavior = behavior_field if isinstance(behavior_field, dict) else {}
    net = net_field if isinstance(net_field, dict) else {}
    target = target_field if isinstance(target_field, dict) else {}
    file_block_field = target.get("file")
    file_block = file_block_field if isinstance(file_block_field, dict) else {}
    summary_field = behavior.get("summary")
    summary_raw = summary_field if isinstance(summary_field, dict) else {}
    cti_field = raw.get("cti")

    processes = [
        SandboxProcess(
            pid=_int(p.get("pid")),
            ppid=_int(p.get("ppid")),
            name=str(p.get("process_name") or p.get("name") or ""),
            command_line=str(p.get("command_line") or p.get("cmd") or ""),
            first_seen=str(p.get("first_seen") or ""),
            calls=[c for c in _list(p.get("calls")) if isinstance(c, dict)],
        )
        for p in _list(behavior.get("processes"))
        if isinstance(p, dict)
    ]
    signatures = [
        SandboxSignatureRow(
            name=str(s.get("name") or ""),
            description=str(s.get("description") or s.get("name") or ""),
            severity=_int(s.get("severity") or s.get("score")),
            marks=list(_list(s.get("marks"))),
            ttp_tags=_as_str_list(s.get("ttp_tags") or s.get("attck_id")),
        )
        for s in _list(raw.get("signatures"))
        if isinstance(s, dict)
    ]
    published: dict[str, Any] = {}
    extras: dict[str, Any] = {}
    arrangement: dict[str, list[str]] | None = None
    if keep_arrangement:
        words = CAPE_RENAMES if renames is None else renames
        published, extras, arrangement = kept_source(raw, words)
    return SandboxReport(
        provider=provider,
        source_format=source_format,
        task_id=str(task_id or _block(raw.get("info")).get("id") or ""),
        target=SandboxTarget(
            # CAPE nests the hashes under target.file.*; a handful of other
            # builds (and the neutral providers upstream of this one) put them
            # directly on target. Both are checked so neither shape loses data.
            sha256=str(target.get("sha256") or file_block.get("sha256") or ""),
            md5=str(target.get("md5") or file_block.get("md5") or ""),
            name=str(target.get("name") or file_block.get("name") or ""),
            file_type=str(file_block.get("type") or ""),
            mime_type=str(file_block.get("type") or ""),
            size=_int(file_block.get("size")),
            sha1=str(target.get("sha1") or file_block.get("sha1") or ""),
            sha512=str(target.get("sha512") or file_block.get("sha512") or ""),
            ssdeep=str(target.get("ssdeep") or file_block.get("ssdeep") or ""),
        ),
        processes=processes,
        apistats={
            str(pid): {str(api): _int(n) for api, n in (stats or {}).items()}
            for pid, stats in _block(behavior.get("apistats")).items()
            if isinstance(stats, dict)
        },
        generic_events=[g for g in _list(behavior.get("generic")) if isinstance(g, dict)],
        signatures=signatures,
        network=SandboxNetwork(
            dns=_rows(net.get("dns")),
            http=_traffic_process_stated(_rows(net.get("http")), traffic_process_fields),
            tcp=_traffic_process_stated(_rows(net.get("tcp")), traffic_process_fields),
            udp=_traffic_process_stated(_rows(net.get("udp")), traffic_process_fields),
            hosts=_rows(net.get("hosts")),
            domains=[d for d in _list(net.get("domains")) if isinstance(d, str | dict)],
            tls=_rows(net.get("tls")),
            icmp=_rows(net.get("icmp")),
            pcap_local_path=_text_or_none(net.get("pcap_local_path")),
        ),
        dropped_files=_rows(raw.get("dropped")),
        registry=_as_str_list(summary_raw.get("keys")),
        channels=_cape_channels(raw, behavior),
        screenshots=_rows(raw.get("screenshots")),
        cti=cti_field if isinstance(cti_field, dict) else {},
        unavailable=[],
        synthetic=bool(raw.get("synthetic")),
        raw=raw,
        summary={key: _as_str_list(summary_raw.get(key)) for key in _SUMMARY_KEYS},
        file_writes=_as_str_list(raw.get("file_writes") or raw.get("files_written")),
        process_tree=_rows(behavior.get("processtree")),
        resolved_apis=_as_str_list(summary_raw.get("resolved_apis")),
        extracted=_extracted(raw.get("CAPE")),
        procdumps=_rows(raw.get("procdump")),
        memory=_rows(raw.get("procmemory")),
        ids_alerts=_rows(_block(raw.get("suricata")).get("alerts")),
        extras=extras,
        published=published,
        arrangement=arrangement,
    )


def _split_host_port(value: str) -> tuple[str, int | None]:
    """Split Triage's combined ``"host:port"`` flow endpoint.

    Triage's dynamic-report flows carry the destination as one string rather
    than separate host/port fields (confirmed against the "Dynamic Report"
    docs page on 2026-09-04). A value with no trailing ``:<digits>`` is kept
    whole as the host, port ``None`` — this also covers a bare IPv6 address,
    which is never mistaken for a port suffix (its last group can be all
    digits: ``2001:db8::1``). An IPv6 address Triage writes with brackets
    (``[2001:db8::1]:443``) is returned without them, as every other source
    states one.
    """
    if value.count(":") > 1 and not value.startswith("["):
        # Several colons without brackets: a bare IPv6 address, whose last
        # group is not a port (``2001:db8::1``), or no host at all.
        return value, None
    host, sep, port_str = value.rpartition(":")
    if sep and port_str.isdigit():
        return _unbracketed(host), int(port_str)
    return _unbracketed(value), None


def _unbracketed(host: str) -> str:
    """``host`` without the brackets that set an IPv6 address apart from its port."""
    if len(host) > 2 and host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


# The key a flow row states its attribution under: ``True`` when the process
# that made the flow is the sample's or one it started, ``False`` when the
# report names that process and it is neither, and absent when the report does
# not say. A platform fact, so it is right or it is not there.
SAMPLE_TREE_KEY = "sample_process_tree"
# The image of the process outside the sample's tree that made a flow, on
# the flow's row: which process reached the address, as the report names it.
FLOW_PROCESS_KEY = "process"
# Beside a flow's ``procid``: the report names the process that made the flow
# and does not list it among the task's processes (a guest service the
# sandbox does not follow), so the traffic is not the sample's. Set only where
# the task lists processes at all.
PROCESS_UNLISTED_KEY = "process_not_listed"
# On a flow's or a request's row: the id the report's process list gives the
# process that made it, in one text form (``pid_of``), as the row's reader
# read it under the field its format states it under
# (``ReportReader.traffic_process_fields``). The one key the launcher's
# reading and the publish rule read a row's process by; a row naming no
# process, or one under a value that cannot be an id, carries none.
TRAFFIC_PROCESS_KEY = "platform_process"
# On a request riding on a flow id several flows of its task share: each
# flow's process facts, the request being the sample's when any of them is
# (``ledger_projection.traffic_makers``). Where they all agree, the request
# carries their facts on itself instead.
TRAFFIC_FLOWS_KEY = "platform_flows"


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"').strip("'"))[-1].lower()


def _named_files(proc: dict[str, Any]) -> set[str]:
    """The file names a process record runs: its image, and each path its command line names.

    Whole file names, never slices: a command line's first word and every
    comma- or space-separated path in it (``rundll32.exe <dll>,#1`` runs the
    DLL), each cut to its file name.
    """
    names = {_basename(str(proc.get("image") or ""))}
    for token in re.split(r"[\s,]+", str(proc.get("cmd") or "")):
        cleaned = token.strip().strip('"').strip("'")
        if cleaned:
            names.add(_basename(cleaned))
    return {name for name in names if name}


def _is_the_sample(proc: dict[str, Any], sample: dict[str, Any]) -> bool:
    """Whether a process record with no ``orig`` mark runs the submitted file.

    A file name the process runs equals the name the sample was submitted
    under, or is the sample's digest with an extension (a sandbox names the
    staged copy by its hash). An equal name, never a contained one: a guest's
    ``MicrosoftEdgeUpdate.exe`` is not a sample submitted as ``update.exe``.
    """
    target = _basename(str(sample.get("target") or ""))
    digest = str(sample.get("sha256") or "").strip().lower()
    for name in _named_files(proc):
        if target and name == target:
            return True
        if digest and name.rsplit(".", 1)[0] == digest:
            return True
    return False


def runs_the_submitted_file(image: str, command_line: str, file_name: str, sha256: str) -> bool:
    """The file lineage fact for one process of any sandbox: it runs the submitted file.

    The test the flows' attribution reads (:func:`_is_the_sample`), over a
    process's image and command line and the name and digest the sample was
    submitted under.
    """
    return _is_the_sample(
        {"image": image, "cmd": command_line}, {"target": file_name, "sha256": sha256}
    )


@dataclass(frozen=True)
class SampleTree:
    """The sample's process tree among a listing's processes (:func:`sample_process_tree`).

    ``pids`` and ``names`` (lower case) of its processes; ``unsettled`` the
    pids whose attribution the listing does not settle: one the two lineage
    facts disagree about, or one more than one listed process carries with
    lineages that differ. A record naming an unsettled pid is unattributed.
    ``reached`` is every pid a listed process of the tree carries, a pid
    another listed process also carries outside it included: a process read
    by its place in the listing, not a record read by its pid.
    """

    pids: frozenset[str]
    names: frozenset[str]
    unsettled: frozenset[str]
    reached: frozenset[str] = frozenset()


def _node_field(node: Any, name: str) -> Any:
    return node.get(name) if isinstance(node, Mapping) else getattr(node, name, None)


def pid_text(value: Any) -> str:
    """A pid as a listing's records are matched by: its text, never ``0``, ``None`` or a bool."""
    text = "" if value is None or isinstance(value, bool) else str(value).strip()
    return "" if text in ("0", "None") else text


@dataclass(frozen=True)
class _Placed:
    """The listed processes, in listing order, and where the two lineage facts place each."""

    nodes: list[tuple[Any, str, str]]  # (the node, its pid text, its name)
    tree: set[int]
    disputed: set[int]
    marked: set[int]
    stated: bool
    # The processes that record a lineage of their own: a parent pid, or a
    # place under another listed process.
    linked: set[int]


def _placed(roots: list[Any], file_name: str, sha256: str) -> _Placed:
    """Each listed process placed by the two lineage facts (:func:`sample_process_tree`)."""
    # (node, pid, parent pid, index of the process it is listed under, name,
    #  runs the submitted file, marked)
    nodes: list[tuple[Any, str, str, int | None, str, bool, bool]] = []
    stack: list[tuple[Any, int | None]] = [(node, None) for node in reversed(roots)]
    while stack:
        node, container = stack.pop()
        pid = pid_text(_node_field(node, "pid"))
        name = str(_node_field(node, "name") or "")
        runs = bool(file_name or sha256) and runs_the_submitted_file(
            name, str(_node_field(node, "command_line") or ""), file_name, sha256
        )
        parent = pid_text(_node_field(node, "ppid")) or (
            nodes[container][1] if container is not None else ""
        )
        index = len(nodes)
        nodes.append(
            (node, pid, parent, container, name, runs, _node_field(node, "marked") is True)
        )
        stack.extend(
            (child, index) for child in reversed(list(_node_field(node, "children") or []))
        )
    by_pid: dict[str, list[int]] = {}
    for index, row in enumerate(nodes):
        if row[1]:
            by_pid.setdefault(row[1], []).append(index)

    def _parent_of(index: int) -> int | None:
        _node, _pid, parent, container, *_rest = nodes[index]
        if parent:
            parents = by_pid.get(parent) or []
            return parents[0] if len(parents) == 1 else None
        # No parent pid recorded, under a process that records none either:
        # the place in the listing is the only link there is.
        return container

    def _reach(seeds: set[int]) -> set[int]:
        # Each process settled once: a chain is walked to the first settled
        # process, and every process on it takes that answer.
        settled: dict[int, bool] = {}
        for start in range(len(nodes)):
            chain: list[int] = []
            on_chain: set[int] = set()
            current: int | None = start
            reaches = False
            while current is not None:
                if current in settled:
                    reaches = settled[current]
                    break
                if current in seeds:
                    reaches = settled[current] = True
                    break
                if current in on_chain:
                    break
                on_chain.add(current)
                chain.append(current)
                current = _parent_of(current)
            for one in chain:
                settled[one] = reaches
        return {index for index, reaches in settled.items() if reaches}

    by_file = _reach({i for i, row in enumerate(nodes) if row[5]})
    by_mark = _reach({i for i, row in enumerate(nodes) if row[6]})
    if by_file and by_mark:
        tree, disputed = by_file & by_mark, by_file ^ by_mark
    else:
        tree, disputed = by_file | by_mark, set()
    return _Placed(
        nodes=[(row[0], row[1], row[4]) for row in nodes],
        tree=tree,
        disputed=disputed,
        marked=by_mark,
        stated=bool(by_file or by_mark),
        linked={i for i, row in enumerate(nodes) if row[2] or row[3] is not None},
    )


def sample_process_tree(roots: list[Any], file_name: str = "", sha256: str = "") -> SampleTree:
    """The sample's process tree among the listed processes, read from its lineage facts.

    The facts the network block's flows are attributed by: the processes that
    run the submitted file (its name or its digest,
    :func:`runs_the_submitted_file`) and the processes the sandbox marks as the
    sample's (``marked``). Each gives a tree, the listed processes whose parent
    chain reaches one it names; where both name processes, a process in both
    trees is the sample's and one in exactly one is disputed; where one alone
    names any, its tree is the answer. A listed root that is neither is not
    the sample's, nor is anything under it, whatever the listing calls a root.
    A parent pid more than one listed process carries is no link: the chain
    stops there. A process that records no parent pid, listed under one that
    records no pid either, descends from that one by its place in the listing.
    One rule for every surface that attributes a process: the export's host
    values and the report's table of the commands the sample started.
    """
    placed = _placed(roots, file_name, sha256)
    nodes, tree = placed.nodes, placed.tree
    by_pid: dict[str, list[int]] = {}
    for index, (_node, pid, _name) in enumerate(nodes):
        if pid:
            by_pid.setdefault(pid, []).append(index)
    unsettled = {nodes[i][1] for i in placed.disputed if nodes[i][1]}
    unsettled.update(pid for pid, listed in by_pid.items() if len({i in tree for i in listed}) > 1)
    return SampleTree(
        pids=frozenset(nodes[i][1] for i in tree if nodes[i][1]) - unsettled,
        names=frozenset(n for n in (nodes[i][2].strip().lower() for i in tree) if n),
        unsettled=frozenset(unsettled),
        reached=frozenset(nodes[i][1] for i in tree if nodes[i][1]),
    )


# Where :func:`process_placement` places a listed process: in the sample's
# tree, outside it, or disputed (``LINEAGE_MARKED`` or ``LINEAGE_FILE``, the
# fact that alone names it); ``PLACED_UNSTATED`` for every process of a
# listing neither fact names any process in.
PLACED_IN_TREE = "tree"
PLACED_OUTSIDE = "outside"
PLACED_UNSTATED = ""
# A process outside the tree that carries a pid a process of the tree carries,
# records no lineage of its own (no parent pid, listed as a root) and names the
# same image as that process, or none: another reading of that process, so not
# placed. A reading that names another image is another process, outside.
PLACED_UNSETTLED = "unsettled"

_QUOTED = re.compile(r'"([^"]*)"')


def _image_of(name: str) -> str:
    """The image a listed name names: its path's file name, lower case; ``""`` for none.

    The path is the text inside the first pair of quotes of a quoted name, and
    otherwise the text before the first ``(``: a listing's note after the
    image (``rundll32.exe (cmdline: ...)``) is not part of it, and a path with
    spaces (``C:\\Program Files\\Foo\\foo.exe``) keeps them.
    """
    text = name or ""
    quoted = _QUOTED.search(text)
    path = quoted.group(1) if quoted else text.split("(", 1)[0]
    return path.strip().replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


def process_placement(
    roots: list[Any], file_name: str = "", sha256: str = ""
) -> list[tuple[Any, str]]:
    """Each listed process, in listing order, with where the sample's lineage rule places it.

    The rule of :func:`sample_process_tree`, read per listed process rather
    than per pid: a process with no recorded pid that runs the submitted file
    or carries the sandbox's mark is placed by its own fact, and two
    processes that carry one pid are each placed by their own lineage. Where
    neither fact names any process, no process is placed
    (``PLACED_UNSTATED``): the listing says nothing either way. A process
    that records no lineage of its own and carries a pid a process of the
    tree carries, naming the same image as that process or none, is a reading
    of it (``PLACED_UNSETTLED``); one naming another image is another process.
    """
    placed = _placed(roots, file_name, sha256)
    tree_images: dict[str, set[str]] = {}
    for i in placed.tree:
        if placed.nodes[i][1]:
            tree_images.setdefault(placed.nodes[i][1], set()).add(_image_of(placed.nodes[i][2]))
    out: list[tuple[Any, str]] = []
    for index, (node, pid, name) in enumerate(placed.nodes):
        if not placed.stated:
            where = PLACED_UNSTATED
        elif index in placed.tree:
            where = PLACED_IN_TREE
        elif index in placed.disputed:
            where = LINEAGE_MARKED if index in placed.marked else LINEAGE_FILE
        elif (
            index not in placed.linked
            and pid in tree_images
            and (not _image_of(name) or _image_of(name) in tree_images[pid])
        ):
            where = PLACED_UNSETTLED
        else:
            where = PLACED_OUTSIDE
        out.append((node, where))
    return out


# Which of the two facts alone names a flow's process as the sample's, on a
# row whose attribution is therefore not stated: ``"marked"`` when the sandbox
# marks it as the sample's and it runs none of the submitted file's names and
# descends from none of its processes, ``"file"`` when it runs the submitted
# file (or descends from a process that does) and the sandbox marks it not. A
# row stored before the value was normalised says ``"orig"`` for ``"marked"``.
LINEAGE_DISPUTED_KEY = "lineage_disputed"
LINEAGE_MARKED = "marked"
LINEAGE_FILE = "file"
# Beside a disputed row: the name published text gives the sandbox whose mark
# it is, the display name its report format declares
# (``core.report_formats.reader_display_name``).
LINEAGE_MARKED_BY_KEY = "lineage_marked_by"
# The keys a flow's row states the process that made it under, which an HTTP
# request riding on that flow takes from it (``triage_overview_to_sandbox_report``).
TRAFFIC_PROCESS_KEYS: tuple[str, ...] = (
    "procid",
    "pid",
    TRAFFIC_PROCESS_KEY,
    SAMPLE_TREE_KEY,
    LINEAGE_DISPUTED_KEY,
    LINEAGE_MARKED_BY_KEY,
    FLOW_PROCESS_KEY,
    PROCESS_UNLISTED_KEY,
)
# The value a row stored before the normalisation gives a marked process, and
# the sandbox such a row, which names no marker, was marked by: the one
# reader that wrote one (the triage format's declared name).
LINEAGE_MARKED_STORED = "orig"


def _ancestors(parent: Mapping[Any, Any], nodes: set[Any]) -> set[Any]:
    """Every listed process up the parent chains of ``nodes``, ``nodes`` left out.

    Each chain is walked only up to a process already reached, so the walk
    costs time linear in the list.
    """
    out: set[Any] = set()
    for node in nodes:
        current = parent.get(node)
        while current is not None and current in parent and current not in out:
            out.add(current)
            current = parent.get(current)
    return out - nodes


def _reach(parent: dict[Any, Any], roots: set[Any]) -> set[Any]:
    """Every listed process whose parent chain reaches one of ``roots``, the roots included.

    Each process's answer is settled once: a chain is walked only up to the
    first process already settled, and every process on it takes that answer,
    so a long chain or many processes cost time linear in the list.
    """
    settled: dict[Any, bool] = {}
    for procid in parent:
        chain: list[Any] = []
        on_chain: set[Any] = set()
        current, reaches = procid, False
        while current:
            if current in settled:
                reaches = settled[current]
                break
            if current in roots:
                reaches = settled[current] = True
                break
            if current in on_chain:
                break
            on_chain.add(current)
            chain.append(current)
            current = parent.get(current)
        for node in chain:
            settled[node] = reaches
    return {procid for procid in parent if settled.get(procid)}


class _Lineage:
    """What one task's process records say about the sample's process tree."""

    def __init__(
        self,
        tree: set[Any],
        disputed: dict[Any, str],
        images: dict[Any, str],
        stated: bool,
    ) -> None:
        self.tree = frozenset(tree)
        self.disputed = dict(disputed)
        self.images = dict(images)
        # Whether either fact names any process, which is what lets a listed
        # process outside every tree be stated as outside it.
        self.stated = stated


def _sample_process_tree(task: dict[str, Any], sample: dict[str, Any]) -> _Lineage:
    """The sample's process tree in one task, read from the two facts the report holds.

    The two facts: the processes Triage marks ``orig``, and the processes that
    run the submitted file (:func:`_is_the_sample`: its name or the digest's,
    equal and never contained). Each gives a tree, the processes whose parent
    chain (``procid_parent``) reaches one it names. Where both name processes,
    a process in both trees is the sample's, a listed process in neither is
    not, and one in exactly one tree is disputed: the facts disagree, so its
    attribution is not stated. A desktop process Triage marked, which runs
    none of the submitted file's names and descends from none of its
    processes, was read as the sample on the mark alone and the address it
    reached published as the sample's. Where only one fact names any process,
    its tree is the answer; where neither does, nothing is stated.
    """
    # Each process by its id in one text form (``pid_of``): an id of a type
    # that cannot be one is not stated, and the process is not keyed.
    processes = [
        (pid_of(p.get("procid")), p) for p in task.get("processes") or [] if isinstance(p, dict)
    ]
    listed = [(procid, p) for procid, p in processes if procid]
    parent = {procid: pid_of(p.get("procid_parent")) for procid, p in listed}
    # As the report writes them, for a reader: the case is the file's own.
    images = {
        procid: re.split(r"[\\/]", str(p.get("image") or p.get("name") or "").strip())[-1]
        for procid, p in listed
    }
    marked = {procid for procid, p in listed if p.get("orig") is True}
    named = {procid for procid, p in listed if _is_the_sample(p, sample)}
    by_mark, by_file = _reach(parent, marked), _reach(parent, named)
    if marked and named:
        disputed = {procid: LINEAGE_MARKED for procid in by_mark - by_file}
        disputed.update({procid: LINEAGE_FILE for procid in by_file - by_mark})
        return _Lineage(by_mark & by_file, disputed, images, True)
    return _Lineage(by_mark or by_file, {}, images, bool(marked or named))


# The sandbox whose ``orig`` mark a row stored without its marker's name was
# read by, by the name its format declares (``core.legacy_tool_tables``). A
# report read now names the format it was read as.
LINEAGE_STORED_MARKED_BY = reader_display_name(STORED_LINEAGE_MARKER_FORMAT)


def _flow_attribution(
    flow: dict[str, Any], lineage: _Lineage, marked_by: str = LINEAGE_STORED_MARKED_BY
) -> dict[str, Any]:
    """What one Triage flow says about the process that made it, and its network facts.

    ``procid`` and ``pid`` as the flow gives them; ``sample_process_tree`` only
    where the report settles it (see ``SAMPLE_TREE_KEY``); for a listed
    process outside the tree, or one the two facts disagree about
    (``LINEAGE_DISPUTED_KEY``), its image (``FLOW_PROCESS_KEY``), which is
    what the publish rule names when it refuses the row; the destination's AS
    number, AS organisation and country where Triage recorded them.
    """
    out: dict[str, Any] = {}
    stated = flow.get(_TRIAGE_TRAFFIC_PROCESS_FIELD)
    procid = pid_of(stated)
    if stated not in (None, ""):
        out["procid"] = stated
    if procid:
        # The id in the text form the process list is keyed by, on both sides.
        out[TRAFFIC_PROCESS_KEY] = procid
        if procid in lineage.tree:
            out[SAMPLE_TREE_KEY] = True
        elif procid in lineage.disputed:
            out[LINEAGE_DISPUTED_KEY] = lineage.disputed[procid]
            if lineage.disputed[procid] == LINEAGE_MARKED:
                out[LINEAGE_MARKED_BY_KEY] = marked_by
            if lineage.images.get(procid):
                out[FLOW_PROCESS_KEY] = lineage.images[procid]
        elif lineage.stated and procid in lineage.images:
            out[SAMPLE_TREE_KEY] = False
            if lineage.images.get(procid):
                out[FLOW_PROCESS_KEY] = lineage.images[procid]
        elif lineage.images and procid not in lineage.images:
            out[PROCESS_UNLISTED_KEY] = True
    if flow.get("pid") not in (None, ""):
        out["pid"] = flow.get("pid")
    for key in ("as_num", "as_org", "country"):
        if flow.get(key) not in (None, ""):
            out[key] = flow[key]
    return out


# Where a run's launch arguments were carried by a generated launcher
# (``providers.launcher``): the lineage :func:`attribute_the_launcher` gives a
# process, under :data:`LINEAGE_KEY` of its ``extra`` and of a flow's row. The
# launcher's processes are the platform's, not the sample's; the sample's are
# the process that runs the generated sample member and everything it started.
# The key is the platform's own: a sandbox's field of that name is taken out
# at intake (``schemas.sandbox_document.unearned_marks_removed``).
LINEAGE_LAUNCHER = "launcher"
LINEAGE_SAMPLE = "sample"
# The task a reader listed a process or a flow in, on the process's ``extra``
# and on the flow's row, where the report holds several tasks whose process
# ids are each the task's own (Triage's behavioural tasks): a process is the
# pair of its task and its id, never its id alone.
PROCESS_TASK_KEY = "platform_task"
# Beside a dropped file's lineage: which of the platform's files it is. The
# archive's members are unpacked in the guest, and a sandbox may list them
# among the files written: neither is a file the sample wrote.
LINEAGE_REASON_KEY = "platform_lineage_reason"
DROPPED_LAUNCHER = "the generated launcher"
DROPPED_SAMPLE = "the submitted sample, unpacked"
# A file the launcher's own process wrote or dumped (its memory regions, a
# file its script host writes on start): the launcher's, by the writer's
# lineage in the row's own task, where the started program did not reach the
# launcher's process in that task. Where it did, the row stays among the
# sample's files, marked with the launcher's lineage as not established.
DROPPED_BY_LAUNCHER = "written by the generated launcher's process"
DROPPED_BY_LAUNCHER_REACHED = (
    "written by the generated launcher's process, which the started program reached "
    "in that task: the launcher's attribution is not established"
)
LINEAGE_LAUNCHER_UNSETTLED = "launcher, not established"
# The platform's keys on a dropped file's row, set again on each reading.
_DROPPED_PLATFORM_KEYS = frozenset({LINEAGE_KEY, LINEAGE_REASON_KEY, MEMBER_FACT_KEY})
# The values of the report's ``LAUNCHER_ATTRIBUTION_KEY`` mark: the sample's
# own processes were told apart from the launcher's in every task that lists
# a process, or they were not, and why (:func:`attribution_not_established`).
ATTRIBUTION_ESTABLISHED = "established"
ATTRIBUTION_NOT_ESTABLISHED = "not established"
# The per-task signatures a reader keeps whole (``task.signatures``), whose
# rows name the processes an overview's signature of the same name may not.
TASK_SIGNATURES_CHANNEL = "task.signatures"
# What the sandbox's own score and family judged, beside them in ``cti``: the
# archive run from the launcher, which was seen to start the sample, or which
# was not.
CTI_ANALYSED_KEY = "analysed"
CTI_ANALYSED_LAUNCHER = (
    "the submitted archive, run from its picked launcher script, which started the sample: "
    "the launcher's own behaviour is part of what the sandbox scored"
)
CTI_ANALYSED_LAUNCHER_UNSEEN = (
    "the submitted archive, run from its picked launcher script; the report does not show "
    "the script starting the sample: the launcher's own behaviour is part of what the "
    "sandbox scored"
)


def attribution_not_established(reason: str) -> str:
    """The ``LAUNCHER_ATTRIBUTION_KEY`` mark of a report whose sample was not told apart."""
    return f"{ATTRIBUTION_NOT_ESTABLISHED}: {reason}"


@dataclass(frozen=True)
class _LauncherNames:
    """What a launch record's launcher block names: the generated members, hosts and digests."""

    # Each member's file name, and its path inside the archive (lower case,
    # forward slashes): the two are one for a member at the archive's root.
    sample: str
    script: str
    hosts: frozenset[str]
    script_sha256: str
    sample_sha256: str
    sample_path: str = ""
    script_path: str = ""


def _member_path(value: Any) -> str:
    """An archive member's path inside the archive, lower case with forward slashes."""
    return "/".join(p for p in str(value or "").strip().lower().replace("\\", "/").split("/") if p)


def _launcher_names(launcher: Any) -> _LauncherNames | None:
    """The generated names a launch record's launcher block holds; ``None`` without all three."""
    if not isinstance(launcher, Mapping):
        return None
    sample_path = _member_path(launcher.get("sample_member"))
    script_path = _member_path(launcher.get("launcher_member"))
    hosts = launcher.get("script_host_images")
    images = frozenset(
        str(h).strip().lower() for h in (hosts if isinstance(hosts, list | tuple) else []) if h
    )
    if not (sample_path and script_path and images):
        return None
    return _LauncherNames(
        sample_path.rsplit("/", 1)[-1],
        script_path.rsplit("/", 1)[-1],
        images,
        str(launcher.get("launcher_sha256") or "").strip().lower(),
        str(launcher.get("sample_sha256") or "").strip().lower(),
        sample_path,
        script_path,
    )


_Node = tuple[str, str]


def _folder(path: str) -> str:
    """The folder of a guest path, lower case with forward slashes; ``""`` for a bare name."""
    text = path.strip().strip('"').strip("'").replace("\\", "/")
    return text.rsplit("/", 1)[0].rstrip("/").lower() if "/" in text else ""


def _archive_root(folder: str, member_path: str) -> str:
    """The folder the archive was unpacked into, from the folder its member ``member_path`` is in.

    ``""`` where the folder does not end in the member's own folder inside the archive.
    """
    inner = member_path.rsplit("/", 1)[0] if "/" in member_path else ""
    if not inner:
        return folder
    return folder[: -len(inner) - 1] if folder.endswith("/" + inner) else ""


# A guest path that names its place whole: a drive's, a share's or a root's.
_PLACED_PATH = re.compile(r"^(?:[a-z]:/|/)")


def _guest_place(path: str) -> str:
    """A written file's guest path, lower case with forward slashes; ``""`` for one not whole.

    The guest a launcher runs in is Windows, whose paths are read without case.
    """
    text = path.strip().strip('"').strip("'").replace("\\", "/").lower()
    return text if _PLACED_PATH.match(text) else ""


def _dropped_paths(row: Mapping[str, Any]) -> list[str]:
    """The guest paths and names a dropped-file row gives its file under."""
    out: list[str] = []
    for key in ("name", "filepath", "path", "guest_paths"):
        value = row.get(key)
        for one in value if isinstance(value, list) else [value]:
            if isinstance(one, str) and one.strip():
                out.append(one)
    return out


def _signature_nodes(
    pids: list[str], by_pid: Mapping[str, set[_Node]], task: str | None = None
) -> set[_Node] | None:
    """The listed processes a signature's pids name; ``None`` where a pid names none.

    With ``task``, the pids are that task's; without, a pid names the process
    of that id in every task that lists one.
    """
    nodes: set[_Node] = set()
    for pid in pids:
        found = {node for node in by_pid.get(pid, set()) if task is None or node[0] == task}
        if not found:
            return None
        nodes |= found
    return nodes


# The fields a written file names the processes that wrote it under, the
# process list's own id first: a sandbox that lists its processes by an id of
# its own names the writer by that id too, beside the guest's pid.
_WRITER_KEYS: tuple[str, ...] = ("procid", "pids", "pid", "process_id")


def _writer_pids(row: Mapping[str, Any]) -> list[str]:
    """The processes a written file's row names as its writer, by the first field naming one."""
    for key in _WRITER_KEYS:
        value = row.get(key)
        pids = [
            pid
            for one in (value if isinstance(value, list) else [value])
            if isinstance(one, int | str) and not isinstance(one, bool)
            for text in str(one).split(",")
            if (pid := pid_of(text))
        ]
        if pids:
            return pids
    return []


# What becomes of a written file the sample wrote that a member's facts touch
# (:data:`MEMBER_FACT_KEY`): it holds the member's digest away from the
# member's place, or it sits at the member's place with another digest.
MEMBER_COPIED = "a copy of the archive member, away from the member's place"
MEMBER_CHANGED = "at the archive member's place, with another digest"
# A file a process of the sample's tree wrote at a member's place, or under a
# member's name, whose digest does not show it changed: the sample's, never
# the member's copy.
MEMBER_WRITTEN = "at the archive member's place or under its name, written by the sample's process"


# The fields a signature's indicator names its source process and the process
# it acted on under: the process list's own id first, then the guest's pid.
_INDICATOR_SOURCE_KEYS: tuple[str, ...] = ("procid", "pid", "process_id")
_INDICATOR_TARGET_KEYS: tuple[str, ...] = ("procid_target", "pid_target", "target_pid")


def _indicator_pid(indicator: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        pid = pid_of(indicator.get(key))
        if pid:
            return pid
    return ""


def _reached_launcher_tasks(
    report: SandboxReport, by_pid: Mapping[str, set[_Node]], launcher_nodes: set[_Node]
) -> set[str]:
    """The tasks in which a process not of the launcher's acted on a launcher process.

    Read from the signatures' indicators that name the process acted on (a
    write into its memory, a thread created in it, a handle opened on it):
    one whose target is a launcher process and whose source is not, or names
    none, reaches the launcher in that task. The per-task signatures
    (:data:`TASK_SIGNATURES_CHANNEL`) are read in their own task; a
    signature's marks naming no task are read in each task that lists the
    target's id. Linear in the indicators.
    """
    out: set[str] = set()
    sources: list[tuple[str | None, Any]] = [
        (None, signature.marks) for signature in report.signatures
    ]
    for row in report.channels.get(TASK_SIGNATURES_CHANNEL) or []:
        if isinstance(row, dict) and isinstance(row.get(TASK_ROWS_KEY), list):
            listed_in = str(row.get(TASK_KEY) or "")
            sources.extend(
                (listed_in, signature.get("indicators"))
                for signature in row[TASK_ROWS_KEY]
                if isinstance(signature, dict)
            )
    for task, indicators in sources:
        for indicator in indicators if isinstance(indicators, list) else []:
            if not isinstance(indicator, Mapping):
                continue
            target = _indicator_pid(indicator, _INDICATOR_TARGET_KEYS)
            if not target:
                continue
            source = _indicator_pid(indicator, _INDICATOR_SOURCE_KEYS)
            for node in by_pid.get(target, ()):
                if task is not None and node[0] != task:
                    continue
                from_launcher = bool(source) and (node[0], source) in launcher_nodes
                if node in launcher_nodes and not from_launcher:
                    out.add(node[0])
    return out


def _members(names: _LauncherNames) -> tuple[tuple[str, str, str, str], ...]:
    """Each archive member: its path inside the archive, its file name, its digest, its reason."""
    return (
        (names.script_path, names.script, names.script_sha256, DROPPED_LAUNCHER),
        (names.sample_path, names.sample, names.sample_sha256, DROPPED_SAMPLE),
    )


def _member_places(names: _LauncherNames, roots: set[str]) -> list[set[str]]:
    """Each member's places in the guest, one per folder the archive was unpacked into.

    Built once per report: a hostile report's many folders and many rows
    cost their sum, never their product.
    """
    return [{f"{root}/{path}" for root in roots} for path, _n, _s, _r in _members(names)]


def _member_reading(
    row: Mapping[str, Any],
    names: _LauncherNames,
    roots: set[str],
    places: list[set[str]],
    by_sample: bool = False,
) -> tuple[str, dict[str, Any] | None, bool]:
    """Whether a written file is the platform's copy of an archive member, and what it says else.

    ``(reason, fact, unplaced)``. A file is a member's copy only at the
    member's place (``places``, :func:`_member_places`), the folder the
    archive was unpacked into joined with the member's path inside it,
    holding the member's digest where the row states one. Elsewhere, a file
    with a member's digest is the sample's, stated as a copy of the member,
    and one at the member's place with another digest is the sample's,
    stated as changed (``fact``). A row that states no whole guest path, or
    a report whose launcher folder is not known, is read by its names and
    digest (:func:`_the_member`), and a member found so is ``unplaced``. A
    row one of whose writers is a process of the sample's tree
    (``by_sample``) is never a member's copy: where it would be one, it is
    the sample's, stated as written there (:data:`MEMBER_WRITTEN`).
    """
    paths = _dropped_paths(row)
    digest = str(row.get("sha256") or "").strip().lower()
    members = _members(names)
    placed = {_guest_place(path) for path in paths} - {""}

    def written(path: str, sha256: str, at: set[str]) -> dict[str, Any]:
        fact = MEMBER_COPIED if digest and digest == sha256 and not placed & at else MEMBER_WRITTEN
        return {"fact": fact, "member": path, "member_at": sorted(at), "at": paths}

    if not roots or not placed:
        files = {_basename(path) for path in paths}
        where = {_folder(path) for path in paths} - {""}
        # A copy elsewhere in the guest, where the report shows the launcher's
        # folder, is the sample's own doing (a copy of itself it wrote).
        if not (roots and where and not where & roots):
            for (path, name, sha256, reason), at in zip(members, places, strict=True):
                if _the_member(name, sha256, files, digest, bool(roots)):
                    if by_sample:
                        return "", written(path, sha256, at), False
                    return reason, None, True
        return "", None, False
    for (path, _name, sha256, reason), at in zip(members, places, strict=True):
        if placed & at and (not digest or not sha256 or digest == sha256):
            if by_sample:
                return "", written(path, sha256, at), False
            return reason, None, False
    for (path, _name, sha256, _reason), at in zip(members, places, strict=True):
        if not sha256 or not digest:
            continue
        fact = ""
        if placed & at and digest != sha256:
            fact = MEMBER_CHANGED
        elif digest == sha256 and not placed & at:
            fact = MEMBER_COPIED
        if fact:
            return "", {"fact": fact, "member": path, "member_at": sorted(at), "at": paths}, False
    return "", None, False


def _the_member(name: str, sha256: str, files: set[str], digest: str, folder_known: bool) -> bool:
    """Whether a written file is the archive's member ``name``, by its name or its digest.

    Where the launcher's folder is known, either says it. With no folder
    known a digest alone is not enough (the sample's own copy of itself has
    the sample's digest): the member's name must match too, and the digest,
    where both are known.
    """
    named = name in files
    same = bool(sha256) and digest == sha256
    if folder_known:
        return named or same
    return named and (same or not sha256 or not digest)


def attribute_the_launcher(report: SandboxReport, launcher: Any) -> None:
    """Mark, in place, what in ``report`` is the generated launcher's and what the sample's.

    ``launcher`` is the launch record's launcher block
    (``providers.submission.launch_record``): the names and digests the
    platform generated for the archive it submitted. One rule for every
    sandbox, read from the neutral report alone, a process being the pair of
    its task (:data:`PROCESS_TASK_KEY`) and its id:

    * the sample's tree is rooted at each process whose image's file name is
      the sample member, and holds everything those started
      (``lineage: "sample"``), a script host the sample itself started
      included;
    * a process whose image is one of the record's script host images and
      whose command line names the launcher member, and that the sample did
      not start, is the launcher's (``lineage: "launcher"``), where the task
      states the parent of a process running the sample as a process it
      lists, only as an ancestor of a process of the sample's tree; in a
      task where the sample's tree is rooted, so is every process it started
      outside that tree, and in a task where it is not, the host alone: what
      it started is attributed to no one, since the sample may be among it
      under another name;
    * a flow's attribution (``SAMPLE_TREE_KEY``) is read from that tree, a
      flow of the launcher's process says so, and a flow of a process
      attributed to no one states nothing;
    * a signature every process of which is the launcher's, in every task
      that lists it, is moved to the :data:`LAUNCHER_SIGNATURES_CHANNEL`
      channel, marked, so its techniques and indicators are never read as
      the sample's; one that names no process takes its processes from the
      per-task signatures of the same name (:data:`TASK_SIGNATURES_CHANNEL`),
      whose launcher rows are marked the same way, and one that still names
      none stays, counted (``UNATTRIBUTED_SIGNATURES_KEY``);
    * a dropped file that is the launcher script or the unpacked sample at
      the member's own place (the folder the archive was unpacked into,
      joined with the member's path inside it, compared without case) and
      holding the member's digest where the row states one, is marked as the
      platform's with its reason (:data:`LINEAGE_REASON_KEY`), never a file
      the sample wrote; a file with a member's digest elsewhere, or at the
      member's place with another digest, is the sample's, with that stated
      (:data:`MEMBER_FACT_KEY`); a row that states no whole guest path, or a
      report whose launcher folder is not known, is read by member name or
      digest and each member found so is counted
      (``UNPLACED_MEMBER_FILES_KEY``); a row one of whose writers is a
      process of the sample's tree in its task is never a member's copy: it
      is the sample's, with the member stated (:data:`MEMBER_WRITTEN`,
      :data:`MEMBER_CHANGED` or :data:`MEMBER_COPIED`);
    * a dropped file every writing process of which is the launcher's, read
      in the row's own task (the process list's own id first), is marked as
      the platform's, :data:`DROPPED_BY_LAUNCHER`, where no signature of that
      task shows another process acting on the launcher's process
      (:func:`_reached_launcher_tasks`); where one does, it stays the
      sample's, marked :data:`LINEAGE_LAUNCHER_UNSETTLED`; a row naming no
      task in a report listing processes by task is credited to no one by its
      writer; both are counted (``UNSETTLED_LAUNCHER_FILES_KEY``), the rows
      credited too (``LAUNCHER_FILES_KEY``); a row that names no writer keeps
      the reading above, and no row is taken out;
    * the report says whether the sample's processes were told apart
      (``LAUNCHER_ATTRIBUTION_KEY``), and the sandbox's score and family are
      stated to be its analysis of the archive run from the launcher
      (:data:`CTI_ANALYSED_KEY`).

    Run again on the same report, it gives the same report. A record that
    names no launcher leaves the report as it came.
    """
    names = _launcher_names(launcher)
    if names is None:
        return
    parent: dict[_Node, _Node | None] = {}
    images: dict[_Node, str] = {}
    by_pid: dict[str, set[_Node]] = {}
    roots: set[_Node] = set()
    hosts: set[_Node] = set()
    # The folders the archive was unpacked into, as the launcher's and the
    # sample's processes show them (:func:`_archive_root`).
    folders: set[str] = set()
    for proc in report.processes:
        proc.extra.pop(LINEAGE_KEY, None)
        pid = pid_text(proc.pid)
        if not pid:
            continue
        task = str(proc.extra.get(PROCESS_TASK_KEY) or "")
        node = (task, pid)
        if node in parent:
            continue
        ppid = pid_text(proc.ppid)
        parent[node] = (task, ppid) if ppid else None
        by_pid.setdefault(pid, set()).add(node)
        image = _image_of(proc.name)
        images[node] = re.split(r"[\\/]", proc.name.strip().strip('"'))[-1]
        if image == names.sample:
            roots.add(node)
            quoted = _QUOTED.search(proc.name)
            folder = _folder(quoted.group(1) if quoted else proc.name.split("(", 1)[0])
            folders.add(_archive_root(folder, names.sample_path))
        elif image in names.hosts:
            # A quoted path keeps its spaces; an unquoted one is a word.
            scripts = [
                word
                for word in _QUOTED.findall(proc.command_line)
                if _basename(word) == names.script
            ] or [
                word
                for word in re.split(r"[\s,]+", proc.command_line)
                if _basename(word) == names.script
            ]
            if scripts:
                hosts.add(node)
                folders.update(_archive_root(_folder(t), names.script_path) for t in scripts)
    folders.discard("")
    rooted = {node[0] for node in roots}
    sample_tree = _reach(parent, roots)
    # Where a task states the parent of a process running the sample as a
    # process it lists, the launcher's process is also an ancestor of a
    # process of the sample's tree: a script host the sample started outside
    # its own tree is not the launcher's. A task that states no such parent,
    # or in which no process runs the sample, keeps the rule above alone.
    parented = {root[0] for root in roots if parent.get(root) in parent}
    ancestors = _ancestors(parent, sample_tree)
    hosts = {h for h in hosts if h[0] not in rooted & parented or h in ancestors}
    reached = _reach(parent, hosts - sample_tree) - sample_tree
    launcher_nodes = {n for n in reached if n[0] in rooted} | {
        n for n in hosts if n[0] not in rooted
    }
    for proc in report.processes:
        node = (str(proc.extra.get(PROCESS_TASK_KEY) or ""), pid_text(proc.pid))
        if node in sample_tree:
            proc.extra[LINEAGE_KEY] = LINEAGE_SAMPLE
        elif node in launcher_nodes:
            proc.extra[LINEAGE_KEY] = LINEAGE_LAUNCHER
    # A flow's row, and a request's that names its process (its own, or its
    # flow's), each flow's facts of a request on a shared flow id included.
    traffic: list[dict[str, Any]] = [
        row for row in (*report.network.tcp, *report.network.udp) if isinstance(row, dict)
    ]
    traffic += [row for row in (*report.network.http, *report.network.dns) if isinstance(row, dict)]
    traffic += [r.extra for r in report.network.dns_requests]
    traffic += [
        facts
        for row in list(traffic)
        if isinstance(row.get(TRAFFIC_FLOWS_KEY), list)
        for facts in row[TRAFFIC_FLOWS_KEY]
        if isinstance(facts, dict)
    ]
    for row in traffic:
        procid = pid_of(row.get(TRAFFIC_PROCESS_KEY))
        for key in (SAMPLE_TREE_KEY, LINEAGE_DISPUTED_KEY, LINEAGE_MARKED_BY_KEY, LINEAGE_KEY):
            row.pop(key, None)
        node = (str(row.get(PROCESS_TASK_KEY) or ""), procid)
        if not procid or node not in parent:
            continue
        if node in sample_tree:
            row[SAMPLE_TREE_KEY] = True
            row.pop(FLOW_PROCESS_KEY, None)
            continue
        if node[0] not in rooted and node not in launcher_nodes:
            # Started by the launcher where the sample's tree is not found:
            # the sample's or not, the report does not say.
            row.pop(FLOW_PROCESS_KEY, None)
            continue
        row[SAMPLE_TREE_KEY] = False
        if images.get(node):
            row[FLOW_PROCESS_KEY] = images[node]
        if node in launcher_nodes:
            row[LINEAGE_KEY] = LINEAGE_LAUNCHER
    # The per-task signatures: each row's processes are its task's.
    by_name: dict[str, list[set[_Node] | None]] = {}
    for channel_row in report.channels.get(TASK_SIGNATURES_CHANNEL) or []:
        if not isinstance(channel_row, dict) or not isinstance(
            channel_row.get(TASK_ROWS_KEY), list
        ):
            continue
        task = str(channel_row.get(TASK_KEY) or "")
        marked: list[Any] = []
        for signature in channel_row[TASK_ROWS_KEY]:
            if not isinstance(signature, dict):
                marked.append(signature)
                continue
            plain = {k: v for k, v in signature.items() if k != LINEAGE_KEY}
            pids = _triage_indicator_pids(plain.get("indicators"))
            nodes = _signature_nodes(pids, by_pid, task) if pids else set()
            # A row naming no process may be the sample's: it keeps a
            # same-named signature from the launcher's channel.
            by_name.setdefault(str(plain.get("name") or ""), []).append(nodes if pids else None)
            if nodes and nodes <= launcher_nodes:
                marked.append({**plain, LINEAGE_KEY: LINEAGE_LAUNCHER})
            else:
                marked.append(plain if LINEAGE_KEY in signature else signature)
        channel_row[TASK_ROWS_KEY] = marked
    kept: list[SandboxSignatureRow] = []
    unattributed = 0
    for signature in report.signatures:
        signature.extra.pop(LINEAGE_KEY, None)
        pids = signature.pids or signature_pids({"marks": signature.marks})
        found: list[set[_Node] | None] = (
            [_signature_nodes(pids, by_pid)] if pids else by_name.get(signature.name, [])
        )
        if found and all(nodes and nodes <= launcher_nodes for nodes in found):
            report.channels.setdefault(LAUNCHER_SIGNATURES_CHANNEL, []).append(
                {**signature.model_dump(), LINEAGE_KEY: LINEAGE_LAUNCHER}
            )
            continue
        if not found:
            unattributed += 1
        kept.append(signature)
    report.signatures = kept
    reached = _reached_launcher_tasks(report, by_pid, launcher_nodes)
    tasked = any(node[0] for node in parent)
    places = _member_places(names, folders)
    unplaced = credited = unsettled = 0
    for index, dropped in enumerate(report.dropped_files):
        if not isinstance(dropped, dict):
            continue
        plain = {k: v for k, v in dropped.items() if k not in _DROPPED_PLATFORM_KEYS}
        # The row's writers, read within its own task, as a process is the
        # pair of its task and its id.
        writers = _writer_pids(plain)
        task = str(plain.get(PROCESS_TASK_KEY) or "")
        nodes = {(task, pid) for pid in writers} if task or not tasked else set()
        reason, fact, at_no_place = _member_reading(
            plain, names, folders, places, by_sample=bool(nodes & sample_tree)
        )
        unplaced += at_no_place
        lineage = LINEAGE_LAUNCHER
        if writers and not reason:
            # Written by the launcher's own process.
            if task or not tasked:
                if nodes <= launcher_nodes:
                    if task in reached:
                        # The started program reached the launcher's process:
                        # what it wrote may be the sample's doing, so it stays
                        # among the sample's files, marked.
                        lineage, reason = LINEAGE_LAUNCHER_UNSETTLED, DROPPED_BY_LAUNCHER_REACHED
                        unsettled += 1
                    else:
                        reason = DROPPED_BY_LAUNCHER
                        credited += 1
            elif any(n in launcher_nodes for pid in writers for n in by_pid.get(pid, ())):
                # A row whose task is not known is credited to no one by its
                # writer, and counted.
                unsettled += 1
        if reason:
            report.dropped_files[index] = {
                **plain,
                LINEAGE_KEY: lineage,
                LINEAGE_REASON_KEY: reason,
                **({MEMBER_FACT_KEY: fact} if fact else {}),
            }
        elif fact:
            report.dropped_files[index] = {**plain, MEMBER_FACT_KEY: fact}
        elif len(plain) != len(dropped):
            report.dropped_files[index] = plain
    tasks = {node[0] for node in parent}
    if not tasks:
        said = attribution_not_established("the report lists no process with an id")
    elif not rooted:
        said = attribution_not_established(f"no listed process runs {names.sample}")
    elif tasks - rooted:
        said = attribution_not_established(
            f"no listed process runs {names.sample} in task " + ", ".join(sorted(tasks - rooted))
        )
    else:
        said = ATTRIBUTION_ESTABLISHED
    report.extras[LAUNCHER_ATTRIBUTION_KEY] = said
    report.extras[UNATTRIBUTED_SIGNATURES_KEY] = unattributed
    report.extras[UNPLACED_MEMBER_FILES_KEY] = unplaced
    report.extras[LAUNCHER_FILES_KEY] = credited
    report.extras[UNSETTLED_LAUNCHER_FILES_KEY] = unsettled
    report.cti[CTI_ANALYSED_KEY] = (
        CTI_ANALYSED_LAUNCHER if said == ATTRIBUTION_ESTABLISHED else CTI_ANALYSED_LAUNCHER_UNSEEN
    )


# What :func:`triage_overview_to_sandbox_report` can fill: the process list,
# the signatures, the dumped files, the flows split into TCP and UDP with a
# host row per destination, the DNS and HTTP requests with their names, and
# what the sandbox extracted. Every other list it leaves empty whatever the
# report holds. Given the overview alone it fills the signatures and the
# extracted items and nothing else: the processes, the dumped files and the
# network are read from the task reports.
TRIAGE_OVERVIEW_FILLS: frozenset[str] = frozenset({"signatures", "extracted"})
# The overview's blocks and a signature's fields the reader reads into places
# of their own; every other one is kept under its own name.
_TRIAGE_OVERVIEW_READ: frozenset[str] = frozenset({"sample", "signatures", "extracted"})
_TRIAGE_SIGNATURE_READ: frozenset[str] = frozenset({"name", "desc", "score", "indicators", "ttp"})
# A task report's blocks the reader reads into places of their own, and the
# fields of a flow and of a request it reads; every other one is kept.
_TRIAGE_TASK_READ: frozenset[str] = frozenset({"processes", "dumped", "network"})
# The field a task report's flow names its process under, by the process
# list's own id (``ReportReader.traffic_process_fields``).
TRIAGE_TRAFFIC_PROCESS_FIELDS: tuple[str, ...] = ("procid",)
_TRIAGE_TRAFFIC_PROCESS_FIELD = TRIAGE_TRAFFIC_PROCESS_FIELDS[0]
_TRIAGE_FLOW_READ: frozenset[str] = frozenset(
    {"proto", "dst", "procid", "pid", "as_num", "as_org", "country"}
)
# A request row's parts, by every name the task report writes each under: the
# DNS question and its answer, the HTTP request and its answer. One generation
# writes a question and its answer on one row (``domain_req``/``domain_resp``,
# ``web_req``/``web_resp``), another writes each on a row of its own
# (``dns_request``/``dns_response``, ``http_request``/``http_response``),
# naming the flow and the exchange's index on that flow; the parts' own fields
# are the same in both, apart from an HTTP message's headers (a mapping, or
# ``Name: value`` lines) and its status (a number, or its digits).
_DNS_QUESTION, _DNS_ANSWER, _HTTP_REQUEST, _HTTP_RESPONSE = "dnsq", "dnsa", "httpq", "httpa"
_TRIAGE_REQUEST_PARTS: Mapping[str, str] = {
    "domain_req": _DNS_QUESTION,
    "dns_request": _DNS_QUESTION,
    "domain_resp": _DNS_ANSWER,
    "dns_response": _DNS_ANSWER,
    "web_req": _HTTP_REQUEST,
    "http_request": _HTTP_REQUEST,
    "web_resp": _HTTP_RESPONSE,
    "http_response": _HTTP_RESPONSE,
}
_TRIAGE_REQUEST_READ: frozenset[str] = frozenset(_TRIAGE_REQUEST_PARTS)
# A request row with no part the reader reads is kept whole, per task, in the
# channel of its kind (the name of its first field that holds an object, or
# none): ``task.network.requests.<kind>``, so each such kind is counted by
# its channel's rows.
TRIAGE_UNREAD_REQUESTS_CHANNEL = "task.network.requests"
# How many kinds of unread request rows a task keeps a channel each, and the
# longest name such a kind's channel takes: the rows of every further kind,
# or of a kind with a longer name, join the channel of rows of no kind, each
# labelled with how many kinds the task folded into it. No row is cut, and a
# kind the reader reads is never among them.
TRIAGE_UNREAD_KINDS = 16
TRIAGE_UNREAD_KIND_NAME = 64
TRIAGE_UNREAD_KINDS_FOLDED_KEY = "request_kinds_folded"
# The key a kept task block's row names its task by; the block itself is held
# under the document's grouped-rows key (``schemas.sandbox_document``).
TASK_KEY = "task_report"
TASK_ROWS_KEY = GROUP_ROWS_KEY


def _triage_exchanges(
    rows: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, dict[str, Any]], dict[str, Any]]], list[dict[str, Any]]]:
    """A task's request rows as exchanges, each its parts and its own fields; and the rows unread.

    A row's parts are read under every name :data:`_TRIAGE_REQUEST_PARTS`
    gives them, each part once (a second part of one kind on a row stays among
    the row's own fields). Rows naming the same flow and index are one
    exchange, a question and its answer written on rows of their own: a part
    joins the first exchange of its flow and index still waiting for it (an
    answer the first open question, a question the first answer written
    before it), in the order the rows come; a row naming no flow or no index
    is an exchange by itself. A row with no part read, and the rows of an
    exchange that holds an answer with no question or request, are returned
    apart, whole. Linear in the rows.
    """
    held: list[tuple[dict[str, dict[str, Any]], dict[str, Any], list[dict[str, Any]]]] = []
    unread: list[dict[str, Any]] = []
    # The exchanges of each flow and index waiting for a part, by that part,
    # in the order they were opened.
    waiting: dict[tuple[str, str, str], deque[int]] = {}
    for req in rows:
        parts: dict[str, dict[str, Any]] = {}
        own: dict[str, Any] = {}
        for key, value in req.items():
            kind = _TRIAGE_REQUEST_PARTS.get(key)
            if kind and isinstance(value, dict) and kind not in parts:
                parts[kind] = value
            else:
                own[key] = value
        if not parts:
            unread.append(req)
            continue
        flow, index = req.get("flow"), req.get("index")
        where = (str(flow), str(index)) if _scalar_id(flow) and _scalar_id(index) else None
        at = _waiting_for(waiting, where, parts, held) if where is not None else None
        if at is not None:
            held[at][0].update(parts)
            for key, value in own.items():
                held[at][1].setdefault(key, value)
            held[at][2].append(req)
        else:
            held.append((parts, own, [req]))
            at = len(held) - 1
        if where is not None:
            # What the exchange still waits for: each part's partner it lacks.
            for kind in held[at][0]:
                partner = _PART_PARTNER[kind]
                if partner not in held[at][0]:
                    waiting.setdefault((*where, partner), deque()).append(at)
    exchanges: list[tuple[dict[str, dict[str, Any]], dict[str, Any]]] = []
    for parts, own, kept in held:
        if _DNS_QUESTION in parts or _HTTP_REQUEST in parts:
            exchanges.append((parts, own))
        else:
            # An answer with nothing it answers: kept whole, never read as a request.
            unread.extend(kept)
    return exchanges, unread


def _flow_id(value: Any) -> str:
    """A flow's id as a request names it and as the flow lists it: one text form."""
    return str(value).strip()


def _request_process(flows: list[dict[str, Any]] | None, task: str) -> dict[str, Any]:
    """The process facts an HTTP request takes from the flows of the id it rode on.

    One flow, or several stating the same facts: those facts, flat on the
    request. Several stating different ones: each flow's facts under
    :data:`TRAFFIC_FLOWS_KEY`, so the request is the sample's when any of them
    is and another lineage's only when all name one, whatever their order.
    """
    if not flows:
        return {}
    by_facts = {json.dumps(f, sort_keys=True, default=str): f for f in flows}
    distinct = [by_facts[key] for key in sorted(by_facts)]
    if len(distinct) == 1:
        return {**distinct[0], PROCESS_TASK_KEY: task}
    return {TRAFFIC_FLOWS_KEY: [{**f, PROCESS_TASK_KEY: task} for f in distinct]}


# Each part and the part that completes its exchange: a question and its answer.
_PART_PARTNER: Mapping[str, str] = {
    _DNS_QUESTION: _DNS_ANSWER,
    _DNS_ANSWER: _DNS_QUESTION,
    _HTTP_REQUEST: _HTTP_RESPONSE,
    _HTTP_RESPONSE: _HTTP_REQUEST,
}


def _waiting_for(
    waiting: dict[tuple[str, str, str], deque[int]],
    where: tuple[str, str],
    parts: Mapping[str, Any],
    held: list[tuple[dict[str, dict[str, Any]], dict[str, Any], list[dict[str, Any]]]],
) -> int | None:
    """The first exchange of ``where`` waiting for the row's parts and holding none of them.

    Exchanges that took the part since are dropped from the front as they are
    met, so each is passed over once: linear in the rows.
    """
    first = next(iter(parts))
    queue = waiting.get((*where, first))
    while queue:
        at = queue[0]
        if first in held[at][0]:
            queue.popleft()
            continue
        if parts.keys() & held[at][0].keys():
            return None
        queue.popleft()
        return at
    return None


def _scalar_id(value: Any) -> bool:
    """Whether ``value`` names a flow or an index: a number or non-empty text, never a bool."""
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, str) and bool(value.strip()))


def _header(headers: Any, name: str) -> str:
    """The value of the header ``name`` (any case), held as a mapping or ``Name: value`` lines."""
    wanted = name.lower()
    if isinstance(headers, dict):
        if headers.get(name) not in (None, ""):
            return str(headers[name])
        for key, value in headers.items():
            if str(key).lower() == wanted and value not in (None, ""):
                return str(value)
        return ""
    for line in headers if isinstance(headers, list) else []:
        if isinstance(line, str) and ":" in line:
            key, _, value = line.partition(":")
            if key.strip().lower() == wanted and value.strip():
                return value.strip()
    return ""


def _status(value: Any) -> Any:
    """An HTTP status as the answer gives it, a status written as its digits read as its number."""
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():
        return int(value.strip())
    return value


def _keep_task_block(
    channels: dict[str, Any],
    name: str,
    task: str,
    value: Any,
    labels: Mapping[str, Any] | None = None,
) -> None:
    """One task report's block, kept whole in the channel ``name`` as one row naming its task.

    The block is held by reference, as the task report holds it (``rows``):
    nothing of it is copied or wrapped, so a block costs one small row
    whatever its size. ``labels`` join the task on the row, each item of the
    block read with them. Nothing with no value is kept.
    """
    if value in (None, "", [], {}):
        return
    channels.setdefault(name, []).append({TASK_KEY: task, **(labels or {}), TASK_ROWS_KEY: value})


TRIAGE_NORMALISER_FILLS: frozenset[str] = frozenset(
    {
        "processes",
        "signatures",
        "dropped_files",
        "network.tcp",
        "network.udp",
        "network.hosts",
        "network.dns",
        "network.domains",
        "network.http",
        "extracted",
        # The task reports' blocks with no place of their own.
        "channels",
    }
)


def triage_overview_to_sandbox_report(
    overview: dict[str, Any],
    *,
    provider: str,
    source_format: str,
    task_reports: dict[str, dict[str, Any]] | None = None,
    task_id: str = "",
    marked_by: str = "",
) -> SandboxReport:
    """Map a Triage overview (plus its behavioural task reports) onto the model.

    ``provider`` and ``source_format`` are the sandbox provider and the id of
    the registered reader that read it, which the report records; neither is
    assumed. ``marked_by`` is the name the format the report was matched as
    declares (its ``display_name``, else its name), which a disputed row names
    its marking sandbox by; empty is the name ``source_format`` declares.

    Triage reports what it observed, not every API call: there is no per-call
    log, no apistats, no registry timeline, no generic-event stream and (for a
    file sample) no screenshot. Those five sections are listed in
    ``unavailable`` rather than left empty and silent, because an empty
    dynamic section reads exactly like a clean sample — and the report
    renderers say so out loud.

    Every other channel a consumer reads is populated straight from the
    fixture shape confirmed against Triage's "Dynamic Report" docs page on
    2026-09-04: each task's ``network.flows`` (tcp/udp, split by ``proto``,
    plus a synthesised ``network.hosts`` row per destination carrying that
    flow's ASN/country) and ``network.requests`` (DNS and HTTP exchanges,
    each part read under every name the task report writes it under,
    :data:`_TRIAGE_REQUEST_PARTS`; a row with no part read is kept whole in a
    channel of its kind, :data:`TRIAGE_UNREAD_REQUESTS_CHANNEL`), and each
    task's ``dumped`` files for ``dropped_files``. Every one of these
    is mapped into the *consumer* shape (``network.dns`` rows as
    ``{request, type, answers: [{data}]}``, ``network.tcp``/``udp`` rows as
    ``{dst, dport}``) rather than passed through in Triage's own shape, so
    ``network_extractor``/``network_parser`` read real domains and IPs
    instead of rendering ``N/A`` for fields they don't recognise.

    ``TriageSandboxProvider`` is imported here, inside the function body rather
    than at module scope, because it is the one caller: the provider module
    imports this function at import time, so a module-level import back would
    be circular. By the time anything actually calls this function, both
    modules have finished loading regardless of which one a caller reached
    first.
    """
    from malspark.providers.sandbox.triage import TriageSandboxProvider

    marker = marked_by or reader_display_name(source_format)
    sample_field, analysis_field = overview.get("sample"), overview.get("analysis")
    sample = sample_field if isinstance(sample_field, dict) else {}
    analysis = analysis_field if isinstance(analysis_field, dict) else {}
    processes: list[SandboxProcess] = []
    dropped_files: list[dict[str, Any]] = []
    network = SandboxNetwork()
    hosts_by_ip: dict[str, dict[str, Any]] = {}
    # Whether any behavioural task report was read: without one, the report is
    # the overview's alone, and says so (``read_from``).
    tasks_read = 0
    extracted = _rows(overview.get("extracted"))
    channels: dict[str, Any] = {}
    for task_name, task in (task_reports or {}).items():
        if not isinstance(task, dict):
            continue
        tasks_read += 1
        # The task report's blocks with no place of their own (its signatures
        # with their per-process indicators, the task, the errors, ...), kept
        # whole as ``task.<block>`` channels, each row naming its task; what
        # it extracted joins the overview's.
        for block, value in task.items():
            if block == "extracted":
                # Each row as the task lists it, by reference: a row the
                # overview lists too is kept twice rather than compared with
                # every row before it.
                extracted.extend(_rows(value))
            elif block not in _TRIAGE_TASK_READ:
                _keep_task_block(channels, f"task.{block}", str(task_name), value)
        lineage = _sample_process_tree(task, sample)
        for proc in task.get("processes") or []:
            if not isinstance(proc, dict):
                continue
            pid_key = "procid" if proc.get("procid") else "pid"
            ppid_key = "procid_parent" if proc.get("procid_parent") else "ppid"
            name_key = "image" if proc.get("image") else "name"
            read = {pid_key, ppid_key, name_key, "cmd", "started"}
            processes.append(
                SandboxProcess(
                    pid=_int(proc.get(pid_key)),
                    ppid=_int(proc.get(ppid_key)),
                    name=str(proc.get(name_key) or ""),
                    command_line=str(proc.get("cmd") or ""),
                    first_seen=str(proc.get("started") or ""),
                    calls=[],
                    # What the task report says of the process beyond those
                    # (the guest's own pid and parent, the sample mark, when
                    # it ended), under its own names, and the task that lists
                    # it, whose process ids are its own.
                    extra={
                        **{k: v for k, v in proc.items() if k not in read},
                        PROCESS_TASK_KEY: str(task_name),
                    },
                )
            )
        dumped_field = task.get("dumped")
        # Each row names its task, whose process ids its writer is read by.
        dropped_files.extend(
            {**row, PROCESS_TASK_KEY: str(task_name)} for row in _rows(dumped_field)
        )

        net_field = task.get("network")
        net = net_field if isinstance(net_field, dict) else {}
        for block, value in net.items():
            if block not in ("flows", "requests"):
                _keep_task_block(channels, f"task.network.{block}", str(task_name), value)

        # Each flow's process facts by its id, which an HTTP request riding on
        # it takes; every flow of an id the task lists twice is kept.
        flow_process: dict[str, list[dict[str, Any]]] = {}
        for flow in _rows(net.get("flows")):
            if _scalar_id(flow.get("id")):
                attribution = _flow_attribution(flow, lineage, marker)
                flow_process.setdefault(_flow_id(flow["id"]), []).append(
                    {k: attribution[k] for k in TRAFFIC_PROCESS_KEYS if k in attribution}
                )
        for flow in _rows(net.get("flows")):
            proto = str(flow.get("proto") or "").lower()
            dst_host, dst_port = _split_host_port(str(flow.get("dst") or ""))
            if not dst_host:
                continue
            row: dict[str, Any] = {"dst": dst_host, "dport": dst_port}
            row.update(_flow_attribution(flow, lineage, marker))
            row[PROCESS_TASK_KEY] = str(task_name)
            # The flow's other fields (its source, times, bytes, protocols,
            # the name and TLS facts the sandbox recorded), under their own names.
            flow_extra = {k: v for k, v in flow.items() if k not in _TRIAGE_FLOW_READ}
            if flow_extra:
                row["extra"] = flow_extra
            if proto == "tcp":
                network.tcp.append(row)
            elif proto == "udp":
                network.udp.append(row)
            host_row = hosts_by_ip.setdefault(dst_host, {"ip": dst_host})
            as_num, as_org = flow.get("as_num"), flow.get("as_org")
            if as_num or as_org:
                host_row["asn"] = " ".join(str(x) for x in (as_num, as_org) if x)
            if flow.get("country"):
                host_row["country_name"] = str(flow["country"])

        exchanges, unread = _triage_exchanges(_rows(net.get("requests")))
        unread_kinds: dict[str, list[dict[str, Any]]] = {}
        folded: set[str] = set()
        for req in unread:
            kind = next((str(k) for k, v in req.items() if isinstance(v, dict)), "")
            if kind and kind not in unread_kinds:
                named = len(unread_kinds) - ("" in unread_kinds)
                if (
                    kind in folded
                    or named >= TRIAGE_UNREAD_KINDS
                    or len(kind) > TRIAGE_UNREAD_KIND_NAME
                ):
                    folded.add(kind)
                    kind = ""
            unread_kinds.setdefault(kind, []).append(req)
        for kind, kept in unread_kinds.items():
            channel = TRIAGE_UNREAD_REQUESTS_CHANNEL + (f".{kind}" if kind else "")
            labels = {TRIAGE_UNREAD_KINDS_FOLDED_KEY: len(folded)} if folded and not kind else {}
            _keep_task_block(channels, channel, str(task_name), kept, labels)

        for parts, req_extra in exchanges:
            domain_req = parts.get(_DNS_QUESTION)
            domain_resp = parts.get(_DNS_ANSWER)
            web_req = parts.get(_HTTP_REQUEST)
            web_resp = parts.get(_HTTP_RESPONSE)
            # ``req_extra``: the exchange's own fields beside its parts (the flow
            # it rode on, its index, its time), kept on each row it gives. The
            # request names no process: an HTTP request takes the process facts
            # of the flow it rode on, in its own task (``made``). A DNS request
            # takes none: its flow is the guest's resolver, never the program
            # that asked.
            ridden = req_extra.get("flow")
            made = _request_process(
                flow_process.get(_flow_id(ridden)) if _scalar_id(ridden) else None,
                str(task_name),
            )

            if domain_req is not None:
                answers = [
                    {"data": str(a["value"])}
                    for a in _rows((domain_resp or {}).get("answers"))
                    if a.get("value")
                ]
                # The request in the structural form
                # (``SandboxDnsRequest``): the document's chokepoint writes its
                # rows, its answers and other fields once, and links its names.
                questions = [
                    q for q in _rows(domain_req.get("questions")) if str(q.get("name") or "")
                ]
                if len(questions) > 1:
                    # Several questions: each answer keeps the name it answers
                    # and its type, so each question is given the answers for
                    # its own name and its alias chain (``DnsAnswers``).
                    answers = [
                        {
                            "data": str(a["value"]),
                            **({"name": str(a["name"])} if a.get("name") else {}),
                            **({"type": str(a["type"])} if a.get("type") else {}),
                        }
                        for a in _rows((domain_resp or {}).get("answers"))
                        if a.get("value")
                    ]
                if questions:
                    network.dns_requests.append(
                        SandboxDnsRequest(
                            questions=[
                                {
                                    "request": str(q.get("name") or ""),
                                    "type": str(q.get("type") or ""),
                                }
                                for q in questions
                            ],
                            answers=answers,
                            extra=dict(req_extra),
                        )
                    )
                network.domains.extend(str(q.get("name") or "") for q in questions)

            if web_req is not None:
                parsed_url = urlsplit(str(web_req.get("url") or ""))
                http_row: dict[str, Any] = {
                    "host": parsed_url.hostname or "",
                    "uri": parsed_url.path or "/",
                    "method": str(web_req.get("method") or ""),
                    "status": _status((web_resp or {}).get("status")),
                    "port": parsed_url.port,
                    "encrypted": parsed_url.scheme == "https",
                    "user_agent": _header(web_req.get("headers"), "User-Agent"),
                    **made,
                }
                # The whole request and answer beyond those fields (the URL with
                # its query, every header, the answer's own fields).
                http_extra: dict[str, Any] = dict(req_extra)
                request_rest = {k: v for k, v in web_req.items() if k != "method"}
                if request_rest:
                    http_extra["request"] = request_rest
                response_rest = {k: v for k, v in (web_resp or {}).items() if k != "status"}
                if response_rest:
                    http_extra["response"] = response_rest
                if http_extra:
                    http_row["extra"] = http_extra
                network.http.append(http_row)
    network.hosts = list(hosts_by_ip.values())

    return SandboxReport(
        provider=provider,
        source_format=source_format,
        task_id=str(task_id or sample.get("id") or ""),
        target=SandboxTarget(
            sha256=str(sample.get("sha256") or ""),
            md5=str(sample.get("md5") or ""),
            name=str(sample.get("target") or ""),
            file_type=str(sample.get("kind") or ""),
            mime_type=str(sample.get("kind") or ""),
            size=_int(sample.get("size")),
            sha1=str(sample.get("sha1") or ""),
            sha512=str(sample.get("sha512") or ""),
            ssdeep=str(sample.get("ssdeep") or ""),
        ),
        processes=processes,
        apistats={},
        generic_events=[],
        signatures=[
            SandboxSignatureRow(
                name=str(s.get("name") or ""),
                description=str(s.get("desc") or s.get("name") or ""),
                severity=_int(s.get("score")),
                marks=list(s.get("indicators") or []),
                ttp_tags=_as_str_list(s.get("ttp")),
                pids=_triage_indicator_pids(s.get("indicators")),
                extra={k: v for k, v in s.items() if k not in _TRIAGE_SIGNATURE_READ},
            )
            for s in (overview.get("signatures") or [])
            if isinstance(s, dict)
        ],
        # The configurations, droppers and credentials Triage extracted, as
        # its overview and its task reports list them.
        extracted=extracted,
        channels=channels,
        # The overview's other blocks (the analysis tags, the task list, the
        # per-target summaries, the report version), under their own names.
        extras={k: v for k, v in overview.items() if k not in _TRIAGE_OVERVIEW_READ},
        network=network,
        dropped_files=dropped_files,
        registry=[],
        screenshots=[],
        cti={"family": _as_str_list(analysis.get("family")), "score": analysis.get("score")},
        unavailable=list(TriageSandboxProvider.UNAVAILABLE),
        run_limit_seconds=_triage_run_limit(overview),
        read_from=READ_FROM_TASKS if tasks_read else READ_FROM_OVERVIEW,
        raw=overview,
    )


def _triage_indicator_pids(indicators: Any) -> list[str]:
    """The processes a Triage signature's indicators were seen in, once each, in order.

    Each indicator's process is read under the field its process is listed by
    (``procid``, else ``pid``), the same choice the reader makes for the
    process itself, so a pid here names a process of the report's own list.
    """
    out: dict[str, None] = {}
    for indicator in indicators if isinstance(indicators, list) else []:
        if not isinstance(indicator, dict):
            continue
        key = "procid" if indicator.get("procid") else "pid"
        pid = pid_of(indicator.get(key))
        if pid:
            out[pid] = None
    return list(out)


def _triage_run_limit(overview: dict[str, Any]) -> int | None:
    """The run-time limit Triage set for the task: its behavioural tasks' ``timeout``.

    The overview lists each task with the run-time limit it was given, not how
    long it ran. ``None`` when no behavioural task carries one, or when two
    carry different ones: one figure for the run would then be a figure the
    report does not state.
    """
    tasks = overview.get("tasks")
    rows = list(tasks.values()) if isinstance(tasks, dict) else tasks
    seen: set[int] = set()
    for task in rows if isinstance(rows, list) else []:
        if not isinstance(task, dict) or str(task.get("kind") or "") != "behavioral":
            continue
        value = task.get("timeout")
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            seen.add(value)
    return seen.pop() if len(seen) == 1 else None
