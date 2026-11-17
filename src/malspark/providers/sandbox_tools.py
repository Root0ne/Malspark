"""The job's sandbox report, as tools instead of one wall of JSON.

The report is the neutral sandbox report's document
(``schemas.sandbox_document``), whichever sandbox and reader produced it; each
tool reads its parts by name (``place``), never by a sandbox's own key.

The dynamic analyst has always been handed the whole report as text, chunked
to fit and truncated where it did not. That is the wrong shape for a model
that wants three specific things: what ran, what it talked to, and what the
sandbox's own signatures said. These tools let it ask.

In-process on purpose — there is no server to open, no transport to bind and
nothing to time out, because the report is already in the container. That is
what ``ToolRef(kind="sandbox")`` resolves to: a tool set built from the report
the job already downloaded.

One of the tools, ``sandbox_items``, reads the report as the sections of
``analysis.sandbox_sections``: whole items, each with the id a claim cites it
by, filtered by section, process id, a substring of any text value, a
signature or a list of ids. It is the one tool of the set another analyst may
be given on its own (``BaseAnalyst._sandbox_items_tool``).

A report the container does not have yields the same tools, each answering
``{"error": "no sandbox report for this job"}``, and the mock sandbox's empty
stand-in yields tools answering the sentence that says no sandbox ran. The
agent then knows the channel is empty rather than silently seeing tools that
return nothing.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from malspark.analysis.sandbox_sections import ITEMS_TOOL
from malspark.core.logger import logger
from malspark.pipeline.sandbox_status import NOT_RUN, sandbox_status
from malspark.providers.call_arguments import pick_argument
from malspark.providers.detonation import selected
from malspark.schemas.sandbox_document import MEMBER_FACT_KEY, pid_of, place, signature_pids
from malspark.schemas.sandbox_report import (
    LINEAGE_KEY,
    LINEAGE_LAUNCHER,
    LINEAGE_LAUNCHER_UNSETTLED,
    LINEAGE_MARKED_STORED,
    LINEAGE_REASON_KEY,
    LINEAGE_SAMPLE,
    PROCESS_TASK_KEY,
    STAGED_KEY,
    STAGED_NOTE,
    STAGED_NOTE_KEY,
    dropped_size,
    process_lineage,
    started_by_the_sandbox,
    written_during_the_run,
)
from malspark.schemas.signature_indicators import (
    CHARS_LEFT_OUT,
    DESCRIPTION,
    EVENT,
    PROCESS,
    TARGET,
    VALUES,
    VALUES_LEFT_OUT,
)
from malspark.utils.marked_cut import marked_cut

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

# Every list a tool answers with is the whole list unless the caller asks for
# a page: ``offset`` is where the page starts and ``limit`` how many rows it
# holds, 0 for all of them. A page that stops short says so — ``N of M rows``
# and the ``next_offset`` to ask for — and how much of an answer a model reads
# at once is the platform's tool-answer sizing to decide, which says what it
# cut. A fixed row count used to cut every view at 200 rows without a word to
# the projection that read it, and an address past row 200 never reached the
# report.


def _page(rows: Sequence[Any], offset: Any = 0, limit: Any = 0) -> tuple[list[Any], dict[str, Any]]:
    """One page of ``rows`` and what it says about itself when it is not all of them."""
    start = max(0, _count(offset))
    wanted = _count(limit)
    stop = start + wanted if wanted > 0 else len(rows)
    shown = list(rows[start:stop])
    if start == 0 and len(shown) == len(rows):
        return shown, {}
    meta: dict[str, Any] = {"shown": f"{len(shown)} of {len(rows)} rows, from offset {start}"}
    if stop < len(rows):
        meta["next_offset"] = stop
    return shown, meta


def _count(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


_NO_REPORT = {"error": "no sandbox report for this job", "tool": "sandbox"}


def _no_sandbox_ran(report: dict[str, Any]) -> bool:
    """Whether ``report`` is one no sandbox produced: the mock's stand-in."""
    return sandbox_status(report).status == NOT_RUN


def _no_report(report: dict[str, Any] | None) -> dict[str, Any]:
    """The answer every tool gives where no sandbox ran, saying which absence it is.

    The mock sandbox's stand-in has well-formed empty sections, and a tool
    that read them would answer "0 processes" about a detonation that never
    happened.
    """
    if report is None:
        return dict(_NO_REPORT)
    return {"error": sandbox_status(report).statement, "tool": "sandbox"}


def _report_of(container: Any) -> dict[str, Any] | None:
    """The job's sandbox report as the neutral report's document every reader reads.

    ``container.sandbox_report`` is set by ``app.arun`` alongside
    ``sample_format``, for the same reason: agents are built lazily, from nodes
    that do not all carry the graph state. A ``SandboxReport`` assigned there
    instead of its document is laid out (``schemas.sandbox_document``) so both
    forms read identically here.
    """
    report = getattr(container, "sandbox_report", None)
    if report is None:
        return None
    if isinstance(report, dict):
        return report
    try:
        from malspark.schemas.sandbox_document import sandbox_document

        return sandbox_document(report)
    except Exception as exc:  # noqa: BLE001 — an unreadable report is an empty one
        logger.warning("sandbox tools: could not lay out the report (%s).", type(exc).__name__)
        return None


def _list_at(report: dict[str, Any], name: str) -> list[Any] | None:
    """The part ``name`` of the report where it is a list, else ``None``."""
    value = place(report, name)
    return value if isinstance(value, list) else None


# What a view says of a part the report does not hold. An empty list says the
# sandbox watched and saw nothing; a part that is not there says nothing
# either way, and answering it as ``[]`` read as "no network activity".
_ABSENT_STATEMENT = (
    "The report does not hold this part, so whether there was any is not known. "
    "This is not the same as none."
)


def _absent(*parts: str) -> dict[str, Any]:
    """The answer for parts the report does not hold: named absent, with no empty list."""
    return {"absent": list(parts), "statement": _ABSENT_STATEMENT}


def _unavailable(report: dict[str, Any]) -> frozenset[str]:
    """The report's own ``unavailable`` list, each name as the platform's section id.

    A reader lays every part out, as an empty list where its sandbox could not
    give it, and names those parts here; read alone, the empty list would say
    "none observed".
    """
    from malspark.schemas.sandbox_report import section_id

    named = place(report, "unavailable")
    return frozenset(section_id(n) for n in named) if isinstance(named, list) else frozenset()


def _fills(normalised_by: Sequence[str] | None) -> frozenset[str] | None:
    """The list fields the job's reader declares it fills, or ``None`` when it is not known.

    ``normalised_by`` is ``(provider, source_format[, read_from])``
    (``normalised_by_of``); the declaration is the reader's own
    (``schemas.sandbox_report.normaliser_reading``), the one the sandbox
    sections read too.
    """
    if not normalised_by or len(normalised_by) not in (2, 3):
        return None
    from malspark.schemas.sandbox_report import normaliser_reading

    provider, source_format, *rest = (str(part or "").strip() for part in normalised_by)
    reading = normaliser_reading(source_format, provider, rest[0] if rest else "")
    return reading.fills if reading is not None else None


def _guest_path_fields(normalised_by: Sequence[str] | None) -> tuple[str, ...]:
    """The dropped-file fields the job's reader declares hold a guest path (``Reading``)."""
    reading = _reading(normalised_by)
    return reading.guest_path_fields if reading is not None else ()


# A view's source under the reader's word for it, where the two differ
# (``schemas.sandbox_report.REPORT_LIST_FIELDS``); every other source is its own.
_FILL_NAMES: dict[str, str] = {"calls": "processes.calls"}


def _held(
    report: dict[str, Any],
    part: str,
    unavailable: frozenset[str],
    fills: frozenset[str] | None = None,
) -> bool:
    """Whether the report holds ``part``: present, filled by its reader, not named unavailable.

    A part the job's reader declares it never fills (``fills``) is laid out
    empty whatever the sandbox saw, and is not held. A part is named
    unavailable by its own name, by its last component (``dns`` for
    ``network.dns``, ``mutexes`` for ``summary.mutexes``), or, for a network
    kind, by ``network``. ``calls`` is held where the flat call list or any
    process's own call list is present (``api_calls`` names it).
    """
    from malspark.schemas.sandbox_report import section_id

    if fills is not None and _FILL_NAMES.get(part, part) not in fills:
        return False
    leaf = part.rsplit(".", 1)[-1]
    names = {section_id(part), section_id(leaf)}
    if part.startswith("network."):
        names.add("network")
    if names & unavailable:
        return False
    if part == "calls":
        if isinstance(place(report, "calls"), list):
            return True
        return any(
            isinstance(proc, dict) and isinstance(proc.get("calls"), list)
            for proc in _list_at(report, "processes") or []
        )
    return place(report, part) is not None


def _absent_of(
    report: dict[str, Any], *sources: str, normalised_by: Sequence[str] | None = None
) -> dict[str, Any] | None:
    """``_absent`` naming ``sources`` when the report holds none of them, else ``None``."""
    unavailable, fills = _unavailable(report), _fills(normalised_by)
    if any(_held(report, source, unavailable, fills) for source in sources):
        return None
    return _absent(*sources)


def sandbox_report_section(
    report: dict[str, Any] | None, section: str, offset: int = 0, limit: int = 0
) -> dict[str, Any]:
    """One top-level section of the report, bounded.

    The escape hatch for a section the other tools do not model — ``target``,
    ``cti``, ``extracted``, ``memory``, ``ids`` or any block a sandbox published
    with no place of its own, under its own name. The section names are listed
    in the answer when the requested one is absent, so a model that guessed
    wrong can correct itself in one turn instead of guessing again.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    key = str(section).strip()
    if key not in report:
        return {
            "error": f"no section {key!r} in the report",
            "sections": sorted(str(k) for k in report),
        }
    value = report[key]
    if isinstance(value, list):
        rows, meta = _page(value, offset, limit)
        return {"section": key, "rows": rows, "total": len(value), **meta}
    return {"section": key, "value": _without_host_paths(value)}


# Where the platform recorded the capture it fetched beside the report. A host
# path, written by the platform and not by the sandbox, and a section answer is
# read by a model: it is named the way the job's capture tools take it back.
_CAPTURE_KEY = "pcap_local_path"


def _without_host_paths(value: Any) -> Any:
    if not isinstance(value, dict) or not value.get(_CAPTURE_KEY):
        return value
    from malspark.tools.staging import job_relative

    return {**value, _CAPTURE_KEY: job_relative(str(value[_CAPTURE_KEY]))}


def sandbox_processes(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """The process tree: pid, parent, name and command line, one row each.

    Without the API calls. The call list is where a behaviour report's bulk
    is, and a process tree is the thing an analyst reads first — they are two
    different questions and answering both at once makes the cheap one
    expensive.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    processes = place(report, "processes")
    if not isinstance(processes, list) or _absent_of(
        report, "processes", normalised_by=normalised_by
    ):
        return _absent("processes")
    # In a report a generated launcher's run produced, the sandbox's own
    # "this is the sample" mark points at the picked script or a wrapper,
    # never at the sample: it is set aside, and only the launch lineage says.
    launched = _launcher_attributed(report, processes)
    # Every process's row; the place the sandbox started the submitted file
    # from is read from the report's own processes (their ids as the reader
    # declares them, never the rows printed here), over the whole listing
    # whichever page is asked for, and the row of the same process marked.
    built = [_process_row(proc, launched) if isinstance(proc, dict) else None for proc in processes]
    reading = _reading(normalised_by)
    lineage = process_lineage(processes, reading, lambda proc: _is_marked(proc, launched))
    named = {
        id(node)
        for node in started_by_the_sandbox(
            lineage, *_submitted(report), written=lambda: written_during_the_run(report, reading)
        )
    }
    staged = {id(row) for row, node in zip(built, lineage, strict=True) if id(node) in named}
    page, meta = _page(built, offset, limit)
    rows: list[dict[str, Any]] = []
    for row in page:
        if row is None:
            continue
        # The process whose image is the submitted file as the sandbox
        # started it: its path is the sandbox's, never the sample's doing.
        if id(row) in staged:
            row[STAGED_KEY] = True
        rows.append(row)
    answer: dict[str, Any] = {"processes": rows, "total": len(processes), **meta}
    if any(STAGED_KEY in row for row in rows):
        answer = {STAGED_NOTE_KEY: STAGED_NOTE, **answer}
    return answer


def _submitted(report: dict[str, Any]) -> tuple[str, str]:
    """The name and digest the report's target states the submitted file under.

    On the target block, or on its ``file`` block where the document keeps a
    sandbox's own arrangement (``target.file.*``), as the reader reads either.
    """
    target = place(report, "target")
    held: dict[str, Any] = target if isinstance(target, dict) else {}
    block = held.get("file")
    nested: dict[str, Any] = block if isinstance(block, dict) else {}
    name, sha256 = (str(held.get(key) or nested.get(key) or "") for key in ("name", "sha256"))
    return name, sha256


def _process_row(proc: dict[str, Any], launched: bool) -> dict[str, Any]:
    """One process's row of the view; ``launched``: a generated launcher's run."""
    row = {
        "pid": proc.get("pid"),
        "ppid": proc.get("ppid") or proc.get("parent_id"),
        "name": proc.get("process_name") or proc.get("name") or "",
        "command_line": proc.get("command_line") or proc.get("cmd") or "",
        "first_seen": proc.get("first_seen"),
        "call_count": len(proc.get("calls") or []),
    }
    # The sandbox's own mark that the process is the sample's, where the
    # record carries one: one of the two lineage facts. Where the run
    # submitted a generated launcher, the lineage the launch record gives
    # (``sandbox_report.attribute_the_launcher``) is stated and decides it: a
    # launcher's process is never the sample's.
    lineage = _launch_lineage(proc)
    if lineage:
        row[LINEAGE_KEY] = lineage
    # The task the reader listed it in, where the report holds several whose
    # process ids are each the task's own.
    task = _task_of(proc)
    if task:
        row["task"] = task
    if _is_marked(proc, launched):
        row["marked"] = True
    return row


def _is_marked(proc: dict[str, Any], launched: bool) -> bool:
    """Whether a process is marked as the sample's: by the launch lineage, else by the sandbox."""
    lineage = _launch_lineage(proc)
    return lineage == LINEAGE_SAMPLE or (
        not launched and not lineage and _marked_as_the_sample(proc)
    )


def _task_of(proc: dict[str, Any]) -> str:
    """The task a reader listed a process in (``PROCESS_TASK_KEY``), ``""`` where it says none."""
    extra = proc.get("extra")
    value = extra.get(PROCESS_TASK_KEY) if isinstance(extra, dict) else None
    return str(value) if value else ""


def _launcher_attributed(report: dict[str, Any], processes: list[Any]) -> bool:
    """Whether ``report`` is of a run a generated launcher started, as the platform marked it.

    Its launch mark names a launcher (``schemas.sandbox_document.LAUNCH_KEY``,
    a platform mark no sandbox's document keeps), or a process carries the
    launch lineage the platform gave it (``sandbox_report.attribute_the_launcher``).
    """
    from malspark.schemas.sandbox_document import LAUNCH_KEY, LAUNCHER_ATTRIBUTION_KEY

    if LAUNCHER_ATTRIBUTION_KEY in report:
        return True
    mark = report.get(LAUNCH_KEY)
    if isinstance(mark, dict) and isinstance(mark.get("launcher"), dict):
        return True
    return any(isinstance(proc, dict) and _launch_lineage(proc) for proc in processes)


def _launch_lineage(proc: dict[str, Any]) -> str:
    """The lineage a launch record gave a process (the launcher's, not established, or the
    sample's); ``""`` else."""
    extra = proc.get("extra")
    value = extra.get(LINEAGE_KEY) if isinstance(extra, dict) else None
    return (
        str(value)
        if value in (LINEAGE_LAUNCHER, LINEAGE_LAUNCHER_UNSETTLED, LINEAGE_SAMPLE)
        else ""
    )


def _marked_as_the_sample(proc: dict[str, Any]) -> bool:
    """Whether a process record carries the sandbox's mark that it is the sample's."""
    extra = proc.get("extra")
    return proc.get(LINEAGE_MARKED_STORED) is True or (
        isinstance(extra, dict) and extra.get(LINEAGE_MARKED_STORED) is True
    )


def sandbox_network(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """DNS lookups, hosts, HTTP requests, TCP/UDP endpoints and TLS, per kind.

    Every row of every kind. A page (``offset``/``limit``) is taken per kind, so
    a sample that made a thousand DNS lookups cannot push its two HTTP requests
    off the page, and a kind cut short says ``<kind>_total`` and
    ``<kind>_next_offset``.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    unavailable, fills = _unavailable(report), _fills(normalised_by)
    if not isinstance(report.get("network"), dict) or "network" in unavailable:
        return _absent("network")
    out: dict[str, Any] = {}
    absent: list[str] = []
    for key in NETWORK_VIEW_KINDS:
        rows = _list_at(report, f"network.{key}")
        if rows is None or not _held(report, f"network.{key}", unavailable, fills):
            absent.append(f"network.{key}")
        else:
            page, meta = _page(rows, offset, limit)
            out[key] = [_with_resolver_fact(row) for row in page]
            if meta:
                out[f"{key}_total"] = len(rows)
                if "next_offset" in meta:
                    out[f"{key}_next_offset"] = meta["next_offset"]
    if absent:
        out.update(_absent(*absent))
    return out


# The kinds the network view lists, in its order; the sandbox sections number
# their network items in this same order (``analysis.sandbox_sections``).
NETWORK_VIEW_KINDS: tuple[str, ...] = (
    "dns",
    "hosts",
    "http",
    "tcp",
    "udp",
    "domains",
    "icmp",
    "tls",
)


def _with_resolver_fact(row: Any) -> Any:
    """A flow or host row, marked ``public_resolver`` when it names a public DNS resolver.

    A platform fact beside the sandbox's own: a sandbox's guest resolves
    through a public resolver whatever the sample does, so an analyst reading
    a row to one is told what the address is before it reads it as a contact.
    """
    if not isinstance(row, dict):
        return row
    from malspark.extractors.network_extractor import is_public_resolver

    address = row.get("dst") or row.get("ip") or row.get("address")
    if isinstance(address, str) and is_public_resolver(address):
        return {**row, "public_resolver": True}
    return row


def _signature_techniques(sig: Mapping[str, Any]) -> list[str]:
    """The ATT&CK ids a sandbox tags one signature with, read from any field it uses.

    The normalised report's ``ttp_tags`` and the raw shapes it is read from
    (``ttp``, ``ttps``, ``attck_id``, ``technique_ids``), each read as the ids
    it writes (``analysis.technique_ids.technique_ids_in``); never the
    signature's name.
    """
    from malspark.analysis.technique_ids import technique_ids_in

    found: dict[str, None] = {}
    for key in ("ttp_tags", "ttp", "ttps", "attck_id", "technique_ids"):
        value = sig.get(key)
        for item in value if isinstance(value, list) else [value]:
            if item:
                found.update(dict.fromkeys(technique_ids_in(item)))
    return list(found)


# The most pids one signature row of an answer lists, as the row's references
# are held to five: a signature seen in fifty processes is placed by its first
# ten, and ``pids_total`` counts them all. The report states the count the same
# way (``SandboxSignature.pids_total``).
SIGNATURE_PIDS_SHOWN = 10

# The keys of one indicator as an entry states it (``SignatureIndicators._stated``
# writes them): the neutral form's, the task it was read in and how many times
# that task states it; the signature view lists each under the signature that
# names it. Nothing else in an answer is written with these keys alone.
INDICATOR_SIGNATURE = "signature"
INDICATOR_TASK = "task"
INDICATOR_TIMES = "times"
INDICATOR_KEYS: tuple[str, ...] = (
    INDICATOR_SIGNATURE,
    INDICATOR_TASK,
    PROCESS,
    TARGET,
    EVENT,
    DESCRIPTION,
    VALUES,
    VALUES_LEFT_OUT,
    CHARS_LEFT_OUT,
    INDICATOR_TIMES,
)

# Where an indicator's process is listed more than once: no row is chosen.
INDICATOR_PROCESS_IN_TASKS = "listed in {count} tasks; the indicator names none of them"
INDICATOR_PROCESS_TWICE = "the task lists {count} processes under this id"

# How an answer that leaves indicators out says the rest are read: this view
# called again, by a signature's name from an offset, or by a process or a text.
INDICATORS_READ = (
    "this view with signature=<name> and offset=<offset>, process=<the report's process "
    "id> or contains=<text> lists them, {page} per call"
)
# What the paged call answers for an argument it cannot read, or a report
# whose format states no indicators.
INDICATORS_BAD_PROCESS = "process is not a process id in digits"
INDICATORS_NONE_DECLARED = "the report's format states no indicators for its signatures"
# Why a call naming a process lists no indicator: no indicator names that
# report's process id, or the number is the guest's pid of a listed process,
# whose report's process id is the one to ask with.
INDICATORS_NO_PROCESS = "no indicator names the report's process id {asked}"
INDICATORS_GUEST_PID = (
    "{asked} is the guest's pid of the process the report lists as process id {ids}; "
    "ask with process={first}"
)


def _reading(normalised_by: Sequence[str] | None) -> Any:
    """What the job's reader declares its reports hold (``Reading``), or ``None`` when unknown."""
    if not normalised_by or len(normalised_by) not in (2, 3):
        return None
    from malspark.schemas.sandbox_report import normaliser_reading

    provider, source_format, *rest = (str(part or "").strip() for part in normalised_by)
    return normaliser_reading(source_format, provider, rest[0] if rest else "")


def _size(value: Any) -> int:
    """What ``value`` adds to an answer written as the guardrail writes it, with its separator."""
    from malspark.core.safe_json import dumps

    return len(dumps(value, default=str)) + 2


def _held_text(value: Any, needle: str) -> bool:
    """Whether a string anywhere in ``value`` contains ``needle``, case not counted; one walk."""
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            if needle in current.lower():
                return True
        elif isinstance(current, Mapping):
            stack.extend(current.values())
        elif isinstance(current, list | tuple):
            stack.extend(current)
    return False


class SignatureIndicators:
    """Each signature's indicators as its ledger entry states them, the report read once.

    Read where the job's reader declares its source states them
    (``Reading.signature_indicators``), never by a format's own field name:
    the rows of a signature's name own, then, where the source lists its
    signatures again per task, those of every task row of the same name, each
    in its task. Every process an indicator names is resolved to the process
    row of the same report and task, with the facts the process view states
    for it (its image, the guest's pid where the reader declares where a row
    holds it, its launch lineage or the sandbox's mark); an id the task does
    not list is stated as not listed, and one listed more than once is stated
    as such, never dropped. Equal indicators of one task are listed once with
    their count (``times``). A name's indicators are in one order: those
    naming a process pairing (the acting and the target process) first, then
    those naming one process, then the rest, each group in the report's
    order. Every text is the report's and is written out
    (``sample_written_out``). Linear in the report: each name's indicators
    are gathered and resolved once, however many rows and calls read them.
    """

    def __init__(self, report: dict[str, Any] | None, normalised_by: Sequence[str] | None) -> None:
        reading = _reading(normalised_by)
        self.fields = getattr(reading, "signature_indicators", None)
        from malspark.schemas.process_identity import ProcessIdentities, ProcessKey

        # Every listed process by its task and the report's id, the guest's
        # pid an alias (``schemas.process_identity``), and the rows of each.
        self._identities = ProcessIdentities()
        self._rows: dict[ProcessKey, list[dict[str, Any]]] = {}
        self._own: dict[str, list[list[Any]]] = {}
        self._task_rows: dict[str, list[tuple[str, list[Any]]]] = {}
        self._names: list[str] = []
        self._task_only: list[str] = []
        self._resolved: dict[str, tuple[list[dict[str, Any]], list[int]]] = {}
        self._launched = False
        if self.fields is None or not isinstance(report, dict):
            self.fields = None
            return
        from malspark.schemas.sandbox_document import PROCESS_ID_KEYS, channel_rows
        from malspark.schemas.signature_indicators import indicators_of

        processes = _list_at(report, "processes") or []
        listed = [proc for proc in processes if isinstance(proc, dict)]
        keys = self._identities.add_listing(
            (
                next((p for key in PROCESS_ID_KEYS if (p := pid_of(proc.get(key)))), ""),
                _task_of(proc),
                self._guest_pid(proc),
            )
            for proc in listed
        )
        for key, proc in zip(keys, listed, strict=True):
            if key is not None:
                self._rows.setdefault(key, []).append(proc)
        self._listing = {key.task for key in self._rows}
        self._launched = _launcher_attributed(report, processes)
        fields = self.fields
        named: dict[str, None] = {}
        signatures = place(report, "signatures")
        for row in signatures if isinstance(signatures, list) else []:
            if not isinstance(row, dict):
                continue
            name = _signature_name(row)
            named[name] = None
            listed = indicators_of(row, fields.lists)
            if listed:
                self._own.setdefault(name, []).append(listed)
        channels = place(report, "channels")
        held = channels.get(fields.task_channel) if isinstance(channels, dict) else None
        if fields.task_channel and held is not None:
            from malspark.schemas.sandbox_report import TASK_KEY

            for row in channel_rows(held) or []:
                if not isinstance(row, dict):
                    continue
                listed = indicators_of(row, fields.task_lists)
                if listed:
                    name = str(row.get(fields.task_name) or "")
                    task = str(row.get(TASK_KEY) or "")
                    self._task_rows.setdefault(name, []).append((task, listed))
        # The names in the report's order: a task row of a name no signature
        # row has is the report's too, listed after them.
        self._task_only = [name for name in self._task_rows if name not in named]
        named.update(dict.fromkeys(self._task_rows))
        self._names = list(named)

    def _process(self, procid: str, task: str) -> dict[str, Any]:
        """The process ``procid`` names in ``task`` (any task where none is stated), as listed."""
        from malspark.schemas.process_identity import ProcessKey

        out: dict[str, Any] = {"id": procid}
        # The report's own id, never a guest's pid: an indicator names its
        # processes by the process list's ids.
        held = self._identities.keys(procid, task or None, alias=False)
        if not task:
            tasks = {key.task for key in held}
            if len(tasks) > 1:
                out["not_settled"] = INDICATOR_PROCESS_IN_TASKS.format(count=len(tasks))
                return out
            task = next(iter(tasks), "")
        listed = self._rows.get(ProcessKey(task, procid)) or []
        if not listed:
            # Said only where the task lists processes at all.
            if (task in self._listing) if task else bool(self._rows):
                out["not_listed"] = True
            return out
        if len(listed) > 1:
            out["not_settled"] = INDICATOR_PROCESS_TWICE.format(count=len(listed))
            return out
        from malspark.schemas.sandbox_document import (
            PROCESS_IMAGE_PATH_KEYS,
            PROCESS_NAME_KEYS,
        )
        from malspark.schemas.signature_indicators import INDICATOR_TEXT_CHARS
        from malspark.utils.written_forms import sample_written_out

        (proc,) = listed
        # The guest's pid, where the reader declares where a process row holds
        # it: ``id`` is the report's own id for the process.
        guest = self._guest_pid(proc)
        if guest:
            out["guest_pid"] = guest
        name = next(
            (
                str(proc[key])
                for key in (*PROCESS_NAME_KEYS, *PROCESS_IMAGE_PATH_KEYS)
                if isinstance(proc.get(key), str) and proc[key].strip()
            ),
            "",
        )
        image = re.split(r"[\\/]", name.strip().strip('"'))[-1]
        if image:
            cut = image[:INDICATOR_TEXT_CHARS] + ("…" if len(image) > INDICATOR_TEXT_CHARS else "")
            out["image"] = sample_written_out(cut)
        lineage = _launch_lineage(proc)
        if lineage:
            out[LINEAGE_KEY] = lineage
        if lineage == LINEAGE_SAMPLE or (
            not self._launched and not lineage and _marked_as_the_sample(proc)
        ):
            out["marked"] = True
        return out

    def _guest_pid(self, proc: dict[str, Any]) -> str | None:
        """The guest's pid a process row states, where the reader declares where; else ``None``."""
        from malspark.schemas.signature_indicators import held_at

        paths = self.fields.guest_pid if self.fields is not None else ()
        return next((pid for path in paths if (pid := pid_of(held_at(proc, path)))), None)

    def process_ids_of_guest(self, pid: str) -> list[str]:
        """The report's process ids of the processes whose guest's pid is ``pid``."""
        return self._identities.aliased(pid)

    def _stated(self, task: str, indicator: dict[str, Any], times: int) -> dict[str, Any]:
        """One indicator as the entry states it (:data:`INDICATOR_KEYS`): its processes resolved."""
        from malspark.utils.written_forms import sample_written_out

        out: dict[str, Any] = {}
        if task:
            out[INDICATOR_TASK] = sample_written_out(task)
        for key in (PROCESS, TARGET):
            if indicator.get(key):
                out[key] = self._process(indicator[key], task)
        for key in (EVENT, DESCRIPTION):
            if indicator.get(key):
                out[key] = sample_written_out(indicator[key])
        values = indicator.get(VALUES)
        if isinstance(values, dict) and values:
            # A field the reader declares states a process's guest pid is
            # printed with the process it resolved to where it is that
            # process's; any other number stays as stated.
            fields = self.fields
            printed = {
                name: str(out[key].get("guest_pid") or "")
                for key, names in (
                    (PROCESS, fields.process_guest_pid if fields is not None else ()),
                    (TARGET, fields.target_guest_pid if fields is not None else ()),
                )
                if isinstance(out.get(key), dict)
                for name in names
            }
            kept = {
                k: sample_written_out(v)
                for k, v in values.items()
                if not (printed.get(k) and pid_of(v) == printed[k])
            }
            if kept:
                out[VALUES] = {sample_written_out(k): v for k, v in kept.items()}
        if indicator.get(VALUES_LEFT_OUT):
            out[VALUES_LEFT_OUT] = indicator[VALUES_LEFT_OUT]
        cut = indicator.get(CHARS_LEFT_OUT)
        if isinstance(cut, dict) and cut:
            out[CHARS_LEFT_OUT] = {sample_written_out(k): n for k, n in cut.items()}
        if times > 1:
            out[INDICATOR_TIMES] = times
        return out

    def resolved(self, name: str) -> tuple[list[dict[str, Any]], list[int]]:
        """``name``'s indicators as the entry states them, in their order, and each one's ``times``.

        Each distinct indicator of a task once, the first time the report
        states it; then in the one order (:func:`indicator_rank`). Read once
        per name.
        """
        held = self._resolved.get(name)
        if held is not None:
            return held
        from malspark.schemas.signature_indicators import (
            held_neutral,
            indicator_key,
            indicator_rank,
            neutral_indicator,
        )

        fields = self.fields
        if fields is None:
            return [], []
        distinct: dict[str, list[Any]] = {}
        sources = [
            *(("", listed) for listed in self._own.get(name, ())),
            *self._task_rows.get(name, ()),
        ]
        for task, listed in sources:
            for raw in listed:
                indicator = held_neutral(raw) if fields.neutral else neutral_indicator(raw, fields)
                key = indicator_key(indicator, task)
                found = distinct.get(key)
                if found is not None:
                    found[2] += 1
                else:
                    distinct[key] = [task, indicator, 1]
        ordered = sorted(distinct.values(), key=lambda held: indicator_rank(held[1]))
        stated = [self._stated(task, indicator, times) for task, indicator, times in ordered]
        held = (stated, [times for _task, _indicator, times in ordered])
        self._resolved[name] = held
        return held

    def stated(self, name: str) -> int:
        """How many indicators the report states for ``name``, each repeat counted."""
        return sum(self.resolved(name)[1])

    @property
    def names(self) -> list[str]:
        """Every signature name the report states indicators under, in the report's order."""
        return self._names

    @property
    def task_only(self) -> list[str]:
        """The names only a task report's signatures state, which no signature row has."""
        # A task row is held only where it lists indicators, so each states some.
        return list(self._task_only)

    def process_ids(self, name: str) -> set[str]:
        """The report's ids of the processes ``name``'s indicators name, acting or acted on."""
        from malspark.schemas.signature_indicators import PROCESS, TARGET

        return {
            str(one[key]["id"])
            for one in self.resolved(name)[0]
            for key in (PROCESS, TARGET)
            if isinstance(one.get(key), dict)
        }

    def holds_text(self, name: str, needle: str) -> bool:
        """Whether one of ``name``'s indicators, as the entry states it, holds ``needle``."""
        return bool(needle) and any(_held_text(one, needle) for one in self.resolved(name)[0])

    def of_item(self, signature: Any) -> dict[str, Any]:
        """What the item reader's signature item gains: its first indicators and where the rest are.

        At most ``SIGNATURE_INDICATORS_SHOWN`` in the one order; the rest are
        counted, with the call and the offset that list them
        (``indicators_left_out``, ``indicators_read``). ``{}`` where none is stated.
        """
        if self.fields is None or not isinstance(signature, dict):
            return {}
        from malspark.schemas.signature_indicators import (
            SIGNATURE_INDICATORS_PAGE,
            SIGNATURE_INDICATORS_SHOWN,
        )

        name = _signature_name(signature)
        stated, times = self.resolved(name)
        if not stated:
            return {}
        shown = stated[:SIGNATURE_INDICATORS_SHOWN]
        out: dict[str, Any] = {"indicators_stated": sum(times), "indicators": shown}
        left = sum(times) - sum(times[: len(shown)])
        if left:
            out["indicators_left_out"] = {
                "signature": _written_name(name),
                "left_out": left,
                "offset": len(shown),
            }
            out["indicators_read"] = INDICATORS_READ.format(page=SIGNATURE_INDICATORS_PAGE)
        return out


def _signature_name(row: Mapping[str, Any]) -> str:
    """A signature row's name, as the view's row states it."""
    return str(row.get("name") or row.get("signature") or "")


def _written_name(name: str) -> str:
    """A signature's name as an indicator's entry states it: the report's text, written out."""
    from malspark.utils.written_forms import sample_written_out

    return sample_written_out(name)


def _with_indicators(
    answer: dict[str, Any], names: list[str], indicators: SignatureIndicators, room: int
) -> dict[str, Any]:
    """The rows' answer, then in the room the rows leave: the counts, the indicators, the rest.

    Nothing is added unless every row fits within ``room`` characters with
    the counts beside them: then the answer is the one without indicators.
    Otherwise ``indicators_stated`` maps each signature that states
    indicators to their count, and ``indicators`` lists them, each with its
    signature's name, in one order across the signatures — every process
    pairing first, then those naming one process, then the rest, each group
    by signature and then in the signature's own order — while the whole
    answer stays within ``room``, stopping at the first that does not fit:
    what a signature has listed is the head of its own order.
    ``indicators_left_out`` counts, per signature, the indicators past that
    head, with the offset the paged call (``indicators_read``) lists them
    from; where none is listed, each signature's count is what is left out.
    Linear in the page's indicators.
    """
    from malspark.schemas.signature_indicators import SIGNATURE_INDICATORS_PAGE, indicator_rank

    extras: dict[str, Any] = {
        "indicators_stated": {_written_name(name): indicators.stated(name) for name in names},
        "indicators_read": INDICATORS_READ.format(page=SIGNATURE_INDICATORS_PAGE),
    }
    if _size({**answer, **extras}) > room:
        return answer
    answer.update(extras)
    # Every signature's left-out count at its largest, so the counts are
    # known to fit before any indicator is placed.
    counts = sum(
        _size(
            {
                "signature": _written_name(name),
                "left_out": indicators.stated(name),
                "offset": len(indicators.resolved(name)[0]),
            }
        )
        for name in names
    )
    left = room - _size(answer) - counts - _size({"indicators": [], "indicators_left_out": []})
    listed: list[dict[str, Any]] = []
    head = dict.fromkeys(names, 0)
    # Set at the first indicator that does not fit: none after it is listed.
    full = False
    for rank in range(3):
        for name in names:
            if full:
                break
            stated = indicators.resolved(name)[0]
            at = head[name]
            while at < len(stated) and indicator_rank(stated[at]) == rank:
                item = {INDICATOR_SIGNATURE: _written_name(name), **stated[at]}
                cost = _size(item)
                if cost > left:
                    full = True
                    break
                listed.append(item)
                left -= cost
                at += 1
            head[name] = at
    if not listed:
        return answer
    # The platform's own keys of the answer, after its rows.
    answer.update(indicators=listed)
    rest = []
    for name in names:
        times = indicators.resolved(name)[1]
        past = sum(times[head[name] :])
        if past:
            rest.append({"signature": _written_name(name), "left_out": past, "offset": head[name]})
    if rest:
        answer["indicators_left_out"] = rest
    else:
        del answer["indicators_read"]
    return answer


def _indicator_page(
    indicators: SignatureIndicators,
    signature: Any,
    process: Any,
    contains: Any,
    offset: Any,
    room: int,
) -> dict[str, Any]:
    """The indicators a signature's name, a process id and a text keep, one page from ``offset``.

    In the report's order of signatures and each one's own order, every
    indicator the report states, each with its signature's name; a page is
    at most ``SIGNATURE_INDICATORS_PAGE`` of them and stays within ``room``
    characters (one at least), ``next_offset`` naming where the next starts.
    Linear in the report's indicators.
    """
    from malspark.schemas.signature_indicators import PROCESS, SIGNATURE_INDICATORS_PAGE, TARGET

    if indicators.fields is None:
        return {"indicators": [], "matched": 0, "no": INDICATORS_NONE_DECLARED}
    wanted = None
    if process not in (None, ""):
        # ``pid_of`` reads digits written with spaces around them.
        wanted = pid_of(process) or None
        if wanted is None:
            return {"error": INDICATORS_BAD_PROCESS}
    asked = str(signature or "").strip().casefold()
    needle = str(contains or "").lower()
    matched: list[dict[str, Any]] = []
    for name in indicators.names:
        written = _written_name(name)
        if asked and asked not in (name.strip().casefold(), written.strip().casefold()):
            continue
        for one in indicators.resolved(name)[0]:
            if wanted is not None and wanted not in {
                str(one[key].get("id"))
                for key in (PROCESS, TARGET)
                if isinstance(one.get(key), dict)
            }:
                continue
            item = {INDICATOR_SIGNATURE: written, **one}
            if needle and not _held_text(item, needle):
                continue
            matched.append(item)
    start = max(0, _count(offset))
    page: list[dict[str, Any]] = []
    answer: dict[str, Any] = {"indicators": page, "matched": len(matched), "offset": start}
    left = room - _size({**answer, "next_offset": len(matched)})
    for item in matched[start : start + SIGNATURE_INDICATORS_PAGE]:
        cost = _size(item)
        if page and cost > left:
            break
        page.append(item)
        left -= cost
    stop = start + len(page)
    if stop < len(matched):
        answer["next_offset"] = stop
    if wanted is not None and not matched:
        # An empty answer says why: no indicator names that process id, or
        # the number is a guest's pid, with the process id to ask with.
        ids = indicators.process_ids_of_guest(wanted)
        answer["no"] = (
            INDICATORS_GUEST_PID.format(asked=wanted, ids=", ".join(ids), first=ids[0])
            if ids
            else INDICATORS_NO_PROCESS.format(asked=wanted)
        )
    return answer


def sandbox_signatures(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
    signature: Any = "",
    process: Any = None,
    contains: Any = "",
    room: int | None = None,
) -> dict[str, Any]:
    """The sandbox's own signature hits, with their severity, and their indicators.

    Reported as what they are — one detection engine's opinion — not folded
    into the verdict. A sandbox signature firing is evidence the agent weighs
    alongside everything else it found. Each row lists at most
    :data:`SIGNATURE_PIDS_SHOWN` of the processes the hit was seen in. Where the
    reader declares its source states indicators, each signature's count and
    the indicators themselves, each process they name resolved to the
    report's own row (:class:`SignatureIndicators`), follow every row in the
    room the rows leave within ``room`` characters for the whole answer
    (``SIGNATURE_ANSWER_CHARS`` unless the caller holds a smaller one), and
    only there (:func:`_with_indicators`): the rows are the rows an answer
    without indicators gives, so no row is left out for them. A call naming a
    ``signature``, a ``process`` id or a text it ``contains`` answers the
    matching indicators instead, one page from ``offset``
    (:func:`_indicator_page`).
    """
    from malspark.schemas.signature_indicators import SIGNATURE_ANSWER_CHARS

    room = SIGNATURE_ANSWER_CHARS if room is None else max(0, min(room, SIGNATURE_ANSWER_CHARS))
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    signatures = place(report, "signatures")
    if not isinstance(signatures, list) or _absent_of(
        report, "signatures", normalised_by=normalised_by
    ):
        return _absent("signatures")
    if str(signature or "").strip() or process not in (None, "") or str(contains or ""):
        return _indicator_page(
            SignatureIndicators(report, normalised_by), signature, process, contains, offset, room
        )
    rows: list[dict[str, Any]] = []
    page, meta = _page(signatures, offset, limit)
    indicators = SignatureIndicators(report, normalised_by) if page else None
    named: dict[str, None] = {}
    if page:
        for sig in page:
            if not isinstance(sig, dict):
                continue
            row = {
                "name": sig.get("name") or sig.get("signature") or "",
                "description": sig.get("description") or "",
                "severity": sig.get("severity"),
                "confidence": sig.get("confidence"),
                "references": list(sig.get("references") or [])[:5],
            }
            # The technique ids the sandbox itself tags the signature with, as
            # its report declares them, under the key the tool's declaration
            # reads technique ids from (``technique_ids``). Left out where the
            # sandbox declares none, so an answer without tags is as it was.
            tags = _signature_techniques(sig)
            if tags:
                row["technique_ids"] = tags
            # The processes the hit was seen in, by the pids its marks name
            # (``schemas.sandbox_document.signature_pids``): what places a
            # behaviour in one process of the tree. Left out where none is
            # named, so such an answer is as it was. Past the cap the list is
            # cut and ``pids_total`` says how many there are.
            pids = signature_pids(sig)
            if pids:
                if len(pids) > SIGNATURE_PIDS_SHOWN:
                    row["pids_total"] = len(pids)
                    pids = pids[:SIGNATURE_PIDS_SHOWN]
                row["pids"] = pids
            # The row is the row it always was: what the hit's indicators say
            # follows every row, where the room allows (:func:`_with_indicators`).
            if indicators is not None and indicators.stated(_signature_name(sig)):
                named[_signature_name(sig)] = None
            rows.append(row)
    answer: dict[str, Any] = {"signatures": rows, "total": len(signatures), **meta}
    if indicators is not None and "next_offset" not in meta:
        # A signature only a task report lists has no row: on the page that
        # ends the rows it is announced after them, as the room allows.
        named.update(dict.fromkeys(indicators.task_only))
    if indicators is None or not named:
        return answer
    return _with_indicators(answer, list(named), indicators, room)


def sandbox_dropped_files(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Files the sample wrote, with the hashes the sandbox computed for them."""
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    dropped = place(report, "dropped_files")
    if not isinstance(dropped, list):
        # A document written before the parts were declared named the list so.
        dropped = report.get("dropped_files")
    if (
        not isinstance(dropped, list)
        or {"dropped_files", "dropped"} & _unavailable(report)
        or "dropped_files" not in (_fills(normalised_by) or {"dropped_files"})
    ):
        return _absent("dropped_files")
    # The archive's members a generated launcher's run unpacked in the guest,
    # and the files the launcher's own process wrote or dumped
    # (``sandbox_report.attribute_the_launcher``): the platform's files, never
    # files the sample wrote, listed apart with which file each is. Every row
    # is in one of the two lists.
    platform: list[dict[str, Any]] = []
    written: list[Any] = []
    for entry in dropped:
        if isinstance(entry, dict) and entry.get(LINEAGE_KEY) == LINEAGE_LAUNCHER:
            platform.append(entry)
        else:
            written.append(entry)
    dropped = written
    rows: list[dict[str, Any]] = []
    guest = _guest_path_fields(normalised_by)
    reading = _reading(normalised_by)

    def _path(entry: dict[str, Any]) -> Any:
        # A path field the reader declares the guest's; never one it does not.
        declared = next((entry[f] for f in guest if entry.get(f)), "")
        return entry.get("filepath") or entry.get("guest_paths") or declared

    page, meta = _page(dropped, offset, limit)
    if page:
        for entry in page:
            if not isinstance(entry, dict):
                continue
            row = {
                "name": entry.get("name") or entry.get("filepath") or "",
                "path": _path(entry),
                "size": dropped_size(entry, reading),
                "sha256": entry.get("sha256"),
                "type": entry.get("type"),
            }
            # What the row says the file is and where it came from, where it says.
            for key in _DROPPED_FACT_KEYS:
                if entry.get(key) not in (None, ""):
                    row[key] = entry[key]
            # The processes the sandbox says wrote the file, where it says:
            # which tree wrote it is what makes the file the sample's.
            row.update(_writer(entry, reading))
            if entry.get(LINEAGE_KEY):
                row[LINEAGE_KEY] = entry[LINEAGE_KEY]
                if entry.get(LINEAGE_REASON_KEY):
                    row[LINEAGE_REASON_KEY] = entry[LINEAGE_REASON_KEY]
            # A file the sample wrote that holds an archive member's digest
            # away from its place, or sits at its place changed: said so.
            if isinstance(entry.get(MEMBER_FACT_KEY), dict):
                row[MEMBER_FACT_KEY] = entry[MEMBER_FACT_KEY]
            rows.append(row)
    answer: dict[str, Any] = {"dropped": rows, "total": len(dropped), **meta}
    if platform:
        answer["platform_files"] = [
            {
                "name": entry.get("name") or entry.get("filepath") or "",
                "path": _path(entry),
                "sha256": entry.get("sha256"),
                LINEAGE_KEY: entry.get(LINEAGE_KEY),
                LINEAGE_REASON_KEY: entry.get(LINEAGE_REASON_KEY) or "",
                # The process that wrote it, where the sandbox names one: a
                # file the launcher's process wrote is listed with its writer.
                **_writer(entry, reading),
            }
            for entry in platform
        ]
    return answer


# What a dropped file's row states it is (a written file, a dumped region) and
# where it came from, kept as the row states it.
_DROPPED_FACT_KEYS = ("kind", "origin")


def _writer(entry: dict[str, Any], reading: Any) -> dict[str, Any]:
    """The process a dropped-file record names as its writer: ``pids``, ``task``, ``guest_pid``.

    The writer's ids are read from every field the job's reader declares
    holds one, else the generic fields
    (``schemas.sandbox_report.dropped_writer``); the task the reader listed
    the row in, and the guest's pid of the writer where the reader declares
    the field that holds it and it is another number, stand beside them: one
    process identity (``schemas.process_identity``). ``{}`` for a row naming
    no writer.
    """
    from malspark.schemas.sandbox_report import dropped_writer

    pids, guest = dropped_writer(entry, reading)
    if not pids:
        return {}
    out: dict[str, Any] = {"pids": pids}
    task = entry.get(PROCESS_TASK_KEY)
    if task:
        out["task"] = str(task)
    if guest:
        out["guest_pid"] = guest
    return out


# Registry APIs, and what each one does to the key it names. A call the table
# does not know is still reported, as ``access`` — the key it touched is the
# fact, and guessing the verb would be worse than saying the honest word.
_REGISTRY_OPS: dict[str, str] = {
    "regsetvalueexa": "modify",
    "regsetvalueexw": "modify",
    "ntsetvaluekey": "modify",
    "regcreatekeyexa": "create",
    "regcreatekeyexw": "create",
    "ntcreatekey": "create",
    "regdeletekeya": "delete",
    "regdeletekeyw": "delete",
    "regdeletekeyexa": "delete",
    "regdeletekeyexw": "delete",
    "regdeletevaluea": "delete",
    "regdeletevaluew": "delete",
    "ntdeletekey": "delete",
    "ntdeletevaluekey": "delete",
    "regqueryvalueexa": "query",
    "regqueryvalueexw": "query",
    "ntqueryvaluekey": "query",
    "regopenkeyexa": "query",
    "regopenkeyexw": "query",
    "ntopenkey": "query",
    "ntopenkeyex": "query",
}

# What a call says it did, where the operation its API names is only what it
# may do: for each such operation, the argument the outcome is filed under and
# what each recorded value means. A create call opens the key when it already
# exists and says so in its disposition (1 created a new key, 2 opened an
# existing one), and a key only opened was read, not created. A call that
# records no outcome, or one this table does not know, keeps its API's
# operation.
_REGISTRY_OUTCOMES: dict[str, tuple[str, dict[int, str]]] = {
    "create": ("Disposition", {1: "create", 2: "query"}),
}

# A write the call itself reports as failed (``status`` false) changed
# nothing: the key was reached and that is all, so it is recorded as bare
# access, which any read or write of the key replaces.
_FAILED_WRITE = "access"

# What one operation on a key says, against another on the same key: the bare
# fact of access least, a read more, a write most.
_REGISTRY_OP_WEIGHT: dict[str, int] = {
    "access": 0,
    "query": 1,
    "create": 2,
    "modify": 2,
    "delete": 2,
}

# The argument names each reader takes its value from, most wanted first: a
# call's own argument order never decides. A registry key is a full path before
# a subkey and a subkey before the bare hive handle (``Registry``), which is
# the key only for a call that names nothing else; a value is what was written
# or, for a query, what was read (``Data``, or ``Information`` for the native
# value query); a value's name is what a write names the value it wrote under;
# a service is its name, under either spelling, before its display name or the
# binary it runs.
_REGISTRY_KEY_ARGS = ("FullName", "KeyName", "ObjectAttributes", "SubKey", "Registry")
_REGISTRY_VALUE_ARGS = ("Buffer", "Data", "ValueData", "Value", "Information")
_REGISTRY_VALUE_NAME_ARGS = ("ValueName", "lpValueName")
# The operations that change one value, whose row is the value's own.
_VALUE_OPERATIONS = frozenset({"create", "modify", "delete"})
_MUTEX_APIS = frozenset({"ntcreatemutant", "ntopenmutant", "createmutexa", "createmutexw"})
# The mutex APIs that create one: only a creation names the process that made
# the mutex. An open, or a create that found the mutex already there, names a
# process that used someone's mutex.
_MUTEX_CREATE_APIS = frozenset({"ntcreatemutant", "createmutexa", "createmutexw"})
# What a create says when the object already existed: the native status
# STATUS_OBJECT_NAME_EXISTS as its return, and ERROR_ALREADY_EXISTS as the
# Win32 call's last error, by number or by name.
_NT_NAME_EXISTS = 0x40000000
_WIN32_ALREADY_EXISTS = 183
_EXISTED_WORDS = ("OBJECT_NAME_EXISTS", "ALREADY_EXISTS")
_LAST_ERROR_KEYS = ("last_error", "lasterror", "LastError")
_MUTEX_ARGS = ("MutexName", "lpName", "ObjectAttributes", "Name")
_SERVICE_APIS = frozenset({"createservicea", "createservicew", "startservicea", "startservicew"})
_SERVICE_ARGS = ("ServiceName", "lpServiceName", "DisplayName", "BinaryPathName")


def _calls(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Every API call the report recorded, however it filed them.

    A report may carry a flat call list and also one list per process; a
    report that has both would double-count, so the flat list wins when it is
    there.
    """
    flat = place(report, "calls")
    if isinstance(flat, list) and flat:
        return [row for row in flat if isinstance(row, dict)]
    out: list[dict[str, Any]] = []
    for proc in _list_at(report, "processes") or []:
        if isinstance(proc, dict):
            out.extend(row for row in (proc.get("calls") or []) if isinstance(row, dict))
    return out


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _argument(call: dict[str, Any], names: tuple[str, ...]) -> str:
    """The text of the first of ``names``, in that order, this call carries.

    Whichever shape the call filed its arguments in; see ``call_arguments``.
    """
    value = pick_argument(call.get("arguments"), names, accept=_text)
    return value.strip() if isinstance(value, str) else ""


def _summary_list(report: dict[str, Any], name: str) -> list[str]:
    """The text entries of the behaviour summary's part ``name``."""
    values = place(report, name)
    return [str(v) for v in values if isinstance(v, str)] if isinstance(values, list) else []


def _registry_operation(call: dict[str, Any], operation: str) -> str:
    """What ``call`` did to its key: its API's operation, as the call's own outcome refines it."""
    if operation != "query" and call.get("status") is False:
        return _FAILED_WRITE
    outcome = _REGISTRY_OUTCOMES.get(operation)
    if outcome is None:
        return operation
    name, meanings = outcome
    code = _outcome_code(pick_argument(call.get("arguments"), (name,)))
    return operation if code is None else meanings.get(code, operation)


def _outcome_code(recorded: Any) -> int | None:
    """An outcome a call recorded, as the number it is: filed as an integer or as text.

    Text is read as written, a ``0x`` prefix as hexadecimal and leading zeros
    as decimal (``"02"`` is 2); anything else is no outcome.
    """
    if isinstance(recorded, bool):
        return None
    if isinstance(recorded, int):
        return recorded
    if not isinstance(recorded, str):
        return None
    text = recorded.strip()
    for base in (0, 10):
        try:
            return int(text, base)
        except ValueError:
            continue
    return None


def sandbox_registry_ops(
    report: dict[str, Any] | None,
    limit: int = 0,
    offset: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Registry keys the sample touched, with the operation and the value written.

    Two sources, because sandboxes fill them unevenly: the behaviour summary's
    key list, which says a key was touched and nothing else, and the registry
    API calls themselves, which say what was done and what was written. The
    call wins where both name the same key — an operation is worth more than
    the bare fact of access — and for the same reason a read never replaces a
    write: a key created, modified or deleted and then read stays the write,
    with what was written, and a read that saw no value leaves an earlier
    read's value standing. Between writes the later one in the report's order
    stands; that order is the report's process by process, not time. A row
    is a key and the value an operation names: two values written to one
    key are a row each, with the value's name, what was done to it and the
    pids of the calls that did it; a delete of one value is that value's
    row; an operation that names no value is the key's own row, which a read
    leaves out beside a value's write.

    A call's own outcome refines what its API may do (``_REGISTRY_OUTCOMES``):
    a create that opened an existing key is a read. A write the call reports as
    failed is bare access, without the value it did not write.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    missing = _absent_of(report, "registry", "calls", normalised_by=normalised_by)
    if missing is not None:
        return missing
    # Each key's rows, by the name of the value an operation names (``""``
    # for one that names none), in the order first met.
    rows: dict[str, dict[str, dict[str, Any]]] = {}
    # The pids of the calls behind each row's operation: a row names the
    # processes that did what it says, where the report kept the pid.
    pids: dict[tuple[str, str, str], set[str]] = {}
    summary_only: set[str] = set()
    for key in _summary_list(report, "registry"):
        if key not in rows:
            rows[key] = {"": {"key": key, "operation": "access", "value": None}}
            summary_only.add(key)
    for pid, call in _calls_by_process(report):
        api = str(call.get("api") or "")
        # Zw* and Nt* are the same native call; the table lists the Nt name.
        name = api.lower()
        if name.startswith("zw"):
            name = "nt" + name[2:]
        listed = _REGISTRY_OPS.get(name)
        if listed is None:
            continue
        key = _argument(call, _REGISTRY_KEY_ARGS)
        if not key:
            continue
        operation = _registry_operation(call, listed)
        value = _argument(call, _REGISTRY_VALUE_ARGS) or None
        if operation == _FAILED_WRITE:
            value = None
        # A write or a delete names the value it changed, where the call
        # carries the name: that value's own row.
        named = _argument(call, _REGISTRY_VALUE_NAME_ARGS) if operation in _VALUE_OPERATIONS else ""
        if key in summary_only:
            # The call wins over the summary's bare fact of access.
            summary_only.discard(key)
            rows[key] = {}
        own = rows.setdefault(key, {})
        if pid:
            pids.setdefault((key, named, operation), set()).add(pid)
        before = own.get(named)
        if before is not None:
            if _REGISTRY_OP_WEIGHT[operation] < _REGISTRY_OP_WEIGHT[before["operation"]]:
                continue
            if operation == before["operation"] == "query" and value is None:
                continue
        own[named] = {"key": key, "operation": operation, "value": value}
        if named:
            own[named]["value_name"] = named
    ordered = []
    for key, own in rows.items():
        # A read that names no value says nothing beside a value's write.
        most = max(_REGISTRY_OP_WEIGHT[row["operation"]] for row in own.values())
        for named, row in own.items():
            if not named and len(own) > 1 and _REGISTRY_OP_WEIGHT[row["operation"]] < most:
                continue
            made_by = pids.get((key, named, row["operation"]))
            ordered.append({**row, "pids": sorted(made_by)} if made_by else row)
    page, meta = _page(ordered, offset, limit)
    return {"registry": page, "total": len(ordered), **meta}


# How many of an API's calling processes one row names, in name order.
_CALLERS_PER_API = 8
# How much of one call's arguments a row quotes; a longer one ends in the cut mark.
_FIRST_ARGS_CHARS = 400


def _calls_by_process(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Every API call with the pid that made it, ``""`` when the report lost it.

    The same walk as :func:`_calls`, keeping the process each nested list
    belongs to; a flat call list carries its pid on the row or not at all.
    """
    flat = place(report, "calls")
    if isinstance(flat, list) and flat:
        return [(str(row.get("pid") or ""), row) for row in flat if isinstance(row, dict)]
    out: list[tuple[str, dict[str, Any]]] = []
    for proc in _list_at(report, "processes") or []:
        if isinstance(proc, dict):
            pid = str(proc.get("pid") or "")
            out.extend((pid, row) for row in (proc.get("calls") or []) if isinstance(row, dict))
    return out


def sandbox_api_calls(
    report: dict[str, Any] | None,
    process: str | None = None,
    name: str | None = None,
    limit: int = 0,
    offset: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """The API-call histogram, with the first call of each API.

    The call stream itself is where a behaviour report's bulk is, so what comes
    back is one row per API rather than one per call: the name, the module the
    sandbox resolved it from when it recorded one, the first eight processes
    that made it by name, how often, and the arguments and time of the first
    call, which is usually the one that says what the sample was after.
    ``process`` narrows by pid or process name, ``name`` by a substring of the
    API name.

    What the sandbox recorded and nothing else. The rows used to carry a
    behaviour category and a suspicious flag copied from the import table,
    which was this tool doing the analysis; what an API is used for is the
    knowledge server's ``api_capability`` question, asked when the model
    decides the answer matters.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    missing = _absent_of(report, "apistats", "calls", normalised_by=normalised_by)
    if missing is not None:
        return missing

    names_by_pid = {
        str(proc.get("pid")): str(proc.get("process_name") or proc.get("name") or "")
        for proc in _list_at(report, "processes") or []
        if isinstance(proc, dict)
    }
    wanted_process = (process or "").strip().lower()
    wanted_name = (name or "").strip().lower()

    def _is_wanted(pid: str) -> bool:
        if not wanted_process:
            return True
        return wanted_process in {pid.lower(), names_by_pid.get(pid, "").lower()}

    def _label(pid: str) -> str:
        return names_by_pid.get(pid) or pid

    counts: dict[str, int] = {}
    callers: dict[str, set[str]] = {}
    apistats = place(report, "apistats")
    if isinstance(apistats, dict):
        for pid, stats in apistats.items():
            if not _is_wanted(str(pid)) or not isinstance(stats, dict):
                continue
            for api, count in stats.items():
                try:
                    counts[str(api)] = counts.get(str(api), 0) + int(count)
                except (TypeError, ValueError):
                    continue
                if _label(str(pid)):
                    callers.setdefault(str(api), set()).add(_label(str(pid)))

    first_call: dict[str, dict[str, Any]] = {}
    left_out = 0
    for pid, call in _calls_by_process(report):
        api = str(call.get("api") or "")
        if api and not pid and wanted_process:
            left_out += 1
        # With a process asked for, a call the report gave no pid cannot be
        # said to be that process's: it is left out rather than listed under it.
        if not api or (not pid and wanted_process) or (pid and not _is_wanted(pid)):
            continue
        counts.setdefault(api, 0)
        if pid and _label(pid):
            callers.setdefault(api, set()).add(_label(pid))
        if api not in first_call:
            first_call[api] = call

    rows: list[dict[str, Any]] = []
    for api, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        if wanted_name and wanted_name not in api.lower():
            continue
        call = first_call.get(api, {})
        arguments = call.get("arguments")
        module = call.get("dll") or call.get("module")
        seen = call.get("timestamp") or call.get("time")
        rows.append(
            {
                "api": api,
                "dll": str(module) if module else None,
                "processes": sorted(callers.get(api, set()))[:_CALLERS_PER_API],
                # How many processes called it, beside the few named.
                "process_count": len(callers.get(api, set())),
                "count": count,
                "first_args": marked_cut(str(arguments), _FIRST_ARGS_CHARS) if arguments else "",
                "first_seen": str(seen) if seen not in (None, "") else None,
            }
        )
    page, meta = _page(rows, offset, limit)
    answer: dict[str, Any] = {"apis": page, "total": len(rows), **meta}
    if left_out:
        # Said, not dropped: these calls may be the asked process's.
        answer["left_out_without_pid"] = left_out
    return answer


def _created_the_mutex(call: dict[str, Any]) -> bool:
    """Whether a mutex call created its mutex: a create API whose recorded status says so.

    A create the call says found the mutex already there opened it, and one
    it says failed made nothing. A call that records no status is taken at its
    API's word.
    """
    api = str(call.get("api") or "").lower()
    if api not in _MUTEX_CREATE_APIS or call.get("status") is False:
        return False
    said = [call.get("pretty_return"), *(call.get(key) for key in _LAST_ERROR_KEYS)]
    if api.startswith("nt"):
        said.append(call.get("return"))
        if _outcome_code(call.get("return")) == _NT_NAME_EXISTS:
            return False
    elif any(_outcome_code(call.get(key)) == _WIN32_ALREADY_EXISTS for key in _LAST_ERROR_KEYS):
        return False
    return not any(
        word in str(value).upper() for value in said if value is not None for word in _EXISTED_WORDS
    )


def sandbox_mutexes(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """The named mutexes the sample created or opened.

    A mutex name is often the one durable string a family carries across
    builds, which is why it gets a tool of its own rather than a filter over
    the call stream.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    missing = _absent_of(report, "summary.mutexes", "calls", normalised_by=normalised_by)
    if missing is not None:
        return missing
    names: list[str] = list(_summary_list(report, "summary.mutexes"))
    pids: dict[str, set[str]] = {}
    for pid, call in _calls_by_process(report):
        if str(call.get("api") or "").lower() not in _MUTEX_APIS:
            continue
        name = _argument(call, _MUTEX_ARGS)
        if name and name not in names:
            names.append(name)
        if name and pid and _created_the_mutex(call):
            pids.setdefault(name, set()).add(pid)
    page, meta = _page(names, offset, limit)
    answer: dict[str, Any] = {"mutexes": page, "total": len(names), **meta}
    # The processes whose calls named each mutex, where the report kept the
    # pid; a name only the summary lists has none.
    by_name = {name: sorted(pids[name]) for name in page if name in pids}
    if by_name:
        answer["pids"] = by_name
    return answer


def sandbox_services_and_tasks(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Services installed or started, scheduled tasks, and the commands run.

    Three answers in one call because they are one question — what did the
    sample arrange to happen again — and an agent that had to make three calls
    to ask it would routinely make one and miss the other two.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    missing = _absent_of(
        report,
        "summary.created_services",
        "summary.started_services",
        "summary.executed_commands",
        "calls",
        normalised_by=normalised_by,
    )
    if missing is not None:
        return missing
    services: list[str] = [
        *_summary_list(report, "summary.created_services"),
        *_summary_list(report, "summary.started_services"),
    ]
    commands: list[str] = list(_summary_list(report, "summary.executed_commands"))
    tasks: list[str] = [cmd for cmd in commands if "schtasks" in cmd.lower()]
    for call in _calls(report):
        api = str(call.get("api") or "").lower()
        if api in _SERVICE_APIS:
            name = _argument(call, _SERVICE_ARGS)
            if name and name not in services:
                services.append(name)
    deduped_services = list(dict.fromkeys(services))
    out: dict[str, Any] = {"total": len(deduped_services) + len(tasks) + len(commands)}
    for key, rows in (("services", deduped_services), ("tasks", tasks), ("commands", commands)):
        page, meta = _page(rows, offset, limit)
        out[key] = page
        if meta:
            out[f"{key}_total"] = len(rows)
            if "next_offset" in meta:
                out[f"{key}_next_offset"] = meta["next_offset"]
    return out


def sandbox_channels(
    report: dict[str, Any] | None, name: str = "", offset: int = 0, limit: int = 0
) -> dict[str, Any]:
    """The platform-namespaced channels a non-Windows guest publishes.

    ``android.permissions``, ``linux.systemd``, ``macos.launchd`` and whatever
    else a sandbox has to say that the report's other parts have no home for.
    Called with no name it lists what exists, which is how an agent discovers a
    channel it did not know to ask for.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    channels = place(report, "channels")
    if not isinstance(channels, dict):
        return {"channels": [], "rows": []}
    available = sorted(str(k) for k in channels)
    key = str(name).strip()
    if not key:
        return {"channels": available, "rows": []}
    if key not in channels:
        return {"error": f"no channel {key!r}", "channels": available}
    from malspark.schemas.sandbox_document import channel_rows

    # A kept block's items are each a row, built only for the page asked.
    rows = channel_rows(channels[key]) or []
    page, meta = _page(rows, offset, limit)
    return {"channel": key, "rows": page, "total": len(rows), **meta}


def sandbox_items(
    report: dict[str, Any] | None,
    section: str,
    pid: Any = None,
    contains: str = "",
    signature: str = "",
    ids: list[str] | str | None = None,
    *,
    sections: Any = None,
    normalised_by: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """The items of one section of the report, whole, each with its id and its report fields.

    Read-only over the report the job holds (``analysis.sandbox_sections``):
    no sandbox is asked anything. The filters combine; with none, every item
    of the section is answered. ``matched`` is how many items the filters
    keep, so an answer the guardrail shortens still says how many there are,
    and ``ids_not_read`` how many asked ids past the section's own size were
    not read. Nothing is summarised, ranked or labelled. ``sections`` is the
    report read once for the job (``items_tool`` holds it); without it the
    report is read for this call, as ``normalised_by`` produced it.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    from malspark.analysis.sandbox_sections import (
        NO_PID_ROWS,
        SECTION_PREFIXES,
        Sections,
        pid_of,
    )

    name = str(section or "").strip().lower()
    if name not in SECTION_PREFIXES:
        return {"error": ITEMS_NO_SECTION, "sections": list(SECTION_PREFIXES)}
    found = sections if isinstance(sections, Sections) else Sections(report, normalised_by)
    held = found.sections[name]
    if held.no:
        return {"section": name, "no": held.no}
    wanted_pid = None
    if pid not in (None, ""):
        if not found.names_processes(name):
            return {"section": name, "no": NO_PID_ROWS.format(section=name)}
        wanted_pid = pid_of(pid.strip() if isinstance(pid, str) else pid)
        if wanted_pid is None:
            return {"error": ITEMS_BAD_PID, "section": name}
    if str(signature or "").strip() and name != "signatures":
        return {"error": ITEMS_SIGNATURE_SECTION, "section": name}
    listed = re.split(r"[\s,;]+", ids) if isinstance(ids, str) else ids
    asked = [i for i in listed if i] if isinstance(listed, list) else []
    kept = found.query(
        name,
        pid=wanted_pid,
        contains=str(contains or ""),
        signature=str(signature or ""),
        ids=asked,
    )
    answer: dict[str, Any] = {"section": name, "matched": len(kept.items), "items": kept.items}
    if kept.missing:
        answer["not_in_section"] = kept.missing
    if kept.missing_more:
        answer["more_not_in_section"] = kept.missing_more
    if kept.not_read:
        answer["ids_not_read"] = kept.not_read
    return answer


# What ``sandbox_items`` answers for an argument it cannot read.
ITEMS_NO_SECTION = "no such section in the sandbox report; the sections are listed"
ITEMS_BAD_PID = "pid is not a process id in digits"
ITEMS_SIGNATURE_SECTION = "the signature filter reads the signatures section only"

# The arguments that narrow a ``sandbox_items`` answer, named in the notice a
# shortened answer carries.
_ITEM_FILTERS = ("pid", "contains", "signature", "ids")


# The views of a detonation's report the source offers beside the item reader,
# by the tool each is offered as, in the order :func:`sandbox_tools` builds
# them. Every one is read through :func:`read_view`.
_VIEWS: dict[str, Callable[..., dict[str, Any]]] = {
    "sandbox_report_section": sandbox_report_section,
    "sandbox_processes": sandbox_processes,
    "sandbox_network": sandbox_network,
    "sandbox_signatures": sandbox_signatures,
    "sandbox_dropped_files": sandbox_dropped_files,
    "sandbox_registry_ops": sandbox_registry_ops,
    "sandbox_api_calls": sandbox_api_calls,
    "sandbox_mutexes": sandbox_mutexes,
    "sandbox_services_and_tasks": sandbox_services_and_tasks,
    "sandbox_channels": sandbox_channels,
}
# The views whose answer no reader's declaration shapes: they take none.
_UNDECLARED_VIEWS = frozenset({"sandbox_report_section", "sandbox_channels"})

_VIEW_READERS: tuple[str, ...] = tuple(_VIEWS)


def read_view(
    tool: str,
    report: dict[str, Any] | None,
    normalised_by: Sequence[str] | None,
    /,
    *args: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    """``tool``'s view of ``report``, read with the reader that built the report.

    The one way a view is read: the pack, the read of a later detonation and
    an analyst's call each come here. ``normalised_by`` is that reader
    (``normalised_by_of``, ``DetonationRecord.normalised_by``), ``None`` where
    the run states none, and it is required: the reader's declaration says
    what a row's fields mean (``Reading``), and a read without it states
    another row for the same record.
    """
    view = _VIEWS[tool]
    if tool in _UNDECLARED_VIEWS:
        return view(report, *args, **kwargs)
    return view(report, *args, normalised_by=normalised_by, **kwargs)


def network_view(
    report: dict[str, Any] | None, normalised_by: Sequence[str] | None, /
) -> dict[str, Any]:
    """The whole network view of ``report``, read through :func:`read_view`.

    For a reader that holds a report and reads it as no tool's call (the
    report's network block), so it names no tool to read it.
    """
    return read_view("sandbox_network", report, normalised_by)


# Every tool of this source that reads a detonation, each taking the
# ``detonation`` selector; ``request_detonation`` asks for one and reads none.
DETONATION_READERS: tuple[str, ...] = (*_VIEW_READERS, ITEMS_TOOL)

# What every reader says of its ``detonation`` argument, in its description.
_DETONATION_ARG = (
    "``detonation`` names a later detonation of the sample to read (d2, d3 and "
    "so on, as the pack's index and request_detonation name them); empty reads "
    "the job's own detonation (d1)."
)


def sandbox_tools(container: Any, agent: str | None = None) -> list[BaseTool]:
    """The sandbox tools, each closed over this job's report.

    Built per resolution rather than once per process: the report is the job's,
    and a tool cached across jobs would answer the previous sample's questions.
    Each reader takes an optional ``detonation`` selector: empty (or ``d1``)
    reads the job's own detonation, the report this closure holds; a later
    one (``d2``…) is read from ``container.detonations`` at the call, so a
    detonation carried out after the agent was built is readable by it. The
    selector is one of the call's arguments, so the ledger records which
    detonation a read was of, and a read of one detonation is never served
    from a read of another.
    """
    from langchain_core.tools import StructuredTool

    report = _report_of(container)
    normalised_by = normalised_by_of(container)

    def _views(tool: str, detonation: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """``tool``'s view of the report ``detonation`` selects; a later one's answer names it."""
        later, problem = selected(container, detonation)
        if problem:
            return {"error": problem, "tool": "sandbox"}
        if later is None:
            return read_view(tool, report, normalised_by, *args, **kwargs)
        answer = read_view(tool, later.report, later.normalised_by, *args, **kwargs)
        return {**later.stated(), **answer} if isinstance(answer, dict) else answer

    def _report_section(
        section: str, offset: int = 0, limit: int = 0, detonation: str = ""
    ) -> dict[str, Any]:
        """Read one top-level section of the sandbox report by name.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_report_section", detonation, section, offset, limit)

    def _processes(offset: int = 0, limit: int = 0, detonation: str = "") -> dict[str, Any]:
        """List the processes the sandbox observed, with their command lines.

        A row marked ``staged_by_sandbox`` is where the sandbox started the submitted file from.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_processes", detonation, offset, limit)

    def _network(offset: int = 0, limit: int = 0, detonation: str = "") -> dict[str, Any]:
        """List the DNS lookups, hosts, HTTP requests and endpoints observed.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_network", detonation, offset, limit)

    def _signatures(
        offset: int = 0,
        limit: int = 0,
        signature: str = "",
        process: str = "",
        contains: str = "",
        detonation: str = "",
    ) -> dict[str, Any]:
        """List the sandbox's own signature hits and their severity, then their indicators.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset. A signature's indicators say which
        process did what to which. Where the answer has room after every row,
        ``indicators_stated`` maps each signature to how many the report
        states, as many indicators as fit follow in ``indicators``, and
        ``indicators_left_out`` says how many of each signature's are not
        listed and from which offset; otherwise the answer is the rows alone.
        ``signature`` (a name), ``process`` (the report's process id, acting or acted on)
        or ``contains`` (a text) lists the matching indicators instead, {page}
        per call from ``offset``, ``next_offset`` naming the next page.
        """
        return _views(
            "sandbox_signatures",
            detonation,
            offset,
            limit,
            signature=signature,
            process=process,
            contains=contains,
            room=_answer_room(sizer),
        )

    def _dropped_files(offset: int = 0, limit: int = 0, detonation: str = "") -> dict[str, Any]:
        """List the files the sample wrote, with their hashes.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_dropped_files", detonation, offset, limit)

    def _channels(
        name: str = "", offset: int = 0, limit: int = 0, detonation: str = ""
    ) -> dict[str, Any]:
        """List the platform channels, or read one of them by name.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_channels", detonation, name, offset, limit)

    def _registry_ops(offset: int = 0, limit: int = 0, detonation: str = "") -> dict[str, Any]:
        """List the registry keys the sample touched, with what it did to each.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_registry_ops", detonation, limit, offset)

    def _api_calls(
        process: str = "", name: str = "", offset: int = 0, limit: int = 0, detonation: str = ""
    ) -> dict[str, Any]:
        """List the API calls observed, by frequency, with each API's first call.

        ``process`` narrows to one pid or process name, ``name`` to APIs whose
        name contains the text. Rows carry what the sandbox recorded; ask
        api_capability what an API is used for.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_api_calls", detonation, process or None, name or None, limit, offset)

    def _mutexes(offset: int = 0, limit: int = 0, detonation: str = "") -> dict[str, Any]:
        """List the named mutexes the sample created or opened.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_mutexes", detonation, offset, limit)

    def _services_and_tasks(
        offset: int = 0, limit: int = 0, detonation: str = ""
    ) -> dict[str, Any]:
        """List services installed or started, scheduled tasks, and commands run.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return _views("sandbox_services_and_tasks", detonation, offset, limit)

    sizer = _answer_sizer(container)
    return [
        *(
            StructuredTool.from_function(
                func=_sized(func, sizer),
                name=name,
                description=f"{_paged(_described(func))}\n\n{_DETONATION_ARG}",
            )
            for func, name in zip(
                (
                    _report_section,
                    _processes,
                    _network,
                    _signatures,
                    _dropped_files,
                    _registry_ops,
                    _api_calls,
                    _mutexes,
                    _services_and_tasks,
                    _channels,
                ),
                _VIEW_READERS,
                strict=True,
            )
        ),
        items_tool(report, sizer, normalised_by, container=container),
        *_request_tools(container, agent),
    ]


def _request_tools(container: Any, agent: str | None = None) -> list[BaseTool]:
    """The ``request_detonation`` tool, where the job can carry ``agent``'s request out."""
    from malspark.providers.detonation_requests import offered, request_tool

    return [request_tool(container)] if offered(container, agent) else []


def _paged(description: str) -> str:
    """``description`` with the declared page of the indicator call in place of ``{page}``."""
    from malspark.schemas.signature_indicators import SIGNATURE_INDICATORS_PAGE

    return description.replace("{page}", str(SIGNATURE_INDICATORS_PAGE))


def _described(func: Any) -> str:
    """``func``'s docstring as a tool description, read as LangChain reads one it is not given."""
    import textwrap

    return textwrap.dedent(func.__doc__ or "").strip()


def normalised_by_of(container: Any) -> tuple[str, ...] | None:
    """``(provider, source_format, read_from)`` of the reader behind the job's report, if said."""
    value = getattr(container, "sandbox_normalised", None)
    if isinstance(value, tuple) and len(value) in (2, 3):
        return tuple(str(part) for part in value)
    return None


def items_tool(
    report: dict[str, Any] | None,
    sizer: Any = None,
    normalised_by: tuple[str, ...] | None = None,
    *,
    container: Any = None,
) -> BaseTool:
    """The ``sandbox_items`` tool, closed over one job's report and the reader that produced it.

    With ``container``, its ``detonation`` argument reads a later detonation's
    report from ``container.detonations``, its items' ids qualified by it.
    """
    from langchain_core.tools import StructuredTool

    from malspark.analysis.sandbox_sections import ITEMS_TOOL, Sections

    # The report read into sections once for the job, on the first call, and
    # held by this closure only: never cached across jobs. A later
    # detonation's, once each, by its name.
    held: list[Sections] = []
    later_held: dict[str, Sections] = {}

    def _sections() -> Sections | None:
        if report is None or _no_sandbox_ran(report):
            return None
        if not held:
            held.append(Sections(report, normalised_by))
        return held[0]

    def _items(
        section: str,
        pid: int | str | None = None,
        contains: str = "",
        signature: str = "",
        ids: list[str] | str | None = None,
        detonation: str = "",
    ) -> dict[str, Any]:
        """Read items of one section of the job's sandbox report, whole.

        ``section`` is one of ``processes``, ``api_calls``, ``files``,
        ``registry``, ``network``, ``signatures``, ``dropped``, ``mutexes``,
        ``commands``, ``services``, ``events``, ``apistats``, ``channels``,
        ``screenshots``, ``extracted`` (the configurations and payloads the
        sandbox extracted), ``resolved_apis``, ``alerts`` (an intrusion
        detection engine's) or ``procdumps``; the pack's sandbox section index
        gives each one's item count, or why the report does not carry it. Each item comes
        with its id (proc:<pid> for a process, <prefix>:<n> for the n-th item
        of any other section), the report list it came from and the report's
        own fields. ``pid`` (a number) keeps the items of that process id, in
        the sections whose rows name a process; ``contains``
        keeps the items one of whose text values contains the text (a path,
        key, host, URL or command line), case not counted; ``signature`` keeps
        the signature with that item id or name; ``ids`` keeps the items with
        those ids, a list or one text of ids separated by commas or spaces. The
        filters combine; with none, every item of the section
        is answered, and ``matched`` counts the items kept. A process's API
        calls are the api_calls items whose process is its id. A claim may
        cite an item by its id.
        """
        if not str(detonation or "").strip() or container is None:
            return sandbox_items(
                report, section, pid, contains, signature, ids, sections=_sections()
            )
        later, problem = selected(container, detonation)
        if problem:
            return {"error": problem, "tool": "sandbox"}
        if later is None:
            return sandbox_items(
                report, section, pid, contains, signature, ids, sections=_sections()
            )
        if later.name not in later_held:
            later_held[later.name] = Sections(later.report or {}, later.normalised_by, later.name)
        answer = sandbox_items(
            later.report, section, pid, contains, signature, ids, sections=later_held[later.name]
        )
        return {**later.stated(), **answer}

    description = _described(_items)
    if container is not None:
        description += (
            "\n\n" + _DETONATION_ARG + " A later detonation's item ids are qualified "
            "by it (d2/proc:<pid>, d2/net:<n>)."
        )
    return StructuredTool.from_function(
        func=_sized(_items, sizer, _ITEM_FILTERS), name=ITEMS_TOOL, description=description
    )


def _answer_room(sizer: Any) -> int | None:
    """How large an answer the model's copy holds whole now, or ``None`` with no guardrail.

    The size an answer is shortened to under the job's limit for this call
    (``output_shortening.shorten_target``): a view that keeps what it lists
    within it is never cut by the guardrail for what it lists beside its rows.
    """
    limit = getattr(sizer, "answer_limit", None)
    if not callable(limit):
        return None
    from malspark.agents.output_shortening import shorten_target

    return shorten_target(int(limit()), _PAGING)


def _answer_sizer(container: Any) -> Any:
    """The job's answer guardrail (``ServerRegistry.answer_sizer``), or ``None`` without one."""
    get_registry = getattr(container, "get_server_registry", None)
    if not callable(get_registry):
        return None
    try:
        return get_registry().answer_sizer()
    except Exception as exc:  # noqa: BLE001 — a view answered unsized is still an answer
        logger.warning("sandbox tools: no answer guardrail for this job (%s).", exc)
        return None


# The arguments every view pages by, named in the notice a shortened answer
# carries so the rows it left out are one call away.
_PAGING = ("offset", "limit")


def _sized(func: Any, sizer: Any, narrowing: tuple[str, ...] = _PAGING) -> Any:
    """``func``, its answer sent through the MCP toolkit's guardrail when there is one.

    The same sizing an MCP tool's answer gets: measured against the room the
    conversation has, shortened as a JSON document whose bookkeeping says what
    was left out, the budget charged. The recorder's notice then names the
    arguments in ``narrowing`` (``offset`` and ``limit`` for the paged views),
    so every row stays reachable.
    """
    import functools

    from malspark.core.safe_json import dumps

    if sizer is None:
        return func

    @functools.wraps(func)
    def _answer(*args: Any, **kwargs: Any) -> Any:
        value = func(*args, **kwargs)
        text = dumps(value, default=str)
        return sizer._apply_output_guardrail(text, narrowing)

    return _answer
