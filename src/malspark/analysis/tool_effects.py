"""What each tool a run called does beyond answering, said once, from what the run recorded.

The **effects** part of the run's disclosure record
(``run_summary["disclosure"]["effects"]``), printed in Appendix B under its
own lead sentence after the isolation part. For every tool the run actually
called (each ledger entry that made a call, a repeat or a guard's answer
left out), it says:

* whether the call **runs the sample's code**: no, natively, under emulation,
  or in a sandbox (``ToolEffects.executes``);
* whether the tool **reaches the network** beyond its own server
  (``ToolEffects.network``), or reaches it only in a named way: to refresh
  reference data it keeps, the configured case store, or the operator's own
  sandbox, which is not a third party;
* what of the sample it **sends to a third party**: nothing, its hash or its
  bytes (``ToolEffects.third_party``; the bytes also by
  ``ToolFacts.discloses_sample``, :func:`sends_sample_bytes`).

Each answer is read, in this order, from:

1. the tool's declaration under the source it was called through, as the
   entry stored it when it was written (``LedgerEntry.facts``,
   ``core.declared_reading``): the built-in servers' and providers' shipped
   declarations and an operator's ``tool_facts`` alike, the same mechanism
   every other reading of a tool uses;
2. for the network only, the ``openWorldHint`` the tool's own MCP server gave
   it when it was attached, kept on the entry beside the declaration
   (``core.declared_reading.server_hints``) and said to be the server's own
   hint; ``readOnlyHint``, ``destructiveHint`` and ``idempotentHint`` say
   nothing of these three, and are kept in the part as given;
   before it, a server's own declaration that its tool reaches the network,
   where the block does not trust that declaration
   (``core.declared_reading.served_statement``), said as the server's own
   declaration (``server_stated``); anything else such a declaration said is
   said as the server's own statement and never answers a count;
3. otherwise **undeclared**, said as such and never taken as "no", with the
   reason the declaration gives where it gives one (``why_undeclared``). An
   entry with no recorded source is undeclared on every count: it is never
   read by its tool's name.

**Only a call that completed had an effect.** Each row counts its calls by
how they ended: completed, failed (made, and broke: whether its effect
happened cannot be told), not run (the pipeline wrote that it never made the
call, ``triage_pack.was_not_made``) and refused (a guard answered it with no
tool run, ``schemas.evidence.is_guard_answer``). An effect is said to have
happened only for a tool with a completed call; the others are said as such,
never as having run or sent anything. A repeat of an earlier entry is no call.
The platform's own in-process tools (no source and no server, or a question to
the team) are left out by the rule the disclosure uses
(:func:`is_platform_internal`).

**Said in the voice of where it came from.** A line says an effect a
declaration states as declared ("Declared to …", with the declared ``when``
and offline condition); an effect the platform read of the tool's listing or
program (``core.declared_reading.platform_read``) and the cautious answer as
taken ("Taken as …"); and a server's own declaration or hint as its own; never
as an event. Each row keeps where each answer came from (``network_from``,
``third_party_from``, ``executes_from``, ``why_from``). Sent bytes a
declaration itself states are declared, ``discloses_sample`` alone taken. A
tool whose declared work is running the sample's code "Ran" it only where a
counted call of it completed under no declared condition. A row stored before
these fields cannot tell a declaration from a reading: it says a network, a
sent hash and sent bytes as taken.

**One source of truth with the disclosure.** Where the sample's bytes were
read is the isolation part (``analysis.isolation``): a tool that ran the
sample's code natively or under emulation is told with the isolation row of
its source. Where they were sent is the disclosure's upload rows, which read
the same rule as this part (:func:`sends_sample_bytes`), so a tool said here
to send the sample's bytes is always a tool upload there. A tool that reaches
the sandbox service its server fronts (``network: operator_sandbox``) is told
where the disclosure placed that call (``places``): the operator's own, not a
third party, only where it is placed on this machine; outside it, at the host
the settings name; and, where the disclosure cannot place it, that it cannot
be told, with the disclosure's own reason.

Never a tool's name. Linear in the entries.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any

from malspark.core.tool_declarations import (
    EXECUTES_EMULATION,
    EXECUTES_NATIVE,
    EXECUTES_NO,
    EXECUTES_SANDBOX,
    NETWORK_CASE_STORE,
    NETWORK_ON_REFRESH,
    NETWORK_OPERATOR_SANDBOX,
    THIRD_PARTY_BYTES,
    THIRD_PARTY_HASH,
    THIRD_PARTY_NO,
)

# The version of the part's shape.
EFFECTS_VERSION = 1

# Where an answer came from.
DECLARED = "declared"
SERVER_HINT = "server_hint"
# What a server's own declaration of its tool said, where its block does not
# trust it (``core.served_declarations``): only that it reaches the network.
SERVER_STATED = "server_stated"
# The MCP hint that answers whether a tool reaches the network.
OPEN_WORLD_HINT = "openWorldHint"
# Where a row's network answer came from, in the voice its line says it in
# (``network_from``): an effects block that states it; the cautious answer
# for a tool declared or taken to send the sample or its hash out, which
# reaches the network whatever its block says of it; the server's own
# declaration its block does not trust; the server's own hint.
FROM_DECLARED = "declared"
FROM_SENDS = "sends"
FROM_SERVER = "server"
FROM_HINT = "hint"
# An answer the platform read of the tool's listing or program, laid under the
# declarations (``core.declared_reading.platform_read``): taken, never declared.
# Also where a row's sent hash or bytes, its run and its reason came from.
FROM_READ = "read"
# What a row that does not record where its answer came from is said as: taken.
_FROM_TAKEN = "taken"
# Where a row's sent bytes came from (``third_party_from``): the declaration's own
# ``effects.third_party`` of ``bytes``, or ``discloses_sample`` alone, the cautious
# reading.
FROM_DISCLOSES = "discloses"

INTRO_SENTENCE = (
    "**Tool effects:** what each tool this run called is declared to do beyond answering: run "
    "the sample's code, reach the network, or send the sample's hash or bytes to a third party. "
    "Where the sample's bytes were read is the isolation part above, and where they were sent "
    "the upload rows of the disclosure; a tool whose declaration does not say is listed as "
    "undeclared, and is not taken as safe."
)

# What a missing answer is, as the undeclared line says it.
_UNDECLARED_EXECUTES = "run the sample's code"
_UNDECLARED_NETWORK = "reach the network"
_UNDECLARED_THIRD_PARTY = "send the sample's hash or bytes to a third party"

# The lead of each line that names the tools that ran the sample's code: a completed
# call whose declared work is running it, under no declared condition, is that run.
_RAN = {
    EXECUTES_NATIVE: "Ran the sample's code natively",
    EXECUTES_EMULATION: "Ran the sample's code under emulation",
}
# The same tools where the record does not hold that run: a declared condition, or a
# row stored before calls were counted by how they ended.
_DECLARED_TO_RUN = {
    EXECUTES_NATIVE: "Declared to run the sample's code natively",
    EXECUTES_EMULATION: "Declared to run the sample's code under emulation",
}
# The same tools where running the sample's code is the platform's reading of them.
_TAKEN_TO_RUN = {
    EXECUTES_NATIVE: "Taken as running the sample's code natively",
    EXECUTES_EMULATION: "Taken as running the sample's code under emulation",
}
# The lead of each line that names the tools reaching a network in a named way, as
# declared; and the same where the platform read the mode (``network_from``).
_REACHED = {
    NETWORK_OPERATOR_SANDBOX: "Declared to reach the sandbox service its server fronts",
    NETWORK_CASE_STORE: "Declared to reach the configured case-memory store",
    NETWORK_ON_REFRESH: (
        "Declared to reach the network only to fetch or refresh reference data they keep, "
        "sending nothing of the sample"
    ),
}
_TAKEN_REACHED = {
    NETWORK_OPERATOR_SANDBOX: "Taken as reaching the sandbox service its server fronts",
    NETWORK_CASE_STORE: "Taken as reaching the configured case-memory store",
    NETWORK_ON_REFRESH: (
        "Taken as reaching the network only to fetch or refresh reference data they keep, "
        "sending nothing of the sample"
    ),
}
# Where the case-memory store such a tool reaches is, as the disclosure's case-memory
# row places it (``stores``): placed with a host, listed and not placed, or not listed.
_STORE_PLACED = "which the disclosure's case-memory row places"
_STORE_UNPLACED = "of which the disclosure's case-memory row cannot tell where it runs"
_STORE_NONE = "which the disclosure records as kept in the process or not configured"
# The lead of each line that names the tools reaching the network, by where the
# answer came from (``network_from``), a sent hash and a sent file apart, each by
# where the sent hash or file came from.
_REACHES = {
    FROM_DECLARED: "Declared to reach the network",
    (FROM_SENDS, THIRD_PARTY_HASH, FROM_DECLARED): (
        "Taken as reaching the network, as a tool declared to send the sample's hash out"
    ),
    (FROM_SENDS, THIRD_PARTY_HASH, _FROM_TAKEN): (
        "Taken as reaching the network, as a tool taken to send the sample's hash out"
    ),
    (FROM_SENDS, THIRD_PARTY_BYTES, FROM_DECLARED): (
        "Taken as reaching the network, as a tool declared to send the sample's bytes to a third "
        "party"
    ),
    (FROM_SENDS, THIRD_PARTY_BYTES, _FROM_TAKEN): (
        "Taken as reaching the network, as a tool taken to send the sample's file out"
    ),
    _FROM_TAKEN: "Taken as reaching the network",
    FROM_SERVER: (
        "Stated by its own server, in a declaration its block does not trust, to reach the network"
    ),
    FROM_HINT: "Said by its server's own hint to reach outside its server",
}


@dataclass(frozen=True)
class Effects:
    """One tool's three answers, each empty (or ``None``) where nothing says."""

    executes: str = ""
    network: bool | str | None = None
    third_party: str = ""
    network_by: str = ""
    why_undeclared: str = ""
    when: str = ""
    network_from: str = ""
    offline_without_credentials: bool | None = None
    third_party_from: str = ""
    executes_from: str = ""
    why_from: str = ""


# How a call ended, as a row counts it.
COMPLETED = "completed"
FAILED = "failed"
NOT_RUN = "not_run"
REFUSED = "refused"
OUTCOMES: tuple[str, ...] = (COMPLETED, FAILED, NOT_RUN, REFUSED)


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def sends_sample_bytes(facts: Any) -> bool:
    """Whether a declaration says the tool sends the sample's bytes out of the deployment.

    ``discloses_sample``, or ``effects.third_party`` of ``bytes``: either one
    says it. The one rule the disclosure's upload rows and this part read.
    """
    if facts is None:
        return False
    if getattr(facts, "discloses_sample", False) is True:
        return True
    effects = getattr(facts, "effects", None)
    return effects is not None and getattr(effects, "third_party", "") == THIRD_PARTY_BYTES


def entry_effects(entry: Any) -> Effects:
    """What the entry's tool does beyond answering, as the entry stored it; never by its name.

    A declaration that says the tool sends the sample or its hash to a third
    party says it reaches the network too, whatever else it says: the
    cautious answer is kept, and ``network_from`` says it was taken so. Each
    answer the platform read of the tool's listing or program, rather than a
    declaration stated, is kept as read (:data:`FROM_READ`).
    """
    from malspark.core.declared_reading import (
        declared_only,
        kind_free_facts,
        platform_read,
        recorded,
        served_statement,
        server_hints,
    )

    if not recorded(entry):
        return Effects()
    read = platform_read(entry)

    def origin(dotted: str, value: Any) -> str:
        if value in ("", None):
            return ""
        return FROM_READ if dotted in read else FROM_DECLARED

    facts = kind_free_facts(declared_only(entry))
    declared = facts.effects
    executes = declared.executes if declared is not None else ""
    network = declared.network if declared is not None else None
    third_party = declared.third_party if declared is not None else ""
    third_party_from = origin("effects.third_party", third_party)
    if sends_sample_bytes(facts) and third_party != THIRD_PARTY_BYTES:
        third_party, third_party_from = THIRD_PARTY_BYTES, FROM_DISCLOSES
    network_from = origin("effects.network", network)
    if third_party in (THIRD_PARTY_HASH, THIRD_PARTY_BYTES) and network not in (
        True,
        NETWORK_OPERATOR_SANDBOX,
    ):
        network, network_from = True, FROM_SENDS
    network_by = DECLARED if network is not None else ""
    if network is None and served_statement(entry).get("effects.network") is True:
        # What the server itself declared of its tool, where no declaration
        # the operator trusts says: only that it reaches the network.
        network, network_by, network_from = True, SERVER_STATED, FROM_SERVER
    if network is None:
        hint = server_hints(entry).get(OPEN_WORLD_HINT)
        if hint is not None:
            network, network_by, network_from = hint, SERVER_HINT, FROM_HINT
    why = declared.why_undeclared if declared is not None else ""
    when = declared.when if declared is not None else ""
    offline = declared.offline_without_credentials if declared is not None else None
    return Effects(
        executes,
        network,
        third_party,
        network_by,
        why,
        when,
        network_from,
        offline,
        third_party_from,
        origin("effects.executes", executes),
        origin("effects.why_undeclared", why),
    )


def is_platform_internal(entry: Any) -> bool:
    """Whether the entry is the platform's own in-process tool, or a question put to the team.

    No source and no server (or the team's): the rule the disclosure leaves
    such an entry out by, whatever the tool's name.
    """
    from malspark.agents.delegation import TEAM_SERVER

    if _field(entry, "source"):
        return False
    server = str(_field(entry, "server") or "")
    return not server or server == TEAM_SERVER


def outcome(entry: Any) -> str | None:
    """How the entry's call ended (:data:`OUTCOMES`); ``None`` for an answer served again.

    A guard's answer is refused; any other entry answered without a run
    ended no call of its own, and a step never run is not run
    (``schemas.evidence.call_state``).
    """
    from malspark.schemas import evidence

    if evidence.is_guard_answer(entry):
        return REFUSED
    state = evidence.call_state(entry)
    if state == evidence.SERVED:
        return None
    if state == evidence.NOT_RUN:
        return NOT_RUN
    return COMPLETED if _field(entry, "ok") is not False else FAILED


def _read_where(isolation: Mapping[str, Any] | None) -> dict[str, tuple[str, bool, str]]:
    """Each source the isolation part placed: where it read, whether isolated, and on what."""
    rows = isolation.get("rows") if isinstance(isolation, Mapping) else None
    out: dict[str, tuple[str, bool, str]] = {}
    for row in rows or []:
        if isinstance(row, Mapping):
            out[str(row.get("source") or "")] = (
                str(row.get("where") or ""),
                row.get("isolated") is True,
                str(row.get("isolated_by") or ""),
            )
    return out


def _least_isolated(
    places: list[str], source: str, placed: Mapping[str, tuple[str, bool, str]]
) -> str:
    """The place a row of several reads as: the least isolated, so none reads safer than it ran.

    The entry's own source (the worker, for the pack) whenever it is among
    them; otherwise a place the isolation part did not place, then one not
    isolated, then the one nearest the worker. ``source`` with no places.
    """
    from malspark.analysis.isolation import _ORDER

    if not places:
        return source
    if source in places:
        return source

    def exposure(place: str) -> tuple[int, int, int]:
        held = placed.get(place)
        if held is None:
            return (0, 0, 0)
        return (1, int(bool(held[1])), _ORDER.get(held[0], len(_ORDER)))

    return min(places, key=exposure)


def effects_part(
    entries: Iterable[Any],
    *,
    isolation: Mapping[str, Any] | None = None,
    partial_reason: str = "",
    places: Mapping[tuple[str, str], Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """The effects part of the disclosure record: one row per tool the run called.

    ``entries`` are the run's ledger entries; ``isolation`` the record's
    isolation part, which places the sources that read the sample;
    ``partial_reason`` why the record may miss a call; ``places`` where the
    disclosure placed each ``(source, tool)`` it placed. Linear in the entries.

    Each row counts the calls whose tool ran (``calls``), the ones answered
    without a run (``served``) and the steps never run (``not_run``), by the
    one definition (``schemas.evidence.call_state``): together they are the
    row's entries. A guard's refusal is served, and counted ``refused`` too.
    """
    from malspark.analysis.isolation import ran_on_sources
    from malspark.core.declared_reading import served_statement, server_hints
    from malspark.schemas.evidence import MADE, SERVED, call_state

    placed = _read_where(isolation)
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in entries:
        if is_platform_internal(entry):
            continue
        ended = outcome(entry)
        server = str(_field(entry, "server") or "")
        source = str(_field(entry, "source") or "")
        tool = str(_field(entry, "tool") or "")
        key = (source, "" if source else server, tool)
        row = rows.get(key)
        if row is None:
            effects = entry_effects(entry)
            row = {
                "source": source,
                "server": key[1],
                "tool": tool,
                "calls": 0,
                "served": 0,
                "executes": effects.executes,
                "network": effects.network,
                "network_by": effects.network_by,
                "third_party": effects.third_party,
                "why_undeclared": effects.why_undeclared,
                "when": effects.when,
                # Where the network answer came from, and the declared offline
                # condition: said by the lines, read by no count and no placement.
                "network_from": effects.network_from,
                "offline_without_credentials": effects.offline_without_credentials,
                # Where the sent hash or bytes came from: the declaration, the platform's
                # reading, or the cautious reading of ``discloses_sample``; and where the
                # run of the sample's code and the reason it cannot be declared came from:
                # said by the lines only.
                "third_party_from": effects.third_party_from,
                "executes_from": effects.executes_from,
                "why_from": effects.why_from,
                "hints": server_hints(entry),
                **dict.fromkeys(OUTCOMES, 0),
            }
            stated = {
                name: value
                for name, value in served_statement(entry).items()
                if name != "effects.network"
            }
            if stated:
                # What its own server said of it that no declaration says:
                # said as such, never counted as declared.
                row["server_states"] = stated
            if effects.executes in (EXECUTES_NATIVE, EXECUTES_EMULATION):
                # Placed where its readings ran when the entry names a server
                # that ran them (``ran_on``), else by its source.
                reading = _least_isolated(ran_on_sources(entry), source, placed)
                where = placed.get(reading) if reading else None
                row["read_where"] = where[0] if where is not None else None
                row["read_isolated"] = where[1] if where is not None else False
                row["read_isolated_by"] = where[2] if where is not None else ""
            if effects.network == NETWORK_OPERATOR_SANDBOX:
                held = (places or {}).get((source, tool)) or {}
                row["placed_where"] = str(held.get("where") or "")
                row["placed_host"] = str(held.get("host") or "")
                row["placed_why"] = str(
                    held.get("why") or ("" if held else "the disclosure does not place it")
                )
            rows[key] = row
        state = call_state(entry)
        if state == MADE:
            row["calls"] += 1
        elif state == SERVED:
            row["served"] += 1
        if ended is not None:
            row[ended] += 1
    return {
        "v": EFFECTS_VERSION,
        "partial_reason": str(partial_reason or ""),
        "tools": [rows[key] for key in sorted(rows)],
    }


# ---------------------------------------------------------------------------
# The sentences
# ---------------------------------------------------------------------------


def _code(text: str) -> str:
    return f"`{text}`"


def _joined(items: list[str], word: str = "and") -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + f" {word} " + items[-1]


@cache
def _in_process_labels() -> Mapping[str, str]:
    from malspark.core.builtin_declarations import in_process_declarations

    return {str(ref): cfg.label for ref, cfg in in_process_declarations().items()}


def _label(row: Mapping[str, Any], code: Callable[[str], str]) -> str:
    """Where the tool was called through, as a reader is told it."""
    source = str(row.get("source") or "")
    if not source:
        server = str(row.get("server") or "")
        if server:
            return f"tool server {code(server)}, which recorded no source"
        return "the platform's own tools, which record no source"
    labels = _in_process_labels()
    if source in labels:
        return f"{labels[source] or 'the in-process source'} ({code(source)})"
    kind, _, key = source.partition(":")
    if kind == "mcp" and key:
        return f"tool server {code(key)}"
    if kind == "provider" and key:
        return f"the {code(key)} provider's tool server"
    return f"source {code(source)}"


def _read_note(row: Mapping[str, Any]) -> str:
    """Where a tool that ran the sample's code read it, as the isolation part placed its source."""
    from malspark.analysis.isolation import (
        BY_DECLARATION,
        CHILD,
        IN_PROCESS,
        LOCAL_SERVICE,
        REMOTE_SERVICE,
    )

    where = row.get("read_where")
    if where is None:
        return "the isolation part records no read of the sample by its source"
    if where == IN_PROCESS:
        return "read in the worker process itself"
    if where == CHILD:
        kept = (
            "measured as kept from the worker"
            if row.get("read_isolated")
            else "not shown to be kept from the worker"
        )
        if row.get("read_isolated") and row.get("read_isolated_by") == BY_DECLARATION:
            kept = "kept from the worker as its block's declaration of a launcher says"
        return f"read in a process the worker started, {kept}"
    if where == LOCAL_SERVICE:
        return "read at a local server this run does not measure"
    if where == REMOTE_SERVICE:
        return "read outside this machine"
    return "where it read the sample cannot be told"


def _named(
    rows: list[Mapping[str, Any]],
    code: Callable[[str], str],
    note: Callable[[Mapping[str, Any]], str] | None = None,
) -> str:
    """The tools, grouped by where they were called through (and by ``note``), in row order."""
    groups: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        said = note(row) if note is not None else ""
        groups.setdefault((_label(row, code), said), []).append(code(str(row.get("tool") or "")))
    parts = []
    for (label, said), tools in groups.items():
        parts.append(f"{_joined(tools)} on {label}" + (f", {said}" if said else ""))
    return "; ".join(parts)


def network_from(row: Mapping[str, Any]) -> str:
    """Where a row's network answer came from, as its line says it.

    A row built with ``network_from`` says it. A row stored before it cannot tell a
    declaration from the platform's reading: a network is taken; a named mode, which only
    a declaration gives, and a closed network stay as stored.
    """
    if "network_from" in row:
        return str(row.get("network_from") or "")
    by = row.get("network_by")
    if by == SERVER_STATED:
        return FROM_SERVER
    if by == SERVER_HINT:
        return FROM_HINT
    if by != DECLARED:
        return ""
    return _FROM_TAKEN if row.get("network") is True else FROM_DECLARED


def _reaches_key(row: Mapping[str, Any]) -> Any:
    """Which lead a row reaching the network is said under; one whose origin is not recorded,
    or not known here, is taken."""
    held: Any = network_from(row) or _FROM_TAKEN
    if held == FROM_SENDS:
        voice = FROM_DECLARED if third_party_from(row) == FROM_DECLARED else _FROM_TAKEN
        held = (held, row.get("third_party"), voice)
    return held if held in _REACHES else _FROM_TAKEN


def third_party_from(row: Mapping[str, Any]) -> str:
    """Where a row's sent hash or bytes came from, as its line says it.

    A row built with ``third_party_from`` says it. A row stored before it cannot tell a
    declaration from the platform's reading: a sent hash is taken, and sent bytes may be
    ``discloses_sample`` alone, so they are taken too.
    """
    if "third_party_from" in row:
        return str(row.get("third_party_from") or "")
    sent = row.get("third_party")
    if sent == THIRD_PARTY_BYTES:
        return FROM_DISCLOSES
    if sent == THIRD_PARTY_HASH:
        return _FROM_TAKEN
    return FROM_DECLARED if sent else ""


def executes_from(row: Mapping[str, Any]) -> str:
    """Where a row's answer of running the sample's code came from; a row stored before it
    says it as stored."""
    if "executes_from" in row:
        return str(row.get("executes_from") or "")
    return FROM_DECLARED if row.get("executes") else ""


def why_from(row: Mapping[str, Any]) -> str:
    """Where a row's reason its effects cannot be declared came from; a row stored before it
    says it as stored."""
    if "why_from" in row:
        return str(row.get("why_from") or "")
    return FROM_DECLARED if row.get("why_undeclared") else ""


def _ran(row: Mapping[str, Any]) -> bool:
    """Whether the row's record holds the run itself: a counted completed call of a tool whose
    declared work is running the code, under no declared condition."""
    return int(row.get(COMPLETED) or 0) > 0 and not _when(row)


def _hint_closed(row: Mapping[str, Any]) -> str:
    """Where a tool taken to reach the network has a server whose own hint says it does not."""
    hints = row.get("hints")
    if isinstance(hints, Mapping) and hints.get(OPEN_WORLD_HINT) is False:
        return "though its server's own hint says it does not reach outside its server"
    return ""


def _offline(row: Mapping[str, Any]) -> str:
    """The declared condition under which the tool answers from this machine, as declared."""
    if row.get("offline_without_credentials") is True:
        return "declared to answer offline when it is given no credentials"
    return ""


def _server_states(row: Mapping[str, Any]) -> str:
    held = row.get("server_states")
    if not isinstance(held, Mapping):
        return ""
    return ", ".join(f"{name} {value}" for name, value in sorted(held.items()))


def _when(row: Mapping[str, Any]) -> str:
    return str(row.get("when") or "")


def _with_when(*notes: Callable[[Mapping[str, Any]], str]) -> Callable[[Mapping[str, Any]], str]:
    """The declared ``when`` first, then each note that says something, joined."""

    def _both(row: Mapping[str, Any]) -> str:
        return ", ".join(part for part in (_when(row), *(note(row) for note in notes)) if part)

    return _both


def _sandbox_place(code: Callable[[str], str]) -> Callable[[Mapping[str, Any]], str]:
    """Where the disclosure placed a call to the sandbox service a tool's server fronts."""
    from malspark.core.host_locality import LOCAL, REMOTE

    def _note(row: Mapping[str, Any]) -> str:
        where, host = row.get("placed_where"), str(row.get("placed_host") or "")
        if where == LOCAL and host and not row.get("placed_why"):
            return (
                f"at {code(host)}, which the disclosure places on this machine, so the "
                "operator's own and not a third party"
            )
        if where == REMOTE and host:
            return (
                f"at {code(host)}, outside this machine; whether it is the operator's own the "
                "settings do not say"
            )
        why = str(row.get("placed_why") or "the record does not say")
        return f"where it went cannot be told: {why}"

    return _note


def _missing(row: Mapping[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    if not row.get("executes"):
        out.append(_UNDECLARED_EXECUTES)
    if row.get("network") is None:
        out.append(_UNDECLARED_NETWORK)
    if not row.get("third_party"):
        out.append(_UNDECLARED_THIRD_PARTY)
    return tuple(out)


def _closed(row: Mapping[str, Any]) -> bool:
    """Whether the row's tool is declared or taken to do none of the three."""
    return (
        row.get("network") is False
        and row.get("network_by") == DECLARED
        and row.get("executes") == EXECUTES_NO
        and row.get("third_party") == THIRD_PARTY_NO
    )


def _declared_closed(row: Mapping[str, Any]) -> bool:
    """Whether a declaration states each of the three answers of a row doing none of them."""
    return (
        network_from(row) == FROM_DECLARED
        and executes_from(row) == FROM_DECLARED
        and third_party_from(row) == FROM_DECLARED
    )


def _of_calls(state: str) -> Callable[[Mapping[str, Any]], str]:
    def _note(row: Mapping[str, Any]) -> str:
        count, calls = int(row.get(state) or 0), int(row.get("calls") or 0)
        if "served" in row:
            # A step never run is out of every call of the tool. A row stored
            # before ``served`` was counted holds it in ``calls``.
            calls += int(row.get(NOT_RUN) or 0)
        if state == REFUSED:
            # A refusal is an answer without a run: out of every call asked.
            # A row stored before ``served`` was counted holds it in ``calls``.
            calls += int(row.get("served") or 0)
        return f"{count} of {calls} calls" if count != calls else ""

    return _note


# What a call that did not complete is said to be, by how it ended.
_ENDED = {
    NOT_RUN: "Was not run, so none of its declared effects happened",
    REFUSED: "Was refused, so nothing was sent",
    FAILED: "Failed, so whether its declared effects happened cannot be told",
}


def _store_where(stores: Any) -> str:
    """Where the configured case-memory store is, as the disclosure's case-memory row says."""
    from malspark.core.host_locality import LOCAL, REMOTE

    rows = [row for row in stores or [] if isinstance(row, Mapping)]
    if any(row.get("where") in (LOCAL, REMOTE) and row.get("host") for row in rows):
        return _STORE_PLACED
    return _STORE_UNPLACED if rows else _STORE_NONE


def _split(
    rows: list[Mapping[str, Any]], declared: Callable[[Mapping[str, Any]], bool]
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """``rows`` whose answer a declaration states, and the rest, which are taken."""
    return [row for row in rows if declared(row)], [row for row in rows if not declared(row)]


def effects_lines(
    part: Any, code: Callable[[str], str] = _code, *, stores: Any = None
) -> list[str]:
    """The part's sentences, one per line; ``[]`` for a record without the part.

    An effect is said for the tools with a completed call only; a tool whose
    calls failed, were not run or were refused is said as such. ``stores`` are
    the disclosure's case-memory rows, which place the store a tool is declared
    to reach.
    """
    if not isinstance(part, Mapping) or "tools" not in part:
        return []
    # A row whose every entry was answered again from an earlier one is no
    # call of its tool: it is counted, and said nowhere here.
    every = [
        row
        for row in part.get("tools") or []
        if isinstance(row, Mapping)
        and any(int(row.get(key) or 0) for key in ("calls", REFUSED, NOT_RUN))
    ]
    # A row stored before calls were counted by how they ended holds only
    # ``calls``: each is read as completed, as it was then.
    rows = [row for row in every if int(row.get(COMPLETED, row.get("calls")) or 0)]
    lines: list[str] = []
    if part.get("partial_reason"):
        lines.append(
            f"This part may be incomplete: {part['partial_reason']}, and a call made in the step "
            "it stopped in may not be recorded."
        )
    if not every:
        lines.append("This run recorded no tool call, so no tool's effects are said.")
        return lines

    def ran_declared(row: Mapping[str, Any]) -> bool:
        return executes_from(row) == FROM_DECLARED

    for mode in (EXECUTES_NATIVE, EXECUTES_EMULATION):
        stated, taken = _split([row for row in rows if row.get("executes") == mode], ran_declared)
        ran = [row for row in stated if _ran(row)]
        if ran:
            lines.append(f"{_RAN[mode]}: {_named(ran, code, _with_when(_read_note))}.")
        declared_only = [row for row in stated if not _ran(row)]
        if declared_only:
            lines.append(
                f"{_DECLARED_TO_RUN[mode]}: {_named(declared_only, code, _with_when(_read_note))}."
            )
        if taken:
            lines.append(f"{_TAKEN_TO_RUN[mode]}: {_named(taken, code, _with_when(_read_note))}.")
    place = _sandbox_place(code)

    def sandbox_declared(row: Mapping[str, Any]) -> bool:
        return ran_declared(row) and (
            row.get("network") != NETWORK_OPERATOR_SANDBOX or network_from(row) == FROM_DECLARED
        )

    own = [
        row
        for row in rows
        if row.get("executes") == EXECUTES_SANDBOX
        and row.get("network") == NETWORK_OPERATOR_SANDBOX
    ]
    stated, taken = _split(own, sandbox_declared)
    if stated:
        lines.append(
            f"Declared to have the sample run in the sandbox service its server fronts: "
            f"{_named(stated, code, _with_when(place))}."
        )
    if taken:
        lines.append(
            f"Taken as having the sample run in the sandbox service its server fronts: "
            f"{_named(taken, code, _with_when(place))}."
        )
    theirs = [
        row
        for row in rows
        if row.get("executes") == EXECUTES_SANDBOX
        and row.get("network") != NETWORK_OPERATOR_SANDBOX
    ]
    stated, taken = _split(theirs, ran_declared)
    if stated:
        lines.append(
            f"Declared to run the sample in a sandbox its server does not front, which may be a "
            f"third party's: {_named(stated, code, _when)}."
        )
    if taken:
        lines.append(
            f"Taken as running the sample in a sandbox its server does not front, which may be a "
            f"third party's: {_named(taken, code, _when)}."
        )
    reached = [row for row in rows if row.get("network") is True]
    for key, lead in _REACHES.items():
        held = [row for row in reached if _reaches_key(row) == key]
        if held:
            lines.append(f"{lead}: {_named(held, code, _with_when(_offline, _hint_closed))}.")
    for mode, lead in _REACHED.items():
        stated, taken = _split(
            [row for row in rows if row.get("network") == mode],
            lambda row: network_from(row) == FROM_DECLARED,
        )
        notes = (place,) if mode == NETWORK_OPERATOR_SANDBOX else ()
        where = f", {_store_where(stores)}" if mode == NETWORK_CASE_STORE else ""
        for held, said in ((stated, lead), (taken, _TAKEN_REACHED[mode])):
            if held:
                lines.append(f"{said}{where}: {_named(held, code, _with_when(*notes))}.")
    stated, taken = _split(
        [row for row in rows if row.get("third_party") == THIRD_PARTY_HASH],
        lambda row: third_party_from(row) == FROM_DECLARED,
    )
    if stated:
        lines.append(
            "Declared to send the sample's hash to a third party: "
            f"{_named(stated, code, _with_when(_offline))}."
        )
    if taken:
        lines.append(
            "Taken as sending the sample's hash to a third party: "
            f"{_named(taken, code, _with_when(_offline))}."
        )
    sent = [row for row in rows if row.get("third_party") == THIRD_PARTY_BYTES]
    handed = [row for row in sent if row.get("network") == NETWORK_OPERATOR_SANDBOX]
    out = [row for row in sent if row.get("network") != NETWORK_OPERATOR_SANDBOX]
    # Sent bytes a declaration itself states are declared; ``discloses_sample`` alone and
    # the platform's reading are taken, with what the upload rows know of where it went.
    stated = [row for row in handed if third_party_from(row) == FROM_DECLARED]
    if stated:
        lines.append(
            f"Declared to hand the sample's bytes to the sandbox service its server fronts: "
            f"{_named(stated, code, _with_when(place))}; where each call sent them is in the "
            "upload rows of the disclosure above."
        )
    taken = [row for row in handed if third_party_from(row) != FROM_DECLARED]
    if taken:
        lines.append(
            f"Taken as handing the sample's file to the sandbox service its server fronts: "
            f"{_named(taken, code, _with_when(place))}; the upload rows of the disclosure "
            "above say what is known of where each call sent it."
        )
    stated = [row for row in out if third_party_from(row) == FROM_DECLARED]
    if stated:
        lines.append(
            f"Declared to send the sample's bytes to a third party: "
            f"{_named(stated, code, _with_when())}; where each call sent them is in the upload "
            "rows of the disclosure above."
        )
    taken = [row for row in out if third_party_from(row) != FROM_DECLARED]
    if taken:
        lines.append(
            f"Taken as sending the sample's file out of the deployment: "
            f"{_named(taken, code, _with_when())}; the upload rows of the disclosure above say "
            "what is known of where each call sent it."
        )
    stated, taken = _split([row for row in every if _closed(row)], _declared_closed)
    for held, lead in (
        (stated, "Declared to do none of these"),
        (taken, "Taken as doing none of these"),
    ):
        if held:
            places = list(dict.fromkeys(_label(row, code) for row in held))
            lines.append(
                f"{lead}: {len(held)} {'tool' if len(held) == 1 else 'tools'}, on "
                f"{_joined(places)}."
            )
    hinted = [
        row for row in rows if row.get("network") is False and row.get("network_by") == SERVER_HINT
    ]
    if hinted:
        lines.append(
            f"Said not to reach the network by its server's own hint ({OPEN_WORLD_HINT} false), "
            f"which no declaration says: {_named(hinted, code)}."
        )
    stated = [row for row in rows if isinstance(row.get("server_states"), Mapping)]
    if stated:
        lines.append(
            "Said of itself by its own server, which no declaration the operator trusts says: "
            f"{_named(stated, code, _server_states)}."
        )
    for state, lead in _ENDED.items():
        held = [row for row in every if int(row.get(state) or 0) and not _closed(row)]
        if held:
            lines.append(f"{lead}: {_named(held, code, _of_calls(state))}.")
    groups: dict[tuple[tuple[str, ...], str, str], list[Mapping[str, Any]]] = {}
    for row in every:
        made = int(row.get(COMPLETED, row.get("calls")) or 0) + int(row.get(FAILED) or 0)
        missing = _missing(row)
        if missing and made:
            why = str(row.get("why_undeclared") or "")
            # The reason as its declaration states it, or as the platform read it.
            said = (
                "its declaration"
                if why_from(row) == FROM_DECLARED
                else "the platform's reading of its listing"
            )
            groups.setdefault((missing, why, said), []).append(row)
    for (missing, why, said), held in groups.items():
        lines.append(
            f"Undeclared whether it may {_joined(list(missing), 'or')}, so not taken as safe: "
            f"{_named(held, code)}" + (f"; {said} says why: {why}" if why else "") + "."
        )
    return lines
