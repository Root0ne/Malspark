"""The environment a run ran in, recorded by code so a reader states it without guessing.

``run_summary.environment`` is built by :func:`environment_record` from the
job's own records, never from a model and never from what a setting says
should happen:

* ``host`` is the worker's host as it reads itself (:func:`host_facts`): the
  operating system and its release, the machine type, the processor model,
  and the kernel's logical processors and total memory; beside them, what
  the worker process itself may use where a limit is readable — the
  processors its CPU affinity and CPU quota leave it (``cpus_available``)
  and its memory limit (``memory_limit_bytes``), both from the control
  groups it runs in, v2 or v1. A fact the host does not give is left out,
  and reading the host never fails the run.
* ``agents`` is, per agent, one row per model of its list it was built to
  send with (``llm.sent_request``, kept by the registry as each model is
  built): the configured model identifier (one shaped like a file-system
  path kept by its base name, ``model_reduced``); the sampling parameters
  and thinking switches its provider adapter read off the request body the
  client built when the model was built, the statement that no sampling
  parameter was sent and the provider's default applied, or the statement
  that the adapter reported nothing; how many requests the platform changed
  a thinking switch of after that (``thinking_changed_requests``, where any
  were); the effort level sent and the setting it came from, or why none
  was; and how many recorded answers came from its place in the list
  (``answered``; a fallback that was never needed answered none; rows that
  share a place each carry its total, ``answered_shared``).
  Beside the rows, each model identifier the provider's answers carried and
  how many answers carried it (``TokenLedger.response_models``), an
  identifier shaped like a file-system path kept by its base name and listed
  in ``response_models_reduced``. An agent whose answers carried none has an
  empty map.
* ``tools`` is, per tool server the job's registry or one of its providers
  attached, how it served the run and what it ran (:func:`tools_record`):
  the name and version it gave at its attach, its manifest's version, and
  each requirement its tools declare as its manifest reports it — a module's
  installed distribution and version, a data path's file count and digest, a
  binary's version where the tool declares how to ask it. The steps the
  pipeline runs in its own process are the row ``pipeline``, read on the
  worker's host with the environment of the server each stands in for.

Written when the judge builds the summary and again once the run's last
model call is made (the report node, and a stopped run's summary), so the
report stage's own agents are in it. A summary stored before the block
existed has none, and reads as it always did.
"""

from __future__ import annotations

import functools
import os
import platform
import subprocess
import sys
from collections.abc import Iterable, Mapping
from typing import Any

from malspark.core.logger import logger
from malspark.tools.capabilities import NOT_REPORTED

# The record's shape version: a reader that meets a newer one reads what it
# knows. 2: a row's ``sampling`` may be ``None`` (not reported), rows carry
# ``thinking`` and ``answered``, and ``tools`` is recorded.
ENVIRONMENT_VERSION = 2

# The server every entry of a step the pipeline runs in its own process is
# recorded under (``pipeline.triage_pack.PIPELINE``), and the agent its server
# steps' entries are recorded under.
PIPELINE = "pipeline"
# How a tool server served the run (``tools_record``).
SERVED_OFFERED = "offered"
SERVED_CALLED = "called"
SERVED_PACK_STEP = "pack_step"
SERVED_IN_PROCESS = "in_process"
SERVED_ATTACHED = "attached"

# How long a host query (``sysctl`` on macOS) may take, in seconds.
_QUERY_TIMEOUT_S = 2.0


def _text(value: Any) -> str:
    return str(value or "").strip()


def _linux_cpu_model() -> str:
    """The processor model ``/proc/cpuinfo`` names, or ``""``."""
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return ""
    # ``model name`` on x86, ``Model`` or ``Hardware`` on many ARM boards.
    for key in ("model name", "Model", "Hardware"):
        for line in lines:
            name, sep, value = line.partition(":")
            if sep and name.strip() == key and value.strip():
                return value.strip()
    return ""


def _sysctl(key: str) -> str:
    """One ``sysctl -n`` value, or ``""``."""
    try:
        done = subprocess.run(  # noqa: S603 — a fixed argument list, no shell
            ["sysctl", "-n", key],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=_QUERY_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def _windows_cpu_model() -> str:
    """The processor name the registry holds, or ``""``."""
    try:
        import winreg  # type: ignore[import-not-found]

        with winreg.OpenKey(  # type: ignore[attr-defined]
            winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined]
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        ) as key:
            value, _kind = winreg.QueryValueEx(key, "ProcessorNameString")  # type: ignore[attr-defined]
        return _text(value)
    except Exception:  # noqa: BLE001 — an unread fact is left out
        return ""


def _windows_memory_bytes() -> int | None:
    """Total physical memory as ``GlobalMemoryStatusEx`` reports it, or ``None``."""
    try:
        import ctypes

        class _Status(ctypes.Structure):
            _fields_ = [  # noqa: RUF012 — the structure's declared layout
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = _Status()
        status.dwLength = ctypes.sizeof(_Status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
            return None
        return int(status.ullTotalPhys) or None
    except Exception:  # noqa: BLE001 — an unread fact is left out
        return None


def _posix_memory_bytes() -> int | None:
    """Total physical memory from ``sysconf``, or ``None`` where it gives none."""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, ValueError, OSError):
        return None
    total = int(pages) * int(size)
    return total if total > 0 else None


# Where the control groups are mounted, where the hybrid layout mounts v2
# beside v1 controllers (under the root), and the value a v1 limit holds when
# none is set (the page counter's maximum, rounded to a page): any value at or
# above it is no limit.
_CGROUP_ROOT = "/sys/fs/cgroup"
_CGROUP_UNIFIED = "unified"
_V1_NO_LIMIT = 1 << 62


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _up_to(mount: str, path: str) -> list[str]:
    """``path``'s directory under ``mount``, then each parent's, the mount itself last."""
    parts = [p for p in path.split("/") if p and p != ".."]
    return [os.path.join(mount, *parts[:depth]) for depth in range(len(parts), -1, -1)]


def _cgroup_dirs() -> tuple[list[str], dict[str, list[str]]]:
    """The v2 directories of this process's group, its own first, then each parent up to
    the mount, under the v2 mount and the hybrid layout's; and per v1 controller, its
    directory, then each parent up to the controller's mount.

    Inside a namespace the path the kernel names may not exist under the mount;
    the parents, the mount among them, are still read."""
    v2: list[str] = []
    v1: dict[str, list[str]] = {}
    for line in _read_text("/proc/self/cgroup").splitlines():
        _id, _sep, rest = line.partition(":")
        controllers, _sep, path = rest.partition(":")
        path = path.strip() or "/"
        if not controllers:
            for mount in (_CGROUP_ROOT, os.path.join(_CGROUP_ROOT, _CGROUP_UNIFIED)):
                v2.extend(_up_to(mount, path))
            continue
        for controller in controllers.split(","):
            v1[controller] = _up_to(os.path.join(_CGROUP_ROOT, controller), path)
    return v2, v1


def _cpu_quota(v2: list[str], v1: dict[str, list[str]]) -> float | None:
    """The fewest processors a CPU quota of this process's groups allows, or ``None``."""
    quotas: list[float] = []
    for folder in v2:
        quota, _sep, period = _read_text(os.path.join(folder, "cpu.max")).partition(" ")
        q, p = _positive_int(quota), _positive_int(period)
        if q and p:
            quotas.append(q / p)
    for folder in v1.get("cpu", []):
        q = _positive_int(_read_text(os.path.join(folder, "cpu.cfs_quota_us")))
        p = _positive_int(_read_text(os.path.join(folder, "cpu.cfs_period_us")))
        if q and p:
            quotas.append(q / p)
    return min(quotas) if quotas else None


def _cpus_available() -> int | float | None:
    """The processors this process may use: its CPU affinity, held to its groups' quota."""
    affinity: int | None = None
    try:
        affinity = len(os.sched_getaffinity(0)) or None  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        affinity = None
    quota = _cpu_quota(*_cgroup_dirs())
    if quota is None:
        return affinity
    allowed = min(float(affinity), quota) if affinity else quota
    rounded = round(allowed, 2)
    return int(rounded) if rounded.is_integer() else rounded


def _memory_limit_bytes() -> int | None:
    """The lowest memory limit of this process's groups, or ``None`` where none is set."""
    v2, v1 = _cgroup_dirs()
    limits = [
        value
        for folder in v2
        if (value := _positive_int(_read_text(os.path.join(folder, "memory.max")))) is not None
    ]
    for folder in v1.get("memory", []):
        value = _positive_int(_read_text(os.path.join(folder, "memory.limit_in_bytes")))
        if value is not None and value < _V1_NO_LIMIT:
            limits.append(value)
    return min(limits) if limits else None


def _positive_int(text: str) -> int | None:
    try:
        value = int(text)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


@functools.lru_cache(maxsize=1)
def host_facts() -> dict[str, Any]:
    """The worker's host as it reads itself, each fact only where it is given. Never raises.

    ``os`` and ``os_release`` are the system and its release (the kernel's on
    Linux, the product version on macOS), ``os_version`` the build string,
    ``machine`` the machine type, ``cpu_model`` the processor's own name,
    ``logical_cpus`` the logical processors and ``memory_bytes`` the total
    physical memory, both as the kernel counts them for the whole machine.
    ``cpus_available`` is how many processors this process may use (its CPU
    affinity, held to a CPU quota of its control groups, a fraction where the
    quota is one) and ``memory_limit_bytes`` the memory limit of its control
    groups, each only where it is readable and, for the limit, where one is
    set: inside a container they are what the worker had, where the kernel's
    are the host's. Read once per process: none of them changes while it runs.
    """
    facts: dict[str, Any] = {}
    try:
        system = _text(platform.system())
        release = _text(platform.release())
        if sys.platform == "darwin":
            release = _text(platform.mac_ver()[0]) or release
        cpu_model, memory = "", None
        if sys.platform.startswith("linux"):
            cpu_model, memory = _linux_cpu_model(), _posix_memory_bytes()
        elif sys.platform == "darwin":
            cpu_model = _sysctl("machdep.cpu.brand_string")
            memory = _positive_int(_sysctl("hw.memsize"))
        elif sys.platform == "win32":
            cpu_model, memory = _windows_cpu_model(), _windows_memory_bytes()
        else:
            memory = _posix_memory_bytes()
        for key, value in (
            ("os", system),
            ("os_release", release),
            ("os_version", _text(platform.version())),
            ("machine", _text(platform.machine())),
            ("cpu_model", cpu_model or _text(platform.processor())),
            ("logical_cpus", os.cpu_count()),
            ("memory_bytes", memory),
            ("cpus_available", _cpus_available()),
            ("memory_limit_bytes", _memory_limit_bytes()),
        ):
            if value:
                facts[key] = value
    except Exception as exc:  # noqa: BLE001 — the host never fails a run
        logger.debug("run environment: the host was read in part (%s).", exc)
    return facts


def agents_record(
    sent: list[Any],
    response_models: dict[str, dict[str, int]],
    answered: dict[str, dict[int, int]] | None = None,
    reduced: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Per agent, what each model of its list was built to send and which models answered.

    ``sent`` is the registry's records in build order (``SentRequest``); a
    model built again (for another event loop) that sends the same is listed
    once. ``response_models``, ``answered`` and ``reduced`` are the token
    ledger's own maps (``response_models``, ``answers_by_position``,
    ``reduced_response_models``). Where ``answered`` is given, each row
    carries the answers recorded at its place in the list. An answer names
    its place, not which of the models built for that place gave it, so rows
    that share a place (a model built again that sends something else) each
    carry the place's total and say so (``answered_shared``); the total is
    counted once. Agents are keyed in lowercase on both sides, as the
    registry keys them.
    """
    out: dict[str, dict[str, Any]] = {}

    def _block(agent: Any) -> dict[str, Any]:
        return out.setdefault(str(agent).lower(), {"requests": [], "response_models": {}})

    for record in sent:
        row = record.as_dict()
        block = _block(record.agent)
        if row not in block["requests"]:
            block["requests"].append(row)
    for agent, models in (response_models or {}).items():
        held = _block(agent)["response_models"]
        for name, count in models.items():
            held[str(name)] = held.get(str(name), 0) + int(count)
    for agent, names in (reduced or {}).items():
        if names:
            _block(agent)["response_models_reduced"] = sorted({str(n) for n in names})
    if answered is not None:
        counts = {str(a).lower(): dict(by) for a, by in answered.items()}
        for agent, block in out.items():
            places = [int(row["position"]) for row in block["requests"]]
            for row in block["requests"]:
                row["answered"] = int(counts.get(agent, {}).get(int(row["position"]), 0))
                if places.count(int(row["position"])) > 1:
                    row["answered_shared"] = True
    for block in out.values():
        block["requests"].sort(key=lambda row: int(row.get("position") or 0))
        block["response_models"] = dict(sorted(block["response_models"].items()))
    return dict(sorted(out.items()))


def _ledger_map(ledger: Any, name: str) -> dict[str, Any] | None:
    """One of the token ledger's per-agent maps, or ``None`` where it keeps none."""
    read = getattr(ledger, name, None)
    held = read() if callable(read) else None
    return held if isinstance(held, dict) else None


def _field(entry: Any, name: str) -> str:
    value = entry.get(name) if isinstance(entry, dict) else getattr(entry, name, None)
    return _text(value)


def _served(
    container: Any, entries: Iterable[Any], own: Mapping[str, Mapping[str, Any]] | None = None
) -> tuple[dict[str, set[str]], list[str]]:
    """Per server, how it served the run; and the tools the pipeline ran in its own process.

    A tool or ledger entry names its server (``malspark_server``, ``server``)
    where the job's server registry stamped it. A provider's own server
    (``own``, by key, from ``own_tool_server``) stamps nothing: a tool or entry
    that names no server is its when its name is one of the tools that server
    served (``tools``); a name more than one such server served is none's.
    """
    claimed: dict[str, set[str]] = {}
    for key, held in (own or {}).items():
        names = held.get("tools") if isinstance(held, Mapping) else None
        for name in names if isinstance(names, list | tuple) else ():
            claimed.setdefault(_text(name), set()).add(key)
    owners = {name: next(iter(keys)) for name, keys in claimed.items() if len(keys) == 1}
    served: dict[str, set[str]] = {}
    tools_of = getattr(container, "setup_tools", None)
    set_up = tools_of() if callable(tools_of) else {}
    for tools in (set_up or {}).values():
        for tool in tools or ():
            server = _text((getattr(tool, "metadata", None) or {}).get("malspark_server"))
            server = server or owners.get(_text(getattr(tool, "name", None)), "")
            if server:
                served.setdefault(server, set()).add(SERVED_OFFERED)
    in_process: list[str] = []
    for entry in entries or ():
        server, tool = _field(entry, "server"), _field(entry, "tool")
        server = server or owners.get(tool, "")
        if server == PIPELINE:
            if tool and tool not in in_process:
                in_process.append(tool)
        elif server:
            how = SERVED_PACK_STEP if _field(entry, "agent") == PIPELINE else SERVED_CALLED
            served.setdefault(server, set()).add(how)
    return served, in_process


def _server_info(info: Any) -> dict[str, str] | str:
    """The name and version a server gave for itself (MCP ``serverInfo``), or ``"not reported"``."""
    held = {
        key: str(info[key])
        for key in ("name", "version")
        if isinstance(info, dict) and info.get(key)
    }
    return held or NOT_REPORTED


def _server_environ(directory: str, config: Any) -> dict[str, str]:
    """The environment the shipped sidecar ``directory`` is launched with, as this worker reads it.

    This process's, with what the launch hands it (``sidecar_needs.handed_env``)
    and the server block's own ``env`` over it, for the first enabled block of
    ``config`` that launches that sidecar; this process's alone when none
    does. The steps the pipeline runs in its own process for that server's
    tools read the same overlay (``pipeline.nodes._server_environ``).
    """
    from malspark.tools.sidecar_needs import handed_env, sidecar_of

    environ = dict(os.environ)
    servers = getattr(getattr(config, "mcp", None), "servers", None) or {}
    for block in servers.values() if isinstance(servers, dict) else ():
        try:
            if not getattr(block, "enabled", True) or sidecar_of(block) != directory:
                continue
            environ.update(handed_env(block, config))
            environ.update({str(k): str(v) for k, v in (getattr(block, "env", None) or {}).items()})
        except Exception:  # noqa: BLE001, S112 — an unreadable block adds nothing
            continue
        break
    return environ


def _in_process_requirements(container: Any, tools: list[str]) -> list[dict[str, Any]]:
    """What the shipped declarations of ``tools`` require, read on this process's host.

    A step the pipeline runs in its own process calls the code a shipped
    sidecar serves under the same tool name, so its requirements are that
    tool's declaration (``tools.sidecar_needs``), the first that declares the
    name, as ``sidecar_needs.without_reads`` looks one up for a pack step. A
    data path is read as the worker reads it, the core setting first, with
    the environment of the server the step stands in for
    (:func:`_server_environ`). Each step's own entry names the data it ran
    with (``tools.capabilities.data_used``).
    """
    from malspark.tools.capabilities import requirement_facts
    from malspark.tools.sidecar_needs import BY_DIRECTORY

    config = getattr(container, "config", None)
    wanted = set(tools)
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for directory, declared in BY_DIRECTORY.items():
        needs = []
        for need in declared:
            if need.name in wanted and need.requires:
                needs.append(need)
                wanted.discard(need.name)
        if not needs:
            continue
        for row in requirement_facts(needs, _server_environ(directory, config), config):
            key = (str(row.get("kind")), str(row.get("name")))
            if key in rows:
                rows[key]["tools"].extend(t for t in row["tools"] if t not in rows[key]["tools"])
            else:
                rows[key] = row
    return list(rows.values())


def _own_servers(container: Any) -> dict[str, dict[str, Any]]:
    """The tool servers the job's providers drive through handles of their own, by key.

    Each provider's ``own_tool_server`` (``providers.base.ServerOfItsOwn``):
    the static providers this job built and its sandbox provider.
    """
    providers: list[Any] = list((getattr(container, "_static_provider_cache", None) or {}).values())
    sandbox = getattr(container, "_sandbox_provider_cache", None)
    if sandbox is not None:
        providers.append(sandbox)
    out: dict[str, dict[str, Any]] = {}
    for provider in providers:
        read = getattr(provider, "own_tool_server", None)
        try:
            held = read() if callable(read) else None
        except Exception:  # noqa: BLE001, S112 — a provider that cannot say is left out
            continue
        if isinstance(held, dict) and _text(held.get("server")):
            out.setdefault(_text(held.get("server")), held)
    return out


def tools_record(container: Any, entries: Iterable[Any] = ()) -> dict[str, Any]:
    """Per tool server that served the run, what it ran. Never raises.

    A server is listed when the job's server registry attached it, or a
    provider attached it through a handle of its own (``own_tool_server``);
    a name a tool carries that no handle backs (an agent-to-agent delegation)
    is no tool server and is not listed. Each row says how the server served
    the run: the run offered one of its tools to an agent (``offered``: its
    tools carried the server, ``malspark_server``), an agent called one
    (``called``) or a pack step did (``pack_step``), each read from the job's
    setup and its ledger ``entries``; a provider's own server is read from
    the names of the tools it served (``own_tool_server``), since its tools
    and entries carry no server. A server attached and neither offered nor
    called is ``attached``. The steps the pipeline ran in its own process
    are the row ``pipeline`` (``in_process``). Each server row holds
    ``server_info``, the name and version the server gave at its attach (the
    reading ``efficiency.fingerprint.parts.servers`` holds too), the version
    its capability manifest gives (``manifest_version``) and its
    ``requirements`` as the manifest reports them, reduced to the known keys
    and capped (``tools.capabilities.reported_requirements``); a fact the
    server did not give is ``"not reported"``. Where the registry and a
    provider both name a server, the registry's reading is kept.
    """
    try:
        from malspark.tools.capabilities import package_version, reported_requirements

        own_servers = _own_servers(container)
        served, in_process = _served(container, entries, own_servers)
        registry = getattr(container, "_server_registry_cache", None)
        versions_of = getattr(registry, "server_versions", None)
        versions = dict(versions_of()) if callable(versions_of) else {}
        setup_of = getattr(container, "setup_server_versions", None)
        if callable(setup_of):
            versions.update(setup_of())
        manifests_of = getattr(registry, "server_manifests", None)
        manifests = dict(manifests_of()) if callable(manifests_of) else {}
        for server, own in own_servers.items():
            if server not in versions and server not in manifests:
                versions[server] = own.get("server_info") or {}
                if isinstance(own.get("manifest"), dict):
                    manifests[server] = own["manifest"]
        out: dict[str, dict[str, Any]] = {}
        for server in sorted({*versions, *manifests}):
            held = manifests.get(server)
            row: dict[str, Any] = {
                "served": sorted(served.get(server) or {SERVED_ATTACHED}),
                "server_info": _server_info(versions.get(server)),
            }
            if isinstance(held, dict):
                row["manifest_version"] = _text(held.get("version")) or NOT_REPORTED
                requirements = reported_requirements(held.get("requirements"))
                row["requirements"] = NOT_REPORTED if requirements is None else requirements
            else:
                row["manifest_version"] = NOT_REPORTED
                row["requirements"] = NOT_REPORTED
            out[server] = row
        if in_process:
            out[PIPELINE] = {
                "served": [SERVED_IN_PROCESS],
                "package_version": package_version(),
                "requirements": _in_process_requirements(container, in_process),
            }
        return dict(sorted(out.items()))
    except Exception as exc:  # noqa: BLE001 — telemetry never breaks a summary
        logger.debug("run environment: the tools were not recorded (%s).", exc)
        return {}


def environment_record(container: Any, entries: Iterable[Any] = ()) -> dict[str, Any] | None:
    """``run_summary.environment`` as of now, or ``None`` where nothing was read. Never raises.

    ``entries`` is the run's evidence ledger, which names the servers a pack
    step or an agent called (``tools_record``).
    """
    try:
        record: dict[str, Any] = {"v": ENVIRONMENT_VERSION}
        host = host_facts()
        if host:
            record["host"] = dict(host)
        tools = tools_record(container, entries)
        if tools:
            record["tools"] = tools
        registry = getattr(container, "_llm_registry", None)
        sent_of = getattr(registry, "sent_requests", None)
        sent = list(sent_of()) if callable(sent_of) else []
        ledger_of = getattr(container, "get_token_ledger", None)
        ledger = ledger_of() if callable(ledger_of) else None
        agents = agents_record(
            sent,
            _ledger_map(ledger, "response_models") or {},
            _ledger_map(ledger, "answers_by_position"),
            _ledger_map(ledger, "reduced_response_models"),
        )
        if agents:
            record["agents"] = agents
        return record if len(record) > 1 else None
    except Exception as exc:  # noqa: BLE001 — telemetry never breaks a summary
        logger.debug("run environment: not recorded (%s).", exc)
        return None
