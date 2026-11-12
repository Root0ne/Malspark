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
  built): the sampling parameters and thinking switches its provider adapter
  read off the request body the client would send, the statement that no
  sampling parameter was sent and the provider's default applied, or the
  statement that the adapter reported nothing; the effort level sent and the
  setting it came from, or why none was; and how many calls that model
  answered (``answered``; a fallback that was never needed answered none).
  Beside the rows, each model identifier the provider's answers carried and
  how many answers carried it (``TokenLedger.response_models``), an
  identifier shaped like a file-system path kept by its base name and listed
  in ``response_models_reduced``. An agent whose answers carried none has an
  empty map.

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
from typing import Any

from malspark.core.logger import logger

# The record's shape version: a reader that meets a newer one reads what it
# knows. 2: a row's ``sampling`` may be ``None`` (not reported), and rows carry
# ``thinking`` and ``answered``.
ENVIRONMENT_VERSION = 2

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


# Where the control groups are mounted, and the value a v1 limit holds when
# none is set (the page counter's maximum, rounded to a page): any value at or
# above it is no limit.
_CGROUP_ROOT = "/sys/fs/cgroup"
_V1_NO_LIMIT = 1 << 62


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _cgroup_dirs() -> tuple[list[str], dict[str, list[str]]]:
    """The v2 directories of this process's group, its own first, then each parent up to
    the mount; and per v1 controller, its directory and the controller's mount root."""
    v2: list[str] = []
    v1: dict[str, list[str]] = {}
    for line in _read_text("/proc/self/cgroup").splitlines():
        _id, _sep, rest = line.partition(":")
        controllers, _sep, path = rest.partition(":")
        path = path.strip() or "/"
        if not controllers:
            parts = [p for p in path.split("/") if p and p != ".."]
            while True:
                v2.append(os.path.join(_CGROUP_ROOT, *parts))
                if not parts:
                    break
                parts.pop()
            continue
        for controller in controllers.split(","):
            mount = os.path.join(_CGROUP_ROOT, controller)
            v1[controller] = [os.path.join(mount, *[p for p in path.split("/") if p]), mount]
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
            break
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
            break
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
    carries the calls the model at its place in the list answered. Agents are
    keyed in lowercase on both sides, as the registry keys them.
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
            for row in block["requests"]:
                row["answered"] = int(counts.get(agent, {}).get(int(row["position"]), 0))
    for block in out.values():
        block["requests"].sort(key=lambda row: int(row.get("position") or 0))
        block["response_models"] = dict(sorted(block["response_models"].items()))
    return dict(sorted(out.items()))


def _ledger_map(ledger: Any, name: str) -> dict[str, Any] | None:
    """One of the token ledger's per-agent maps, or ``None`` where it keeps none."""
    read = getattr(ledger, name, None)
    held = read() if callable(read) else None
    return held if isinstance(held, dict) else None


def environment_record(container: Any) -> dict[str, Any] | None:
    """``run_summary.environment`` as of now, or ``None`` where nothing was read. Never raises."""
    try:
        record: dict[str, Any] = {"v": ENVIRONMENT_VERSION}
        host = host_facts()
        if host:
            record["host"] = dict(host)
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
