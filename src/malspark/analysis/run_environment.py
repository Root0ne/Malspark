"""The environment a run ran in, recorded by code so a reader states it without guessing.

``run_summary.environment`` is built by :func:`environment_record` from the
job's own records, never from a model and never from what a setting says
should happen:

* ``host`` is the worker's host as it reads itself (:func:`host_facts`): the
  operating system and its release, the machine type, the processor model,
  the logical processors and the total memory. A fact the host does not give
  is left out, and reading the host never fails the run.
* ``agents`` is, per agent, what each model of its list sent with every
  request (``llm.sent_request``, kept by the registry as each model is built):
  the sampling parameters read off the built model, or the statement that none
  was sent and the provider's default applied; the effort level sent and the
  setting it came from, or why none was; and, beside them, each model
  identifier the provider's answers carried and how many answers carried it
  (``TokenLedger.response_models``). An agent whose answers carried none has
  an empty map.

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

# The record's shape version: a reader that meets a newer one reads what it knows.
ENVIRONMENT_VERSION = 1

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
    physical memory. Read once per process: none of them changes while it runs.
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
        ):
            if value:
                facts[key] = value
    except Exception as exc:  # noqa: BLE001 — the host never fails a run
        logger.debug("run environment: the host was read in part (%s).", exc)
    return facts


def agents_record(sent: list[Any], response_models: dict[str, dict[str, int]]) -> dict[str, Any]:
    """Per agent, what each model of its list sent and which models its answers named.

    ``sent`` is the registry's records in build order (``SentRequest``); a
    model built again (for another event loop) that sends the same is listed
    once. ``response_models`` is the token ledger's own map.
    """
    out: dict[str, dict[str, Any]] = {}
    for record in sent:
        row = record.as_dict()
        block = out.setdefault(str(record.agent), {"requests": [], "response_models": {}})
        if row not in block["requests"]:
            block["requests"].append(row)
    for agent, models in (response_models or {}).items():
        block = out.setdefault(str(agent), {"requests": [], "response_models": {}})
        block["response_models"] = {str(k): int(v) for k, v in models.items()}
    for block in out.values():
        block["requests"].sort(key=lambda row: int(row.get("position") or 0))
    return dict(sorted(out.items()))


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
        models_of = getattr(ledger, "response_models", None)
        models = models_of() if callable(models_of) else {}
        agents = agents_record(sent, models if isinstance(models, dict) else {})
        if agents:
            record["agents"] = agents
        return record if len(record) > 1 else None
    except Exception as exc:  # noqa: BLE001 — telemetry never breaks a summary
        logger.debug("run environment: not recorded (%s).", exc)
        return None
