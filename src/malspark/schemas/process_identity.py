"""A process's identity, read in one place: its task and the report's id, the guest's pid an alias.

A sandbox report that holds several tasks gives each task's processes ids of
the task's own, so one id can name two processes; and a sandbox that lists its
processes by an id of its own names the guest's pid beside it, another number
for the same process. Every surface that names a process reads it here: the
evidence roots a signature's indicator gives, the dropped-files view's writer,
the sample's process tree and the export's host rows.

A number names the one process whose id, or whose guest's pid, it is, in the
task where one is stated (:meth:`ProcessIdentities.resolve`); a number more
than one process answers to names none, and neither does one no process
answers to. Nothing is guessed: an id a task lists twice, or an indicator's
process the report does not settle, adds no identity.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from malspark.schemas.sandbox_document import pid_of

# How a process a listing's id names in more than one task is written: its id
# and the task it is listed in.
IN_TASK = "{id} in task {task}"
# The keys an answer's row states a process's id, its task and the guest's
# pid under: a process listing's row (``pid``) and a signature indicator's
# process (``id``, resolved by ``providers.sandbox_tools.SignatureIndicators``).
_ID_KEYS = ("pid", "id")
TASK_KEY = "task"
GUEST_PID_KEY = "guest_pid"
# What an indicator's process states where the report does not settle it.
_UNSETTLED_KEYS = ("not_settled", "not_listed")
# Where an indicator names the process that acted and the one acted on.
_INDICATOR_PROCESSES = ("process", "target")


@dataclass(frozen=True, order=True)
class ProcessKey:
    """One process: the task the report lists it in (``""`` where it states none) and its id."""

    task: str
    id: str


@dataclass
class ProcessIdentities:
    """Every process the answers of one run name, by id and by the guest's pid.

    Linear in what it reads: each process is added once, and a number is
    looked up in two maps.
    """

    _by_id: dict[str, dict[ProcessKey, None]] = field(default_factory=dict)
    _by_guest: dict[str, dict[ProcessKey, None]] = field(default_factory=dict)
    _guest_of: dict[ProcessKey, str] = field(default_factory=dict)

    def add(self, pid: Any, *, task: Any = "", guest_pid: Any = "") -> ProcessKey | None:
        """The process ``pid`` names in ``task``, with its guest's pid where one is stated."""
        number = pid_of(pid)
        if not number:
            return None
        key = ProcessKey(str(task or ""), number)
        self._by_id.setdefault(number, {})[key] = None
        guest = pid_of(guest_pid)
        if guest:
            self._by_guest.setdefault(guest, {})[key] = None
            self._guest_of.setdefault(key, guest)
        return key

    def keys(self, number: Any, task: str | None = None) -> list[ProcessKey]:
        """Every process ``number`` is the id or the guest's pid of, in ``task`` where given."""
        text = pid_of(number)
        if not text:
            return []
        held = {**self._by_id.get(text, {}), **self._by_guest.get(text, {})}
        return sorted(key for key in held if task is None or key.task == task)

    def resolve(self, number: Any, task: str | None = None) -> ProcessKey | None:
        """The one process ``number`` names (in ``task`` if given); ``None`` for none or several."""
        found = self.keys(number, task)
        return found[0] if len(found) == 1 else None

    def guest_of(self, key: ProcessKey) -> str:
        """The guest's pid an answer states for ``key``, ``""`` where none does."""
        return self._guest_of.get(key, "")

    def written(self, key: ProcessKey) -> str:
        """``key`` as a root names it: its id, with its task where another task lists the id too."""
        tasks = {held.task for held in self._by_id.get(key.id, {})}
        return IN_TASK.format(id=key.id, task=key.task) if len(tasks) > 1 else key.id

    def read_answer(
        self, data: Any, indicator_paths: Iterable[str], *, listing: bool = False
    ) -> None:
        """The processes an answer names: its indicators at dotted paths, its rows if a listing.

        ``listing``: the answer is a process listing (``processes`` rows), as
        its tool's kind declares; no other answer's rows are read as one.
        """
        if not isinstance(data, Mapping):
            return
        for row in data.get("processes") or [] if listing else ():
            if isinstance(row, Mapping):
                self.add(_id_of(row), task=row.get(TASK_KEY), guest_pid=row.get(GUEST_PID_KEY))
        for path in indicator_paths:
            for indicator in held_at_path(data, path):
                for process, task in indicator_processes(indicator):
                    self.add(_id_of(process), task=task, guest_pid=process.get(GUEST_PID_KEY))


def held_at_path(data: Any, path: str) -> list[Any]:
    """The items of the lists a dotted ``path`` names in ``data`` (``*``: each list element)."""
    nodes: list[Any] = [data]
    parts = [part for part in path.split(".") if part]
    for part in parts:
        step: list[Any] = []
        for node in nodes:
            if part == "*" and isinstance(node, list):
                step.extend(node)
            elif part != "*" and isinstance(node, Mapping) and part in node:
                step.append(node[part])
        nodes = step
    out: list[Any] = []
    for node in nodes:
        out.extend(node if isinstance(node, list) else ())
    return out


def indicator_processes(indicator: Any) -> list[tuple[Mapping[str, Any], str]]:
    """``(process, task)`` for each process an indicator names that the report settles.

    The acting process first, then the one acted on; an indicator's process
    the report does not list, or lists more than once, is none.
    """
    if not isinstance(indicator, Mapping):
        return []
    task = str(indicator.get(TASK_KEY) or "")
    out: list[tuple[Mapping[str, Any], str]] = []
    for name in _INDICATOR_PROCESSES:
        process = indicator.get(name)
        if not isinstance(process, Mapping) or any(process.get(k) for k in _UNSETTLED_KEYS):
            continue
        if pid_of(_id_of(process)):
            out.append((process, task))
    return out


def _id_of(row: Mapping[str, Any]) -> Any:
    """The id a row states its process under (:data:`_ID_KEYS`), ``None`` where it states none."""
    return next((row[key] for key in _ID_KEYS if row.get(key) not in (None, "")), None)
