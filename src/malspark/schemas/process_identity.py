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
answers to. Nothing is guessed: an id one listing holds twice in a task names
no process by any number (:meth:`ProcessIdentities.add_listing`), an
indicator's process the report does not settle adds no identity, and a row
that states no task is read against the tasks the record lists: the one task
that holds its id, or none where several do.
"""

from __future__ import annotations

from collections import Counter
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
    # A process two answers state two guest pids for: neither is its guest's
    # pid, though each still names it.
    _guest_disputed: set[ProcessKey] = field(default_factory=set)
    # The (task, id) pairs one listing holds more than once: two processes.
    _twice: set[ProcessKey] = field(default_factory=set)
    # Whether every process of a task (``None``: of every task) states its
    # guest's pid, asked once per task until a process is added.
    _every_guest: dict[str | None, bool] = field(default_factory=dict)

    def add(self, pid: Any, *, task: Any = "", guest_pid: Any = "") -> ProcessKey | None:
        """The process ``pid`` names in ``task``, with its guest's pid where one is stated."""
        number = pid_of(pid)
        if not number:
            return None
        key = ProcessKey(str(task or ""), number)
        self._by_id.setdefault(number, {})[key] = None
        self._every_guest.clear()
        guest = pid_of(guest_pid)
        if guest:
            self._by_guest.setdefault(guest, {})[key] = None
            if self._guest_of.setdefault(key, guest) != guest:
                self._guest_disputed.add(key)
        return key

    def add_listing(self, rows: Iterable[tuple[Any, Any, Any]]) -> list[ProcessKey | None]:
        """The processes one listing's rows name, each ``(id, task, guest's pid)``, in order.

        An id the listing holds twice in one task is two processes, and the
        number names neither; the same process listed by two answers (two
        pages, a call repeated) is one.
        """
        keys = [self.add(pid, task=task, guest_pid=guest) for pid, task, guest in rows]
        held = Counter(key for key in keys if key is not None)
        self._twice.update(key for key, count in held.items() if count > 1)
        return keys

    def twice(self, key: ProcessKey) -> bool:
        """Whether a listing holds ``key``'s id twice in its task: no one process."""
        return key in self._twice

    def _tasked(self, number: str) -> list[ProcessKey]:
        return [key for key in self._by_id.get(number, {}) if key.task]

    def _as_listed(self, key: ProcessKey) -> list[ProcessKey]:
        """``key`` read against the tasks the record lists: a task-less row is its id's tasks'."""
        if key.task:
            return [key]
        return self._tasked(key.id) or [key]

    def keys(self, number: Any, task: str | None = None, *, alias: bool = True) -> list[ProcessKey]:
        """Every process ``number`` is the id (or, with ``alias``, the guest's pid) of.

        In ``task`` where given. A row that states no task names the process
        of its id in each task that lists the id; a pair one listing holds
        twice is listed twice, two processes.
        """
        text = pid_of(number)
        if not text:
            return []
        held = dict(self._by_id.get(text, {}))
        if alias:
            held.update(self._by_guest.get(text, {}))
        found = {one for key in held for one in self._as_listed(key)}
        out = sorted(key for key in found if task is None or key.task == task)
        return sorted(out + [key for key in out if key in self._twice])

    def resolve(
        self, number: Any, task: str | None = None, *, alias: bool = True
    ) -> ProcessKey | None:
        """The one process ``number`` names (in ``task`` if given); ``None`` for none or several."""
        found = self.keys(number, task, alias=alias)
        return found[0] if len(found) == 1 else None

    def states_every_guest_pid(self, task: str | None = None) -> bool:
        """Whether every listed process a record could name states its guest's pid.

        Those of ``task`` where the record states one, else every listed
        process; a row that states no task is read as its listed process
        (:meth:`guest_of`'s rule). A task no process is listed in states none.
        Read once per task.
        """
        held = self._every_guest.get(task)
        if held is None:
            named = {
                one
                for keys in self._by_id.values()
                for key in keys
                for one in self._as_listed(key)
                if task is None or one.task == task
            }
            held = bool(named) and all(self._states_guest(key) for key in named)
            self._every_guest[task] = held
        return held

    def _states_guest(self, key: ProcessKey) -> bool:
        """Whether an answer states a guest's pid for ``key``, two differing ones included."""
        held = [key, ProcessKey("", key.id)] if key.task else [key]
        return any(one in self._guest_of and self._as_listed(one) == [key] for one in held)

    def aliased(self, guest_pid: Any) -> list[str]:
        """The report's ids of the processes whose guest's pid is ``guest_pid``, other than it."""
        text = pid_of(guest_pid)
        ids = (key.id for key in self._by_guest.get(text, {}) if key.id != text)
        return list(dict.fromkeys(ids))

    def guest_of(self, key: ProcessKey) -> str:
        """The guest's pid an answer states for ``key``, ``""`` where none does or two differ."""
        held = [key, ProcessKey("", key.id)] if key.task else [key]
        for one in held:
            if one in self._guest_of and self._as_listed(one) == [key]:
                return "" if one in self._guest_disputed else self._guest_of[one]
        return ""

    def written(self, key: ProcessKey) -> str:
        """``key`` as a root names it: its id, with its task where another task lists the id too.

        A process of no task is its id alone: a task is never written empty.
        """
        tasks = {held.task for held in self._tasked(key.id)}
        return IN_TASK.format(id=key.id, task=key.task) if key.task and len(tasks) > 1 else key.id

    def read_answer(
        self, data: Any, indicator_paths: Iterable[str], *, listing: bool = False
    ) -> None:
        """The processes an answer names: its indicators at dotted paths, its rows if a listing.

        ``listing``: the answer is a process listing (``processes`` rows), as
        its tool's kind declares; no other answer's rows are read as one.
        """
        if not isinstance(data, Mapping):
            return
        if listing:
            self.add_listing(
                (_id_of(row), row.get(TASK_KEY), row.get(GUEST_PID_KEY))
                for row in data.get("processes") or []
                if isinstance(row, Mapping)
            )
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
