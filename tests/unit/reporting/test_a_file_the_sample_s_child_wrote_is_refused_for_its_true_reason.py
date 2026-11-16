"""A file the sample's child wrote is the sample's tree's; a refusal of it says its true reason.

A sandbox report that holds several tasks gives each task's processes ids of
the task's own, and names a written file's writer by that id, or only by the
guest's pid. The export reads the writer as one process (``schemas.
process_identity``): its task and the report's id, the guest's pid an alias,
and the sample's tree per task (``sample_process_trees``). A writer the tree of
its task holds is the sample's, so its file is withheld only because the
judge named no such indicator; one the listing places outside the tree is
outside; one whose number the listing does not settle is unattributed; and one
whose number no listed process answers to, where every listed process it
could name (its task's, where it states one) states its guest pid, is said to
be named so, never placed outside a tree it was not tested against; where one
of them states none, such a number may be its guest pid, and the writer is
unattributed. The process tree the report
is built from keeps each process's task and the guest's pid any answer of the
run states for it.

Every value is synthetic.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.ledger_projection import dynamic_from_ledger
from malspark.reporting.models import DynamicBehavior, ProcessNode
from malspark.reporting.renderers.stix_renderer import (
    HOST_ROW_OUTSIDE_THE_TREE,
    HOST_ROW_UNLISTED,
    UNATTRIBUTED_HOST_ROW,
    sandbox_facts_for_the_judge,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.sandbox_report import sample_process_trees

SAMPLE = "a1b2c3.exe"
DIGEST = "5cd55b0775d76e715b840827d0f3201470df24f2230dce71c7313de7f41761a7"
NOT_HELD = (
    "the sandbox report names the process that wrote it by a number its process list does not hold"
)


def _node(pid: int, name: str, ppid: int, task: str = "", **more: Any) -> ProcessNode:
    return ProcessNode(pid=pid, ppid=ppid, name=name, task=task, **more)


def _two_tasks() -> list[ProcessNode]:
    """Two tasks of one report, each the sample starting defrag.exe; id 87 is in both."""
    return [
        _node(85, SAMPLE, 56, "t1", children=[_node(87, "defrag.exe", 85, "t1", marked=True)]),
        _node(87, SAMPLE, 81, "t2", children=[_node(89, "defrag.exe", 87, "t2", marked=True)]),
    ]


def _every_guest_pid_stated() -> list[ProcessNode]:
    """:func:`_two_tasks` with every process's guest pid stated."""
    processes = _two_tasks()
    for root, guests in zip(processes, (("1496", "1924"), ("3756", "4156")), strict=True):
        root.guest_pid, root.children[0].guest_pid = guests
    return processes


def _fact(processes: list[ProcessNode], **writer: Any) -> str:
    dynamic = DynamicBehavior(
        process_tree=processes,
        file_operations=[{"operation": "write", "name": "a.dat", "sha256": DIGEST, **writer}],
    )
    ask = sandbox_facts_for_the_judge(None, dynamic, sample={"file_name": SAMPLE})
    return str(ask("hash", DIGEST))


class TestTheTreeIsReadPerTask:
    def test_each_task_has_its_own_tree(self) -> None:
        trees = sample_process_trees(_two_tasks(), SAMPLE)

        assert trees.by_task["t1"].pids == {"87"}
        assert trees.by_task["t2"].pids == {"89"}

    def test_a_listing_with_no_task_is_one_tree_as_it_was(self) -> None:
        roots = [_node(10, SAMPLE, 1, children=[_node(11, "cmd.exe", 10)])]

        assert sample_process_trees(roots, SAMPLE).by_task[""].pids == {"10", "11"}


class TestTheWriterIsOneProcess:
    def test_the_sample_s_child_named_by_its_task_and_id_is_the_sample_s(self) -> None:
        assert _fact(_two_tasks(), pids=["87"], task="t1") == ""

    def test_the_sample_s_child_named_by_its_guest_pid_alone_is_the_sample_s(self) -> None:
        processes = _two_tasks()
        processes[0].children[0].guest_pid = "1924"

        assert _fact(processes, pids=["1924"]) == ""

    def test_an_id_two_tasks_list_named_without_its_task_is_unattributed(self) -> None:
        assert _fact(_two_tasks(), pids=["87"]) == UNATTRIBUTED_HOST_ROW.format(did="wrote")

    def test_a_number_no_listed_process_answers_to_is_said_to_be_so(self) -> None:
        processes = _every_guest_pid_stated()

        assert _fact(processes, pids=["1928"]) == HOST_ROW_UNLISTED.format(did="wrote")
        assert HOST_ROW_UNLISTED.format(did="wrote") == NOT_HELD

    def test_where_the_listing_states_no_guest_pid_the_writer_is_unattributed(self) -> None:
        assert _fact(_two_tasks(), pids=["1924"]) == UNATTRIBUTED_HOST_ROW.format(did="wrote")

    def test_where_one_process_states_no_guest_pid_the_number_may_be_its(self) -> None:
        processes = _every_guest_pid_stated()
        processes[0].children[0].guest_pid = ""

        assert _fact(processes, pids=["1928"]) == UNATTRIBUTED_HOST_ROW.format(did="wrote")
        assert _fact(processes, pids=["1928"], task="t1") == UNATTRIBUTED_HOST_ROW.format(
            did="wrote"
        )

    def test_a_record_s_task_is_read_alone_where_it_states_one(self) -> None:
        processes = _every_guest_pid_stated()
        processes[1].children[0].guest_pid = ""

        assert _fact(processes, pids=["1928"], task="t1") == HOST_ROW_UNLISTED.format(did="wrote")
        assert _fact(processes, pids=["1928"], task="t2") == UNATTRIBUTED_HOST_ROW.format(
            did="wrote"
        )
        assert _fact(processes, pids=["1928"]) == UNATTRIBUTED_HOST_ROW.format(did="wrote")

    def test_a_task_the_listing_does_not_hold_states_no_guest_pid(self) -> None:
        assert _fact(_every_guest_pid_stated(), pids=["1928"], task="t9") == (
            UNATTRIBUTED_HOST_ROW.format(did="wrote")
        )

    def test_an_id_a_task_lists_twice_names_no_writer_by_any_number(self) -> None:
        processes = _two_tasks()
        processes[0].children[0].children = [
            _node(900, "x.exe", 87, "t1", guest_pid="1500"),
            _node(900, "y.exe", 87, "t1", guest_pid="1504"),
        ]
        unattributed = UNATTRIBUTED_HOST_ROW.format(did="wrote")

        assert _fact(processes, pids=["900"], task="t1") == unattributed
        assert _fact(processes, pids=["1500"]) == unattributed

    def test_a_listed_process_outside_the_tree_is_outside(self) -> None:
        processes = [*_two_tasks(), _node(40, "svchost.exe", 4, "t1")]

        assert _fact(processes, pids=["40"], task="t1") == HOST_ROW_OUTSIDE_THE_TREE

    def test_a_listed_writer_outside_the_tree_beside_an_unlisted_number_is_outside(self) -> None:
        processes = [*_every_guest_pid_stated(), _node(40, "svchost.exe", 4, "t1", guest_pid="700")]

        assert _fact(processes, pids=["40", "1928"], task="t1") == HOST_ROW_OUTSIDE_THE_TREE

    def test_a_disputed_writer_is_unattributed_as_it_was(self) -> None:
        # 85 runs the submitted file and carries no mark: the two facts disagree.
        assert _fact(_two_tasks(), pids=["85"], task="t1") == UNATTRIBUTED_HOST_ROW.format(
            did="wrote"
        )


class TestTheTreeTheReportIsBuiltFromKeepsTheIdentity:
    @staticmethod
    def _ledger() -> list[LedgerEntry]:
        rows = [
            {"pid": 85, "ppid": 56, "name": SAMPLE, "task": "t1"},
            {"pid": 87, "ppid": 85, "name": "defrag.exe", "task": "t1", "marked": True},
            {"pid": 87, "ppid": 81, "name": SAMPLE, "task": "t2"},
            {"pid": 89, "ppid": 87, "name": "defrag.exe", "task": "t2", "marked": True},
        ]
        indicators = [
            {
                "signature": "Writes into another process",
                "task": "t1",
                "process": {"id": "85", "guest_pid": "1496"},
                "target": {"id": "87", "guest_pid": "1924"},
            }
        ]
        return [
            LedgerEntry(id="ev_0001", tool="sandbox_processes", structured={"processes": rows}),
            LedgerEntry(
                id="ev_0002", tool="sandbox_signatures", structured={"indicators": indicators}
            ),
            LedgerEntry(
                id="ev_0003",
                tool="sandbox_dropped_files",
                structured={"dropped": [{"name": "a.dat", "sha256": DIGEST, "pids": ["1924"]}]},
            ),
        ]

    def test_a_child_is_nested_under_its_parent_of_its_own_task(self) -> None:
        dynamic = dynamic_from_ledger(self._ledger())
        assert dynamic is not None

        (first, second) = dynamic.process_tree
        assert (first.pid, first.task, [c.pid for c in first.children]) == (85, "t1", [87])
        assert (second.pid, second.task, [c.pid for c in second.children]) == (87, "t2", [89])

    def test_a_process_keeps_the_guest_pid_an_indicator_states(self) -> None:
        dynamic = dynamic_from_ledger(self._ledger())
        assert dynamic is not None

        first = dynamic.process_tree[0]
        assert (first.guest_pid, first.children[0].guest_pid) == ("1496", "1924")
        assert dynamic.process_tree[1].guest_pid == ""

    def test_a_process_listing_s_own_guest_pid_is_kept(self) -> None:
        ledger = self._ledger()
        ledger[0].structured["processes"][2]["guest_pid"] = "3756"

        dynamic = dynamic_from_ledger(ledger)
        assert dynamic is not None
        assert dynamic.process_tree[1].guest_pid == "3756"

    def test_a_stored_row_named_by_the_guest_pid_is_the_sample_s_tree_s(self) -> None:
        dynamic = dynamic_from_ledger(self._ledger())
        ask = sandbox_facts_for_the_judge(None, dynamic, sample={"file_name": SAMPLE})

        assert ask("hash", DIGEST) == ""
