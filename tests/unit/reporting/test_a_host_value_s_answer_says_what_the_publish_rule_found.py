"""A host value's refusal says what the publish rule found in the records it read, never more.

A file, a digest, a key or a mutex the sandbox recorded is refused unless a
record of it names a process of the sample's tree. The refusal says what the
publish rule found, over every record of the value it read: no process at all,
or each number those records name (as a pid is read: ``0`` and text are none),
by its field and its task, with what the rule found for it — matched to no
process of the process list it read where that list states a guest pid for
every process, undecided where it does not, not placed in or outside the tree,
or matched to a listed process. It never states what the whole report says, so
a record the rule did not read, or a further detonation's own listing, cannot
contradict it. The decision is the one it was: no record of the tree, no
publish. No "," or ";" stands outside brackets.

Every value is synthetic.
"""

from __future__ import annotations

import re
from typing import Any

from malspark.pipeline.validation import _states_publish_state
from malspark.reporting.models import DynamicBehavior, ProcessNode
from malspark.reporting.publish_parts import refused
from malspark.reporting.renderers.stix_renderer import sandbox_facts_for_the_judge

SAMPLE = "a1b2c3.exe"
DIGEST = "5c" * 32
NONE_FOUND = "the publish rule found no process that wrote it"
NOT_PLACED = "the publish rule could not place the process that wrote it ({})"
UNDECIDED = (
    "it could not decide whether {} since the process list it read does not state a guest pid "
    "for every process"
)


def _listing(*, every_guest_pid: bool = False) -> list[ProcessNode]:
    """The sample (85) starting defrag.exe (87); with every guest pid stated or none."""
    child = ProcessNode(pid=87, ppid=85, name="defrag.exe", marked=True)
    root = ProcessNode(pid=85, ppid=56, name=SAMPLE, children=[child])
    if every_guest_pid:
        root.guest_pid, child.guest_pid = "1496", "1924"
    return [root]


def _twice() -> list[ProcessNode]:
    """:func:`_listing` with id 900 listed twice under the sample: the number names neither."""
    processes = _listing()
    processes[0].children += [
        ProcessNode(pid=900, ppid=85, name="x.exe"),
        ProcessNode(pid=900, ppid=85, name="y.exe"),
    ]
    return processes


def _fact(processes: list[ProcessNode], *rows: dict[str, Any]) -> str:
    writes = [{"operation": "write", "name": "a.dat", "sha256": DIGEST, **row} for row in rows]
    dynamic = DynamicBehavior(process_tree=processes, file_operations=writes)
    ask = sandbox_facts_for_the_judge(None, dynamic, sample={"file_name": SAMPLE})
    return str(ask("hash", DIGEST))


def _outside_brackets(text: str) -> str:
    depth, kept = 0, []
    for char in text:
        depth += char == "("
        if depth == 0:
            kept.append(char)
        depth -= char == ")" and depth > 0
    return "".join(kept)


class TestNoNumberIsNoProcessFound:
    def test_a_record_naming_no_process(self) -> None:
        assert _fact(_listing(), {}) == NONE_FOUND

    def test_a_record_naming_a_value_that_is_no_pid(self) -> None:
        assert _fact(_listing(), {"pids": ["0"]}) == NONE_FOUND
        assert _fact(_listing(), {"pid": 0}) == NONE_FOUND
        assert _fact(_listing(), {"pid": "unknown"}) == NONE_FOUND

    def test_a_value_that_is_no_pid_where_every_guest_pid_is_stated(self) -> None:
        # The decision is the one it was (refused); the rule found no number.
        assert _fact(_listing(every_guest_pid=True), {"pid": 0}) == NONE_FOUND


class TestEveryNumberIsKeptByItsField:
    def test_two_numbers_of_one_record(self) -> None:
        assert _fact(_listing(), {"pids": ["1536", "908"]}) == NOT_PLACED.format(
            UNDECIDED.format("pids 1536 and 908 are listed processes")
        )

    def test_a_number_under_the_process_id_field(self) -> None:
        assert _fact(_listing(), {"process_id": 1780}) == NOT_PLACED.format(
            UNDECIDED.format("process id 1780 is a listed process")
        )

    def test_two_records_of_one_value_the_second_naming_a_number(self) -> None:
        assert _fact(_listing(), {}, {"pids": ["1780"]}) == NOT_PLACED.format(
            UNDECIDED.format("pid 1780 is a listed process")
        )

    def test_an_unsettled_number_beside_a_number_of_the_tree(self) -> None:
        said = _fact(_twice(), {"pids": ["900", "87"]})

        assert said == NOT_PLACED.format(
            "it could not place pid 900 in or outside the sample's process tree and it matched "
            "pid 87 to a process of the sample's process tree"
        )


class TestTheListingIsTheOneItWasMatchedAgainst:
    def test_a_number_matched_to_no_process_of_a_listing_stating_every_guest_pid(self) -> None:
        assert _fact(_listing(every_guest_pid=True), {"pids": ["1780"]}) == (
            "the publish rule matched pid 1780 to no process of the process list it read and "
            "that list states a guest pid for every process"
        )

    def test_a_further_detonation_s_row_whose_own_listing_holds_the_number(self) -> None:
        # The first detonation's row names no writer; a further detonation's
        # row names guest pid 5000, which that detonation's own listing holds.
        # The sentence says what the rule matched, against the list it read.
        later = {"pids": ["5000"], "observed_in": [{"detonation": 2}]}
        said = _fact(_listing(every_guest_pid=True), {}, later)

        assert said == (
            "the publish rule matched pid 5000 to no process of the process list it read and "
            "that list states a guest pid for every process"
        )

    def test_a_listing_that_states_no_guest_pid_for_some_process(self) -> None:
        processes = _listing(every_guest_pid=True)
        processes[0].children[0].guest_pid = ""

        assert _fact(processes, {"pids": ["1780"]}) == NOT_PLACED.format(
            UNDECIDED.format("pid 1780 is a listed process")
        )

    def test_one_number_under_two_tasks_keeps_each_task(self) -> None:
        # Task t1 lists id 900 twice; task t2 does not list it and states no guest pid.
        processes = [
            ProcessNode(
                pid=85,
                ppid=56,
                name=SAMPLE,
                task="t1",
                children=[
                    ProcessNode(pid=900, ppid=85, name="x.exe", task="t1"),
                    ProcessNode(pid=900, ppid=85, name="y.exe", task="t1"),
                ],
            ),
            ProcessNode(pid=86, ppid=56, name=SAMPLE, task="t2"),
        ]
        said = _fact(processes, {"pids": ["900"], "task": "t1"}, {"pids": ["900"], "task": "t2"})

        assert said == NOT_PLACED.format(
            "it could not place pid 900 of task t1 in or outside the sample's process tree and "
            "it could not decide whether pid 900 of task t2 is a listed process since the "
            "process list it read does not state a guest pid for every process of task t2"
        )


class TestTheFormsCarryNoMarkOutsideBrackets:
    def test_no_comma_or_semicolon_outside_brackets(self) -> None:
        outside = [*_listing(every_guest_pid=True)]
        outside.append(ProcessNode(pid=40, ppid=4, name="svchost.exe", guest_pid="700"))
        said = [
            _fact(_listing(), {}),
            _fact(_listing(), {"pids": ["1536", "908"]}),
            _fact(_twice(), {"pids": ["900", "87"]}),
            _fact(_listing(every_guest_pid=True), {"pids": ["1780"]}),
            _fact(outside, {"pids": ["40", "1780"]}),
            _fact(_listing(), {"process": "svchost.exe"}),
        ]

        assert said[-2] == (
            "the publish rule matched pid 40 to a listed process outside the sample's process "
            "tree and matched pid 1780 to no process of the process list it read and that list "
            "states a guest pid for every process"
        )
        assert said[-1] == (
            "the publish rule matched the process name svchost.exe to no process of the "
            "sample's process tree"
        )
        assert all(not re.search(r"[,;]", _outside_brackets(one)) for one in said)
        # A writer's word-for-word restatement, bracketed or not, is a restatement.
        for one in said:
            answer = refused(one, "no model kept it as an indicator")
            restated = f"{one} and no model kept it as an indicator"
            assert _states_publish_state(f" ({restated}) was dropped.", answer), one
            assert _states_publish_state(f" {restated}; it was dropped.", answer), one

    def test_a_record_of_the_tree_still_publishes_on_the_judge_s_keep_alone(self) -> None:
        assert _fact(_listing(), {}, {"pids": ["87"]}) == ""
