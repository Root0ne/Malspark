"""A process is its task and the report's own id; the guest's pid is an alias of it.

One reader of process identity (``schemas.process_identity``) serves every
surface that names a process: the signature placer, the dropped-files view,
the sample's tree and the export. A number names the one process whose id or
guest's pid it is, in the task where one is stated; a number two processes
answer to names none.

Every value is synthetic.
"""

from __future__ import annotations

from malspark.schemas.process_identity import ProcessIdentities, ProcessKey
from tests.linear_cost import assert_ratio


def _two_tasks() -> ProcessIdentities:
    found = ProcessIdentities()
    found.add("85", task="t1", guest_pid="1496")
    found.add("87", task="t1", guest_pid="1924")
    found.add("87", task="t2", guest_pid="3756")
    found.add("89", task="t2", guest_pid="4156")
    return found


class TestANumberNamesOneProcess:
    def test_a_guest_pid_names_the_process_it_is_an_alias_of(self) -> None:
        assert _two_tasks().resolve("1924") == ProcessKey("t1", "87")
        assert _two_tasks().resolve(1496) == ProcessKey("t1", "85")

    def test_an_id_two_tasks_list_names_none_unless_the_task_is_stated(self) -> None:
        found = _two_tasks()

        assert found.resolve("87") is None
        assert found.keys("87") == [ProcessKey("t1", "87"), ProcessKey("t2", "87")]
        assert found.resolve("87", task="t2") == ProcessKey("t2", "87")

    def test_an_id_equal_to_another_process_s_guest_pid_names_none(self) -> None:
        found = ProcessIdentities()
        found.add("10", guest_pid="20")
        found.add("20", guest_pid="30")

        assert found.resolve("20") is None
        assert found.resolve("30") == ProcessKey("", "20")

    def test_a_number_no_process_answers_to_names_none(self) -> None:
        assert _two_tasks().resolve("999") is None
        assert _two_tasks().keys("999") == []
        assert _two_tasks().resolve("not a pid") is None

    def test_a_listing_with_no_task_and_no_guest_pid_names_by_id(self) -> None:
        found = ProcessIdentities()
        found.add(84)

        assert found.resolve("84") == ProcessKey("", "84")
        assert found.guest_of(ProcessKey("", "84")) == ""

    def test_a_guest_pid_equal_to_its_own_id_is_one_process(self) -> None:
        found = ProcessIdentities()
        found.add("84", guest_pid="84")

        assert found.resolve("84") == ProcessKey("", "84")


class TestAnIdATaskListsTwiceNamesNoProcess:
    @staticmethod
    def _twice() -> ProcessIdentities:
        found = ProcessIdentities()
        found.add_listing(
            [("85", "t1", "1496"), ("900", "t1", "1500"), ("900", "t1", "1504"), ("900", "t2", "")]
        )
        return found

    def test_the_id_names_none_with_or_without_its_task(self) -> None:
        found = self._twice()

        assert found.resolve("900") is None
        assert found.resolve("900", task="t1") is None
        assert found.resolve("900", task="t2") == ProcessKey("t2", "900")
        assert found.resolve("85") == ProcessKey("t1", "85")

    def test_neither_guest_pid_names_it(self) -> None:
        found = self._twice()

        assert found.resolve("1500") is None
        assert found.resolve("1504") is None

    def test_one_process_two_answers_list_is_one_process(self) -> None:
        found = ProcessIdentities()
        found.add_listing([("85", "t1", "1496")])
        found.add_listing([("85", "t1", "1496")])

        assert found.resolve("85") == ProcessKey("t1", "85")


class TestARowThatStatesNoTaskIsReadAgainstTheListedTasks:
    def test_an_id_one_task_holds_is_that_task_s_process(self) -> None:
        found = _two_tasks()
        found.add("85", guest_pid="1496")

        assert found.resolve("85") == ProcessKey("t1", "85")
        assert found.written(ProcessKey("t1", "85")) == "85"

    def test_an_id_several_tasks_hold_names_none(self) -> None:
        found = _two_tasks()
        found.add("87")

        assert found.resolve("87") is None
        assert found.keys("87") == [ProcessKey("t1", "87"), ProcessKey("t2", "87")]

    def test_it_never_rewrites_another_row_s_root(self) -> None:
        found = ProcessIdentities()
        found.add("85", task="t1")
        found.add("85", guest_pid="1496")

        assert found.written(ProcessKey("t1", "85")) == "85"
        assert found.written(ProcessKey("", "85")) == "85"

    def test_its_guest_pid_is_the_listed_process_s(self) -> None:
        found = ProcessIdentities()
        found.add("85", task="t1")
        found.add("85", guest_pid="1496")

        assert found.resolve("1496") == ProcessKey("t1", "85")
        assert found.guest_of(ProcessKey("t1", "85")) == "1496"

    def test_its_guest_pid_is_no_process_s_where_two_tasks_list_its_id(self) -> None:
        found = ProcessIdentities()
        found.add("87", task="t1")
        found.add("87", task="t2")
        found.add("87", guest_pid="1924")

        assert found.guest_of(ProcessKey("t1", "87")) == ""
        assert found.guest_of(ProcessKey("t2", "87")) == ""

    def test_the_process_s_own_task_s_statement_is_read_before_it(self) -> None:
        found = ProcessIdentities()
        found.add("85", task="t1", guest_pid="1496")
        found.add("85", guest_pid="2000")

        assert found.guest_of(ProcessKey("t1", "85")) == "1496"


class TestAProcessIsWrittenByItsIdAndItsTaskWhereTheIdIsShared:
    def test_an_id_one_task_lists_is_written_alone(self) -> None:
        assert _two_tasks().written(ProcessKey("t1", "85")) == "85"

    def test_an_id_two_tasks_list_is_written_with_its_task(self) -> None:
        assert _two_tasks().written(ProcessKey("t1", "87")) == "87 in task t1"

    def test_the_guest_pid_of_a_process_is_kept(self) -> None:
        assert _two_tasks().guest_of(ProcessKey("t2", "87")) == "3756"

    def test_two_answers_stating_two_guest_pids_keep_neither_as_its_guest_pid(self) -> None:
        found = _two_tasks()
        found.add("87", task="t2", guest_pid="4000")

        assert found.guest_of(ProcessKey("t2", "87")) == ""
        assert found.resolve("4000") == ProcessKey("t2", "87")
        assert found.resolve("3756") == ProcessKey("t2", "87")


class TestWhetherEveryProcessARecordCouldNameStatesItsGuestPid:
    def test_a_listing_stating_every_guest_pid_states_them_in_each_task(self) -> None:
        found = _two_tasks()

        assert found.states_every_guest_pid() is True
        assert found.states_every_guest_pid("t1") is True
        assert found.states_every_guest_pid("t2") is True

    def test_one_process_stating_none_is_read_in_its_task_and_the_listing(self) -> None:
        found = _two_tasks()
        found.add("86", task="t1")

        assert found.states_every_guest_pid() is False
        assert found.states_every_guest_pid("t1") is False
        assert found.states_every_guest_pid("t2") is True

    def test_a_task_less_row_s_guest_pid_is_its_listed_process_s(self) -> None:
        found = ProcessIdentities()
        found.add("85", task="t1")
        found.add("85", guest_pid="1496")

        assert found.states_every_guest_pid("t1") is True

    def test_a_task_less_row_s_guest_pid_is_no_one_process_s_where_two_tasks_list_its_id(
        self,
    ) -> None:
        found = ProcessIdentities()
        found.add("87", task="t1")
        found.add("87", task="t2")
        found.add("87", guest_pid="1924")

        assert found.states_every_guest_pid() is False

    def test_a_task_less_row_of_a_listed_process_is_no_process_of_its_own(self) -> None:
        found = ProcessIdentities()
        found.add("84", task="b1", guest_pid="1756")
        found.add("84")

        assert found.states_every_guest_pid() is True

    def test_a_task_the_listing_does_not_hold_and_an_empty_listing_state_none(self) -> None:
        assert _two_tasks().states_every_guest_pid("t9") is False
        assert ProcessIdentities().states_every_guest_pid() is False

    def test_a_process_added_after_the_question_is_counted(self) -> None:
        found = _two_tasks()
        assert found.states_every_guest_pid("t1") is True

        found.add("86", task="t1")

        assert found.states_every_guest_pid("t1") is False


class TestEveryAnswerThatNamesAProcessIsRead:
    def test_a_process_listing_and_a_signature_s_indicators_are_read(self) -> None:
        found = ProcessIdentities()
        found.read_answer(
            {"processes": [{"pid": 85, "task": "t1"}, {"pid": 87, "task": "t1"}]},
            ("indicators",),
            listing=True,
        )
        found.read_answer(
            {
                "indicators": [
                    {
                        "task": "t1",
                        "process": {"id": "85", "guest_pid": "1496"},
                        "target": {"id": "87", "guest_pid": "1924"},
                    },
                    # A process the report does not settle is no identity.
                    {"task": "t1", "process": {"id": "91", "not_settled": "listed twice"}},
                ]
            },
            ("indicators",),
        )
        found.read_answer(
            {
                "items": [
                    {"id": "sig:2", "indicators": [{"process": {"id": "89", "guest_pid": "77"}}]}
                ]
            },
            ("items.*.indicators",),
        )

        assert found.resolve("1924") == ProcessKey("t1", "87")
        assert found.resolve("1496") == ProcessKey("t1", "85")
        assert found.resolve("91") is None
        assert found.resolve("77") == ProcessKey("", "89")

    def test_rows_of_an_answer_that_is_no_listing_are_not_read(self) -> None:
        found = ProcessIdentities()
        found.read_answer({"processes": [{"pid": 85}]}, ())

        assert found.resolve("85") is None

    def test_reading_is_linear_in_the_rows(self) -> None:
        def read(n: int):  # type: ignore[no-untyped-def]
            rows = [{"pid": i, "task": f"t{i % 3}"} for i in range(1, n + 1)]

            def run() -> None:
                found = ProcessIdentities()
                found.read_answer({"processes": rows}, (), listing=True)
                for i in range(1, n + 1):
                    found.resolve(str(i))

            return run

        assert_ratio(read(2000), read(20000), 30, what="20,000 rows against 2,000")
