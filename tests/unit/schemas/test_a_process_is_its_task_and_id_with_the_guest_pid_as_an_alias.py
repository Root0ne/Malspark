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


class TestAProcessIsWrittenByItsIdAndItsTaskWhereTheIdIsShared:
    def test_an_id_one_task_lists_is_written_alone(self) -> None:
        assert _two_tasks().written(ProcessKey("t1", "85")) == "85"

    def test_an_id_two_tasks_list_is_written_with_its_task(self) -> None:
        assert _two_tasks().written(ProcessKey("t1", "87")) == "87 in task t1"

    def test_the_guest_pid_of_a_process_is_kept(self) -> None:
        assert _two_tasks().guest_of(ProcessKey("t2", "87")) == "3756"


class TestEveryAnswerThatNamesAProcessIsRead:
    def test_a_process_listing_and_a_signature_s_indicators_are_read(self) -> None:
        found = ProcessIdentities()
        found.read_answer(
            {"processes": [{"pid": 85, "task": "t1"}, {"pid": 87, "task": "t1"}]},
            ("indicators",),
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

    def test_reading_is_linear_in_the_rows(self) -> None:
        def read(n: int):  # type: ignore[no-untyped-def]
            rows = [{"pid": i, "task": f"t{i % 3}"} for i in range(1, n + 1)]

            def run() -> None:
                found = ProcessIdentities()
                found.read_answer({"processes": rows}, ())
                for i in range(1, n + 1):
                    found.resolve(str(i))

            return run

        assert_ratio(read(2000), read(20000), 30, what="20,000 rows against 2,000")
