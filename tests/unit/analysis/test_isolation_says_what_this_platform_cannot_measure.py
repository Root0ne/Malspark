"""Where nothing of a process can be measured, the isolation part says so.

Windows has no POSIX user ids and no ``/proc``. There the worker's facts, a
started server's process and its tree are unread, field by field, and the
part says they are not available on this platform, rather than reading as a
user that is the worker's own or a tree with nothing under it.
"""

from __future__ import annotations

import os

import pytest

from malspark.analysis import isolation


class TestIsolationWhereNothingCanBeMeasured:
    """Windows has no user ids and no /proc: the part says so instead of reading as measured."""

    @pytest.fixture(autouse=True)
    def _no_user_ids(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("geteuid", "getegid", "getgroups"):
            monkeypatch.delattr(os, name, raising=False)

    def test_the_worker_s_facts_are_unread_and_say_why(self) -> None:
        facts = isolation.worker_facts()
        assert facts["uid"] is None and facts["cap_eff_zero"] is None
        assert facts["unavailable"] == isolation.NOT_ON_THIS_PLATFORM
        line = isolation._worker_line(facts, isolation._code)
        assert "a user that could not be read" in line
        assert "not available on this platform" in line

    def test_a_process_is_unread_field_by_field(self) -> None:
        measured = isolation.measure_process(os.getpid(), ["PATH"])
        assert all(measured[key] is None for key in isolation.MEASURED_FIELDS[:-1])
        assert measured["platform_names_in_env"] == []

    def test_a_tree_is_not_judged_and_says_why(self) -> None:
        tree = isolation.measure_tree(os.getpid(), [])
        assert tree["descendants"] == []
        assert tree["descendants_judged"] is False
        assert tree["descendants_why"] == isolation.NOT_ON_THIS_PLATFORM

    def test_an_unmeasured_stdio_reader_is_said_not_available_and_not_isolated(self) -> None:
        part = isolation.isolation_part(
            {"capa": 2},
            0,
            {},
            worker=isolation.worker_facts(),
            in_process={},
            route=lambda _source: ("stdio", "", "", ""),
            needs_network=lambda _source: False,
        )
        (row,) = part["rows"]
        assert row["why_not_measured"] == isolation.NOT_ON_THIS_PLATFORM
        assert part["isolated"] is False
        assert any(
            "not available on this platform" in line for line in isolation.isolation_lines(part)
        )


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="no user ids on this host")
def test_a_posix_worker_s_facts_carry_no_unavailable_key() -> None:
    facts = isolation.worker_facts()
    assert "unavailable" not in facts
    assert facts["uid"] is not None
