"""A later detonation of the sample is read apart from the job's own.

Each detonation has its own report. The sandbox readers take a ``detonation``
selector (empty or ``d1`` is the job's own); a later detonation's items carry
ids qualified by its name (``d2/proc:…``), its section index names it, and
the run's item index knows its ids apart from the first's. The selector is
one of the call's arguments, so two reads of two detonations are two calls
to the repeat-serving rules.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from malspark.agents.evidence_recorder import RepeatGuard
from malspark.analysis import sandbox_sections as ss
from malspark.providers import sandbox_tools
from malspark.providers.detonation import AGENT_ORIGIN, DetonationRecord, selected

FIRST: dict[str, Any] = {
    "behavior": {"processes": [{"pid": 100, "process_name": "locker.exe"}]},
    "network": {"dns": [], "hosts": []},
    "signatures": [],
}
SECOND: dict[str, Any] = {
    "behavior": {
        "processes": [
            {"pid": 200, "process_name": "locker.exe", "command_line": "locker.exe --password x"},
            {"pid": 204, "ppid": 200, "process_name": "vssadmin.exe"},
        ]
    },
    "network": {"dns": [{"request": "c2.example.test", "type": "A"}], "hosts": []},
    "signatures": [{"name": "deletes_shadow_copies", "severity": 3}],
}


def _container(*, later: list[DetonationRecord] | None = None) -> Any:
    first = DetonationRecord(report=FIRST)
    second = DetonationRecord(
        ordinal=2, origin=AGENT_ORIGIN, arguments="--password x", report=SECOND
    )
    return SimpleNamespace(
        sandbox_report=FIRST,
        detonations=[first, *(later if later is not None else [second])],
    )


def _tool(container: Any, name: str) -> Any:
    return next(t for t in sandbox_tools.sandbox_tools(container) if t.name == name)


class TestTheSelector:
    def test_empty_and_d1_read_the_job_s_own_report(self) -> None:
        tool = _tool(_container(), "sandbox_processes")
        assert tool.invoke({}) == tool.invoke({"detonation": "d1"})
        assert [p["pid"] for p in tool.invoke({})["processes"]] == [100]
        assert "detonation" not in tool.invoke({})

    def test_d2_reads_its_own_report_and_names_it(self) -> None:
        answer = _tool(_container(), "sandbox_processes").invoke({"detonation": "d2"})
        assert answer["detonation"] == "d2"
        assert [p["pid"] for p in answer["processes"]] == [200, 204]

    def test_every_reader_takes_the_selector(self) -> None:
        for tool in sandbox_tools.sandbox_tools(_container()):
            assert "detonation" in tool.args_schema.model_fields, tool.name
            assert "d2" in tool.description, tool.name

    def test_a_detonation_the_job_does_not_hold_is_named_with_those_it_holds(self) -> None:
        answer = _tool(_container(), "sandbox_signatures").invoke({"detonation": "d3"})
        assert answer["error"].startswith("no detonation 'd3' in this job")
        assert "d1, d2" in answer["error"]

    def test_a_selector_that_is_not_a_detonation_s_name_is_refused(self) -> None:
        _, problem = selected(_container(), "second")
        assert "d1, d2" in problem

    def test_a_detonation_that_returned_no_report_says_why(self) -> None:
        failed = DetonationRecord(ordinal=2, origin=AGENT_ORIGIN, failure="the task timed out")
        answer = _tool(_container(later=[failed]), "sandbox_network").invoke({"detonation": "d2"})
        assert answer["error"] == "detonation d2 returned no sandbox report: the task timed out"

    def test_a_detonation_landed_after_the_tools_were_built_is_readable(self) -> None:
        container = _container(later=[])
        tool = _tool(container, "sandbox_processes")
        container.detonations.append(
            DetonationRecord(ordinal=2, origin=AGENT_ORIGIN, report=SECOND)
        )
        assert tool.invoke({"detonation": "d2"})["detonation"] == "d2"

    def test_two_reads_of_two_detonations_are_two_calls(self) -> None:
        first = RepeatGuard._key("sandbox_processes", {})
        second = RepeatGuard._key("sandbox_processes", {"detonation": "d2"})
        assert first != second
        # A read with no selector is keyed as it always was.
        assert first == RepeatGuard._key("sandbox_processes", {})


class TestQualifiedItems:
    def test_a_later_detonation_s_items_carry_its_name(self) -> None:
        answer = _tool(_container(), ss.ITEMS_TOOL).invoke(
            {"section": "processes", "detonation": "d2"}
        )
        assert answer["detonation"] == "d2"
        ids = [item["id"] for item in answer["items"]]
        assert ids == ["d2/proc:200", "d2/proc:204"]
        assert answer["items"][1]["parent"] == "d2/proc:200"

    def test_the_first_s_items_stay_unqualified(self) -> None:
        answer = _tool(_container(), ss.ITEMS_TOOL).invoke({"section": "processes"})
        assert [item["id"] for item in answer["items"]] == ["proc:100"]

    def test_a_later_detonation_answers_its_ids_qualified_or_bare(self) -> None:
        tool = _tool(_container(), ss.ITEMS_TOOL)
        for asked in ("d2/sig:1", "sig:1"):
            answer = tool.invoke({"section": "signatures", "ids": asked, "detonation": "d2"})
            assert [item["id"] for item in answer["items"]] == ["d2/sig:1"]
        answer = tool.invoke({"section": "signatures", "ids": "d3/sig:1", "detonation": "d2"})
        assert answer["items"] == []
        assert answer["not_in_section"] == ["d3/sig:1"]

    def test_the_item_id_pattern_reads_a_qualifier_only_from_d2(self) -> None:
        assert ss.cited_item_ids("seen [d2/proc:200, proc:100, d1/proc:9]") == [
            "d2/proc:200",
            "proc:100",
        ]
        assert ss.ITEM_ID_RE.findall("http://h/d2/proc:4 xd2/net:1") == []
        assert ss.split_qualifier("D2/Net:3") == ("d2", "net:3")


class _Entry:
    """A section index entry as the pack records it (agent ``pipeline``, source ``pack``)."""

    def __init__(self, structured: dict[str, Any]) -> None:
        self.structured = structured
        self.ok = True
        self.declared_kind = ss.SECTIONS_KIND
        self.agent = "pipeline"
        self.source = "pack"


class TestTheIndex:
    def test_a_later_detonation_s_index_names_it_and_the_first_s_does_not(self) -> None:
        assert "detonation" not in ss.section_index(FIRST)
        assert ss.section_index(SECOND, None, "d2")["detonation"] == "d2"

    def test_the_item_index_knows_each_detonation_s_ids_apart(self, monkeypatch: Any) -> None:
        from malspark.core import declared_reading

        monkeypatch.setattr(declared_reading, "kind_of", lambda entry: entry.declared_kind)
        entries = [
            _Entry(ss.section_index(FIRST)),
            # The platform's read of d2 states its launch (``DetonationRecord.stated``).
            _Entry({**ss.section_index(SECOND, None, "d2"), "launched_with": "-p x"}),
        ]
        assert ss.index_entry(entries) is entries[0]
        index = ss.item_index_of(entries)
        assert index is not None
        assert index.known("proc:100") and not index.known("proc:200")
        assert index.known("d2/proc:200") and index.known("d2/sig:1")
        assert not index.known("d2/proc:100") and not index.known("d3/proc:200")
        assert "d2/proc:204" in list(index.ids())
        citations = ss.ItemCitations(
            index, ss.Sections(FIRST), {"d2": ss.Sections(SECOND, None, "d2")}
        )
        assert citations.item("d2/proc:204")["parent"] == "d2/proc:200"
        assert citations.item("proc:100")["id"] == "proc:100"
