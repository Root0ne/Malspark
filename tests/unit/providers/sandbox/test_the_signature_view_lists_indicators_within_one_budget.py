"""The signature view keeps its rows, lists indicators after them within one budget, and pages them.

Each row of the view (``sandbox_signatures``) is the row it always was and
gains one field, ``indicators_stated``: how many indicators the report states
for the signature. After the rows, ``indicators`` lists them, each with its
signature's name, within one budget for the whole answer
(``SIGNATURE_ANSWER_CHARS``, and never more than the model's copy of the
answer holds): those naming a process pairing first, then those naming one
process, then the rest. ``indicators_left_out`` counts, per signature, what
the budget leaves out, with the offset from which a call naming the signature
lists the rest. A call that names a signature, a process id or a text answers
the matching indicators, a page (``SIGNATURE_INDICATORS_PAGE``) from an
offset, so every indicator the report states is reachable resolved.

The large report is synthetic: a hundred CAPE signatures of thirty marks each.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.agents.mcp_client import MCPLangChainToolkit
from malspark.providers import sandbox_tools
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_signatures
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.signature_indicators import (
    SIGNATURE_ANSWER_CHARS,
    SIGNATURE_INDICATORS_PAGE,
)
from tests.linear_cost import assert_scales

CAPE = ("cape", "cape2")
# The cap on the model's copy of a tool answer where nothing else sets it.
DEFAULT_CAP = 6000


def _mark(i: int, j: int) -> dict[str, Any]:
    return {
        "type": "call",
        "pid": 1000 + (j % 5),
        "cid": j,
        "call": {
            "timestamp": "2026-01-01 10:00:00,123",
            "thread_id": "2244",
            "category": "process",
            "api": f"NtWriteVirtualMemory{j}",
            "arguments": [{"name": "Buffer", "value": "MZ\\x90\\x00" * 10}],
            "id": i * 100 + j,
        },
    }


def _cape(signatures: list[dict[str, Any]], processes: int = 5) -> dict[str, Any]:
    payload = {
        "info": {"id": 7},
        "behavior": {
            "processes": [
                {"process_id": 1000 + k, "parent_id": 4, "process_name": f"p{k}.exe"}
                for k in range(processes)
            ]
        },
        "signatures": signatures,
    }
    return sandbox_document(required_reader("cape2").read(payload, provider="cape"))


def _large(count: int = 100, marks: int = 30) -> dict[str, Any]:
    return _cape(
        [
            {
                "name": f"sig{i}",
                "severity": 2,
                "description": "d",
                "data": [_mark(i, j) for j in range(marks)],
            }
            for i in range(count)
        ]
    )


def _sized(answer: dict[str, Any], cap: int = DEFAULT_CAP) -> dict[str, Any]:
    """The model's copy of ``answer`` under ``cap``, as the guardrail writes it."""
    from malspark.core.safe_json import dumps

    text = MCPLangChainToolkit(None, max_output_chars=cap)._apply_output_guardrail(
        dumps(answer, default=str), ("offset", "limit")
    )
    copy: dict[str, Any] = json.loads(text)
    return copy


class _Registry:
    def __init__(self, cap: int) -> None:
        self.cap = cap

    def answer_sizer(self) -> MCPLangChainToolkit:
        return MCPLangChainToolkit(None, max_output_chars=self.cap)


class _Container:
    def __init__(self, report: dict[str, Any], normalised: Any, cap: int) -> None:
        self.sandbox_report = report
        self.sandbox_normalised = normalised
        self.registry = _Registry(cap)

    def get_server_registry(self) -> _Registry:
        return self.registry


def _model_copy(report: dict[str, Any], normalised: Any, cap: int = DEFAULT_CAP) -> dict[str, Any]:
    """What the model reads of an unfiltered call of the view, through the job's guardrail."""
    container = _Container(report, normalised, cap)
    (tool,) = [t for t in sandbox_tools.sandbox_tools(container) if t.name == "sandbox_signatures"]
    copy: dict[str, Any] = json.loads(tool.invoke({}))
    return copy


class TestTheRows:
    def test_each_row_is_the_row_without_indicators_with_its_count(self) -> None:
        report = _large(5, 3)
        bare = sandbox_signatures(report)["signatures"]
        rows = sandbox_signatures(report, normalised_by=CAPE)["signatures"]
        assert [row.pop("indicators_stated") for row in rows] == [3] * 5
        assert rows == bare

    def test_a_signature_with_no_indicator_gains_no_field(self) -> None:
        report = _cape([{"name": "quiet", "severity": 1, "description": "d"}])
        answer = sandbox_signatures(report, normalised_by=CAPE)
        assert answer == sandbox_signatures(report)


class TestTheOrder:
    def test_a_pairing_comes_before_one_process_before_the_rest(self) -> None:
        report = _cape(
            [
                {"name": "a", "data": [{"type": "ioc", "ioc": "x"}]},
                {"name": "b", "data": [{"type": "call", "pid": 1000, "call": {"api": "A"}}]},
            ]
        )
        answer = sandbox_signatures(report, normalised_by=CAPE)
        assert [one["signature"] for one in answer["indicators"]] == ["b", "a"]

    def test_the_head_of_each_signature_s_order_is_what_it_lists(self) -> None:
        answer = sandbox_signatures(_large(), normalised_by=CAPE)
        listed: dict[str, int] = {}
        for one in answer["indicators"]:
            listed[one["signature"]] = listed.get(one["signature"], 0) + 1
        for rest in answer["indicators_left_out"]:
            assert rest["offset"] == listed.get(rest["signature"], 0)


class TestOneBudget:
    def test_the_answer_stays_within_the_budget(self) -> None:
        answer = sandbox_signatures(_large(), normalised_by=CAPE)
        assert answer["indicators"]
        assert len(json.dumps(answer)) <= SIGNATURE_ANSWER_CHARS

    def test_it_stays_within_twice_the_answer_without_indicators(self) -> None:
        report = _large()
        bare = len(json.dumps(sandbox_signatures(report)))
        assert len(json.dumps(sandbox_signatures(report, normalised_by=CAPE))) <= 2 * bare

    def test_what_the_budget_leaves_out_is_counted_per_signature(self) -> None:
        answer = sandbox_signatures(_large(), normalised_by=CAPE)
        listed: dict[str, int] = {}
        for one in answer["indicators"]:
            listed[one["signature"]] = listed.get(one["signature"], 0) + one.get("times", 1)
        left = {rest["signature"]: rest["left_out"] for rest in answer["indicators_left_out"]}
        for row in answer["signatures"]:
            name = row["name"]
            assert listed.get(name, 0) + left.get(name, 0) == row["indicators_stated"]
        assert "offset=" in answer["indicators_read"]

    def test_where_the_rows_fill_the_budget_none_is_listed_and_each_count_stands(self) -> None:
        answer = sandbox_signatures(_large(), normalised_by=CAPE, room=1000)
        assert "indicators" not in answer and "indicators_left_out" not in answer
        assert all(row["indicators_stated"] == 30 for row in answer["signatures"])
        assert "offset=" in answer["indicators_read"]


class TestTheModelsCopy:
    """Under the cap on the model's copy, the indicators cost no row a model would see."""

    @pytest.mark.parametrize("cap", [DEFAULT_CAP, 12_000, 20_000, 40_000])
    def test_no_row_is_left_out_for_an_indicator(self, cap: int) -> None:
        report = _large()
        copy = _model_copy(report, CAPE, cap)
        counts_only = sandbox_signatures(report, normalised_by=CAPE, room=0)
        assert len(copy["signatures"]) >= len(_sized(counts_only, cap)["signatures"])

    def test_the_model_sees_the_rows_where_they_fit_whole(self) -> None:
        report = _large(20, 30)
        copy = _model_copy(report, CAPE)
        assert len(copy["signatures"]) == 20
        assert len(json.dumps(copy)) <= DEFAULT_CAP


class TestThePagedCall:
    @staticmethod
    def _sixty() -> dict[str, Any]:
        marks = [{"type": "ioc", "pid": 1000, "ioc": f"10.0.0.{i}"} for i in range(80)]
        return _cape([{"name": "wide", "data": marks}])

    def test_it_reaches_the_sixtieth_indicator(self) -> None:
        page = sandbox_signatures(self._sixty(), normalised_by=CAPE, signature="wide", offset=59)
        assert page["indicators"][0]["values"]["ioc"] == "10.0.0.59"
        assert page["matched"] == 80 and page["offset"] == 59

    def test_its_pages_list_every_indicator_once(self) -> None:
        report = self._sixty()
        seen: list[str] = []
        offset: int | None = 0
        while offset is not None:
            page = sandbox_signatures(report, normalised_by=CAPE, signature="wide", offset=offset)
            assert len(page["indicators"]) <= SIGNATURE_INDICATORS_PAGE
            seen += [one["values"]["ioc"] for one in page["indicators"]]
            offset = page.get("next_offset")
        assert seen == [f"10.0.0.{i}" for i in range(80)]

    def test_it_continues_where_the_unfiltered_answer_stops(self) -> None:
        report = _large()
        answer = sandbox_signatures(report, normalised_by=CAPE)
        rest = answer["indicators_left_out"][0]
        page = sandbox_signatures(
            report, normalised_by=CAPE, signature=rest["signature"], offset=rest["offset"]
        )
        listed = [one for one in answer["indicators"] if one["signature"] == rest["signature"]]
        whole = sandbox_signatures(report, normalised_by=CAPE, signature=rest["signature"])
        assert whole["indicators"][: len(listed)] == listed
        assert page["indicators"][0] == whole["indicators"][len(listed)]

    def test_a_process_id_lists_the_indicators_naming_it(self) -> None:
        page = sandbox_signatures(_large(3, 10), normalised_by=CAPE, process="1002")
        assert page["matched"] == 3 * 2
        assert all(one["process"]["id"] == "1002" for one in page["indicators"])

    def test_a_text_lists_the_indicators_holding_it(self) -> None:
        page = sandbox_signatures(_large(3, 10), normalised_by=CAPE, contains="virtualmemory7")
        assert [one["signature"] for one in page["indicators"]] == ["sig0", "sig1", "sig2"]

    def test_a_process_that_is_no_id_is_refused(self) -> None:
        page = sandbox_signatures(_large(1, 1), normalised_by=CAPE, process="cmd.exe")
        assert "error" in page

    def test_a_report_whose_format_states_none_says_so(self) -> None:
        page = sandbox_signatures(_large(1, 1), signature="sig0")
        assert page["matched"] == 0 and page["no"]


class TestTheCostIsLinear:
    @staticmethod
    def _report(n: int) -> dict[str, Any]:
        return _large(n, 6)

    def test_the_unfiltered_answer(self) -> None:
        assert_scales(
            self._report, 40, lambda doc: sandbox_signatures(doc, normalised_by=CAPE), factor=8
        )

    @pytest.mark.parametrize(
        "asked",
        [{"signature": "sig0", "offset": 2}, {"process": "1001"}, {"contains": "memory4"}],
        ids=["signature", "process", "contains"],
    )
    def test_the_paged_call_and_its_filters(self, asked: dict[str, Any]) -> None:
        def report(n: int) -> dict[str, Any]:
            # Every signature of one name, so a name's indicators grow with the report.
            document = _large(n, 6)
            for row in document["signatures"]:
                row["name"] = "sig0"
            return document

        assert_scales(
            report, 40, lambda doc: sandbox_signatures(doc, normalised_by=CAPE, **asked), factor=8
        )
