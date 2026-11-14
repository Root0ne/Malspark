"""A flow or a request names the process that made it by one key, in one text form.

Each reader writes the process a flow or a request names, by the id the
report's process list gives it, under one key (``TRAFFIC_PROCESS_KEY``), read
from the field its format states it under (a reader's declaration, or a
mapping's ``field_names``). The launcher's reading and the publish rule read
that key alone. A process id is compared in one text form on both sides, so a
flow naming ``"86"`` names the listed process 86; an id of a type that cannot
be one is not stated, and no report makes the reader raise. Every flow of an
id a task lists twice is kept: a request riding on it is the sample's when
any of them is, another lineage's only when all name one, whatever their order.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from malspark.core.config import RestMappingConfig
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_dropped_files, sandbox_network
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import (
    LINEAGE_KEY,
    LINEAGE_LAUNCHER,
    PROCESS_UNLISTED_KEY,
    SAMPLE_TREE_KEY,
    TRAFFIC_PROCESS_KEY,
    SandboxReport,
    attribute_the_launcher,
)

LIVE = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox" / "triage_live"
CRL = "http://c.pki.goog/r/r1.crl"
LAUNCHER = {
    "sample_member": "cmd.exe",
    "launcher_member": "launch.ps1",
    "script_host_images": ["powershell.exe"],
    "launcher_sha256": "b" * 64,
    "sample_sha256": "c" * 64,
}


def _json(name: str) -> Any:
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


def _read(task: dict[str, Any]) -> SandboxReport:
    return required_reader("triage").read(
        _json("overview.json"), provider="triage", task_id="s1", task_reports={"behavioral1": task}
    )


def _network(report: SandboxReport) -> Any:
    view = sandbox_network(sandbox_document(report))
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="dynamic",
        tool="sandbox_network",
        args={},
        server=None,
        output=json.dumps(view),
    )
    return network_from_ledger([entry])


def _url(report: SandboxReport) -> Any:
    network = _network(report)
    return next(u for u in network.urls if u.url == CRL)


def _with_flow_32(*procids: Any) -> dict[str, Any]:
    """The live task with its HTTP flow (32) listed once per procid, in that order."""
    task = _json("behavioral1.json")
    flows = [f for f in task["network"]["flows"] if f["id"] != 32]
    (template,) = [f for f in task["network"]["flows"] if f["id"] == 32]
    for procid in procids:
        flow = dict(template)
        if procid is None:
            flow.pop("procid")
        else:
            flow["procid"] = procid
        flows.append(flow)
    task["network"]["flows"] = flows
    return task


class TestOneTextForm:
    def test_a_flow_naming_a_listed_number_as_text_is_that_process(self) -> None:
        report = _read(_with_flow_32("86"))
        (flow,) = report.network.tcp
        assert flow[SAMPLE_TREE_KEY] is True and PROCESS_UNLISTED_KEY not in flow
        assert flow[TRAFFIC_PROCESS_KEY] == "86"
        assert all(row[SAMPLE_TREE_KEY] is True for row in report.network.http)
        assert _url(report).sample_process_tree is True

    def test_a_process_listed_by_text_is_the_one_a_flow_names_by_number(self) -> None:
        task = _with_flow_32(86)
        for proc in task["processes"]:
            proc["procid"] = str(proc["procid"])
            proc["procid_parent"] = str(proc["procid_parent"])
        report = _read(task)
        (flow,) = report.network.tcp
        assert flow[SAMPLE_TREE_KEY] is True and PROCESS_UNLISTED_KEY not in flow
        assert _url(report).sample_process_tree is True

    def test_a_flow_is_not_listed_only_when_its_id_is_none_of_the_listed_ones(self) -> None:
        report = _read(_with_flow_32(" 46 "))
        (flow,) = report.network.tcp
        assert flow[PROCESS_UNLISTED_KEY] is True and flow[TRAFFIC_PROCESS_KEY] == "46"


class TestEveryFlowOfAnIdIsKept:
    @pytest.mark.parametrize("order", [(46, 86), (86, 46)])
    def test_a_request_on_an_id_the_sample_s_flow_shares_is_the_sample_s(
        self, order: tuple[int, int]
    ) -> None:
        url = _url(_read(_with_flow_32(*order)))
        assert url.sample_process_tree is True and url.made_by is None

    @pytest.mark.parametrize("order", [(46, 47), (47, 46)])
    def test_a_request_on_an_id_only_unlisted_flows_share_names_them_all(
        self, order: tuple[int, int]
    ) -> None:
        url = _url(_read(_with_flow_32(*order)))
        assert url.sample_process_tree is False
        assert url.made_by is not None and url.made_by.unlisted == ["procid 46", "procid 47"]

    @pytest.mark.parametrize("order", [(46, None), (None, 46)])
    def test_a_request_on_an_id_a_flow_naming_no_process_shares_states_no_maker(
        self, order: tuple[Any, Any]
    ) -> None:
        url = _url(_read(_with_flow_32(*order)))
        assert url.sample_process_tree is None and url.made_by is None


MAPPED = RestMappingConfig(
    processes="$.procs[*]",
    tcp="$.net.tcp[*]",
    http="$.net.http[*]",
    field_names={"tcp.platform_process": "proc", "http.platform_process": "proc"},
)


def _mapped_payload() -> dict[str, Any]:
    return {
        "procs": [
            {
                "pid": 10,
                "ppid": 0,
                "name": "C:\\Windows\\powershell.exe",
                "command_line": "powershell.exe -File C:\\u\\launch.ps1",
            },
            {"pid": 11, "ppid": 10, "name": "C:\\u\\cmd.exe", "command_line": "C:\\u\\cmd.exe"},
        ],
        "net": {
            "tcp": [
                {"dst": "198.51.100.7", "dport": 80, "proc": 10},
                {"dst": "203.0.113.5", "dport": 443, "proc": 11},
            ],
            "http": [
                {"host": "launcher.example", "uri": "/a", "proc": 10},
                {"host": "sample.example", "uri": "/b", "proc": 11},
            ],
        },
    }


class TestAFormatNamingItsProcessUnderAnotherKey:
    def test_its_launcher_s_requests_are_marked_like_its_flows(self) -> None:
        report = required_reader("generic").read(
            _mapped_payload(), provider="upload", mapping=MAPPED
        )
        attribute_the_launcher(report, LAUNCHER)
        flows = {row["dst"]: row for row in report.network.tcp}
        requests = {row["host"]: row for row in report.network.http}
        assert flows["198.51.100.7"][LINEAGE_KEY] == LINEAGE_LAUNCHER
        assert requests["launcher.example"][LINEAGE_KEY] == LINEAGE_LAUNCHER
        assert requests["launcher.example"][SAMPLE_TREE_KEY] is False
        assert flows["203.0.113.5"][SAMPLE_TREE_KEY] is True
        assert requests["sample.example"][SAMPLE_TREE_KEY] is True

    def test_a_mapping_declaring_no_such_field_names_no_process(self) -> None:
        mapping = MAPPED.model_copy(update={"field_names": {}})
        report = required_reader("generic").read(
            _mapped_payload(), provider="upload", mapping=mapping
        )
        attribute_the_launcher(report, LAUNCHER)
        rows = (*report.network.tcp, *report.network.http)
        assert all(TRAFFIC_PROCESS_KEY not in row and LINEAGE_KEY not in row for row in rows)

    def test_a_cape_flow_naming_its_pid_is_marked_as_before(self) -> None:
        payload = {
            "info": {"id": 1},
            "behavior": {
                "processes": [
                    {
                        "pid": 10,
                        "ppid": 0,
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -File C:\\u\\launch.ps1",
                    }
                ]
            },
            "network": {"tcp": [{"dst": "198.51.100.7", "dport": 80, "pid": 10}]},
        }
        report = required_reader("cape2").read(payload, provider="cape")
        attribute_the_launcher(report, LAUNCHER)
        (flow,) = report.network.tcp
        assert flow[TRAFFIC_PROCESS_KEY] == "10" and flow[LINEAGE_KEY] == LINEAGE_LAUNCHER


WEIRD = [None, True, -1, 10**30, 1.5, "", "x", [], [1], {}, {"a": 1}, float("nan")]
PLACES = [
    "flow.id",
    "flow.procid",
    "req.flow",
    "req.index",
    "req.part",
    "req.headers",
    "req.status",
    "dumped.procid",
    "dumped.path",
    "proc.procid",
    "proc.procid_parent",
    "req.row",
    "flows",
    "requests",
    "dumped",
]


def _put(task: dict[str, Any], where: str, value: Any) -> None:
    network = task["network"]
    dumped = task["dumped"]
    if where == "flow.id":
        network["flows"][0]["id"] = value
    elif where == "flow.procid":
        network["flows"][1]["procid"] = value
    elif where == "req.flow":
        network["requests"][2]["flow"] = value
    elif where == "req.index":
        network["requests"][2]["index"] = value
    elif where == "req.part":
        network["requests"][2]["http_request"] = value
    elif where == "req.headers":
        network["requests"][2]["http_request"]["headers"] = value
    elif where == "req.status":
        network["requests"][3]["http_response"]["status"] = value
    elif where == "dumped.procid":
        dumped[2]["procid"] = value
    elif where == "dumped.path":
        dumped[2]["path"] = value
    elif where == "proc.procid":
        task["processes"][0]["procid"] = value
    elif where == "proc.procid_parent":
        task["processes"][1]["procid_parent"] = value
    elif where == "req.row":
        network["requests"] += [value, {1: {"x": 1}, "k": value}]
    else:
        (network if where in ("flows", "requests") else task)[where] = value


class TestAnIdThatCannotBeOne:
    @pytest.mark.parametrize("where", PLACES)
    @pytest.mark.parametrize("value", WEIRD, ids=repr)
    def test_no_report_makes_the_reader_raise(self, where: str, value: Any) -> None:
        task = _json("behavioral1.json")
        _put(task, where, value)
        report = _read(task)
        attribute_the_launcher(report, LAUNCHER)
        document = sandbox_document(report)
        sandbox_network(document)
        sandbox_dropped_files(document, normalised_by=["triage", "triage", "tasks"])
        json.dumps(document, default=str)
        _network(report)

    @pytest.mark.parametrize("value", [True, 1.5, [86], {"a": 86}, 10**30, "x"], ids=repr)
    def test_a_flow_s_process_under_such_a_value_is_not_stated(self, value: Any) -> None:
        report = _read(_with_flow_32(value))
        (flow,) = report.network.tcp
        assert TRAFFIC_PROCESS_KEY not in flow and SAMPLE_TREE_KEY not in flow
        assert PROCESS_UNLISTED_KEY not in flow
        assert _url(report).made_by is None
