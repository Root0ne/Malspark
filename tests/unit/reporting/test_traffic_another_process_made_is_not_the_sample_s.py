"""A name, a URL or an address another process made traffic to is not published as the sample's.

A DNS or HTTP request a sandbox records names no process of its own; it rides
on a flow that does. An HTTP request takes the flow's process facts; a DNS
request takes none, since its flow is the guest's resolver, never the program
that asked, and a name is decided from its HTTP requests and the flows to the
addresses it resolved to. One rule decides the three kinds: where the report
names the process that made the traffic and that process is not of the
sample's lineage (a process outside its tree, the launcher's, or one the
report does not list among the task's processes), the value is not published
as observed from the sample, and the answer says whose it is. Where the report
names no process, the value is decided as it is without one; where the
sample's tree made it, it is published.

The live reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission; their DNS and HTTP requests are the guest's
own certificate-revocation traffic, made by processes the report does not list.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from malspark.pipeline.validation import (
    UNATTRIBUTED_INDICATOR_CODE,
    unattributed_indicator_violations,
)
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_network
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.reporting.models import (
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
    SampleIdentity,
    TrafficMakers,
)
from malspark.reporting.renderers.stix_renderer import (
    ExtendedSTIXRenderer,
    emulation_kwargs,
    publish_answer,
    publishes,
    sandbox_facts_for_the_judge,
    sandbox_row_kwargs,
)
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import (
    LINEAGE_DISPUTED_KEY,
    LINEAGE_KEY,
    LINEAGE_LAUNCHER,
    PROCESS_UNLISTED_KEY,
    SAMPLE_TREE_KEY,
    TRAFFIC_PROCESS_KEY,
    SandboxReport,
    attribute_the_launcher,
)
from tests.linear_cost import assert_scales

LIVE = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox" / "triage_live"
SHA256 = "a" * 64
CRL = "http://c.pki.goog/r/r1.crl"
HOST = "c.pki.goog"
LAUNCHER = {
    "sample_member": "cmd.exe",
    "launcher_member": "launch.ps1",
    "script_host_images": ["powershell.exe", "pwsh.exe"],
    "launcher_sha256": "aba6bd87cb5e4c8d594551ce5194d6a120ca721d85d766c0317598e0b5754a6e",
    "sample_sha256": "",
}


def _json(name: str) -> Any:
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


def _sandbox(task: dict[str, Any], launcher: dict[str, Any] | None = None) -> SandboxReport:
    report = required_reader("triage").read(
        _json("overview.json"), provider="triage", task_id="s1", task_reports={"behavioral1": task}
    )
    if launcher:
        attribute_the_launcher(report, launcher)
    return report


def _report(sandbox: SandboxReport) -> MalwareReport:
    view = sandbox_network(sandbox_document(sandbox))
    ledger = [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps(view),
        )
    ]
    report = MalwareReportBuilder(
        file_hash=SHA256,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        sample_platform="windows",
        sample_file_type="pe",
        evidence_ledger=ledger,
    ).build_deterministic()
    report.network = network_from_ledger(ledger)
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _patterns(report: MalwareReport) -> list[str]:
    return [str(getattr(o, "pattern", "")) for o in ExtendedSTIXRenderer().render(report).objects]


def _answer(report: MalwareReport, kind: str, value: str) -> str:
    return publish_answer(kind, value, "sandbox", None, **emulation_kwargs(report, kind, value))


def _with_flows(**procids: Any) -> dict[str, Any]:
    """The live task with each flow's process replaced (``flow_<id>=procid``, None for none)."""
    task = _json("behavioral1.json")
    for flow in task["network"]["flows"]:
        key = f"flow_{flow['id']}"
        if key in procids:
            if procids[key] is None:
                flow.pop("procid", None)
                flow.pop("pid", None)
            else:
                flow["procid"] = procids[key]
    return task


class TestTheLiveReport:
    def test_the_revocation_list_url_and_its_host_are_not_the_sample_s(self) -> None:
        report = _report(_sandbox(_json("behavioral1.json")))
        patterns = _patterns(report)
        assert not any(HOST in p for p in patterns)
        url = _answer(report, "url", CRL)
        assert url.startswith(
            "no: the publish rule counted its requests as made by a process the report does not "
            "list (procid 46)"
        )
        # The name: its HTTP requests and the flow to the address it resolved
        # to (procid 46), each named with its makers; the DNS lookup's flow is
        # the resolver's (procid 36).
        host = _answer(report, "domain", HOST)
        assert host.startswith(
            "no: the publish rule counted its requests as made by a process the report does not "
            "list (procid 46) and the flows to 172.217.76.94 (an address it resolved to) as made "
            "by a process the report does not list (procid 46)"
        )
        # The rows stay, as recorded, with whose they are.
        (domain,) = [d for d in report.network.domains if d.fqdn == HOST]
        assert domain.sample_process_tree is False
        assert domain.made_by is not None and domain.made_by.unlisted == ["procid 46"]
        (table_row,) = [i for i in report.consolidated_iocs if i.value == CRL]
        assert table_row.published == url

    def test_the_address_names_the_process_the_report_does_not_list(self) -> None:
        report = _report(_sandbox(_json("behavioral1.json")))
        assert _answer(report, "ip", "172.217.76.94").startswith(
            "no: the publish rule found a flow to it made by a process the report does not list "
            "(procid 46)"
        )


class TestAFlowOfTheStartedProgram:
    def test_publishes_its_requests(self) -> None:
        # cmd.exe (procid 86), marked as the sample's by the sandbox, made both flows.
        report = _report(_sandbox(_with_flows(flow_31=86, flow_32=86)))
        assert publishes(_answer(report, "url", CRL))
        assert f"[url:value = '{CRL}']" in _patterns(report)
        (domain,) = [d for d in report.network.domains if d.fqdn == HOST]
        assert domain.sample_process_tree is True and domain.made_by is None


class TestTheLauncherSFlow:
    def test_says_it_is_the_launcher_s(self) -> None:
        report = _report(_sandbox(_with_flows(flow_31=84, flow_32=84), LAUNCHER))
        assert _answer(report, "url", CRL).startswith(
            "no: the publish rule counted its requests as made by the launcher's process "
            "(powershell.exe (procid 84))"
        )
        assert not any(HOST in p for p in _patterns(report))


C2 = "cdn-sync-update.net"
C2_ADDRESS = "172.217.76.94"


def _lookup_only(flow_32: Any, *, port: int = 443) -> dict[str, Any]:
    """The live task with its name renamed, its DNS lookup alone and flow 32 by ``flow_32``.

    ``flow_32`` is the procid of the flow to the address the name resolved to;
    ``None`` takes the flow out.
    """
    task = json.loads(json.dumps(_json("behavioral1.json")).replace(HOST, C2))
    flows = [f for f in task["network"]["flows"] if f["id"] != 32 or flow_32 is not None]
    for flow in flows:
        if flow["id"] == 32:
            flow.update(procid=flow_32, dst=f"{C2_ADDRESS}:{port}", protocols=["tls"])
    task["network"]["flows"] = flows
    task["network"]["requests"] = [r for r in task["network"]["requests"] if r["flow"] == 31]
    return task


class TestANameIsDecidedByItsRequestsAndTheFlowsToItsAddresses:
    """A DNS request's flow is the guest's resolver, never the program that asked."""

    def test_the_sample_s_flow_to_the_resolved_address_publishes_the_name(self) -> None:
        # The lookup rode on the resolver's flow (procid 36, not listed); cmd.exe
        # (procid 86, the sample's) reached the address over TLS; no HTTP row.
        report = _report(_sandbox(_lookup_only(86)))
        assert publishes(_answer(report, "domain", C2))
        assert f"[domain-name:value = '{C2}']" in _patterns(report)
        (domain,) = [d for d in report.network.domains if d.fqdn == C2]
        assert domain.sample_process_tree is True and domain.made_by is None

    def test_a_name_only_the_launcher_s_flows_reached_is_withheld(self) -> None:
        report = _report(_sandbox(_lookup_only(84), LAUNCHER))
        assert _answer(report, "domain", C2).startswith(
            "no: the publish rule counted the flows to 172.217.76.94 (an address it resolved to) "
            "as made by the launcher's process (powershell.exe (procid 84))"
        )
        assert not any(C2 in p for p in _patterns(report))
        # The row stays, with whose traffic it is.
        (domain,) = [d for d in report.network.domains if d.fqdn == C2]
        assert domain.made_by is not None and domain.made_by.launcher == [
            "powershell.exe (procid 84)"
        ]

    def test_a_name_with_dns_records_alone_is_decided_as_without_a_process(self) -> None:
        report = _report(_sandbox(_lookup_only(None)))
        (domain,) = [d for d in report.network.domains if d.fqdn == C2]
        assert domain.sample_process_tree is None and domain.made_by is None
        assert _answer(report, "domain", C2) == publish_answer("domain", C2, "sandbox", None)
        assert f"[domain-name:value = '{C2}']" in _patterns(report)

    def test_a_dns_request_takes_no_process_from_its_flow(self) -> None:
        sandbox = _sandbox(_json("behavioral1.json"))
        (request,) = sandbox.network.dns_requests
        assert request.extra == {"flow": 31, "index": 1}


class TestAReportNamingNoProcess:
    def test_decides_as_without_a_process(self) -> None:
        report = _report(_sandbox(_with_flows(flow_31=None, flow_32=None)))
        (domain,) = [d for d in report.network.domains if d.fqdn == HOST]
        assert domain.sample_process_tree is None and domain.made_by is None
        assert publishes(_answer(report, "url", CRL))
        assert f"[url:value = '{CRL}']" in _patterns(report)
        # Stored without the new facts, the row dumps as it did.
        assert "made_by" not in domain.model_dump()
        assert "sample_process_tree" not in domain.model_dump()


class TestTheCostIsLinear:
    def test_many_names_resolving_to_one_address_many_processes_reached(self) -> None:
        # Each name takes the address's flows: names plus flows, never their product.
        def make(n: int) -> list[Any]:
            view = {
                "dns": [
                    {"request": f"n{i}.example.net", "type": "A", "answers": [{"data": C2_ADDRESS}]}
                    for i in range(n)
                ],
                "tcp": [
                    {
                        "dst": C2_ADDRESS,
                        TRAFFIC_PROCESS_KEY: str(1000 + i),
                        PROCESS_UNLISTED_KEY: True,
                    }
                    for i in range(n)
                ],
            }
            return [
                build_entry(
                    entry_id="ev_0001",
                    seq=1,
                    agent="dynamic",
                    tool="sandbox_network",
                    args={},
                    server=None,
                    output=json.dumps(view),
                )
            ]

        network = network_from_ledger(make(40))
        assert network is not None
        made = {d.fqdn: d.made_by for d in network.domains}["n0.example.net"]
        assert made is not None and len(made.unlisted) == 16 and made.more
        assert_scales(make, 400, network_from_ledger, factor=8)


SVCHOST = TrafficMakers(outside=["svchost.exe (procid 9)"])
NAME = "evil.example.net"
ADDRESS = "185.199.111.20"


def _judged(url: str, *, told: bool) -> MalwareReport:
    """A report whose judge kept ``url``, asked or not with its host's fact as validation asks."""
    network = NetworkIOCs(
        ips=[
            NetworkIP(
                address=ADDRESS,
                source="sandbox",
                sample_process_tree=False,
                outside_processes=["svchost.exe (procid 9)"],
            )
        ],
        domains=[
            NetworkDomain(fqdn=NAME, source="sandbox", sample_process_tree=False, made_by=SVCHOST)
        ],
        urls=[NetworkURL(url=url, source="sandbox", sample_process_tree=False, made_by=SVCHOST)],
    )
    facts = sandbox_facts_for_the_judge(network, None, None, {"file_name": "s.exe"})
    bundle = SimpleNamespace(
        objects=[SimpleNamespace(type="indicator", name="u", pattern=f"[url:value = '{url}']")]
    )
    asked = [
        {
            "agent": "judge",
            "code": UNATTRIBUTED_INDICATOR_CODE,
            "message": "kept",
            "answered": "true",
            "subject": v.subject,
        }
        for v in unattributed_indicator_violations(bundle, facts)
    ]
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        overall_confidence=0.9,
        network=network,
        judge_indicators=[JudgeIndicator(kind="url", value=url)],
        run_summary={"validation": {"unresolved": asked}} if told else {},
    )


def _url_answer(report: MalwareReport, url: str) -> str:
    return publish_answer("url", url, "sandbox", None, **sandbox_row_kwargs(report, "url", url))


class TestTheJudgeKeepsAWithheldUrlByItsHost:
    """Validation asks a URL indicator under its host; the keep is read under the same subject."""

    def test_a_url_on_a_name_kept_with_its_host_s_fact_is_published(self) -> None:
        url = f"http://{NAME}/gate"
        answer = _url_answer(_judged(url, told=True), url)
        assert publishes(answer)
        assert "the judge when asked with its host's fact" in answer
        # The URL's own wording: whose traffic its own records say it is.
        assert "made by a process outside the sample's process tree" in answer

    def test_a_url_on_a_name_with_no_question_recorded_stays_withheld(self) -> None:
        url = f"http://{NAME}/gate"
        answer = _url_answer(_judged(url, told=False), url)
        assert answer.startswith(
            "no: the publish rule counted its requests as made by a process outside"
        )
        assert "no question with this fact is recorded" in answer

    def test_a_url_on_an_address_kept_with_its_host_s_fact_is_published(self) -> None:
        url = f"http://{ADDRESS}/gate"
        answer = _url_answer(_judged(url, told=True), url)
        assert publishes(answer)
        assert "the judge when asked with its host's fact" in answer

    def test_a_url_on_an_address_with_no_question_recorded_stays_withheld(self) -> None:
        url = f"http://{ADDRESS}/gate"
        answer = _url_answer(_judged(url, told=False), url)
        assert answer.startswith("no: ")
        assert "no question with this fact is recorded" in answer


LAUNCHER_ROW = {
    TRAFFIC_PROCESS_KEY: "84",
    SAMPLE_TREE_KEY: False,
    LINEAGE_KEY: LINEAGE_LAUNCHER,
    "process": "powershell.exe",
}
UNLISTED_ROW = {TRAFFIC_PROCESS_KEY: "46", PROCESS_UNLISTED_KEY: True}
SAMPLE_ROW = {TRAFFIC_PROCESS_KEY: "86", SAMPLE_TREE_KEY: True}
DISPUTED_ROW = {TRAFFIC_PROCESS_KEY: "5", LINEAGE_DISPUTED_KEY: "marked", "process": "x.exe"}
NO_PROCESS_ROW: dict[str, Any] = {}
MIXED_URL = "http://mixed.example.net/a"
MIXED_ADDRESS = "185.199.108.33"


def _mixed(*, http: tuple[dict[str, Any], ...] = (), tcp: tuple[dict[str, Any], ...] = ()) -> Any:
    """A report of HTTP records on one URL and flows to one address, each with the facts given."""
    view = {
        "http": [{"host": "mixed.example.net", "uri": "/a", **facts} for facts in http],
        "tcp": [{"dst": MIXED_ADDRESS, "dport": 443, **facts} for facts in tcp],
    }
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="dynamic",
        tool="sandbox_network",
        args={},
        server=None,
        output=json.dumps(view),
    )
    network = network_from_ledger([entry])
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        overall_confidence=0.9,
        network=network,
    )


class TestMixedRecords:
    """One value's records naming processes of different lineages, or none."""

    @pytest.mark.parametrize("order", [0, 1])
    def test_the_launcher_and_an_unlisted_process_withhold_it_naming_both(self, order: int) -> None:
        rows = (LAUNCHER_ROW, UNLISTED_ROW)[:: 1 if order == 0 else -1]
        report = _mixed(http=rows)
        (url,) = report.network.urls
        assert url.sample_process_tree is False and url.made_by is not None
        assert url.made_by.launcher == ["powershell.exe (procid 84)"]
        assert url.made_by.unlisted == ["procid 46"]
        answer = _url_answer(report, MIXED_URL)
        assert answer.startswith("no: the publish rule counted its requests as made by ")
        assert "the launcher's process" in answer and "does not list" in answer

    @pytest.mark.parametrize("order", [0, 1])
    def test_the_sample_and_a_disputed_process_publish_it(self, order: int) -> None:
        rows = (SAMPLE_ROW, DISPUTED_ROW)[:: 1 if order == 0 else -1]
        report = _mixed(http=rows)
        (url,) = report.network.urls
        assert url.sample_process_tree is True and url.made_by is None
        assert publishes(_url_answer(report, MIXED_URL))

    @pytest.mark.parametrize("order", [0, 1])
    def test_another_lineage_and_a_record_naming_no_process_decide_it_as_without_one(
        self, order: int
    ) -> None:
        rows = (LAUNCHER_ROW, NO_PROCESS_ROW)[:: 1 if order == 0 else -1]
        report = _mixed(http=rows)
        (url,) = report.network.urls
        assert url.sample_process_tree is None and url.made_by is None
        assert _url_answer(report, MIXED_URL) == publish_answer("url", MIXED_URL, "sandbox", None)

    def test_an_address_some_of_whose_flows_name_no_process_names_no_unlisted_one(self) -> None:
        report = _mixed(tcp=(UNLISTED_ROW, NO_PROCESS_ROW))
        (ip,) = report.network.ips
        assert ip.unlisted_processes == []
        # What the rule read in each flow is said; it is not put on the unlisted process.
        assert _answer(report, "ip", MIXED_ADDRESS).startswith(
            "no: the publish rule found a flow to it made by a process the report does not list "
            "(platform_process 46) and read no process id from its other flow"
        )

    def test_an_address_every_flow_of_which_is_unlisted_names_them(self) -> None:
        report = _mixed(tcp=(UNLISTED_ROW, {**UNLISTED_ROW, TRAFFIC_PROCESS_KEY: "47"}))
        (ip,) = report.network.ips
        assert ip.unlisted_processes == ["procid 46", "procid 47"]
        assert _answer(report, "ip", MIXED_ADDRESS).startswith(
            "no: the publish rule found flows to it made by a process the report does not list "
            "(procid 46, procid 47)"
        )

    def test_an_address_the_launcher_and_an_unlisted_process_reached(self) -> None:
        # Not every flow is unlisted, nor every flow outside the tree: the
        # address is withheld as no flow of the tree reached it, as without
        # the listing.
        report = _mixed(tcp=(LAUNCHER_ROW, UNLISTED_ROW))
        (ip,) = report.network.ips
        assert ip.sample_process_tree is None and ip.unlisted_processes == []
        answer = _answer(report, "ip", MIXED_ADDRESS)
        assert answer.startswith(
            "no: the publish rule found flows to it made by the launcher's process (powershell.exe "
            "platform_process 84) and by a process the report does not list (platform_process 46)"
        )


class TestATaskListingNoProcess:
    def test_a_flow_naming_an_id_says_nothing_of_its_listing(self) -> None:
        task = _json("behavioral1.json")
        task["processes"] = []
        sandbox = _sandbox(task)
        rows = (*sandbox.network.tcp, *sandbox.network.udp, *sandbox.network.http)
        assert rows and all(PROCESS_UNLISTED_KEY not in row for row in rows)
        assert all(row[TRAFFIC_PROCESS_KEY] in ("36", "46") for row in rows)


class TestANameSAddressFlows:
    def test_an_address_flow_naming_no_process_leaves_the_name_as_without_one(self) -> None:
        view = {
            "dns": [
                {"request": "mixed.example.net", "type": "A", "answers": [{"data": MIXED_ADDRESS}]}
            ],
            "tcp": [{"dst": MIXED_ADDRESS, **UNLISTED_ROW}, {"dst": MIXED_ADDRESS}],
        }
        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps(view),
        )
        network = network_from_ledger([entry])
        assert network is not None
        (domain,) = network.domains
        assert domain.sample_process_tree is None and domain.made_by is None


class TestALauncherFlowSharingAnId:
    def test_the_launcher_s_facts_on_a_shared_flow_id_are_marked(self) -> None:
        task = _json("behavioral1.json")
        (flow_32,) = [f for f in task["network"]["flows"] if f["id"] == 32]
        task["network"]["flows"].append({**flow_32, "procid": 84})
        report = _report(_sandbox(task, LAUNCHER))
        url = next(u for u in report.network.urls if u.url == CRL)
        assert url.made_by is not None
        assert url.made_by.launcher == ["powershell.exe (procid 84)"]
        assert url.made_by.unlisted == ["procid 46"]


PAGE_NAME = "c2-gate.example.net"
PAGE_ADDRESS = "93.184.7.7"
PAGE_URL = f"http://{PAGE_NAME}/g"
# A page's flow placed under another lineage is read as placed under none.
UNSTATED_ADDRESS = (
    "no: the publish rule read only part of the network view and did not place the process a "
    "flow to it names by id"
)


def _view_of(facts: dict[str, Any], *, page: bool) -> MalwareReport:
    """A name, its address and a URL on it, each record of the process ``facts`` give.

    ``page`` reads the view as one page of a longer one, as a paged call returns it.
    """
    view = {
        "dns": [{"request": PAGE_NAME, "type": "A", "answers": [{"data": PAGE_ADDRESS}]}],
        "http": [{"host": PAGE_NAME, "uri": "/g", "method": "GET", "port": 80, **facts}],
        "tcp": [{"dst": PAGE_ADDRESS, "dport": 80, **facts}],
        **({"next_offset": 1, "http_total": 2, "tcp_total": 2} if page else {}),
    }
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="dynamic",
        tool="sandbox_network",
        args={"offset": 0, "limit": 1} if page else {},
        server=None,
        output=json.dumps(view),
    )
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        overall_confidence=0.9,
        network=network_from_ledger([entry]),
    )


class TestAPageShowsOnlyThatARecordIsTheSampleS:
    """A page cannot show that no record of a value is the sample's: it may be on another."""

    @pytest.mark.parametrize("facts", [LAUNCHER_ROW, UNLISTED_ROW], ids=["launcher", "unlisted"])
    def test_another_lineage_s_records_leave_the_three_kinds_as_without_them(
        self, facts: dict[str, Any]
    ) -> None:
        report = _view_of(facts, page=True)
        assert _url_answer(report, PAGE_URL) == publish_answer("url", PAGE_URL, "sandbox", None)
        domain = publish_answer(
            "domain", PAGE_NAME, "sandbox", None, **sandbox_row_kwargs(report, "domain", PAGE_NAME)
        )
        assert domain == publish_answer("domain", PAGE_NAME, "sandbox", None)
        address = publish_answer(
            "ip", PAGE_ADDRESS, "sandbox", None, **sandbox_row_kwargs(report, "ip", PAGE_ADDRESS)
        )
        assert address.startswith(UNSTATED_ADDRESS)
        (ip,) = report.network.ips
        assert ip.unlisted_processes == [] and ip.sample_process_tree is None

    @pytest.mark.parametrize("facts", [LAUNCHER_ROW, UNLISTED_ROW], ids=["launcher", "unlisted"])
    def test_a_whole_view_still_withholds_them(self, facts: dict[str, Any]) -> None:
        report = _view_of(facts, page=False)
        assert _url_answer(report, PAGE_URL).startswith(
            "no: the publish rule counted its requests as made"
        )

    def test_the_sample_s_record_on_a_page_publishes_them(self) -> None:
        report = _view_of(SAMPLE_ROW, page=True)
        assert publishes(_url_answer(report, PAGE_URL))
        for kind, value in (("domain", PAGE_NAME), ("ip", PAGE_ADDRESS)):
            kwargs = sandbox_row_kwargs(report, kind, value)
            assert publishes(publish_answer(kind, value, "sandbox", None, **kwargs))


def _view_read(
    facts: dict[str, Any], args: dict[str, Any], markers: dict[str, Any] | None = None
) -> MalwareReport:
    """:func:`_view_of`'s view, called with ``args``, its rows answered beside ``markers``."""
    view = {
        "dns": [{"request": PAGE_NAME, "type": "A", "answers": [{"data": PAGE_ADDRESS}]}],
        "http": [{"host": PAGE_NAME, "uri": "/g", "method": "GET", "port": 80, **facts}],
        "tcp": [{"dst": PAGE_ADDRESS, "dport": 80, **facts}],
        **(markers or {}),
    }
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="dynamic",
        tool="sandbox_network",
        args=args,
        server=None,
        output=json.dumps(view),
    )
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        overall_confidence=0.9,
        network=network_from_ledger([entry]),
    )


class TestAViewIsAPageOnlyWhereItsAnswerShowsItWasCut:
    """A call's row limit makes no page: an answer holding every row is the whole view."""

    def test_an_answer_within_its_row_limit_is_the_whole_view(self) -> None:
        report = _view_read(UNLISTED_ROW, {"offset": 0, "limit": 40})
        (url,) = report.network.urls
        assert url.sample_process_tree is False
        assert url.made_by is not None and url.made_by.unlisted == ["procid 46"]
        assert _url_answer(report, PAGE_URL) == _url_answer(
            _view_of(UNLISTED_ROW, page=False), PAGE_URL
        )

    @pytest.mark.parametrize(
        ("args", "markers"),
        [
            ({"limit": 1}, {"http_total": 2, "http_next_offset": 1}),
            ({}, {"has_more": True}),
            ({}, {"next_cursor": "c2"}),
            ({"offset": 1}, {}),
            ({"limit": 1}, {}),
        ],
        ids=["count", "flag", "next-field", "offset-argument", "list-filling-its-limit"],
    )
    def test_an_answer_that_shows_or_cannot_rule_out_a_cut_is_a_page(
        self, args: dict[str, Any], markers: dict[str, Any]
    ) -> None:
        report = _view_read(UNLISTED_ROW, args, markers)
        (url,) = report.network.urls
        assert url.sample_process_tree is None and url.made_by is None


class TestAnAddressNamesItsProcessByTheNeutralKey:
    """The address's reason names a process by the one key, an older stored row by its field."""

    def _reason(self, row: dict[str, Any]) -> str:
        report = _mixed(tcp=(row,))
        kwargs = sandbox_row_kwargs(report, "ip", MIXED_ADDRESS)
        return publish_answer("ip", MIXED_ADDRESS, "sandbox", None, **kwargs)

    def test_a_flow_naming_its_process_by_another_field_is_named_by_its_id(self) -> None:
        row = {"pid": 1234, TRAFFIC_PROCESS_KEY: "1234", SAMPLE_TREE_KEY: False}
        answer = self._reason({**row, "process": "powershell.exe"})
        assert "(powershell.exe (procid 1234))" in answer and "None" not in answer

    def test_a_stored_row_naming_its_process_by_the_older_field_is_named_by_it(self) -> None:
        answer = self._reason({"procid": 84, SAMPLE_TREE_KEY: False, "process": "powershell.exe"})
        assert "(powershell.exe (procid 84))" in answer

    def test_a_row_naming_no_id_is_named_by_its_image_alone(self) -> None:
        answer = self._reason({SAMPLE_TREE_KEY: False, "process": "powershell.exe"})
        assert "(powershell.exe)" in answer and "procid" not in answer

    def test_a_disputed_process_is_named_by_the_neutral_key(self) -> None:
        answer = self._reason({**DISPUTED_ROW, "pid": 77})
        assert "x.exe (procid 5)" in answer and "None" not in answer


PARTIAL_NAMES = [f"q{i}.example.net" for i in range(12)]
PARTIAL_ADDRESSES = [f"198.51.100.{i + 1}" for i in range(12)]


def _resolved_in_part(procid: int, launcher: dict[str, Any] | None = None) -> Any:
    """One request of twelve names sharing twelve answers that name no name, read whole.

    The request's size bounds what its questions are given together: the
    sixth name is given part of its addresses, the bound spent. Every address
    is reached by a flow of ``procid``.
    """
    task = _json("behavioral1.json")
    task["network"]["requests"] = [
        {
            "flow": 31,
            "index": 1,
            "dns_request": {"questions": [{"name": n, "type": "A"} for n in PARTIAL_NAMES]},
        },
        {
            "flow": 31,
            "index": 1,
            "dns_response": {"answers": [{"type": "A", "value": a} for a in PARTIAL_ADDRESSES]},
        },
    ]
    task["network"]["flows"] += [
        {"id": 90 + i, "proto": "tcp", "dst": f"{a}:443", "procid": procid}
        for i, a in enumerate(PARTIAL_ADDRESSES)
    ]
    network = network_from_ledger([], sandbox_report=sandbox_document(_sandbox(task, launcher)))
    assert network is not None
    return {d.fqdn: d for d in network.domains}


class TestANameResolvedInPart:
    """A name given part of its addresses reads their flows as a page's: the sample's count."""

    @pytest.mark.parametrize(("procid", "launcher"), [(46, None), (84, LAUNCHER)])
    def test_another_lineage_s_flows_to_its_addresses_leave_it_as_without_them(
        self, procid: int, launcher: dict[str, Any] | None
    ) -> None:
        names = _resolved_in_part(procid, launcher)
        partial = names["q5.example.net"]
        assert partial.resolved_ips_partial and partial.resolved_ips
        assert partial.sample_process_tree is None and partial.made_by is None
        # A name given all its addresses is decided by their flows.
        whole = names["q0.example.net"]
        assert not whole.resolved_ips_partial and whole.sample_process_tree is False

    def test_the_sample_s_flow_to_one_of_its_addresses_publishes_it(self) -> None:
        partial = _resolved_in_part(86)["q5.example.net"]
        assert partial.resolved_ips_partial and partial.sample_process_tree is True
