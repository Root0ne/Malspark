"""A part of a view never overrides the whole view, and a process it names is unplaced, never none.

Where the run read the whole network view of a detonation, that view's reading
of who made a request decides: a part of the same detonation's view (a page,
an answer cut short, or one exactly as long as its row limit) adds only a
record of the sample's tree. Where only parts were read, a part can only show
that a record is the sample's, so a process of another lineage it names is
placed neither in the sample's tree nor outside it: a URL or a host name whose
records all name processes, none of them the sample's and some only in parts,
is unattributed, and published only on the judge's keep against that fact, as
an undecided address is. A record that names no process at all keeps the
reading a value without a process fact has. An address reads as it did.

Every value is synthetic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.reporting.ledger_projection import network_from_ledger
from malspark.reporting.models import (
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkURL,
    SampleIdentity,
    TrafficMakers,
    UnplacedTraffic,
)
from malspark.reporting.renderers.stix_renderer import (
    publish_answer,
    publishes,
    sandbox_facts_for_the_judge,
    sandbox_row_kwargs,
    unplaced_traffic_reason,
)
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_report import (
    PROCESS_UNLISTED_KEY,
    SAMPLE_TREE_KEY,
    TRAFFIC_PROCESS_KEY,
)
from tests.unit.reporting._sandbox_fact import answered_the_sandbox_fact

NAME = "relay.example.net"
ADDRESS = "203.0.113.7"
URL = f"http://{NAME}/g"
UNLISTED = {TRAFFIC_PROCESS_KEY: "46", PROCESS_UNLISTED_KEY: True}
SAMPLE = {TRAFFIC_PROCESS_KEY: "86", SAMPLE_TREE_KEY: True}
NONE: dict[str, Any] = {}
# A view called with no bound and answered whole; a page its own markers cut;
# an answer exactly as long as its row limit, with no marker beside it.
WHOLE: tuple[dict[str, Any], dict[str, Any]] = ({}, {})
CUT = ({"offset": 0, "limit": 1}, {"http_total": 2, "tcp_total": 2, "next_offset": 1})
FILLED: tuple[dict[str, Any], dict[str, Any]] = ({"limit": 1}, {})
COUNTED = (
    "no: the publish rule counted its requests as made by a process the report does not list "
    "(procid 46)"
)
URL_UNPLACED = (
    "no: the publish rule read only part of the network view and did not place the process "
    "the requests to it name by id (procid 46)"
)
NAME_UNPLACED = (
    "no: the publish rule read only part of the network view and did not place the process "
    "the traffic records to it name by id (procid 46)"
)
# What the address rule says of the address in each reading, as it said it.
ADDRESS_BESIDE_A_WHOLE_VIEW = (
    "the publish rule found a flow to it made by a process the report does not list "
    "(platform_process 46)"
)
ADDRESS_IN_PARTS = (
    "the publish rule read only part of the network view and did not place the process a "
    "flow to it names by id (platform_process 46)"
)


def _entry(number: int, facts: dict[str, Any], args: dict[str, Any], marks: dict[str, Any]) -> Any:
    view = {
        "dns": [{"request": NAME, "type": "A", "answers": [{"data": ADDRESS}]}],
        "http": [{"host": NAME, "uri": "/g", "method": "GET", "port": 80, **facts}],
        "tcp": [{"dst": ADDRESS, "dport": 80, **facts}],
        **marks,
    }
    return build_entry(
        entry_id=f"ev_{number:04d}",
        seq=number,
        agent="dynamic",
        tool="sandbox_network",
        args=args,
        server=None,
        output=json.dumps(view),
    )


def _report(
    facts: dict[str, Any], *reads: tuple[dict[str, Any], dict[str, Any]], kept: bool = False
) -> MalwareReport:
    ledger = [_entry(n, facts, args, marks) for n, (args, marks) in enumerate(reads, 1)]
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64)),
        verdict="Malware",
        overall_confidence=0.9,
        network=network_from_ledger(ledger),
        judge_indicators=(
            [JudgeIndicator(kind="url", value=URL), JudgeIndicator(kind="domain", value=NAME)]
            if kept
            else []
        ),
        run_summary=answered_the_sandbox_fact(f"domain:{NAME}") if kept else {},
    )


def _answer(report: MalwareReport, kind: str, value: str) -> str:
    return publish_answer(kind, value, "sandbox", None, **sandbox_row_kwargs(report, kind, value))


class TestAPartBesideAWholeView:
    @pytest.mark.parametrize("part", [CUT, FILLED], ids=["cut", "filled-its-limit"])
    @pytest.mark.parametrize("first", [True, False], ids=["whole-first", "part-first"])
    def test_the_whole_view_s_unlisted_process_decides(
        self, part: tuple[dict[str, Any], dict[str, Any]], first: bool
    ) -> None:
        reads = (WHOLE, part) if first else (part, WHOLE)
        report = _report(UNLISTED, *reads)
        (url,) = report.network.urls
        assert url.sample_process_tree is False and url.unplaced is None
        assert url.made_by is not None and url.made_by.unlisted == ["procid 46"]
        assert _answer(report, "url", URL).startswith(COUNTED)
        assert _answer(report, "url", URL) == _answer(_report(UNLISTED, WHOLE), "url", URL)
        assert not publishes(_answer(report, "domain", NAME))

    def test_a_part_still_shows_the_sample_s_record(self) -> None:
        whole = _entry(1, UNLISTED, *WHOLE)
        part = _entry(2, SAMPLE, *CUT)
        network = network_from_ledger([whole, part])
        assert network is not None
        (url,) = network.urls
        assert url.sample_process_tree is True

    @pytest.mark.parametrize("part", [CUT, FILLED], ids=["cut", "filled-its-limit"])
    def test_the_address_reads_as_it_did(self, part: tuple[dict[str, Any], dict[str, Any]]) -> None:
        report = _report(UNLISTED, WHOLE, part)
        said = sandbox_row_kwargs(report, "ip", ADDRESS)
        assert said["unattributed"] == ADDRESS_BESIDE_A_WHOLE_VIEW


class TestPartsAlone:
    @pytest.mark.parametrize(
        "reads", [(CUT,), (FILLED,), (CUT, CUT)], ids=["cut", "filled-its-limit", "two-parts"]
    )
    def test_a_url_and_its_name_are_unattributed(
        self, reads: tuple[tuple[dict[str, Any], dict[str, Any]], ...]
    ) -> None:
        report = _report(UNLISTED, *reads)
        (url,) = report.network.urls
        assert url.sample_process_tree is None and url.made_by is None
        assert url.unplaced is not None and url.unplaced.processes == ["procid 46"]
        assert _answer(report, "url", URL).startswith(URL_UNPLACED)
        assert _answer(report, "domain", NAME).startswith(NAME_UNPLACED)
        assert not publishes(_answer(report, "url", URL))
        assert not publishes(_answer(report, "domain", NAME))

    def test_the_judge_is_asked_with_the_fact(self) -> None:
        report = _report(UNLISTED, CUT)
        ask = sandbox_facts_for_the_judge(report.network)
        assert f"no: {ask('url', URL)}" == URL_UNPLACED
        assert f"no: {ask('domain', NAME)}" == NAME_UNPLACED

    def test_kept_by_the_judge_against_the_fact_they_are_published(self) -> None:
        report = _report(UNLISTED, CUT, kept=True)
        assert publishes(_answer(report, "url", URL))
        assert publishes(_answer(report, "domain", NAME))

    @pytest.mark.parametrize("reads", [(CUT,), (FILLED,)], ids=["cut", "filled-its-limit"])
    def test_the_address_reads_as_it_did(
        self, reads: tuple[tuple[dict[str, Any], dict[str, Any]], ...]
    ) -> None:
        report = _report(UNLISTED, *reads)
        assert sandbox_row_kwargs(report, "ip", ADDRESS)["unattributed"] == ADDRESS_IN_PARTS


class TestARecordNamingNoProcess:
    @pytest.mark.parametrize(
        "reads", [(WHOLE,), (CUT,), (WHOLE, CUT)], ids=["whole", "cut", "both"]
    )
    def test_keeps_the_reading_without_a_process_fact(
        self, reads: tuple[tuple[dict[str, Any], dict[str, Any]], ...]
    ) -> None:
        report = _report(NONE, *reads)
        (url,) = report.network.urls
        assert url.unplaced is None and url.made_by is None
        assert _answer(report, "url", URL) == publish_answer("url", URL, "sandbox", None)
        assert publishes(_answer(report, "domain", NAME))

    def test_beside_a_part_s_unlisted_process_it_keeps_that_reading(self) -> None:
        unlisted = _entry(1, UNLISTED, *CUT)
        silent = _entry(2, NONE, {"offset": 1, "limit": 1}, {"http_total": 2, "tcp_total": 2})
        network = network_from_ledger([unlisted, silent])
        assert network is not None
        (url,) = network.urls
        assert url.unplaced is None and url.made_by is None and url.sample_process_tree is None


class TestTheSentence:
    def test_records_placed_elsewhere_are_counted_before_the_processes_not_placed(self) -> None:
        row = NetworkURL(
            url=URL,
            source="sandbox",
            unplaced=UnplacedTraffic(
                processes=["procid 47"],
                views=["d2"],
                placed=TrafficMakers(unlisted=["procid 46"]),
                more=True,
            ),
        )
        assert unplaced_traffic_reason(row, "url") == (
            "the publish rule read only part of detonation d2's network view and counted "
            "requests to it as made by a process the report does not list (procid 46) and did "
            "not place the process the other requests to it name by id (procid 47) (and further "
            "processes the records name)"
        )

    def test_a_row_the_tree_made_or_one_with_no_such_process_says_nothing(self) -> None:
        unplaced = UnplacedTraffic(processes=["procid 47"])
        made = NetworkURL(url=URL, source="sandbox", sample_process_tree=True, unplaced=unplaced)
        assert unplaced_traffic_reason(made, "url") == ""
        assert unplaced_traffic_reason(NetworkURL(url=URL, source="sandbox"), "url") == ""

    def test_a_stored_row_without_the_fact_dumps_as_it_did(self) -> None:
        assert "unplaced" not in NetworkURL(url=URL, source="sandbox").model_dump()
