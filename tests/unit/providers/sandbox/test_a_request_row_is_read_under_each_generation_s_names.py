"""A task report's DNS and HTTP requests are read under every name the report writes them under.

One generation of Triage's task report writes a question and its answer on one
row (``domain_req``/``domain_resp``, ``web_req``/``web_resp``); another writes
each on a row of its own (``dns_request``/``dns_response``,
``http_request``/``http_response``), naming the flow and the exchange's index.
Both fill the same model fields. A row of a kind the reader does not read is
kept whole in a channel of its kind, so it is counted, never dropped.

The live reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission (an archive holding a text file and a
PowerShell script that starts cmd.exe); their DNS and HTTP rows are the guest's
own certificate-revocation traffic.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_channels, sandbox_network
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import (
    SAMPLE_TREE_KEY,
    TRIAGE_UNREAD_KIND_NAME,
    TRIAGE_UNREAD_KINDS,
    TRIAGE_UNREAD_KINDS_FOLDED_KEY,
    TRIAGE_UNREAD_REQUESTS_CHANNEL,
    SandboxReport,
)
from tests.linear_cost import assert_scales

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox"
LIVE = FIXTURES / "triage_live"
CRL = "http://c.pki.goog/r/r1.crl"
CRL2 = "http://c.pki.goog/wr2/oBFYYahzgVI.crl"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read(tasks: dict[str, dict[str, Any]], overview: dict[str, Any] | None = None) -> Any:
    return required_reader("triage").read(
        overview or _json(LIVE / "overview.json"),
        provider="triage",
        task_id="s1",
        task_reports=tasks,
    )


def _live() -> SandboxReport:
    return _read(
        {
            "behavioral1": _json(LIVE / "behavioral1.json"),
            "behavioral2": _json(LIVE / "behavioral2.json"),
        }
    )


def _unread_channels(report: SandboxReport) -> list[str]:
    return [name for name in report.channels if name.startswith(TRIAGE_UNREAD_REQUESTS_CHANNEL)]


def _bare(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in row.items() if k != "extra"} for row in rows]


# The process facts of the live report's HTTP flow (32): procid 46, not listed.
FLOW_32 = {
    "procid": 46,
    "pid": 2572,
    "platform_process": "46",
    "process_not_listed": True,
    "platform_task": "behavioral1",
}


def _task(*requests: dict[str, Any]) -> dict[str, Any]:
    return {"processes": [], "network": {"requests": list(requests)}}


OLD_DNS = {
    "flow": 2,
    "domain_req": {"questions": [{"name": "old.example", "type": "A"}]},
    "domain_resp": {"answers": [{"name": "old.example", "type": "A", "value": "192.0.2.1"}]},
}
OLD_HTTP = {
    "flow": 1,
    "web_req": {
        "method": "POST",
        "url": "https://old.example/gate.php",
        "headers": {"User-Agent": "UA-old"},
    },
    "web_resp": {"status": 200, "headers": {}},
}


class TestTheLiveGeneration:
    def test_the_dns_question_and_its_answers_are_one_request(self) -> None:
        report = _live()
        (request,) = report.network.dns_requests
        assert request.questions == [{"request": "c.pki.goog", "type": "IN A"}]
        assert request.answers == [{"data": "pki-goog.l.google.com"}, {"data": "172.217.76.94"}]
        # The exchange's own fields, as each of its rows names them; no process
        # facts: the flow it rode on is the guest's resolver.
        assert request.extra == {"flow": 31, "index": 1}
        assert report.network.domains == ["c.pki.goog"]
        dns = sandbox_document(report)["network"]["dns"]
        assert _bare(dns) == [
            {
                "request": "c.pki.goog",
                "type": "IN A",
                "answers": [{"data": "pki-goog.l.google.com"}, {"data": "172.217.76.94"}],
            }
        ]

    def test_each_http_request_is_paired_with_its_own_answer(self) -> None:
        report = _live()
        assert _bare(report.network.http) == [
            {
                "host": "c.pki.goog",
                "uri": "/r/r1.crl",
                "method": "GET",
                "status": 200,
                "port": None,
                "encrypted": False,
                "user_agent": "Microsoft-CryptoAPI/10.0",
                **FLOW_32,
            },
            {
                "host": "c.pki.goog",
                "uri": "/wr2/oBFYYahzgVI.crl",
                "method": "GET",
                "status": 200,
                "port": None,
                "encrypted": False,
                "user_agent": "Microsoft-CryptoAPI/10.0",
                **FLOW_32,
            },
        ]
        first, second = (row["extra"] for row in report.network.http)
        assert (first["flow"], first["index"], first["request"]["url"]) == (32, 1, CRL)
        assert (second["flow"], second["index"], second["request"]["url"]) == (32, 2, CRL2)
        # Each answer stays with its request: the two answers' lengths differ.
        assert "Content-Length: 993" in first["response"]["headers"]
        assert "Content-Length: 107468" in second["response"]["headers"]

    def test_no_request_row_of_the_live_report_is_left_unread(self) -> None:
        report = _live()
        assert not _unread_channels(report)

    def test_an_http_request_takes_the_process_facts_of_its_flow(self) -> None:
        # The rows name no process; the flows they rode on name processes the
        # task does not list (the guest's own services), so no HTTP row is the
        # sample's and each says its process is not listed.
        report = _live()
        assert all(SAMPLE_TREE_KEY not in row for row in report.network.http)
        flows = (*report.network.tcp, *report.network.udp)
        assert all(SAMPLE_TREE_KEY not in row for row in flows)
        assert {row["procid"] for row in flows} == {36, 46}
        assert all(row["process_not_listed"] is True for row in (*flows, *report.network.http))

    def test_a_request_on_a_flow_of_another_task_takes_nothing_from_it(self) -> None:
        one = _json(LIVE / "behavioral1.json")
        two = _json(LIVE / "behavioral2.json")
        # The second task's requests name flow 32, which only the first task holds.
        two["network"]["requests"] = [r for r in one["network"]["requests"] if r["flow"] == 32]
        report = _read(
            {
                "behavioral1": {**one, "network": {**one["network"], "requests": []}},
                "behavioral2": two,
            }
        )
        assert report.network.http and all("procid" not in r for r in report.network.http)


class TestTheStoredGeneration:
    def test_a_row_holding_both_parts_reads_as_before(self) -> None:
        report = _read({"behavioral1": _task(OLD_DNS, OLD_HTTP)})
        (request,) = report.network.dns_requests
        assert request.questions == [{"request": "old.example", "type": "A"}]
        assert request.answers == [{"data": "192.0.2.1"}]
        assert request.extra == {"flow": 2}
        assert _bare(report.network.http) == [
            {
                "host": "old.example",
                "uri": "/gate.php",
                "method": "POST",
                "status": 200,
                "port": None,
                "encrypted": True,
                "user_agent": "UA-old",
            }
        ]
        assert report.network.http[0]["extra"] == {
            "flow": 1,
            "request": {"url": "https://old.example/gate.php", "headers": {"User-Agent": "UA-old"}},
            "response": {"headers": {}},
        }

    def test_two_rows_on_one_flow_without_an_index_stay_two_requests(self) -> None:
        second = copy.deepcopy(OLD_HTTP)
        second["web_req"]["url"] = "https://old.example/two"
        report = _read({"behavioral1": _task(OLD_HTTP, second)})
        assert [row["uri"] for row in report.network.http] == ["/gate.php", "/two"]


class TestAMixedReport:
    def test_both_generations_are_read(self) -> None:
        live = _json(LIVE / "behavioral1.json")
        live["network"]["requests"] = [OLD_DNS, *live["network"]["requests"], OLD_HTTP]
        report = _read({"behavioral1": live})
        assert [q["request"] for r in report.network.dns_requests for q in r.questions] == [
            "old.example",
            "c.pki.goog",
        ]
        assert report.network.domains == ["old.example", "c.pki.goog"]
        assert [row["host"] + row["uri"] for row in report.network.http] == [
            "c.pki.goog/r/r1.crl",
            "c.pki.goog/wr2/oBFYYahzgVI.crl",
            "old.example/gate.php",
        ]


class TestARowOfAnotherKind:
    def test_is_kept_whole_and_counted_by_its_kind(self) -> None:
        smtp = {"flow": 7, "index": 1, "smtp_request": {"from": "a@example.org"}}
        smtp2 = {"flow": 7, "index": 2, "smtp_request": {"from": "b@example.org"}}
        tls = {"flow": 8, "index": 1, "tls_hello": {"sni": "example.org"}}
        bare = {"flow": 9, "index": 1, "note": "text only"}
        live = _json(LIVE / "behavioral1.json")
        live["network"]["requests"] += [smtp, tls, smtp2, bare]
        report = _read({"behavioral1": live})
        document = sandbox_document(report)
        name = f"{TRIAGE_UNREAD_REQUESTS_CHANNEL}.smtp_request"
        answer = sandbox_channels(document, name)
        assert answer["total"] == 2
        assert [row["smtp_request"]["from"] for row in answer["rows"]] == [
            "a@example.org",
            "b@example.org",
        ]
        assert all(row["task_report"] == "behavioral1" for row in answer["rows"])
        tls_channel = f"{TRIAGE_UNREAD_REQUESTS_CHANNEL}.tls_hello"
        assert sandbox_channels(document, tls_channel)["total"] == 1
        assert sandbox_channels(document, TRIAGE_UNREAD_REQUESTS_CHANNEL)["total"] == 1
        # The rows read are read as without them.
        assert len(report.network.http) == 2 and len(report.network.dns_requests) == 1

    def test_an_answer_with_no_request_is_kept_and_counted(self) -> None:
        live = _json(LIVE / "behavioral1.json")
        orphan_dns = {"flow": 40, "index": 1, "dns_response": {"answers": [{"value": "192.0.2.4"}]}}
        orphan_http = {"flow": 41, "index": 3, "http_response": {"status": "404"}}
        old_orphan = {"flow": 42, "domain_resp": {"answers": [{"value": "192.0.2.5"}]}}
        live["network"]["requests"] += [orphan_dns, orphan_http, old_orphan]
        document = sandbox_document(_read({"behavioral1": live}))
        dns = sandbox_channels(document, f"{TRIAGE_UNREAD_REQUESTS_CHANNEL}.dns_response")
        http = sandbox_channels(document, f"{TRIAGE_UNREAD_REQUESTS_CHANNEL}.http_response")
        old = sandbox_channels(document, f"{TRIAGE_UNREAD_REQUESTS_CHANNEL}.domain_resp")
        assert (dns["total"], http["total"], old["total"]) == (1, 1, 1)
        assert dns["rows"][0]["dns_response"] == orphan_dns["dns_response"]
        # No answer is read as a request of its own.
        assert len(document["network"]["http"]) == 2

    def test_a_part_of_an_unread_kind_beside_a_read_one_stays_on_the_row(self) -> None:
        row = {
            "flow": 3,
            "index": 1,
            "http_request": {"method": "GET", "url": "http://x.example/"},
            "ws_upgrade": {"v": 13},
        }
        report = _read({"behavioral1": _task(row)})
        (http,) = report.network.http
        assert http["extra"]["ws_upgrade"] == {"v": 13}
        assert not _unread_channels(report)


class TestDownstream:
    def test_the_dns_name_and_the_url_reach_the_ledger_s_network_block(self) -> None:
        view = sandbox_network(sandbox_document(_live()))
        assert [row["request"] for row in view["dns"]] == ["c.pki.goog"]
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
        domains = {d.fqdn: d for d in network.domains}
        assert "c.pki.goog" in domains
        assert "172.217.76.94" in domains["c.pki.goog"].resolved_ips
        urls = {u.url: u for u in network.urls}
        assert CRL in urls and CRL2 in urls
        assert urls[CRL].method == "GET"
        assert domains["c.pki.goog"].source == "sandbox" and urls[CRL].source == "sandbox"


class TestAnswersArePairedInOrder:
    """An answer joins the first open question of its flow and index."""

    def test_two_http_requests_on_one_flow_and_index_keep_their_own_answers(self) -> None:
        rows = [
            {"flow": 5, "index": 1, "http_request": {"method": "GET", "url": "http://x.example/1"}},
            {"flow": 5, "index": 1, "http_request": {"method": "GET", "url": "http://x.example/2"}},
            {"flow": 5, "index": 1, "http_response": {"status": "200"}},
            {"flow": 5, "index": 1, "http_response": {"status": "404"}},
        ]
        report = _read({"behavioral1": _task(*rows)})
        assert [(row["uri"], row["status"]) for row in report.network.http] == [
            ("/1", 200),
            ("/2", 404),
        ]

    def test_two_dns_questions_on_one_flow_and_index_keep_their_own_answers(self) -> None:
        def question(name: str) -> dict[str, Any]:
            return {"flow": 6, "index": 1, "dns_request": {"questions": [{"name": name}]}}

        def answer(value: str) -> dict[str, Any]:
            return {"flow": 6, "index": 1, "dns_response": {"answers": [{"value": value}]}}

        rows = [
            question("a.example"),
            question("b.example"),
            answer("192.0.2.1"),
            answer("192.0.2.2"),
        ]
        report = _read({"behavioral1": _task(*rows)})
        assert [(r.questions[0]["request"], r.answers) for r in report.network.dns_requests] == [
            ("a.example", [{"data": "192.0.2.1"}]),
            ("b.example", [{"data": "192.0.2.2"}]),
        ]

    def test_an_answer_written_before_its_question_is_still_its(self) -> None:
        rows = [
            {"flow": 7, "index": 1, "http_response": {"status": 301}},
            {"flow": 7, "index": 1, "http_request": {"method": "GET", "url": "http://y.example/"}},
        ]
        (row,) = _read({"behavioral1": _task(*rows)}).network.http
        assert row["status"] == 301


class TestTheKindsOfUnreadRowsAreBounded:
    """Each task keeps a bounded number of unread kinds, of bounded names; no row is cut."""

    def test_kinds_beyond_the_limit_join_the_bare_channel_counted(self) -> None:
        kinds = [{"flow": 9, "index": i, f"kind{i:02d}": {"n": i}} for i in range(40)]
        long_name = {"flow": 9, "index": 99, "k" * (TRIAGE_UNREAD_KIND_NAME + 1): {"n": 0}}
        report = _read({"behavioral1": _task(*kinds, long_name)})
        named = [
            name for name in _unread_channels(report) if name != TRIAGE_UNREAD_REQUESTS_CHANNEL
        ]
        assert named == [f"{TRIAGE_UNREAD_REQUESTS_CHANNEL}.kind{i:02d}" for i in range(16)]
        assert TRIAGE_UNREAD_KINDS == 16
        document = sandbox_document(report)
        bare = sandbox_channels(document, TRIAGE_UNREAD_REQUESTS_CHANNEL, limit=100)
        assert bare["total"] == 25
        assert all(row[TRIAGE_UNREAD_KINDS_FOLDED_KEY] == 25 for row in bare["rows"])
        # Every row is kept: the named kinds' rows and the bare channel's.
        assert sum(sandbox_channels(document, n)["total"] for n in named) + bare["total"] == 41

    def test_a_kind_that_is_read_is_never_cut(self) -> None:
        kinds = [{"flow": 9, "index": i, f"kind{i:02d}": {"n": i}} for i in range(40)]
        live = _json(LIVE / "behavioral1.json")
        live["network"]["requests"] = kinds + live["network"]["requests"]
        report = _read({"behavioral1": live})
        assert len(report.network.http) == 2 and len(report.network.dns_requests) == 1


class TestTheCostIsLinear:
    def test_many_questions_on_one_flow_and_index_then_their_answers(self) -> None:
        def make(n: int) -> dict[str, Any]:
            questions = [
                {"flow": 1, "index": 1, "http_request": {"url": f"http://x.example/{i}"}}
                for i in range(n)
            ]
            answers = [{"flow": 1, "index": 1, "http_response": {"status": 200}} for _ in range(n)]
            return _task(*questions, *answers)

        report = _read({"behavioral1": make(3)})
        assert [row["status"] for row in report.network.http] == [200, 200, 200]
        assert_scales(make, 500, lambda task: _read({"behavioral1": task}), factor=8)

    def test_many_unread_kinds_with_long_names(self) -> None:
        def make(n: int) -> dict[str, Any]:
            return _task(*({"flow": 1, "index": i, f"{i}{'k' * 80}": {"n": i}} for i in range(n)))

        assert_scales(make, 20000, lambda task: _read({"behavioral1": task}), factor=8)


class TestALongKindName:
    def test_a_kind_with_a_longer_name_joins_the_bare_channel(self) -> None:
        row = {"flow": 9, "index": 1, "k" * (TRIAGE_UNREAD_KIND_NAME + 1): {"n": 0}}
        report = _read({"behavioral1": _task(row)})
        assert _unread_channels(report) == [TRIAGE_UNREAD_REQUESTS_CHANNEL]
        bare = sandbox_channels(sandbox_document(report), TRIAGE_UNREAD_REQUESTS_CHANNEL)
        assert bare["total"] == 1 and bare["rows"][0][TRIAGE_UNREAD_KINDS_FOLDED_KEY] == 1

    def test_the_name_bound_alone_folds_a_kind(self) -> None:
        # Two kinds, far under the bound on their number: a name of 65
        # characters is folded, one of 64 keeps its channel.
        assert TRIAGE_UNREAD_KIND_NAME == 64
        longer, longest_kept = "k" * 65, "m" * 64
        rows = (
            {"flow": 9, "index": 1, longer: {"n": 0}},
            {"flow": 9, "index": 2, longest_kept: {}},
        )
        report = _read({"behavioral1": _task(*rows)})
        assert sorted(_unread_channels(report)) == [
            TRIAGE_UNREAD_REQUESTS_CHANNEL,
            f"{TRIAGE_UNREAD_REQUESTS_CHANNEL}.{longest_kept}",
        ]
