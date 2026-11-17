"""A request's user agent is read where its reader declares the record states it.

Which field of a request record states the User-Agent header is the reader's
declaration (``Reading.request_user_agent_fields``, the channel that declares a
dropped row's size fields), read in one place
(``sandbox_report.request_user_agent``): every declared field, then the
generic ``user_agent``. The network view states each record as it is, the
agent once; the report reads it through that one place with the run's reader,
taken where the job's record holds it. Synthetic reports only.
"""

from __future__ import annotations

from typing import Any

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import read_view
from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.ledger_projection import network_from_ledger, network_from_sandbox_report
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_document import sandbox_document

AGENT = "Mozilla/4.0 (compatible; MSIE 8.0)"
CAPE = ("lab", "cape2")


def _cape(http: list[dict[str, Any]]) -> dict[str, Any]:
    raw = {
        "target": {"file": {"name": "a.exe", "sha256": "a" * 64}},
        "behavior": {"processes": []},
        "network": {"http": http},
    }
    return sandbox_document(required_reader("cape2").read(raw, provider="lab"))


def _row(document: dict[str, Any], reader: Any) -> dict[str, Any]:
    (row,) = read_view("sandbox_network", document, reader)["http"]
    return row


CAPE_ROW = {"host": "c.example.com", "uri": "/g", "method": "GET", "user-agent": AGENT}


def _url(network: Any) -> tuple[Any, Any]:
    assert network is not None
    (url,) = network.urls
    return url.method, url.user_agent


class TestTheViewStatesTheRecordAsItIs:
    def test_a_row_that_states_the_agent_under_its_declared_field_gets_no_second_key(
        self,
    ) -> None:
        row = _row(_cape([CAPE_ROW]), CAPE)

        assert row["user-agent"] == AGENT
        assert "user_agent" not in row

    def test_the_answer_is_the_same_whichever_reader_is_named(self) -> None:
        document = _cape([CAPE_ROW])

        assert _row(document, CAPE) == _row(document, None)


class TestTheReportReadsItWithTheRun_sReader:
    def test_the_report_s_own_read_of_the_document_reads_the_declared_field(self) -> None:
        document = _cape([CAPE_ROW])

        assert _url(network_from_ledger([], sandbox_report=document, normalised_by=CAPE)) == (
            "GET",
            AGENT,
        )
        assert _url(network_from_sandbox_report(document, CAPE)) == ("GET", AGENT)

    def test_an_analyst_s_read_in_the_ledger_is_read_with_the_run_s_reader(self) -> None:
        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output="{}",
        ).model_copy(update={"structured": read_view("sandbox_network", _cape([CAPE_ROW]), CAPE)})

        assert _url(network_from_ledger([entry], normalised_by=CAPE)) == ("GET", AGENT)

    def test_the_declared_field_is_read_before_the_generic_name(self) -> None:
        document = _cape([{**CAPE_ROW, "user_agent": "Own/1.0"}])

        assert _url(network_from_sandbox_report(document, CAPE)) == ("GET", AGENT)
        # A read that names no reader knows the generic name alone.
        assert _url(network_from_sandbox_report(document, None)) == ("GET", "Own/1.0")

    def test_the_report_s_network_table_prints_it(self) -> None:
        report = MalwareReportBuilder(
            file_hash="a" * 64,
            file_name="a.exe",
            sample_path=None,
            sandbox_report=_cape([CAPE_ROW]),
            sandbox_normalised_by=CAPE,
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.8,
            sample_platform="windows",
            sample_file_type="PE",
            evidence_ledger=[],
        ).build_deterministic()

        lines = [line for line in MarkdownRenderer().render(report).splitlines() if "/g" in line]
        assert any(AGENT in line and "GET" in line for line in lines), lines
