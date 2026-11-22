"""A feed row is suspicious where the network block flags it or its publication claims activity.

``is_suspicious`` is true where a detector or a reputation source flagged the
value in the report's network block, or the IOC table publishes the row under
a type that claims activity: any type but ``benign`` or ``unknown`` (the
vocabulary's words for no claim of activity), read whatever its case or
surrounding space, and a published row with no type. So a published row is
never served as not suspicious beside its own publication, and a flag the
network block holds is never lost by a withholding. A form row is no domain:
the network block's flag, read of it as one, does not stand on it.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.report_service import _claims_activity, ioc_feed_rows
from malspark.reporting.models import ConsolidatedIOC

# A URL the sample requested, its host, an address in the sample's process
# tree, an address no flow of the tree reaches that a reputation source
# flagged, and a mutex an analyst listed.
NETWORK: dict[str, Any] = {
    "domains": [
        {
            "fqdn": "c2.example.com",
            "source": "sandbox",
            "is_suspicious": False,
            "reason": None,
            "queried_pids": [],
            "resolved_ips": [],
        },
    ],
    "ips": [
        {
            "address": "203.0.113.7",
            "source": "sandbox",
            "is_suspicious": False,
            "sample_process_tree": True,
        },
        {
            "address": "198.51.100.23",
            "source": "sandbox",
            "is_suspicious": True,
            "sample_process_tree": False,
        },
    ],
    "urls": [{"url": "http://c2.example.com/gate", "source": "sandbox", "method": "GET"}],
    "user_agents": [],
    "ja3_fingerprints": [],
    "ja3s_fingerprints": [],
}


def _report(verdict: str, confidence: float | None = 0.9) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": "2026-05-16T00:00:00+00:00",
        "verdict": verdict,
        "identity": {
            "hashes": {"sha256": "f" * 64},
            "file_name": "sample.exe",
            "file_type": "PE",
            "signing": {"is_signed": False},
        },
        "network": NETWORK,
        "executive_summary": "",
    }
    if confidence is not None:
        report["overall_confidence"] = confidence
    return report


def _by_value(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["value"]: row for row in rows}


class TestTheFlagFollowsThePublication:
    def test_every_published_row_under_an_activity_type_is_suspicious(self) -> None:
        rows = ioc_feed_rows(_report("Malware"))

        published = [row for row in rows if row["published"]]
        assert published
        assert all(
            row["is_suspicious"] for row in published if row["indicator_type"] != "benign"
        ), [(row["value"], row["indicator_type"]) for row in published]

    def test_a_published_url_and_its_published_host_agree(self) -> None:
        rows = _by_value(ioc_feed_rows(_report("Malware")))

        url, host = rows["http://c2.example.com/gate"], rows["c2.example.com"]
        assert url["published"] and host["published"]
        assert url["is_suspicious"] is True
        assert host["is_suspicious"] is True

    def test_the_sample_s_own_digest_is_suspicious_under_a_malware_verdict(self) -> None:
        rows = _by_value(ioc_feed_rows(_report("Malware")))

        assert rows["sha256:" + "f" * 64]["is_suspicious"] is True

    def test_a_published_row_of_a_kind_the_network_block_never_flags_is_suspicious(
        self,
    ) -> None:
        rows = _by_value(ioc_feed_rows(_report("Malware")))

        for value in ("http://c2.example.com/gate", "sha256:" + "f" * 64):
            assert rows[value]["published"] is True
            assert rows[value]["is_suspicious"] is True


class TestTheNetworkBlockSFlagStands:
    def test_a_withheld_row_a_reputation_source_flagged_keeps_that_flag(self) -> None:
        row = _by_value(ioc_feed_rows(_report("Malware")))["198.51.100.23"]

        assert row["published"] is False
        assert row["is_suspicious"] is True

    def test_a_withheld_row_nothing_flagged_is_not_suspicious(self) -> None:
        network = {
            **NETWORK,
            "ips": [{**NETWORK["ips"][1], "is_suspicious": False}],
        }
        row = _by_value(ioc_feed_rows({**_report("Malware"), "network": network}))["198.51.100.23"]

        assert row["published"] is False
        assert row["is_suspicious"] is False

    def test_a_form_row_carries_no_flag_the_network_block_read_of_it_as_a_domain(
        self,
    ) -> None:
        report = {
            **_report("Malware"),
            "static": {"interesting_strings": [{"kind": "domain", "value": "q7zk3vbn.x9kq2.name"}]},
            "network": {
                **NETWORK,
                "domains": [
                    *NETWORK["domains"],
                    {
                        "fqdn": "q7zk3vbn.x9kq2.name",
                        "source": "strings",
                        "is_suspicious": True,
                        "reason": "DGA-like (score 0.80)",
                        "dga_score": 0.8,
                    },
                ],
            },
        }

        row = _by_value(ioc_feed_rows(report))["q7zk3vbn.x9kq2.name"]

        assert "type" in row and row["kind"] != "domain"
        assert row["published"] is False
        assert row["is_suspicious"] is False


class TestATypeThatClaimsNoActivity:
    def test_the_digest_published_as_benign_is_not_suspicious(self) -> None:
        row = _by_value(ioc_feed_rows(_report("Benign")))["sha256:" + "f" * 64]

        assert row["published"] is True
        assert row["indicator_type"] == "benign"
        assert row["is_suspicious"] is False

    def test_the_digest_published_as_unknown_is_not_suspicious(self) -> None:
        row = _by_value(ioc_feed_rows(_report("Malware", confidence=None)))["sha256:" + "f" * 64]

        assert row["published"] is True
        assert row["indicator_type"] == "unknown"
        assert row["is_suspicious"] is False


def _published(indicator_type: str | None) -> ConsolidatedIOC:
    return ConsolidatedIOC(
        type="Mutex",
        value="Local\\example-lock",
        kind="mutex",
        source="judge",
        published="yes: the judge's own indicator",
        role="indicator",
        indicator_type=indicator_type,
    )


class TestTheTypeIsReadWhateverItsCase:
    @pytest.mark.parametrize("written", ["Benign", " UNKNOWN ", "benign\n", "Unknown"])
    def test_a_no_claim_type_in_any_case_claims_no_activity(self, written: str) -> None:
        assert _claims_activity(_published(written)) is False

    @pytest.mark.parametrize("written", ["Malicious-Activity", " anomalous-activity ", None])
    def test_any_other_type_and_no_type_claim_activity(self, written: str | None) -> None:
        assert _claims_activity(_published(written)) is True

    def test_a_withheld_row_claims_no_activity_whatever_its_type(self) -> None:
        row = _published("malicious-activity").model_copy(
            update={"published": "no: no model kept it"}
        )

        assert _claims_activity(row) is False


class TestNoOtherFieldMoves:
    def test_the_note_still_carries_the_network_block_s_reason(self) -> None:
        network = {
            **NETWORK,
            "domains": [{**NETWORK["domains"][0], "reason": "resolved by the sample"}],
        }
        report = {**_report("Malware"), "network": network}

        row = _by_value(ioc_feed_rows(report))["c2.example.com"]

        assert row["notes"] == "resolved by the sample"
