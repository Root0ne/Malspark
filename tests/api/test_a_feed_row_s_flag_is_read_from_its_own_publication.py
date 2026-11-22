"""A row of ``/iocs`` carries ``is_suspicious`` from the record that decides its publication.

The flag is read off the row of the report's IOC table the feed serves, the
same record its ``published`` answer and its export type come from: a row the
table publishes under a type that claims activity is suspicious, a row the
table withholds is not, and a row published under ``benign`` or ``unknown``
(the vocabulary's words for no claim of activity) is not. So a published row
is never served as not suspicious beside its own publication, and two rows of
one host are never told apart by having been read from different places.
"""

from __future__ import annotations

from typing import Any

from app.services.report_service import ioc_feed_rows

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
            "address": "185.99.133.7",
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

    def test_a_withheld_row_is_not_suspicious_whatever_the_network_block_says(self) -> None:
        row = _by_value(ioc_feed_rows(_report("Malware")))["198.51.100.23"]

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


class TestNoOtherFieldMoves:
    def test_the_note_still_carries_the_network_block_s_reason(self) -> None:
        network = {
            **NETWORK,
            "domains": [{**NETWORK["domains"][0], "reason": "resolved by the sample"}],
        }
        report = {**_report("Malware"), "network": network}

        row = _by_value(ioc_feed_rows(report))["c2.example.com"]

        assert row["notes"] == "resolved by the sample"
