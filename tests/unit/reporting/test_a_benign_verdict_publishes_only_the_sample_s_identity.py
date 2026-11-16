"""A Benign verdict publishes the sample's identity and withholds every other value.

What each verdict publishes is one declared table
(``schemas.judgement.PUBLICATION_BY_VERDICT``), read by the one publish rule
and by nothing else. Under Benign the sample's own digests are published as
its identity, typed ``benign``; its similarity digests, which also match other
files, are withheld; and every other value is withheld whoever recorded it,
with the verdict's reason first and what the evidence said of it after. A
withheld row stays listed. The IOC table, ``/iocs``, MISP and the STIX export
read the one row, so they say the same; no surface marks a ``benign`` identity
for detection.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.report_service import ioc_feed_rows
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.renderers.stix_renderer import (
    UNPUBLISHED_VALUE_CODE,
    ExtendedSTIXRenderer,
    exported_indicator_values,
    publishes,
)
from malspark.schemas.judgement import BENIGN_WITHHOLDS, BENIGN_WITHHOLDS_SIMILARITY
from malspark.schemas.stix_models import Bundle

SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32
IMPHASH = "d" * 32
OBSERVED = "gate9.example.org"
WRITTEN = "C:\\ProgramData\\relay.dat"
IDENTITY = {SHA256, SHA1, MD5}


def _judge() -> dict[str, Any]:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332211",
                "name": "judge indicator",
                "pattern": f"[domain-name:value = '{OBSERVED}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": "2026-01-01T00:00:00Z",
            }
        ],
    }


def _report(verdict: str, confidence: float | None = 0.9) -> MalwareReport:
    """A report holding a value of every source: identity, similarity, network, strings, judge."""
    judge = _judge()
    return MalwareReport(
        identity=SampleIdentity(
            hashes=FileHashes(sha256=SHA256, sha1=SHA1, md5=MD5, imphash=IMPHASH)
        ),
        verdict=verdict,  # type: ignore[arg-type]
        overall_confidence=confidence,
        malware_category="loader",
        network=NetworkIOCs(domains=[NetworkDomain(fqdn=OBSERVED, source="sandbox")]),
        # A path the string sweep read that the sample's own process line names
        # whole: a second source in this run records it.
        static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=WRITTEN)]),
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "sample.exe", "command_line": WRITTEN}]
        ),
        judge_indicators=[
            JudgeIndicator(kind=v.kind, value=v.value, algorithm=v.algorithm)
            for v in exported_indicator_values(judge)
        ],
    )


def _rows(report: MalwareReport) -> dict[str, Any]:
    return {row.value: row for row in build_consolidated_iocs(report)}


def _export(report: MalwareReport) -> tuple[dict[str, Any], ExtendedSTIXRenderer]:
    renderer = ExtendedSTIXRenderer()
    bundle = renderer.render(report, Bundle.model_validate(_judge()))
    return bundle.model_dump(mode="json"), renderer


def _indicators(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return [obj for obj in bundle["objects"] if obj.get("type") == "indicator"]


def _feed(report: MalwareReport) -> list[dict[str, Any]]:
    return ioc_feed_rows(report.model_dump(mode="json"))


def _value(row: dict[str, Any]) -> str:
    """A feed row's value as the table holds it: a digest without its algorithm."""
    return str(row["value"]).split(":", 1)[-1] if row["kind"] == "hash" else str(row["value"])


class TestUnderBenign:
    def test_the_sample_s_own_digests_are_published_as_its_identity(self) -> None:
        rows = _rows(_report("Benign"))

        for value in IDENTITY:
            assert rows[value].published == "yes: the sample's own digest"
            assert (rows[value].role, rows[value].indicator_type) == ("sample_identity", "benign")

    def test_a_similarity_digest_is_withheld_with_the_verdict_first(self) -> None:
        row = _rows(_report("Benign"))[IMPHASH]

        assert row.published == f"no: {BENIGN_WITHHOLDS_SIMILARITY}; the sample's own digest"
        assert (row.role, row.indicator_type) == ("similarity", None)

    @pytest.mark.parametrize("value", [OBSERVED, WRITTEN])
    def test_every_other_value_is_withheld_whoever_recorded_it(self, value: str) -> None:
        malware = _rows(_report("Malware"))[value]
        benign = _rows(_report("Benign"))[value]

        # The evidence publishes it; the verdict withholds it, and says so first,
        # with what the evidence said kept after it.
        assert publishes(malware.published)
        assert benign.published == f"no: {BENIGN_WITHHOLDS}; {malware.published[len('yes: ') :]}"
        assert (benign.role, benign.indicator_type) == ("listed", None)

    def test_the_feed_publishes_the_identity_alone_and_lists_the_rest(self) -> None:
        feed = _feed(_report("Benign"))

        published = {_value(row) for row in feed if row["published"]}
        assert published == IDENTITY
        assert {row["indicator_type"] for row in feed if row["published"]} == {"benign"}
        # A withheld row stays in ``include=all`` with its reason.
        listed = {row["value"]: row for row in feed if not row["published"]}
        assert listed[OBSERVED]["publish_answer"].startswith(f"no: {BENIGN_WITHHOLDS}")

    def test_the_export_carries_one_benign_identity_indicator_and_nothing_else(self) -> None:
        bundle, renderer = _export(_report("Benign"))

        (indicator,) = _indicators(bundle)
        assert indicator["indicator_types"] == ["benign"]
        for value in IDENTITY:
            assert value in indicator["pattern"]
        assert IMPHASH not in str(bundle)
        assert "Files like the sample" not in str(bundle)
        assert OBSERVED not in str(_indicators(bundle))
        # The judge's indicator names a value no row publishes: declined, recorded.
        assert UNPUBLISHED_VALUE_CODE in [code for code, _why in renderer.declined]

    def test_misp_marks_no_benign_identity_for_detection(self) -> None:
        report = _report("Benign")

        attributes = build_misp_attributes(report, build_consolidated_iocs(report), owner="r")

        assert {a["value"] for a in attributes} == IDENTITY
        assert not any(a["to_ids"] for a in attributes)


class TestEveryOtherVerdictPublishesAsBefore:
    """The regression guard: the verdict's table changes nothing but Benign's row."""

    @pytest.mark.parametrize(
        ("verdict", "confidence", "own_type"),
        [
            ("Malware", 0.9, "malicious-activity"),
            ("Suspicious", 0.9, "anomalous-activity"),
            # Stated with no confidence: the table's "not stated" row.
            ("Malware", None, "unknown"),
        ],
    )
    def test_every_value_is_published_and_typed_by_the_table(
        self, verdict: str, confidence: float | None, own_type: str
    ) -> None:
        report = _report(verdict, confidence)
        rows = _rows(report)
        bundle, _renderer = _export(report)
        feed = _feed(report)

        published = {_value(row) for row in feed if row["published"]}
        assert published == {*IDENTITY, IMPHASH, OBSERVED, WRITTEN}
        assert {rows[v].indicator_type for v in IDENTITY} == {own_type}
        assert rows[IMPHASH].indicator_type == "anomalous-activity"
        by_name = {obj["name"]: obj for obj in _indicators(bundle)}
        (own,) = [obj for name, obj in by_name.items() if name.startswith("Sample hash")]
        (similar,) = [obj for name, obj in by_name.items() if name.startswith("Files like")]
        assert own["indicator_types"] == [own_type]
        assert similar["indicator_types"] == ["anomalous-activity"]
        assert IMPHASH in similar["pattern"] and IMPHASH not in own["pattern"]
        assert OBSERVED in str(_indicators(bundle))

    def test_misp_marks_the_identity_for_detection_under_malware(self) -> None:
        report = _report("Malware")

        attributes = build_misp_attributes(report, build_consolidated_iocs(report), owner="r")

        flagged = {a["value"]: a["to_ids"] for a in attributes}
        assert all(flagged[value] for value in IDENTITY)
        assert flagged[IMPHASH] is False


class TestEveryRowStatesWhatEveryExportCarries:
    @pytest.mark.parametrize("verdict", ["Malware", "Suspicious", "Benign"])
    def test_the_bundle_carries_each_published_row_under_its_type(self, verdict: str) -> None:
        report = _report(verdict)
        bundle, _renderer = _export(report)

        exported: dict[str, list[str]] = {}
        for obj in _indicators(bundle):
            for value in exported_indicator_values({"objects": [obj]}) or []:
                exported[value.value.lower()] = obj["indicator_types"]
            if obj["name"].startswith(("Sample hash", "Files like")):
                for digest in (SHA256, SHA1, MD5, IMPHASH):
                    if digest in obj["pattern"]:
                        exported[digest] = obj["indicator_types"]
        for row in build_consolidated_iocs(report):
            if publishes(row.published) and row.indicator_type:
                assert exported.get(row.value.lower()) == [row.indicator_type], row.value
            elif row.role == "listed":
                assert row.value.lower() not in exported, row.value


class TestTheRowRecordsWhatTheExportCarries:
    def test_the_feed_carries_each_row_s_role(self) -> None:
        roles = {_value(row): row["role"] for row in _feed(_report("Benign"))}

        assert {roles[value] for value in IDENTITY} == {"sample_identity"}
        assert roles[IMPHASH] == "similarity"
        assert roles[OBSERVED] == "listed"

    def test_a_url_is_typed_as_flagged_activity_under_malware(self) -> None:
        from malspark.reporting.models import NetworkURL

        report = _report("Malware")
        report.network = NetworkIOCs(
            urls=[NetworkURL(url="https://gate9.example.org/p", source="sandbox")]
        )

        row = _rows(report)["https://gate9.example.org/p"]

        assert (row.role, row.indicator_type) == ("indicator", "malicious-activity")

    def test_a_host_row_the_judge_names_carries_the_judge_s_type(self) -> None:
        from malspark.reporting.models import ConsolidatedIOC
        from malspark.reporting.renderers.stix_renderer import table_row_record

        report = _report("Malware")
        report.judge_indicators = [
            JudgeIndicator(kind="mutex", value="runmark", indicator_types=["compromised"])
        ]
        row = ConsolidatedIOC(
            type="Mutex", kind="mutex", value="runmark", source="sandbox", published="yes: x"
        )

        assert table_row_record(row, report) == ("indicator", "compromised")

    def test_a_value_only_the_judge_names_is_withheld_under_benign(self) -> None:
        # The judge names a file the sample's own process line holds whole: a
        # second source publishes it under Malware, and the verdict withholds it.
        path = "C:\\Tools\\kit\\loader.exe"

        def report_for(verdict: str) -> MalwareReport:
            report = _report(verdict)
            report.dynamic = DynamicBehavior(
                process_tree=[{"pid": 1, "name": "sample.exe", "command_line": path}]
            )
            report.judge_indicators = [JudgeIndicator(kind="path", value=path)]
            return report

        malware = _rows(report_for("Malware"))[path]
        benign = _rows(report_for("Benign"))[path]

        assert (malware.source, publishes(malware.published)) == ("judge", True)
        assert benign.published.startswith(f"no: {BENIGN_WITHHOLDS}")

    def test_the_export_types_an_indicator_as_its_row_does(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting import builder

        report = _report("Malware")
        table = [
            row.model_copy(update={"indicator_type": "compromised"})
            if row.value == OBSERVED
            else row
            for row in builder.build_consolidated_iocs(report)
        ]
        monkeypatch.setattr(builder, "ioc_table", lambda *_a, **_k: table)

        bundle, _renderer = _export(report)

        (domain,) = [o for o in _indicators(bundle) if OBSERVED in o["pattern"]]
        assert domain["indicator_types"] == ["compromised"]


def test_a_url_the_strings_hold_on_a_developer_host_is_withheld_whoever_vouches() -> None:
    from malspark.reporting.models import NetworkURL

    url = "https://android.googlesource.com/platform/stage.bin"
    report = _report("Malware")
    report.network = NetworkIOCs(
        urls=[NetworkURL(url=url, source="strings")],
        domains=[
            NetworkDomain(
                fqdn="android.googlesource.com",
                source="strings",
                reputation={"source": "virustotal", "malicious": 9},
            )
        ],
    )

    assert _rows(report)[url].published == "no: it is on a developer or package-registry host"
    assert url not in str(_indicators(_export(report)[0]))
