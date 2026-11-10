"""Every export carries the report's TLP level, the one its cover prints.

The level was computed once (``ReportBuilder._build_front_matter``) and printed
on the cover only: the STIX bundle, ``/iocs`` and the MISP attributes left
without it, so a receiver could not tell how the report may be shared. The
STIX export now names the level's TLP 2.0 marking definition, by the id the
STIX extension fixes, on every domain object and relationship, and carries
that definition; the MISP attributes carry the ``tlp:`` tag.
"""

from __future__ import annotations

from stix2validator import ValidationOptions, validate_instance

from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import MalwareReport, NetworkIOCs, NetworkIP
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from malspark.schemas.stix_models import tlp_name

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"
C2 = "82.157.13.47"

AMBER = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "created": "2022-10-01T00:00:00Z",
    "name": "TLP:AMBER",
    "extensions": {
        "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
            "extension_type": "property-extension",
            "tlp_2_0": "amber",
        }
    },
}
# The objects STIX 2.1 calls domain objects and relationships; the
# cyber-observables (``file``, ``process``) and the marking itself are not marked.
_UNMARKED = {"file", "process", "marking-definition"}


def _report() -> MalwareReport:
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
        evidence_ledger=[],
    ).build_deterministic()
    report.executive_summary = "A loader."
    return report


def test_the_names_are_the_tlp_2_0_names() -> None:
    assert [tlp_name(level) for level in ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")] == [
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ]
    assert tlp_name("") is None


def test_the_stix_export_marks_every_object_with_the_report_s_level() -> None:
    report = _report()
    report.tlp = "AMBER"

    bundle = ExtendedSTIXRenderer().render(report).model_dump(mode="json")

    markings = [o for o in bundle["objects"] if o["type"] == "marking-definition"]
    assert markings == [AMBER]
    for obj in bundle["objects"]:
        if obj["type"] in _UNMARKED:
            assert "object_marking_refs" not in obj, obj["id"]
        else:
            assert obj["object_marking_refs"] == [AMBER["id"]], obj["id"]
    result = validate_instance(bundle, ValidationOptions(version="2.1"))
    assert result.is_valid, [str(error) for error in result.errors]


def test_a_report_with_a_network_value_is_amber_as_its_cover_says() -> None:
    builder = MalwareReportBuilder(
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
        evidence_ledger=[],
    )
    report = builder.build_deterministic()
    report.network = NetworkIOCs(ips=[NetworkIP(address=C2, source="sandbox")])
    report.front_matter = builder._build_front_matter(report)
    report.tlp = report.front_matter.tlp

    bundle = ExtendedSTIXRenderer().render(report).model_dump(mode="json")

    assert report.front_matter.tlp == "AMBER"
    assert [o["name"] for o in bundle["objects"] if o["type"] == "marking-definition"] == [
        "TLP:AMBER"
    ]


def test_each_misp_attribute_carries_the_tlp_tag() -> None:
    report = _report()
    report.tlp = "GREEN"

    attributes = build_misp_attributes(report, owner="report-1")

    sample = next(a for a in attributes if a["type"] == "sha256")
    assert sample == {
        "uuid": "af2fbbf4-7d76-55af-86f2-131866289b5f",
        "type": "sha256",
        "category": "Payload delivery",
        "value": SHA256,
        "to_ids": True,
        "comment": "the sample; published because the sample's own digest",
        "Tag": [{"name": "tlp:green"}],
    }
    assert all({"name": "tlp:green"} in a["Tag"] for a in attributes)
