"""The same report renders to the same STIX bundle, byte for byte.

Every indicator, malware object, relationship, process, note, observed-data and
report of the export, and the bundle itself, had a random id, and every
``created``, ``modified`` and ``valid_from`` was the time of the render. A
consumer importing a re-rendered report held each object twice, which is why a
stored bundle was never rendered again. Each id is now derived from what
identifies the object (the sample's SHA-256, the kind, the pattern, a
relationship's ends) in one namespace, and every time is the time the report
was built.

Each id is the report's: the report's identity (the sample's SHA-256 and the
time it was built) is in every key, so another run of the same sample yields
other objects and no id is ever published with two ``created`` values. The
sample's own malware object is keyed on the report alone, not on the name the
run gave it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.models import (
    DynamicBehavior,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    ProcessNode,
)
from malspark.reporting.renderers.stix_renderer import PRODUCER_IDENTITY_ID, ExtendedSTIXRenderer
from malspark.reporting.run_diff import _stix_object_key
from malspark.schemas.stix_models import STIX_ID_NAMESPACE, Bundle, Indicator, Malware

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"
BUILT = datetime(2026, 5, 16, 8, 30, tzinfo=UTC)
REPORT = (SHA256, "2026-05-16T08:30:00+00:00")
C2 = "82.157.13.47"


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
    report.generated_at = BUILT
    report.executive_summary = "A loader."
    report.network = NetworkIOCs(
        ips=[NetworkIP(address=C2, source="sandbox", is_suspicious=True, sample_process_tree=True)]
    )
    report.dynamic = DynamicBehavior(
        process_tree=[
            ProcessNode(
                pid=100,
                name="sample.exe",
                command_line="sample.exe /run",
                children=[ProcessNode(pid=101, name="cmd.exe", command_line="cmd /c x")],
            )
        ]
    )
    return report


def _judge() -> Bundle:
    return Bundle(
        objects=[
            Malware(id="malware--1", name="loader sample", is_family=False),
            Indicator(
                id="indicator--1",
                name="C2",
                pattern=f"[ipv4-addr:value = '{C2}']",
                indicator_types=["malicious-activity"],
            ),
        ]
    )


def _derived(kind: str, *identifying: str) -> str:
    """The recipe, restated: the UUIDv5 of the joined values, in the UUIDv4 form."""
    name = "|".join((kind, *identifying))
    derived = uuid.uuid5(STIX_ID_NAMESPACE, name)
    return f"{kind}--{uuid.UUID(bytes=derived.bytes, version=4)}"


def test_the_namespace_is_the_platform_s_own() -> None:
    assert STIX_ID_NAMESPACE == uuid.UUID("f074057c-56c7-502a-8d42-4a328cc70644")
    assert uuid.uuid5(uuid.NAMESPACE_URL, "malspark:stix") == STIX_ID_NAMESPACE


def test_two_renders_are_byte_identical_and_key_the_same_objects() -> None:
    report = _report()
    first = ExtendedSTIXRenderer().render(report, _judge()).model_dump_json()
    second = ExtendedSTIXRenderer().render(report, _judge()).model_dump_json()

    assert first == second
    objects = Bundle.model_validate_json(first).model_dump(mode="json")["objects"]
    keys = [_stix_object_key(o) for o in objects]
    assert keys == [
        _stix_object_key(o)
        for o in Bundle.model_validate_json(second).model_dump(mode="json")["objects"]
    ]


def test_each_id_is_derived_from_what_identifies_the_object() -> None:
    bundle = ExtendedSTIXRenderer().render(_report(), _judge()).model_dump(mode="json")
    by_type: dict[str, list[dict]] = {}
    for obj in bundle["objects"]:
        by_type.setdefault(obj["type"], []).append(obj)

    assert bundle["id"] == _derived("bundle", *REPORT)
    (malware,) = by_type["malware"]
    assert malware["id"] == _derived("malware", *REPORT)
    (c2,) = [o for o in by_type["indicator"] if C2 in o["pattern"]]
    assert c2 == {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _derived("indicator", *REPORT, f"[ipv4-addr:value = '{C2}']"),
        "created": "2026-05-16T08:30:00Z",
        "modified": "2026-05-16T08:30:00Z",
        "created_by_ref": PRODUCER_IDENTITY_ID,
        "object_marking_refs": ["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"],
        "name": f"IP {C2}",
        "description": "Published because: the sandbox recorded it.",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[ipv4-addr:value = '{C2}']",
        "pattern_type": "stix",
        "valid_from": "2026-05-16T08:30:00Z",
    }
    indicates = [
        o
        for o in by_type["relationship"]
        if o["relationship_type"] == "indicates" and o["source_ref"] == c2["id"]
    ]
    assert [o["id"] for o in indicates] == [
        _derived("relationship", *REPORT, "indicates", c2["id"], malware["id"])
    ]
    (report_object,) = by_type["report"]
    assert report_object["id"] == _derived("report", *REPORT)
    (observed,) = by_type["observed-data"]
    assert observed["id"] == _derived("observed-data", *REPORT)
    assert {o["id"] for o in by_type["process"]} <= set(observed["object_refs"])


def test_every_time_is_the_time_the_report_was_built() -> None:
    bundle = ExtendedSTIXRenderer().render(_report(), _judge()).model_dump(mode="json")

    stamps = {
        (o["type"], name, o[name])
        for o in bundle["objects"]
        for name in ("created", "modified")
        # The TLP marking keeps the time its standard definition states.
        if name in o and o["type"] != "marking-definition"
    }
    assert {stamp for _type, _name, stamp in stamps} == {"2026-05-16T08:30:00Z"}
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 2
    assert {o["valid_from"] for o in indicators} == {"2026-05-16T08:30:00Z"}


def test_the_judge_s_labels_name_the_ids_the_export_publishes_under() -> None:
    from malspark.reporting.renderers.stix_renderer import relabelled

    renderer = ExtendedSTIXRenderer()
    bundle = renderer.render(_report(), _judge()).model_dump(mode="json")
    (malware,) = [o for o in bundle["objects"] if o["type"] == "malware"]

    labels = {
        "the sample": "malware--1",
        "the address": "indicator--1",
        "shared": ["malware--1", "indicator--1"],
    }

    # The judge's address indicator is folded into the one the export mints
    # for the same value, so the export does not carry it: its id stays.
    assert relabelled(labels, renderer.renamed) == {
        "the sample": malware["id"],
        "the address": "indicator--1",
        "shared": [malware["id"], "indicator--1"],
    }
    assert malware["id"] == _derived("malware", *REPORT)


def _ids(bundle: dict) -> dict[str, list[str]]:
    by_type: dict[str, list[str]] = {}
    for obj in bundle["objects"]:
        by_type.setdefault(obj["type"], []).append(obj["id"])
    return by_type


def test_the_sample_s_malware_object_keeps_its_id_whatever_the_run_names_it() -> None:
    judge = _judge()
    renamed = Bundle(
        objects=[
            Malware(id="malware--1", name="renamed family", is_family=True),
            *judge.objects[1:],
        ]
    )

    first = ExtendedSTIXRenderer().render(_report(), judge).model_dump(mode="json")
    second = ExtendedSTIXRenderer().render(_report(), renamed).model_dump(mode="json")

    assert [o["name"] for o in second["objects"] if o["type"] == "malware"] == ["renamed family"]
    assert (
        _ids(first)["malware"]
        == _ids(second)["malware"]
        == ["malware--80e6e3f8-f7e4-4b0f-bcd0-dda8910191c6"]
    )
    assert _ids(first)["malware"] == [_derived("malware", *REPORT)]
    assert first["id"] == second["id"]


def test_another_run_of_the_sample_is_other_objects() -> None:
    later = _report()
    later.generated_at = datetime(2026, 5, 17, 9, 0, tzinfo=UTC)

    first = ExtendedSTIXRenderer().render(_report(), _judge()).model_dump(mode="json")
    second = ExtendedSTIXRenderer().render(later, _judge()).model_dump(mode="json")

    assert first["id"] != second["id"]
    kept = {
        kind: sorted(set(ids) & set(_ids(second).get(kind, [])))
        for kind, ids in _ids(first).items()
    }
    # Only what is not one report's keeps its id: the producer's identity, the
    # TLP marking the standard fixes and the files the standard derives ids for.
    assert {kind: ids for kind, ids in kept.items() if ids} == {
        "file": [
            "file--89cf33b0-d6ed-55ab-ad48-857fa71e17f5",
            "file--92f3be57-c516-591d-98b0-b5e7c5424cb3",
        ],
        "identity": [PRODUCER_IDENTITY_ID],
        "marking-definition": ["marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"],
    }
