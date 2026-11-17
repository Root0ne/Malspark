"""A condition of a judge's pattern lends the indicator nothing of the value it names.

What an indicator asserts is one reading (``stix_renderer.asserted_values``):
the operand of an ``=`` and each member of an ``IN``. The operand of a
``!=``, a ``NOT IN`` or a doubly negated comparison is a condition: the export
does not count it as written, lends the indicator none of its ledger ids, its
publish reason or its detonation marks, and gives none of it a row.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    ObservedIn,
    PersistenceMechanism,
    SampleIdentity,
)
from malspark.reporting.renderers.stix_renderer import (
    UNPUBLISHED_VALUE_CODE,
    ExtendedSTIXRenderer,
    exported_indicator_values,
)
from malspark.schemas.stix_models import Bundle, Indicator

RELAY = "C:\\ProgramData\\relay.dat"
OTHER = "C:\\ProgramData\\b.dat"
GATE = "gate.example-c2.net"
EXCLUDED = "other.example-c2.net"


def _escaped(value: str) -> str:
    return value.replace("\\", "\\\\")


def _judge(pattern: str) -> dict[str, Any]:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332201",
                "name": "judge 1",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": "2026-01-01T00:00:00Z",
            }
        ],
    }


def _report(judge: dict[str, Any], **over: Any) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="loader",
        judge_indicators=[
            JudgeIndicator(
                kind=v.kind,
                value=v.value,
                algorithm=v.algorithm,
                indicator_patterns=list(v.indicator_patterns),
                indicator_types=list(v.indicator_types),
            )
            for v in exported_indicator_values(judge)
        ],
        **over,
    )
    return report.model_copy(update={"consolidated_iocs": build_consolidated_iocs(report)})


def _export(report: MalwareReport, judge: dict[str, Any]) -> tuple[list[dict[str, Any]], Any]:
    renderer = ExtendedSTIXRenderer()
    bundle = renderer.render(report, Bundle.model_validate(judge)).model_dump(mode="json")
    return [o for o in bundle["objects"] if o.get("type") == "indicator"], renderer


def test_a_host_value_only_a_condition_names_is_written_as_the_platform_s() -> None:
    """The excluded key is not written by the judge's indicator, so the platform writes it."""
    named = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\relay"
    excluded = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\other"
    judge = _judge(
        f"[windows-registry-key:key = '{_escaped(named)}' "
        f"AND windows-registry-key:key != '{_escaped(excluded)}']"
    )
    report = _report(
        judge,
        persistence=[
            PersistenceMechanism(kind="registry_run", target=key, payload="relay.exe")
            for key in (named, excluded)
        ],
    )
    indicators, _renderer = _export(report, judge)

    assert [o["name"] for o in indicators if "judge" in o["name"]] == ["judge 1"]
    assert [o["pattern"] for o in indicators if "windows-registry-key" in o["pattern"]] == [
        judge["objects"][0]["pattern"],
        f"[windows-registry-key:key = '{_escaped(excluded)}']",
    ]


def test_a_condition_lends_the_indicator_no_ledger_id() -> None:
    from malspark.reporting.renderers.stix_renderer import _with_record_evidence

    indicator = Indicator(
        name="judge 1",
        pattern=f"[file:name = '{_escaped(OTHER)}' AND file:name != '{_escaped(RELAY)}']",
    )
    value_evidence = {("path", OTHER.lower()): ["ev_0002"], ("path", RELAY.lower()): ["ev_0001"]}
    (written,) = _with_record_evidence(
        [indicator],
        None,
        SimpleNamespace(ttp_mappings=[]),
        {"ev_0001": 0, "ev_0002": 1},
        value_evidence=value_evidence,
    )

    assert written.x_malspark_evidence_refs == ["ev_0002"]


def test_a_condition_lends_the_indicator_no_publish_reason() -> None:
    judge = _judge(f"[domain-name:value = '{GATE}' AND domain-name:value != '{EXCLUDED}']")
    report = _report(
        judge,
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn=GATE, source="sandbox"),
                NetworkDomain(fqdn=EXCLUDED, source="strings", reputation={"malicious": 3}),
            ]
        ),
    )
    indicators, _renderer = _export(report, judge)

    (carried,) = [o for o in indicators if o["name"] == "judge 1"]
    assert carried["description"] == "Published because: the sandbox recorded it."


def test_a_condition_lends_the_indicator_no_detonation_mark() -> None:
    from malspark.reporting.renderers.stix_renderer import _with_the_detonations

    later = ObservedIn(detonation="d2", launched_with="/s")
    rows = [SimpleNamespace(kind="path", value=RELAY, observed_in=[later])]
    indicator = Indicator(
        name="judge 1",
        pattern=f"[file:name = '{_escaped(OTHER)}' AND file:name != '{_escaped(RELAY)}']",
    )
    (written,) = _with_the_detonations([indicator], rows, SimpleNamespace(ttp_mappings=[]))

    assert not written.x_malspark_observed_in


@pytest.mark.parametrize(
    "pattern",
    [
        f"[file:name NOT IN ('{_escaped(RELAY)}', '{_escaped(OTHER)}')]",
        f"[file:name NOT != '{_escaped(RELAY)}']",
    ],
)
def test_a_negated_comparison_asserts_no_value(pattern: str) -> None:
    judge = _judge(pattern)
    report = _report(
        judge,
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": f"s.exe {RELAY} {OTHER}"}]
        ),
    )
    indicators, renderer = _export(report, judge)

    assert not report.judge_indicators
    assert not [r for r in report.consolidated_iocs if r.value in (RELAY, OTHER)]
    assert "judge 1" not in [o["name"] for o in indicators]
    assert (
        UNPUBLISHED_VALUE_CODE,
        "the judge's indicator 'judge 1' asserts no value: it names no value with = or IN. It is "
        "not in the exported bundle and is unchanged in the judge's own bundle.",
    ) in [tuple(d) for d in renderer.declined]
