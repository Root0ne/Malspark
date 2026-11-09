"""A Sigma draft selects only on whole values a log records, or says why there is none.

Two stored runs drafted Sigma rules that could match nothing. One selected on a
sandbox signature's description cut at 80 characters ("…the Active Setu…",
"…to run on boot…"): a cut value matches no log. The next ones held the
descriptions whole, and still matched nothing: a signature's name or
description is the sandbox's reading of what it saw, not a field of any process
or registry event. A selection is now built only from the registry keys and
images a sandbox watched or the run publishes, each whole; the signatures move
to the rule's description; and with no such value left there is no Sigma draft,
and the report and the bundle say why.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    RegistryMod,
    SampleIdentity,
    SandboxSignature,
)
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.utils.marked_cut import CUT_MARK

# A sandbox's signatures as a stored run carries them: the most severe first,
# two of them longer than the 80 characters a selection value was once cut at
# (102 and 95 characters).
LONG_SIGNATURES = [
    ("Detect example Loader variant 2", "Detect example Loader variant 2", 10),
    ("Family: Example loader", "Example is a loader written in C++.", 10),
    (
        "Boot or Logon Autostart Execution: Active Setup",
        "Adversaries may achieve persistence by adding a Registry key to the Active Setup of "
        "the local machine.",
        8,
    ),
    ("Unsigned PE", "Checks for missing Authenticode signature.", 3),
    (
        "Uses Task Scheduler COM API",
        "The Task Scheduler COM API can be used to schedule applications to run on boot or at "
        "set times.",
        0,
    ),
]
# The three a later run's sandbox recorded.
SHORT_SIGNATURES = LONG_SIGNATURES[:2] + LONG_SIGNATURES[3:4]
# A key the sandbox watched, longer than 80 characters.
WATCHED_KEY = (
    "Software\\ExampleVendor\\ExampleProduct\\Components\\{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}"
    "\\StubPath"
)


def _report(
    signatures: list[tuple[str, str, int]],
    keys: list[str] | None = None,
    verdict: str = "Malware",
) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64)),
        verdict=verdict,
        malware_category="loader",
        dynamic=DynamicBehavior(
            sandbox_signatures=[
                SandboxSignature(name=name, description=text, severity=severity)
                for name, text, severity in signatures
            ],
            registry_mods=[
                RegistryMod(hive="HKLM", key=key, value_name="x", operation="create")
                for key in keys or []
            ],
        ),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return MalwareReportBuilder.attach_detection_signatures(report)


def _sigma(report: MalwareReport) -> Any:
    return next((r for r in report.detection_signatures if r.kind == "sigma"), None)


def _values(node: Any) -> list[str]:
    if isinstance(node, dict):
        return [v for key, item in node.items() if key != "condition" for v in _values(item)]
    if isinstance(node, list):
        return [v for item in node for v in _values(item)]
    return [str(node)]


class TestASelection:
    def test_names_no_signature(self) -> None:
        rule = _sigma(_report(LONG_SIGNATURES, keys=[WATCHED_KEY]))

        assert rule is not None
        detection = yaml.safe_load(rule.body)["detection"]
        assert set(detection) == {"selection_registry", "condition"}
        assert not any(text in _values(detection) for _, text, _ in LONG_SIGNATURES)

    def test_no_detection_value_carries_a_cut_mark(self) -> None:
        rule = _sigma(_report(LONG_SIGNATURES, keys=[WATCHED_KEY]))

        values = _values(yaml.safe_load(rule.body)["detection"])
        assert values == ["\\" + WATCHED_KEY]
        assert not any(CUT_MARK in value for value in values)

    def test_the_signatures_are_named_whole_in_the_description(self) -> None:
        rule = _sigma(_report(LONG_SIGNATURES, keys=[WATCHED_KEY]))

        description = yaml.safe_load(rule.body)["description"]
        assert CUT_MARK not in description
        for _, text, _ in LONG_SIGNATURES:
            assert text in description

    def test_a_draft_with_no_signature_keeps_its_description(self) -> None:
        rule = _sigma(_report([], keys=[WATCHED_KEY]))

        assert yaml.safe_load(rule.body)["description"] == "Auto-generated for sha256 dddddddddddd"

    def test_a_built_draft_leaves_nothing_unsaid(self) -> None:
        assert _report(LONG_SIGNATURES, keys=[WATCHED_KEY]).drafts_not_built == []


class TestNoValueALogRecords:
    @pytest.mark.parametrize(
        ("signatures", "count"),
        [(LONG_SIGNATURES, "the 5 signatures"), (SHORT_SIGNATURES, "the 3 signatures")],
    )
    def test_makes_no_sigma_draft_and_says_why(
        self, signatures: list[tuple[str, str, int]], count: str
    ) -> None:
        report = _report(signatures)

        assert _sigma(report) is None
        (item,) = report.drafts_not_built
        assert item.kind == "sigma"
        assert "no registry key or image path" in item.why
        assert f"{count} the sandbox recorded are its reading of what it saw" in item.why

    def test_one_signature_is_said_in_the_singular(self) -> None:
        (item,) = _report(LONG_SIGNATURES[3:4]).drafts_not_built

        assert "the signature the sandbox recorded is its reading" in item.why

    def test_no_signature_says_only_what_is_missing(self) -> None:
        (item,) = _report([]).drafts_not_built

        assert item.why == (
            "no registry key or image path that this run publishes or a sandbox watched is "
            "left to select on"
        )

    @pytest.mark.parametrize("layout", [BUNDLE, ANALYST])
    def test_the_report_says_why(self, layout: Any) -> None:
        text = MarkdownRenderer(layout=layout).render(_report(SHORT_SIGNATURES))

        assert "No Sigma draft: no registry key or image path" in text
        assert "selection_sandbox" not in text

    def test_a_benign_verdict_says_why_on_its_own(self) -> None:
        assert _report(SHORT_SIGNATURES, verdict="Benign").drafts_not_built == []

    def test_the_record_dumps_as_before_when_empty(self) -> None:
        report = _report([], keys=[WATCHED_KEY])

        assert "drafts_not_built" not in report.model_dump()
