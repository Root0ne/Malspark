"""The headline malware name is the grounded family of a non-benign run (RC-20)."""

from __future__ import annotations

import pytest

from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.models import FamilyAttribution, FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.layout import ANALYST, BUNDLE, FULL
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from malspark.schemas.stix_models import Malware


def _builder() -> MalwareReportBuilder:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="x.exe",
        sample_path=None,
        sandbox_report=None,
        reports={},
        isr_reports={},
        stix_output=None,
        run_summary=None,
        discussion_history=None,
        final_decision="Malware",
    )


def _name(
    family: str | None, category: str | None, *, verdict: str = "Malware", grounded: bool = True
) -> str | None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict=verdict,  # type: ignore[arg-type]
        malware_category=category,
        attribution=FamilyAttribution(family=family, family_grounded=grounded),
    )
    return _builder()._build_front_matter(report).malware_name


@pytest.mark.parametrize(
    ("family", "category", "verdict", "grounded", "expected"),
    [
        ("njRAT", "trojan", "Malware", True, "njRAT"),
        ("  AsyncRAT ", "trojan", "Malware", True, "AsyncRAT"),
        ("Generic", "benign", "Benign", True, "Benign"),
        ("Emotet", "trojan", "Malware", False, "Trojan"),
        ("generic", "trojan", "Malware", True, "Trojan"),
        ("Unknown", "ransomware", "Malware", True, "Ransomware"),
        ("Unknown family", "ransomware", "Malware", True, "Ransomware"),
        ("-", "ransomware", "Malware", True, "Ransomware"),
        ("Emotet", "benign", "Benign", True, "Benign"),
        (None, "ransomware", "Malware", True, "Ransomware"),
        # A category stated as none names nothing; a category that is a name is title-cased.
        (None, "none: a legitimate SSH client build; no malware behaviour", "Benign", True, None),
        (None, "none", "Benign", True, None),
        (None, "SSH tunnelling tool", "Suspicious", True, "Ssh Tunnelling Tool"),
        (None, "information stealer", "Malware", True, "Information Stealer"),
    ],
)
def test_the_headline_name(
    family: str | None, category: str, verdict: str, grounded: bool, expected: str | None
) -> None:
    assert _name(family, category, verdict=verdict, grounded=grounded) == expected


def test_a_category_stated_as_none_gives_no_subtitle() -> None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), platform="windows"),
        verdict="Benign",
        malware_category="none: a legitimate archiver",
    )
    assert _builder()._build_front_matter(report).subtitle is None
    report.malware_category = "loader"
    assert _builder()._build_front_matter(report).subtitle == "loader targeting Windows"


def test_a_multi_word_category_reads_the_same_on_every_surface() -> None:
    report = MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="x.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        judge_assessment=None,
        malware_category="information stealer",
        evidence_ledger=[],
    ).build_deterministic()
    assert report.front_matter is not None
    assert report.front_matter.malware_name == "Information Stealer"
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    assert "**Category:** information stealer" in analyst
    assert ", a information stealer," in analyst.split("## 7. Conclusion", 1)[1]
    for layout in (BUNDLE, FULL):
        rendered = MarkdownRenderer(layout=layout).render(report)
        assert "**Category:** information stealer _(a behavioural class" in rendered, layout
    bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
    (malware,) = [obj for obj in bundle.objects if isinstance(obj, Malware)]
    assert malware.name == "information stealer"
