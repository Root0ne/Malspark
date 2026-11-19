"""The HTML header card says who named the family where the report head says it.

The card reads the attribution's fields as the report head does
(``_family_words``) and adds the head's own qualifier: a family the sandbox's
own classification named, with the judge naming none, and a judge family with
no evidence cited. A judge family with cited evidence and no family print as
the card always printed them.
"""

from __future__ import annotations

import pytest

from malspark.reporting.models import (
    FamilyAttribution,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.markdown import MarkdownRenderer


def _report(attribution: FamilyAttribution) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.exe"),
        verdict="Malware",
        overall_confidence=0.8,
        attribution=attribution,
    )


def _family_fact(report: MalwareReport) -> str:
    out = HtmlRenderer(layout="analyst").render(report, embed_figures=False)
    cover = out[out.index('<header class="cover"') : out.index("</header>")]
    start = cover.index('<span class="cover-fact">Family')
    return cover[start : cover.index("</span>", start) + len("</span>")]


@pytest.mark.parametrize(
    ("attribution", "fact"),
    [
        (
            FamilyAttribution(
                family="latrodectus",
                family_source="sandbox",
                family_grounded=False,
            ),
            '<span class="cover-fact">Family <b>latrodectus</b> (named by the sandbox&#x27;s '
            "own classification; the judge named none)</span>",
        ),
        (
            FamilyAttribution(
                family="latrodectus",
                family_source="sandbox",
                family_note="the signature's own family name",
            ),
            '<span class="cover-fact">Family <b>latrodectus</b> (named by the sandbox&#x27;s '
            "own classification; the judge named none; the signature&#x27;s own family "
            "name)</span>",
        ),
        (
            FamilyAttribution(family="Loader", family_source="judge", family_grounded=False),
            '<span class="cover-fact">Family <b>Loader</b> (no evidence cited)</span>',
        ),
        (
            FamilyAttribution(
                family="Loader",
                family_source="judge",
                family_confidence=0.7,
                family_evidence_ids=["ev_0001"],
            ),
            '<span class="cover-fact">Family <b>Loader</b></span>',
        ),
        (
            FamilyAttribution(family="unknown"),
            '<span class="cover-fact">Family <b>not identified</b></span>',
        ),
    ],
    ids=["sandbox", "sandbox-with-note", "judge-no-evidence", "judge-cited", "none"],
)
def test_the_card_names_the_family_with_the_head_s_qualifier(
    attribution: FamilyAttribution, fact: str
) -> None:
    assert _family_fact(_report(attribution)) == fact


@pytest.mark.parametrize(
    "attribution",
    [
        FamilyAttribution(family="latrodectus", family_source="sandbox"),
        FamilyAttribution(family="Loader", family_source="judge", family_grounded=False),
    ],
)
def test_the_card_and_the_head_say_the_same_qualifier(attribution: FamilyAttribution) -> None:
    report = _report(attribution)
    head = next(
        line for line in MarkdownRenderer().render(report).splitlines() if "**Family:**" in line
    )
    family = head.split("**Family:**", 1)[1]
    qualifier = family.split("(", 1)[1].rsplit(")", 1)[0]
    if attribution.family_source == "judge":
        qualifier = "no evidence cited"
    assert f"({qualifier.replace(chr(39), '&#x27;')})" in _family_fact(report)
