"""A hostile launch text is inert on every surface that names a later detonation.

Launch arguments are text an agent chose, and may come from the sample. On
every text surface (the pack line and its row head, the Markdown table cell
and code span, the analyst report, the evidence-section title, the STIX
description, the MISP comment, the ATT&CK layer metadata, the drafted YARA,
Sigma and Suricata rules, the section bundles' technique lists) the text is on
one line, holds nothing that closes a code span, opens a tag or a template,
ends a table cell, cites an entry or an item, or reorders the line, and is cut.
In a drafted rule it is also in that language's own place for text: a YARA
``//`` comment that runs to the end of its line, a Sigma description that YAML
reads back as the one string it wrote, a Suricata ``#`` comment line; each
draft still passes its own check, and its strings, selections and alert lines
are those of the same draft with no mark (T-679). On a JSON surface
(``/iocs``, ``x_malspark_observed_in``) the text is the exact text, a JSON
string (T-671 review r3 R4). Offline.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from malspark.reporting.detonation_marks import LAUNCH_TEXT_CHARS

HOSTILE = (
    "a`b|c\nd\re<script>x</script>]] {{t}} {%x%} <|im_start|> [ev_0001] d3/proc:1 "
    "‮RTL​ZW " + "Z" * 5000
)
# What none of a text surface's launch text may hold as it is.
RAW = ("`", "|", "<", ">", "{", "}", "\n", "\r", "‮", "​", "[ev_0001]", "d3/proc:1")


@pytest.fixture
def report(monkeypatch: pytest.MonkeyPatch) -> Any:
    import tests.unit.reporting.test_a_later_detonation_s_observations_reach_the_report as base

    monkeypatch.setattr(base, "ARGS", HOSTILE)
    return base._report(base._ledger())


def _pack_rows() -> list[dict[str, Any]]:
    from tests.unit.pipeline.test_a_later_detonation_is_read_by_the_platform import (
        _entered_update,
        container_with_a_pending_request,
    )

    container = container_with_a_pending_request()
    container.detonation_requests[0].arguments = HOSTILE
    return _entered_update(container, {"evidence_ledger": []})["evidence_ledger"]


def _pack_line(_report: Any) -> str:
    from malspark.pipeline.triage_pack import pack_block, pack_entries

    block = pack_block(pack_entries(_pack_rows()), 0)
    return next(line for line in block.split("\n") if "launched with" in line)


def _row_head(_report: Any) -> str:
    from malspark.pipeline.triage_pack import pack_row_heads

    return next(head for head in pack_row_heads(_pack_rows()).values() if "launched with" in head)


def _markdown_cell(report: Any) -> str:
    from malspark.reporting.renderers import MarkdownRenderer

    text = MarkdownRenderer().render(report)
    return next(
        line for line in text.split("\n") if line.startswith("|") and "launched with" in line
    )


def _analyst_report(report: Any) -> str:
    from malspark.reporting.renderers import MarkdownRenderer
    from malspark.reporting.renderers.layout import ANALYST

    text = MarkdownRenderer(layout=ANALYST).render(report)
    return next(line for line in text.split("\n") if "launched with" in line)


def _section_title(_report: Any) -> str:
    import tests.unit.reporting.test_a_later_detonation_s_observations_reach_the_report as base
    from malspark.reporting.ledger_report import build_sections

    sections = build_sections(base._ledger(), {}, "pe", "windows")
    return next(s.title for s in sections if "launched with" in (s.title or ""))


def _stix_description(report: Any) -> str:
    from malspark.reporting.builder import build_consolidated_iocs
    from malspark.reporting.renderers.stix_renderer import _with_the_detonations
    from malspark.schemas.stix_models import Indicator

    table = build_consolidated_iocs(report)
    indicator = Indicator(name="IP", pattern="[ipv4-addr:value = '198.51.100.7']")
    (marked,) = _with_the_detonations([indicator], table, report)
    return str(marked.description)


def _misp_comment(report: Any) -> str:
    from malspark.reporting.builder import build_consolidated_iocs
    from malspark.reporting.misp import build_misp_attributes

    table = build_consolidated_iocs(report)
    comments = [a["comment"] for a in build_misp_attributes(report, table, owner="u")]
    return next(c for c in comments if "launched with" in c)


def _layer_value(report: Any) -> str:
    from malspark.reporting.navigator_layer import build_layer

    layer = build_layer(report.model_dump(mode="json"))
    values = [
        f"launched with {m['value'].split('launched with ', 1)[1]}"
        for t in layer["techniques"]
        for m in t["metadata"]
        if m["name"] == "observed in"
    ]
    return values[0]


def _rules(launch: str = HOSTILE) -> dict[str, Any]:
    import tests.unit.reporting.test_a_rule_on_a_later_detonation_s_value_says_so as rules
    from malspark.reporting.detection_signatures import build_detection_rules

    drafted: dict[str, Any] = {}
    for rule in build_detection_rules(rules._report(later=bool(launch), launch=launch)):
        drafted.setdefault(rule.kind, rule)
        if "launched with" in rule.body:
            drafted[rule.kind] = rule
    return drafted


def _yara_comment(_report: Any) -> str:
    body = _rules()["yara"].body
    return next(line for line in body.split("\n") if "launched with" in line)


def _sigma_description(_report: Any) -> str:
    import yaml

    return str(yaml.safe_load(_rules()["sigma"].body)["description"])


def _suricata_comment(_report: Any) -> str:
    body = _rules()["suricata"].body
    return next(line for line in body.split("\n") if "launched with" in line)


def _bundle_line(section: str, listed: str) -> Callable[[Any], str]:
    def _line(report: Any) -> str:
        from malspark.reporting.evidence_bundles import bundle_for

        return next(t for t in bundle_for(section, report)["facts"][listed] if "launched with" in t)

    return _line


TEXT_SURFACES: dict[str, Callable[[Any], str]] = {
    "pack line": _pack_line,
    "row head": _row_head,
    "Markdown cell": _markdown_cell,
    "analyst report": _analyst_report,
    "evidence-section title": _section_title,
    "STIX description": _stix_description,
    "MISP comment": _misp_comment,
    "ATT&CK layer metadata": _layer_value,
    "YARA comment": _yara_comment,
    "Sigma description": _sigma_description,
    "Suricata comment": _suricata_comment,
    "executive-summary bundle techniques": _bundle_line("executive_summary", "top_ttps"),
    "mitigations bundle techniques": _bundle_line("mitigations", "ttps"),
}


def _launch(text: str) -> str:
    """The launch text a surface wrote: the code span after ``launched with``."""
    after = text.split("launched with ", 1)[1]
    fence = len(after) - len(after.lstrip("`"))
    assert fence >= 1, text[:200]
    body = after[fence:]
    return body[: body.index("`" * fence)].strip()


@pytest.mark.parametrize("surface", list(TEXT_SURFACES))
def test_a_text_surface_writes_the_launch_text_inert(surface: str, report: Any) -> None:
    text = TEXT_SURFACES[surface](report)
    assert "\n" not in text and "\r" not in text
    launch = _launch(text)
    for raw in RAW:
        assert raw not in launch, (surface, raw)
    assert len(launch) <= LAUNCH_TEXT_CHARS
    assert launch.endswith("…")


def test_the_iocs_feed_and_the_stix_property_keep_the_exact_text(report: Any) -> None:
    from app.services.report_service import ioc_feed_rows
    from malspark.reporting.builder import build_consolidated_iocs
    from malspark.reporting.renderers.stix_renderer import _with_the_detonations
    from malspark.schemas.stix_models import Indicator

    rows = [r for r in ioc_feed_rows(report.model_dump(mode="json")) if r.get("observed_in")]
    marks = rows[0]["observed_in"]
    assert marks[-1] == {"detonation": "d2", "launched_with": HOSTILE}
    assert json.loads(json.dumps(marks)) == marks
    table = build_consolidated_iocs(report)
    indicator = Indicator(name="IP", pattern="[ipv4-addr:value = '198.51.100.7']")
    (marked,) = _with_the_detonations([indicator], table, report)
    assert marked.x_malspark_observed_in == [{"detonation": "d2", "launched_with": HOSTILE}]


@pytest.mark.parametrize("kind", ["yara", "sigma", "suricata"])
def test_a_rule_holds_the_launch_text_in_its_own_place_for_text(kind: str) -> None:
    import yaml

    from malspark.reporting import detection_signatures as drafts

    marked, plain = _rules()[kind], _rules("")[kind]
    if kind != "yara" or drafts._YARA_AVAILABLE:
        assert marked.compile_error is None, marked.compile_error
    if kind == "yara":
        # Everything after ``//`` on its line is comment, and the code before it
        # is the code the draft with no mark has.
        line = next(line for line in marked.body.split("\n") if "launched with" in line)
        assert line.index("  // ") < line.index("launched with")
        assert [x.split("  // ", 1)[0] for x in marked.body.split("\n")] == [
            x.split("  // ", 1)[0] for x in plain.body.split("\n")
        ]
    elif kind == "sigma":
        doc, bare = yaml.safe_load(marked.body), yaml.safe_load(plain.body)
        assert "launched with" in doc.pop("description")
        bare.pop("description")
        assert doc == bare
    else:
        lines = [x for x in marked.body.split("\n") if "launched with" in x]
        assert lines and all(x.startswith("# ") for x in lines)
        assert [x for x in marked.body.split("\n") if not x.startswith("#")] == [
            x for x in plain.body.split("\n") if not x.startswith("#")
        ]
