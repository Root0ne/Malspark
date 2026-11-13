"""A hostile launch text is inert on every surface that names a later detonation.

Launch arguments are text an agent chose, and may come from the sample. On
every text surface (the pack line and its row head, the Markdown table cell
and code span, the analyst report, the evidence-section title, the STIX
description, the MISP comment, the ATT&CK layer metadata) the text is on one
line, holds nothing that closes a code span, opens a tag or a template, ends a
table cell, cites an entry or an item, or reorders the line, and is cut. On a
JSON surface (``/iocs``, ``x_malspark_observed_in``) the text is the exact text,
a JSON string (T-671 review r3 R4). Offline.
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


TEXT_SURFACES: dict[str, Callable[[Any], str]] = {
    "pack line": _pack_line,
    "row head": _row_head,
    "Markdown cell": _markdown_cell,
    "analyst report": _analyst_report,
    "evidence-section title": _section_title,
    "STIX description": _stix_description,
    "MISP comment": _misp_comment,
    "ATT&CK layer metadata": _layer_value,
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
