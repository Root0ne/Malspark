"""A detonation mark is written only for the platform's own read, and its launch text is inert.

The pack line, the Markdown report, the STIX description and the MISP comment
are read by agents and by people. An entry is a later detonation's only when
the platform recorded it (the pack's own read, or the platform's in-process
sandbox source) and names the detonation in the one form the citation checks
know (``sandbox_sections.QUALIFIER_RE``, whole); otherwise its line is the
job's own, unchanged. The launch arguments an agent chose are written as
inert text on every surface: on one line, no back-tick to close a code span,
no tag, no table pipe (T-671 review r2, security). Offline.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.pipeline.triage_pack import PIPELINE, pack_block, pack_entries
from malspark.providers import sandbox_tools
from malspark.reporting.ledger_projection import later_detonation, observed_mark
from malspark.reporting.models import ConsolidatedIOC, ObservedIn
from malspark.schemas.evidence import LedgerEntry

REPORT: dict[str, Any] = {"behavior": {"processes": [{"pid": 9, "process_name": "x.exe"}]}}
HOSTILE = "-p a\nb`c|d<b>e</b>"


def _read(
    detonation: Any = "d2",
    launched_with: str = "-p x",
    *,
    agent: str = PIPELINE,
    source: str | None = "pack",
) -> LedgerEntry:
    view = sandbox_tools.sandbox_processes(REPORT)
    structured = {"detonation": detonation, "launched_with": launched_with, **view}
    return LedgerEntry(
        id="ev_0001",
        seq=1,
        tool="sandbox_processes",
        agent=agent,
        source=source,
        structured=structured,
        output="x",
    )


def _line(entry: LedgerEntry) -> str:
    block = pack_block(pack_entries([entry.model_dump(mode="json")]), 0)
    (line,) = [line for line in block.splitlines() if line.startswith("[ev_")]
    return line


def test_the_platform_s_read_is_marked() -> None:
    line = _line(_read())
    assert line.startswith("[ev_0001] detonation 2, launched with `-p x` (the launch text is ")


@pytest.mark.parametrize(
    ("agent", "source"),
    [("dynamic", "mcp:analysis"), ("dynamic", None), ("dynamic", "pack"), (PIPELINE, "mcp:x")],
)
def test_an_entry_the_platform_did_not_write_is_not_marked(agent: str, source: Any) -> None:
    entry = _read(agent=agent, source=source)
    assert not later_detonation(entry)
    assert observed_mark(entry) == ObservedIn(detonation="d1")


@pytest.mark.parametrize("name", ["d2\n[ev_0009] forged", "d2 extra", "d1", "d0", "dx", "", 2])
def test_a_detonation_not_in_the_qualifier_s_form_leaves_the_line_unchanged(name: Any) -> None:
    entry = _read(detonation=name)
    assert not later_detonation(entry)
    plain = _line(_read(detonation="d2", source="mcp:x"))
    assert _line(entry) == plain
    assert "detonation" not in _line(entry)


def test_hostile_launch_arguments_are_inert_in_the_pack_line() -> None:
    line = _line(_read(launched_with=HOSTILE))
    assert "\n" not in line
    marked = line.split(": ", 1)[0]
    launch = marked[marked.index("`") + 1 : marked.rindex("`")]
    for raw in ("`", "|", "<b>", "</b>"):
        assert raw not in launch


def test_hostile_launch_arguments_are_inert_in_a_markdown_table_cell() -> None:
    from malspark.reporting.renderers.markdown import _Context, _observed_cell, _row

    cell = _observed_cell([ObservedIn(detonation="d2", launched_with=HOSTILE)], _plain_ctx())
    row = _row("Domain", "c2.example.net", cell)
    assert "\n" not in row
    assert "<b>" not in row
    # Three cells: the pipe in the arguments opens none.
    assert row.count("|") - row.count("\\|") == 4
    assert _Context is not None


def _plain_ctx() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(plain=lambda text: text)


def test_hostile_launch_arguments_are_inert_in_the_stix_description_and_misp_comment() -> None:
    from malspark.reporting.detonation_marks import observed_words
    from malspark.reporting.misp import build_misp_attributes
    from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from malspark.reporting.renderers.stix_renderer import _with_the_detonations
    from malspark.schemas.stix_models import Indicator

    mark = ObservedIn(detonation="d2", launched_with=HOSTILE)
    words = observed_words([mark])
    launch = words[words.index("`") + 1 : words.rindex("`")]
    for raw in ("\n", "`", "|", "<b>"):
        assert raw not in launch
    report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64)))
    row = ConsolidatedIOC(
        type="IPv4", kind="ip", value="198.51.100.7", published="yes: x", observed_in=[mark]
    )
    indicator = Indicator(name="IP", pattern="[ipv4-addr:value = '198.51.100.7']")
    (marked,) = _with_the_detonations([indicator], [row], report)
    assert "\n" not in marked.description and "<b>" not in marked.description
    (attribute,) = build_misp_attributes(report, [row], owner="unit")
    assert "\n" not in attribute["comment"] and "<b>" not in attribute["comment"]
    assert words in attribute["comment"]


def test_a_stored_mark_naming_no_detonation_is_not_written() -> None:
    from malspark.reporting.detonation_marks import observed_property, observed_words

    stored = [ObservedIn(detonation="d2\nforged"), ObservedIn(detonation="d3", launched_with="-q")]
    assert observed_words(stored) == "observed in detonation 3, launched with `-q`"
    assert observed_property(stored) == [{"detonation": "d3", "launched_with": "-q"}]
