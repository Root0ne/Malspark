"""Every sandbox view that answers resolved indicators declares where, by its kind.

A resolved indicator (which process did what to which, each process resolved
to the report's row) is a structured record of the detonation, not a string
a tool printed: a value an answer holds only there keeps the standing it has
where no answer holds it. The report reads that by the parts each kind
declares (``RECORD_PARTS_OF_KIND``). Every view of the sandbox source is
called here over the live report, with every argument that reaches
indicators or pages them, and every indicator an answer holds — a mapping
written with the keys the writer declares (``INDICATOR_KEYS``), its
processes resolved or not — must sit at a path its kind declares, so no view
can answer them where the declaration does not reach.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malspark.analysis.sandbox_sections import SECTION_PREFIXES
from malspark.core.builtin_declarations import RECORD_PARTS_OF_KIND
from malspark.providers import sandbox_tools
from malspark.providers.sandbox.readers import required_reader
from malspark.reporting import tool_kinds
from malspark.reporting.ledger_projection import without_record_parts
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.sandbox_document import sandbox_document

LIVE = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox" / "triage_live"
TRIAGE = ("triage", "triage", "tasks")
WPM = "Suspicious use of WriteProcessMemory"


def _json(name: str) -> Any:
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


class _Container:
    def __init__(self) -> None:
        report = required_reader("triage").read(
            _json("overview.json"),
            provider="triage",
            task_id="s1",
            task_reports={"behavioral1": _json("behavioral1.json")},
        )
        self.sandbox_report = sandbox_document(report)
        self.sandbox_normalised = TRIAGE


def _calls(container: _Container) -> list[tuple[str, dict[str, Any]]]:
    """Every view with no argument, and with each argument that reaches indicators."""
    document = container.sandbox_report
    calls: list[tuple[str, dict[str, Any]]] = [
        (name, {}) for name in sandbox_tools._VIEW_READERS if name != "sandbox_report_section"
    ]
    calls += [("sandbox_report_section", {"section": key}) for key in document]
    calls += [
        ("sandbox_signatures", {"signature": WPM}),
        ("sandbox_signatures", {"process": "86"}),
        ("sandbox_signatures", {"contains": "wrote"}),
        ("sandbox_signatures", {"offset": 1, "limit": 2}),
        ("sandbox_signatures", {"signature": WPM, "offset": 1, "limit": 1}),
        ("sandbox_signatures", {"process": "86", "offset": 1}),
        ("sandbox_signatures", {"contains": "wrote", "offset": 1, "limit": 1}),
    ]
    calls += [(sandbox_tools.ITEMS_TOOL, {"section": name}) for name in SECTION_PREFIXES]
    calls += [
        (sandbox_tools.ITEMS_TOOL, {"section": "signatures", "signature": WPM}),
        (sandbox_tools.ITEMS_TOOL, {"section": "signatures", "pid": 86}),
        (sandbox_tools.ITEMS_TOOL, {"section": "signatures", "contains": "wrote"}),
        (sandbox_tools.ITEMS_TOOL, {"section": "signatures", "ids": "sig:0 sig:1 sig:2"}),
    ]
    return calls


def _answers(container: _Container) -> list[tuple[str, dict[str, Any], Any]]:
    """Each call's answer, and the signature view's within each room an answer may have."""
    tools = {tool.name: tool for tool in sandbox_tools.sandbox_tools(container)}
    answers: list[tuple[str, dict[str, Any], Any]] = []
    for name, args in _calls(container):
        answer = tools[name].invoke(args)
        answers.append((name, args, json.loads(answer) if isinstance(answer, str) else answer))
    for room in (0, 2_000, 6_000, None):
        for args in ({}, {"signature": WPM}, {"offset": 1, "limit": 2}):
            answer = sandbox_tools.sandbox_signatures(
                container.sandbox_report, normalised_by=TRIAGE, room=room, **args
            )
            answers.append(("sandbox_signatures", {**args, "room": room}, answer))
    return answers


def _resolved_at(value: Any, path: str = "") -> list[str]:
    """The paths of the lists holding indicators in ``value`` (dotted, ``*`` a list)."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, held in value.items():
            found += _resolved_at(held, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        if any(_is_indicator(item) for item in value):
            found.append(path)
        for item in value:
            found += _resolved_at(item, f"{path}.*")
    return found


def _is_indicator(item: Any) -> bool:
    """A mapping written with the writer's keys alone, beyond the signature naming it."""
    return (
        isinstance(item, dict)
        and set(item) <= set(sandbox_tools.INDICATOR_KEYS)
        and bool(set(item) - {sandbox_tools.INDICATOR_SIGNATURE})
    )


def test_every_indicator_sits_where_its_view_s_kind_declares() -> None:
    container = _Container()
    seen: set[str] = set()
    for name, args, answer in _answers(container):
        kind = tool_kinds.kind_of(LedgerEntry(id="ev_0001", tool=name))
        declared = RECORD_PARTS_OF_KIND.get(kind, ())
        for path in _resolved_at(answer):
            seen.add(name)
            assert path in declared, (name, args, path)
        # And stripping the declared parts leaves none.
        assert not _resolved_at(without_record_parts(answer, declared)), (name, args)
    # The views known to answer them were reached, so the check read something.
    assert {"sandbox_signatures", sandbox_tools.ITEMS_TOOL} <= seen


def test_a_nested_path_strips_each_element_s_part_and_nothing_beside_it() -> None:
    answer = {
        "items": [
            {"fields": {"name": "a"}, "indicators": [{"x": 1}]},
            {"fields": {"name": "b"}},
        ],
        "indicators": "kept",
    }
    assert without_record_parts(answer, ("items.*.indicators",)) == {
        "items": [{"fields": {"name": "a"}}, {"fields": {"name": "b"}}],
        "indicators": "kept",
    }


def test_a_key_named_star_is_a_key_and_not_each_element() -> None:
    answer = {"items": {"*": {"indicators": [{"x": 1}]}}, "rows": [{"indicators": [1]}]}
    assert without_record_parts(answer, ("items.*.indicators", "rows.*.indicators")) == {
        "items": {"*": {"indicators": [{"x": 1}]}},
        "rows": [{}],
    }


def test_the_writer_writes_no_key_beyond_its_declaration() -> None:
    from malspark.schemas.signature_indicators import (
        CHARS_LEFT_OUT,
        DESCRIPTION,
        EVENT,
        PROCESS,
        TARGET,
        VALUES,
        VALUES_LEFT_OUT,
    )

    indicators = sandbox_tools.SignatureIndicators(_Container().sandbox_report, TRIAGE)
    every = {
        PROCESS: "84",
        TARGET: "86",
        EVENT: "WriteProcessMemory",
        DESCRIPTION: "wrote into another process",
        VALUES: {"domain": "relay-beta-1a2b.top"},
        VALUES_LEFT_OUT: 2,
        CHARS_LEFT_OUT: {DESCRIPTION: 9},
    }
    stated = indicators._stated("behavioral1", every, 3)

    assert set(stated) == set(sandbox_tools.INDICATOR_KEYS) - {sandbox_tools.INDICATOR_SIGNATURE}
    assert _is_indicator(stated)
    # And a values-only one is one too, wherever it stands.
    assert _resolved_at({"rows": [{VALUES: {"domain": "relay-beta-1a2b.top"}}]}) == ["rows"]
