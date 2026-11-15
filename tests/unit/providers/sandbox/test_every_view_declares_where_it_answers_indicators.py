"""Every sandbox view that answers resolved indicators declares where, by its kind.

A resolved indicator (which process did what to which, each process resolved
to the report's row) is a structured record of the detonation, not a string
a tool printed: a value an answer holds only there keeps the standing it has
where no answer holds it. The report reads that by the parts each kind
declares (``RECORD_PARTS_OF_KIND``). Every view of the sandbox source is
called here over the live report, with every argument that reaches
indicators, and every resolved indicator an answer holds must sit at a path
its kind declares, so no view can answer them where the declaration does not
reach.

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
# The facts a resolved process states (``SignatureIndicators._process``).
PROCESS_FACTS = {"id", "guest_pid", "image", "platform_lineage", "marked", "not_listed"}


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
    ]
    calls += [(sandbox_tools.ITEMS_TOOL, {"section": name}) for name in SECTION_PREFIXES]
    calls += [
        (sandbox_tools.ITEMS_TOOL, {"section": "signatures", "signature": WPM}),
        (sandbox_tools.ITEMS_TOOL, {"section": "signatures", "pid": 86}),
    ]
    return calls


def _resolved_at(value: Any, path: str = "") -> list[str]:
    """The paths of the lists holding resolved indicators in ``value`` (dotted, ``*`` a list)."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, held in value.items():
            found += _resolved_at(held, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        if any(_is_resolved(item) for item in value):
            found.append(path)
        for item in value:
            found += _resolved_at(item, f"{path}.*")
    return found


def _is_resolved(item: Any) -> bool:
    return isinstance(item, dict) and any(
        isinstance(item.get(key), dict)
        and "id" in item[key]
        and set(item[key]) <= PROCESS_FACTS | {"not_settled"}
        for key in ("process", "target")
    )


def test_every_resolved_indicator_sits_where_its_view_s_kind_declares() -> None:
    container = _Container()
    tools = {tool.name: tool for tool in sandbox_tools.sandbox_tools(container)}
    seen: set[str] = set()
    for name, args in _calls(container):
        answer = tools[name].invoke(args)
        answer = json.loads(answer) if isinstance(answer, str) else answer
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
