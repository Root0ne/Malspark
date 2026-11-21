"""The coverage, isolation and run-summary sentences rest on no tool, server or model by name.

Each sentence of these parts says what the platform read and what that reading
gave, under a condition read from the record's own fields. Neither the words
nor the conditions that choose them, nor the record entries that state those
conditions, name a tool or a tool server any shipped declaration holds, a
provider or a model family; and no code of
the modules reads an entry's tool by a tool's name (T-817, T-818, T-819).
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import pytest
from tests.tool_name_reads import findings

from malspark.analysis import coverage, isolation, run_summary
from malspark.core.builtin_declarations import builtin_server_names, provider_names
from malspark.core.declared_reading import _shipped_tools_by_source

ROOT = Path(__file__).resolve().parents[3]
RECORDS = ROOT / "scripts" / "audit" / "publishing_records"
# Shipped names that are also plain words of these sentences ("the sandbox
# report", "a network of its own", "the analysis"), read there as words.
_PLAIN_WORDS = frozenset({"analysis", "network", "sandbox"})
# Model families no declaration names.
_FAMILIES = ("ollama", "llama", "deepseek", "claude", "haiku", "qwen", "openai", "anthropic")


def _names() -> list[str]:
    """Every tool and server name the shipped declarations hold, and the model families."""
    shipped = {*builtin_server_names(), *provider_names()}
    for source, tools in _shipped_tools_by_source().items():
        shipped.add(source.partition(":")[2] or source)
        shipped.update(tools)
    return sorted(shipped - _PLAIN_WORDS) + list(_FAMILIES)


def _named(text: str) -> list[str]:
    return [
        name
        for name in _names()
        if re.search(rf"(?<![a-z0-9_]){re.escape(name)}(?![a-z0-9_])", text, re.I)
    ]


def _offenders(module: object, constants: list[str], functions: list[str], record: dict) -> list:
    """Each form, condition or record condition of the part that names a shipped name."""
    found = [(name, _named(getattr(module, name))) for name in constants]
    found += [(name, _named(inspect.getsource(getattr(module, name)))) for name in functions]
    keys = {f"{getattr(module, '__name__', '')}:{name}" for name in (*constants, *functions)}
    found += [
        (key, _named(entry["condition"]))
        for entry in record["entries"]
        if (key := entry.get("function") or entry.get("constant")) in keys
    ]
    return [(where, names) for where, names in found if names]


def _record(module: object) -> dict:
    path = RECORDS / f"{getattr(module, '__name__', '')}.json"
    return dict(json.loads(path.read_text(encoding="utf-8")))


# The constants each part writes, and the functions whose conditions choose its forms.
PARTS = {
    "coverage": (coverage, ["NOTHING_MISSING"], ["coverage_lines"]),
    "isolation": (
        isolation,
        ["INTRO_SENTENCE", "INTRO_DECLARED_SENTENCE", "APART", "NOT_MEASURED_DISAGREE"],
        [
            "intro_sentence",
            "_apart",
            "_user",
            "_capabilities",
            "_env_clause",
            "_child_line",
            "_launcher_sentence",
            "_started_check",
            "_shown_not_kept",
            "isolation_lines",
        ],
    ),
    "run_summary": (run_summary, [], ["generation_lines", "_prompt_read"]),
}


@pytest.mark.parametrize("part", sorted(PARTS))
def test_no_form_or_condition_names_a_tool_server_or_model(part: str) -> None:
    module, constants, functions = PARTS[part]
    assert _offenders(module, constants, functions, _record(module)) == []


def test_the_names_are_every_shipped_tool_and_server() -> None:
    names = set(_names())
    for source, tools in _shipped_tools_by_source().items():
        assert set(tools) - _PLAIN_WORDS <= names, source
    assert set(builtin_server_names()) - _PLAIN_WORDS <= names


def test_a_shipped_name_planted_in_a_form_or_a_condition_is_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = sorted(set(_names()) - set(_FAMILIES) - set(builtin_server_names()))[0]
    module, constants, functions = PARTS["isolation"]
    record = _record(module)
    monkeypatch.setattr(module, "APART", f"not read by `{tool}` across its starts")
    assert _offenders(module, constants, functions, record) == [("APART", [tool])]
    monkeypatch.undo()
    planted = {
        "entries": [
            {**entry, "condition": f"{entry['condition']}; read from {tool}"}
            if entry.get("function") == f"{module.__name__}:_launcher_sentence"
            else entry
            for entry in record["entries"]
        ]
    }
    assert _offenders(module, constants, functions, planted) == [
        (f"{module.__name__}:_launcher_sentence", [tool])
    ]


@pytest.mark.parametrize("part", sorted(PARTS))
def test_no_code_of_the_part_reads_a_tool_by_its_name(part: str) -> None:
    module = PARTS[part][0]
    path = Path(inspect.getfile(module))
    assert findings(path.read_text(encoding="utf-8"), f"analysis/{path.name}") == []
