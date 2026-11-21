"""The coverage sentences rest on no tool, server or model by name.

Each sentence of these parts says what the platform read and what that reading
gave, under a condition read from the record's own fields. Neither the words
nor the conditions that choose them, nor the record entries that state those
conditions, name a tool server, a provider or a model family; and no code of
the modules reads an entry's tool by a tool's name (T-817).
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import pytest
from tests.tool_name_reads import findings

from malspark.analysis import coverage
from malspark.core.builtin_declarations import builtin_server_names, provider_names

ROOT = Path(__file__).resolve().parents[3]
RECORDS = ROOT / "scripts" / "audit" / "publishing_records"
# Server keys that are plain words of these sentences, not a name.
_PLAIN_WORDS = frozenset({"analysis", "knowledge", "network", "die"})
_FAMILIES = ("ollama", "llama", "deepseek", "claude", "haiku", "qwen", "openai", "anthropic")


def _names() -> list[str]:
    servers = [name for name in builtin_server_names() if name not in _PLAIN_WORDS]
    return [*servers, *provider_names(), *_FAMILIES]


def _named(text: str) -> list[str]:
    return [name for name in _names() if re.search(rf"(?<![a-z0-9_]){re.escape(name)}", text, re.I)]


# The constants each part writes, and the functions whose conditions choose its forms.
PARTS = {
    "coverage": (coverage, ["NOTHING_MISSING"], ["coverage_lines"]),
}


@pytest.mark.parametrize("part", sorted(PARTS))
def test_no_form_or_condition_names_a_tool_server_or_model(part: str) -> None:
    module, constants, functions = PARTS[part]
    for name in constants:
        assert _named(getattr(module, name)) == [], name
    for name in functions:
        assert _named(inspect.getsource(getattr(module, name))) == [], name
    keys = {f"{module.__name__}:{name}" for name in (*constants, *functions)}
    record = json.loads((RECORDS / f"{module.__name__}.json").read_text(encoding="utf-8"))
    for entry in record["entries"]:
        key = entry.get("function") or entry.get("constant")
        if key in keys:
            assert _named(entry["condition"]) == [], key


@pytest.mark.parametrize("part", sorted(PARTS))
def test_no_code_of_the_part_reads_a_tool_by_its_name(part: str) -> None:
    module = PARTS[part][0]
    path = Path(inspect.getfile(module))
    assert findings(path.read_text(encoding="utf-8"), f"analysis/{path.name}") == []
