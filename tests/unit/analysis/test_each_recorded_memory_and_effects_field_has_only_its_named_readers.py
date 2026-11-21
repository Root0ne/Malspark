"""Each field the disclosure records of the case memory and of a tool's effects has named readers.

The store row's ``case``, ``case_why``, ``similar_read`` and ``similar_shown`` are noted on
the job's container where the platform decides or does the thing, and laid on the record
when the disclosure is built, after the report node's last model call; each effects row's
``network_from``, ``third_party_from`` and ``offline_without_credentials`` are written with
the effects part, built at the same time. No model and no decision reads them: the only
code that names them is listed here, by a search of the whole source tree, the web console
included, so a new reader is a changed test (T-815, T-820).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TREES = ("src", "apps/api/app", "apps/web/src", "scripts")
SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs")


def _naming(pattern: str, trees: tuple[str, ...] = TREES) -> set[str]:
    found: set[str] = set()
    for tree in trees:
        base = ROOT / tree
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.suffix in SUFFIXES and path.is_file():
                if re.search(pattern, path.read_text(encoding="utf-8", errors="replace")):
                    found.add(str(path.relative_to(ROOT)))
    return found


DISCLOSURE = "src/malspark/analysis/disclosure.py"
MEMORY = "src/malspark/memory/long_term_memory.py"


def test_the_case_memory_fields_are_read_only_by_the_case_memory_line() -> None:
    # Written by memory_facts and read by the case-memory line, both in the disclosure.
    for field in ("case_why", "similar_read", "similar_shown"):
        assert _naming(rf"[\"']{field}[\"']") == {DISCLOSURE}, field
    # ``case`` is read by its key in the disclosure alone, in the platform's code and its
    # console (the scripts' own manifests carry a ``case`` of their own).
    assert _naming(r"get\(\"case\"\)|\[\"case\"\]", TREES[:3]) == {DISCLOSURE}
    # Noted on the container where the platform decides or does it.
    assert _naming(r"\bmemory_case\b") == {
        DISCLOSURE,
        MEMORY,
        "src/malspark/core/container.py",
        "src/malspark/pipeline/nodes.py",
    }
    assert _naming(r"\bsimilar_case_read\b") == {
        DISCLOSURE,
        MEMORY,
        "src/malspark/core/container.py",
        "src/malspark/agents/judge_agent.py",
        "src/malspark/pipeline/nodes.py",
    }


EFFECTS = "src/malspark/analysis/tool_effects.py"


def test_a_network_origin_and_the_offline_condition_are_read_only_by_the_lines() -> None:
    # Written by the effects part and read by its lines, in the one module: the
    # disclosure places calls by ``network`` and ``network_by``, which stay as they were.
    assert _naming(r"[\"']network_from[\"']|\.network_from\b") == {EFFECTS}
    assert _naming(r"[\"']third_party_from[\"']|\.third_party_from\b") == {EFFECTS}
    # The row's offline flag; the declaration's own field is read by the declarations,
    # the proposals and the offline rehearsal, as before.
    assert _naming(
        r"get\(\"offline_without_credentials\"\)|\[\"offline_without_credentials\"\]"
    ) == {EFFECTS}


def test_no_form_or_condition_names_a_tool_a_server_or_a_source() -> None:
    """The case-memory line, the calls made here and the effects leads read fields only."""
    import ast
    import inspect

    from malspark.analysis import disclosure, tool_effects
    from malspark.core.config import Settings
    from malspark.core.tool_declarations import ToolDeclarations

    # Every shipped tool's name and every server's or provider's reference (a bare name,
    # ``network``, ``analysis``, an in-process ``sandbox``, is also a plain word and a row
    # field: the reference is what a rule special to it would name).
    names: set[str] = set()
    for declared in ToolDeclarations.from_settings(Settings(_env_file=None))._sources.values():
        if ":" in str(declared.source):
            names.add(str(declared.source))
        names.update(declared.tools)
    held = [
        disclosure._named_modes,
        disclosure._declared_tools,
        disclosure._stayed_line,
        disclosure._nothing_sentence,
        disclosure.memory_facts,
        disclosure._similar_sentence,
        disclosure._case_sentences,
        disclosure._store_line,
        tool_effects.entry_effects,
        tool_effects.network_from,
        tool_effects.third_party_from,
        tool_effects._ran,
        tool_effects._reaches_key,
        tool_effects._hint_closed,
        tool_effects._offline,
        tool_effects.effects_lines,
    ]
    literals: set[str] = set()
    for function in held:
        tree = ast.parse(inspect.getsource(function).lstrip())
        docs = {
            id(node.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if id(node) not in docs:
                    literals.add(node.value)
    for table in (
        tool_effects._REACHES,
        tool_effects._REACHED,
        tool_effects._DECLARED_TO_RUN,
        disclosure._SIMILAR_READ,
        {"": disclosure._REFRESH_DECLARED},
    ):
        literals.update(str(text) for text in table.values())
    for literal in literals:
        for word in re.findall(r"[A-Za-z0-9_:.\-]+", literal):
            assert word not in names, (word, literal)
