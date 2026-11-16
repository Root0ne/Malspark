"""No surface asks the publish rule: each reads the row the IOC table built.

The rule is asked once per value, by the table's builder
(``builder.ioc_table``), and the row records the answer, its role and the type
an export carries it under. A surface that asked the rule again could ask it
with other arguments, which is how the export and the feed came to publish
different values for one run. This test reads the source: the export's code,
everything it calls in its own module, and every other surface module, and
fails when any of them names the rule.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXPORT = ROOT / "src" / "malspark" / "reporting" / "renderers" / "stix_renderer.py"

# The rule and the functions that answer for it: a surface names none of them.
RULE = frozenset(
    {
        "publish_answer",
        "indicator_publish_reason",
        "_evidence_reason",
        "judge_value_answer",
        "judge_indicator_rows",
        "withheld_by_the_verdict",
        "table_row_record",
        "publication_for",
        "published_url_hosts",
        "emulation_kwargs",
        "sandbox_host_kwargs",
        "bound_kwargs",
    }
)

# Every other surface of a report's indicators: the Markdown, HTML and analyst
# reports, MISP, the rule drafts and the ``/iocs`` feed.
SURFACES = (
    ROOT / "src" / "malspark" / "reporting" / "misp.py",
    ROOT / "src" / "malspark" / "reporting" / "detection_signatures.py",
    ROOT / "src" / "malspark" / "reporting" / "renderers" / "markdown.py",
    ROOT / "src" / "malspark" / "reporting" / "renderers" / "html.py",
    ROOT / "src" / "malspark" / "reporting" / "renderers" / "analyst.py",
    ROOT / "apps" / "api" / "app" / "services" / "report_service.py",
)


def _names(node: ast.AST) -> set[str]:
    """Every name and attribute ``node`` reads."""
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
        elif isinstance(child, ast.alias):
            found.add(child.asname or child.name.rsplit(".", 1)[-1])
    return found


def _export_reach() -> dict[str, set[str]]:
    """The export's methods and every function of its module they reach, with what each reads."""
    tree = ast.parse(EXPORT.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    (renderer,) = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ExtendedSTIXRenderer"
    ]
    reached: dict[str, set[str]] = {}
    queue = [
        (f"ExtendedSTIXRenderer.{m.name}", m)
        for m in renderer.body
        if isinstance(m, ast.FunctionDef)
    ]
    while queue:
        name, node = queue.pop()
        if name in reached:
            continue
        reached[name] = _names(node)
        for called in reached[name] & set(functions):
            queue.append((called, functions[called]))
    return reached


def test_the_export_reaches_no_part_of_the_rule() -> None:
    reached = _export_reach()

    assert "ExtendedSTIXRenderer._render" in reached
    asking = {name: sorted(names & RULE) for name, names in reached.items() if names & RULE}
    assert asking == {}


def test_the_export_reads_the_table_the_builder_built() -> None:
    assert "ioc_table" in _export_reach()["ExtendedSTIXRenderer._render"]


def test_no_other_surface_names_the_rule() -> None:
    for path in SURFACES:
        named = _names(ast.parse(path.read_text(encoding="utf-8"))) & RULE
        assert not named, f"{path.name} names {sorted(named)}"
