"""Every call of the publish answer hands it the report, so the launch rule is asked everywhere.

The publish rule refuses a value a further detonation's launch text supplied
(``launch_echo.launch_supplied_refusal``), which it reads off the report's
record. A call that left the report out would publish such a value on its
surface while another surface refused it. Every call of ``publish_answer`` in
the platform's source, the builder's wrapper of it included, passes the
report by keyword, never a literal ``None``; and the function is referred to
only where it is called, imported or defined, so no alias, partial or
attribute lookup reaches it unread. This reads every reference.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCES = (ROOT / "src" / "malspark", ROOT / "apps" / "api" / "app")
NAME = "publish_answer"


def _faults(source: str, where: str) -> list[str]:
    """Each reference to the publish answer in ``source`` that is not a call passing the report
    by keyword (never a literal ``None``), its import or its definition."""
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    names = {NAME}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names |= {alias.asname or alias.name for alias in node.names if alias.name == NAME}
    out: list[str] = []
    for node in ast.walk(tree):
        # A name or an attribute read (a field of that name written is no reference).
        if isinstance(node, ast.Name) and node.id in names and isinstance(node.ctx, ast.Load):
            held: ast.expr = node
        elif (
            isinstance(node, ast.Attribute)
            and node.attr in names
            and isinstance(node.ctx, ast.Load)
        ):
            held = node
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("getattr", "attrgetter")
            and any(isinstance(arg, ast.Constant) and arg.value in names for arg in node.args)
        ):
            out.append(f"{where}:{node.lineno}: looked up by name")
            continue
        else:
            continue
        call = parents.get(held)
        if not isinstance(call, ast.Call) or call.func is not held:
            out.append(f"{where}:{held.lineno}: referred to without a call")
            continue
        given = [keyword.value for keyword in call.keywords if keyword.arg == "report"]
        if not given:
            out.append(f"{where}:{call.lineno}: no report")
        elif isinstance(given[0], ast.Constant) and given[0].value is None:
            out.append(f"{where}:{call.lineno}: the report is None")
    return sorted(out, key=lambda fault: int(fault.split(":")[1]))


def _calls() -> list[str]:
    found: list[str] = []
    for base in SOURCES:
        for path in sorted(base.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if NAME in text:
                found.append(str(path.relative_to(ROOT)))
    return found


def test_the_calls_are_found() -> None:
    assert {
        "src/malspark/reporting/builder.py",
        "src/malspark/reporting/stated_host_values.py",
        "src/malspark/reporting/renderers/stix_renderer.py",
    } <= set(_calls())


def test_every_reference_is_a_call_that_passes_the_report_by_keyword() -> None:
    faults: list[str] = []
    for where in _calls():
        faults += _faults((ROOT / where).read_text(encoding="utf-8"), where)
    assert faults == []


class TestTheCheckReadsEveryReference:
    def test_a_call_with_the_report_passes(self) -> None:
        source = "from x import publish_answer\npublish_answer('ip', v, 's', report=r)\n"
        assert _faults(source, "m") == []

    def test_an_aliased_import_is_read_by_its_alias(self) -> None:
        source = "from x import publish_answer as answer\nanswer('ip', v, 's')\n"
        assert _faults(source, "m") == ["m:2: no report"]

    def test_a_partial_and_a_lookup_by_name(self) -> None:
        source = (
            "import functools\nfrom x import publish_answer\n"
            "f = functools.partial(publish_answer, report=r)\n"
            "g = getattr(x, 'publish_answer')\n"
            "h = x.publish_answer\n"
        )
        assert _faults(source, "m") == [
            "m:3: referred to without a call",
            "m:4: looked up by name",
            "m:5: referred to without a call",
        ]

    def test_a_literal_none_for_the_report(self) -> None:
        source = "from x import publish_answer\npublish_answer('ip', v, 's', report=None)\n"
        assert _faults(source, "m") == ["m:2: the report is None"]
