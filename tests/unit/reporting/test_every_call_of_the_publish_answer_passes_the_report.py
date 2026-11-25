"""Every call of the publish answer hands it the report, so the launch rule is asked everywhere.

The publish rule refuses a value a further detonation's launch text supplied
(``launch_echo.launch_supplied_refusal``), which it reads off the report's
record. A call that left the report out would publish such a value on its
surface while another surface refused it. Every call of ``publish_answer`` in
the platform's source, the builder's wrapper of it included, passes the
report by keyword; this reads every call site.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCES = (ROOT / "src" / "malspark", ROOT / "apps" / "api" / "app")
NAMES = frozenset({"publish_answer", "_publish_answer"})


def _calls() -> list[tuple[str, int, ast.Call]]:
    found: list[tuple[str, int, ast.Call]] = []
    for base in SOURCES:
        for path in sorted(base.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else ""
                )
                if name in NAMES:
                    found.append((str(path.relative_to(ROOT)), node.lineno, node))
    return found


def test_the_calls_are_found() -> None:
    files = {path for path, _line, _call in _calls()}
    assert {
        "src/malspark/reporting/builder.py",
        "src/malspark/reporting/stated_host_values.py",
        "src/malspark/reporting/renderers/stix_renderer.py",
    } <= files


def test_every_call_passes_the_report_by_keyword() -> None:
    missing = [
        f"{path}:{line}"
        for path, line, call in _calls()
        if not any(keyword.arg == "report" for keyword in call.keywords)
    ]
    assert missing == []
