"""Each field the disclosure records of the case memory and of a tool's effects has named readers.

The store row's ``case``, ``case_why``, ``similar_read`` and ``similar_shown`` are noted on
the job's container where the platform decides or does the thing, and laid on the record
when the disclosure is built, after the report node's last model call. No model and no
decision reads them: the only code that names them is listed here, by a search of the
whole source tree, the web console included, so a new reader is a changed test (T-815).
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
