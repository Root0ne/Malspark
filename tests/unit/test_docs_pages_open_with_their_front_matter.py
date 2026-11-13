"""Every docs page opens with its front matter.

The docs site reads a page's title and description from the ``---`` block on
its first line; a line inserted above it (a table row pasted at the top) turns
the block into body text, and the page loses its title.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "apps" / "docs" / "content"


def test_every_page_opens_with_a_titled_front_matter() -> None:
    broken = []
    for page in sorted(DOCS.rglob("*.mdx")):
        lines = page.read_text(encoding="utf-8").splitlines()
        end = lines.index("---", 1) if lines[:1] == ["---"] and "---" in lines[1:] else -1
        if end < 0 or not any(line.startswith("title:") for line in lines[1:end]):
            broken.append(str(page.relative_to(ROOT)))
    assert not broken, f"a page does not open with its front matter: {broken}"
