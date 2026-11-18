"""How the report writes the judge's malware category, one reading for every surface.

The judge states a category in its own words: a behavioural class ("loader"), or that
the sample has none, alone ("none") or with what it is instead ("none: a legitimate
archiver", "none (a legitimate archiver)"). A line prints a category stated as none in
one form, "none (<what it states instead>)"; a name standing for the sample (the
cover's malware name, a subtitle) is never made of one.
"""

from __future__ import annotations

import re
from typing import Any

# A category the judge states as none, and what it states after the word, where it is
# set off by a colon, a semicolon or a spaced dash.
_STATED_NONE = re.compile(r"\s*none\b", re.IGNORECASE)
_NONE_THEN = re.compile(r"\s*none\s*(?::|;|\s[-–—])\s*(?P<rest>\S.*)", re.I | re.S)


def _one_line(value: Any) -> str:
    return " ".join(str(value or "").split())


def stated_none(category: Any) -> bool:
    """Whether the judge states the category as none ("none", "None: a legitimate tool")."""
    return bool(_STATED_NONE.match(str(category or "")))


def category_shown(category: Any) -> str:
    """The category as a line prints it: ``""`` for none given or "unknown"; one stated as
    none set off by a colon, a semicolon or a dash as "none (<the rest>)"; any other as
    the judge wrote it, on one line."""
    text = _one_line(category)
    if not text or text.lower() == "unknown":
        return ""
    found = _NONE_THEN.fullmatch(text)
    return f"none ({found.group('rest').strip()})" if found else text


def category_name(category: Any) -> str | None:
    """The category as a name standing for the sample, or ``None``: none for a category
    stated as none or not given; any other title-cased ("information stealer" is
    "Information Stealer")."""
    text = _one_line(category)
    if not text or stated_none(text):
        return None
    return str(category).title()
