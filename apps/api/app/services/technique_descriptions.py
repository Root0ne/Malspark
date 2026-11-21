"""The description of each technique mitre.json hands out: the text the analyst report's ATT&CK
table prints for it (T-727).

The words are read off the render that prints the table (``analyst.printed_procedures``), of
the report a surface renders its report text from at that moment, read in sorted key order
(``key_ordered``) as the served exports read it. Each is plain text as the table's cell holds
it, ``""`` for a row that prints ``-``. A row of the column the STIX fallback wrote (a stored
report holding no published technique list) keeps its own description.

Where the words cannot be read (the report does not validate, or its render raises), the
answer says why and the caller decides what stands: the worker records the reason and stores
empty descriptions, a served answer and the enrichment write keep the stored column as
stored. A render that raises is logged here with its trace; the caller logs what it did.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.logging_config import get_logger

logger = get_logger("service.technique_descriptions")


def holds_published_list(document: Any) -> bool:
    """Whether a stored report holds a published technique list the column is built from."""
    return isinstance(document, Mapping) and bool(document.get("ttp_mappings"))


def printed_words(document: Any) -> tuple[dict[str, str] | None, str | None]:
    """The words the analyst report's ATT&CK table prints for each published technique of the
    report ``document``, by technique id, and ``None``; or ``None`` and why they were not read.
    """
    from malspark.reporting.models import MalwareReport, key_ordered
    from malspark.reporting.renderers.analyst import printed_procedures

    if not isinstance(document, Mapping):
        return None, "the report is not a document"
    try:
        typed = MalwareReport.model_validate(key_ordered(document))
    except Exception as exc:  # noqa: BLE001 — the caller says what stands in its place
        return None, f"the report does not validate ({type(exc).__name__})"
    try:
        return printed_procedures(typed), None
    except Exception as exc:  # noqa: BLE001 — the caller says what stands in its place
        logger.exception("the analyst report's render raised reading the technique descriptions")
        return None, f"the analyst report's render raised ({type(exc).__name__})"


def described(rows: Any, document: Any) -> tuple[Any, str | None]:
    """The stored column ``rows``, each description the words the analyst report of
    ``document`` prints for that technique (``""`` where its row prints none), and ``None``;
    the column as stored where ``document`` holds no published technique list, and as stored
    with the reason where the words could not be read."""
    if not isinstance(rows, list) or not holds_published_list(document):
        return rows, None
    words, why = printed_words(document)
    if words is None:
        return rows, why
    return [
        {**row, "description": words.get(str(row.get("technique_id") or ""), "")}
        if isinstance(row, Mapping)
        else row
        for row in rows
    ], None


# What the run summary records when the descriptions were not read off the report's table.
NOT_READ_REASON = (
    "The technique descriptions mitre.json hands out were not read off the analyst report's "
    "ATT&CK table: {why}. Each description stored is empty; the claims stand in the report."
)
