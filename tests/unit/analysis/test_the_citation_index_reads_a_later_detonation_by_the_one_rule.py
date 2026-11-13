"""The citation index reads a later detonation's index by the one rule every other reader asks.

``item_index_of`` and ``index_entry`` decide which section index is a later
detonation's as the pack, the report and the projection decide it
(``analysis.detonation_reads.later_detonation_name``): only the platform's
own read names one. A pack step of another source whose tool answers a
``detonation`` key registers no ``d2/…`` id, and a name that fails the form
never takes an entry away from serving as the first detonation's index
(T-671 review r3 R3). Offline.
"""

from __future__ import annotations

from typing import Any

from malspark.analysis import sandbox_sections as ss
from malspark.schemas.evidence import LedgerEntry

REPORT: dict[str, Any] = {"behavior": {"processes": [{"pid": 9, "process_name": "x.exe"}]}}


def _index(detonation: Any, *, source: str, launched: bool = True) -> LedgerEntry:
    structured: dict[str, Any] = {**ss.section_index(REPORT), "detonation": detonation}
    if launched:
        structured["launched_with"] = "-p x"
    return LedgerEntry(
        id="ev_0001",
        tool=ss.SECTIONS_TOOL,
        agent="pipeline",
        source=source,
        facts={"v": 1, "kind": ss.SECTIONS_KIND},
        structured=structured,
    )


def test_the_platform_s_read_registers_its_qualified_ids() -> None:
    index = ss.item_index_of([_index("d2", source="pack")])
    assert index is not None and index.known("d2/proc:9")
    assert ss.index_entry([_index("d2", source="pack")]) is None


def test_another_source_s_detonation_key_registers_no_qualified_id() -> None:
    entry = _index("d2", source="mcp:x")
    index = ss.item_index_of([entry])
    assert index is not None
    assert not index.known("d2/proc:9")
    # It serves as what it is: an index of the job's own detonation.
    assert index.known("proc:9")
    assert ss.index_entry([entry]) is entry


def test_a_name_that_fails_the_form_still_serves_as_the_first_s_index() -> None:
    for name in ("zz", "d1", "d2\n", "d2 x"):
        for source in ("pack", "mcp:x"):
            entry = _index(name, source=source)
            assert ss.index_entry([entry]) is entry, (name, source)
            index = ss.item_index_of([entry])
            assert index is not None and index.known("proc:9") and not index.later
