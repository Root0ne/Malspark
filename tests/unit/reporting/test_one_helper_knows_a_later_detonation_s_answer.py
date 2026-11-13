"""One helper decides that an answer is a later detonation's, wherever a read is drawn.

The evidence sections and the ledger projection both read a further
detonation's answer by ``ledger_projection.later_detonation``: a
third-party tool's answer that only happens to hold a ``detonation`` key is
the job's own and is drawn in the job's own tables (T-671 review B7). Offline.
"""

from __future__ import annotations

from malspark.reporting.ledger_report import build_sections, detonation_of_section
from malspark.schemas.evidence import LedgerEntry


def test_a_third_party_answer_with_a_detonation_key_is_drawn_as_the_job_s_own() -> None:
    rows = {"processes": [{"pid": 7, "name": "x.exe"}]}
    ledger = [
        LedgerEntry(
            id="ev_0001",
            tool="sandbox_processes",
            agent="dynamic",
            structured={"detonation": "my-run", **rows},
        ),
        # The platform's in-process sandbox source, as the recorder filed it.
        LedgerEntry(
            id="ev_0002",
            tool="sandbox_processes",
            agent="dynamic",
            source="sandbox",
            facts={"v": 1, "kind": "sandbox_processes"},
            structured={"detonation": "d2", "launched_with": "-p x", **rows},
        ),
    ]
    sections = build_sections(ledger, {}, "pe", "windows")
    apart = [s.key for s in sections if detonation_of_section(s.key)]
    assert apart and all(detonation_of_section(k) == "d2" for k in apart)
    assert not any("my-run" in s.key or "my-run" in s.title for s in sections)
