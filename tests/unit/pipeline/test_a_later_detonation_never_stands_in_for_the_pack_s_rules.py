"""A later detonation's pack entries never stand in for an answer the static provider would give.

``triage_pack.rules_already_recorded`` tells the report node that the pack
already produced the kinds an evidence-only static provider answers. The
platform's reads of a further detonation are pack entries of the sandbox's
kinds; whatever kinds a provider declares, they never count as the pack's
own answer of them (T-671 review r2, the unverified ``pack_has_kind``).
Offline.
"""

from __future__ import annotations

from malspark.pipeline.triage_pack import rules_already_recorded
from tests.unit.pipeline.test_a_later_detonation_s_pack_lines_are_marked import _rows


def test_the_default_rule_kinds_are_not_tripped_by_a_later_detonation() -> None:
    later = _rows()[2:]
    assert not rules_already_recorded(later)


def test_a_declared_sandbox_kind_counts_the_job_s_own_entry_only() -> None:
    kinds = ["sandbox_processes", "sandbox_sections"]
    later = _rows()[2:]
    assert not rules_already_recorded(later, kinds)
    # The same reads, as the job's own: they do count.
    own = [
        {**row, "structured": {k: v for k, v in row["structured"].items() if k != "launched_with"}}
        for row in later
    ]
    assert rules_already_recorded(own, kinds)
