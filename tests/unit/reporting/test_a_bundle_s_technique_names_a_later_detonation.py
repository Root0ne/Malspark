"""A section bundle's technique list names a later detonation where it observed the technique.

The executive summary's ``top_ttps`` and the mitigations' ``ttps`` list each
published technique. One whose mark (``TTPMapping.observed_in``) names only a
further detonation says that detonation and its launch; one the job's own
detonation observed too says which part each detonation is; one with no mark
reads as it always did, so a run with one detonation bundles the same (T-679).
"""

from __future__ import annotations

import hashlib
import json

import pytest

from malspark.reporting.evidence_bundles import bundle_for
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    ObservedIn,
    SampleIdentity,
    TTPMapping,
)

ARGS = "-p hunter2"
D1 = ObservedIn(detonation="d1")
D2 = ObservedIn(detonation="d2", launched_with=ARGS)
LISTS = {"executive_summary": "top_ttps", "mitigations": "ttps"}


def _report(*, later: bool = True) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="8" * 64)),
        verdict="Malware",
        ttp_mappings=[
            TTPMapping(
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                observed_in=[D2] if later else [],
            ),
            TTPMapping(
                technique_id="T1622",
                technique_name="Debugger Evasion",
                observed_in=[D1, D2] if later else [],
            ),
            TTPMapping(technique_id="T1027", technique_name="Obfuscated Files or Information"),
        ],
    )


def _listed(section: str, report: MalwareReport) -> list[str]:
    return list(bundle_for(section, report)["facts"][LISTS[section]])


@pytest.mark.parametrize("section", list(LISTS))
def test_a_technique_only_a_later_detonation_observed_names_it(section: str) -> None:
    listed = _listed(section, _report())
    assert listed[0] == (
        f"T1486 Data Encrypted for Impact (observed in detonation 2, launched with `{ARGS}`)"
    )


@pytest.mark.parametrize("section", list(LISTS))
def test_mixed_support_says_which_part_each_detonation_is(section: str) -> None:
    listed = _listed(section, _report())
    assert listed[1] == (
        "T1622 Debugger Evasion (observed in the job's own detonation and in detonation 2, "
        f"launched with `{ARGS}`)"
    )


@pytest.mark.parametrize("section", list(LISTS))
def test_a_technique_with_no_mark_reads_as_it_did(section: str) -> None:
    assert _listed(section, _report())[2] == "T1027 Obfuscated Files or Information"


# The two bundles as 8fe0ba5db builds them for the report with one detonation.
PINNED = {
    "executive_summary": "e84f6f2d540be3cc8dc04171ee02b9c99eff713c5f46a7ee0f716763464c0f47",
    "mitigations": "c9915ff5cbed94a5410b27c686946b046ddaf3eea4548db32b728fde9eb4b6ae",
}


@pytest.mark.parametrize("section", list(PINNED))
def test_a_run_with_one_detonation_bundles_the_same(section: str) -> None:
    bundle = bundle_for(section, _report(later=False))
    text = json.dumps(bundle, sort_keys=True, default=str)
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == PINNED[section]
