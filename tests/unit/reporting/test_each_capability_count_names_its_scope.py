"""Each capability count a section is shown names the scope it was counted in.

The encryption, discovery, evasion and persistence sections were shown the
import table's category counts under keys that named no scope (an anti-debug
count of 0), while the names the run resolved at runtime
were counted apart and shown only to the string-resolution section. A zero
counted over the imports then read as true of the sample whole. Each section
is now shown its categories in the profile of each scope the run measured,
under the key that names that scope; a profile not measured is not named.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.composer import _bundle_text
from malspark.reporting.evidence_bundles import bundle_for, is_empty
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity, StaticAnalysis

IMPORTS = "capability_profile_of_import_table"
RESOLVED = "capability_profile_of_names_resolved_at_runtime_not_imports"


def _report(**static: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        static=StaticAnalysis(**static),
    )


def _both_measured() -> MalwareReport:
    return _report(
        api_capabilities={"persistence": 1},
        api_capabilities_evidence_ids=["ev_0010"],
        api_capabilities_resolved={
            "anti_debug": 7,
            "evasion": 4,
            "discovery": 10,
            "registry": 5,
            "persistence": 4,
        },
        api_capabilities_resolved_evidence_ids=["ev_0011"],
        api_technique_hits=[
            {"technique_id": "T1622", "name": "Debugger Evasion"},
            {"technique_id": "T1082", "name": "System Information Discovery"},
        ],
    )


def test_the_evasion_section_is_shown_each_profile_under_its_scope() -> None:
    facts = bundle_for("evasion_antiforensics", _both_measured())["facts"]
    assert facts == {
        IMPORTS: {"anti_debug": 0, "evasion": 0},
        RESOLVED: {"anti_debug": 7, "evasion": 4},
        "evasion_techniques": ["T1622"],
    }


def test_the_discovery_section_is_shown_each_profile_under_its_scope() -> None:
    facts = bundle_for("discovery", _both_measured())["facts"]
    assert facts == {
        IMPORTS: {"discovery": 0},
        RESOLVED: {"discovery": 10},
        "discovery_techniques": ["T1082"],
    }


def test_the_encryption_section_states_a_zero_in_every_scope_that_counted_none() -> None:
    facts = bundle_for("encryption_scheme", _both_measured())["facts"]
    assert facts == {IMPORTS: {"crypto": 0}, RESOLVED: {"crypto": 0}}


def test_the_persistence_section_is_shown_each_profile_under_its_scope() -> None:
    facts = bundle_for("persistence_detail", _both_measured())["facts"]
    assert facts == {
        "persistence_mechanisms": [],
        "persistence_assessed": [],
        IMPORTS: {"persistence": 1, "registry": 0},
        RESOLVED: {"persistence": 4, "registry": 5},
    }


@pytest.mark.parametrize(
    ("section", "categories", "others"),
    [
        ("encryption_scheme", ("crypto",), {}),
        ("discovery", ("discovery",), {"discovery_techniques": []}),
        ("evasion_antiforensics", ("anti_debug", "evasion"), {"evasion_techniques": []}),
        (
            "persistence_detail",
            ("persistence", "registry"),
            {"persistence_mechanisms": [], "persistence_assessed": []},
        ),
    ],
)
def test_with_no_resolved_profile_only_the_import_table_is_named(
    section: str, categories: tuple[str, ...], others: dict[str, Any]
) -> None:
    report = _report(api_capabilities={"persistence": 1}, api_capabilities_evidence_ids=["ev_0010"])
    facts = bundle_for(section, report)["facts"]
    counts = {"persistence": 1}
    assert facts == {IMPORTS: {c: counts.get(c, 0) for c in categories}, **others}


@pytest.mark.parametrize(
    ("section", "facts"),
    [
        ("encryption_scheme", {RESOLVED: {"crypto": 2}}),
        ("discovery", {RESOLVED: {"discovery": 0}, "discovery_techniques": []}),
        (
            "evasion_antiforensics",
            {RESOLVED: {"anti_debug": 7, "evasion": 0}, "evasion_techniques": []},
        ),
        (
            "persistence_detail",
            {
                "persistence_mechanisms": [],
                "persistence_assessed": [],
                RESOLVED: {"persistence": 0, "registry": 0},
            },
        ),
    ],
)
def test_with_no_import_profile_only_a_measured_resolved_profile_is_named(
    section: str, facts: dict[str, Any]
) -> None:
    unmeasured = {k: v for k, v in facts.items() if k != RESOLVED}
    assert bundle_for(section, _report())["facts"] == unmeasured
    resolved = _report(
        api_capabilities_resolved={"crypto": 2, "anti_debug": 7},
        api_capabilities_resolved_evidence_ids=["ev_0011"],
    )
    assert bundle_for(section, resolved)["facts"] == facts


def test_the_section_request_holds_both_scoped_lines_and_no_unscoped_count() -> None:
    bundle = bundle_for("evasion_antiforensics", _both_measured())
    text = _bundle_text("evasion_antiforensics", bundle)
    block = text.split("DETERMINISTIC FACTS:\n", 1)[1].split("\n\n", 1)[0]
    assert block.splitlines() == [
        '- capability_profile_of_import_table: {"anti_debug": 0, "evasion": 0}',
        "- capability_profile_of_names_resolved_at_runtime_not_imports:"
        ' {"anti_debug": 7, "evasion": 4}',
        '- evasion_techniques: ["T1622"]',
    ]


def test_the_string_count_names_the_strings_it_counts() -> None:
    from malspark.reporting.models import StringIOC

    report = _report(interesting_strings=[StringIOC(value="http://a.example/x", kind="url")])
    assert bundle_for("string_resolution", report)["facts"] == {
        "static_import_count": 0,
        "strings_typed_as_indicators_count": 1,
        IMPORTS: {},
    }


def test_the_string_section_names_each_profile_by_the_same_scoped_key() -> None:
    from malspark.reporting.models import ImportRow, StringIOC

    report = _both_measured()
    assert report.static is not None
    report.static.imports = [ImportRow(dll="advapi32.dll", function="RegSetValueExW")]
    report.static.interesting_strings = [StringIOC(value="http://a.example/x", kind="url")]
    facts = bundle_for("string_resolution", report)["facts"]
    assert facts == {
        "static_import_count": 1,
        "strings_typed_as_indicators_count": 1,
        IMPORTS: {"persistence": 1},
        RESOLVED: {"discovery": 10, "anti_debug": 7, "registry": 5, "evasion": 4, "persistence": 4},
    }
    assert list(facts[RESOLVED]) == [
        "discovery",
        "anti_debug",
        "registry",
        "evasion",
        "persistence",
    ]


@pytest.mark.parametrize(
    "section",
    ["cli_flags", "attack_procedures", "conclusion", "limitations", "ransom_note", "summary"],
)
def test_every_other_section_names_the_import_profile_by_its_scope(section: str) -> None:
    report = _report(
        api_capabilities={"registry": 2, "network": 5},
        api_capabilities_evidence_ids=["ev_0010"],
    )
    facts = bundle_for(section, report)["facts"]
    assert facts == {IMPORTS: {"network": 5, "registry": 2}}
    assert list(facts[IMPORTS]) == ["network", "registry"]


# The constructed profiles of the skip-decision cases: every combination of a
# measured, unmeasured, zero, nonzero, negative or unknown category in either
# scope, and two ordinary runs.
_SKIP_CASES: dict[str, dict[str, Any]] = {
    "nothing_measured": {},
    "both_measured": {
        "api_capabilities": {"persistence": 1},
        "api_capabilities_evidence_ids": ["ev_0010"],
        "api_capabilities_resolved": {
            "anti_debug": 7,
            "evasion": 4,
            "discovery": 10,
            "registry": 5,
            "persistence": 4,
        },
        "api_capabilities_resolved_evidence_ids": ["ev_0011"],
        "api_technique_hits": [
            {"technique_id": "T1622", "name": "Debugger Evasion"},
            {"technique_id": "T1082", "name": "System Information Discovery"},
        ],
    },
    "resolved_only_nonzero": {
        "api_capabilities_resolved": {"crypto": 2, "anti_debug": 7},
        "api_capabilities_resolved_evidence_ids": ["ev_1"],
    },
    "imports_zero_resolved_nonzero": {
        "api_capabilities": {"network": 3},
        "api_capabilities_evidence_ids": ["ev_0"],
        "api_capabilities_resolved": {"crypto": 2, "discovery": 1, "persistence": 1},
        "api_capabilities_resolved_evidence_ids": ["ev_1"],
    },
    "resolved_measured_empty": {
        "api_capabilities": {"network": 3},
        "api_capabilities_evidence_ids": ["ev_0"],
        "api_capabilities_resolved_evidence_ids": ["ev_1"],
    },
    "resolved_ids_only": {"api_capabilities_resolved_evidence_ids": ["ev_1"]},
    "imports_zero_valued_category": {
        "api_capabilities": {"network": 0},
        "api_capabilities_evidence_ids": ["ev_0"],
    },
    "resolved_zero_valued_category": {
        "api_capabilities_resolved": {"crypto": 0},
        "api_capabilities_resolved_evidence_ids": ["ev_1"],
    },
    "resolved_counts_no_ids": {"api_capabilities_resolved": {"crypto": 2}},
    "imports_counts_no_ids": {"api_capabilities": {"crypto": 2}},
    "unknown_category": {
        "api_capabilities": {"quantum_magic": 9},
        "api_capabilities_resolved": {"quantum_magic": 4},
        "api_capabilities_evidence_ids": ["e"],
        "api_capabilities_resolved_evidence_ids": ["f"],
    },
    "same_category_both": {
        "api_capabilities": {"anti_debug": 3},
        "api_capabilities_resolved": {"anti_debug": 3},
        "api_capabilities_evidence_ids": ["e"],
        "api_capabilities_resolved_evidence_ids": ["f"],
    },
    "negative": {
        "api_capabilities": {"crypto": -1},
        "api_capabilities_evidence_ids": ["e"],
        "api_capabilities_resolved": {"crypto": -2},
        "api_capabilities_resolved_evidence_ids": ["f"],
    },
    "large": {
        "api_capabilities": {f"c{i:03d}": i % 7 + 1 for i in range(300)},
        "api_capabilities_evidence_ids": ["e"],
    },
}

_WHOLE_PROFILE = ("cli_flags", "conclusion", "summary")

# The sections written, per case, as they were before the counts were scoped
# (read off that source on the same inputs); every other section is skipped.
_WRITTEN: dict[str, set[str]] = {
    "nothing_measured": set(),
    "both_measured": {
        *_WHOLE_PROFILE,
        "string_resolution",
        "persistence_detail",
        "evasion_antiforensics",
        "discovery",
    },
    "resolved_only_nonzero": {"string_resolution"},
    "imports_zero_resolved_nonzero": {*_WHOLE_PROFILE, "string_resolution"},
    "resolved_measured_empty": {*_WHOLE_PROFILE, "string_resolution"},
    "resolved_ids_only": set(),
    "imports_zero_valued_category": {*_WHOLE_PROFILE, "string_resolution"},
    "resolved_zero_valued_category": {"string_resolution"},
    "resolved_counts_no_ids": {"string_resolution"},
    "imports_counts_no_ids": {*_WHOLE_PROFILE, "string_resolution", "encryption_scheme"},
    "unknown_category": {*_WHOLE_PROFILE, "string_resolution"},
    "same_category_both": {*_WHOLE_PROFILE, "string_resolution", "evasion_antiforensics"},
    "negative": {*_WHOLE_PROFILE, "string_resolution", "encryption_scheme"},
    "large": {*_WHOLE_PROFILE, "string_resolution"},
}

_SKIP_SECTIONS = (
    "encryption_scheme",
    "discovery",
    "evasion_antiforensics",
    "persistence_detail",
    "string_resolution",
    *_WHOLE_PROFILE,
)


@pytest.mark.parametrize("case", sorted(_SKIP_CASES))
def test_a_section_is_skipped_exactly_when_it_was_before_the_counts_were_scoped(
    case: str,
) -> None:
    report = _report(**_SKIP_CASES[case])
    written = {s for s in _SKIP_SECTIONS if not is_empty(bundle_for(s, report))}
    assert written == _WRITTEN[case]
