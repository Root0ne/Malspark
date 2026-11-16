"""Sigma tags come from published cells and name what the rule selects; a Suricata draft is
cut between rules (RC-21).

A Sigma draft is tagged with a technique only where that technique's own
statement, its evidence quotes and roots, names a value the draft selects,
whole and delimited; a tactic only for a technique kept, from a cell the report
published. A draft no technique names carries no tags.
"""

from __future__ import annotations

import yaml

from malspark.reporting import detection_signatures as ds
from malspark.reporting.models import (
    CapabilityCell,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)

# The values one draft selects, as its selections hold them.
SELECTED = ["\\Custom_update\\", ":wtfbbq"]


def _cell(tactic_name: str, technique: str, not_published: str = "") -> CapabilityCell:
    return CapabilityCell(
        tactic="TA0003",
        tactic_name=tactic_name,
        technique_id=technique,
        technique_name="n",
        not_published=not_published,
    )


def _mapping(technique: str, quotes: list[str], roots: list[str] | None = None) -> TTPMapping:
    return TTPMapping(
        technique_id=technique,
        technique_name="n",
        evidence_quotes=quotes,
        evidence_roots=roots or [],
    )


def _report(mappings: list[TTPMapping], cells: list[CapabilityCell]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        ttp_mappings=mappings,
        capability_matrix=cells,
    )


def test_an_unpublished_cell_gives_no_tactic_tag() -> None:
    report = _report(
        [
            _mapping(
                "T1547", ["The loader copies itself to C:\\ProgramData\\Custom_update\\a.exe."]
            ),
            _mapping("T1059", ["It runs 'Custom_update' each hour."]),
        ],
        [
            _cell("Persistence", "T1547"),
            _cell("Execution", "T1059", "the catalogue has no such id"),
        ],
    )
    assert ds._sigma_tags(report, SELECTED) == [
        "attack.t1547",
        "attack.t1059",
        "attack.persistence",
    ]


def test_a_technique_naming_no_selected_value_gives_no_tag_nor_its_tactic() -> None:
    report = _report(
        [
            _mapping("T1055", ["Seven WriteProcessMemory rows into defrag.exe."]),
            _mapping("T1564.004", [], ["stream written: update.dat:wtfbbq"]),
        ],
        [_cell("Defense Evasion", "T1055"), _cell("Persistence", "T1564.004")],
    )
    assert ds._sigma_tags(report, SELECTED) == ["attack.t1564.004", "attack.persistence"]


def test_a_value_in_running_text_or_inside_another_name_names_nothing() -> None:
    report = _report(
        [
            _mapping("T1105", ["It writes the Custom_update folder."]),
            _mapping("T1140", ["It decodes C:\\ProgramData\\Custom_update2\\x.dat."]),
        ],
        [_cell("Command and Control", "T1105")],
    )
    assert ds._sigma_tags(report, SELECTED) == []


def test_a_draft_no_technique_names_carries_no_tags() -> None:
    report = _report(
        [_mapping("T1055", ["Seven WriteProcessMemory rows into defrag.exe."])],
        [_cell("Defense Evasion", "T1055")],
    )
    rule = ds._sigma_rule(
        report,
        "file",
        {"product": "windows", "category": "file_event"},
        {"selection_folder": {"TargetFilename|contains": ["\\Custom_update\\"]}},
        [],
    )
    assert "tags" not in yaml.safe_load(rule.body)
    assert rule.compile_error is None


def test_a_long_draft_keeps_every_rule_it_holds_whole(monkeypatch: object) -> None:
    monkeypatch.setattr(ds, "_SURICATA_MAX_BODY_BYTES", 400)  # type: ignore[attr-defined]
    lines = []
    for n in range(10):
        lines.append(f"# why {n}")
        lines.append(f'alert dns any any -> any any (msg:"rule {n}"; sid:{n};)')
    body = ds._suricata_body_within(lines)
    kept = body.splitlines()
    assert all(line.endswith(";)") for line in kept if line.startswith("alert"))
    assert len(body.encode("utf-8")) < 400 + 200
    assert kept[-1].startswith("# (cut at the draft's size:")
    rules = [line for line in kept if line.startswith("alert")]
    assert f"{10 - len(rules):,} more indicators" in kept[-1]


def test_a_short_draft_is_unchanged() -> None:
    lines = ["# a", 'alert ip any any -> any any (msg:"x"; sid:1;)']
    assert ds._suricata_body_within(lines) == "\n".join(lines)


def test_the_header_lines_survive_a_cut_and_the_capped_are_counted(monkeypatch: object) -> None:
    monkeypatch.setattr(ds, "_SURICATA_MAX_BODY_BYTES", 120)  # type: ignore[attr-defined]
    header = ["# one", "# two", "# three"]
    lines = [*header, "# why", 'alert dns any any -> any any (msg:"' + "x" * 200 + '"; sid:1;)']
    kept = ds._suricata_body_within(lines, header=3, capped=4).splitlines()
    assert kept[:3] == header
    assert "5 more indicators" in kept[-1]
