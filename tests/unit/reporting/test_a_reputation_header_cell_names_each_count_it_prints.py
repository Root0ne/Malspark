"""The report's reputation cell names each count it prints, and states no fraction.

"M of N engines flag it" read as "N engines looked, N - M found nothing",
where N held engines that gave no verdict, or a sum the platform made over
categories it did not name. The cell prints the counts the lookup's record
holds, each under the record's own name for it: the flagged count always, the
members of the answer's counts object that are not zero under the names the
answer wrote, and the engine count the service gave beside them. A sum is never
printed, no figure the cell printed before is lost, and the whole tally stands
in the evidence bundle's rows, every member under its own name (an entry that
recorded no source keeps the rows it always had). Two lookups of one tool that
state different tallies have their rows named by entry.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

import pytest

from malspark.core import declared_reading
from malspark.core.config import Settings, get_settings, install_settings
from malspark.core.reputation import ReputationRecord, counts_line
from malspark.reporting.ledger_report import build_sections
from malspark.reporting.models import (
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    ReputationAnswer,
    SampleIdentity,
)
from malspark.reporting.renderers.markdown import _reputation_line
from malspark.schemas.evidence import build_entry, format_entry_id

# The answer's own tally and engine count, as a stored lookup wrote them.
STATS = {
    "malicious": 0,
    "failure": 2,
    "timeout": 28,
    "harmless": 0,
    "suspicious": 0,
    "undetected": 37,
    "type-unsupported": 3,
    "confirmed-timeout": 1,
}
_FRACTION = re.compile(r"\d+ of \d+|\d+/\d+")


def _report(*answers: ReputationAnswer, tool: str = "get_file_report") -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        evidence_index=[
            EvidenceIndexRow(id=answer.entry_id, agent="pipeline", tool=tool) for answer in answers
        ],
        reputation=list(answers),
    )


def _answer(**over: Any) -> ReputationAnswer:
    fields: dict[str, Any] = {
        "entry_id": "ev_0018",
        "tool": "get_file_report",
        "service": "HashRep",
        "malicious": 0,
        "suspicious": 0,
        "total": sum(STATS.values()),
        "engines": 71,
        "stats": STATS,
        "last_seen": "2026-08-23T08:03:36Z",
    }
    return ReputationAnswer(**{**fields, **over})


def test_the_cell_prints_the_flagged_count_the_members_not_zero_and_the_engines_by_name() -> None:
    cell = _reputation_line(_report(_answer()))
    assert cell == (
        "HashRep, counts in the lookup's record: malicious 0, failure 2, timeout 28, "
        "undetected 37, type-unsupported 3, confirmed-timeout 1; engines 71 "
        "(analysis 2026-08-23T08:03:36Z; get_file_report, ev_0018)"
    )
    assert not _FRACTION.search(cell)
    assert "total" not in cell


def test_a_total_the_answer_gave_is_printed_under_its_name_and_a_sum_is_not() -> None:
    # A declared total with no counts object: the answer's own figure.
    declared = _answer(malicious=3, total=60, engines=None, stats={})
    assert _reputation_line(_report(declared)).startswith(
        "HashRep, counts in the lookup's record: malicious 3; total 60 ("
    )
    # A total that is the sum of the members: the members are printed, the sum is not.
    summed = _answer(malicious=4, total=14, engines=None, stats={"malicious": 4, "clean": 10})
    cell = _reputation_line(_report(summed))
    assert cell.startswith("HashRep, counts in the lookup's record: malicious 4, clean 10 (")
    assert "14" not in cell


def test_every_figure_the_cell_printed_before_is_still_printed() -> None:
    # Before: "<malicious> of <engines, else total> engines flag it as malicious".
    for answer in (
        _answer(),
        _answer(malicious=58, stats={**STATS, "malicious": 58}, engines=75),
        _answer(malicious=3, total=60, engines=None, stats={}),
        _answer(malicious=1, total=70, engines=None, stats={}),
        _answer(malicious=0, total=0, engines=0, stats={"malicious": 0, "harmless": 0}),
    ):
        cell = _reputation_line(_report(answer))
        engines = answer.engine_count()
        assert f"malicious {answer.malicious}" in cell
        if answer.engines is not None:
            assert f"engines {engines}" in cell
        elif engines != sum(answer.stats.values()) or not answer.stats:
            assert f"total {engines}" in cell
        assert not _FRACTION.search(cell)
        assert "()" not in cell


def test_a_member_s_name_is_the_answer_s_text_and_writes_no_markdown() -> None:
    answer = _answer(stats={"malicious": 0, "*bad* [x](#y) <u>z</u>": 5})
    cell = _reputation_line(_report(answer))
    assert '"\\*bad\\* \\[x\\](#y) \\<u\\>z\\</u\\>" 5' in cell


def test_a_flagged_count_with_no_engine_count_and_a_stored_report_read_as_before() -> None:
    flagged = _answer(malicious=4, total=None, engines=None, stats={})
    assert _reputation_line(_report(flagged)) == (
        "HashRep: 4 engines flag it as malicious (get_file_report, ev_0018)"
    )
    stored = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        evidence_index=[EvidenceIndexRow(id="ev_0017", agent="pipeline", tool="get_file_report")],
        sections=[
            EvidenceSection(
                key="tool_get_file_report",
                title="Get file report",
                kind="kv",
                rows=[["engines malicious", "52"], ["engines", "75"]],
                evidence_ids=["ev_0017"],
            )
        ],
    )
    assert _reputation_line(stored) == (
        "Reputation lookup: 52 of 75 engines flag it as malicious (get_file_report, ev_0017)"
    )


def test_the_helper_says_a_missing_flagged_count_and_nothing_for_an_empty_record() -> None:
    assert counts_line(ReputationRecord(service="S", engines=70)) == (
        "S, counts in the lookup's record: malicious not counted; engines 70"
    )
    assert counts_line(ReputationRecord(service="S", summary="not known")) == ""
    # ``suspicious`` beside a counts object that holds no member of that name.
    record = ReputationRecord(service="S", malicious=1, suspicious=2, stats={"bad": 1, "x": 0})
    assert counts_line(record) == (
        "S, counts in the lookup's record: malicious 1, bad 1, suspicious 2"
    )


def test_two_different_records_never_print_the_same_cell() -> None:
    forged = ReputationRecord(service="S", malicious=1, stats={"harmless 3; engines": 75})
    held = ReputationRecord(service="S", malicious=1, engines=75, stats={"harmless": 3})
    assert counts_line(forged) == (
        'S, counts in the lookup\'s record: malicious 1, "harmless 3; engines" 75'
    )
    assert (
        counts_line(held) == "S, counts in the lookup's record: malicious 1, harmless 3; engines 75"
    )
    assert counts_line(ReputationRecord(service="S", malicious=1, stats={"x, malicious": 99})) == (
        'S, counts in the lookup\'s record: malicious 1, "x, malicious" 99'
    )


def test_a_member_named_like_a_label_of_the_line_is_written_as_the_answer_s_key() -> None:
    said = "S, counts in the lookup's record: "
    engines = ReputationRecord(service="S", malicious=1, engines=75, stats={"engines": 70})
    assert counts_line(engines) == said + 'malicious 1, "engines" 70; engines 75'
    total = ReputationRecord(service="S", malicious=1, total=12, stats={"total": 10})
    assert counts_line(total) == said + 'malicious 1, "total" 10; total 12'
    # A member of the flagged or the suspicious name with no field beside it.
    unread = ReputationRecord(service="S", engines=4, stats={"malicious": 3, "suspicious": 1})
    assert counts_line(unread) == (said + '"malicious" 3, "suspicious" 1; engines 4')


# Field and member of the flagged and the suspicious name: absent, equal, different.
# (field name, field value, member value, the line after the service's name)
FIELD_AND_MEMBER: list[tuple[str, int | None, int, str]] = [
    ("malicious", None, 0, '"malicious" 0, harmless 5; engines 70'),
    ("malicious", None, 3, '"malicious" 3, harmless 5; engines 70'),
    ("malicious", 3, 3, "malicious 3, harmless 5; engines 70"),
    ("malicious", 0, 0, "malicious 0, harmless 5; engines 70"),
    ("malicious", 4, 3, 'malicious 4, "malicious" 3, harmless 5; engines 70'),
    ("malicious", 4, 0, 'malicious 4, "malicious" 0, harmless 5; engines 70'),
    ("suspicious", None, 0, 'malicious 1, "suspicious" 0, harmless 5; engines 70'),
    ("suspicious", None, 2, 'malicious 1, "suspicious" 2, harmless 5; engines 70'),
    ("suspicious", 2, 2, "malicious 1, suspicious 2, harmless 5; engines 70"),
    ("suspicious", 0, 0, "malicious 1, harmless 5; engines 70"),
    ("suspicious", 4, 2, 'malicious 1, "suspicious" 2, harmless 5, suspicious 4; engines 70'),
    ("suspicious", 0, 2, 'malicious 1, "suspicious" 2, harmless 5, suspicious 0; engines 70'),
]


@pytest.mark.parametrize(("name", "field", "member", "line"), FIELD_AND_MEMBER)
def test_a_flagged_or_suspicious_member_is_printed_unless_it_equals_a_field_present(
    name: str, field: int | None, member: int, line: str
) -> None:
    fields: dict[str, Any] = {"malicious": 1} if name == "suspicious" else {}
    record = ReputationRecord(
        service="S", engines=70, stats={name: member, "harmless": 5}, **{**fields, name: field}
    )
    said = counts_line(record)
    assert said == f"S, counts in the lookup's record: {line}"
    # A count the record holds is never beside words saying it holds none.
    assert "not counted" not in said


def test_a_member_named_like_a_digit_string_or_a_label_is_written_by_the_same_rule() -> None:
    said = "S, counts in the lookup's record: malicious 1, "
    for name, shown in (("10", "10"), ("total", '"total"'), ("suspicious", '"suspicious"')):
        record = ReputationRecord(service="S", malicious=1, stats={name: 2})
        assert counts_line(record) == f"{said}{shown} 2"


def test_a_member_name_that_is_no_plain_token_is_quoted() -> None:
    for name, shown in (
        ("a,b", '"a,b"'),
        ("a;b", '"a;b"'),
        ('a"b', '"a\\"b"'),
        ("a\\b", '"a\\\\b"'),
        ("a\nb", '"a\\nb"'),
        ("a b", '"a b"'),
        ("", '""'),
        ('"harmless"', '"\\"harmless\\""'),
    ):
        record = ReputationRecord(service="S", malicious=1, stats={name: 2})
        assert counts_line(record) == f"S, counts in the lookup's record: malicious 1, {shown} 2"
        cell = _reputation_line(_report(_answer(malicious=1, engines=None, stats={name: 2})))
        assert "\n" not in cell
    # Plain tokens are written as the answer wrote them.
    plain = ReputationRecord(service="S", malicious=0, stats={"type-unsupported": 3, "a.b_1": 1})
    assert counts_line(plain).endswith("malicious 0, type-unsupported 3, a.b_1 1")


def test_a_flagged_or_suspicious_member_is_left_out_only_where_it_equals_the_field() -> None:
    said = "S, counts in the lookup's record: "
    differ = ReputationRecord(
        service="S", malicious=5, total=10, stats={"malicious": 3, "harmless": 7}
    )
    assert counts_line(differ) == said + 'malicious 5, "malicious" 3, harmless 7'
    zero = ReputationRecord(service="S", malicious=9, stats={"malicious": 0, "harmless": 2})
    assert counts_line(zero) == said + 'malicious 9, "malicious" 0, harmless 2'
    suspicious = ReputationRecord(
        service="S",
        malicious=1,
        suspicious=4,
        stats={"malicious": 1, "suspicious": 2, "harmless": 3},
    )
    assert counts_line(suspicious) == said + 'malicious 1, "suspicious" 2, harmless 3, suspicious 4'
    unflagged = ReputationRecord(
        service="S", malicious=1, suspicious=0, stats={"malicious": 1, "suspicious": 2}
    )
    assert counts_line(unflagged) == said + 'malicious 1, "suspicious" 2, suspicious 0'
    # Equal: the one figure once, under the field's name.
    same = ReputationRecord(
        service="S", malicious=1, suspicious=2, stats={"malicious": 1, "suspicious": 2, "x": 3}
    )
    assert counts_line(same) == said + "malicious 1, suspicious 2, x 3"


# ---------------------------------------------------------------------------
# The evidence bundle's rows: the whole tally
# ---------------------------------------------------------------------------

# A reputation server declared only as data, for the entries that recorded a
# source; an entry that recorded none is read through the declaration shipped
# for its tool's name, which is what the source-less cases test.
DECLARED: dict[str, Any] = {
    "command": "tally-server",
    "enabled": True,
    "tool_facts": {
        "get_file_report": {
            "kind": "reputation",
            "arguments": {"hash": "hash"},
            "display_name": "HashRep",
            "reputation": {
                "stats": "/data/attributes/last_analysis_stats",
                "malicious": "/data/attributes/last_analysis_stats/malicious",
                "suspicious": "/data/attributes/last_analysis_stats/suspicious",
                "engines": "/coverage/engines",
            },
        }
    },
}


@pytest.fixture(autouse=True)
def _declared() -> Iterator[None]:
    """Install a settings object declaring the server, and put the process's back."""
    previous = get_settings()
    install_settings(Settings.model_validate({"mcp": {"servers": {"hashrep": DECLARED}}}))
    declared_reading.forget()
    yield
    install_settings(previous)
    declared_reading.forget()


def _lookup(seq: int, stats: dict[str, int], engines: int = 71, *, sourced: bool = True) -> Any:
    payload = {
        "data": {"attributes": {"last_analysis_stats": stats}},
        "coverage": {"engines": engines},
    }
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent="pipeline",
        tool="get_file_report",
        args={},
        server="hashrep" if sourced else None,
        source="mcp:hashrep" if sourced else None,
        output=json.dumps(payload),
    )


def _rows(*entries: Any) -> list[list[str]]:
    (section,) = [s for s in build_sections(list(entries)) if s.key == "tool_get_file_report"]
    return [list(row) for row in section.rows if row[0] not in {"data", "coverage"}]


def test_the_bundle_rows_hold_every_member_under_its_own_name() -> None:
    assert _rows(_lookup(1, STATS)) == [
        ["engines malicious", "0"],
        ["engines suspicious", "0"],
        ["engines undetected", "37"],
        ["engines harmless", "0"],
        ["failure", "2"],
        ["timeout", "28"],
        ["type-unsupported", "3"],
        ["confirmed-timeout", "1"],
        ["engines", "71"],
    ]


def test_an_entry_that_recorded_no_source_keeps_the_rows_it_always_had() -> None:
    assert _rows(_lookup(1, STATS, sourced=False)) == [
        ["engines malicious", "0"],
        ["engines suspicious", "0"],
        ["engines undetected", "37"],
        ["engines harmless", "0"],
        ["engines", "71"],
    ]


def test_lookups_stating_one_tally_are_one_set_of_rows() -> None:
    assert _rows(_lookup(1, STATS), _lookup(2, STATS)) == _rows(_lookup(1, STATS))


def test_lookups_stating_different_tallies_name_their_entries_on_each_row() -> None:
    other = {**STATS, "malicious": 2, "undetected": 35}
    rows = _rows(_lookup(1, STATS), _lookup(2, STATS), _lookup(3, other))
    assert ["engines malicious (ev_0001, ev_0002)", "0"] in rows
    assert ["engines malicious (ev_0003)", "2"] in rows
    assert ["timeout (ev_0001, ev_0002)", "28"] in rows
    assert ["timeout (ev_0003)", "28"] in rows
    assert ["engines (ev_0001, ev_0002)", "71"] in rows
    assert ["engines (ev_0003)", "71"] in rows
    # No count row is left unnamed once the tallies differ.
    named = re.compile(r"\((ev_\d{4}(, )?)+\)$")
    assert all(named.search(label) for label, _value in rows)


def test_a_later_entry_stating_an_earlier_tally_joins_its_rows() -> None:
    other = {**STATS, "malicious": 2, "undetected": 35}
    rows = _rows(_lookup(1, STATS), _lookup(2, other), _lookup(3, STATS))
    assert ["engines malicious (ev_0001, ev_0003)", "0"] in rows
    assert ["engines malicious (ev_0002)", "2"] in rows
    assert ["engines (ev_0001, ev_0003)", "71"] in rows
    assert ["engines (ev_0002)", "71"] in rows
    assert len(rows) == 18


def test_a_member_named_like_a_row_label_or_no_plain_token_is_written_as_the_answer_s_key() -> None:
    stats = {
        "malicious": 1,
        "engines": 70,
        "engines malicious": 9,
        "harmless (ev_0002)": 5,
        "a\nb": 4,
    }
    assert _rows(_lookup(1, stats, engines=75)) == [
        ["engines malicious", "1"],
        ['"engines"', "70"],
        ['"engines malicious"', "9"],
        ['"harmless (ev_0002)"', "5"],
        ['"a\\nb"', "4"],
        ["engines", "75"],
    ]


def _together(rows: list[list[str]], labels: list[str]) -> None:
    """The rows under ``labels`` stand next to each other, in that order."""
    shown = [label for label, _value in rows]
    start = shown.index(labels[0])
    assert shown[start : start + len(labels)] == labels


def test_each_entry_s_rows_come_out_together_beside_an_entry_that_recorded_no_source() -> None:
    other = {**STATS, "malicious": 2, "undetected": 35}
    plain = [
        "engines malicious",
        "engines suspicious",
        "engines undetected",
        "engines harmless",
        "engines",
    ]
    tally = [
        "engines malicious",
        "engines suspicious",
        "engines undetected",
        "engines harmless",
        "failure",
        "timeout",
        "type-unsupported",
        "confirmed-timeout",
        "engines",
    ]
    for entries in (
        (_lookup(1, STATS, sourced=False), _lookup(2, STATS), _lookup(3, other)),
        (_lookup(2, STATS), _lookup(1, STATS, sourced=False), _lookup(3, other)),
        (_lookup(2, STATS), _lookup(3, other), _lookup(1, STATS, sourced=False)),
    ):
        rows = _rows(*entries)
        assert len(rows) == len(plain) + 2 * len(tally)
        _together(rows, plain)
        _together(rows, [f"{label} (ev_0002)" for label in tally])
        _together(rows, [f"{label} (ev_0003)" for label in tally])
    # One sourced entry beside one that recorded none: each says whose rows they are.
    rows = _rows(_lookup(1, STATS, sourced=False), _lookup(2, STATS))
    _together(rows, plain)
    _together(rows, [f"{label} (ev_0002)" for label in tally])
