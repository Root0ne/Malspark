"""The pack's reputation line names each count it prints, and states no fraction.

The line a model reads is written by the one wording of a record's counts
(``core.reputation.counts_line``): every member of the answer's counts object,
zeros too, with the flagged count and the engine count first, so the run-state
block's cut loses members and never those two. A record written now stores
the keys of the answer each count was read under (``names``) and how many
members of the counts object were not read (``unread``); its line says each
count under those keys, and a dropped or blanked answer text changes nothing it
prints. A record that stores no keys is said under the record's own names, as
the record's. A sum is never printed; a total the answer gave under a key is,
also where it equals the members' sum. An answer whose counts nothing can state
keeps the pack's line as it was, its own text; an empty parenthesis is never
printed.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from malspark.core.reputation import (
    LEDGER_ONLY,
    ReputationRecord,
    counts_line,
    record_at_write,
    reputation_of,
)
from malspark.pipeline.run_state import _LINE_CHARS, render_run_state
from malspark.pipeline.triage_pack import PIPELINE, render_pack
from malspark.reporting.builder import _reputation_answers
from malspark.reporting.models import (
    EvidenceIndexRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from malspark.reporting.renderers.markdown import _reputation_line
from malspark.schemas.evidence import LedgerEntry, build_entry, format_entry_id

SHA = "d" * 64
_FRACTION = re.compile(r"\d+ of \d+|\d+/\d+")

# A lookup read by the answer's shape, and one read through declared paths.
SHAPE: dict[str, Any] = {
    "v": 1,
    "kind": "reputation",
    "reader": "reputation_shape",
    "arguments": {"hash": "hash"},
    "reputation": {"service": "HashRep"},
}


def _declared(**paths: Any) -> dict[str, Any]:
    return {
        "v": 1,
        "kind": "reputation",
        "arguments": {"hash": "hash"},
        "display_name": "AnyIntel",
        "reputation": paths,
    }


# The answer's own tally and engine count, in the shape a stored lookup gave.
TALLY = {
    "malicious": 0,
    "suspicious": 0,
    "undetected": 37,
    "harmless": 0,
    "timeout": 28,
    "confirmed-timeout": 1,
    "failure": 2,
    "type-unsupported": 3,
}
SHAPED = {"data": {"last_analysis_stats": TALLY}, "coverage": {"engines": 71}}


def _written(facts: dict[str, Any], answer: Any, *, tool: str = "lookup") -> LedgerEntry:
    """A lookup's entry as the writer stores it: its facts and the record read at write."""
    output = answer if isinstance(answer, str) else json.dumps(answer)
    entry = build_entry(
        entry_id=format_entry_id(1),
        seq=1,
        agent=PIPELINE,
        tool=tool,
        args={"hash": SHA},
        server="anyintel",
        output=output,
        stage="triage_pack",
    )
    record = record_at_write(facts, ok=True, output=output, structured=entry.structured)
    return entry.model_copy(update={"facts": facts, "reputation": record})


def _dropped(entry: LedgerEntry) -> LedgerEntry:
    """The entry after a byte budget blanked its answer, as ``apply_budget`` leaves it."""
    return entry.model_copy(update={"output": "", "structured": None, "truncated": True})


def _line(entry: LedgerEntry) -> str:
    return render_pack([entry], 0)


def _stored(record: dict[str, Any], answer: Any = SHAPED) -> LedgerEntry:
    """An entry written before records stored keys: its record holds values only."""
    entry = _written(SHAPE, answer)
    return entry.model_copy(update={"reputation": record})


# ---------------------------------------------------------------------------
# A record that stores no keys: the record's own names, said to be the record's
# ---------------------------------------------------------------------------

STORED = {
    "v": 1,
    "service": "HashRep",
    "malicious": 0,
    "suspicious": 0,
    "total": 71,
    "engines": 71,
    "stats": {
        "failure": 2,
        "timeout": 28,
        "harmless": 0,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 37,
        "type-unsupported": 3,
        "confirmed-timeout": 1,
    },
}
STORED_LINE = (
    "[ev_0001] reputation: HashRep, counts in the lookup's record: malicious 0; engines 71; "
    "failure 2, timeout 28, harmless 0, suspicious 0, undetected 37, type-unsupported 3, "
    "confirmed-timeout 1"
)


def test_a_record_storing_no_keys_is_said_under_its_own_names_with_every_member() -> None:
    entry = _stored(STORED)

    assert _line(entry) == STORED_LINE
    assert _line(_dropped(entry)) == STORED_LINE
    assert not _FRACTION.search(STORED_LINE)


def test_a_total_that_is_no_sum_is_kept_in_a_record_storing_no_keys() -> None:
    record = {"v": 1, "service": "HashRep", "malicious": 3, "total": 60}
    assert _line(_dropped(_stored(record))) == (
        "[ev_0001] reputation: HashRep, counts in the lookup's record: malicious 3; total 60"
    )


# ---------------------------------------------------------------------------
# A record written now: each count under the keys it was read under
# ---------------------------------------------------------------------------

SHAPED_LINE = (
    "[ev_0001] reputation: HashRep, read from the lookup's answer: "
    "data.last_analysis_stats.malicious 0; coverage.engines 71; "
    "counts read from data.last_analysis_stats: suspicious 0, undetected 37, harmless 0, "
    "timeout 28, confirmed-timeout 1, failure 2, type-unsupported 3"
)


def test_a_record_written_now_stores_the_keys_its_counts_were_read_under() -> None:
    entry = _written(SHAPE, SHAPED)

    assert entry.reputation is not None
    assert entry.reputation["names"] == {
        "engines": "coverage.engines",
        "stats": "data.last_analysis_stats",
        "malicious": "data.last_analysis_stats.malicious",
        "suspicious": "data.last_analysis_stats.suspicious",
    }
    assert entry.reputation["unread"] == 0
    assert _line(entry) == SHAPED_LINE


def test_no_figure_is_lost_when_a_budget_blanks_the_answer_text() -> None:
    entry = _written(SHAPE, SHAPED)

    assert _line(_dropped(entry)) == SHAPED_LINE


def test_the_values_a_decision_reads_are_the_ones_read_before_keys_were_stored() -> None:
    record = reputation_of(_written(SHAPE, SHAPED))

    assert record is not None
    assert record.model_dump(exclude=set(LEDGER_ONLY), exclude_defaults=True) == {
        "service": "HashRep",
        "malicious": 0,
        "suspicious": 0,
        "total": 71,
        "engines": 71,
        "stats": TALLY,
    }


def test_the_run_state_cut_keeps_the_flagged_and_the_engine_count() -> None:
    tally = {"malicious": 3, **{f"category-{n}": n for n in range(40)}}
    entry = _written(SHAPE, {"data": {"stats": tally}, "coverage": {"engines": 75}})

    block = render_run_state({"evidence_ledger": [entry.model_dump()]})
    line = next(row for row in block.splitlines() if "reputation:" in row)

    assert len(line) == _LINE_CHARS
    assert line.endswith("…")
    assert line.startswith(
        "[ev_0001] reputation: HashRep, read from the lookup's answer: data.stats.malicious 3; "
        "coverage.engines 75; counts read from data.stats: category-0 0, category-1 1, "
    )


# Declared positives and total, budget-dropped: the pack printed "3 malicious ()".
DECLARED_TOTAL = _declared(malicious="/positives", total="/total")


def test_a_declared_flagged_count_and_total_are_said_under_their_keys_with_or_without_text() -> (
    None
):
    entry = _written(DECLARED_TOTAL, {"positives": 3, "total": 60})
    line = "[ev_0001] reputation: AnyIntel, read from the lookup's answer: positives 3; total 60"

    assert _line(entry) == line
    assert _line(_dropped(entry)) == line
    assert "()" not in _line(_dropped(entry))


def test_a_declared_total_alone_says_no_flagged_count_was_read() -> None:
    entry = _written(_declared(total="/total"), {"total": 70})

    assert _line(entry) == (
        "[ev_0001] reputation: AnyIntel, read from the lookup's answer: "
        "no flagged count read; total 70"
    )


def test_a_declared_total_equal_to_the_members_sum_is_printed() -> None:
    facts = _declared(stats="/stats", malicious="/stats/malicious", total="/total")
    entry = _written(facts, {"stats": {"malicious": 3, "harmless": 7}, "total": 10})

    assert _line(entry) == (
        "[ev_0001] reputation: AnyIntel, read from the lookup's answer: stats.malicious 3; "
        "total 10; counts read from stats: harmless 7"
    )


def test_a_summed_total_is_never_printed() -> None:
    facts = _declared(stats="/stats", malicious="/stats/malicious")
    entry = _written(facts, {"stats": {"malicious": 3, "harmless": 7}})

    line = _line(entry)
    assert line == (
        "[ev_0001] reputation: AnyIntel, read from the lookup's answer: stats.malicious 3; "
        "counts read from stats: harmless 7"
    )
    assert "10" not in line


def test_a_count_whose_key_holds_no_whole_number_is_said_to_be_one() -> None:
    entry = _written(_declared(malicious="/bad", total="/total"), {"bad": "4", "total": 60})

    assert _line(entry) == (
        "[ev_0001] reputation: AnyIntel, read from the lookup's answer: "
        "bad not read as a whole number; total 60"
    )


@pytest.mark.parametrize(
    ("members", "said"),
    [
        ({"undetected": 60.0, "flag": True}, "2 members of stats not read as whole numbers"),
        ({"undetected": 2.5}, "1 member of stats not read as a whole number"),
    ],
)
def test_the_members_not_read_are_counted(members: dict[str, Any], said: str) -> None:
    tally = {"malicious": 3, "harmless": 5, "timeout": 1, **members}
    entry = _written(SHAPE, {"stats": tally})

    assert _line(entry) == (
        "[ev_0001] reputation: HashRep, read from the lookup's answer: stats.malicious 3; "
        f"counts read from stats: harmless 5, timeout 1; {said}"
    )


@pytest.mark.parametrize(
    ("facts", "answer", "said"),
    [
        # Own keys, an engines figure under a key holding the word.
        (
            SHAPE,
            {
                "verdicts": {"positives": 3, "negatives": 40, "errors": 5, "unscanned": 2},
                "engines_version": 3,
            },
            "verdicts.positives 3; engines_version 3; "
            "counts read from verdicts: negatives 40, errors 5, unscanned 2",
        ),
        # Two tallies: the one read is named.
        (
            SHAPE,
            {
                "community": {"malicious": 9, "harmless": 1, "suspicious": 0},
                "scan": {"malicious": 2, "undetected": 10, "timeout": 30},
            },
            "community.malicious 9; counts read from community: harmless 1, suspicious 0",
        ),
        # A member named total inside the tally is the answer's member.
        (
            SHAPE,
            {"data": {"malicious": 1, "undetected": 50, "harmless": 2, "total": 70}},
            "data.malicious 1; counts read from data: undetected 50, harmless 2, total 70",
        ),
        (
            SHAPE,
            {"stats": {"malicious": 0, "undetected": 0, "harmless": 0}, "engines_answered": 0},
            "stats.malicious 0; engines_answered 0; "
            "counts read from stats: undetected 0, harmless 0",
        ),
        # Declared counts object with no flagged path.
        (
            _declared(stats="/stats"),
            {"stats": {"detected": 3, "clean": 40}},
            "no flagged count read; counts read from stats: detected 3, clean 40",
        ),
        # Declared counts object and engines.
        (
            _declared(stats="/last", malicious="/last/malicious", engines="/engines"),
            {"last": {"malicious": 0, "undetected": 37, "timeout": 28}, "engines": 71},
            "last.malicious 0; engines 71; counts read from last: undetected 37, timeout 28",
        ),
        # A path through a wildcard names the keys after it.
        (
            _declared(stats="/**7/tally", malicious="/**7/tally/malicious"),
            {"a": [{"tally": {"malicious": 5, "harmless": 1}}]},
            "tally.malicious 5; counts read from tally: harmless 1",
        ),
    ],
)
def test_each_count_is_said_under_the_keys_it_was_read_under(
    facts: dict[str, Any], answer: Any, said: str
) -> None:
    entry = _written(facts, answer)
    service = "HashRep" if facts is SHAPE else "AnyIntel"
    line = f"[ev_0001] reputation: {service}, read from the lookup's answer: {said}"

    assert _line(entry) == line
    assert _line(_dropped(entry)) == line
    assert not _FRACTION.search(line)


def test_a_key_that_is_no_plain_token_is_quoted_and_forges_no_count_or_line() -> None:
    answer = {"t.x": {"malicious": 1, "harmless 3; engines": 75, "a\n[ev_0009] b": 2}}
    entry = _written(SHAPE, answer)

    # The member whose key holds the word "engines" is the shape's engine count,
    # said under its keys; an id in a key is written out as any answer text is.
    assert _line(entry) == (
        '[ev_0001] reputation: HashRep, read from the lookup\'s answer: "t.x".malicious 1; '
        '"t.x"."harmless 3; engines" 75; '
        'counts read from "t.x": "harmless 3; engines" 75, "a\\n[ev\\x5f0009] b" 2'
    )


# ---------------------------------------------------------------------------
# What stays as it was
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "answer",
    [
        {"scan_results": {"detected": 3, "clean": 40, "error": 2}},
        {"stats": {"malicious": "3", "harmless": "40", "undetected": "2"}},
        {"verdict": "malicious"},
        {"sonuc": {"zararli": 3, "temiz": 40, "hata": 2}},
        {"positives": 3, "total": 60},
    ],
)
def test_an_answer_whose_counts_nothing_states_keeps_its_own_text(answer: Any) -> None:
    entry = _written(SHAPE, answer)

    assert _line(entry) == f"[ev_0001] reputation: HashRep: {json.dumps(answer)}"


def test_a_flagged_count_alone_keeps_its_line_and_prints_no_empty_parenthesis() -> None:
    answer = {"bad": 4, "note": "seen"}
    entry = _written(_declared(malicious="/bad"), answer)

    assert _line(entry) == f"[ev_0001] reputation: AnyIntel 4 malicious ({json.dumps(answer)})"
    assert _line(_dropped(entry)) == (
        "[ev_0001] reputation: AnyIntel, read from the lookup's answer: bad 4"
    )


def test_counts_read_from_prose_keep_their_line_and_are_the_record_s_when_the_text_is_gone() -> (
    None
):
    facts = _declared(text_patterns=[r"(?P<malicious>\d+)/(?P<total>\d+) engines"])
    entry = _written(facts, "flagged by 3/60 engines")

    assert entry.reputation is not None and "names" not in entry.reputation
    assert _line(entry) == "[ev_0001] reputation: AnyIntel 3 malicious (flagged by 3/60 engines)"
    assert _line(_dropped(entry)) == (
        "[ev_0001] reputation: AnyIntel, counts in the lookup's record: malicious 3; total 60"
    )


def test_the_report_carries_no_key_and_its_cell_is_the_record_s() -> None:
    # A tool the platform reads as a reputation lookup, so the header cell cites it.
    entry = _written(SHAPE, SHAPED, tool="get_file_report")
    answers = _reputation_answers([entry])
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA)),
        evidence_index=[EvidenceIndexRow(id="ev_0001", agent="pipeline", tool="get_file_report")],
        reputation=answers,
    )

    dumped = json.loads(report.model_dump_json())["reputation"][0]
    assert not set(LEDGER_ONLY) & set(dumped)
    assert "names" not in json.dumps(MalwareReport.model_json_schema()["$defs"]["ReputationAnswer"])
    assert _reputation_line(report) == _reputation_line(
        MalwareReport.model_validate_json(report.model_dump_json())
    )
    assert _reputation_line(report) == (
        "HashRep, counts in the lookup's record: malicious 0, undetected 37, timeout 28, "
        "confirmed-timeout 1, failure 2, type-unsupported 3; engines 71 (get_file_report, ev_0001)"
    )


def test_the_header_cell_s_wording_is_unchanged_by_stored_keys() -> None:
    record = ReputationRecord.model_validate(_written(SHAPE, SHAPED).reputation)
    without = record.model_copy(update={"names": {}, "unread": None})

    assert (
        counts_line(record)
        == counts_line(without)
        == (
            "HashRep, counts in the lookup's record: malicious 0, undetected 37, timeout 28, "
            "confirmed-timeout 1, failure 2, type-unsupported 3; engines 71"
        )
    )


def test_the_labels_stand_before_the_members_so_the_cut_loses_members_first() -> None:
    tally = {"malicious": 2, **{f"category-{n}": 0 for n in range(20)}}
    answer = {"data": {"stats": tally, "detections": ["Trojan.A", "Trojan.A"]}}
    entry = _written(SHAPE, answer)

    assert _line(entry).startswith(
        "[ev_0001] reputation: HashRep, read from the lookup's answer: data.stats.malicious 2; "
        "2 detection labels, 1 distinct (engines per label, most first): Trojan.A ×2; "
        "counts read from data.stats: category-0 0, "
    )
    block = render_run_state({"evidence_ledger": [entry.model_dump()]})
    line = next(row for row in block.splitlines() if "reputation:" in row)
    assert "Trojan.A ×2; counts read from data.stats: category-0 0" in line
    assert line.endswith("…") and "category-19" not in line
