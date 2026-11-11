"""The readers of model-written text run in time linear in the text, on hostile lines too.

A model answer is untrusted and can be arbitrarily long. Each reader below is
given a line of words with no comma, semicolon or full stop and many
technique-id tokens of 20 or 40 KB, read as many times as it takes to cost at
least 10 ms of CPU time, and four times as much of the same; the long one may
cost less than ``TIME_RATIO_LIMIT`` times the short one, the two timed in turn
on their best CPU times (``tests.linear_cost.assert_ratio``), so a loaded
machine does not move it.
Nothing is cut to make it pass.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from malspark.agents.base_agent import (
    _EVIDENCE_ENDS_INLINE_RE,
    _PARTIAL_ID_AT_END_RE,
    read_technique_line,
)
from malspark.agents.claim_headings import CLAIM_HEAD_RE, claim_blocks
from malspark.agents.repeat_watch import ClaimRepeatReader
from malspark.pipeline.claim_drops import claim_substance
from malspark.pipeline.debate_facts import (
    claim_references_of,
    fact_atoms,
    ledger_count_facts,
    ledger_stated,
    read_claim_references,
    read_marks,
)
from malspark.pipeline.exit_branches import exit_branches, listing_exits, uncovered_exits
from malspark.pipeline.limit_rulings import REASON_LIMIT, clean_quote, read_rulings
from malspark.pipeline.validation import (
    EntryTexts,
    absence_holders_note,
    ledger_absence_contradictions,
)
from malspark.reporting.absence_answers import (
    FailureCounts,
    count_disagrees,
    denied_subject,
    denies_an_observation,
    failure_counts,
    kept_absence,
    negated_clauses,
    quote_stands,
    reading_denied_in,
)
from malspark.reporting.section_agreement import (
    _candidates,
    _reports_a_claim,
    _said_unread,
    _unread_addresses,
    closing_negations,
    unread_listed_sentences,
    whole_code_absences,
)
from malspark.schemas.evidence import build_entry
from tests.linear_cost import TIME_RATIO_LIMIT, assert_ratio, cpu_seconds, repeated

UNIT = "T1234 Native words T1106 more is not read 0x1400 which that 12 hits Web Protocols "
# The short line's least size and CPU time, and the largest size it grows to.
# The long line is four times the short one, so at most 160 KB: most readers
# build a text of their own from the line, and past about 300 KB the copies
# and the walk leave a small processor cache (claim blocks reads 7.5 ns a
# character up to 160 KB and 11 ns at 640 KB with the cache shared), which a
# ratio would read as the reader's growth. A shorter line is read more times.
SMALLEST = 20_000
LEAST_SECONDS = 0.01
LARGEST = 40_000


_COUNTS = FailureCounts(failed=2, redone=1, by_name={"decompil": (1, 1)})


def _hostile(size: int) -> str:
    return (UNIT * (size // len(UNIT) + 1))[:size]


def _scales_linearly(read: Callable[[str], object]) -> None:
    def reading(size: int, times: int = 1) -> Callable[[], object]:
        text = _hostile(size)
        return lambda: [read(text) for _ in range(times)]

    # The short size is the least that costs LEAST_SECONDS; only the ratio is asserted.
    size = SMALLEST
    took = cpu_seconds(reading(size), repeats=5)
    while took < LEAST_SECONDS and size < LARGEST:
        size *= 2
        took = cpu_seconds(reading(size), repeats=5)
    # A reader that stops early, or reads even the largest line in C under
    # LEAST_SECONDS, reads it this many times on both sides, so the short run
    # is long enough to read a ratio from. A count estimated from a reading of
    # a few clock ticks can fall short, so it is doubled until the short run,
    # read by the measure's own clock, takes LEAST_SECONDS. A reading of no
    # tick at all (Windows' thread clock moves in 15.6 ms steps) estimates
    # nothing, and the doubling starts from two.
    if took >= LEAST_SECONDS:
        times = 1
    elif took > 0:
        times = math.ceil(1.5 * LEAST_SECONDS / took)
    else:
        times = 2
    while cpu_seconds(reading(size, times), repeats=3) < LEAST_SECONDS:
        times *= 2
    assert_ratio(
        reading(size, times),
        reading(size * 4, times),
        TIME_RATIO_LIMIT,
        what=f"{size * 4} characters",
    )


def _built(make: Callable[[str], str], read: Callable[[str], object]) -> Callable[[str], object]:
    """``read`` of the text ``make`` builds from the hostile line, built once for each line.

    For a reader whose own work does not grow with its text (it reads a bounded
    part of it): built in the timed call, the building is the whole cost
    measured, and a text four times as long can cross the allocator's
    large-block threshold, past which each one takes fresh pages the system
    maps and zeroes (building 40 KB took 1.5 us and 160 KB 57 us), which the
    ratio would read as the reader's growth.
    """
    built: dict[int, str] = {}

    def read_built(text: str) -> object:
        if len(text) not in built:
            built[len(text)] = make(text)
        return read(built[len(text)])

    return read_built


ENTRIES = EntryTexts.from_ledger(
    [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="a",
            server="a",
            tool="decompile_function",
            args={"address": "0x1400"},
            output="undefined8 FUN_00001400(void)\n{ FUN_00001800(); }",
        )
    ]
)
LEDGER = [{"id": "ev_0001", "tool": "t", "structured": {"matches": [], "total": 12}}]
# A fact about a routine an entry lists, as the agreement round reads it.
LISTED = [SimpleNamespace(addresses=frozenset({0x1400}), id="listed.1")]


def _hostile_listing(text: str) -> str:
    """A listing as long as ``text``: deep nesting, a long else-if chain, a wide condition.

    A tool's listing is not model text, but the exit reader is read on every
    answer checked. The wide condition tests every variable the statements
    before it set by a call, and every exit under it hands back its own value.
    """
    k = max(1, len(text) // 4 // 60)
    flat = "".join(f"  v{i} = FUN_{0x402000 + i:x}(v{i + 1});\n" for i in range(k))
    deep = (
        "".join(
            f"if (v{i} == 0x20) {{\n  v{i} = FUN_{0x401000 + i:x}(v{i + 1});\n  r = 0x30;\n"
            for i in range(k)
        )
        + "}\n" * k
    )
    chain = "".join(f"if (w == {12 + i}) r = -1;\nelse " for i in range(k)) + "r = 0;\n"
    wide = (
        "if ("
        + " || ".join(f"v{i}" for i in range(k))
        + ") {\n"
        + "".join(f"  r = {0x40 + i};\n" for i in range(k))
        + "}\n"
    )
    return f"int FUN_401000(int v0)\n{{\n  int r;\n{flat}{deep}{chain}{wide}  return r;\n}}\n"


# The exits a claim's words are read against.
EXITS = exit_branches(
    [
        build_entry(
            entry_id="ev_0002",
            seq=2,
            agent="a",
            server="a",
            tool="decompile_function",
            args={"address": "0x1400"},
            output=(
                "int FUN_00001400(void)\n{\n  int r;\n  r = 0;\n"
                "  if (FUN_00001800() == 0x1c) {\n    r = -1;\n  }\n  return r;\n}"
            ),
        )
    ],
    {},
)


@pytest.mark.parametrize(
    "read",
    [
        pytest.param(read_technique_line, id="technique line"),
        pytest.param(lambda t: read_technique_line("T1106 " + t), id="technique line after an id"),
        pytest.param(lambda t: CLAIM_HEAD_RE.match("CLAIM " + t), id="claim heading"),
        pytest.param(lambda t: CLAIM_HEAD_RE.match("CLAIM" + " " * len(t) + "x"), id="spaces"),
        pytest.param(lambda t: claim_blocks("CLAIM R1: " + t), id="claim blocks"),
        pytest.param(lambda t: ClaimRepeatReader(None).feed("CLAIM R1: " + t), id="streaming"),
        pytest.param(
            lambda t: ledger_absence_contradictions({"body": t}, ENTRIES), id="absence sentences"
        ),
        pytest.param(
            lambda t: ledger_count_facts(["[analysts: A] ev_0001 " + t], {}, LEDGER, ["a"]),
            id="ledger counts",
        ),
        pytest.param(
            lambda t: ledger_stated(
                ["[analysts: A] ev_0001 " + t],
                {},
                LEDGER,
                ["a"],
                ["entry ev_0001 states total = 12."],
            ),
            id="stated lines",
        ),
        pytest.param(
            lambda t: fact_atoms(['For the line "x": ' + "entry ev_1 (" * (len(t) // 12)]),
            id="stated fact parts",
        ),
        pytest.param(
            lambda t: read_technique_line("T1106" + " " * len(t) + "1"),
            id="technique line with a run of spaces",
        ),
        pytest.param(
            lambda t: read_technique_line("T1106" + " - " * (len(t) // 3) + "x"),
            id="technique line with spaced dashes",
        ),
        pytest.param(lambda t: read_technique_line("T1106 (" + t + ")"), id="technique note"),
        pytest.param(
            lambda t: read_technique_line("T1106 (a); " * (len(t) // 10) + "T1106 ("),
            id="technique line of notes left open",
        ),
        pytest.param(
            lambda t: read_technique_line("none" + " " * len(t) + "(T1106 not supported"),
            id="none line with a note left open",
        ),
        pytest.param(
            lambda t: _EVIDENCE_ENDS_INLINE_RE.search(" " * len(t) + "x"),
            id="evidence end after a run of spaces",
        ),
        pytest.param(
            lambda t: _PARTIAL_ID_AT_END_RE.sub("", " " * len(t) + "x"),
            id="partial id after a run of spaces",
        ),
        pytest.param(
            lambda t: claim_substance(
                SimpleNamespace(claims=[SimpleNamespace(claim=t + "a" + "." * len(t))])
            ),
            id="claim substance",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {
                    "body": "The names "
                    + "(" * (len(t) // 2)
                    + "A1)" * (len(t) // 4)
                    + " are not read."
                },
                ENTRIES,
            ),
            id="absence sentence with brackets",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {"body": "is not read, which is not in the ledger. " * (len(t) // 41)}, ENTRIES
            ),
            id="one clause of many statements",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {"body": "no a " * (len(t) // 5) + "is in the evidence."}, ENTRIES
            ),
            id="many subjects of no",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {"body": "The decompile of " + "x " * (len(t) // 2) + "0x1400 was not obtained."},
                ENTRIES,
            ),
            id="a long decompile subject",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {
                    "body": "The body of 0x1400"
                    + ", which a" * (len(t) // 9)
                    + " is not in my rows."
                },
                ENTRIES,
            ),
            id="a subject of many asides",
        ),
        pytest.param(
            lambda t: ledger_absence_contradictions(
                {"body": "the " + "plain " * (len(t) // 6) + "slots 0x1400 remain unresolved."},
                ENTRIES,
            ),
            id="many words describing a kind noun",
        ),
        pytest.param(
            lambda t: absence_holders_note("Slot 0x1400 is unresolved, and " + t, ENTRIES),
            id="a claim's absence note",
        ),
        pytest.param(
            lambda t: ledger_count_facts([" " * len(t) + "x"], {}, LEDGER, ["a"]),
            id="claim numbers after a run of spaces",
        ),
        pytest.param(
            lambda t: ledger_count_facts(["T1106" + " " * len(t) + "1"], {}, LEDGER, ["a"]),
            id="claim numbers between an id and a number",
        ),
        pytest.param(
            lambda t: read_marks(
                ["[analysts: a]" + " [new]" * (len(t) // 6) + " [not blocking: x"]
            ),
            id="many marks after the field and one left open",
        ),
        pytest.param(
            lambda t: read_marks(["[analysts: a] [not blocking: " + "[x] " * (len(t) // 4)]),
            id="a mark after the field whose reason never closes",
        ),
        pytest.param(
            lambda t: claim_references_of(
                "[analysts: a] " + "its claim 3 own " * (len(t) // 16), ["a", "b"], ["a"]
            ),
            id="its claims on a one-analyst line",
        ),
        pytest.param(
            lambda t: read_claim_references(
                ["[analysts: a] " + "its claim 3 own " * (len(t) // 16) + "[blocking: x]"],
                ["a", "b"],
            ),
            id="the merge's reading of its claims",
        ),
        pytest.param(
            lambda t: read_claim_references(
                ["[analysts: a, b] " + "claim 3 " * (len(t) // 8) + "[blocking: x]"], ["a", "b"]
            ),
            id="claim numbers read for no analyst",
        ),
        pytest.param(
            lambda t: unread_listed_sentences(t, LISTED),  # type: ignore[arg-type]
            id="sentences calling listed code unread",
        ),
        pytest.param(lambda t: _unread_addresses(t, t), id="addresses said unread"),
        pytest.param(lambda t: _said_unread([SimpleNamespace(text=t)]), id="said unread"),  # type: ignore[list-item]
        pytest.param(whole_code_absences, id="whole-code absences"),
        pytest.param(closing_negations, id="closing negations"),
        pytest.param(_reports_a_claim, id="a reported claim"),
        pytest.param(
            lambda t: whole_code_absences(t, unsettled=True), id="unsettled section 5 absences"
        ),
        pytest.param(negated_clauses, id="negated clauses"),
        pytest.param(
            lambda t: denied_subject("and, " * (len(t) // 5) + " not known"),
            id="the items of what a sentence denies",
        ),
        pytest.param(
            lambda t: reading_denied_in("no " * (len(t) // 3) + "0x1400 was not read."),
            id="the clause denying a reading",
        ),
        pytest.param(
            _built(lambda t: "that word " * (len(t) // 10) + "not seen", denies_an_observation),
            id="a denied observation",
        ),
        pytest.param(
            lambda t: denied_subject("that set " * (len(t) // 9) + "was not known"),
            id="nouns a demonstrative points back with",
        ),
        pytest.param(lambda t: kept_absence(negated_clauses(t), t), id="an absence kept"),
        pytest.param(
            lambda t: kept_absence(
                ["the mutex name is not passed in that call"], "name is not, " * (len(t) // 13)
            ),
            id="an absence kept among many clauses",
        ),
        pytest.param(
            lambda t: kept_absence(
                negated_clauses(
                    "; ".join(f"wordx{i} alphax{i} is not known" for i in range(len(t) // 30))
                ),
                "; ".join(f"betay{i} gammay{i} is not shown" for i in range(len(t) // 30)),
            ),
            id="an absence kept among distinct clauses on both sides",
        ),
        pytest.param(
            lambda t: kept_absence(
                negated_clauses(
                    "; ".join(f"name{i} mutex is not known" for i in range(len(t) // 26))
                ),
                "; ".join(f"name mutex{i} is not shown" for i in range(len(t) // 26)),
            ),
            id="an absence kept among clauses sharing its words",
        ),
        pytest.param(lambda t: quote_stands(t[: len(t) // 2], [t]), id="a kept sentence's quote"),
        pytest.param(
            lambda t: _candidates(
                "The more words of 0x1400 are not read.",
                {
                    "s": SimpleNamespace(
                        id="s",
                        kind="section 5",
                        text=t,
                        cites=frozenset(),
                        addresses=frozenset(),
                        write=print,
                        lists_code=False,
                        label="5",
                    )
                },  # type: ignore[dict-item]
            ),
            id="a refused keep's candidate sources",
        ),
        pytest.param(
            lambda t: failure_counts("4 of 158 calls " * (len(t) // 15) + "failed"),
            id="failure counts",
        ),
        pytest.param(
            lambda t: count_disagrees("3 tool calls failed and " * (len(t) // 24), _COUNTS),
            id="a failure count held to the ledger",
        ),
        pytest.param(lambda t: read_rulings("L1: UPHELD: " + t, 1), id="limit ruling"),
        pytest.param(
            lambda t: read_rulings("L1 " + " " * len(t) + " UPHELD", 1), id="limit ruling spaces"
        ),
        pytest.param(lambda t: read_rulings("- **L1 " + t, 1), id="limit ruling with no word"),
        pytest.param(lambda t: clean_quote(t, REASON_LIMIT), id="limit ruling reason"),
        pytest.param(_built(_hostile_listing, listing_exits), id="exit branches of a listing"),
        pytest.param(
            lambda t: uncovered_exits(
                SimpleNamespace(claims=[SimpleNamespace(claim=t, evidence_ref="[ev_0002]")]),
                EXITS,
            ),
            id="a claim's words against exit branches",
        ),
    ],
)
def test_four_times_the_hostile_line_stays_under_the_ratio(read: Callable[[str], object]) -> None:
    _scales_linearly(read)


def test_a_megabyte_run_of_spaces_after_a_claim_word_stays_under_the_ratio() -> None:
    # The lines above stay at 160 KB for the processor cache's sake; this one
    # reader reaches megabytes. Its text is built before the measure and the
    # pattern walks it in C at a constant 6.5 ns a character from 40 KB to
    # 5 MB with a small cache shared, so 1.28 MB against 5.12 MB measures the
    # reader alone, and a step quadratic in the run would read 16.
    small, large = ("CLAIM" + " " * size + "x" for size in (1_280_000, 5_120_000))
    assert CLAIM_HEAD_RE.match(small) is None
    assert_ratio(
        repeated(lambda: CLAIM_HEAD_RE.match(small), 2),
        repeated(lambda: CLAIM_HEAD_RE.match(large), 2),
        TIME_RATIO_LIMIT,
        what="5,120,000 spaces against 1,280,000",
    )
