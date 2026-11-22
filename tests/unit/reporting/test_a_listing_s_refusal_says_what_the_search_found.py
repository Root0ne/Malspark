"""A listed value's refusal says what the publish rule's search found and names the deciding test.

A value an analyst listed is looked for, whole, in the kept text of every tool
answer of the run that did not fail (``ledger_projection.tool_sightings``). The
search decides nothing: it is a fact after the refusal, saying what it read and
what it gave ("found it in none", or the entries it names), never that no tool
saw the value or that no second source records it, and with no "only". It sets
apart an answer to a call whose arguments hold the value whole, and says so in
those words. A search that read nothing gives no result: where the run's record
holds no successful tool answer, or a stored report keeps no tool section, it
says that, read from the same record the search reads.

* A row an analyst's listing gave (source ``analyst``) is refused by the test
  that refuses a listing: the publish rule takes no listing as a source. A
  domain, an address or a URL is then asked as the string sweep's, and the
  judge's keep is refused as well. For any other kind the judge's keep is a
  fact after the refusal, said only where the judge's indicators were read and
  none names the value.
* A row of another source that the search found the value in is refused by its
  own tests (the strings refusal), the search's entries and who lists it after.
* A judge's value with no row of its own is refused as the string sweep's
  would be, naming the judge's indicator in place of a row.

Every part goes through ``publish_parts``, so every reader composes the same
words.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from malspark.pipeline.validation import (
    recommendation_indicator_violations,
    unpublished_value_violations,
)
from malspark.reporting import builder
from malspark.reporting.builder import MalwareReportBuilder, evidence_index_row
from malspark.reporting.ledger_projection import tool_sightings, value_key
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import ConsolidatedIOC, MalwareReport
from malspark.reporting.narrative_agent import published_answers
from malspark.reporting.publish_parts import PublishAnswer, answer_state, told_whole
from malspark.reporting.renderers import stix_renderer as S
from malspark.reporting.renderers.markdown import _Context
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, Artifact
from malspark.schemas.stix_models import Indicator

ROOT = Path(__file__).resolve().parents[3]
LISTER = "an artifact of the dynamic analyst"
SEARCH = (
    "the publish rule's whole-value search of the kept text of the run's successful tool "
    "answers, which sets apart an answer to a call whose arguments hold it,"
)
# The search of a stored report's sections sets no call's answer apart.
REPORT_SEARCH = "the publish rule's whole-value search of the tool sections this report keeps"
# What a search that had nothing to read says in place of a result.
READ_NONE = "the publish rule's whole-value search read no successful tool answer of the run"
NO_SECTION = "this report keeps no tool section for the publish rule's search to read"
JUDGE = "the judge did not keep it as an indicator"
LISTING = (
    f"its row is an analyst's listing ({LISTER}) and the publish rule takes no listing as a source"
)
ENTRIES = "ev_0006 (iocs_from_file); ev_0033 (strings)"
# The words no answer of the publish rule says any more.
RETIRED = (
    "no tool in this run saw it",
    "seen only in the text of",
    "no second source in this run records it",
    "named only by an analyst",
    "sets apart an answer to a query for it",
)


class TestTheWords:
    def test_a_listed_mutex_the_search_found_in_none(self) -> None:
        answer = S.listing_reason("mutex", LISTER)

        assert answer == f"no: {LISTING}; {SEARCH} found it in none"
        assert (answer.refusing, answer.facts) == ((LISTING,), (f"{SEARCH} found it in none",))

    def test_a_listed_mutex_the_search_found_names_its_entries(self) -> None:
        answer = S.listing_reason("mutex", LISTER, ENTRIES)

        assert answer == f"no: {LISTING}; {SEARCH} found it in {ENTRIES}"

    @pytest.mark.parametrize("kind", ["domain", "ip", "url"])
    def test_a_listed_network_value_also_gives_the_judge_s_keep_its_part(self, kind: str) -> None:
        answer = S.listing_reason(kind, LISTER)

        assert answer == (
            f"no: {LISTING}, and the judge did not keep it as an indicator; "
            f"{SEARCH} found it in none"
        )
        assert answer.refusing == (LISTING, S.JUDGE_DID_NOT_KEEP)

    def test_a_call_s_answer_the_search_set_apart_is_named(self) -> None:
        answer = S.listing_reason("mutex", LISTER, asked_in="ev_0004 (get_domain_report)")

        assert answer == (
            f"no: {LISTING}; {SEARCH} found it in none and set apart ev_0004 (get_domain_report)"
        )

    def test_a_search_that_read_no_answer_gives_no_result(self) -> None:
        answer = S.listing_reason("mutex", LISTER, searched=S.SEARCHED_NO_ANSWER)

        assert answer == f"no: {LISTING}; {READ_NONE}"
        assert answer.facts == (READ_NONE,)
        assert "found it" not in answer

    def test_a_report_that_keeps_no_tool_section_gives_no_result(self) -> None:
        answer = S.listing_reason("mutex", LISTER, searched=S.SEARCHED_NO_SECTION)

        assert answer == f"no: {LISTING}; {NO_SECTION}"
        assert "found it" not in answer

    def test_the_judge_s_keep_is_a_fact_where_the_judge_named_none(self) -> None:
        told = S.listing_reason("mutex", LISTER, judge_names_none=True)
        untold = S.listing_reason("mutex", LISTER)

        assert told == f"no: {LISTING}; {JUDGE}; {SEARCH} found it in none"
        assert (told.refusing, told.facts) == ((LISTING,), (JUDGE, f"{SEARCH} found it in none"))
        # The state, what a writer restates, is the refusal alone either way.
        assert answer_state(told) == answer_state(untold) == f"no: {LISTING}"
        assert JUDGE not in untold

    @pytest.mark.parametrize("kind", ["domain", "ip", "url"])
    def test_a_network_listing_keeps_the_judge_s_keep_as_its_part_alone(self, kind: str) -> None:
        answer = S.listing_reason(kind, LISTER, judge_names_none=True)

        assert answer.refusing == (LISTING, S.JUDGE_DID_NOT_KEEP)
        assert answer.facts == (f"{SEARCH} found it in none",)

    def test_a_stored_report_s_search_names_its_kept_sections(self) -> None:
        found = S.listing_reason("mutex", LISTER, "ev_0006 (iocs_from_file)", S.SEARCHED_THE_REPORT)
        none = S.listing_reason("mutex", LISTER, searched=S.SEARCHED_THE_REPORT)

        assert found == f"no: {LISTING}; {REPORT_SEARCH} found it in ev_0006 (iocs_from_file)"
        assert none == f"no: {LISTING}; {REPORT_SEARCH} found it in none"

    def test_a_listing_with_no_lister_named(self) -> None:
        assert S.listing_reason("registry") == (
            "no: its row is an analyst's listing and the publish rule takes no listing as a "
            f"source; {SEARCH} found it in none"
        )

    def test_a_strings_row_the_search_found_is_refused_by_its_own_tests(self) -> None:
        answer = S.publish_answer(
            "domain", "relay.example.net", "strings", listed_by=LISTER, seen_in=ENTRIES
        )
        alone = S.publish_answer("domain", "relay.example.net", "strings")

        assert answer == (
            "no: its row's source is strings and no row of the string sweep holds it and the "
            "publish rule found no recovery of it and read no reputation record for it; "
            f"{SEARCH} found it in {ENTRIES}; {LISTER} lists it"
        )
        assert isinstance(answer, PublishAnswer) and isinstance(alone, PublishAnswer)
        assert answer.refusing == alone.refusing

    def test_a_strings_mutex_the_search_found_is_refused_by_its_own_tests(self) -> None:
        answer = S.publish_answer("mutex", "Global\\relay", "strings", seen_in=ENTRIES)
        alone = S.publish_answer("mutex", "Global\\relay", "strings")

        assert answer == (
            "no: its row's source is strings and no row of the string sweep holds it and the "
            f"publish rule's lookup found no second source; {SEARCH} found it in {ENTRIES}"
        )
        assert isinstance(answer, PublishAnswer) and isinstance(alone, PublishAnswer)
        assert answer.refusing == alone.refusing

    def test_a_cut_string_the_search_found_keeps_the_cut_as_its_refusal(self) -> None:
        record = S.SecondSources(cut={"relay.example.net": "relay.exa"})
        answer = S.publish_answer(
            "domain", "relay.example.net", "strings", corroborating=record, seen_in=ENTRIES
        )

        assert isinstance(answer, PublishAnswer)
        assert answer.refusing == (S.CUT_REASON,)
        assert answer.facts == ('the string reads "relay.exa"', f"{SEARCH} found it in {ENTRIES}")

    def test_a_judge_s_value_with_no_row_names_the_judge_s_indicator(self) -> None:
        answer = S.publish_answer(
            "mutex", "Global\\relay", "strings", seen_in=ENTRIES, judge_s_value=True
        )

        assert answer == (
            "no: the judge's indicator names it and no row of the string sweep holds it and the "
            f"publish rule's lookup found no second source; {SEARCH} found it in {ENTRIES}"
        )

    def test_no_answer_says_a_retired_word(self) -> None:
        for answer in (
            S.listing_reason("mutex", LISTER),
            S.listing_reason("domain", LISTER, ENTRIES),
            S.listing_reason("mutex", asked_in="ev_0004 (get_domain_report)"),
            S.listing_reason("mutex", searched=S.SEARCHED_NO_ANSWER),
            S.publish_answer("domain", "relay.example.net", "strings", seen_in=ENTRIES),
        ):
            assert not [word for word in RETIRED if word in answer], answer
            assert " only " not in f" {answer} "

    def test_no_product_source_writes_a_retired_word(self) -> None:
        written: list[str] = []
        for path in sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "apps").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    written += [f"{path}: {w}" for w in RETIRED if w in node.value.lower()]

        assert written == []


def _entry(
    number: int,
    tool: str,
    output: str = "",
    structured: Any = None,
    args: dict[str, Any] | None = None,
    *,
    ok: bool = True,
    truncated: bool = False,
    dropped: int = 0,
    repeated_of: str | None = None,
) -> LedgerEntry:
    return LedgerEntry(
        id=f"ev_{number:04d}",
        tool=tool,
        output=output,
        structured=structured,
        args=args or {},
        ok=ok,
        truncated=truncated,
        chars_dropped=dropped,
        repeated_of=repeated_of,
    )


POOL = "--quietKsyncAKsyncBprintspoolbitsdhcp"
# (label, kind, value, ledger, the entries the search finds it in)
BUILT: list[tuple[str, str, str, list[LedgerEntry], list[str]]] = [
    (
        "B1 inside a longer run of text",
        "scheduled_task",
        "RefreshAgent",
        [_entry(1, "strings", structured={"strings": [{"text": "Lb3RefreshAgentShell.dll"}]})],
        [],
    ),
    (
        "B2 inside a short run of a string pool",
        "registry",
        "KsyncB",
        [_entry(1, "strings", structured={"strings": [{"text": POOL}]})],
        [],
    ),
    (
        "B3 the bytes of a memory read",
        "scheduled_task",
        "RefreshUser",
        [
            _entry(
                1,
                "read_memory",
                structured={"data": list(b"RefreshUser"), "hex": b"RefreshUser".hex()},
            )
        ],
        [],
    ),
    (
        "B4 a path escaped in a JSON text",
        "registry",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        [
            _entry(
                1,
                "reg_dump",
                output='{"key": "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\'
                'CurrentVersion\\\\Run"}',
            )
        ],
        [],
    ),
    (
        "B5 UTF-16 text",
        "mutex",
        "RelayMutex01",
        [_entry(1, "carve", output="x " + "\x00".join("RelayMutex01") + "\x00 y")],
        [],
    ),
    (
        "B6 a query's answer beside a whole holder",
        "domain",
        "relay-chat.example.net",
        [
            _entry(1, "extract_iocs", structured={"domains": ["relay-chat.example.net"]}),
            _entry(
                2,
                "strings",
                structured={
                    "pattern": "relay-chat.example.net",
                    "strings": [{"text": "https://relay-chat.example.net/x"}],
                },
                args={"pattern": "relay-chat.example.net"},
            ),
        ],
        ["ev_0001 (extract_iocs)"],
    ),
    (
        "B7 only the cut part of a shortened answer",
        "mutex",
        "RelayMutex01",
        [
            _entry(
                1, "strings", output="(first 4000 characters kept)", truncated=True, dropped=50000
            )
        ],
        [],
    ),
    (
        "B8 only a failed call's text",
        "mutex",
        "RelayMutex01",
        [_entry(1, "strings", output="error after printing RelayMutex01", ok=False)],
        [],
    ),
    (
        "B9 a defanged host",
        "domain",
        "evil-c2.top",
        [_entry(1, "report_tool", output="contacts hxxps://evil-c2[.]top/gate")],
        [],
    ),
    (
        "B10 a bare component between separators",
        "mutex",
        "relaylock",
        [_entry(1, "strings", output="C:\\ProgramData\\relaylock\\x.dat")],
        [],
    ),
    (
        "B11 B1 under a tool nobody declared",
        "scheduled_task",
        "RefreshAgent",
        [_entry(1, "mytool", structured={"rows": ["Lb3RefreshAgentShell.dll"]})],
        [],
    ),
    (
        "B12 nothing holds it",
        "scheduled_task",
        "NeverSeenTask",
        [_entry(1, "strings", structured={"strings": [{"text": "unrelated"}]})],
        [],
    ),
    (
        "B13 a whole holder",
        "scheduled_task",
        "RefreshAgent",
        [_entry(1, "strings", structured={"strings": [{"text": "RefreshAgent"}]})],
        ["ev_0001 (strings)"],
    ),
]


# Built inputs on which a form of the search's clause could be untrue:
# (label, kind, value, ledger, the clause the answer must carry)
BUILT_FORMS: list[tuple[str, str, str, list[LedgerEntry], str]] = [
    (
        "F1 an operation on the value, not a query for it",
        "mutex",
        "RelayMutex01",
        [
            _entry(
                1,
                "transform_bytes",
                output="RelayMutex01 xored",
                args={"data": "RelayMutex01", "op": "xor"},
            )
        ],
        f"{SEARCH} found it in none and set apart ev_0001 (transform_bytes)",
    ),
    ("F2 an empty ledger", "mutex", "RelayMutex01", [], READ_NONE),
    (
        "F3 only failed answers",
        "mutex",
        "RelayMutex01",
        [
            _entry(1, "strings", output="RelayMutex01", ok=False),
            _entry(2, "carve", output="RelayMutex01", ok=False),
        ],
        READ_NONE,
    ),
    (
        "F4 failed answers and one successful",
        "mutex",
        "RelayMutex01",
        [
            _entry(1, "strings", output="RelayMutex01", ok=False),
            _entry(2, "carve", output="unrelated"),
        ],
        f"{SEARCH} found it in none",
    ),
    (
        "F5 answers that succeeded and kept no text",
        "mutex",
        "RelayMutex01",
        [_entry(1, "strings"), _entry(2, "carve")],
        f"{SEARCH} found it in none",
    ),
    (
        "F6 only set-apart answers",
        "mutex",
        "RelayMutex01",
        [_entry(1, "lookup", output="RelayMutex01 unknown", args={"q": "RelayMutex01"})],
        f"{SEARCH} found it in none and set apart ev_0001 (lookup)",
    ),
    (
        "F7 only a repeated call's entry",
        "mutex",
        "RelayMutex01",
        [_entry(2, "strings", output="RelayMutex01", repeated_of="ev_0001")],
        READ_NONE,
    ),
]


def _search_record(ledger: list[LedgerEntry], kind: str, value: str) -> dict[str, Any]:
    """The search's record as the builder stores it: the sightings of the entries
    that repeat no earlier one, and the index of every entry."""
    seen, queried = tool_sightings([e for e in ledger if not e.repeated_of], [(kind, value)])
    return {
        "tool_sightings": seen,
        "tool_queries": queried,
        "evidence_index": [evidence_index_row(entry) for entry in ledger],
    }


def _built_answer(kind: str, value: str, ledger: list[LedgerEntry]) -> PublishAnswer:
    """The answer the table's listed path gives, with the sightings the run's search gives."""
    record = _search_record(ledger, kind, value)
    sighted, searched = S.listed_value_sightings(record, kind, value)
    answer = S.publish_answer(
        kind,
        value,
        "analyst",
        listed_by=LISTER,
        seen_in=sighted,
        tool_search=searched,
        asked_in="" if sighted else S.query_answers(record, kind, value, as_found=True),
    )
    assert isinstance(answer, PublishAnswer)
    return answer


class TestTheBuiltInputs:
    @pytest.mark.parametrize(
        ("label", "kind", "value", "ledger", "found"), BUILT, ids=[b[0] for b in BUILT]
    )
    def test_the_search_clause_names_exactly_what_the_search_found(
        self, label: str, kind: str, value: str, ledger: list[LedgerEntry], found: list[str]
    ) -> None:
        answer = _built_answer(kind, value, ledger)
        seen, _queried = tool_sightings(ledger, [(kind, value)])
        named = [f"{eid} ({tool})" for eid, tool in seen[value_key(kind, value)]]

        assert named == found
        read = any(entry.ok for entry in ledger)
        clause = (
            f"{SEARCH} found it in {'; '.join(named) if named else 'none'}" if read else READ_NONE
        )
        assert answer.facts == (clause,)
        assert answer.refusing[0] == LISTING
        assert not S.publishes(answer)
        assert not [word for word in RETIRED if word in answer]

    @pytest.mark.parametrize(
        ("label", "kind", "value", "ledger", "clause"),
        BUILT_FORMS,
        ids=[b[0] for b in BUILT_FORMS],
    )
    def test_each_form_of_the_clause_is_true_of_its_input(
        self, label: str, kind: str, value: str, ledger: list[LedgerEntry], clause: str
    ) -> None:
        answer = _built_answer(kind, value, ledger)

        assert answer.facts == (clause,)
        assert not S.publishes(answer)

    def test_a_tool_nobody_declared_is_answered_as_a_declared_one(self) -> None:
        by_label = {b[0]: b for b in BUILT}
        declared = _built_answer(*by_label["B1 inside a longer run of text"][1:4])
        undeclared = _built_answer(*by_label["B11 B1 under a tool nobody declared"][1:4])

        assert undeclared == declared
        assert (undeclared.refusing, undeclared.facts) == (declared.refusing, declared.facts)

    def test_an_answer_the_search_does_not_read_whole_is_no_absence_over_the_run(self) -> None:
        by_label = {b[0]: b for b in BUILT}
        cut = _built_answer(*by_label["B7 only the cut part of a shortened answer"][1:4])
        failed = _built_answer(*by_label["B8 only a failed call's text"][1:4])

        assert cut.facts == (f"{SEARCH} found it in none",)
        assert failed.facts == (READ_NONE,)
        for answer in (cut, failed):
            assert "this run" not in answer and "no tool" not in answer

    def test_the_controls_keep_their_meaning(self) -> None:
        by_label = {b[0]: b for b in BUILT}
        nothing = _built_answer(*by_label["B12 nothing holds it"][1:4])
        whole = _built_answer(*by_label["B13 a whole holder"][1:4])

        assert nothing.facts == (f"{SEARCH} found it in none",)
        assert whole.facts == (f"{SEARCH} found it in ev_0001 (strings)",)


MUTEX = "Global\\relay-mutex-7f3c"


def _report(ledger: list[LedgerEntry], judge_bundle: dict[str, Any] | None = None) -> MalwareReport:
    isrs = {
        "dynamic": AgentISR(
            agent_id="dynamic",
            domain="dynamic",
            artifacts=[
                Artifact(
                    kind="iocs",
                    label="Iocs",
                    columns=["Type", "Value"],
                    rows=[["mutex", MUTEX]],
                    evidence_ids=["ev_0001"],
                    source="dynamic",
                )
            ],
        )
    }
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=isrs,
        stix_output={"objects": []} if judge_bundle is None else judge_bundle,
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=ledger,
    ).build_deterministic()


def _mutex_row(report: MalwareReport) -> ConsolidatedIOC:
    (row,) = [r for r in builder.ioc_table(report) if r.value == MUTEX]
    return row


# Ledgers of every mix of what the search reads and leaves: a failed answer, a
# successful one, a repeated call's entry.
LEDGERS: list[tuple[str, list[LedgerEntry]]] = [
    ("empty", []),
    ("one failed", [_entry(1, "strings", output=MUTEX, ok=False)]),
    ("one successful", [_entry(1, "strings", output=MUTEX)]),
    (
        "failed and successful",
        [_entry(1, "strings", output=MUTEX, ok=False), _entry(2, "carve", output=MUTEX)],
    ),
    ("a repeat alone", [_entry(2, "strings", output=MUTEX, repeated_of="ev_0001")]),
    (
        "a successful, a repeat and a failed",
        [
            _entry(1, "strings", output=MUTEX),
            _entry(2, "strings", output=MUTEX, repeated_of="ev_0001"),
            _entry(3, "carve", output=MUTEX, ok=False),
        ],
    ),
    (
        "a repeat that failed and a successful",
        [
            _entry(1, "carve", output=MUTEX),
            _entry(2, "carve", output=MUTEX, ok=False, repeated_of="ev_0001"),
        ],
    ),
]


class TestTheSearchAndWhatItReadAgree:
    """The read-nothing form is read from the index of the same ledger the search reads."""

    @pytest.mark.parametrize("ledger", [h for _n, h in LEDGERS], ids=[n for n, _h in LEDGERS])
    def test_the_answers_counted_read_are_the_answers_the_search_read(
        self, ledger: list[LedgerEntry]
    ) -> None:
        report = _report(ledger)
        # Every entry's text holds the value whole, so the search names every
        # answer it read.
        searched = [eid for eid, _tool in report.tool_sightings[value_key("mutex", MUTEX)]]

        assert S.answers_the_search_reads(report) == searched

    @pytest.mark.parametrize("ledger", [h for _n, h in LEDGERS], ids=[n for n, _h in LEDGERS])
    def test_the_row_says_the_search_read_nothing_exactly_where_it_read_nothing(
        self, ledger: list[LedgerEntry]
    ) -> None:
        emptied = [e.model_copy(update={"output": "unrelated"}) for e in ledger]
        report = _report(emptied)
        facts = _mutex_row(report).published.facts
        read = S.answers_the_search_reads(report)

        assert facts[-1] == (f"{SEARCH} found it in none" if read else READ_NONE)

    def test_a_stored_report_with_no_tool_section_says_it_keeps_none(self) -> None:
        report = _report([_entry(1, "strings", output=MUTEX)])
        stored = report.model_dump(mode="json")
        stored["tool_sightings"] = None
        stored["tool_queries"] = None
        kept = MalwareReport.model_validate(stored)
        stored["sections"] = [
            s for s in stored["sections"] if not str(s.get("source") or "").startswith("tool:")
        ]
        bare = MalwareReport.model_validate(stored)

        assert _mutex_row(kept).published.facts[-1].startswith(f"{REPORT_SEARCH} found it in ")
        assert _mutex_row(bare).published.facts[-1] == NO_SECTION


class TestTheJudgeSKeepIsAFactWhereItWasRead:
    def test_a_judge_that_named_other_values_did_not_keep_it(self) -> None:
        bundle = {
            "objects": [
                {
                    "type": "indicator",
                    "pattern": "[mutex:name = 'OtherMutex02']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                }
            ]
        }
        row = _mutex_row(_report([_entry(1, "strings", output=MUTEX)], bundle))

        assert row.published.facts[0] == JUDGE
        assert answer_state(row.published) == f"no: {LISTING}"

    def test_no_judge_bundle_says_nothing_of_the_judge(self) -> None:
        row = _mutex_row(_report([_entry(1, "strings", output=MUTEX)], {}))

        assert JUDGE not in row.published
        assert row.published.facts == (f"{SEARCH} found it in ev_0001 (strings)",)

    def test_the_fact_reads_the_judge_s_own_bundle(self) -> None:
        bundle = {
            "objects": [
                {
                    "type": "indicator",
                    "pattern": f"[mutex:name = '{MUTEX}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                }
            ]
        }
        report = _report([_entry(1, "strings", output=MUTEX)])
        stored = report.model_dump(mode="json")
        # A report whose stored reading of the judge's values is empty while
        # its bundle names the value.
        stored["stix_bundle_extended"] = bundle
        stored["judge_indicators"] = []

        assert not S.judge_names_none_of(MalwareReport.model_validate(stored), "mutex", MUTEX)
        assert S.judge_names_none_of(report, "mutex", MUTEX)
        assert not S.judge_names_none_of({"stix_bundle_extended": {}}, "mutex", MUTEX)


class TestEveryReaderComposesFromTheParts:
    """The readers of the listing's parts: the indicator table, the writers' table answers and
    their feedback, a cell beside a value, the export's decline, the recommendation retry,
    MISP, and the stored document the job package carries."""

    REPORT = staticmethod(
        lambda: _report(
            [_entry(1, "strings", structured={"strings": [{"text": MUTEX}]})],
        )
    )

    def _row(self, report: MalwareReport) -> ConsolidatedIOC:
        (row,) = [r for r in report.consolidated_iocs if r.value == MUTEX]
        return row

    def test_the_indicator_table_prints_the_composition(self) -> None:
        row = self._row(self.REPORT())

        assert isinstance(row.published, PublishAnswer)
        assert row.published == (f"no: {LISTING}; {JUDGE}; {SEARCH} found it in ev_0001 (strings)")

    def test_the_writers_table_answer_keeps_the_parts(self) -> None:
        report = self.REPORT()
        answer = published_answers(report)("mutex", MUTEX)

        assert isinstance(answer, PublishAnswer)
        assert (answer.refusing, answer.facts) == (
            (LISTING,),
            (JUDGE, f"{SEARCH} found it in ev_0001 (strings)"),
        )

    def test_the_writer_s_feedback_and_the_mark_carry_the_state(self) -> None:
        answer = self._row(self.REPORT()).published
        value = "relay-gate.example.net"

        (found,) = unpublished_value_violations(
            {"body": f"It reaches {value} today."},
            lambda kind, held: answer if held == value else "",
        )

        assert f"({answer_state(answer)})" in found.message
        assert found.labels == (f"{value} ({answer_state(answer)})",)
        assert SEARCH not in found.message

    def test_a_cell_prints_the_state_or_the_whole_answer(self) -> None:
        answer = self._row(self.REPORT()).published
        ctx = _Context.of(self.REPORT())
        ctx._answers = lambda kind, held: answer if held == "relay-gate.example.net" else ""

        ctx.whole_answer_printed = lambda kind, held, said: True
        assert ctx.publish_state("relay-gate.example.net") == f" ({answer_state(answer)})"
        ctx.whole_answer_printed = lambda kind, held, said: False
        assert ctx.publish_state("relay-gate.example.net") == f" ({answer})"

    def test_the_export_s_decline_and_the_recommendation_carry_the_whole_answer(self) -> None:
        answer = self._row(self.REPORT()).published
        row = ConsolidatedIOC(type="Domain", kind="domain", value="x.example.org", published=answer)
        indicator = Indicator(
            name="X",
            pattern="[domain-name:value = 'x.example.org']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
        )

        declined = S._judge_indicator_unpublished(indicator, [row])
        (asked,) = recommendation_indicator_violations(
            {
                "defensive_recommendations": [
                    {"category": "dns", "action": "Block x.example.org.", "priority": "P1"}
                ]
            },
            lambda kind, held: answer if held == "x.example.org" else "",
        )

        assert declined is not None and f"({told_whole(answer)})" in declined[1]
        assert f"x.example.org ({told_whole(answer)})" in asked.message

    def test_misp_reads_the_decision_alone(self) -> None:
        report = self.REPORT()

        attributes = build_misp_attributes(report, owner="a" * 32)

        assert all(MUTEX not in str(attribute.get("value")) for attribute in attributes)

    def test_the_stored_document_holds_the_composition(self) -> None:
        report = self.REPORT()
        row = self._row(report)

        stored = MalwareReport.model_validate_json(report.model_dump_json())
        (again,) = [r for r in stored.consolidated_iocs if r.value == MUTEX]

        assert again.published == str(row.published)
