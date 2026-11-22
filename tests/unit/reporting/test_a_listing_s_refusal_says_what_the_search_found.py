"""A listed value's refusal says what the publish rule's search found and names the deciding test.

A value an analyst listed is looked for, whole, in the kept text of every tool
answer of the run that did not fail (``ledger_projection.tool_sightings``). The
search decides nothing: it is a fact after the refusal, saying what it read and
what it gave ("found it in none", or the entries it names), never that no tool
saw the value or that no second source records it, and with no "only".

* A row an analyst's listing gave (source ``analyst``) is refused by the test
  that refuses a listing: the publish rule takes no listing as a source. A
  domain, an address or a URL is then asked as the string sweep's, and the
  judge's keep is refused as well.
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
from malspark.reporting.builder import MalwareReportBuilder
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
    "answers, which sets apart an answer to a query for it,"
)
# The search of a stored report's sections sets no query's answer apart.
REPORT_SEARCH = "the publish rule's whole-value search of the tool sections this report keeps"
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

    def test_a_query_s_answer_the_search_set_apart_is_named(self) -> None:
        answer = S.listing_reason("mutex", LISTER, asked_in="ev_0004 get_domain_report")

        assert answer == (
            f"no: {LISTING}; {SEARCH} found it in none and set apart ev_0004 get_domain_report"
        )

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
            S.listing_reason("mutex", asked_in="ev_0004 get_domain_report"),
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
    )


POOL = "--silentGupdateSGupdateUfdrespubupnphostfirewall"
# (label, kind, value, ledger, the entries the search finds it in)
BUILT: list[tuple[str, str, str, list[LedgerEntry], list[str]]] = [
    (
        "B1 inside a longer run of text",
        "scheduled_task",
        "UpdateSystem",
        [_entry(1, "strings", structured={"strings": [{"text": "Ia2UpdateSystemNetapi32.dll"}]})],
        [],
    ),
    (
        "B2 inside a short run of a string pool",
        "registry",
        "GupdateU",
        [_entry(1, "strings", structured={"strings": [{"text": POOL}]})],
        [],
    ),
    (
        "B3 the bytes of a memory read",
        "scheduled_task",
        "UpdateUser",
        [
            _entry(
                1,
                "read_memory",
                structured={"data": list(b"UpdateUser"), "hex": b"UpdateUser".hex()},
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
        "GentlemenMutex01",
        [_entry(1, "carve", output="x " + "\x00".join("GentlemenMutex01") + "\x00 y")],
        [],
    ),
    (
        "B6 a query's answer beside a whole holder",
        "domain",
        "tox.chat",
        [
            _entry(1, "extract_iocs", structured={"domains": ["tox.chat"]}),
            _entry(
                2,
                "strings",
                structured={"pattern": "tox.chat", "strings": [{"text": "https://tox.chat/x"}]},
                args={"pattern": "tox.chat"},
            ),
        ],
        ["ev_0001 (extract_iocs)"],
    ),
    (
        "B7 only the cut part of a shortened answer",
        "mutex",
        "GentlemenMutex01",
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
        "GentlemenMutex01",
        [_entry(1, "strings", output="error after printing GentlemenMutex01", ok=False)],
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
        "gentlemenlock",
        [_entry(1, "strings", output="C:\\ProgramData\\gentlemenlock\\x.dat")],
        [],
    ),
    (
        "B11 B1 under a tool nobody declared",
        "scheduled_task",
        "UpdateSystem",
        [_entry(1, "mytool", structured={"rows": ["Ia2UpdateSystemNetapi32.dll"]})],
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
        "UpdateSystem",
        [_entry(1, "strings", structured={"strings": [{"text": "UpdateSystem"}]})],
        ["ev_0001 (strings)"],
    ),
]


def _built_answer(kind: str, value: str, ledger: list[LedgerEntry]) -> PublishAnswer:
    """The answer the table's listed path gives, with the sightings the run's search gives."""
    seen, queried = tool_sightings(ledger, [(kind, value)])
    key = value_key(kind, value)
    sighted = "; ".join(f"{eid} ({tool})" for eid, tool in seen.get(key, []))
    asked = "" if sighted else "; ".join(f"{eid} {tool}" for eid, tool in queried.get(key, []))
    answer = S.publish_answer(
        kind,
        value,
        "analyst",
        listed_by=LISTER,
        seen_in=sighted,
        tool_search=S.SEARCHED_THE_RUN,
        asked_in=asked,
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
        clause = f"{SEARCH} found it in {'; '.join(named) if named else 'none'}"
        assert answer.facts == (clause,)
        assert answer.refusing[0] == LISTING
        assert not S.publishes(answer)
        assert not [word for word in RETIRED if word in answer]

    def test_a_tool_nobody_declared_is_answered_as_a_declared_one(self) -> None:
        by_label = {b[0]: b for b in BUILT}
        declared = _built_answer(*by_label["B1 inside a longer run of text"][1:4])
        undeclared = _built_answer(*by_label["B11 B1 under a tool nobody declared"][1:4])

        assert undeclared == declared
        assert (undeclared.refusing, undeclared.facts) == (declared.refusing, declared.facts)

    @pytest.mark.parametrize(
        "label", ["B7 only the cut part of a shortened answer", "B8 only a failed call's text"]
    )
    def test_an_answer_the_search_does_not_read_whole_is_no_absence_over_the_run(
        self, label: str
    ) -> None:
        answer = _built_answer(*{b[0]: b for b in BUILT}[label][1:4])

        assert answer.facts == (f"{SEARCH} found it in none",)
        assert "this run" not in answer and "no tool" not in answer

    def test_the_controls_keep_their_meaning(self) -> None:
        by_label = {b[0]: b for b in BUILT}
        nothing = _built_answer(*by_label["B12 nothing holds it"][1:4])
        whole = _built_answer(*by_label["B13 a whole holder"][1:4])

        assert nothing.facts == (f"{SEARCH} found it in none",)
        assert whole.facts == (f"{SEARCH} found it in ev_0001 (strings)",)


MUTEX = "Global\\relay-mutex-7f3c"


def _report(ledger: list[LedgerEntry]) -> MalwareReport:
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
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=ledger,
    ).build_deterministic()


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
        assert row.published == f"no: {LISTING}; {SEARCH} found it in ev_0001 (strings)"

    def test_the_writers_table_answer_keeps_the_parts(self) -> None:
        report = self.REPORT()
        answer = published_answers(report)("mutex", MUTEX)

        assert isinstance(answer, PublishAnswer)
        assert (answer.refusing, answer.facts) == (
            (LISTING,),
            (f"{SEARCH} found it in ev_0001 (strings)",),
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
