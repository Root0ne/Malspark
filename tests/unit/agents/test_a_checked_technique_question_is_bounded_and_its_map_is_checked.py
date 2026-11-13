"""The checked-technique question stays bounded, and a map rests on more than a lookup.

A tool's declared answer field can name hundreds of ids, and one id can be
passed in fifty thousand entries: the question asks at most
``MAX_CHECKED_QUESTIONS`` checked techniques, names a few entries per agent and
place, and fits the checked ones into the room the judge's window has left
after the other techniques, which keep their place; every id left out is
recorded as not asked, with why, and the question says how many. A map that
cites only the entries where its id was looked up is declined, a map settled
with no catalogue is declined, a free-text answer is read with its entries
outside its reason, a new review loads under the reader that predates the
checked kind, and a standing map reaches the export.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Literal
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, Field

from malspark.agents.judge_agent import (
    CHECKED_LEFT_OUT_NOTICE,
    TECHNIQUE_MAP_FORM,
    TECHNIQUE_QUESTION_CHECKED_NOTE,
    TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS,
    JudgeAgent,
    _line_map_decision,
    technique_question_text,
)
from malspark.analysis.technique_ids import technique_ids_in
from malspark.extractors import capability_matrix
from malspark.extractors.capability_matrix import (
    CHECK_NOT_RUN,
    CHECKED_CAP_REASON,
    CHECKED_WINDOW_REASON,
    MAX_CHECKED_QUESTIONS,
    NO_CATALOGUE_FINDING,
    TechniqueQuestion,
    build_capability_matrix,
    checked_question_line,
    judge_questions,
    settle_mapped_techniques,
)
from malspark.pipeline.validation import MAP_RESTS_ON_ITS_LOOKUP_CODE
from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, ClaimEvidence
from malspark.schemas.stix_models import (
    EVIDENCE_REFS_PROPERTY,
    TECHNIQUE_REVIEW_PROPERTY,
    Bundle,
    CheckedDecision,
    TechniqueDecision,
    TechniqueReview,
    attack_pattern_id,
)
from malspark.tools import knowledge
from tests.linear_cost import assert_scales

CHECKED = "T1041"
CARRIED = "T1071.001"
DESCRIBES = "The beacon sends the host data it collected out over its command and control channel"
WINDOWS = {"platform": "windows", "file_type": "pe"}
DECLARES = {"v": 1, "kind": "rule_hits", "techniques": [{"path": "/hits/*/ttp"}]}


def _bundle(*, malware: bool = False) -> Bundle:
    objects: list[dict[str, Any]] = [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332211",
            "name": "Web Protocols",
            "external_references": [{"source_name": "mitre-attack", "external_id": CARRIED}],
        }
    ]
    if malware:
        objects.append({"type": "malware", "id": "malware--1", "name": "x", "is_family": False})
    return Bundle.model_validate({"objects": objects})


def _isrs(*extra: ClaimEvidence) -> dict[str, AgentISR]:
    return {
        "triage": AgentISR(
            agent_id="triage",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim=(
                        "The beacon talks to its command and control server over HTTP web protocols"
                    ),
                    evidence_ref="[ev_0004], [ev_0005]",
                    confidence=0.7,
                    technique_id=CARRIED,
                ),
                *extra,
            ],
        )
    }


def _ledger(*extra: LedgerEntry) -> list[LedgerEntry]:
    return [
        LedgerEntry(id="ev_0004", agent="triage", tool="any_reader", output="POST /gate"),
        LedgerEntry(id="ev_0005", agent="triage", tool="any_reader", output="counter=1"),
        LedgerEntry(
            id="ev_0010",
            agent="triage",
            tool="any_validator",
            args={"ids": [CARRIED, CHECKED]},
            output='{"invalid": []}',
        ),
        *extra,
    ]


class _Llm:
    def __init__(self, answer: str = "[]") -> None:
        self.answer = answer
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content=self.answer)


class TestTheQuestionIsBounded:
    def test_hundreds_of_ids_in_a_declared_answer_field_ask_at_most_the_cap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Every id reads as catalogued, so the cap alone decides.
        monkeypatch.setattr(capability_matrix, "_unknown_to_the_catalogue", lambda ids: set())
        named = [f"T{1100 + i // 10}.{i % 10:03d}" for i in range(600)]
        flood = LedgerEntry(
            id="ev_0001",
            agent="pack",
            tool="any_scanner",
            structured={"hits": [{"ttp": tid} for tid in named]},
            source="mcp:operator",
            facts=DECLARES,
        )

        questions, not_asked = judge_questions(
            _bundle().model_dump(), _isrs(), None, ledger=[flood, *_ledger()]
        )
        checked = [q.technique_id for q in questions if q.kind == "checked"]

        assert len(checked) == MAX_CHECKED_QUESTIONS
        # An id an agent passed in a call's arguments goes first, though seen later.
        assert checked[0] == CHECKED
        assert checked[1:] == named[: MAX_CHECKED_QUESTIONS - 1]
        cut = [tid for tid, why in not_asked.items() if why == CHECKED_CAP_REASON]
        assert cut == named[MAX_CHECKED_QUESTIONS - 1 :]
        assert str(MAX_CHECKED_QUESTIONS) in CHECKED_CAP_REASON

    def test_ids_inside_one_long_argument_cannot_push_out_an_id_looked_up_on_its_own(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(capability_matrix, "_unknown_to_the_catalogue", lambda ids: set())
        junk = [f"T{2000 + i // 10}.{i % 10:03d}" for i in range(500)]
        sample_text = LedgerEntry(
            id="ev_0001", agent="triage", tool="any_reader", args={"text": " ".join(junk)}
        )
        answered = LedgerEntry(
            id="ev_0002",
            agent="pack",
            tool="any_scanner",
            structured={"hits": [{"ttp": "T1999.001"}]},
            source="mcp:operator",
            facts=DECLARES,
        )
        lookup = LedgerEntry(
            id="ev_0003", agent="triage", tool="any_lookup", args={"technique_id": CHECKED}
        )

        questions, not_asked = judge_questions(
            _bundle().model_dump(), _isrs(), None, ledger=[answered, sample_text, lookup]
        )
        checked = [q.technique_id for q in questions if q.kind == "checked"]

        # A whole argument value first, then ids inside a longer one, then answers.
        assert checked == [CHECKED, *junk[: MAX_CHECKED_QUESTIONS - 1]]
        cut = [tid for tid, why in not_asked.items() if why == CHECKED_CAP_REASON]
        assert cut == [*junk[MAX_CHECKED_QUESTIONS - 1 :], "T1999.001"]

    def test_one_id_passed_in_fifty_thousand_entries_makes_a_short_line(self) -> None:
        ledger = [
            LedgerEntry(id=f"ev_{i:06d}", agent="triage", args={"ids": [CHECKED]})
            for i in range(50_000)
        ]

        (question,) = judge_questions(_bundle().model_dump(), _isrs(), None, ledger=ledger)[0]
        line = checked_question_line(question)

        assert line == ("triage in the arguments of ev_000000, ev_000001, ev_000002 and 49997 more")
        assert len(question.checked) == 50_000

    def _ask(
        self, monkeypatch: pytest.MonkeyPatch, room: int, *claims: ClaimEvidence
    ) -> tuple[TechniqueReview | None, _Llm]:
        llm = _Llm('[{"id": "T1124", "decision": "keep", "reason": "k"}]')
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
        monkeypatch.setattr(judge, "_question_room", lambda fixed, cap: room)
        review = asyncio.run(
            judge.decide_techniques(
                _bundle(),
                _isrs(*claims),
                reports={"triage": "r"},
                evidence_texts={},
                routed=WINDOWS,
                ledger=_ledger(),
            )
        )
        return review, llm

    def test_checked_techniques_take_only_the_room_the_window_has_left(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        claimed = ClaimEvidence(
            claim="The binary reads the system time",
            evidence_ref="[ev_0005]",
            confidence=0.6,
            technique_id="T1124",
        )

        review, llm = self._ask(monkeypatch, 100, claimed)

        assert review is not None
        # The claimed technique keeps its place; the checked one is left out and said.
        assert review.asked == ["T1124"]
        assert review.not_asked == {CHECKED: CHECKED_WINDOW_REASON}
        assert review.checked == {}
        text = str(llm.calls[0][1].content)
        assert CHECKED_LEFT_OUT_NOTICE.format(count=1) in text
        # No checked technique is asked, so the system text says none is.
        assert str(llm.calls[0][0].content) == TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS
        assert f"{CHECKED} " not in text.split("TECHNIQUES TO DECIDE", 1)[1]

        roomy, llm = self._ask(monkeypatch, 1_000_000, claimed)
        assert roomy is not None and roomy.asked == ["T1124", CHECKED]
        assert str(llm.calls[0][0].content) == (
            TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS + TECHNIQUE_QUESTION_CHECKED_NOTE
        )
        assert "NOTE: " not in str(llm.calls[0][1].content)

    def test_the_room_the_others_get_is_sized_without_the_checked_ones(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        claimed = ClaimEvidence(
            claim="The binary reads the system time",
            evidence_ref="[ev_0005]",
            confidence=0.6,
            technique_id="T1124",
        )
        sized: list[int] = []

        def room(fixed: int, cap: int) -> int:
            sized.append(fixed)
            return 1_000_000

        for ledger in (_ledger(), _ledger()[:2]):
            judge = JudgeAgent(llm=_Llm('[{"id": "T1124", "decision": "keep"}]'))  # type: ignore[arg-type]
            monkeypatch.setattr(judge, "_question_room", room)
            asyncio.run(
                judge.decide_techniques(
                    _bundle(), _isrs(claimed), evidence_texts={}, routed=WINDOWS, ledger=ledger
                )
            )

        # With the checked technique and without it, the others are given one room:
        # only the system text's sentence about checked techniques is weighed.
        assert len(sized) == 2
        assert sized[0] - sized[1] == len(TECHNIQUE_QUESTION_CHECKED_NOTE)

    def test_the_cards_go_in_only_where_room_is_left_after_the_checked_ones(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "malspark.agents.judge_agent.technique_card_lines", lambda tid: ["a card line"]
        )
        claimed = ClaimEvidence(
            claim="The binary reads the system time",
            evidence_ref="[ev_0005]",
            confidence=0.6,
            technique_id="T1124",
        )

        def asked(room: int) -> tuple[bool, str]:
            review, llm = self._ask(monkeypatch, room, claimed)
            text = str(llm.calls[0][1].content) if llm.calls else ""
            return review is not None and CHECKED in review.asked, text

        low, high = 0, 100_000
        assert asked(high)[0] and not asked(low)[0]
        while high - low > 1:
            middle = (low + high) // 2
            low, high = (low, middle) if asked(middle)[0] else (middle, high)
        # At the least room that holds the checked technique, none is left for cards.
        _kept, text = asked(high)
        assert "a card line" not in text
        assert "a card line" in asked(100_000)[1]

    def test_with_only_checked_techniques_and_no_room_nothing_is_asked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        review, llm = self._ask(monkeypatch, 10)

        assert llm.calls == []
        assert review == TechniqueReview(not_asked={CHECKED: CHECKED_WINDOW_REASON})


class TestTheReadersAreLinear:
    def test_the_question_text_is_linear_in_a_checked_question_s_places(self) -> None:
        def built(n: int) -> list[TechniqueQuestion]:
            return [
                TechniqueQuestion(
                    CHECKED,
                    "checked",
                    checked=[(f"a{i % 3}", f"ev_{i:06d}", "arguments") for i in range(n)],
                )
            ]

        assert_scales(built, 40_000, lambda q: technique_question_text(q, {}), factor=10)

    def test_one_string_with_many_distinct_ids_is_read_in_linear_time(self) -> None:
        def built(n: int) -> str:
            return " ".join(f"T{1000 + i // 1000}.{i % 1000:03d}" for i in range(n))

        assert_scales(built, 40_000, technique_ids_in, factor=10)


def _settled(decision: CheckedDecision, ledger: list[LedgerEntry], attck: Any = knowledge) -> Any:
    review = TechniqueReview(asked=[decision.technique_id], checked_decisions=[decision])
    out = settle_mapped_techniques(
        review, _bundle().model_dump(), _isrs(), WINDOWS, ledger=ledger, attck=attck
    )
    return out.checked_decisions[0]


def _map(*entries: str, reason: str = DESCRIBES) -> CheckedDecision:
    return CheckedDecision(
        technique_id=CHECKED, decision="map", reason=reason, evidence_ids=list(entries)
    )


class TestAMapRestsOnMoreThanItsLookup:
    def test_a_map_citing_only_the_lookups_of_its_id_is_declined(self) -> None:
        out = _settled(_map("ev_0010"), _ledger())

        assert (out.decision, out.declined_by_check) == (
            "decline",
            "attck.map_rests_on_its_lookup",
        )
        assert MAP_RESTS_ON_ITS_LOOKUP_CODE == out.declined_by_check

    def test_a_map_citing_a_lookup_and_another_entry_stands(self) -> None:
        out = _settled(_map("ev_0010", "ev_0004"), _ledger())

        assert (out.decision, out.declined_by_check) == ("map", "")

    def test_an_entry_whose_declared_answer_names_the_id_is_evidence(self) -> None:
        answered = LedgerEntry(
            id="ev_0011",
            agent="pack",
            tool="any_scanner",
            args={"rules": [CHECKED]},
            structured={"hits": [{"ttp": CHECKED}]},
            source="mcp:operator",
            facts=DECLARES,
        )

        out = _settled(_map("ev_0011"), _ledger(answered))

        assert (out.decision, out.declined_by_check) == ("map", "")

    def test_the_question_says_a_lookup_is_not_an_entry_it_rests_on(self) -> None:
        assert "(a lookup of it) is not an entry it rests on" in TECHNIQUE_MAP_FORM


class TestAMapReasonIsNoClaimSentence:
    """A map's reason is read as the claim's sentence for the absence and describe
    questions; an id it names beside the mapped one is no claim of the judge's and
    gets no question of its own."""

    REASON = f"{DESCRIBES}; the scanner's rule metadata also tags T1430, and its legacy tag T1064"

    def test_a_map_whose_reason_names_an_out_of_scope_and_a_retired_id_stands(self) -> None:
        out = _settled(_map("ev_0004", "ev_0005", reason=self.REASON), _ledger())

        assert (out.decision, out.declined_by_check, out.check_finding) == ("map", "", "")

    def test_the_capability_matrix_publishes_it(self) -> None:
        review = settle_mapped_techniques(
            TechniqueReview(
                asked=[CHECKED],
                checked_decisions=[_map("ev_0004", "ev_0005", reason=self.REASON)],
            ),
            _bundle().model_dump(),
            _isrs(),
            WINDOWS,
            ledger=_ledger(),
            attck=knowledge,
        )
        bundle = {**_bundle().model_dump(), TECHNIQUE_REVIEW_PROPERTY: review.model_dump()}

        _cells, mappings = build_capability_matrix(
            stix_output=bundle, isr_reports=_isrs(), sample=WINDOWS
        )

        assert CHECKED in {m.technique_id.upper() for m in mappings}


class TestWithNoCatalogue:
    def test_every_map_is_declined_as_not_checked(self) -> None:
        out = _settled(_map("ev_0004"), _ledger(), attck=None)

        assert (out.decision, out.declined_by_check, out.check_finding) == (
            "decline",
            CHECK_NOT_RUN,
            NO_CATALOGUE_FINDING,
        )


class TestAFreeTextAnswer:
    def test_a_decline_written_inside_a_sentence_is_a_decline_with_that_sentence(self) -> None:
        assert _line_map_decision(f"{CHECKED} — I decline to map it to anything") == (
            CHECKED,
            "decline",
            "I decline to map it to anything",
            [],
        )

    @pytest.mark.parametrize(
        "line",
        [
            f"{CHECKED} — do not map; the lookup is all there is",
            f"{CHECKED}: not mapped: the lookup is all there is",
        ],
    )
    def test_a_negated_map_is_the_judge_s_decline_with_its_sentence(self, line: str) -> None:
        tid, decision, reason, entries = _line_map_decision(line) or ("", "", "", [])

        assert (tid, decision, entries) == (CHECKED, "decline", [])
        assert reason.endswith("the lookup is all there is") and "map" in reason

    def test_a_map_stated_plainly_stays_a_map(self) -> None:
        assert _line_map_decision(f"{CHECKED}: map — ev_0004: the sample posts host data") == (
            CHECKED,
            "map",
            "the sample posts host data",
            ["ev_0004"],
        )

    def test_entries_written_before_the_decision_are_the_map_s(self) -> None:
        assert _line_map_decision(
            f"{CHECKED} (ev_0001, ev_0002) — map: the sample sends host data"
        ) == (CHECKED, "map", "the sample sends host data", ["ev_0001", "ev_0002"])

    def test_an_entry_the_reason_writes_is_not_one_the_map_cites(self) -> None:
        assert _line_map_decision(
            f"{CHECKED}: map — ev_0004: the sample, unlike ev_0009, posts host data"
        ) == (CHECKED, "map", "the sample, unlike ev_0009, posts host data", ["ev_0004"])


# The review's shape before the checked kind, as its reader declared it.
class _EarlierDecision(BaseModel):
    technique_id: str
    decision: Literal["keep", "drop"]
    reason: str = ""


class _EarlierReview(BaseModel):
    asked: list[str] = Field(default_factory=list)
    decisions: list[_EarlierDecision] = Field(default_factory=list)
    unanswered: str | None = None
    not_asked: dict[str, str] = Field(default_factory=dict)
    shortened: str | None = None
    undescribed: dict[str, str] = Field(default_factory=dict)


class TestTheEarlierReader:
    def test_a_new_review_with_a_keep_and_a_map_loads_with_its_keep(self) -> None:
        review = TechniqueReview(
            asked=["T1124", CHECKED],
            decisions=[TechniqueDecision(technique_id="T1124", decision="keep", reason="k")],
            checked_decisions=[_map("ev_0004")],
            checked={CHECKED: "triage in the arguments of ev_0010"},
        )

        earlier = _EarlierReview.model_validate(json.loads(review.model_dump_json()))

        assert [(d.technique_id, d.decision, d.reason) for d in earlier.decisions] == [
            ("T1124", "keep", "k")
        ]
        assert review.decision_for(CHECKED) == review.checked_decisions[0]


def _standing() -> TechniqueReview:
    return settle_mapped_techniques(
        TechniqueReview(asked=[CHECKED], checked_decisions=[_map("ev_0004", "ev_0005")]),
        _bundle().model_dump(),
        _isrs(),
        WINDOWS,
        ledger=_ledger(),
        attck=knowledge,
    )


def _exported(review: TechniqueReview) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from app.worker.analysis_worker import _extract_mitre

    judge = _bundle(malware=True)
    judge.x_malspark_technique_review = review
    report = MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=_isrs(),
        stix_output=judge.model_dump(mode="json"),
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        evidence_ledger=[],
    ).build_deterministic()
    bundle = ExtendedSTIXRenderer().render(
        report,
        judge,
        ledger_ids=[e.id for e in _ledger()],
    )
    mitre = _extract_mitre({"malware_report": report.model_dump(mode="json")}) or []
    return bundle.model_dump(mode="json")["objects"], mitre


class TestTheExport:
    def test_a_standing_map_reaches_the_stix_patterns_and_the_mitre_export(self) -> None:
        review = _standing()
        assert review.checked_decisions[0].decision == "map"

        objects, mitre = _exported(review)

        assert attack_pattern_id(CHECKED) in {o["id"] for o in objects}
        (edge,) = [
            o
            for o in objects
            if o["type"] == "relationship" and o.get("target_ref") == attack_pattern_id(CHECKED)
        ]
        assert edge[EVIDENCE_REFS_PROPERTY] == ["ev_0004", "ev_0005"]
        assert CHECKED in [row["technique_id"] for row in mitre]

    def test_a_declined_id_reaches_neither(self) -> None:
        declined = TechniqueReview(
            asked=[CHECKED],
            checked_decisions=[
                CheckedDecision(technique_id=CHECKED, decision="decline", reason="no path")
            ],
        )

        objects, mitre = _exported(declined)

        assert attack_pattern_id(CHECKED) not in {o["id"] for o in objects}
        assert CHECKED not in [row["technique_id"] for row in mitre]
