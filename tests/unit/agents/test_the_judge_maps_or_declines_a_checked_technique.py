"""A technique an agent checked that nothing carries goes to the judge, to map or to decline.

One run's triage validated T1041 and filed no claim with it, so it was in no
published list although the report stated the behaviour. Such an id is now
put in the one question the judge is already asked after its verdict, as a
``checked`` technique: the judge maps it to the ledger entries it rests on or
declines it with a reason. A map is checked as an analyst's claim of the
technique is, and one that fails a check is recorded as declined by it and
never published; one that passes is published like a technique the judge
states, its entries as its sources. A declined id is recorded on the review
and adds nothing to the printed report.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

from malspark.agents.judge_agent import (
    QUESTION_CLAIM_ENTRIES_HEADING,
    TECHNIQUE_ANSWER_FORM,
    TECHNIQUE_MAP_FORM,
    TECHNIQUE_QUESTION_CHECKED_NOTE,
    TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS,
    JudgeAgent,
    TechniqueMapAnswer,
    _structured_decisions,
    read_technique_answer,
    technique_question_text,
)
from malspark.extractors.capability_matrix import (
    build_capability_matrix,
    judge_questions,
    settle_mapped_techniques,
)
from malspark.memory.attck_loader import technique_label
from malspark.memory.technique_cards import technique_card_lines
from malspark.pipeline.validation import (
    ABSENCE_CLAIM_CODE,
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    PARENT_OF_A_PUBLISHED_SUB_TECHNIQUE_CODE,
    PLATFORM_MISMATCH_CODE,
    UNGROUNDED_TECHNIQUE_CODE,
)
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import JUDGE_ONLY_TECHNIQUE_MARKER, AgentISR, ClaimEvidence
from malspark.schemas.stix_models import Bundle, TechniqueDecision, TechniqueReview
from malspark.tools import knowledge

CHECKED = "T1041"  # Exfiltration Over C2 Channel: validated, on no claim
CARRIED = "T1071.001"  # Web Protocols: claimed and in the bundle
DESCRIBES = "The beacon sends the host data it collected out over its command and control channel"
WINDOWS = {"platform": "windows", "file_type": "pe"}


def _pattern(tid: str, name: str, n: int) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--0f1e2d3c-4b5a-4968-8776-65544333221{n}",
        "name": name,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _bundle(*patterns: dict[str, Any]) -> Bundle:
    return Bundle.model_validate(
        {"objects": list(patterns) or [_pattern(CARRIED, "Web Protocols", 1)]}
    )


def _claim(text: str, tid: str | None, ref: str) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.7, technique_id=tid)


def _isrs(*claims: ClaimEvidence) -> dict[str, AgentISR]:
    return {
        "triage": AgentISR(
            agent_id="triage",
            domain="static",
            claims=list(claims)
            or [
                _claim(
                    "The beacon posts its form fields over HTTP", CARRIED, "[ev_0004], [ev_0005]"
                )
            ],
        )
    }


def _ledger(*ids: str) -> list[LedgerEntry]:
    return [
        LedgerEntry(id="ev_0004", agent="triage", tool="any_reader", output="POST /gate"),
        LedgerEntry(id="ev_0005", agent="triage", tool="any_reader", output="counter=1&os=10"),
        LedgerEntry(
            id="ev_0010",
            agent="triage",
            tool="any_validator",
            args={"ids": list(ids) or [CARRIED, CHECKED]},
            output='{"invalid": []}',
        ),
    ]


class _Llm:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content=self.answer)


def _ask(
    answer: str,
    *,
    ledger: list[LedgerEntry] | None = None,
    isrs: dict[str, AgentISR] | None = None,
    bundle: Bundle | None = None,
) -> tuple[TechniqueReview | None, _Llm]:
    llm = _Llm(answer)
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    review = asyncio.run(
        judge.decide_techniques(
            bundle or _bundle(),
            isrs or _isrs(),
            reports={"triage": "r"},
            evidence_texts={},
            routed=WINDOWS,
            ledger=ledger if ledger is not None else _ledger(),
        )
    )
    return review, llm


def _map(reason: str = DESCRIBES, entries: list[str] | None = None, tid: str = CHECKED) -> str:
    return json.dumps(
        [
            {
                "id": tid,
                "decision": "map",
                "evidence_ids": ["ev_0004", "ev_0005"] if entries is None else entries,
                "reason": reason,
            }
        ]
    )


class TestTheQuestion:
    def test_a_checked_technique_is_asked_with_where_it_was_seen_and_its_card(self) -> None:
        questions, _not_asked = judge_questions(
            _bundle().model_dump(), _isrs(), WINDOWS, ledger=_ledger()
        )
        (question,) = questions
        text = technique_question_text(questions, {})

        assert (question.technique_id, question.kind) == (CHECKED, "checked")
        assert (
            f"1. {technique_label(CHECKED)} — checked by triage in the arguments of ev_0010; "
            "on no claim, finding or bundle object"
        ) in text
        assert f"{QUESTION_CLAIM_ENTRIES_HEADING}\n- triage: ev_0004, ev_0005" in text
        for line in technique_card_lines(CHECKED):
            assert f"   {line}" in text
        assert text.endswith(TECHNIQUE_ANSWER_FORM + "\n" + TECHNIQUE_MAP_FORM)
        # The entries are listed by id, not shown: nothing is cited.
        assert "EVIDENCE CITED" not in text

    def test_the_system_text_says_what_a_checked_technique_is(self) -> None:
        _review, llm = _ask(_map())

        assert llm.calls[0][0].content == (
            TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS + TECHNIQUE_QUESTION_CHECKED_NOTE
        )

    def test_with_nothing_checked_the_question_is_byte_identical(self) -> None:
        # The same run with the validator naming only the carried id, and with
        # no ledger id in any argument: the question reads as it did before.
        isrs = _isrs(
            _claim("The beacon posts its form fields over HTTP", CARRIED, "[ev_0004]"),
            _claim("The binary reads the system time", "T1124", "[ev_0005]"),
        )
        _r1, carried_only = _ask(
            '[{"id": "T1124", "decision": "keep", "reason": "x"}]',
            ledger=_ledger(CARRIED),
            isrs=isrs,
        )
        _r2, without_ids = _ask(
            '[{"id": "T1124", "decision": "keep", "reason": "x"}]',
            ledger=[e.model_copy(update={"args": {}}) for e in _ledger()],
            isrs=isrs,
        )
        sent = [str(m.content) for m in carried_only.calls[0]]

        assert sent == [str(m.content) for m in without_ids.calls[0]]
        assert sent[0] == TECHNIQUE_QUESTION_SYSTEM_WITHOUT_TOOLS
        assert sent[1].endswith("\n\n" + TECHNIQUE_ANSWER_FORM)
        assert QUESTION_CLAIM_ENTRIES_HEADING not in sent[1]

    def test_an_id_the_catalogue_rejects_is_not_asked_and_says_why(self) -> None:
        questions, not_asked = judge_questions(
            _bundle().model_dump(), _isrs(), WINDOWS, ledger=_ledger(CARRIED, "T1999")
        )

        assert questions == []
        assert not_asked["T1999"].startswith("not asked: ")


class TestTheAnswer:
    def test_a_map_is_read_with_its_entries_and_a_decline_with_its_reason(self) -> None:
        answer = json.dumps(
            [
                {"id": CHECKED, "decision": "map", "evidence_ids": ["EV_0004"], "reason": "r1"},
                {"id": "T1083", "decision": "decline", "reason": "nothing lists files"},
                {"id": "T1124", "decision": "keep", "reason": "r3"},
            ]
        )

        read = read_technique_answer(answer, [CHECKED, "T1083", "T1124"], {CHECKED, "T1083"})

        assert [(d.technique_id, d.decision, d.reason, d.evidence_ids) for d in read] == [
            (CHECKED, "map", "r1", ["ev_0004"]),
            ("T1083", "decline", "nothing lists files", []),
            ("T1124", "keep", "r3", []),
        ]

    def test_a_line_answer_reads_a_map_s_entries_after_its_decision(self) -> None:
        text = f"{CHECKED}: map — ev_0004, ev_0005: the beacon posts host data\nT1083: decline: no"

        read = read_technique_answer(text, [CHECKED, "T1083"], {CHECKED, "T1083"})

        assert [(d.decision, d.evidence_ids) for d in read] == [
            ("map", ["ev_0004", "ev_0005"]),
            ("decline", []),
        ]

    def test_an_answer_in_the_other_kind_s_form_leaves_the_id_undecided(self) -> None:
        answer = json.dumps(
            [
                {"id": CHECKED, "decision": "keep", "reason": "kept"},
                {"id": "T1124", "decision": "map", "evidence_ids": ["ev_0004"]},
                {"id": "T1083", "decision": "map it", "evidence_ids": ["ev_0004"]},
            ]
        )

        assert read_technique_answer(answer, [CHECKED, "T1124", "T1083"], {CHECKED, "T1083"}) == []

    def test_a_malformed_answer_is_unanswered_as_before(self) -> None:
        review, _llm = _ask("I would map it, probably.")

        assert review is not None
        assert review.decisions == []
        assert (
            review.unanswered
            == "the answer named none of the techniques in a form that could be read"
        )
        assert review.checked == {CHECKED: "triage in the arguments of ev_0010"}

    def test_a_provider_with_structured_output_is_asked_for_the_map_form(
        self, monkeypatch: Any
    ) -> None:
        offered: list[Any] = []
        parsed = TechniqueMapAnswer.model_validate(
            {
                "decisions": [
                    {
                        "id": CHECKED,
                        "decision": "map",
                        "evidence_ids": ["ev_0004"],
                        "reason": DESCRIBES,
                    }
                ]
            }
        )

        class _Structured:
            async def ainvoke(self, messages: list[Any]) -> Any:
                return {"raw": MagicMock(content="{}"), "parsed": parsed, "parsing_error": None}

        judge = JudgeAgent(llm=MagicMock())
        monkeypatch.setattr(judge, "_supports_structured_output", lambda: True)
        monkeypatch.setattr(judge, "_reading_model", lambda ledger, schemas: (None, None))
        monkeypatch.setattr("malspark.llm.registry.schema_tool_worth_offering", lambda llm: True)
        judge.llm.with_structured_output = lambda model, **k: (
            offered.append(model),
            _Structured(),
        )[1]

        review = asyncio.run(
            judge.decide_techniques(
                _bundle(), _isrs(), evidence_texts={}, routed=WINDOWS, ledger=_ledger()
            )
        )

        assert offered == [TechniqueMapAnswer]
        assert review is not None
        assert [(d.decision, d.evidence_ids) for d in review.decisions] == [("map", ["ev_0004"])]

    def test_a_structured_answer_is_read_by_kind(self) -> None:
        parsed = TechniqueMapAnswer.model_validate(
            {
                "decisions": [
                    {"id": CHECKED, "decision": "map", "evidence_ids": ["ev_0005"], "reason": "r"},
                    {"id": "T1124", "decision": "drop", "reason": "no"},
                ]
            }
        )

        read = _structured_decisions(parsed, [CHECKED, "T1124"], {CHECKED})

        assert [(d.technique_id, d.decision, d.evidence_ids) for d in read] == [
            (CHECKED, "map", ["ev_0005"]),
            ("T1124", "drop", []),
        ]


def _settled(decision: TechniqueDecision, **kwargs: Any) -> TechniqueDecision:
    review = TechniqueReview(asked=[decision.technique_id], decisions=[decision])
    settled = settle_mapped_techniques(
        review,
        kwargs.get("bundle", _bundle()).model_dump(),
        kwargs.get("isrs", _isrs()),
        kwargs.get("sample", WINDOWS),
        ledger=_ledger(),
        attck=knowledge,
    )
    (out,) = settled.decisions
    return out


def _mapped(reason: str = DESCRIBES, entries: list[str] | None = None, tid: str = CHECKED) -> Any:
    return TechniqueDecision(
        technique_id=tid,
        decision="map",
        reason=reason,
        evidence_ids=["ev_0004", "ev_0005"] if entries is None else entries,
    )


class TestTheChecks:
    def test_a_map_every_check_passes_stands(self) -> None:
        out = _settled(_mapped())

        assert (out.decision, out.declined_by_check, out.evidence_ids) == (
            "map",
            "",
            ["ev_0004", "ev_0005"],
        )

    def test_a_map_with_no_entry_or_an_entry_the_run_never_recorded_is_declined(self) -> None:
        for entries, said in (([], "cites no ledger entry"), (["ev_0004", "ev_0099"], "ev_0099")):
            out = _settled(_mapped(entries=entries))

            assert (out.decision, out.declined_by_check) == ("decline", UNGROUNDED_TECHNIQUE_CODE)
            assert said in out.check_finding
            # The judge's own entries and reason are kept beside the check's.
            assert (out.evidence_ids, out.reason) == (entries, DESCRIBES)

    def test_a_map_whose_reason_does_not_describe_it_is_declined_by_the_describe_check(
        self,
    ) -> None:
        out = _settled(_mapped(reason="The analyst validated this id earlier in the run"))

        assert (out.decision, out.declined_by_check) == ("decline", CLAIM_DOES_NOT_DESCRIBE_CODE)

    def test_a_map_whose_reason_states_absence_is_declined(self) -> None:
        out = _settled(
            _mapped(reason="No data is exfiltrated over the command and control channel")
        )

        assert (out.decision, out.declined_by_check) == ("decline", ABSENCE_CLAIM_CODE)

    def test_a_map_the_sample_cannot_host_is_declined_by_the_scope_check(self) -> None:
        out = _settled(_mapped(), sample={"platform": "android", "file_type": "apk"})

        assert (out.decision, out.declined_by_check) == ("decline", PLATFORM_MISMATCH_CODE)

    def test_a_mapped_parent_of_a_published_sub_technique_is_declined(self) -> None:
        bundle = _bundle(_pattern("T1547.001", "Registry Run Keys / Startup Folder", 2))
        isrs = _isrs(_claim("The sample adds a Run key", "T1547.001", "[ev_0004]"))
        reason = "The sample sets a Run key so that it starts at boot or logon"

        parent = _settled(_mapped(reason=reason, tid="T1547"), bundle=bundle, isrs=isrs)

        assert (parent.decision, parent.declined_by_check) == (
            "decline",
            "attck.parent_of_a_published_sub_technique",
        )
        assert PARENT_OF_A_PUBLISHED_SUB_TECHNIQUE_CODE == parent.declined_by_check
        assert "T1547.001" in parent.check_finding

    def test_a_mapped_sub_technique_of_a_published_parent_stands(self) -> None:
        bundle = _bundle(_pattern("T1547", "Boot or Logon Autostart Execution", 2))
        isrs = _isrs(_claim("The sample starts at logon", "T1547", "[ev_0004]"))
        reason = "The sample writes its path under the Run key of the registry to start at logon"

        sub = _settled(_mapped(reason=reason, tid="T1547.001"), bundle=bundle, isrs=isrs)

        assert (sub.decision, sub.declined_by_check) == ("map", "")

    def test_the_judge_s_answer_is_settled_before_it_is_returned(self) -> None:
        review, _llm = _ask(_map(entries=["ev_0042"]))

        assert review is not None
        (decision,) = review.decisions
        assert (decision.decision, decision.declined_by_check) == (
            "decline",
            UNGROUNDED_TECHNIQUE_CODE,
        )


def _matrix(review: TechniqueReview) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = _bundle()
    bundle.x_malspark_technique_review = review
    cells, mappings = build_capability_matrix(
        stix_output=bundle.model_dump(), isr_reports=_isrs(), sample=WINDOWS, ledger=_ledger()
    )
    return {c.technique_id: c for c in cells}, {m.technique_id: m for m in mappings}


class TestPublishing:
    def test_a_map_that_stands_is_published_on_its_entries_and_marked_as_the_judge_s(
        self,
    ) -> None:
        review, _llm = _ask(_map())
        assert review is not None

        cells, mappings = _matrix(review)

        assert mappings[CHECKED].sources == ["ev_0004", "ev_0005"]
        assert mappings[CHECKED].contributing_layers == ["judge"]
        assert JUDGE_ONLY_TECHNIQUE_MARKER in cells[CHECKED].note
        assert cells[CHECKED].not_published == ""

    def test_every_published_technique_cites_a_ledger_entry(self) -> None:
        review, _llm = _ask(_map())
        assert review is not None
        # A map with no entry, written straight onto a review, is not published either.
        bare = review.model_copy(
            update={"decisions": [*review.decisions, _mapped(entries=[], tid="T1083")]}
        )

        _cells, mappings = _matrix(bare)

        assert set(mappings) == {CARRIED, CHECKED}
        for mapping in mappings.values():
            assert any(s.startswith("ev_") for s in mapping.sources), mapping.technique_id

    def test_a_declined_id_is_recorded_on_the_review_and_prints_nothing(self) -> None:
        declined, _llm = _ask(
            json.dumps([{"id": CHECKED, "decision": "decline", "reason": "no data path is shown"}])
        )
        by_check, _llm = _ask(_map(reason="validated earlier"))
        assert declined is not None and by_check is not None

        for review in (declined, by_check):
            cells, mappings = _matrix(review)
            assert CHECKED not in cells and CHECKED not in mappings
            report = MalwareReport(
                identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
                capability_matrix=list(cells.values()),
                ttp_mappings=list(mappings.values()),
            )
            assert CHECKED not in MarkdownRenderer().render(report)
        assert declined.decision_for(CHECKED) is not None
        assert declined.decision_for(CHECKED).reason == "no data path is shown"  # type: ignore[union-attr]
        assert by_check.decision_for(CHECKED).declined_by_check == CLAIM_DOES_NOT_DESCRIBE_CODE  # type: ignore[union-attr]

    def test_the_mapped_technique_reaches_the_published_list_the_export_reads(self) -> None:
        review, _llm = _ask(_map())
        assert review is not None
        cells, mappings = _matrix(review)
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            capability_matrix=list(cells.values()),
            ttp_mappings=list(mappings.values()),
        )

        assert CHECKED in MarkdownRenderer().render(report)


class TestAnEarlierDocument:
    def test_a_review_written_before_the_checked_kind_reads_and_dumps_as_it_did(self) -> None:
        stored = {
            "asked": ["T1055"],
            "decisions": [{"technique_id": "T1055", "decision": "drop", "reason": "no write"}],
            "unanswered": None,
            "not_asked": {},
            "shortened": None,
            "undescribed": {},
        }

        review = TechniqueReview.model_validate(stored)

        assert review.checked == {}
        assert review.decisions[0].evidence_ids == []
        # Nothing the checked kind added is written for it.
        dumped = review.model_dump()
        assert "checked" not in dumped
        assert dumped["decisions"] == stored["decisions"]

    def test_a_bundle_carrying_an_earlier_review_builds_the_same_matrix(self) -> None:
        bundle = _bundle()
        bundle.x_malspark_technique_review = TechniqueReview.model_validate(
            {"asked": [CARRIED], "decisions": [{"technique_id": CARRIED, "decision": "keep"}]}
        )

        cells, mappings = build_capability_matrix(
            stix_output=bundle.model_dump(), isr_reports=_isrs()
        )

        assert [c.technique_id for c in cells] == [CARRIED]
        assert [m.technique_id for m in mappings] == [CARRIED]
