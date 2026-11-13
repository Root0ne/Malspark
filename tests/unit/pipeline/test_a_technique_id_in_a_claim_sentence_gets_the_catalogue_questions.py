"""A technique id a claim's sentence names gets the catalogue's questions.

The id on a claim's TECHNIQUE line is asked whether the catalogue knows it and
whether it can apply to the sample's platform. An id the claim's sentence
names beside the line is asked the same two questions, once per block and id,
on a path that names the sentence (``claims[N].text.<id>``), where the caller
says the text is a claim's sentence (``claim_sentences``). It is not asked
whether the sentence describes it: a sentence names ids as metadata, headings
and associations it does not assert. An id the sentence negates or states as
absent, withdrawn or retired, before the id or after it, and does nothing
else with, and an id the block's TECHNIQUE line carries, are not asked here; a
sentence that goes on about the id or makes it a parenthetical remark is
asked. A long list of ids costs in proportion to its length. The question names two ways out
that are both true to the sentence: correct the id, or say plainly that the
technique is not asserted. A sentence id never marks
the claim's own technique invalid.

Every sentence and id here is made up for the test.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from malspark.agents.base_agent import BaseAnalyst
from malspark.pipeline.validation import (
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    PLATFORM_MISMATCH_CODE,
    VALIDITY_CODE,
    expected_technique_scope,
    sentence_technique_violations,
    settle_validation_marks,
    validate_isr,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, ClaimEvidence
from tests.linear_cost import assert_scales, assert_under

CATALOGUE: dict[str, dict[str, Any]] = {
    "T1027": {"domain": "enterprise", "platforms": ["Windows", "Linux"]},
    "T1055": {"domain": "enterprise", "platforms": ["Windows"]},
    "T1000": {"domain": "enterprise", "platforms": ["Linux"]},
    "T1583": {"domain": "enterprise", "platforms": ["PRE"]},
}
WINDOWS = {"platform": "windows", "file_type": "pe"}


class _Attck:
    """A stand-in for ``tools.knowledge`` that never loads the real bundle."""

    def attck_validate(self, ids: list[str]) -> dict[str, Any]:
        return {"invalid": [{"id": t} for t in ids if t not in CATALOGUE], "checked": len(ids)}

    def attck_lookup(self, technique_id: str) -> dict[str, Any]:
        row = CATALOGUE.get(technique_id, {})
        return {
            "valid": technique_id in CATALOGUE,
            "technique_id": technique_id,
            "name": technique_id,
            "domain": row.get("domain"),
            "platforms": list(row.get("platforms") or []),
            "tactics": [],
        }

    def attck_scope(self, technique_id: str) -> dict[str, Any]:
        row = CATALOGUE.get(technique_id, {})
        return {"domain": row.get("domain"), "platforms": list(row.get("platforms") or [])}


def _claim(text: str, technique: str | None = None) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0001]", confidence=0.6, technique_id=technique
    )


def _found(*claims: ClaimEvidence, attck: Any = None) -> list[Any]:
    isr = AgentISR(agent_id="static", domain="static", claims=list(claims))
    return validate_isr(
        isr,
        attck=_Attck() if attck is None else attck,
        ledger_ids=["ev_0001"],
        sample=WINDOWS,
        issued=1,
        claim_sentences=True,
    )


def _sentence(found: list[Any]) -> list[tuple[str, str, str]]:
    return [(v.code, v.path, v.subject) for v in found if ".text." in v.path]


class TestTheSentenceIds:
    def test_an_id_the_catalogue_does_not_hold_is_asked(self) -> None:
        found = _found(_claim("It decodes its payload, as T1999 names."))

        assert _sentence(found) == [(VALIDITY_CODE, "static.claims[0].text.T1999", "T1999")]
        assert "T1999" in found[0].message

    def test_an_id_of_another_platform_is_asked(self) -> None:
        found = _found(_claim("It reads its configuration (T1000)."))

        assert _sentence(found) == [
            (PLATFORM_MISMATCH_CODE, "static.claims[0].text.T1000", "T1000")
        ]

    def test_a_pre_only_id_is_not_asked(self) -> None:
        assert _sentence(_found(_claim("Its server was registered beforehand (T1583)."))) == []

    def test_an_id_the_sentence_negates_is_not_asked(self) -> None:
        assert _sentence(_found(_claim("There is no evidence of T1999 or T1000."))) == []

    def test_the_describe_question_is_never_asked_of_a_sentence_id(self) -> None:
        found = _found(_claim("The tool's metadata lists T1055 beside its rule name."))

        assert _sentence(found) == []
        assert CLAIM_DOES_NOT_DESCRIBE_CODE not in {v.code for v in found}

    def test_the_block_s_own_technique_is_not_asked_again(self) -> None:
        found = _found(_claim("It writes into another process (T1000).", technique="T1000"))

        assert _sentence(found) == []
        assert [v.code for v in found] == [PLATFORM_MISMATCH_CODE]

    def test_one_id_named_twice_is_asked_once(self) -> None:
        assert len(_sentence(_found(_claim("T1999 then T1999 again.")))) == 1

    def test_no_catalogue_asks_nothing(self) -> None:
        isr = AgentISR(agent_id="static", domain="static", claims=[_claim("It is T1999.")])

        assert (
            _sentence(
                validate_isr(
                    isr, attck=None, ledger_ids=["ev_0001"], sample=WINDOWS, claim_sentences=True
                )
            )
            == []
        )

    def test_a_sentence_id_never_marks_the_claim_s_own_technique(self) -> None:
        claim = _claim("It hides its strings, unlike T1999.", technique="T1027")
        isr = AgentISR(agent_id="static", domain="static", claims=[claim])
        found = validate_isr(
            isr, attck=_Attck(), ledger_ids=["ev_0001"], sample=WINDOWS, claim_sentences=True
        )

        settle_validation_marks(isr, found)

        assert _sentence(found) == [(VALIDITY_CODE, "static.claims[0].text.T1999", "T1999")]
        assert claim.technique_id_valid is not False

    def test_a_caller_with_no_claim_sentence_is_asked_nothing_of_one(self) -> None:
        isr = AgentISR(agent_id="judge", domain="judge", claims=[_claim("It is T1999 (T1000).")])

        found = validate_isr(
            isr, attck=_Attck(), ledger_ids=["ev_0001"], sample=WINDOWS, claim_sentences=False
        )

        assert _sentence(found) == []


class TestAnIdTheSentenceStatesAbsent:
    """An id the sentence states as absent, withdrawn or retired, before it or after
    it, is not asked; the same id the sentence asserts is."""

    STATED_ABSENT = (
        "T1000 is not asserted because no Linux call exists.",
        "Location tracking (T1000) is withdrawn.",
        "Startup-folder persistence (T1000) is dropped.",
        "The earlier Startup-folder (T1000) reading is withdrawn and is not asserted here.",
        "The report's T1000 entry is not supported.",
        "The report withdraws T1000.",
        "The scanner's T1999 identifier is not adopted.",
        "The rule's legacy tag T1999 is retired.",
        "The rule's tag is T1999 (deprecated).",
        "The scanner also tags T1000, not asserted.",
        'The scanner\'s rule label "Location Tracking (T1000)" is not asserted.',
        "T1999 and T1000 are not asserted.",
    )

    def test_each_form_is_not_asked(self) -> None:
        for text in self.STATED_ABSENT:
            assert _sentence(_found(_claim(text))) == [], text

    ASSERTED = (
        ("It reads its configuration (T1000), as the scanner asserts.", "T1000"),
        ("The payload (T1000) was dropped to the temporary folder.", "T1000"),
        ("The loader (T1000) is dropped and run.", "T1000"),
        ("T1999 is used, and the earlier reading is withdrawn.", "T1999"),
        ("The rule's tag T1999 is not retired.", "T1999"),
    )

    def test_the_same_id_asserted_is_asked(self) -> None:
        for text, tid in self.ASSERTED:
            assert [subject for _c, _p, subject in _sentence(_found(_claim(text)))] == [tid], text

    # A sentence that does more with the id than state it absent: the predicate
    # does not end its clause, the id is a parenthetical remark's subject only,
    # or a later clause turns or goes on.
    DOES_MORE = (
        ("T1000 is not asserted by the scanner but is shown by the code at 0x401000", "T1000"),
        ("T1000 is not asserted by the scanner, but the code at 0x401000 performs it", "T1000"),
        ("T1000 is not asserted here, yet the code at 0x401000 reads the GPS fix", "T1000"),
        ("T1000 was not supported by evidence but is performed", "T1000"),
        ("T1000 is retired as a label, but the sample performs location tracking", "T1000"),
        (
            "T1000 location capture is withdrawn from the old binary and now performed live",
            "T1000",
        ),
        ("T1000 (deprecated name) tracks the device location", "T1000"),
        ("T1999 is deprecated in favour of T1027 and the sample uses it", "T1999"),
        ("T1000, not asserted, but it tracks location", "T1000"),
        # Hard cases of the same reading.
        ("T1000 is withdrawn; however, the code at 0x401000 performs it.", "T1000"),
        ("T1000 is not asserted, the sample reads the GPS fix.", "T1000"),
        ("The report withdraws T1000 but the code performs it.", "T1000"),
        ("T1000 is withdrawn and the sample uses it.", "T1000"),
        ("The payload (T1000) is dropped, then run.", "T1000"),
        ("No evidence of T1000 is retired, but the code at 0x401000 performs it.", "T1000"),
        ("T1000 is not asserted though the code reads the GPS fix.", "T1000"),
        ("T1000, not asserted, is what the code at 0x401000 does.", "T1000"),
        ("T1000 (deprecated) is used by the sample.", "T1000"),
        ("The location (T1000) entry is withdrawn and replaced by T1027.", "T1000"),
        ("The report withdraws its earlier T1000 reading of the GPS call.", "T1000"),
    )

    def test_a_sentence_that_does_more_with_the_id_is_asked(self) -> None:
        for text, tid in self.DOES_MORE:
            assert [subject for _c, _p, subject in _sentence(_found(_claim(text)))] == [tid], text

    STAYS = (
        ("T1000 was dropped by the loader into %TEMP%", ["T1000"]),
        ("the retired T1999 behaviour is used here", ["T1999"]),
        ("T1000 is not retired", ["T1000"]),
        ("T1000 remains supported", ["T1000"]),
        ("T1000, not T1055, is supported", ["T1000"]),
        ("T1000 is asserted; T1998 is not asserted", ["T1000"]),
        ("T1000 is used and T1998 is not asserted", ["T1000"]),
        ("T1000, T1998 and T1999 are not asserted", []),
        ("'T1000' is NOT ASSERTED", []),
        ("(T1000) is withdrawn", []),
        ("T1000 Is Withdrawn.", []),
        ("the report withdraws its earlier T1000", []),
        ("T1000 is not asserted.", []),
        ("T1000 is withdrawn", []),
        ("Location tracking (T1000) is withdrawn", []),
        ("capa also tags T1000, not asserted", []),
        # Hard cases that state the id absent and do nothing else with it.
        ("T1000 is not asserted; T1027 is used.", []),
        ("T1999 is not asserted by the scanner here.", []),
        ("T1999 is deprecated in favour of T1027.", []),
        ("The report withdraws T1000 and T1998.", []),
        ("T1000 is withdrawn and is not asserted here.", []),
        ("No GPS API is imported, so T1000 is not asserted.", []),
        ("T1000 is not asserted because the scanner reads only a string.", []),
        ("T1000 is not asserted. The code at 0x401000 hides a window.", []),
        ("T1000 (deprecated); T1027 is used.", []),
        ("T1000 is not asserted (no GPS API).", []),
        # A negation before the statement is the shared reader's to read.
        ("no evidence of T1000 is retired", []),
        ("neither T1000 nor T1998 is retired", []),
        ("No T1000 activity was withdrawn", []),
        ("no sign of T1000 is withdrawn either", []),
        ("it is not the case that T1000 is not asserted", []),
    )

    def test_a_sentence_that_only_states_the_id_absent_is_read_as_before(self) -> None:
        for text, asked in self.STAYS:
            assert [subject for _c, _p, subject in _sentence(_found(_claim(text)))] == asked, text

    @staticmethod
    def _id_list(size: int) -> str:
        return "T1000" + ", T1998" * size + " are not asserted"

    def test_a_long_id_list_costs_in_proportion_to_its_length(self) -> None:
        scope = expected_technique_scope(WINDOWS)

        def read(text: str) -> None:
            assert sentence_technique_violations(text, set(), _Attck(), scope, path="c") == []

        assert_scales(self._id_list, 4000, read, factor=4)
        text = self._id_list(16000)
        assert_under(lambda: read(text), 1.0, what="a list of 16,000 ids")

    def test_the_question_names_two_ways_out_both_true_to_the_sentence(self) -> None:
        for text in ("It decodes its payload, as T1999 names.", "It reads its file (T1000)."):
            (found,) = [v for v in _found(_claim(text)) if ".text." in v.path]
            tid = found.subject

            assert "correct the id" in found.message
            assert f'"{tid} is not asserted"' in found.message
            assert "leave" not in found.message and "drop" not in found.message
            assert "remove" not in found.message
            # The example the question gives is itself read as a statement of absence.
            assert _sentence(_found(_claim(f"{tid} is not asserted."))) == []


# ---------------------------------------------------------------------------
# Through the analyst's validation turn
# ---------------------------------------------------------------------------

NAMED = (
    "CLAIM 1: The sample reads a file, which its metadata files under T1059.099.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)


class _Analyst(BaseAnalyst):
    def __init__(self) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self._evidence_entries = [LedgerEntry(id="ev_0003", tool="any_reader", output="file")]
        self._budget_records: list[dict[str, Any]] = [{"agent": "reverser"}]
        self.seen_turns: list[Any] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(messages)
        return NAMED


def test_the_turn_records_the_sentence_id_s_question_in_record_only(monkeypatch: Any) -> None:
    from malspark.core.settings_overrides import build_settings

    built = build_settings({"validation": {"feedback": "record_only"}})
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)
    analyst = _Analyst()
    analyst._container = SimpleNamespace(event_sink=object())
    isr = analyst._text_to_isr(NAMED, 0)
    with (
        patch("malspark.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", lambda *_a: True),
        patch.object(BaseAnalyst, "_seconds_the_last_loop_left", return_value=None),
        patch.object(BaseAnalyst, "_callees_to_ask", return_value=None),
        patch("malspark.pipeline.validation.emit_validation_feedback", lambda _sink, **kw: None),
    ):
        analyst._validate_isr(isr, "evidence")

    assert analyst.seen_turns == []
    (found,) = [v for v in analyst.validation_findings if ".text." in v.path]
    assert (found.code, found.subject, found.asked) == (VALIDITY_CODE, "T1059.099", False)
