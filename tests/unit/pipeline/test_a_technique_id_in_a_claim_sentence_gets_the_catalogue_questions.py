"""A technique id a claim's sentence names gets the catalogue's questions.

The id on a claim's TECHNIQUE line is asked whether the catalogue knows it and
whether it can apply to the sample's platform. An id the claim's sentence
names beside the line is asked the same two questions, once per block and id,
on a path that names the sentence (``claims[N].text.<id>``), where the caller
says the text is a claim's sentence (``claim_sentences``). It is not asked
whether the sentence describes it: a sentence names ids as metadata, headings
and associations it does not assert. An id the sentence negates, and an id the
block's TECHNIQUE line carries, are not asked here. A sentence id never marks
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
    settle_validation_marks,
    validate_isr,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

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
