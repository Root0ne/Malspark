"""A finding of a report round names the statement it is about, without a value.

The narrative's and the composer's checks quoted the rejected sentence only
inside the message, so a finding about one sentence of a section could not say
which one. A finding now carries ``statements``: where in the checked answer
its statements stand, in the walk its ``path`` already uses (``key_findings.1``
is the second key finding) with the sentence's number after ``#`` where a
string holds several. A finding about the whole answer says ``*``. Where a
finding is about a statement is the only thing the locator holds: never the
sentence, never a value of the sample.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from malspark.pipeline.validation import (
    ABSENCE_CONTRADICTS_LEDGER_CODE,
    CITATION_NOT_EVIDENCE_CODE,
    CITATION_WRONG_ENTRY_CODE,
    ENTRY_CONTENTS_MISSTATED_CODE,
    REPEATED_ITEMS_CODE,
    STATED_VALUE_UNHELD_CODE,
    TECHNIQUE_NAME_CODE,
    UNCITED_CONFIGURATION_CODE,
    UNCITED_IDENTIFIER_CODE,
    UNGROUNDED_CAPABILITY_CODE,
    UNGROUNDED_FINDING_CODE,
    UNPUBLISHED_RECOMMENDATION_TECHNIQUE_CODE,
    CapabilityGrounding,
    EntryTexts,
    ValidationTally,
    Violation,
    citation_violations,
    configuration_citation_violations,
    identifier_citation_violations,
    key_finding_citation_violations,
    ledger_absence_contradictions,
    misstated_entry_contents,
    narrative_capability_violations,
    recommendation_technique_violations,
    repeated_item_violations,
    schema_violations,
    section_capability_violations,
    stated_value_violations,
    technique_name_violations,
    wrong_entry_citations,
)
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity, TTPMapping
from malspark.schemas.evidence import LedgerEntry
from tests.linear_cost import assert_scales

MARKER = "examplemark-7"
FILLER = "The sample is a console program."


def _entry(entry_id: str, tool: str, output: str) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="pipeline", server="pipeline", tool=tool, output=output)


def _texts() -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _entry("ev_0011", "get_file_report", json.dumps({"engines": 70})),
            _entry("ev_0012", "floss", json.dumps({"strings": [{"string": MARKER}]})),
        ]
    )


def _grounding() -> CapabilityGrounding:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_type="pe"),
        ttp_mappings=[TTPMapping(technique_id="T1027", technique_name="technique T1027")],
    )
    return CapabilityGrounding.from_report(report)


class TestASentenceOfAProseField:
    def test_a_wrongly_cited_value_names_its_sentence_in_the_body(self) -> None:
        body = f"{FILLER} It carries the marker `{MARKER}` [ev_0011]. {FILLER}"

        (found,) = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

        assert found.code == CITATION_WRONG_ENTRY_CODE
        assert found.statements == ("body#1",)

    def test_a_capability_names_the_summary_sentence_and_the_key_finding_row(self) -> None:
        payload = {
            "executive_summary": f"{FILLER} It performs data exfiltration of documents.",
            "key_findings": [
                {"text": "It runs on Windows.", "evidence_ids": []},
                {"text": "It performs data exfiltration over the network.", "evidence_ids": []},
            ],
        }

        found = narrative_capability_violations(payload, _grounding())

        (exfiltration,) = [v for v in found if v.path == "exfiltration"]
        assert exfiltration.code == UNGROUNDED_CAPABILITY_CODE
        assert exfiltration.statements == ("executive_summary#1", "key_findings.1.text")

    def test_a_section_capability_names_the_field_of_the_row(self) -> None:
        payload = {
            "text": "In conclusion:",
            "channels": [{"protocol": "https", "note": "used for command and control"}],
        }

        (found,) = section_capability_violations(payload, _grounding())

        assert found.statements == ("channels.0.note",)

    def test_a_technique_written_with_another_name_names_its_sentence(self) -> None:
        body = f"{FILLER} It pads the file, T1027 (Binary Padding). {FILLER}"

        (found,) = technique_name_violations({"body": body})

        assert found.code == TECHNIQUE_NAME_CODE
        assert found.statements == ("body#1",)

    def test_a_citation_that_is_no_evidence_names_its_sentence(self) -> None:
        body = f"{FILLER} It reads the key [ev_0099]."

        (found,) = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert found.code == CITATION_NOT_EVIDENCE_CODE
        assert found.statements == ("body#1",)

    def test_a_misstated_entry_names_its_sentence(self) -> None:
        entries = _texts()
        body = f"{FILLER} The entry ev_0012 holds nothing [ev_0012]."

        (found,) = misstated_entry_contents({"body": body}, entries)

        assert found.code == ENTRY_CONTENTS_MISSTATED_CODE
        assert found.statements == ("body#1",)

    def test_an_absence_the_ledger_contradicts_names_its_sentence(self) -> None:
        entries = EntryTexts.from_ledger(
            [
                LedgerEntry(
                    id="ev_0010",
                    agent="pipeline",
                    server="pipeline",
                    tool="batch_decompile",
                    args={"functions": "0xb670"},
                    output=json.dumps({"0xb670": "int f(void) { return 1; }"}),
                )
            ]
        )
        body = f"{FILLER} The body of 0xb670 is not in the evidence."

        (found,) = ledger_absence_contradictions({"body": body}, entries)

        assert found.code == ABSENCE_CONTRADICTS_LEDGER_CODE
        assert found.statements == ("body#1",)

    def test_a_locator_holds_no_word_of_the_sentence_and_no_value(self) -> None:
        body = f"{FILLER} It carries the marker `{MARKER}` [ev_0011]."

        (found,) = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

        assert MARKER not in " ".join(found.statements)
        assert all(word not in " ".join(found.statements) for word in FILLER.split())

    def test_a_key_that_is_not_a_field_name_is_not_written(self) -> None:
        payload = {f"{MARKER} 1": f"It carries the marker `{MARKER}` [ev_0011]."}

        (found,) = wrong_entry_citations(payload, _texts(), prose=())

        assert MARKER not in " ".join(found.statements)
        assert found.statements == ("?",)


class TestARowOfATable:
    def test_a_value_no_cited_entry_holds_names_its_row(self) -> None:
        payload = {
            "items": [
                {"key": "A", "value": MARKER, "evidence_refs": ["ev_0012"]},
                {"key": "B", "value": "never-seen-value", "evidence_refs": ["ev_0012"]},
            ]
        }

        (found,) = stated_value_violations(payload, _texts())

        assert found.code == STATED_VALUE_UNHELD_CODE
        assert found.statements == ("items.1.value",)

    def test_a_configuration_item_citing_nothing_names_its_row(self) -> None:
        payload = {
            "items": [
                {"key": "A", "value": "x", "how_obtained": "inferred", "evidence_refs": []},
                {"key": "B", "value": "y", "how_obtained": "decrypted", "evidence_refs": []},
            ]
        }

        (found,) = configuration_citation_violations(payload, ["ev_0011"])

        assert found.code == UNCITED_CONFIGURATION_CODE
        assert found.statements == ("items.1",)

    def test_a_host_identifier_citing_nothing_names_its_row(self) -> None:
        payload = {
            "identifiers": [
                {"kind": "k", "value": "x", "evidence_refs": ["ev_0011"]},
                {"kind": "k", "value": "y", "evidence_refs": []},
            ]
        }

        (found,) = identifier_citation_violations(payload, ["ev_0011"])

        assert found.code == UNCITED_IDENTIFIER_CODE
        assert found.statements == ("identifiers.1",)

    def test_a_key_finding_citing_no_entry_names_its_row(self) -> None:
        payload = {
            "key_findings": [
                {"text": "It runs.", "evidence_ids": ["ev_0011"]},
                {"text": "It spreads.", "evidence_ids": ["ev_0099"]},
            ]
        }

        (found,) = key_finding_citation_violations(payload, ["ev_0011"])

        assert found.code == UNGROUNDED_FINDING_CODE
        assert found.statements == ("key_findings.1",)

    def test_a_recommendation_naming_an_unpublished_technique_names_its_row(self) -> None:
        payload = {
            "defensive_recommendations": [
                {"action": "Hunt for T1027.", "rationale": "", "detection": ""},
                {"action": "Hunt for T1053.", "rationale": "", "detection": ""},
            ]
        }

        (found,) = recommendation_technique_violations(payload, ["T1027"])

        assert found.code == UNPUBLISHED_RECOMMENDATION_TECHNIQUE_CODE
        assert found.statements == ("defensive_recommendations.1",)

    def test_a_row_written_again_names_the_repeat(self) -> None:
        payload = {"items": [{"v": "x"}, {"v": "y"}, {"v": "x"}]}

        (found,) = repeated_item_violations(payload, {"items": ("v",)})

        assert found.code == REPEATED_ITEMS_CODE
        assert found.statements == ("items.2",)


class TestTheWholeAnswer:
    def test_a_schema_finding_names_the_field_it_is_about(self) -> None:
        class Out(BaseModel):
            body: str

        (found,) = schema_violations(Out, {"body": 3}, code="composer.schema")

        assert found.statements == ("body",)

    def test_a_schema_finding_without_a_field_is_about_the_whole_answer(self) -> None:
        class Out(BaseModel):
            body: str

        (unread,) = schema_violations(Out, None, code="composer.schema")
        (not_json,) = schema_violations(Out, None, code="composer.schema", answer="")

        assert unread.statements == ("*",)
        assert not_json.statements == ("*",)


class TestTheLocatorIsCarried:
    def test_a_summary_row_carries_it_and_an_unlocated_finding_none(self) -> None:
        located = Violation(code="a.b", message="m", statements=("body#1", "items.2"))
        bare = Violation(code="a.c", message="m")

        assert located.to_dict()["statements"] == "body#1,items.2"
        assert "statements" not in bare.to_dict()
        tally = ValidationTally()
        tally.record_unresolved("composer:x", [located, bare])
        assert tally.unresolved[0]["statements"] == "body#1,items.2"
        assert "statements" not in tally.unresolved[1]

    def test_a_stored_row_without_it_loads_as_before(self) -> None:
        row: dict[str, Any] = {"agent": "narrative", "code": "a.b", "message": "m"}

        assert Violation(code=row["code"], message=row["message"]).statements == ()


class TestTheCostIsLinear:
    def test_locating_grows_with_the_answer(self) -> None:
        entries = _texts()

        def _build(size: int) -> dict[str, str]:
            body = " ".join(f"Sentence number {n} is plain." for n in range(size))
            return {"body": f"{body} It carries the marker `{MARKER}` [ev_0011]."}

        def _call(payload: dict[str, str]) -> None:
            (found,) = wrong_entry_citations(payload, entries, prose=("body",))
            assert found.statements

        assert_scales(_build, 1000, _call, factor=8)
