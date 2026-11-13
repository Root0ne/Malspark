"""Every entry id a composed section writes, in any field, is one the run issued.

The bracket reading of a section's prose asks about a citation that is not an
id it may cite. A composed section is the composer model's own in every
field, so its answer is read a second way as well: each ``ev_`` id written
anywhere in it, a citing field or a record's text, bracketed or not, that the
run did not issue is asked about once under ``report.citation_not_evidence``.
A code span is not read, nor an item id. A configuration or identifier row the
row's own check already asks about for citing no entry is left to that
question, and the narrative's key findings, which their own check reads, are
not read this way.

Every sentence and id here is made up for the test.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

from malspark.pipeline.validation import (
    CITATION_NOT_EVIDENCE_CODE,
    UNCITED_CONFIGURATION_CODE,
    UNCITED_IDENTIFIER_CODE,
    citation_violations,
    configuration_citation_violations,
    identifier_citation_violations,
    key_finding_citation_violations,
)
from malspark.reporting.composer import ReportComposer
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.narrative_agent import NARRATIVE_PROSE

ISSUED = ["ev_0001", "ev_0002", "ev_0003"]


def _asked(payload: Any, citable: list[str] = ISSUED, **kw: Any) -> list[str]:
    found = citation_violations(payload, citable, records=True, **kw)
    assert {v.code for v in found} <= {CITATION_NOT_EVIDENCE_CODE}
    return [v.message.split(" ", 1)[0].strip("[]") for v in found]


class TestTheRecordReading:
    def test_an_unissued_id_in_a_citing_field_is_asked(self) -> None:
        payload = {"commands": [{"command": "0x01", "evidence_refs": ["ev_0002", "ev_0099"]}]}

        assert _asked(payload) == ["ev_0099"]

    def test_an_unissued_id_in_a_record_s_text_is_asked(self) -> None:
        payload = {"encryption_scheme": {"key_source": "derived from the host name (ev_0042)"}}

        assert _asked(payload) == ["ev_0042"]

    def test_an_unbracketed_id_in_prose_is_asked(self) -> None:
        assert _asked({"body": "The loader decodes it, as ev_0077 holds."}, prose=("body",)) == [
            "ev_0077"
        ]

    def test_the_message_writes_the_id_as_it_stands_with_a_remedy_for_a_citing_field(
        self,
    ) -> None:
        payload = {"commands": [{"command": "0x01", "evidence_refs": ["ev_0099"]}]}

        (found,) = citation_violations(payload, ISSUED, prose=(), records=True)

        assert found.message.startswith("ev_0099 is not an entry this answer was shown.")
        assert "[ev_0099]" not in found.message
        assert "in brackets" not in found.message and "sentence" not in found.message
        assert "in its place" in found.message
        assert "ev_0001, ev_0002, ev_0003" in found.message

    def test_an_issued_id_of_any_agent_is_not_asked(self) -> None:
        assert _asked({"flags": [{"flag": "-k", "evidence_ref": "ev_0003"}]}) == []

    def test_item_ids_are_not_read(self) -> None:
        assert (
            _asked({"steps": [{"action": "runs", "evidence_refs": ["proc:9", "d2/proc:84"]}]}) == []
        )

    def test_an_id_in_a_code_span_is_not_read(self) -> None:
        assert _asked({"steps": [{"action": "prints `ev_0099` to the console"}]}) == []

    def test_each_end_of_a_range_is_read(self) -> None:
        assert _asked({"steps": [{"action": "reads", "evidence_refs": ["ev_0001-ev_0099"]}]}) == [
            "ev_0099"
        ]

    def test_a_malformed_id_is_not_read(self) -> None:
        assert _asked({"steps": [{"action": "ev_99 and ev_0005x"}]}) == []

    def test_one_id_is_asked_once_wherever_it_stands(self) -> None:
        payload = {"body": "Seen [ev_0099].", "steps": [{"evidence_refs": ["ev_0099"]}]}

        assert _asked(payload, prose=("body",)) == ["ev_0099"]

    def test_a_section_handed_no_issued_ids_is_not_read_this_way(self) -> None:
        assert _asked({"steps": [{"evidence_refs": ["ev_0099"]}]}, citable=[]) == []

    def test_without_the_record_reading_a_record_field_is_not_read(self) -> None:
        payload = {"commands": [{"command": "0x01", "evidence_refs": ["ev_0099"]}]}

        assert citation_violations(payload, ISSUED, prose=()) == []


class TestARowAnotherCheckAsksAbout:
    def test_a_configuration_row_citing_only_unissued_ids_is_left_to_its_own_question(
        self,
    ) -> None:
        payload = {
            "items": [{"key": "c2", "how_obtained": "decrypted", "evidence_refs": ["ev_0099"]}]
        }

        assert _asked(payload) == []
        assert [v.code for v in configuration_citation_violations(payload, ISSUED)] == [
            UNCITED_CONFIGURATION_CODE
        ]

    def test_a_configuration_row_with_an_issued_id_beside_it_is_asked_once(self) -> None:
        payload = {
            "items": [
                {"key": "c2", "how_obtained": "decrypted", "evidence_refs": ["ev_0001", "ev_0099"]}
            ]
        }

        assert _asked(payload) == ["ev_0099"]
        assert configuration_citation_violations(payload, ISSUED) == []

    def test_an_identifier_citing_only_unissued_ids_is_left_to_its_own_question(self) -> None:
        payload = {"identifiers": [{"value": "Global\\x", "evidence_refs": ["ev_0099"]}]}

        assert _asked(payload) == []
        assert [v.code for v in identifier_citation_violations(payload, ISSUED)] == [
            UNCITED_IDENTIFIER_CODE
        ]


class TestTheNarrativeKeyFindings:
    def test_an_id_only_in_a_key_finding_s_ids_is_asked_by_its_own_check_alone(self) -> None:
        payload = {
            "executive_summary": "A loader.",
            "key_findings": [{"text": "It decodes its strings.", "evidence_ids": ["ev_0099"]}],
        }

        assert citation_violations(payload, ISSUED, prose=NARRATIVE_PROSE) == []
        assert len(key_finding_citation_violations(payload, ISSUED)) == 1


# ---------------------------------------------------------------------------
# Through the composer
# ---------------------------------------------------------------------------


class _Answers:
    """A model that answers each turn from a list and keeps what it was sent."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.sent: list[list[Any]] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, turns: Any) -> Any:
        self.sent.append(list(turns))
        text = self.answers.pop(0) if self.answers else "{}"

        class _Message:
            content = text

        return _Message()


def test_the_composer_asks_about_an_unissued_id_its_section_writes() -> None:
    llm = _Answers(
        json.dumps({"text": "A Windows DLL; ev_0099 holds its export table."}),
        json.dumps({"text": "A Windows DLL [ev_0004]."}),
    )
    report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))
    composer = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    facts = "Facts established before analysis\n[ev_0001] identity: pe\n[ev_0004] pe: dll"
    with patch(
        "malspark.reporting.composer.structured_output_supported_for_llm", return_value=False
    ):
        asyncio.run(composer.compose(report, facts_block=facts))

    retry = str(llm.sent[1][-1].content)
    assert "ev_0099" in retry
    assert composer.validation_tally.by_code.get(CITATION_NOT_EVIDENCE_CODE) == 1
    assert report.intro_background == "A Windows DLL [ev_0004]."


def test_the_structured_path_reads_every_id_its_section_writes() -> None:
    from langchain_core.messages import HumanMessage

    from malspark.reporting.composer import _ProseOut
    from tests.unit.reporting.test_a_structured_section_is_asked_about_an_unpublished_value import (
        _Model,
    )

    llm = _Model(json.dumps({"body": "It decodes its configuration, as ev_0099 holds."}))
    report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))
    composer = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    composer._report = report
    composer._citable = list(ISSUED)
    with patch(
        "malspark.reporting.composer.structured_output_supported_for_llm", return_value=True
    ):
        result = asyncio.run(
            composer._invoke([HumanMessage(content="write it")], _ProseOut, section="packing")
        )

    assert result is not None and "ev_0099" in result.body
    assert composer.validation_tally.by_code.get(CITATION_NOT_EVIDENCE_CODE) == 1
