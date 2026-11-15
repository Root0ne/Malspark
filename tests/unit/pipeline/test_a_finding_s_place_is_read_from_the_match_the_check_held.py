"""A finding's place is read from the match its check held, in what it read, cheaply.

A place is the sentence a check's own match stands in: the offsets of the match
in the string it was found in, never a search of the text for the item again. It
names every sentence the item stands in, only in the strings the check read,
with the position a row has in the list as written. It is built from the
schema's declared field names, list positions, ``#n``, ``*`` and ``?``, so a key
the producer invented is never in one. Locating costs a run nothing it can
notice, and a locator that fails costs the finding nothing.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from malspark.pipeline import validation
from malspark.pipeline.validation import (
    PLACES_AT_MOST,
    EntryTexts,
    Violation,
    answer_of,
    citation_violations,
    configuration_citation_violations,
    identifier_citation_violations,
    key_finding_citation_violations,
    ledger_absence_contradictions,
    locate_statements,
    locator_path,
    misstated_entry_contents,
    narrative_capability_violations,
    placed,
    recommendation_indicator_violations,
    recommendation_technique_violations,
    repeated_item_violations,
    schema_violations,
    section_capability_violations,
    stated_value_violations,
    technique_name_violations,
    wrong_entry_citations,
)
from malspark.schemas.evidence import LedgerEntry
from tests.linear_cost import assert_scales
from tests.unit.pipeline.test_a_finding_names_its_statement import (
    FILLER,
    MARKER,
    _Body,
    _grounding,
    _texts,
)

# What a place may be written from.
_PLACE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*|\d+|\?|\*)(?:\.(?:[A-Za-z_][A-Za-z0-9_]*|\d+|\?))*(?:#\d+)?"
)

HOSTILE_KEYS = [
    pytest.param(key, id=f"hostile{n}")
    for n, key in enumerate(
        [
            "evil_example_com_4444",
            "4444",
            "Global_Mutex_ABC",
            "get_file_report",
            "a#1",
            "a*b",
            "a?b",
            "a.b.c",
            "ключ_значение",
            "k" * 10_000,
        ]
    )
]


def _clean(places: tuple[str, ...], *keys: str) -> None:
    for place in places:
        assert all(key not in place for key in keys), place
        assert place == "*" or re.fullmatch(_PLACE, place) or re.fullmatch(r"\+\d+", place), place


class TestOnlyWhatTheSchemaDeclaresIsWritten:
    @pytest.mark.parametrize("key", HOSTILE_KEYS)
    def test_a_key_the_producer_invented_is_a_question_mark_on_every_path(self, key: str) -> None:
        sentence = f"{FILLER} It carries the marker `{MARKER}` [ev_0011]."
        cites = f"{FILLER} It reads the key [ev_0099]."
        pads = f"{FILLER} It pads the file, T1027 (Binary Padding)."
        holds = f"{FILLER} The entry ev_0012 holds nothing [ev_0012]."
        claims = f"{FILLER} It performs data exfiltration over the network."
        found: list[Violation] = []
        with answer_of(_Body):
            found += wrong_entry_citations({key: {"x": sentence}}, _texts(), prose=())
            found += citation_violations({key: [cites]}, ["ev_0011"], prose=None)
            found += technique_name_violations({key: pads})
            found += misstated_entry_contents({key: holds}, _texts())
            found += section_capability_violations({key: [claims]}, _grounding())
        assert len(found) == 5
        for violation in found:
            assert violation.statements, violation.code
            assert violation.statements[0].startswith("?"), violation.statements
            _clean(violation.statements, key)

    @pytest.mark.parametrize("key", HOSTILE_KEYS)
    def test_a_ledger_absence_under_an_invented_key_is_a_question_mark(self, key: str) -> None:
        entries = EntryTexts.from_ledger(
            [
                LedgerEntry(
                    id="ev_0010",
                    agent="pipeline",
                    server="pipeline",
                    tool="batch_decompile",
                    args={"functions": "0xb670"},
                    output='{"0xb670": "int f(void) { return 1; }"}',
                )
            ]
        )
        (found,) = ledger_absence_contradictions(
            {key: f"{FILLER} The body of 0xb670 is not in the evidence."}, entries
        )

        assert found.statements == ("?#1",)

    @pytest.mark.parametrize("key", HOSTILE_KEYS)
    def test_a_schema_finding_of_an_extra_forbid_model_never_writes_the_extra_key(
        self, key: str
    ) -> None:
        class Strict(BaseModel):
            model_config = ConfigDict(extra="forbid")
            body: str

        found = schema_violations(Strict, {"body": "x", key: 1}, code="composer.schema")

        assert [v.statements for v in found] == [("?",)]
        assert key not in found[0].statements[0]

    def test_a_key_is_written_where_the_schema_declares_it_and_not_where_it_does_not(self) -> None:
        class Row(BaseModel):
            note: str

        class Out(BaseModel):
            channels: list[Row]

        payload = {
            "channels": [{"note": f"{FILLER} Bad [Foo]."}],
            "extras": [f"{FILLER} Bad [Foo]."],
        }

        with answer_of(Out):
            (found,) = citation_violations(payload, ["ev_0011"], prose=None)
        (bare,) = citation_violations(payload, ["ev_0011"], prose=None)

        assert found.statements == ("channels.0.note#1", "?.0#1")
        assert bare.statements == ("?.0.?#1", "?.0#1")

    def test_a_key_the_check_itself_names_is_written_with_no_schema(self) -> None:
        (found,) = citation_violations(
            {"body": f"{FILLER} Bad [Foo]."}, ["ev_0011"], prose=("body",)
        )

        assert found.statements == ("body#1",)

    def test_a_number_is_written_only_as_a_list_position(self) -> None:
        class Out(BaseModel):
            items: list[str]

        payload = {"items": [f"{FILLER} Bad [Foo]."], "4444": f"{FILLER} Bad [Foo]."}
        with answer_of(Out):
            (found,) = citation_violations(payload, ["ev_0011"], prose=None)

        assert found.statements == ("items.0#1", "?#1")


class TestEverySentenceTheItemStandsIn:
    def test_a_longer_id_is_not_the_item(self) -> None:
        body = "First cites [ev_0012]. Second cites [ev_001]."

        (found,) = citation_violations({"body": body}, ["ev_0012"], prose=("body",))

        assert found.statements == ("body#1",)

    def test_an_unbracketed_mention_before_the_citation_is_not_a_place(self) -> None:
        body = f"{FILLER} It mentions ev_0099 plainly. Then it cites [ev_0099]."

        (found,) = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert found.statements == ("body#2",)

    def test_a_code_span_before_the_citation_is_not_a_place(self) -> None:
        body = f"{FILLER} The text `[ev_0099]` is a literal. Then it cites [ev_0099]."

        (found,) = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert found.statements == ("body#2",)

    def test_an_item_written_in_several_sentences_names_each_in_the_answer_s_order(self) -> None:
        body = "It cites [Foo]. Nothing here. It cites [Foo] again. And [Foo]."

        (found,) = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert found.statements == ("body#0", "body#2", "body#3")

    def test_an_item_in_two_fields_names_each_field(self) -> None:
        payload = {"a": "It cites [Foo].", "b": "It cites [Foo]."}

        (found,) = citation_violations(payload, ["ev_0011"], prose=("a", "b"))

        assert found.statements == ("a", "b")

    def test_an_id_written_bare_in_a_record_is_found_where_it_stands(self) -> None:
        payload = {"rows": [{"text": "Fine.", "evidence_refs": []}, {"text": "See ev_0099 now."}]}

        found = citation_violations(payload, ["ev_0011"], prose=("body",), records=True)

        assert [v.statements for v in found if "ev_0099" in v.message] == [("?.1.?",)]

    def test_a_technique_name_written_twice_names_both_sentences(self) -> None:
        body = f"{FILLER} T1027 (Binary Padding) here. Plain. And T1027 (Binary Padding) there."

        with answer_of(_Body):
            (found,) = technique_name_violations({"body": body})

        assert found.statements == ("body#1", "body#3")

    def test_a_statement_made_in_two_sentences_names_both(self) -> None:
        said = "Entry ev_0012 holds nothing [ev_0012]."
        body = f"{FILLER} {said} Plain. {said}"

        with answer_of(_Body):
            (found,) = misstated_entry_contents({"body": body}, _texts())

        assert found.statements == ("body#1", "body#3")

    def test_a_capability_claimed_in_two_sentences_names_both(self) -> None:
        payload = {
            "executive_summary": (
                "It performs data exfiltration. Plain words. It performs data exfiltration."
            ),
            "key_findings": [],
        }

        (found, *_) = [
            v
            for v in narrative_capability_violations(payload, _grounding())
            if v.path == "exfiltration"
        ]

        assert found.statements == ("executive_summary#0", "executive_summary#2")


class TestThePlaceIsReadInTheTextAsWritten:
    def test_a_code_span_with_sentences_inside_it_does_not_move_the_place(self) -> None:
        body = "Start `One. Two. Three. Four.` cites [Foo]. End."

        (found,) = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert found.statements == ("body#3",)

    def test_a_later_sentence_after_a_code_span_is_placed_by_its_own_offset(self) -> None:
        body = "It cites [Foo]. Start `One. Two. Three. Four.` cites [Foo]. End."

        (found,) = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert found.statements == ("body#0", "body#4")

    def test_an_id_seen_bracketed_and_written_bare_names_both_places(self) -> None:
        payload = {"body": "It cites [ev_0099].", "rows": [{"text": "See ev_0099 here."}]}

        found = citation_violations(payload, ["ev_0011"], prose=("body",), records=True)

        assert [v.statements for v in found] == [("body", "?.0.?")]

    def test_a_field_spelled_by_its_alias_is_declared(self) -> None:
        from pydantic import Field

        class Aliased(BaseModel):
            model_config = ConfigDict(populate_by_name=True)
            note_text: str = Field(alias="noteText")

        assert locator_path(["noteText"], Aliased) == "noteText"
        assert locator_path(["note_text"], Aliased) == "note_text"
        assert locator_path(["other"], Aliased) == "?"


class TestOnlyWhatTheCheckRead:
    def test_a_field_the_check_did_not_read_is_not_named(self) -> None:
        payload = {"executive_summary": "It cites [Foo].", "notes": "It cites [Foo]."}

        (found,) = citation_violations(payload, ["ev_0011"], prose=("executive_summary",))

        assert found.statements == ("executive_summary",)

    def test_the_narrative_check_reads_the_summary_and_the_key_findings_alone(self) -> None:
        text = "It performs data exfiltration."
        payload = {
            "executive_summary": text,
            "key_findings": [{"text": "Plain.", "evidence_ids": [text]}],
            "defensive_recommendations": [{"action": text}],
        }

        (found, *_) = [
            v
            for v in narrative_capability_violations(payload, _grounding())
            if v.path == "exfiltration"
        ]

        assert found.statements == ("executive_summary",)


class TestARowIsWhereItStandsInTheList:
    def test_a_row_after_a_row_that_is_no_dict_keeps_its_position(self) -> None:
        bad = {"text": "It spreads.", "evidence_ids": ["ev_0099"]}
        (found,) = key_finding_citation_violations({"key_findings": ["plain", bad]}, ["ev_0011"])

        assert found.statements == ("key_findings.1",)
        assert found.message.startswith("key finding 1 ")

    def test_every_row_level_finding_counts_the_list_as_written(self) -> None:
        recs = {
            "defensive_recommendations": [
                "plain",
                {"action": "Hunt for T1053.", "rationale": "", "detection": ""},
            ]
        }
        (technique,) = recommendation_technique_violations(recs, ["T1027"])
        assert technique.statements == ("defensive_recommendations.1",)
        assert recommendation_indicator_violations(recs, lambda kind, value: "yes") == []

        cfg = {"items": [None, {"key": "B", "how_obtained": "decrypted", "evidence_refs": []}]}
        (item,) = configuration_citation_violations(cfg, ["ev_0011"])
        assert item.statements == ("items.1",)

        ids = {"identifiers": [3, {"kind": "k", "value": "y", "evidence_refs": []}]}
        (ident,) = identifier_citation_violations(ids, ["ev_0011"])
        assert ident.statements == ("identifiers.1",)

        stated = {
            "items": [
                "plain",
                {"key": "B", "value": "never-seen-value", "evidence_refs": ["ev_0012"]},
            ]
        }
        (value,) = stated_value_violations(stated, _texts())
        assert value.statements == ("items.1.value",)
        assert value.message.startswith("configuration item 1 ")

    def test_a_repeat_after_the_first_is_named_whatever_its_number(self) -> None:
        payload = {"items": [{"v": "x"}, {"v": "x"}, {"v": "y"}, {"v": "x"}]}

        (found,) = repeated_item_violations(payload, {"items": ("v",)})

        assert found.statements == ("items.1", "items.3")


class TestACostNobodyNotices:
    def test_many_bad_items_in_one_body_cost_in_proportion(self) -> None:
        def build(size: int) -> dict[str, str]:
            return {"body": " ".join(f"Sentence {i} cites [Src{i}]." for i in range(size))}

        def call(payload: dict[str, str]) -> None:
            found = citation_violations(payload, ["ev_0011"], prose=("body",))
            assert found[-1].statements

        assert_scales(build, 500, call, factor=8)

    def test_a_finding_quoting_many_sentences_costs_in_proportion(self) -> None:
        def build(size: int) -> list[Violation]:
            text = " ".join(f"Alpha {i} beta gamma delta." for i in range(size))
            payload = placed({"body": text})
            leaf = payload["body"]
            spans = tuple((leaf, m.start(), m.end()) for m in re.finditer(r"Alpha \d+ beta", text))
            return [Violation(code="c", message="m", about=spans)]

        def call(built: list[Violation]) -> None:
            (found,) = locate_statements(built)
            assert found.statements

        assert_scales(build, 3000, call, factor=8)

    def test_many_near_identical_sentences_cost_in_proportion(self) -> None:
        def build(size: int) -> dict[str, str]:
            return {"body": " ".join("Same claim here with it [Foo]." for _ in range(size))}

        def call(payload: dict[str, str]) -> None:
            (found,) = citation_violations(payload, ["ev_0011"], prose=("body",))
            assert found.statements[-1].startswith("+")

        assert_scales(build, 2000, call, factor=8)

    def test_many_technique_names_cost_in_proportion(self) -> None:
        def build(size: int) -> dict[str, str]:
            return {
                "body": " ".join(f"Step {i} uses T1055 (Command Shell) here." for i in range(size))
            }

        def call(payload: dict[str, str]) -> None:
            (found,) = technique_name_violations(payload)
            assert found.statements

        assert_scales(build, 500, call, factor=8)

    def test_a_finding_names_at_most_a_declared_number_of_places_and_counts_the_rest(self) -> None:
        body = " ".join("It cites [Foo]." for _ in range(PLACES_AT_MOST + 5))

        (found,) = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert len(found.statements) == PLACES_AT_MOST + 1
        assert found.statements[-1] == "+5"
        assert found.statements[0] == "body#0"


class TestALocatorNeverCostsAFinding:
    def test_a_text_of_thousands_of_bracket_groups_is_located_without_error(self) -> None:
        body = "It cites " + "[ev_0099]" * 3000 + "."

        found = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert [v.code for v in found] == ["report.citation_not_evidence"]
        assert found[0].statements == ("body",)

    def test_a_locator_that_raises_leaves_every_finding_as_the_check_made_it(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        body = f"{FILLER} It carries the marker `{MARKER}` [ev_0011]."
        expected = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

        def _broken(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("secret sentence text")

        monkeypatch.setattr(validation, "_located", _broken)
        with caplog.at_level(logging.WARNING):
            found = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

        assert [(v.code, v.message, v.path, v.quoted) for v in found] == [
            (v.code, v.message, v.path, v.quoted) for v in expected
        ]
        assert all(v.statements == () for v in found)
        said = " ".join(r.getMessage() for r in caplog.records if r.levelno == logging.WARNING)
        assert "wrong_entry_citations" in said and "RuntimeError" in said
        assert "secret" not in said and MARKER not in said


class TestAFindingIsEqualWhateverItsPlace:
    def test_two_findings_equal_but_for_the_place_compare_equal_and_print_alike(self) -> None:
        a = Violation(code="x.y", message="m", statements=("body#1",), about=(("t", 0, 1),))
        b = Violation(code="x.y", message="m")

        assert a == b
        assert [a] == [b] and a in [b] and b in [a]
        assert repr(a) == repr(b)
        assert hash(a) == hash(b)
