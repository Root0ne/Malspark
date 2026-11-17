"""An entry the model paged through is read part by part, and a row's citation is a set.

In a live run the text of an entry the model paged through is its answer, a
newline and the pages: no single document. Nothing about a value is decided
by parsing that whole text:

- a registry path's leading hive is held by its other spelling only where that
  stands before the rest of the path on one line of the entry, the line
  beginning at the latest of a newline, a newline written as an escape and the
  last quote no escape writes before the path; where that cannot be told, the
  hive is not held and the row is asked;
- the run shown around a value is read in the part it stands in (the answer or
  a page): a part that is a JSON document is read as one, any other part is
  shown as written, and a run that does not hold the value as the row states
  it is not shown.

A row's citation is the set of entries it cites, so a row kept after its run
was shown is asked whatever order it cites them in. The two answers a value
inside a longer run allows are said once per question, after every row's fact.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from malspark.agents.run_evidence_corpus import RunEvidenceCorpus
from malspark.pipeline.validation import (
    INSIDE_A_TOKEN_ENDS,
    STATED_VALUE_INSIDE_A_TOKEN_CODE,
    STATED_VALUE_UNHELD_CODE,
    EntryTexts,
    Violation,
    feedback_text,
    stated_value_violations,
)
from malspark.reporting.composer import ReportComposer, _HostIdentifiersOut
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.schemas.evidence import LedgerEntry

_KEYS = json.dumps({"strings": ["HKCU\\Software\\Other", "Software\\Vendor\\Run"]})
_KEY = "HKCU\\Software\\Vendor\\Run"


def _entry(entry_id: str, output: str, tool: str = "strings") -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="pipeline", server="pipeline", tool=tool, output=output)


def _read(output: str, *pages: str, answer: str | None = None) -> EntryTexts:
    """Entry texts built through the run's corpus, as the report rounds build them."""
    corpus = RunEvidenceCorpus(10_000_000)
    corpus.remember("ev_0001", "strings", output if answer is None else answer)
    for at, page in enumerate(pages):
        corpus.remember(f"ev_0001@{at * 100}+100", "read_evidence", page)
    return EntryTexts.from_ledger([_entry("ev_0001", output)], corpus)


def _identifiers(value: str, *refs: str) -> dict[str, Any]:
    return {
        "identifiers": [{"kind": "k", "value": value, "evidence_refs": list(refs or ["ev_0001"])}]
    }


def _one(payload: dict[str, Any], texts: EntryTexts) -> Violation:
    (found,) = stated_value_violations(payload, texts)
    return found


class TestTheHiveIsReadOnOneLine:
    @pytest.mark.parametrize(
        ("label", "texts"),
        [
            ("no page", lambda: _read(_KEYS)),
            ("one page", lambda: _read(_KEYS, '{"strings": ["more"]}')),
            ("a trailing log line", lambda: _read(_KEYS, answer=_KEYS + "\nread at 12:00")),
            ("a value JSON does not read", lambda: _read(_KEYS[:-1] + ', "score": NaN}')),
            ("cut short", lambda: _read(_KEYS[:-3])),
        ],
    )
    def test_a_hive_in_another_string_holds_nothing_however_the_entry_was_read(
        self, label: str, texts: Any
    ) -> None:
        assert _one(_identifiers(_KEY), texts()).code == STATED_VALUE_UNHELD_CODE, label

    @pytest.mark.parametrize(
        "source",
        [
            'RegOpenKeyExA(0x80000001, "Software\\\\Vendor", 0, 1, &h);',
            'if (r == 0x80000001) s = "Software\\\\Vendor";',
            's = /* HKCU */ "Software\\\\Vendor";',
        ],
    )
    def test_the_accepted_same_line_cases_hold_with_a_page_read(self, source: str) -> None:
        texts = _read(json.dumps({"code": source}), '{"code": "more"}')

        assert stated_value_violations(_identifiers("HKCU\\Software\\Vendor"), texts) == []

    def test_an_escaped_backslash_before_an_n_is_no_newline(self) -> None:
        source = 'f(0x80000001, "C:\\\\new", "Software\\\\Vendor");'
        texts = EntryTexts.from_ledger([_entry("ev_0001", json.dumps({"code": source}))])

        assert stated_value_violations(_identifiers("HKCU\\Software\\Vendor"), texts) == []


class TestTheRunIsShownFromItsPart:
    def test_a_run_in_a_page_is_shown_from_the_page_as_written(self) -> None:
        texts = _read(
            json.dumps({"strings": ["unrelated"]}), "page text poolExampleNoteFile-READ.txtTail end"
        )

        found = _one(_identifiers("ExampleNoteFile-READ.txt"), texts)

        assert found.code == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert "only inside a longer run of text: 'poolexamplenotefile-read.txttail'." in (
            found.message
        )

    def test_a_run_in_the_answer_is_shown_read_as_its_document(self) -> None:
        answer = json.dumps({"strings": ["Software\\Vendor\\RunTail"]})
        texts = _read(answer, "page text that holds nothing")

        found = _one(_identifiers("Software\\Vendor\\Run"), texts)

        # The answer is the entry's stored output: shown in its own case.
        assert "only inside a longer run of text: 'Software\\\\Vendor\\\\RunTail'." in found.message

    def test_a_plain_part_is_shown_as_written_never_decoded(self) -> None:
        texts = _read("dump: xxSoftware\\\\Vendor\\\\RunTail yy")

        found = _one(_identifiers("Software\\Vendor\\Run"), texts)

        assert "only inside a longer run of text: 'xxSoftware\\\\\\\\Vendor\\\\\\\\RunTail'." in (
            found.message
        )

    def test_a_part_that_opens_with_a_bracket_but_is_no_document_is_plain(self) -> None:
        # Cut short: a part JSON does not read is shown as written, escapes and all.
        texts = _read('{"strings": ["xxSoftware\\\\Vendor\\\\RunTail", "cut')

        found = _one(_identifiers("Software\\Vendor\\Run"), texts)

        assert "'xxSoftware\\\\\\\\Vendor\\\\\\\\RunTail'" in found.message

    def test_a_run_that_does_not_hold_the_value_as_stated_is_not_shown(self) -> None:
        texts = _read("dump: xxExampleCaf\\u00e9-NameValueyy end")

        found = _one(_identifiers("ExampleCafé-NameValue"), texts)

        assert found.code == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert "only inside a longer run of text, which is not shown here." in found.message


class TestTheTwoAnswersAreSaidOnce:
    def test_a_row_s_finding_states_its_fact_only(self) -> None:
        texts = _read(json.dumps({"strings": ["xxExampleNoteFile-READ.txtyy"]}))

        found = _one(_identifiers("ExampleNoteFile-READ.txt"), texts)

        assert INSIDE_A_TOKEN_ENDS not in found.message

    def test_the_question_says_the_two_answers_once_after_every_row(self) -> None:
        texts = _read(
            json.dumps(
                {"strings": ["xxExampleNoteFile-READ.txtyy", "aaExampleUpdaterServiceMainbb"]}
            )
        )
        payload = {
            "identifiers": [
                {"kind": "k", "value": "ExampleNoteFile-READ.txt", "evidence_refs": ["ev_0001"]},
                {"kind": "k", "value": "ExampleUpdaterServiceMain", "evidence_refs": ["ev_0001"]},
            ]
        }

        said = feedback_text(stated_value_violations(payload, texts))

        assert said.count(INSIDE_A_TOKEN_ENDS) == 1
        assert said.index(INSIDE_A_TOKEN_ENDS) > said.index("identifier 2 (")

    def test_no_question_without_such_a_row_says_them(self) -> None:
        said = feedback_text([Violation(code=STATED_VALUE_UNHELD_CODE, message="m")])

        assert INSIDE_A_TOKEN_ENDS not in said


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


class TestTheCitationIsASet:
    def test_a_row_kept_with_its_citations_reordered_was_asked(self) -> None:
        from langchain_core.messages import HumanMessage

        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", json.dumps({"strings": ["xxExampleNoteFile-READ.txtyy"]})),
                _entry("ev_0002", json.dumps({"strings": ["unrelated"]})),
            ]
        )
        first = json.dumps(_identifiers("ExampleNoteFile-READ.txt", "ev_0001", "ev_0002"))
        retry = json.dumps(_identifiers("ExampleNoteFile-READ.txt", "ev_0002", "ev_0001"))
        llm = _RawLLM(first, retry)
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        comp._entries = texts
        comp._citable = ["ev_0001", "ev_0002"]
        comp._report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), verdict="Malware"
        )
        with patch(
            "malspark.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            asyncio.run(
                comp._invoke(
                    [HumanMessage(content="write it")],
                    _HostIdentifiersOut,
                    section="host_identifiers",
                    validators=[lambda p: stated_value_violations(p, comp._entries)],
                )
            )

        assert len(llm.sent) == 2
        assert str(llm.sent[1][-1].content).count(INSIDE_A_TOKEN_ENDS) == 1
        (row,) = comp.validation_tally.unresolved
        assert row["code"] == STATED_VALUE_INSIDE_A_TOKEN_CODE
        assert "asked" not in row
