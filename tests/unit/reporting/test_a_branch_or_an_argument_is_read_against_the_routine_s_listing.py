"""A sentence stating a branch or an argument of a listed routine is read against its listing.

haiku13 (T-580): section 4 said "A failed gate returns -1, and 0x3cb4 then loops on
Sleep(1000)", while the listing of 0x3cb4 returns at once on a nonzero result and
loops on zero; section 5 said 0x6f48 "rejects bodies that begin with <html>", while
its listing compares param_3, not the fetched body. No check can tell which way a
condition goes or which argument a sentence means. The agreement round now holds
such a sentence and shows the routine's listing beside it, in part, so the model
reads the two together: it rewrites the sentence on the listing or keeps it. No
call is added, and a run with no such sentence is asked as before.

Every address, entry and tool name below is a neutral value.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    FACT,
    REWRITTEN_CODE,
    Passage,
    ask_section_agreement,
    branch_sense_sentences,
    passages_of,
    prompt_text,
)
from malspark.schemas.evidence import LedgerEntry

BASE = 0x2470000
GATE, LOOP, FETCH = BASE + 0x1400, BASE + 0x2800, BASE + 0x2C00
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
LOOP_CODE = (
    f"  int r = FUN_{GATE:x}();\n  if (r != 0) {{\n    return 0;\n  }}\n"
    "  do { Sleep(1000); } while (1);"
)
FETCH_CODE = "  if (FUN_cmp((char *)param_3, marker, 6) == 0) {\n    write(local_140);\n  }"


def _lifted(entry_id: str, address: int, body: str) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=f"int FUN_{address:x}(int param_1, int param_2, char *param_3)\n{{\n{body}\n}}\n",
        facts=_DECOMPILE,
    )


def _ledger(fetch_body: str = FETCH_CODE) -> list[LedgerEntry]:
    return [
        LedgerEntry(id="ev_0001", tool="image_facts", output='{"image_base": "0x2470000"}'),
        _lifted("ev_0002", GATE, "  return -1;"),
        _lifted("ev_0003", LOOP, LOOP_CODE),
        _lifted("ev_0004", FETCH, fetch_body),
    ]


def _report(section_5: str, limitations: str = "") -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            payloads=TechnicalSubsection(
                title="Payloads", body=section_5, evidence_refs=["ev_0003"]
            ),
            analyst_limitations=(
                TechnicalSubsection(title="Limitations", body=limitations, evidence_refs=[])
                if limitations
                else None
            ),
        ),
    )


def _listings(passages: list[Passage]) -> dict[str, Passage]:
    return {p.id: p for p in passages if p.id.startswith("listing.")}


def _section_5(passages: list[Passage]) -> Passage:
    return next(p for p in passages if p.id == "payloads")


BRANCH = "A failed gate returns -1, and 0x2800 then loops on Sleep(1000) [ev_0003]."
ARGUMENT = (
    "Routine 0x2c00 fetches a body [ev_0004]. With a path argument it rejects bodies that "
    "begin with the marker [ev_0004]."
)


def test_a_branch_sentence_is_held_with_its_routine_s_listing() -> None:
    passages = passages_of(_report(BRANCH), entries=_ledger())
    (listing,) = _listings(passages).values()
    assert listing.kind == FACT and listing.cites == frozenset({"ev_0003"})
    assert "0x2472800 (offset 0x2800)" in listing.text and "if (r != 0)" in listing.text
    section_5 = _section_5(passages)
    assert section_5.branch_sense == ((BRANCH, (listing.id,)),)
    assert BRANCH in section_5.held
    prompt = prompt_text(passages)
    assert "[payloads] each of these states a branch" in prompt
    # Asked once, under its own line, not again in the generic one.
    assert "[payloads] list each of these sentences" not in prompt


def test_an_argument_sentence_pointing_back_is_held_to_the_routine_before_it() -> None:
    passages = passages_of(_report(ARGUMENT), entries=_ledger())
    (listing,) = _listings(passages).values()
    assert "offset 0x2c00" in listing.text and "param_3" in listing.text
    held = dict(_section_5(passages).branch_sense)
    assert list(held) == [ARGUMENT.split(" [ev_0004]. ")[1]]


def test_an_argument_by_its_place_is_held() -> None:
    routines = [Passage(id="r.1", label="", text="", kind=FACT, addresses=frozenset({0x2C00}))]
    sentence = "0x2c00 compares param_3 with the marker."
    assert branch_sense_sentences(sentence, routines) == ((sentence, ("r.1",)),)
    assert branch_sense_sentences("0x2c00 copies the marker.", routines) == ()


def test_a_routine_no_entry_lists_shows_no_listing_and_holds_nothing() -> None:
    sentence = "When 0x9900 fails, the caller returns -1 [ev_0003]."
    passages = passages_of(_report(sentence), entries=_ledger())
    assert not _listings(passages)
    assert _section_5(passages).branch_sense == ()


def test_a_long_listing_with_nothing_named_shows_its_head_with_the_rest_counted() -> None:
    long_body = FETCH_CODE + "\n" + "\n".join(f"  step_{n}();" for n in range(400))
    passages = passages_of(_report(ARGUMENT), entries=_ledger(long_body))
    (listing,) = _listings(passages).values()
    assert "shown in part" in listing.text and "characters left out" in listing.text
    assert "param_3" in listing.text


def test_a_long_listing_shows_the_lines_the_sentence_names_past_the_head() -> None:
    # The branch on the gate's result stands past character 1200 of the listing.
    filler = "\n".join(f"  step_{n}(a, b, c);" for n in range(120))
    body = f"{filler}\n  if (FUN_{GATE:x}() != 0) {{\n    return 0;\n  }}\n{filler}"
    ledger = [*_ledger()[:2], _lifted("ev_0003", LOOP, body), _ledger()[3]]
    sentence = "0x2800 loops when 0x1400 fails [ev_0003]."
    passages = passages_of(_report(sentence), entries=ledger)
    listing = next(p for p in _listings(passages).values() if "offset 0x2800" in p.text)
    assert f"FUN_{GATE:x}() != 0" in listing.text
    assert "int FUN_" in listing.text  # the signature
    assert "[… " in listing.text and " lines …]" in listing.text


def test_a_closing_sentence_is_not_held_by_its_branch_again() -> None:
    passages = passages_of(_report("The gate runs.", limitations=BRANCH), entries=_ledger())
    assert not _listings(passages)


def test_a_run_with_no_such_sentence_is_asked_as_before() -> None:
    plain = "Routine 0x2800 sleeps between cycles [ev_0003]."
    passages = passages_of(_report(plain), entries=_ledger())
    assert not _listings(passages)
    assert "states a branch" not in prompt_text(passages)


class _Reporter:
    def __init__(self, *answers: Any) -> None:
        self.answers = [json.dumps(a) for a in answers]
        self.asked: list[list[BaseMessage]] = []
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        self.asked.append(list(turns))
        return AIMessage(content=self.answers.pop(0) if self.answers else '{"sentences": []}')


def test_the_model_rewrites_a_branch_on_the_listing_in_the_one_call() -> None:
    report = _report(BRANCH)
    rewrite = (
        "When the gate returns nonzero, 0x2800 returns 0 at once; on zero it loops on "
        "Sleep(1000) [ev_0003]."
    )
    row = {
        "passage": "payloads",
        "sentence": BRANCH,
        "sources": ["listing.1"],
        "decision": "rewrite",
        "rewrite": rewrite,
    }
    reporter = _Reporter({"sentences": [row]})
    ledger = _ledger()
    done = asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=[f"ev_{n:04d}" for n in range(1, 6)],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    assert len(reporter.asked) == 1
    assert report.technical_analysis is not None
    assert report.technical_analysis.payloads is not None
    assert report.technical_analysis.payloads.body == rewrite
    assert done.summary["rewritten"] == 1
    assert [r["code"] for r in done.tally.unresolved] == [REWRITTEN_CODE]


def test_other_branch_phrasings_are_held() -> None:
    routines = [
        Passage(id="r.1", label="", text="", kind=FACT, addresses=frozenset({0x3CB4})),
        Passage(id="r.2", label="", text="", kind=FACT, addresses=frozenset({0x33AC})),
    ]
    for sentence, held in (
        ("Routine 0x3cb4 calls 0x33ac only when the gate succeeds.", ("r.1", "r.2")),
        ("0x3cb4 proceeds to the install path if the mutex is absent.", ("r.1",)),
        ("0x3cb4 jumps to 0x33ac when the check is true.", ("r.1", "r.2")),
        ("0x33ac is retried by 0x3cb4 when the gate fails.", ("r.1", "r.2")),
    ):
        assert branch_sense_sentences(sentence, routines) == ((sentence, held),), sentence


def test_an_address_another_clause_names_holds_nothing() -> None:
    routines = [Passage(id="r.1", label="", text="", kind=FACT, addresses=frozenset({0x3868}))]
    sentence = "The sample sleeps 30 seconds when idle; 0x3868 is the init routine."
    assert branch_sense_sentences(sentence, routines) == ()


def test_a_section_5_branch_row_on_another_fact_takes_the_platform_path() -> None:
    # Only a row on the routine's listing is put in as the model wrote it; a row on
    # another source is not the model's words in section 5.
    report = _report(BRANCH)
    row = {
        "passage": "payloads",
        "sentence": BRANCH,
        "sources": ["bound.1"],
        "decision": "rewrite",
        "rewrite": "0x2800 returns 0 when the gate fails [ev_0003].",
    }
    reporter = _Reporter({"sentences": [row]})
    ledger = _ledger()
    asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=[f"ev_{n:04d}" for n in range(1, 6)],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    assert report.technical_analysis is not None
    assert report.technical_analysis.payloads is not None
    assert report.technical_analysis.payloads.body == BRANCH


def test_a_32_bit_name_padded_with_zeros_is_found_past_the_head() -> None:
    from malspark.reporting.section_agreement import _listing_excerpt

    body = "\n".join(f"  iVar{i} = FUN_0040{0x2000 + i:04x}(param_1);" for i in range(400))
    code = (
        "int __cdecl FUN_00401000(int param_1)\n{\n"
        + body
        + "\n  if (iVar1 == 0) { FUN_004012f0(); }\n"
        + body
        + "\n}"
    )
    for sentence in (
        "0x401000 calls 0x4012f0 only when the check fails.",  # virtual addresses
        "0x1000 calls 0x12f0 only when the check fails.",  # offsets
    ):
        shown = _listing_excerpt(code, [sentence], [0x400000])
        assert "FUN_004012f0" in shown and "characters left out" not in shown, sentence
        assert len(shown) <= 1300


def test_an_overlong_line_is_cut_and_the_excerpt_stays_bounded() -> None:
    from malspark.reporting.section_agreement import _listing_excerpt

    signature = "int FUN_00405000(" + ", ".join(f"int param_{i}" for i in range(1, 200)) + ")"
    code = (
        signature + "\n{\n" + "\n".join(f"  x{i} = FUN_0040{i:04x}();" for i in range(3000)) + "\n}"
    )
    shown = _listing_excerpt(code, ["0x5000 calls 0x400010 only when param_3 is zero."], [0x400000])
    assert len(shown) <= 1300
    assert shown.startswith("int FUN_00405000(") and " characters …]" in shown.splitlines()[0]


def test_listings_past_the_question_s_budget_are_left_out_and_said(monkeypatch: Any) -> None:
    import malspark.reporting.section_agreement as module

    monkeypatch.setattr(module, "_LISTINGS_PER_QUESTION", 200)
    text = f"{BRANCH} {ARGUMENT}"
    passages = passages_of(_report(text), entries=_ledger())
    listings = _listings(passages)
    # One listing fits; the other routine is left out, and the round says so.
    assert len(listings) == 1
    (left,) = [p for p in passages if p.id == module.LISTINGS_LEFT_ID]
    assert left.text.startswith("1 listing not shown: budget")
    # A sentence held only on a routine left out is not held.
    held = dict(_section_5(passages).branch_sense)
    assert len(held) == 1 and set(held.values()) == {(next(iter(listings)),)}
    assert "1 listing not shown: budget" in prompt_text(passages)
    reporter = _Reporter()
    ledger = _ledger()
    done = asyncio.run(
        ask_section_agreement(
            reporter,
            _report(text),
            citable_ids=[f"ev_{n:04d}" for n in range(1, 6)],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    assert any("listing not shown: budget" in reason for reason in done.degradations)


def test_calls_and_runs_state_a_branch_only_beside_a_condition_word() -> None:
    routines = [
        Passage(id="r.1", label="", text="", kind=FACT, addresses=frozenset({0x3868})),
        Passage(id="r.2", label="", text="", kind=FACT, addresses=frozenset({0x6250})),
    ]
    held = [
        "On the success path, 0x3868 calls 0x6988.",
        "Routine 0x3868 calls 0x6250 only when the gate succeeds.",
    ]
    for sentence in held:
        assert branch_sense_sentences(sentence, routines), sentence
    pointing = "0x3868 runs the gates. On success it calls 0x6250."
    assert [s for s, _ in branch_sense_sentences(pointing, routines)] == [
        "On success it calls 0x6250."
    ]
    # A failure, a zero or an argument alone is no condition for "calls".
    for sentence in (
        "Routine 0x3868 packs these arguments into a structure and calls 0x6250.",
        "0x3868 calls 0x6250 with a non-zero flag.",
    ):
        assert branch_sense_sentences(sentence, routines) == (), sentence


def test_a_long_line_shows_the_window_around_what_the_sentence_names() -> None:
    from malspark.reporting.section_agreement import _listing_excerpt

    literal = '  s = "' + "A" * 3000 + '"; FUN_00400010(); t = "' + "B" * 3000 + '";'
    code = "int FUN_00405000(void)\n{\n" + literal + "\n" + "\n".join("  y();" for _ in range(500))
    shown = _listing_excerpt(code, ["0x5000 calls 0x400010 only when it fails."], [0x400000])
    line = next(row for row in shown.splitlines() if "FUN_00400010" in row)
    assert line.startswith("[… ") and line.endswith(" characters …]")
    assert len(shown) <= 1300


def test_no_rewrite_rests_on_the_count_of_listings_left_out(monkeypatch: Any) -> None:
    import malspark.reporting.section_agreement as module

    monkeypatch.setattr(module, "_LISTINGS_PER_QUESTION", 200)
    text = f"{BRANCH} {ARGUMENT}"
    report = _report(text)
    row = {
        "passage": "payloads",
        "sentence": BRANCH,
        "sources": [module.LISTINGS_LEFT_ID],
        "decision": "rewrite",
        "rewrite": "0x2800 returns 0 on a nonzero gate result [ev_0003].",
    }
    reporter = _Reporter({"sentences": [row]}, {"sentences": [row]})
    ledger = _ledger()
    asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=[f"ev_{n:04d}" for n in range(1, 6)],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    assert module.UNKNOWN_SOURCE_CODE in str(reporter.asked[-1][-1].content)
    assert report.technical_analysis is not None
    assert report.technical_analysis.payloads is not None
    assert report.technical_analysis.payloads.body == text
