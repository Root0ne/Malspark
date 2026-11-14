"""A record's value cell and a capability bullet of the summary are answered whole.

A channel's encryption cell said "Not established" beside a section 5 paragraph
that states the cipher, and a summary bullet kept a reading the key findings had
been rewritten away from: neither was asked about, so each printed as written.
Each value cell (a channel's protocol, encryption and packet layout; a scheme's
cipher, mode, library and IV) and each capability bullet is now a passage the
agreement question answers whole, as it answers a closing section: held for being
that kind of field, never for its words. An answer that passes stands; a refused
or missing one leaves the sentence out, a cell then printing "-" and a bullet not
printed, recorded; where the question got no answer at all, they print as written.
The routes the first step opened are closed: a procedure left out prints "-", not
an analyst's claim; a host purpose left out says so; a scheme cell left out prints
"-". Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import (
    C2Channel,
    CapabilityBullet,
    CapabilityCell,
    EncryptionScheme,
    HostIdentifier,
    MalwareReport,
    TechniqueProcedure,
)
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    HELD_UNLISTED_CODE,
    REWRITTEN_CODE,
    agreement_violations,
    apply_rows,
    passages_of,
    prompt_text,
    rewrites_violations,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _UNKNOWN,
    _ask,
    _ledger,
    _report,
    _Reporter,
    _row,
)

FIRST = "The gate reads a host mode [ev_0107]."
CELL = "Not established."
BULLET = "The sample resolves a host mode [ev_0107]."
_CELL_LABEL = "5. Technical analysis, channel row 1, encryption"
_BULLET_LABEL = "1. Executive summary, capability bullet 1"
_CELL_WHOLE = "a table cell, every sentence of which is answered"
_BULLET_WHOLE = "a capability bullet of the summary, every sentence of which is answered"


def _cells_and_bullet(background: str = "") -> MalwareReport:
    report = _report(FIRST, background=background)
    report.c2_channels = [C2Channel(name="HTTP channel", encryption=CELL)]
    assert report.technical_analysis is not None
    report.technical_analysis.capability_summary = [
        CapabilityBullet(text=BULLET, evidence_refs=["ev_0107"])
    ]
    return report


def _applied(report: MalwareReport, rows: list[dict[str, Any]]) -> tuple[dict[str, int], list]:
    ledger = _ledger()
    counts, records = apply_rows(
        {"sentences": rows},
        passages_of(report, entries=ledger),
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    return counts, [(v.code, v.subject, v.message) for v in records]


def _left_out(label: str, why: str, sentence: str) -> str:
    return (
        f"The agreement question leaves a sentence of {label} out of the section ({why}): "
        f"{sentence!r}."
    )


def _at(passage: str, row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "passage": passage}


def _beside() -> dict[str, Any]:
    """A row answering the limitations sentence, so the answer is no empty one."""
    return _row(FIRST, "keep", [], reason="no source speaks of it")


def _printed(report: MalwareReport, records: list[Any]) -> tuple[str, str]:
    report.run_summary = {
        "validation": {
            "unresolved": [
                {"code": code, "subject": subject, "message": message}
                for code, subject, message in records
            ]
        }
    }
    return (
        MarkdownRenderer(layout=BUNDLE).render(report),
        MarkdownRenderer(layout=ANALYST).render(report),
    )


def test_each_cell_and_bullet_is_a_passage_answered_whole_and_told_its_ends() -> None:
    passages = {p.id: p for p in passages_of(_cells_and_bullet(), entries=_ledger())}
    for pid in ("communications.1.encryption", "capability_summary.1"):
        assert passages[pid].closing and passages[pid].write is not None
    text = prompt_text(list(passages.values()))
    # Said once in the TASK for every field answered whole, not once per passage.
    assert [line for line in text.splitlines() if line.startswith("  [")] == [
        "  [limitations] answer every sentence of this passage, one row each (1 sentence), as "
        "the TASK asks."
    ]
    task = text.splitlines()[text.splitlines().index("TASK") :]
    assert task[2:] == [
        "List each sentence that says otherwise than its sources, as the system prompt asks. "
        'Return ONLY the JSON object shown there. A "quote" is at least 12 characters of the '
        "source's words, copied exactly.",
        "Besides, answer EVERY sentence of [capability_summary.1], [communications.1.encryption], "
        "[limitations], one row each, against section 5, the facts and the closed debate lines. "
        "A sentence calling something not established, not recovered, not known, not read, read "
        "only in part, failed or not passed says otherwise where section 5 states it from the "
        "code, or a fact shows the code listed or the call redone, even where it means that the "
        "run did not observe it: then rewrite it to say what was not observed and what the code "
        "shows, keeping no clause a source contradicts. Keep a sentence only naming the sources "
        'you read, with "quote": the words of one of them that state the same thing, copied '
        "exactly (an absence is kept only on words that state that absence); where no source "
        'speaks of it, keep it with "sources": [] and "reason". Where it cannot be stated '
        'truly, answer "decision": "drop" with "reason".',
        "Of these, [capability_summary.1], [communications.1.encryption] are value cells and "
        "capability bullets: for each sentence of them, if no answer for it passes the checks, "
        "it is left out of the report; a bullet left with no sentence is not printed; a cell "
        'left with no sentence prints "-".',
    ]


def test_a_cell_and_a_bullet_no_row_answers_are_left_out_and_print_so() -> None:
    report = _cells_and_bullet()
    counts, records = _applied(report, [_at("limitations", _beside())])
    assert report.c2_channels[0].encryption == ""
    assert report.technical_analysis is not None
    assert report.technical_analysis.capability_summary[0].text == ""
    assert counts["dropped"] == 2
    assert [r for r in records if r[0] == DROPPED_CODE] == [
        (
            DROPPED_CODE,
            "capability_summary.1",
            _left_out(_BULLET_LABEL, f"no answer was given for it; {_BULLET_WHOLE}", BULLET),
        ),
        (
            DROPPED_CODE,
            "communications.1.encryption",
            _left_out(_CELL_LABEL, f"no answer was given for it; {_CELL_WHOLE}", CELL),
        ),
    ]
    bundle, analyst = _printed(report, records)
    assert "| HTTP channel | - | - | - | - | no evidence cited |" in bundle
    assert "| HTTP channel | - | - | - | - |" in analyst
    assert BULLET.split(" [")[0] not in analyst
    # No empty item stands where the bullet was.
    assert "\n- -\n" not in analyst


def test_a_refused_answer_for_a_cell_leaves_it_out() -> None:
    report = _cells_and_bullet()
    # A keep quoting nothing a source it names states: refused, and left out.
    keep = _at("communications.1.encryption", _row(CELL, "keep", ["ledger.1"], quote="x"))
    counts, records = _applied(report, [keep, _at("limitations", _beside())])
    assert report.c2_channels[0].encryption == ""
    assert (
        DROPPED_CODE,
        "communications.1.encryption",
        _left_out(
            _CELL_LABEL,
            "kept on no source a check accepts: ledger.1, quoting 'x': agreement.keep_unquoted",
            CELL,
        ),
    ) in records


def test_an_answer_that_passes_stands_in_a_cell_and_a_bullet() -> None:
    report = _cells_and_bullet()
    rewrite = "RC4 over each report [ev_0107]."
    drop = _row(BULLET, "drop", [], reason="the key findings say otherwise")
    counts, records = _applied(
        report,
        [
            _at(
                "communications.1.encryption",
                _row(CELL, "rewrite", ["string_resolution"], rewrite=rewrite),
            ),
            _at("capability_summary.1", drop),
            _at("limitations", _beside()),
        ],
    )
    assert report.c2_channels[0].encryption == rewrite
    assert report.technical_analysis is not None
    assert report.technical_analysis.capability_summary[0].text == ""
    assert (
        REWRITTEN_CODE,
        "",
        f"The agreement question rewrote a sentence of {_CELL_LABEL} on string_resolution: "
        f"{CELL!r} now reads {rewrite!r}.",
    ) in records
    assert (
        DROPPED_CODE,
        "capability_summary.1",
        _left_out(
            _BULLET_LABEL,
            f"the round dropped it; {_BULLET_WHOLE}; its reason: the key findings say otherwise",
            BULLET,
        ),
    ) in records


class _Raising(_Reporter):
    async def ask(self, turns: list[Any], *, call: str, what: str) -> Any:
        raise TimeoutError("late")


def test_no_answer_at_all_leaves_cells_and_bullets_as_written_and_held_sentences_out() -> None:
    report = _cells_and_bullet(background=f"{FIRST} {_UNKNOWN}")
    done = _ask(report, _Raising())
    # A failed call blanks no table and no summary; what the ledger's lines hold is left out.
    assert report.c2_channels[0].encryption == CELL
    assert report.technical_analysis is not None
    assert report.technical_analysis.capability_summary[0].text == BULLET
    assert report.intro_background == FIRST
    assert [
        (r["subject"], r["message"]) for r in done.tally.unresolved if r["code"] == DROPPED_CODE
    ] == [
        (
            "introduction",
            _left_out(
                "12.3 Background",
                "the agreement question got no answer at all; held on what ledger.1 holds lines on",
                _UNKNOWN,
            ),
        )
    ]


_WHOLE_ENDS = (
    "List it: rewrite it on the source that states otherwise, citing an entry that source "
    'cites; keep it naming the source you read and found agreeing, with "quote": its words '
    'that state the same thing, copied exactly, or with "sources": [] and "reason" where no '
    'source speaks of it; or drop it with "reason". If no answer for it passes the checks, it '
    "is left out of the report, and "
)


def test_a_cell_unanswered_in_the_first_turn_is_asked_again_told_what_it_is() -> None:
    passages = passages_of(_cells_and_bullet(), entries=_ledger())
    found = agreement_violations({"sentences": [_at("limitations", _beside())]}, passages)
    # What the field is, every end that passes, the end where none does and what an
    # emptied one prints.
    assert [(v.code, v.path, v.message) for v in found] == [
        (
            HELD_UNLISTED_CODE,
            "held.capability_summary.1",
            "capability_summary.1 is a capability bullet of the summary, every sentence of "
            f"which is answered, and no row lists this sentence: {BULLET!r}. {_WHOLE_ENDS}a "
            "bullet left with no sentence is not printed. Answer with every row again, this one "
            "included.",
        ),
        (
            HELD_UNLISTED_CODE,
            "held.communications.1.encryption",
            "communications.1.encryption is a table cell, every sentence of which is answered, "
            f"and no row lists this sentence: {CELL!r}. {_WHOLE_ENDS}a cell left with no "
            'sentence prints "-". Answer with every row again, this one included.',
        ),
    ]


def test_an_empty_answer_asks_nothing_of_a_cell_or_bullet_held_only_by_its_kind() -> None:
    passages = passages_of(_cells_and_bullet(), entries=_ledger())
    found = agreement_violations({"sentences": []}, passages)
    # Only the limitations sentence is asked about: a cell or a bullet prints as written
    # where no row could be read, so nothing is said of it.
    assert [(v.code, v.path, v.message) for v in found] == [
        (
            HELD_UNLISTED_CODE,
            "held.limitations",
            "limitations holds a sentence of a closing section, every one of which is answered, "
            f"and no row lists this sentence: {FIRST!r}. List it: rewrite it on the source that "
            "states otherwise, or keep it naming the source you read and found agreeing, quoting "
            "its words, or leave it out giving the reason. Answer with every row again, this one "
            "included.",
        )
    ]
    report = _cells_and_bullet()
    done = _ask(report, _Reporter({"sentences": []}, {"sentences": []}))
    assert report.c2_channels[0].encryption == CELL
    assert [(r["code"], r.get("subject"), r["message"]) for r in done.tally.unresolved] == [
        (
            HELD_UNLISTED_CODE,
            None,
            "limitations holds a sentence of a closing section, every one of which is answered, "
            f"and no row lists this sentence: {FIRST!r}. List it: rewrite it on the source that "
            "states otherwise, or keep it naming the source you read and found agreeing, quoting "
            "its words, or leave it out giving the reason. Answer with every row again, this one "
            "included.",
        )
    ]


def test_a_scheme_cell_left_out_prints_a_dash_in_its_row() -> None:
    report = _report(FIRST)
    assert report.technical_analysis is not None
    report.technical_analysis.encryption_scheme = EncryptionScheme(cipher="RC4 [ev_0107].")
    counts, records = _applied(report, [_at("limitations", _beside())])
    assert report.technical_analysis.encryption_scheme.cipher == ""
    assert (
        DROPPED_CODE,
        "encryption_scheme.cipher",
        _left_out(
            "5. Technical analysis, encryption scheme, cipher",
            f"no answer was given for it; {_CELL_WHOLE}",
            "RC4 [ev_0107].",
        ),
    ) in records
    bundle, _analyst = _printed(report, records)
    assert "| Cipher | - |" in bundle


def _with_record(report: MalwareReport, subject: str) -> MalwareReport:
    report.run_summary = {
        "validation": {
            "unresolved": [
                {"code": DROPPED_CODE, "subject": subject, "message": "left out", "agent": "x"}
            ]
        }
    }
    return report


def test_a_host_purpose_left_out_says_so_in_the_bundle() -> None:
    def _made() -> MalwareReport:
        report = _report(FIRST)
        assert report.technical_analysis is not None
        report.technical_analysis.host_identifiers = [
            HostIdentifier(kind="mutex", value="quietlock", purpose="", evidence_refs=["ev_0107"])
        ]
        return report

    bundle = MarkdownRenderer(layout=BUNDLE).render(_with_record(_made(), "host_identifiers.1"))
    assert "| left out by the agreement question | ev_0107 |" in bundle
    # A purpose the model never wrote is not stated, as before.
    bundle = MarkdownRenderer(layout=BUNDLE).render(_made())
    assert "| not stated | ev_0107 |" in bundle


def test_a_procedure_left_out_prints_a_dash_and_no_analyst_claim() -> None:
    claim = "The loader decodes its strings with a rolling XOR key [ev_0107]."

    def _made() -> MalwareReport:
        report = _report(FIRST)
        report.capability_matrix = [
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1027",
                technique_name="Obfuscated Files or Information",
                evidence=[claim],
            )
        ]
        assert report.technical_analysis is not None
        report.technical_analysis.technique_procedures = [
            TechniqueProcedure(technique_id="T1027", procedure="")
        ]
        return report

    analyst = MarkdownRenderer(layout=ANALYST).render(_with_record(_made(), "procedures.1"))
    row = next(line for line in analyst.splitlines() if "T1027" in line and line.startswith("|"))
    # The Procedure cell; the Evidence cell after it cites the technique's entries.
    assert row.split(" | ")[3] == "-"
    assert "rolling XOR key" not in row
    # With no record, the claim's first sentence still stands in for a procedure never written.
    analyst = MarkdownRenderer(layout=ANALYST).render(_made())
    row = next(line for line in analyst.splitlines() if "T1027" in line and line.startswith("|"))
    assert "rolling XOR key" in row


def test_a_cell_refused_in_the_first_turn_and_not_answered_again_is_left_out_as_refused() -> None:
    report = _cells_and_bullet()
    keep = _at("communications.1.encryption", _row(CELL, "keep", ["string_resolution"], quote="x"))
    others = [_at("limitations", _beside()), _at("capability_summary.1", _row(BULLET, "keep", []))]
    done = _ask(report, _Reporter({"sentences": [keep, *others]}, {"sentences": others}))
    assert report.c2_channels[0].encryption == ""
    assert (
        "communications.1.encryption",
        _left_out(
            _CELL_LABEL,
            "kept on no source a check accepts: string_resolution, quoting 'x': "
            "agreement.keep_unquoted",
            CELL,
        ),
    ) in [(r["subject"], r["message"]) for r in done.tally.unresolved if r["code"] == DROPPED_CODE]


def test_a_cell_or_bullet_never_takes_a_closing_sentence_s_name_fact(monkeypatch: Any) -> None:
    import malspark.reporting.section_agreement as agreement

    limitations = f"{FIRST} {_UNKNOWN}"
    # A budget the limitations sentence's own fact fills exactly.
    monkeypatch.setattr(agreement, "_NAMES_PER_QUESTION", 379)
    report = _report(limitations)
    assert report.technical_analysis is not None
    report.technical_analysis.capability_summary = [
        CapabilityBullet(text="Which export the loader calls is not established.")
    ]
    passages = passages_of(report, entries=_ledger())
    assert [(p.id, dict(p.ledger_named)) for p in passages if p.ledger_named] == [
        ("limitations", {_UNKNOWN: ("ledger.1",)})
    ]
    assert [(p.id, p.text) for p in passages if p.id.startswith("ledger.")] == [
        (
            "ledger.1",
            '"QueryHostMode": the function index (ev_0109) lists a call to it from the routine '
            "at offset 0x5a10 through the slot at offset 0xb90; ev_0107 lists the code of the "
            'routine at offset 0x5a10: "[… 3 lines …]\\n  int self = (*_DAT_2470c38)();  /* '
            "2470c38 = ReadSelfToken */\\n  (*_DAT_2470b90)(self,&mode);  /* 2470b90 = "
            'QueryHostMode */\\n  if (mode == 0) { return -1; }\\n[… 2 lines …]"',
        ),
        (
            "ledger.left",
            "1 name the ledger holds not shown: budget (379 characters of such facts per "
            "question); a sentence held only on them is not held",
        ),
    ]


_S5 = "Routine 0x5a10 encrypts each report with RC4 under a 16-byte key [ev_0107]."


def _with_section_5() -> MalwareReport:
    report = _cells_and_bullet()
    assert report.technical_analysis is not None
    assert report.technical_analysis.string_resolution is not None
    report.technical_analysis.string_resolution.body = _S5
    return report


@pytest.mark.parametrize("order", ["passing first", "refused first"])
@pytest.mark.parametrize(
    ("pid", "sentence"),
    [
        ("communications.1.encryption", CELL),
        ("capability_summary.1", BULLET),
        ("limitations", FIRST),
    ],
)
def test_an_answer_that_passes_answers_its_sentence_whatever_another_row_says(
    order: str, pid: str, sentence: str
) -> None:
    report = _with_section_5()
    passing = _at(pid, _row(sentence, "keep", [], reason="no source speaks of it"))
    refused = _at(pid, _row(sentence, "keep", ["string_resolution"], quote="zz"))
    pair = [passing, refused] if order == "passing first" else [refused, passing]
    others = [
        _at(p, _row(s, "keep", [], reason="no source speaks of it"))
        for p, s in (
            ("limitations", FIRST),
            ("capability_summary.1", BULLET),
            ("communications.1.encryption", CELL),
        )
        if p != pid
    ]
    counts, records = _applied(report, [*pair, *others])
    # The sentence stands as the passing row leaves it, with one record; the refused row is
    # not applied.
    assert (counts["dropped"], counts["not_applied"], counts["kept"]) == (0, 1, 3)
    assert report.c2_channels[0].encryption == CELL
    assert report.technical_analysis is not None
    assert report.technical_analysis.capability_summary[0].text == BULLET
    limitations = report.technical_analysis.analyst_limitations
    assert limitations is not None and limitations.body == FIRST
    assert sorted(records) == sorted(
        (
            "agreement.held_kept",
            "",
            f"The agreement question kept a held sentence of {held_label} on no source, because "
            f"'no source speaks of it': {held!r} stands as written.",
        )
        for held_label, held in (
            ("11. Limitations", FIRST),
            (_BULLET_LABEL, BULLET),
            (_CELL_LABEL, CELL),
        )
    )


def test_a_quote_shorter_than_the_floor_is_refused_for_that_and_told_the_end() -> None:
    passages = passages_of(_with_section_5(), entries=_ledger())
    others = [
        _at("limitations", _beside()),
        _at("capability_summary.1", _row(BULLET, "keep", [], reason="no source speaks of it")),
    ]
    told = f"{_KEEP_TOLD} {_CELL_TOLD}"
    # "RC4" stands in section 5, but is shorter than the floor: the refusal says so.
    short = _at(
        "communications.1.encryption", _row(CELL, "keep", ["string_resolution"], quote="RC4")
    )
    assert [
        (v.code, v.path, v.message)
        for v in agreement_violations({"sentences": [short, *others]}, passages)
    ] == [
        (
            "agreement.keep_unquoted",
            "sentences.0.quote",
            "row 1: communications.1.encryption keeps 'Not established.' on string_resolution, "
            "but its quote is shorter than 12 characters, so it quotes nothing; quote at least 12 "
            f"characters of the source's words: {told}",
        )
    ]
    # A quote long enough that stands nowhere is refused for that.
    elsewhere = _at(
        "communications.1.encryption",
        _row(CELL, "keep", ["string_resolution"], quote="a quote nowhere to be found"),
    )
    assert [
        (v.code, v.path, v.message)
        for v in agreement_violations({"sentences": [elsewhere, *others]}, passages)
    ] == [
        (
            "agreement.keep_unquoted",
            "sentences.0.quote",
            "row 1: communications.1.encryption keeps 'Not established.' on string_resolution, "
            f"but its quote does not stand in a source it names: {told}",
        )
    ]


def test_a_refused_rewrite_of_a_cell_is_left_out_for_its_refusal() -> None:
    report = _with_section_5()
    rewrite = _at(
        "communications.1.encryption",
        _row(CELL, "rewrite", ["capability_summary.1"], rewrite="RC4 over each report [ev_0999]."),
    )
    bullet = _at("capability_summary.1", _row(BULLET, "keep", [], reason="no source speaks of it"))
    counts, records = _applied(report, [rewrite, _at("limitations", _beside()), bullet])
    assert report.c2_channels[0].encryption == ""
    assert [r for r in records if r[0] == DROPPED_CODE] == [
        (
            DROPPED_CODE,
            "communications.1.encryption",
            _CELL_LEFT_OUT_REFUSED,
        )
    ]


_CELL_LEFT_OUT_REFUSED = (
    "The agreement question leaves a sentence of 5. Technical analysis, channel row 1, "
    "encryption out of the section (no rewrite of it passed the checks; a table cell, every "
    "sentence of which is answered: agreement.unknown_source, agreement.rewrite_cites_elsewhere, "
    "agreement.rewrite_ungrounded, report.citation_not_evidence): 'Not established.'."
)


def test_the_system_prompt_keeps_only_a_passage_marked_read_only_as_written() -> None:
    from malspark.reporting.section_agreement import SYSTEM_PROMPT

    assert (
        "or the passage is marked (read only): a passage so marked is listed with keep and "
        "never rewritten."
    ) in SYSTEM_PROMPT
    assert "a table cell is listed with keep" not in SYSTEM_PROMPT


def test_only_bullets_left_out_count_in_the_analyst_summary_line_not_the_bundle_s() -> None:
    report = _report(FIRST)
    report.executive_summary = ""
    report.key_findings = []
    assert report.technical_analysis is not None
    report.technical_analysis.capability_summary = [
        CapabilityBullet(text=""),
        CapabilityBullet(text=""),
    ]
    records = [(DROPPED_CODE, f"capability_summary.{n}", "left out") for n in (1, 2)]
    bundle, analyst = _printed(report, records)
    # The analyst report prints the bullets, so counts them; the bundle prints none.
    assert (
        "No summary is printed in this run: the 2 sentences the report model wrote were left "
        "out; the findings below are the platform's own record of what the run established."
    ) in analyst
    assert "No summary was written: the report model wrote none." in bundle
    assert "No summary is printed" not in bundle


def test_a_record_of_procedure_10_leaves_procedure_1_as_before() -> None:
    claim = "The loader decodes its strings with a rolling XOR key [ev_0107]."
    report = _report(FIRST)
    report.capability_matrix = [
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id=f"T10{n:02d}",
            technique_name=f"Technique {n}",
            evidence=[claim],
        )
        for n in range(1, 11)
    ]
    assert report.technical_analysis is not None
    report.technical_analysis.technique_procedures = [
        TechniqueProcedure(technique_id=f"T10{n:02d}", procedure="") for n in range(1, 11)
    ]
    analyst = MarkdownRenderer(layout=ANALYST).render(_with_record(report, "procedures.10"))

    def _row_of(technique: str) -> str:
        return next(
            line for line in analyst.splitlines() if f"| {technique} " in line or technique in line
        )

    # The record names procedure 10 alone: procedure 1 is no left-out one.
    assert "rolling XOR key" in _row_of("T1001")
    assert _row_of("T1010").split(" | ")[3] == "-"


# What the last refusal of a row answering a cell or a bullet ends with: what the field is,
# every end that passes for it, and what becomes of it where none does; said once a row.
_PASSING_ENDS = (
    "every sentence of which is answered: rewrite it on the source that states otherwise, "
    "citing an entry that source cites; keep it naming the source you read and found agreeing, "
    'with "quote": its words that state the same thing, copied exactly, or with "sources": [] '
    'and "reason" where no source speaks of it; or drop it with "reason". If no answer for it '
    "passes the checks, it is left out of the report, and "
)
_CELL_TOLD = (
    f"communications.1.encryption is a table cell, {_PASSING_ENDS}a cell left with no sentence "
    'prints "-".'
)
_BULLET_TOLD = (
    f"capability_summary.1 is a capability bullet of the summary, {_PASSING_ENDS}a bullet left "
    "with no sentence is not printed."
)
_KEEP_TOLD = (
    "quote the words of a source that state the same thing, or rewrite the sentence on the "
    "source that states otherwise."
)
_NOT_SHOWN = (
    "row 1: [ev_0999] is not an entry this answer was shown. Cite an entry by its evidence id "
    "in brackets — this answer may cite ev_0101, ev_0102, ev_0103, ev_0104, ev_0107, ev_0109 — "
    "or write the sentence witho…"
)
_UNGROUNDED = (
    "row 1: the rewrite cites none of the ids its sources cite. Cite the entry a source rests "
    "on, or keep the sentence."
)


def _refusals(pid: str, row: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Every refusal of the agreement round's two checks for ``row`` answering ``pid``, the
    other passages answered by a passing row each."""
    ledger = _ledger()
    citable = [str(e.id) for e in ledger]
    entries = EntryTexts.from_ledger(ledger)
    passages = passages_of(_with_section_5(), entries=ledger)
    others = [
        _at(p, _row(s, "keep", [], reason="no source speaks of it"))
        for p, s in (
            ("limitations", FIRST),
            ("capability_summary.1", BULLET),
            ("communications.1.encryption", CELL),
        )
        if p != pid
    ]
    payload = {"sentences": [_at(pid, row), *others]}
    return [
        (v.code, v.path, v.message)
        for v in [
            *agreement_violations(payload, passages, citable, None, entries),
            *rewrites_violations(payload, citable, None, entries, passages),
        ]
    ]


@pytest.mark.parametrize(
    ("pid", "row", "expected"),
    [
        (
            "communications.1.encryption",
            _row(CELL, "keep", []),
            [
                (
                    "agreement.unknown_source",
                    "sentences.0.sources",
                    "row 1 names no source. Name the ids of the sources you read for the "
                    "sentence of communications.1.encryption, or, keeping a sentence no source "
                    f"speaks of, or leaving one out, give the reason. {_CELL_TOLD}",
                )
            ],
        ),
        (
            "communications.1.encryption",
            _row(CELL, "keep", ["string_resolution"], quote="RC4"),
            [
                (
                    "agreement.keep_unquoted",
                    "sentences.0.quote",
                    "row 1: communications.1.encryption keeps 'Not established.' on "
                    "string_resolution, but its quote is shorter than 12 characters, so it "
                    "quotes nothing; quote at least 12 characters of the source's words: "
                    f"{_KEEP_TOLD} {_CELL_TOLD}",
                )
            ],
        ),
        (
            "communications.1.encryption",
            _row(CELL, "keep", ["string_resolution"], quote="a quote nowhere to be found"),
            [
                (
                    "agreement.keep_unquoted",
                    "sentences.0.quote",
                    "row 1: communications.1.encryption keeps 'Not established.' on "
                    "string_resolution, but its quote does not stand in a source it names: "
                    f"{_KEEP_TOLD} {_CELL_TOLD}",
                )
            ],
        ),
        (
            "communications.1.encryption",
            _row(CELL, "rewrite", ["string_resolution"], rewrite="RC4 over each report [ev_0999]."),
            [
                (
                    "agreement.rewrite_cites_elsewhere",
                    "sentences.0.rewrite",
                    "row 1: the rewrite cites ev_0999, which neither its sources nor "
                    "communications.1.encryption cite. Cite only what the sources you name, or "
                    "the passage itself, cite.",
                ),
                ("agreement.rewrite_ungrounded", "sentences.0.rewrite", _UNGROUNDED),
                (
                    "report.citation_not_evidence",
                    "sentences.0.rewrite",
                    f"{_NOT_SHOWN} {_CELL_TOLD}",
                ),
            ],
        ),
        (
            "capability_summary.1",
            _row(BULLET, "keep", []),
            [
                (
                    "agreement.unknown_source",
                    "sentences.0.sources",
                    "row 1 names no source. Name the ids of the sources you read for the "
                    "sentence of capability_summary.1, or, keeping a sentence no source speaks "
                    f"of, or leaving one out, give the reason. {_BULLET_TOLD}",
                )
            ],
        ),
        (
            "capability_summary.1",
            _row(BULLET, "keep", ["string_resolution"], quote="host mode"),
            [
                (
                    "agreement.keep_unquoted",
                    "sentences.0.quote",
                    f"row 1: capability_summary.1 keeps {BULLET!r} on string_resolution, but its "
                    "quote is shorter than 12 characters, so it quotes nothing; quote at least 12 "
                    f"characters of the source's words: {_KEEP_TOLD} {_BULLET_TOLD}",
                )
            ],
        ),
        (
            "capability_summary.1",
            _row(BULLET, "rewrite", ["string_resolution"], rewrite="It resolves a mode [ev_0999]."),
            [
                (
                    "agreement.rewrite_cites_elsewhere",
                    "sentences.0.rewrite",
                    "row 1: the rewrite cites ev_0999, which neither its sources nor "
                    "capability_summary.1 cite. Cite only what the sources you name, or the "
                    "passage itself, cite.",
                ),
                (
                    "agreement.rewrite_drops_citation",
                    "sentences.0.rewrite",
                    "row 1: the sentence cites ev_0107, which the rewrite does not. Keep every id "
                    "the sentence cites, or keep the sentence.",
                ),
                ("agreement.rewrite_ungrounded", "sentences.0.rewrite", _UNGROUNDED),
                (
                    "report.citation_not_evidence",
                    "sentences.0.rewrite",
                    f"{_NOT_SHOWN} {_BULLET_TOLD}",
                ),
            ],
        ),
    ],
)
def test_every_row_refused_for_a_cell_or_bullet_says_once_what_it_is_and_every_end(
    pid: str, row: dict[str, Any], expected: list[tuple[str, str, str]]
) -> None:
    assert _refusals(pid, row) == expected


def test_a_keep_naming_a_source_with_no_quote_is_refused_for_giving_none() -> None:
    assert _refusals("communications.1.encryption", _row(CELL, "keep", ["string_resolution"])) == [
        (
            "agreement.keep_unquoted",
            "sentences.0.quote",
            "row 1: communications.1.encryption keeps 'Not established.' on string_resolution, "
            "but gives no quote; quote at least 12 characters of the source's words: "
            f"{_KEEP_TOLD} {_CELL_TOLD}",
        )
    ]


def test_a_quote_of_exactly_the_floor_is_not_too_short() -> None:
    from malspark.reporting.absence_answers import quote_stands, quote_too_short

    # Twelve characters, as read: the floor, which a quote may reach.
    assert (quote_too_short("a host mode."), quote_too_short("host mode.")) == (False, True)
    assert quote_stands("a host mode.", ["It reads a host mode."]) is True


@pytest.mark.parametrize("order", ["passing first", "refused first"])
@pytest.mark.parametrize(
    "refused",
    [
        _row(CELL, "keep", ["string_resolution"], quote="zz"),
        _row(CELL, "rewrite", ["string_resolution"], rewrite="RC4 over each report [ev_0999]."),
    ],
    ids=["refused keep", "refused rewrite"],
)
def test_a_refused_row_beside_a_passing_one_for_its_sentence_asks_nothing_more(
    order: str, refused: dict[str, Any]
) -> None:
    passing = _at("communications.1.encryption", _row(CELL, "keep", [], reason="no source speaks"))
    pair = [passing, _at("communications.1.encryption", refused)]
    rows = [
        *(pair if order == "passing first" else pair[::-1]),
        _at("limitations", _beside()),
        _at("capability_summary.1", _row(BULLET, "keep", [], reason="no source speaks of it")),
    ]
    ledger = _ledger()
    citable = [str(e.id) for e in ledger]
    entries = EntryTexts.from_ledger(ledger)
    passages = passages_of(_with_section_5(), entries=ledger)
    payload = {"sentences": rows}
    assert agreement_violations(payload, passages, citable, None, entries) == []
    assert rewrites_violations(payload, citable, None, entries, passages) == []
    # That was the only refusal: the round makes one call, and records no refusal.
    report = _with_section_5()
    reporter = _Reporter(payload, payload)
    done = _ask(report, reporter)
    assert len(reporter.asked) == 1
    assert report.c2_channels[0].encryption == CELL
    assert [r["code"] for r in done.tally.unresolved] == ["agreement.held_kept"] * 3


_HELD_CELL = "Which export the loader calls is not established."


def _held_cell() -> MalwareReport:
    report = _report(FIRST)
    report.c2_channels = [C2Channel(name="HTTP channel", encryption=_HELD_CELL)]
    return report


def test_a_cell_the_ledger_holds_is_asked_again_after_an_empty_answer_told_its_ends() -> None:
    passages = passages_of(_held_cell(), entries=_ledger())
    found = agreement_violations({"sentences": []}, passages)
    # Held on a name the run holds, not only by its kind: asked about where no row could be
    # read, told the ends of a held sentence and what an emptied cell prints.
    assert [(v.code, v.path, v.message) for v in found] == [
        (
            HELD_UNLISTED_CODE,
            "held.communications.1.encryption",
            "communications.1.encryption names what a ledger.N fact shows, and no row lists "
            f"this sentence: {_HELD_CELL!r}. List it: it names what ledger.1 holds lines on: a "
            "keep of it as written is refused, and the same words with a citation added are a "
            "keep; rewrite it in your own words on the lines shown, citing the entry they come "
            "from, saying what the lines show and what stays unknown, each denial in it "
            "followed at once by the entry it rests on, one shown for it, or drop it. If no "
            "answer for it passes the checks, it is left out of the report, and a cell left "
            'with no sentence prints "-". Answer with every row again, this one included.',
        ),
        (
            HELD_UNLISTED_CODE,
            "held.limitations",
            "limitations holds a sentence of a closing section, every one of which is answered, "
            f"and no row lists this sentence: {FIRST!r}. List it: rewrite it on the source that "
            "states otherwise, or keep it naming the source you read and found agreeing, quoting "
            "its words, or leave it out giving the reason. Answer with every row again, this one "
            "included.",
        ),
    ]


def test_a_refusal_for_a_cell_the_ledger_holds_says_what_it_is_once() -> None:
    passages = passages_of(_held_cell(), entries=_ledger())
    keep = _at("communications.1.encryption", _row(_HELD_CELL, "keep", [], reason="none"))
    found = agreement_violations({"sentences": [keep, _at("limitations", _beside())]}, passages)
    # The refusal carries the held sentence's ends already: only what the field is is added.
    assert [(v.code, v.path, v.message) for v in found] == [
        (
            "agreement.keep_unquoted",
            "sentences.0.sources",
            f"row 1: communications.1.encryption keeps {_HELD_CELL!r} naming no source, but "
            "ledger.1 speaks of what it names: it names what ledger.1 holds lines on: a keep of "
            "it as written is refused, and the same words with a citation added are a keep; "
            "rewrite it in your own words on the lines shown, citing the entry they come from, "
            "saying what the lines show and what stays unknown, each denial in it followed at "
            "once by the entry it rests on, one shown for it, or drop it. If no answer for it "
            "passes the checks, it is left out of the report, and a cell left with no sentence "
            'prints "-". communications.1.encryption is a table cell, every sentence of which is '
            "answered.",
        )
    ]


def test_a_cell_s_name_fact_comes_before_a_body_sentence_s_in_the_budget(
    monkeypatch: Any,
) -> None:
    import malspark.reporting.section_agreement as agreement

    # A budget the cell's fact fills exactly: the body sentence's fact, read after it, is
    # not shown, and its sentence is not held on it.
    monkeypatch.setattr(agreement, "_NAMES_PER_QUESTION", 146)
    report = _held_cell()
    assert report.technical_analysis is not None
    assert report.technical_analysis.string_resolution is not None
    report.technical_analysis.string_resolution.body = "No 'quietmode' text is decoded."
    passages = passages_of(report, entries=_ledger())
    assert [(p.id, dict(p.ledger_named)) for p in passages if p.ledger_named] == [
        ("communications.1.encryption", {_HELD_CELL: ("ledger.1",)})
    ]
    assert [(p.id, len(p.text)) for p in passages if p.id == "ledger.1"] == [("ledger.1", 146)]
    assert next(p.text for p in passages if p.id == "ledger.left") == (
        "1 name the ledger holds not shown: budget (146 characters of such facts per "
        "question); a sentence held only on them is not held"
    )


def test_a_keep_quoting_only_blanks_is_refused_for_giving_no_quote() -> None:
    keep = _row(CELL, "keep", ["string_resolution"], quote="   ")
    assert _refusals("communications.1.encryption", keep) == [
        (
            "agreement.keep_unquoted",
            "sentences.0.quote",
            "row 1: communications.1.encryption keeps 'Not established.' on string_resolution, "
            "but gives no quote; quote at least 12 characters of the source's words: "
            f"{_KEEP_TOLD} {_CELL_TOLD}",
        )
    ]


def _beside_the_cell(*rows: dict[str, Any]) -> dict[str, Any]:
    """An answer of ``rows`` for the cell, with the limitations sentence and the bullet each
    answered by a passing row."""
    return {
        "sentences": [
            *(_at("communications.1.encryption", row) for row in rows),
            _at("limitations", _beside()),
            _at("capability_summary.1", _row(BULLET, "keep", [], reason="no source speaks of it")),
        ]
    }


def test_a_rewrite_only_the_prose_checks_refuse_answers_nothing_for_its_sentence() -> None:
    # Its own checks pass; the report rounds' prose checks refuse it: no answer passed, so the
    # refused keep beside it is asked about, and so is the rewrite.
    payload = _beside_the_cell(
        _row(
            CELL, "rewrite", ["string_resolution"], rewrite="Routine 0x5a10 was not read [ev_0107]."
        ),
        _row(CELL, "keep", ["string_resolution"], quote="zz"),
    )
    ledger = _ledger()
    citable = [str(e.id) for e in ledger]
    entries = EntryTexts.from_ledger(ledger)
    passages = passages_of(_with_section_5(), entries=ledger)
    assert [v.code for v in agreement_violations(payload, passages, citable, None, entries)] == [
        "agreement.keep_unquoted"
    ]
    assert [v.code for v in rewrites_violations(payload, citable, None, entries, passages)] == [
        "report.absence_contradicts_ledger"
    ]


def test_a_passing_cited_rewrite_beside_a_refused_keep_asks_nothing_more_in_the_round() -> None:
    # The round reads the rewrite against the entries it may cite, as the report rounds do: it
    # passes, and the refused keep beside it asks no retry.
    rewrite = "Each report is encrypted with RC4 [ev_0107]."
    payload = _beside_the_cell(
        _row(CELL, "rewrite", ["string_resolution"], rewrite=rewrite),
        _row(CELL, "keep", ["string_resolution"], quote="zz"),
    )
    report = _with_section_5()
    reporter = _Reporter(payload, payload)
    _ask(report, reporter)
    assert len(reporter.asked) == 1
    assert report.c2_channels[0].encryption == rewrite
