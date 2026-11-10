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
    assert (
        "  [communications.1.encryption] answer every sentence of this passage, one row each "
        "(1 sentence), as the TASK asks; if no answer for it passes the checks, it is left out "
        'of the report, and a cell left with no sentence prints "-".'
    ) in text
    assert (
        "  [capability_summary.1] answer every sentence of this passage, one row each (1 "
        "sentence), as the TASK asks; if no answer for it passes the checks, it is left out of "
        "the report, and a bullet left with no sentence is not printed."
    ) in text
    assert "answer EVERY sentence of [capability_summary.1], [communications.1.encryption]," in text


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


def test_a_cell_unanswered_in_the_first_turn_is_asked_again() -> None:
    passages = passages_of(_cells_and_bullet(), entries=_ledger())
    found = agreement_violations({"sentences": [_at("limitations", _beside())]}, passages)
    assert {(v.code, v.path) for v in found if v.code == HELD_UNLISTED_CODE} >= {
        (HELD_UNLISTED_CODE, "held.communications.1.encryption"),
        (HELD_UNLISTED_CODE, "held.capability_summary.1"),
    }


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
    assert row.rstrip().endswith("| - |")
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
