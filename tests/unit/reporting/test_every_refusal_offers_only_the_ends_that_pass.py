"""Every refusal of the agreement round offers only the ends that pass, and its end holds.

A value cell saying a redone call failed, giving failed calls a number the ledger's count
does not, or calling code an entry lists not read was offered a keep that every check
refuses, a refusal of its keep said "or keep the sentence", and one said the platform
appends the ledger's listing fact to a sentence the round then left out (T-600). One table
now walks every refusal the round can raise, for every kind of passage it answers, by the
answer that raises it: each refusal is asserted whole, and what it says becomes of the
sentence where no answer passes is what the round does. Over every kind and every answer, the
ends each refusal offers are read off the refusal by the module's own end texts: each passes
when given back, and every end that passes is offered, but in dev's own end texts for a
sentence nothing holds, listed by text; the first turn's lines on each kind are held to the
same. Ends are read as answer kinds, never which entries a rewrite must cite. A
combination that cannot be raised is listed with why. Every address, entry and name here is
a neutral synthetic value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

import malspark.reporting.section_agreement as agreement
from malspark.pipeline.validation import (
    ABSENCE_CONTRADICTS_LEDGER_CODE,
    CITATION_NOT_EVIDENCE_CODE,
    CITATION_WRONG_ENTRY_CODE,
    ENTRY_CONTENTS_MISSTATED_CODE,
    PROSE_SHAPE_CODE,
    VALUE_NOT_CARRIED_CODE,
    EntryTexts,
)
from malspark.reporting.models import (
    C2Channel,
    CapabilityBullet,
    MalwareReport,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    agreement_violations,
    apply_rows,
    passages_of,
    rewrites_violations,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    HELPER,
    _lifted,
    _report,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _ledger as _names_ledger,
)

_S5 = "Routine 0x5a10 encrypts each report with RC4 under a 16-byte key [ev_0107]."
_LIMITATION = "The gate reads a host mode [ev_0107]."
_FAILED = "The decompile of 0x5a10 failed [ev_0101]."
_CONCLUSION = "The file is a loader [ev_0107]."
_CELL = "Not established."
_BULLET = "The sample resolves a host mode [ev_0107]."
_HELD = "Which export the loader calls is not established [ev_0104]."
_UNKNOWN = "The runtime result of `QueryHostMode` is not known [ev_0109]."
_COUNT = "Five tool calls failed [ev_0107]."
_UNREAD = "The routine at 0x5a10 was not read [ev_0107]."
_UNREAD_HELPER = "The routine at 0x6100 was not read [ev_0112]."
_ONE_FAILED = "One call failed."
# Sentences held two ways: on a name or a redone call, and calling code an entry lists not
# read while giving failed calls a number the ledger's count does not.
_HELD_TWICE = (
    "Which export the loader calls is not established, the routine at 0x5a10 was not read, "
    "the decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104]."
)
_UNKNOWN_TWICE = (
    "The runtime result of `QueryHostMode` is not known, the routine at 0x5a10 was not read "
    "and five tool calls failed [ev_0109]."
)
# A held absence of section 5 one passage written without the code speaks of twice: its first
# clause states the checks (a rewrite rests on it, naming the routine section 5 names), its
# second states the absence (a keep quotes it), T-652.
_ABSENT = "The routine is therefore not shown to use timing or locale checks."
_STATES_BOTH = (
    "Routine 0x5a10 runs timing and locale checks [ev_0107], and the loader runs no timing or "
    "locale checks of its own [ev_0107]."
)
_ABSENT_QUOTE = "and the loader runs no timing or locale checks of its own [ev_0107]."
_FAILED_TWICE = (
    "The decompile of 0x5a10 failed [ev_0101], so the routine at 0x5a10 was not read, and "
    "five tool calls failed."
)


def _ledger() -> list[Any]:
    """The run's ledger: a failed decompile a later one redid, its listing, the names the
    run holds, and a second routine's listing."""
    return [*_names_ledger(), _lifted("ev_0112", HELPER, "  return 0;")]


_CELL_ID = "communications.1.encryption"
_BULLET_ID = "capability_summary.1"
_HELD_BULLET_ID = "capability_summary.2"

# The kinds of passage the round answers, by what holds the sentence.
VALUE_CELL = "value cell"
BULLET = "capability bullet"
HELD_CELL = "ledger-held cell"
HELD_BULLET = "ledger-held bullet"
CONCLUSION = "conclusion sentence"
LIMITATIONS = "limitations sentence"
HELD_LIMITATIONS = "limitations sentence held to a redone call"
HELD_BODY = "held body sentence"
KINDS = (
    VALUE_CELL,
    BULLET,
    HELD_CELL,
    HELD_BULLET,
    CONCLUSION,
    LIMITATIONS,
    HELD_LIMITATIONS,
    HELD_BODY,
)
# A held absence of section 5 nothing but its shape holds: walked by the ends its refusals
# offer (:func:`test_every_message_offers_exactly_the_ends_that_pass`), never left out, so
# outside the kinds the whole-message table walks.
S5_ABSENCE = "held absence of section 5"
# The answer kinds: a row's decision, or no row for the sentence.
DECISIONS = ("keep", "rewrite", "drop", "none")


@dataclass(frozen=True)
class _Subject:
    """A sentence of one kind of passage, and the report fields it stands in."""

    kind: str
    pid: str
    sentence: str
    fields: tuple[tuple[str, str], ...] = ()
    # The fact listing the code the sentence calls not read, where it calls some so.
    listing: str = "listed.1"


def _report_of(subject: _Subject) -> MalwareReport:
    """One report holding every kind of passage, with ``subject``'s sentence in its field."""
    said = {
        _CELL_ID: _CELL,
        _BULLET_ID: _BULLET,
        _HELD_BULLET_ID: "",
        "conclusion": _CONCLUSION,
        "limitations": f"{_FAILED} {_LIMITATION}",
        "introduction": "",
        **dict(subject.fields),
    }
    report = _report(said["limitations"], background=said["introduction"])
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    ta.string_resolution.body = _S5
    if "evasion_antiforensics" in said:
        ta.evasion_antiforensics = TechnicalSubsection(
            title="Evasion", body=said["evasion_antiforensics"], evidence_refs=["ev_0107"]
        )
    report.c2_channels = [C2Channel(name="HTTP channel", encryption=said[_CELL_ID])]
    ta.capability_summary = [
        CapabilityBullet(text=text, evidence_refs=["ev_0107"])
        for text in (said[_BULLET_ID], said[_HELD_BULLET_ID])
        if text
    ]
    ta.analyst_conclusion = TechnicalSubsection(title="Conclusion", body=said["conclusion"])
    return report


SUBJECTS = {
    "cell": _Subject(VALUE_CELL, _CELL_ID, _CELL),
    "bullet": _Subject(BULLET, _BULLET_ID, _BULLET),
    "held cell": _Subject(HELD_CELL, _CELL_ID, _HELD, ((_CELL_ID, _HELD),)),
    "held bullet": _Subject(HELD_BULLET, _HELD_BULLET_ID, _HELD, ((_HELD_BULLET_ID, _HELD),)),
    "conclusion": _Subject(CONCLUSION, "conclusion", _CONCLUSION),
    "limitations": _Subject(LIMITATIONS, "limitations", _LIMITATION),
    "held limitations": _Subject(HELD_LIMITATIONS, "limitations", _FAILED),
    "held body": _Subject(HELD_BODY, "introduction", _UNKNOWN, (("introduction", _UNKNOWN),)),
    # Sentences the ledger says otherwise of, whatever a keep of them names.
    "cell failed": _Subject(VALUE_CELL, _CELL_ID, _FAILED, ((_CELL_ID, _FAILED),)),
    "cell count": _Subject(VALUE_CELL, _CELL_ID, _COUNT, ((_CELL_ID, _COUNT),)),
    "cell unread": _Subject(VALUE_CELL, _CELL_ID, _UNREAD, ((_CELL_ID, _UNREAD),)),
    "bullet failed": _Subject(BULLET, _BULLET_ID, _FAILED, ((_BULLET_ID, _FAILED),)),
    "bullet count": _Subject(BULLET, _BULLET_ID, _COUNT, ((_BULLET_ID, _COUNT),)),
    "bullet unread": _Subject(BULLET, _BULLET_ID, _UNREAD, ((_BULLET_ID, _UNREAD),)),
    "conclusion failed": _Subject(CONCLUSION, "conclusion", _FAILED, (("conclusion", _FAILED),)),
    "conclusion count": _Subject(CONCLUSION, "conclusion", _COUNT, (("conclusion", _COUNT),)),
    "conclusion unread": _Subject(CONCLUSION, "conclusion", _UNREAD, (("conclusion", _UNREAD),)),
    "limitations count": _Subject(
        LIMITATIONS, "limitations", _COUNT, (("limitations", f"{_FAILED} {_COUNT}"),)
    ),
    "limitations unread": _Subject(
        LIMITATIONS,
        "limitations",
        _UNREAD_HELPER,
        (("limitations", f"{_FAILED} {_UNREAD_HELPER}"),),
        "listed.2",
    ),
    "limitations one failed call": _Subject(
        LIMITATIONS, "limitations", _ONE_FAILED, (("limitations", f"{_FAILED} {_ONE_FAILED}"),)
    ),
    "held cell twice": _Subject(HELD_CELL, _CELL_ID, _HELD_TWICE, ((_CELL_ID, _HELD_TWICE),)),
    "held bullet twice": _Subject(
        HELD_BULLET, _HELD_BULLET_ID, _HELD_TWICE, ((_HELD_BULLET_ID, _HELD_TWICE),)
    ),
    "held limitations twice": _Subject(
        HELD_LIMITATIONS,
        "limitations",
        _FAILED_TWICE,
        (("limitations", f"{_FAILED_TWICE} {_LIMITATION}"),),
    ),
    "held body twice": _Subject(
        HELD_BODY, "introduction", _UNKNOWN_TWICE, (("introduction", _UNKNOWN_TWICE),)
    ),
    "section 5 absence": _Subject(
        S5_ABSENCE,
        "evasion_antiforensics",
        _ABSENT,
        (
            ("evasion_antiforensics", f"Routine 0x5a10 reads a host mode [ev_0107]. {_ABSENT}"),
            ("introduction", _STATES_BOTH),
        ),
    ),
}


def _row(subject: _Subject, decision: str, sources: list[str], **said: str) -> dict[str, Any]:
    return {
        "passage": subject.pid,
        "sentence": said.pop("sentence", subject.sentence),
        "decision": decision,
        "sources": sources,
        "rewrite": "",
        "quote": "",
        "reason": "",
        **said,
    }


# A sentence no passage holds.
_NOWHERE = "A sentence the passage does not hold."
# Each answer the table gives, as the rows for the subject's sentence: one, none, or three
# naming no sentence of its passage.
_ANSWERS: dict[str, Any] = {
    "keep, no source, no reason": lambda s: _row(s, "keep", []),
    "keep, no source, a reason": lambda s: _row(s, "keep", [], reason="no source speaks of it"),
    "keep, a source, no quote": lambda s: _row(s, "keep", ["string_resolution"]),
    "keep, a quote of a blank": lambda s: _row(s, "keep", ["string_resolution"], quote="   "),
    "keep, on the failed call's fact": lambda s: _row(
        s, "keep", ["inv.1"], quote="no function there"
    ),
    "keep, a quote no source holds": lambda s: _row(
        s, "keep", ["string_resolution"], quote="a quote nowhere to be found"
    ),
    "drop, naming a passage as its source": lambda s: _row(
        s, "drop", ["executive_summary"], reason="it says nothing"
    ),
    "rewrite, no source": lambda s: _row(s, "rewrite", [], rewrite="RC4 over each report."),
    "rewrite, the same words cited": lambda s: _row(
        s, "rewrite", ["string_resolution"], rewrite=s.sentence.rstrip(".") + " [ev_0107]."
    ),
    "rewrite, citing an entry not shown": lambda s: _row(
        s, "rewrite", ["string_resolution"], rewrite="RC4 over each report [ev_0999]."
    ),
    "rewrite, misreading entries": lambda s: _row(
        s,
        "rewrite",
        ["string_resolution"],
        rewrite=(
            "Routine 0x5a10 calls `QueryHostMode` [ev_0107]. Entry ev_0107 is empty [ev_0107]. "
            "Routine 0x5a10 was not read [ev_0107]."
        ),
    ),
    "rewrite, saying a redone call failed": lambda s: _row(
        s, "rewrite", ["inv.1"], rewrite="The decompile of 0x5a10 failed [ev_0101]."
    ),
    "rewrite, a count the ledger does not hold": lambda s: _row(
        s, "rewrite", ["inv.1"], rewrite="Five tool calls failed [ev_0101] [ev_0107]."
    ),
    "rewrite, calling listed code not read": lambda s: _row(
        s, "rewrite", ["listed.1"], rewrite="The routine at 0x5a10 was not read [ev_0107]."
    ),
    "rewrite, its absence again on the listing": lambda s: _row(
        s, "rewrite", [s.listing], rewrite=s.sentence.rstrip(".") + " [ev_0107]."
    ),
    "rewrite, no source, calling listed code not read": lambda s: _row(
        s, "rewrite", [], rewrite="The routine at 0x5a10 was not read [ev_0107]."
    ),
    "rewrite, a denial no entry follows": lambda s: _row(
        s, "rewrite", ["ledger.1"], rewrite="The loader calls no export, as the table shows."
    ),
    "keep, a quote too short": lambda s: _row(s, "keep", ["string_resolution"], quote="RC4 key"),
    "keep, quoting the listing": lambda s: _row(
        s, "keep", [s.listing], quote="lists its code (decompiled or disassembled)"
    ),
    "keep twice": lambda s: [
        _row(s, "keep", [], reason="no source speaks of it"),
        _row(s, "keep", [], reason="no source speaks of it"),
    ],
    "keep, then the same words cited": lambda s: [
        _row(s, "keep", [], reason="no source speaks of it"),
        _row(s, "rewrite", ["string_resolution"], rewrite=s.sentence.rstrip(".") + " [ev_0107]."),
    ],
    "drop, no reason": lambda s: _row(s, "drop", []),
    "rows naming no sentence of it": lambda s: [
        _row(s, "keep", ["string_resolution"], sentence=_NOWHERE, quote=_S5[:20]),
        _row(s, "rewrite", ["string_resolution"], sentence=_NOWHERE, rewrite="RC4 [ev_0107]."),
        _row(s, "drop", [], sentence=_NOWHERE, reason="none"),
    ],
    "no row": lambda s: [],
}


def _others(subject: _Subject, passages: list[Any]) -> list[dict[str, Any]]:
    """A passing drop for every other sentence the round holds, so only the subject's
    refusals are left."""
    return [
        {
            "passage": p.id,
            "sentence": s,
            "decision": "drop",
            "sources": [],
            "rewrite": "",
            "quote": "",
            "reason": "beside the point",
        }
        for p in passages
        if p.write is not None
        for s in p.held
        if (p.id, s) != (subject.pid, subject.sentence)
    ]


def _rows_of(answer: Any) -> list[dict[str, Any]]:
    return answer if isinstance(answer, list) else [answer]


def _asked(subject: _Subject, answer: Any) -> tuple[Any, ...]:
    ledger = _ledger()
    report = _report_of(subject)
    passages = passages_of(report, entries=ledger)
    payload = {"sentences": [*_rows_of(answer), *_others(subject, passages)]}
    return report, passages, payload, [str(e.id) for e in ledger], EntryTexts.from_ledger(ledger)


def _refusals(subject: _Subject, answer: Any) -> list[tuple[str, str, str]]:
    _report_, passages, payload, citable, entries = _asked(subject, answer)
    return [
        (v.code, v.path, v.message)
        for v in (
            *agreement_violations(payload, passages, citable, None, entries),
            *rewrites_violations(payload, citable, None, entries, passages),
        )
    ]


def _fits(row: dict[str, Any]) -> bool:
    """Whether ``row`` fits the schema: one that does not answers nothing."""
    try:
        agreement.AgreementRow.model_validate(row)
    except ValueError:
        return False
    return True


def _cells(subject: _Subject, answer: Any) -> set[tuple[str, str, str]]:
    """The (kind, code, answer kind) each refusal of ``answer`` stands for: a row's own by its
    decision; one asked of the sentence itself by the decision of the row answering it, or
    "none" where no row that fits the schema does."""
    rows = _rows_of(answer)
    answering = [r["decision"] for r in rows if r["sentence"] == subject.sentence and _fits(r)]
    out = set()
    for code, path, _message in _refusals(subject, answer):
        if path.startswith("sentences."):
            decision = rows[int(path.split(".")[1])]["decision"]
        else:
            decision = answering[0] if answering else "none"
        out.add((subject.kind, code, decision))
    return out


def _end(subject: _Subject, answer: Any) -> str:
    """What the round does with the subject's sentence where ``answer`` is its last."""
    report, passages, payload, citable, entries = _asked(subject, answer)
    apply_rows(payload, passages, citable=citable, entries=entries)
    after = next(
        (p.text for p in passages_of(report, entries=_ledger()) if p.id == subject.pid), ""
    )
    if subject.sentence.rstrip(".") + "; the ledger lists the code" in after:
        return "appended"
    if subject.sentence in after:
        return "as written"
    if any(row["rewrite"] and row["rewrite"] in after for row in _rows_of(answer)):
        return "rewritten"
    if subject.pid == _CELL_ID:
        assert report.c2_channels[0].encryption == ""
        return "-"
    if subject.pid.startswith("capability_summary."):
        assert report.technical_analysis is not None
        assert all(b.text != subject.sentence for b in report.technical_analysis.capability_summary)
        return "not printed"
    return "left out"


# The rewrites that pass for each sentence, by the evidence it rests on.
_RC4 = "Each report is encrypted with RC4 [ev_0107]."
_REDONE = "A later call ev_0107 lifted 0x5a10 [ev_0101] [ev_0107]."
_RECOUNTED = "One tool call failed and was redone [ev_0107]."
_READ = "The routine at 0x5a10 was decompiled [ev_0107]."
_EXPORT = "The export table names begin at offset 0x7700 [ev_0104], which calls 0x7720 [ev_0109]."
_CALLED = (
    "Routine 0x5a10 calls `QueryHostMode` [ev_0109], but what it returns at run time is not "
    "recorded [ev_0109]."
)
_SLOT_ROW = "(*_DAT_2470b90)(self,&mode);  /* 2470b90 = QueryHostMode */"
_REWRITES: dict[str, tuple[list[str], str]] = {
    "cell": (["string_resolution"], _RC4),
    "bullet": (["string_resolution"], _RC4),
    "held cell": (["ledger.1"], _EXPORT),
    "held bullet": (["ledger.1"], _EXPORT),
    "conclusion": (["string_resolution"], "The file encrypts each report with RC4 [ev_0107]."),
    "limitations": (["string_resolution"], "The gate encrypts each report with RC4 [ev_0107]."),
    "held limitations": (["inv.1"], _REDONE),
    "held body": (["ledger.1"], _CALLED),
    "cell failed": (["inv.1"], _REDONE),
    "cell count": (["inv.1"], _RECOUNTED),
    "cell unread": (["listed.1"], _READ),
    "bullet failed": (["inv.1"], _REDONE),
    "bullet count": (["inv.1"], _RECOUNTED),
    "bullet unread": (["listed.1"], _READ),
    "conclusion failed": (["inv.1"], _REDONE),
    "conclusion count": (["inv.1"], _RECOUNTED),
    "conclusion unread": (["listed.1"], _READ),
    "limitations count": (["inv.1"], _RECOUNTED),
    "limitations unread": (["listed.2"], "The routine at 0x6100 was decompiled [ev_0112]."),
    "limitations one failed call": (
        ["inv.1"],
        "A later call redid the one that failed [ev_0107].",
    ),
    "held cell twice": (
        ["ledger.1", "inv.1"],
        "The export table names begin at offset 0x7700 [ev_0104]; a later call ev_0107 lifted "
        "0x5a10 [ev_0101] [ev_0107].",
    ),
    "held bullet twice": (
        ["ledger.1", "inv.1"],
        "The export table names begin at offset 0x7700 [ev_0104]; a later call ev_0107 lifted "
        "0x5a10 [ev_0101] [ev_0107].",
    ),
    "held limitations twice": (["inv.1"], _REDONE),
    "held body twice": (["ledger.1"], _CALLED),
    "section 5 absence": (
        ["introduction"],
        "Routine 0x5a10 runs timing and locale checks [ev_0107].",
    ),
}


def _ends(name: str) -> dict[str, dict[str, Any]]:
    """Every end that passes for the subject's sentence, as an answer: a rewrite, a keep
    where one passes, and a drop."""
    subject = SUBJECTS[name]
    sources, rewrite = _REWRITES[name]
    ends = {"rewrite": _row(subject, "rewrite", sources, rewrite=rewrite)}
    if subject.kind != S5_ABSENCE:
        # A body absence nothing but its shape holds is never left out.
        ends["drop"] = _row(subject, "drop", [], reason="the run's evidence does not bear it out")
    if subject.kind == S5_ABSENCE:
        ends["keep"] = _row(subject, "keep", ["introduction"], quote=_ABSENT_QUOTE)
    if subject.kind in (VALUE_CELL, BULLET, CONCLUSION, LIMITATIONS) and name in _KEPT:
        ends["keep"] = _row(subject, "keep", [], reason="no source speaks of it")
    if subject.kind == HELD_BODY and name in _KEPT:
        ends["keep"] = _row(subject, "keep", ["ledger.1"], quote=_SLOT_ROW)
    return ends


# The subjects a keep passes for: any other is one the ledger's lines hold or say otherwise of.
_KEPT = frozenset(
    {
        "cell",
        "bullet",
        "conclusion",
        "limitations",
        "limitations one failed call",
        "held body",
        "section 5 absence",
    }
)


# What every whole message below is written of: the ends a field answered whole or a closing
# sentence no keep passes for may take, and what becomes of each where none passes.
_WHOLE = (
    "rewrite it on the source that states otherwise, citing an entry that source cites; keep it "
    'naming the source you read and found agreeing, with "quote": its words that state the same '
    'thing, copied exactly, or with "sources": [] and "reason" where no source speaks of it; or '
    'drop it with "reason"'
)
_UNKEPT = (
    "a keep of it is refused whatever it names, and the same words with a citation added are a "
    "keep; rewrite it on the source that states otherwise, citing an entry that source cites, "
    'or drop it with "reason"'
)
_DENIAL = "each denial in it followed at once by the entry it rests on, one shown for it"
_LEFT_OUT = "If no answer for it passes the checks, it is left out of the report"
_DASH = 'a cell left with no sentence prints "-"'
_NOT_PRINTED = "a bullet left with no sentence is not printed"
_CELL_IS = "communications.1.encryption is a table cell, every sentence of which is answered"
_BULLET_IS = (
    "capability_summary.1 is a capability bullet of the summary, every sentence of which is "
    "answered"
)
_HELD_BULLET_IS = (
    "capability_summary.2 is a capability bullet of the summary, every sentence of which is "
    "answered"
)
_EVERY_ROW = "Answer with every row again, this one included."
# The report rounds' own findings on a rewrite that misreads the entries it cites.
_NOT_SHOWN = (
    "row 1: [ev_0999] is not an entry this answer was shown. Cite an entry by its evidence id in "
    "brackets — this answer may cite ev_0101, ev_0102, ev_0103, ev_0104, ev_0107, ev_0109, "
    "ev_0112 — or write the sente…"
)
_WRONG_ENTRY = (
    "row 1: 'QueryHostMode' is not in ev_0107 (lift_routine), which the text cites for it; this "
    "run's evidence holds it in ev_0109 (routine_table). Cite the entry that holds the value the "
    "text states."
)
_MISSTATED = (
    "row 1: The text says ev_0107 (lift_routine) holds nothing ('Entry ev_0107 is empty "
    "[ev_0107].'); ev_0107 (lift_routine) holds 8 values in this run. State what the entry "
    "holds, or cite the entry the statemen…"
)
_NOT_READ = (
    "row 1: The text says 0x5a10 was not read ('Routine 0x5a10 was not read [ev_0107].'); "
    "ev_0107 (lift_routine) holds it in this run. State what that entry shows, or say exactly "
    "what is absent."
)

# Every refusal of the round, "code at path: message", in the order the retry shows them, by
# "subject | answer | what the round does where that answer is the last": prints "-", is not
# printed, is left out, has the ledger's listing fact appended, or stands as written.
TABLE: dict[str, list[str]] = {
    "cell | drop, naming a passage as its source | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than communications.1.encryption, but only the facts, the "
        "section 5 passages and the debate rounds listed are sources. Name the sources by "
        f"their ids. {_CELL_IS}: {_WHOLE}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell | rewrite, no source | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of communications.1.encryption, or, keeping a "
        "sentence no source speaks of, or leaving one out, give the reason.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the "
        f"entry a source rests on, or keep the sentence. {_CELL_IS}: {_WHOLE}. {_LEFT_OUT}, and "
        f"{_DASH}.",
    ],
    "cell | rewrite, citing an entry not shown | -": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor communications.1.encryption cite. Cite only "
        "what the sources you name, or the passage itself, cite.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite. Cite the entry a source rests on, or keep the sentence.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN} {_CELL_IS}: "
        f"{_WHOLE}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell | rewrite, saying a redone call failed | -": [
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of "
        "communications.1.encryption: the rewrite still says a call failed or a reading could "
        "not be made, but a later call redid it (ev_0101 by ev_0107). Cite ev_0107 and say "
        f"what it answered, or keep the sentence. {_CELL_IS}: {_WHOLE}. {_LEFT_OUT}, and "
        f"{_DASH}.",
    ],
    "cell | rewrite, a count the ledger does not hold | -": [
        "agreement.failure_count at sentences.0.rewrite: row 1: communications.1.encryption "
        "gives failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, "
        f"0 not redone) does not. State the ledger's count, or no number. {_CELL_IS}: {_WHOLE}. "
        f"{_LEFT_OUT}, and {_DASH}.",
    ],
    "cell | rewrite, calling listed code not read | -": [
        "agreement.unread_standing at sentences.0.rewrite: communications.1.encryption: the "
        "rewrite 'The routine at 0x5a10 was not read [ev_0107].' of 'Not established.' still "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        f"that fact cites, or drop it. {_EVERY_ROW}",
        "report.absence_contradicts_ledger at sentences.0.rewrite: row 1: The text says 0x5a10 "
        "was not read ('The routine at 0x5a10 was not read [ev_0107].'); ev_0107 "
        "(lift_routine) holds it in this run. State what that entry shows, or say exactly what "
        f"is absent. {_CELL_IS}: {_WHOLE}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell | rows naming no sentence of it | -": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        f"agreement.held_unlisted at held.communications.1.encryption: {_CELL_IS}, and no row "
        f"lists this sentence: 'Not established.'. List it: {_WHOLE}. {_LEFT_OUT}, and {_DASH}. "
        f"{_EVERY_ROW}",
    ],
    "bullet | drop, naming a passage as its source | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than capability_summary.1, but only the facts, the section 5 "
        "passages and the debate rounds listed are sources. Name the sources by their ids. "
        f"{_BULLET_IS}: {_WHOLE}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet | rewrite, no source | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of capability_summary.1, or, keeping a "
        "sentence no source speaks of, or leaving one out, give the reason.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        "sentence.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the "
        f"entry a source rests on, or keep the sentence. {_BULLET_IS}: {_WHOLE}. {_LEFT_OUT}, "
        f"and {_NOT_PRINTED}.",
    ],
    "bullet | rewrite, citing an entry not shown | not printed": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor capability_summary.1 cite. Cite only what the "
        "sources you name, or the passage itself, cite.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        "sentence.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite. Cite the entry a source rests on, or keep the sentence.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN} {_BULLET_IS}: "
        f"{_WHOLE}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet | rewrite, saying a redone call failed | not printed": [
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of "
        "capability_summary.1: the rewrite still says a call failed or a reading could not be "
        "made, but a later call redid it (ev_0101 by ev_0107). Cite ev_0107 and say what it "
        "answered, or keep the sentence.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        f"sentence. {_BULLET_IS}: {_WHOLE}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet | rewrite, a count the ledger does not hold | not printed": [
        "agreement.failure_count at sentences.0.rewrite: row 1: capability_summary.1 gives "
        "failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not "
        f"redone) does not. State the ledger's count, or no number. {_BULLET_IS}: {_WHOLE}. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet | rows naming no sentence of it | not printed": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in capability_summary.1 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in capability_summary.1 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in capability_summary.1 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        f"agreement.held_unlisted at held.capability_summary.1: {_BULLET_IS}, and no row lists "
        f"this sentence: 'The sample resolves a host mode [ev_0107].'. List it: {_WHOLE}. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}. {_EVERY_ROW}",
    ],
    "held cell | keep, no source, a reason | -": [
        "agreement.keep_unquoted at sentences.0.sources: row 1: communications.1.encryption "
        "keeps 'Which export the loader calls is not established [ev_0104].' naming no source, "
        "but ledger.1 speaks of what it names: it names what ledger.1 holds lines on: a keep "
        "of it as written is refused, and the same words with a citation added are a keep; "
        "rewrite it in your own words on the lines shown, citing the entry they come from, "
        f"saying what the lines show and what stays unknown, {_DENIAL}, or drop it. "
        f"{_LEFT_OUT}, and {_DASH}. {_CELL_IS}.",
    ],
    "held cell | keep, a source, no quote | -": [
        "agreement.keep_unquoted at sentences.0.quote: row 1: communications.1.encryption "
        "keeps 'Which export the loader calls is not established [ev_0104].' on "
        "string_resolution, but gives no quote: it names what ledger.1 holds lines on: a keep "
        "of it as written is refused, and the same words with a citation added are a keep; "
        "rewrite it in your own words on the lines shown, citing the entry they come from, "
        f"saying what the lines show and what stays unknown, {_DENIAL}, or drop it. "
        f"{_LEFT_OUT}, and {_DASH}. {_CELL_IS}.",
    ],
    "held cell | drop, naming a passage as its source | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than communications.1.encryption, but only the facts, the "
        "section 5 passages and the debate rounds listed are sources. Name the sources by "
        f"their ids. {_CELL_IS}: it names what ledger.1 holds lines on: a keep of it as written "
        "is refused, and the same words with a citation added are a keep; rewrite it in your "
        "own words on the lines shown, citing the entry they come from, saying what the lines "
        f"show and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
    ],
    "held cell | rewrite, no source | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of communications.1.encryption, or, leaving "
        "it out, give the reason.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0104, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the "
        f"entry a source rests on, or drop it. {_CELL_IS}: it names what ledger.1 holds lines "
        "on: a keep of it as written is refused, and the same words with a citation added are "
        "a keep; rewrite it in your own words on the lines shown, citing the entry they come "
        f"from, saying what the lines show and what stays unknown, {_DENIAL}, or drop it. "
        f"{_LEFT_OUT}, and {_DASH}.",
    ],
    "held cell | rewrite, citing an entry not shown | -": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor communications.1.encryption cite. Cite only "
        "what the sources you name, or the passage itself, cite.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0104, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite. Cite the entry a source rests on, or drop it.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN} {_CELL_IS}: it "
        "names what ledger.1 holds lines on: a keep of it as written is refused, and the same "
        "words with a citation added are a keep; rewrite it in your own words on the lines "
        "shown, citing the entry they come from, saying what the lines show and what stays "
        f"unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
    ],
    "held cell | rewrite, saying a redone call failed | -": [
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of "
        "communications.1.encryption: it says a call failed or a reading could not be made, "
        "while a later call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying "
        "what it answered, or drop it.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0104, which the rewrite does not. Keep every id the sentence cites, or drop it. "
        f"{_CELL_IS}: it names what ledger.1 holds lines on: a keep of it as written is "
        "refused, and the same words with a citation added are a keep; rewrite it in your own "
        "words on the lines shown, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
    ],
    "held cell | rows naming no sentence of it | -": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.held_unlisted at held.communications.1.encryption: "
        "communications.1.encryption names what a ledger.N fact shows, and no row lists this "
        "sentence: 'Which export the loader calls is not established [ev_0104].'. List it: it "
        "names what ledger.1 holds lines on: a keep of it as written is refused, and the same "
        "words with a citation added are a keep; rewrite it in your own words on the lines "
        "shown, citing the entry they come from, saying what the lines show and what stays "
        f"unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}. {_EVERY_ROW}",
    ],
    "held cell | no row | -": [
        "agreement.held_unlisted at held.communications.1.encryption: "
        "communications.1.encryption names what a ledger.N fact shows, and no row lists this "
        "sentence: 'Which export the loader calls is not established [ev_0104].'. List it: it "
        "names what ledger.1 holds lines on: a keep of it as written is refused, and the same "
        "words with a citation added are a keep; rewrite it in your own words on the lines "
        "shown, citing the entry they come from, saying what the lines show and what stays "
        f"unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}. {_EVERY_ROW}",
    ],
    "held bullet | keep, no source, a reason | not printed": [
        "agreement.keep_unquoted at sentences.0.sources: row 1: capability_summary.2 keeps "
        "'Which export the loader calls is not established [ev_0104].' naming no source, but "
        "ledger.1 speaks of what it names: it names what ledger.1 holds lines on: a keep of it "
        "as written is refused, and the same words with a citation added are a keep; rewrite "
        "it in your own words on the lines shown, citing the entry they come from, saying what "
        f"the lines show and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and "
        f"{_NOT_PRINTED}. {_HELD_BULLET_IS}.",
    ],
    "held bullet | drop, naming a passage as its source | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than capability_summary.2, but only the facts, the section 5 "
        "passages and the debate rounds listed are sources. Name the sources by their ids. "
        f"{_HELD_BULLET_IS}: it names what ledger.1 holds lines on: a keep of it as written is "
        "refused, and the same words with a citation added are a keep; rewrite it in your own "
        "words on the lines shown, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held bullet | rewrite, no source | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of capability_summary.2, or, leaving it out, "
        "give the reason.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0104, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the "
        f"entry a source rests on, or drop it. {_HELD_BULLET_IS}: it names what ledger.1 holds "
        "lines on: a keep of it as written is refused, and the same words with a citation "
        "added are a keep; rewrite it in your own words on the lines shown, citing the entry "
        f"they come from, saying what the lines show and what stays unknown, {_DENIAL}, or drop "
        f"it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held bullet | rewrite, citing an entry not shown | not printed": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor capability_summary.2 cite. Cite only what the "
        "sources you name, or the passage itself, cite.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0104, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite. Cite the entry a source rests on, or drop it.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN} {_HELD_BULLET_IS}: "
        "it names what ledger.1 holds lines on: a keep of it as written is refused, and the "
        "same words with a citation added are a keep; rewrite it in your own words on the "
        "lines shown, citing the entry they come from, saying what the lines show and what "
        f"stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held bullet | rewrite, saying a redone call failed | not printed": [
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of "
        "capability_summary.2: it says a call failed or a reading could not be made, while a "
        "later call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        "answered, or drop it.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0104, which the rewrite does not. Keep every id the sentence cites, or drop it. "
        f"{_HELD_BULLET_IS}: it names what ledger.1 holds lines on: a keep of it as written is "
        "refused, and the same words with a citation added are a keep; rewrite it in your own "
        "words on the lines shown, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held bullet | rows naming no sentence of it | not printed": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in capability_summary.2 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in capability_summary.2 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in capability_summary.2 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.held_unlisted at held.capability_summary.2: capability_summary.2 names what "
        "a ledger.N fact shows, and no row lists this sentence: 'Which export the loader calls "
        "is not established [ev_0104].'. List it: it names what ledger.1 holds lines on: a "
        "keep of it as written is refused, and the same words with a citation added are a "
        "keep; rewrite it in your own words on the lines shown, citing the entry they come "
        f"from, saying what the lines show and what stays unknown, {_DENIAL}, or drop it. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}. {_EVERY_ROW}",
    ],
    "held bullet | no row | not printed": [
        "agreement.held_unlisted at held.capability_summary.2: capability_summary.2 names what "
        "a ledger.N fact shows, and no row lists this sentence: 'Which export the loader calls "
        "is not established [ev_0104].'. List it: it names what ledger.1 holds lines on: a "
        "keep of it as written is refused, and the same words with a citation added are a "
        "keep; rewrite it in your own words on the lines shown, citing the entry they come "
        f"from, saying what the lines show and what stays unknown, {_DENIAL}, or drop it. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}. {_EVERY_ROW}",
    ],
    "conclusion | keep, a source, no quote | left out": [
        "agreement.keep_unquoted at sentences.0.quote: row 1: conclusion keeps 'The file is a "
        "loader [ev_0107].' on string_resolution, but gives no quote; quote at least 12 "
        "characters of the source's words: quote the words of a source that state the same "
        "thing, or rewrite the sentence on the source that states otherwise.",
    ],
    "conclusion | drop, naming a passage as its source | as written": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as what "
        "states otherwise than conclusion, but only the facts, the section 5 passages and the "
        "debate rounds listed are sources. Name the sources by their ids.",
    ],
    "conclusion | rewrite, no source | as written": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of conclusion, or, keeping a sentence no "
        "source speaks of, or leaving one out, give the reason.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        "sentence.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the entry "
        "a source rests on, or keep the sentence.",
    ],
    "conclusion | rewrite, citing an entry not shown | left out": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor conclusion cite. Cite only what the sources you "
        "name, or the passage itself, cite.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        "sentence.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite. Cite the entry a source rests on, or keep the sentence.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN}",
    ],
    "conclusion | rewrite, saying a redone call failed | left out": [
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of conclusion: the "
        "rewrite still says a call failed or a reading could not be made, but a later call "
        "redid it (ev_0101 by ev_0107). Cite ev_0107 and say what it answered, or keep the "
        "sentence.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        "sentence.",
    ],
    "conclusion | rewrite, a count the ledger does not hold | left out": [
        "agreement.failure_count at sentences.0.rewrite: row 1: conclusion gives failed calls a "
        "number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        "not. State the ledger's count, or no number.",
    ],
    "conclusion | rows naming no sentence of it | as written": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in conclusion as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in conclusion as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in conclusion as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.held_unlisted at held.conclusion: conclusion holds a sentence of a closing "
        "section, every one of which is answered, and no row lists this sentence: 'The file is "
        "a loader [ev_0107].'. List it: rewrite it on the source that states otherwise, or "
        "keep it naming the source you read and found agreeing, quoting its words, or leave it "
        f"out giving the reason. {_EVERY_ROW}",
    ],
    "limitations | drop, naming a passage as its source | as written": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as what "
        "states otherwise than limitations, but only the facts, the section 5 passages and the "
        "debate rounds listed are sources. Name the sources by their ids.",
    ],
    "limitations | rewrite, no source | as written": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of limitations, or, keeping a sentence no "
        "source speaks of, or leaving one out, give the reason.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        "sentence.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the entry "
        "a source rests on, or keep the sentence.",
    ],
    "limitations | rewrite, citing an entry not shown | left out": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor limitations cite. Cite only what the sources "
        "you name, or the passage itself, cite.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        "sentence.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite. Cite the entry a source rests on, or keep the sentence.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN}",
    ],
    "limitations | rewrite, misreading entries | left out": [
        f"report.citation_wrong_entry at sentences.0.rewrite: {_WRONG_ENTRY}",
        f"report.entry_contents_misstated at sentences.0.rewrite: {_MISSTATED}",
        f"report.absence_contradicts_ledger at sentences.0.rewrite: {_NOT_READ}",
    ],
    "limitations | rewrite, saying a redone call failed | left out": [
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of limitations: "
        "the rewrite still says a call failed or a reading could not be made, but a later call "
        "redid it (ev_0101 by ev_0107). Cite ev_0107 and say what it answered, or keep the "
        "sentence.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or keep the "
        "sentence.",
    ],
    "limitations | rewrite, a count the ledger does not hold | left out": [
        "agreement.failure_count at sentences.0.rewrite: row 1: limitations gives failed calls "
        "a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        "not. State the ledger's count, or no number.",
    ],
    "limitations | rows naming no sentence of it | as written": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.held_unlisted at held.limitations: limitations holds a sentence of a "
        "closing section, every one of which is answered, and no row lists this sentence: 'The "
        "gate reads a host mode [ev_0107].'. List it: rewrite it on the source that states "
        "otherwise, or keep it naming the source you read and found agreeing, quoting its "
        f"words, or leave it out giving the reason. {_EVERY_ROW}",
    ],
    "held limitations | keep, no source, a reason | left out": [
        "agreement.keep_unquoted at sentences.0.sources: row 1: limitations keeps 'The "
        "decompile of 0x5a10 failed [ev_0101].' naming no source, but answered.1, inv.1 "
        "speaks of what it names: it says a call failed that a later call redid: a keep of it "
        "as written is refused; rewrite it citing ev_0107 and saying what it answered, "
        f"{_DENIAL}, or drop it. {_LEFT_OUT}.",
        "agreement.failure_redone at sentences.0.decision: row 1: limitations keeps the "
        "sentence, but it says a call failed or a reading could not be made, while a later "
        "call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        f"answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
    ],
    "held limitations | drop, naming a passage as its source | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than limitations, but only the facts, the section 5 passages "
        "and the debate rounds listed are sources. Name the sources by their ids. It says a "
        "call failed that a later call redid: a keep of it as written is refused; rewrite it "
        f"citing ev_0107 and saying what it answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
    ],
    "held limitations | rewrite, no source | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of limitations, or, leaving it out, give the "
        f"reason. {_LEFT_OUT}.",
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of limitations: "
        "it replaces a sentence held to a call that failed and a later call redid (ev_0101 by "
        "ev_0107) and cites none of the calls that redid it. Rewrite it citing ev_0107 and "
        f"saying what it answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0101, which the rewrite does not. Keep every id the sentence cites, or drop it. "
        f"{_LEFT_OUT}.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the "
        f"entry a source rests on, or drop it. {_LEFT_OUT}.",
    ],
    "held limitations | rewrite, citing an entry not shown | left out": [
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of limitations: "
        "it replaces a sentence held to a call that failed and a later call redid (ev_0101 by "
        "ev_0107) and cites none of the calls that redid it. Rewrite it citing ev_0107 and "
        f"saying what it answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor limitations cite. Cite only what the sources "
        f"you name, or the passage itself, cite. {_LEFT_OUT}.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0101, which the rewrite does not. Keep every id the sentence cites, or drop it. "
        f"{_LEFT_OUT}.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        f"the ids its sources cite. Cite the entry a source rests on, or drop it. {_LEFT_OUT}.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN} {_LEFT_OUT}.",
    ],
    "held limitations | rewrite, misreading entries | left out": [
        "agreement.unread_standing at sentences.0.rewrite: limitations: the rewrite 'Routine "
        "0x5a10 calls `QueryHostMode` [ev_0107]. Entry ev_0107 is empty [ev_0107]. Routine "
        "0x5a10 was not read [ev_0107].' of 'The decompile of 0x5a10 failed [ev_0101].' still "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        f"that fact cites, or drop it. {_EVERY_ROW} {_LEFT_OUT}.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0101, which the rewrite does not. Keep every id the sentence cites, or drop it. "
        f"{_LEFT_OUT}.",
        f"report.citation_wrong_entry at sentences.0.rewrite: {_WRONG_ENTRY} {_LEFT_OUT}.",
        f"report.entry_contents_misstated at sentences.0.rewrite: {_MISSTATED} {_LEFT_OUT}.",
        f"report.absence_contradicts_ledger at sentences.0.rewrite: {_NOT_READ} It says a call "
        "failed that a later call redid: a keep of it as written is refused; rewrite it citing "
        f"ev_0107 and saying what it answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
    ],
    "held limitations | rows naming no sentence of it | left out": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.held_unlisted at held.limitations: limitations holds a sentence of a "
        "closing section, every one of which is answered, and no row lists this sentence: 'The "
        "decompile of 0x5a10 failed [ev_0101].'. List it: it says a call failed that a later "
        "call redid: a keep of it as written is refused; rewrite it citing ev_0107 and saying "
        f"what it answered, {_DENIAL}, or drop it. {_LEFT_OUT}. {_EVERY_ROW}",
    ],
    "held limitations | no row | left out": [
        "agreement.held_unlisted at held.limitations: limitations holds a sentence of a "
        "closing section, every one of which is answered, and no row lists this sentence: 'The "
        "decompile of 0x5a10 failed [ev_0101].'. List it: it says a call failed that a later "
        "call redid: a keep of it as written is refused; rewrite it citing ev_0107 and saying "
        f"what it answered, {_DENIAL}, or drop it. {_LEFT_OUT}. {_EVERY_ROW}",
    ],
    "held body | rewrite, no source | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of introduction, or, leaving it out, give "
        f"the reason. {_LEFT_OUT}.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0109, which the rewrite does not. Keep every id the sentence cites, or keep it "
        'naming ledger.1, with "quote": words inside one of its rows that name what the '
        f"sentence names, copied exactly, or drop it. {_LEFT_OUT}.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the "
        'entry a source rests on, or keep it naming ledger.1, with "quote": words inside one '
        "of its rows that name what the sentence names, copied exactly, or drop it. It names "
        'what ledger.1 holds lines on: keep it naming that fact, with "quote": words inside '
        "one of its rows that name what the sentence names, copied exactly; or rewrite it in "
        f"your own words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop "
        f"it. {_LEFT_OUT}.",
    ],
    "held body | rewrite, misreading entries | left out": [
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0109, which the rewrite does not. Keep every id the sentence cites, or keep it "
        'naming ledger.1, with "quote": words inside one of its rows that name what the '
        f"sentence names, copied exactly, or drop it. {_LEFT_OUT}.",
        f"report.citation_wrong_entry at sentences.0.rewrite: {_WRONG_ENTRY} {_LEFT_OUT}.",
        f"report.entry_contents_misstated at sentences.0.rewrite: {_MISSTATED} {_LEFT_OUT}.",
        f"report.absence_contradicts_ledger at sentences.0.rewrite: {_NOT_READ} It names what "
        'ledger.1 holds lines on: keep it naming that fact, with "quote": words inside one of '
        "its rows that name what the sentence names, copied exactly; or rewrite it in your own "
        f"words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop it. "
        f"{_LEFT_OUT}.",
    ],
    "held body | rewrite, saying a redone call failed | left out": [
        "agreement.failure_redone at sentences.0.rewrite: row 1: the rewrite of introduction: "
        "the rewrite still says a call failed or a reading could not be made, but a later call "
        "redid it (ev_0101 by ev_0107). Cite ev_0107 and say what it answered, or keep it "
        'naming ledger.1, with "quote": words inside one of its rows that name what the '
        f"sentence names, copied exactly, or drop it. {_LEFT_OUT}.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0109, which the rewrite does not. Keep every id the sentence cites, or keep it "
        'naming ledger.1, with "quote": words inside one of its rows that name what the '
        "sentence names, copied exactly, or drop it. It names what ledger.1 holds lines on: "
        'keep it naming that fact, with "quote": words inside one of its rows that name what '
        "the sentence names, copied exactly; or rewrite it in your own words on the lines "
        f"shown, citing an entry the fact cites, {_DENIAL}; or drop it. {_LEFT_OUT}.",
    ],
    "held body | rows naming no sentence of it | left out": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in introduction as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in introduction as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in introduction as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.held_unlisted at held.introduction: introduction calls something absent "
        "from the whole code read, and no row lists this sentence: 'The runtime result of "
        "`QueryHostMode` is not known [ev_0109].'. List it: it names what ledger.1 holds lines "
        'on: keep it naming that fact, with "quote": words inside one of its rows that name '
        "what the sentence names, copied exactly; or rewrite it in your own words on the lines "
        f"shown, citing an entry the fact cites, {_DENIAL}; or drop it. {_LEFT_OUT}. "
        f"{_EVERY_ROW}",
    ],
    "cell failed | keep, no source, no reason | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.keep_unquoted at sentences.0.sources: row 1: communications.1.encryption "
        "keeps 'The decompile of 0x5a10 failed [ev_0101].' naming no source, but answered.1, "
        f"inv.1 speaks of what it names: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
        "agreement.failure_redone at sentences.0.decision: row 1: communications.1.encryption "
        "keeps the sentence, but it says a call failed or a reading could not be made, while a "
        "later call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what "
        f"it answered, or drop it. {_CELL_IS}.",
    ],
    "cell failed | keep, no source, a reason | -": [
        "agreement.keep_unquoted at sentences.0.sources: row 1: communications.1.encryption "
        "keeps 'The decompile of 0x5a10 failed [ev_0101].' naming no source, but answered.1, "
        f"inv.1 speaks of what it names: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
        "agreement.failure_redone at sentences.0.decision: row 1: communications.1.encryption "
        "keeps the sentence, but it says a call failed or a reading could not be made, while a "
        "later call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what "
        f"it answered, or drop it. {_CELL_IS}.",
    ],
    "cell failed | rewrite, the same words cited | -": [
        "agreement.failure_redone at sentences.0.decision: row 1: communications.1.encryption "
        "rewrites the sentence into the same words, which keeps it, but it says a call failed "
        "or a reading could not be made, while a later call redid it (ev_0101 by ev_0107). "
        f"Rewrite it citing ev_0107 and saying what it answered, or drop it. {_CELL_IS}: "
        f"{_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell failed | rewrite, misreading entries | -": [
        "agreement.unread_standing at sentences.0.rewrite: communications.1.encryption: the "
        "rewrite 'Routine 0x5a10 calls `QueryHostMode` [ev_0107]. Entry ev_0107 is empty "
        "[ev_0107]. Routine 0x5a10 was not read [ev_0107].' of 'The decompile of 0x5a10 failed "
        "[ev_0101].' still calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0101, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        f"report.citation_wrong_entry at sentences.0.rewrite: {_WRONG_ENTRY}",
        f"report.entry_contents_misstated at sentences.0.rewrite: {_MISSTATED}",
        f"report.absence_contradicts_ledger at sentences.0.rewrite: {_NOT_READ} {_CELL_IS}: "
        f"{_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell failed | no row | -": [
        f"agreement.held_unlisted at held.communications.1.encryption: {_CELL_IS}, and no row "
        f"lists this sentence: 'The decompile of 0x5a10 failed [ev_0101].'. List it: {_UNKEPT}. "
        f"{_LEFT_OUT}, and {_DASH}. {_EVERY_ROW}",
    ],
    "cell count | keep, no source, no reason | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.failure_count at sentences.0.rewrite: row 1: communications.1.encryption "
        "gives failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, "
        f"0 not redone) does not. State the ledger's count, or no number. {_CELL_IS}: "
        f"{_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell count | keep, no source, a reason | -": [
        "agreement.failure_count at sentences.0.rewrite: row 1: communications.1.encryption "
        "gives failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, "
        f"0 not redone) does not. State the ledger's count, or no number. {_CELL_IS}: "
        f"{_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell count | no row | -": [
        f"agreement.held_unlisted at held.communications.1.encryption: {_CELL_IS}, and no row "
        f"lists this sentence: 'Five tool calls failed [ev_0107].'. List it: {_UNKEPT}. "
        f"{_LEFT_OUT}, and {_DASH}. {_EVERY_ROW}",
    ],
    "cell unread | keep, no source, no reason | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.unread_standing at sentences.0.decision: communications.1.encryption: 'The "
        "routine at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: communications.1.encryption "
        "keeps 'The routine at 0x5a10 was not read [ev_0107].' naming no source, but listed.1, "
        f"answered.1, inv.1 speaks of what it names: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}. "
        f"{_CELL_IS}.",
    ],
    "cell unread | keep, no source, a reason | -": [
        "agreement.unread_standing at sentences.0.decision: communications.1.encryption: 'The "
        "routine at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: communications.1.encryption "
        "keeps 'The routine at 0x5a10 was not read [ev_0107].' naming no source, but listed.1, "
        f"answered.1, inv.1 speaks of what it names: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}. "
        f"{_CELL_IS}.",
    ],
    "cell unread | drop, naming a passage as its source | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than communications.1.encryption, but only the facts, the "
        "section 5 passages and the debate rounds listed are sources. Name the sources by "
        f"their ids. {_CELL_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
        "agreement.unread_standing at held.communications.1.encryption: "
        "communications.1.encryption: 'The routine at 0x5a10 was not read [ev_0107].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW} {_CELL_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell unread | rewrite, citing an entry not shown | -": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor communications.1.encryption cite. Cite only "
        "what the sources you name, or the passage itself, cite.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite. Cite the entry a source rests on, or drop it.",
        "agreement.unread_standing at held.communications.1.encryption: "
        "communications.1.encryption: 'The routine at 0x5a10 was not read [ev_0107].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW} {_CELL_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN} {_CELL_IS}: "
        f"{_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell unread | rewrite, calling listed code not read | -": [
        "agreement.unread_standing at sentences.0.rewrite: communications.1.encryption: the "
        "rewrite 'The routine at 0x5a10 was not read [ev_0107].' of 'The routine at 0x5a10 was "
        "not read [ev_0107].' still calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        f"can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.rewrite: row 1: communications.1.encryption "
        "rewrites 'The routine at 0x5a10 was not read [ev_0107].' into the same words, which "
        "keeps it, on listed.1, but the best sentence of those sources states no absence, "
        f"while the sentence states one: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
        "agreement.unread_standing at sentences.0.decision: communications.1.encryption: 'The "
        "routine at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.absence_kept at sentences.0.rewrite: row 1: the rewrite of "
        "communications.1.encryption still states 'The routine at 0x5a10 was not read.', which "
        "listed.1 states otherwise. Leave that clause out and state what the fact states, "
        "keeping what else the sentence says that no source contradicts.",
        "report.absence_contradicts_ledger at sentences.0.rewrite: row 1: The text says 0x5a10 "
        "was not read ('The routine at 0x5a10 was not read [ev_0107].'); ev_0107 "
        "(lift_routine) holds it in this run. State what that entry shows, or say exactly what "
        f"is absent. {_CELL_IS}.",
    ],
    "cell unread | rows naming no sentence of it | -": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.unread_standing at held.communications.1.encryption: "
        "communications.1.encryption: 'The routine at 0x5a10 was not read [ev_0107].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW} {_CELL_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "cell unread | no row | -": [
        "agreement.unread_standing at held.communications.1.encryption: "
        "communications.1.encryption: 'The routine at 0x5a10 was not read [ev_0107].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW} {_CELL_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_DASH}.",
    ],
    "bullet failed | keep, no source, no reason | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.keep_unquoted at sentences.0.sources: row 1: capability_summary.1 keeps "
        "'The decompile of 0x5a10 failed [ev_0101].' naming no source, but answered.1, "
        f"inv.1 speaks of what it names: {_UNKEPT}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
        "agreement.failure_redone at sentences.0.decision: row 1: capability_summary.1 keeps "
        "the sentence, but it says a call failed or a reading could not be made, while a later "
        "call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        f"answered, or drop it. {_BULLET_IS}.",
    ],
    "bullet failed | keep, no source, a reason | not printed": [
        "agreement.keep_unquoted at sentences.0.sources: row 1: capability_summary.1 keeps "
        "'The decompile of 0x5a10 failed [ev_0101].' naming no source, but answered.1, "
        f"inv.1 speaks of what it names: {_UNKEPT}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
        "agreement.failure_redone at sentences.0.decision: row 1: capability_summary.1 keeps "
        "the sentence, but it says a call failed or a reading could not be made, while a later "
        "call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        f"answered, or drop it. {_BULLET_IS}.",
    ],
    "bullet failed | rewrite, misreading entries | not printed": [
        "agreement.unread_standing at sentences.0.rewrite: capability_summary.1: the rewrite "
        "'Routine 0x5a10 calls `QueryHostMode` [ev_0107]. Entry ev_0107 is empty [ev_0107]. "
        "Routine 0x5a10 was not read [ev_0107].' of 'The decompile of 0x5a10 failed "
        "[ev_0101].' still calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0101, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        f"report.citation_wrong_entry at sentences.0.rewrite: {_WRONG_ENTRY}",
        f"report.entry_contents_misstated at sentences.0.rewrite: {_MISSTATED}",
        f"report.absence_contradicts_ledger at sentences.0.rewrite: {_NOT_READ} {_BULLET_IS}: "
        f"{_UNKEPT}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet failed | no row | not printed": [
        f"agreement.held_unlisted at held.capability_summary.1: {_BULLET_IS}, and no row lists "
        f"this sentence: 'The decompile of 0x5a10 failed [ev_0101].'. List it: {_UNKEPT}. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}. {_EVERY_ROW}",
    ],
    "bullet count | keep, no source, no reason | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.failure_count at sentences.0.rewrite: row 1: capability_summary.1 gives "
        "failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not "
        f"redone) does not. State the ledger's count, or no number. {_BULLET_IS}: {_UNKEPT}. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet count | keep, no source, a reason | not printed": [
        "agreement.failure_count at sentences.0.rewrite: row 1: capability_summary.1 gives "
        "failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not "
        f"redone) does not. State the ledger's count, or no number. {_BULLET_IS}: {_UNKEPT}. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet count | no row | not printed": [
        f"agreement.held_unlisted at held.capability_summary.1: {_BULLET_IS}, and no row lists "
        f"this sentence: 'Five tool calls failed [ev_0107].'. List it: {_UNKEPT}. {_LEFT_OUT}, "
        f"and {_NOT_PRINTED}. {_EVERY_ROW}",
    ],
    "bullet unread | keep, no source, no reason | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.unread_standing at sentences.0.decision: capability_summary.1: 'The routine "
        "at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: capability_summary.1 keeps "
        "'The routine at 0x5a10 was not read [ev_0107].' naming no source, but listed.1, "
        f"answered.1, inv.1 speaks of what it names: {_UNKEPT}. {_LEFT_OUT}, and "
        f"{_NOT_PRINTED}. {_BULLET_IS}.",
    ],
    "bullet unread | keep, no source, a reason | not printed": [
        "agreement.unread_standing at sentences.0.decision: capability_summary.1: 'The routine "
        "at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: capability_summary.1 keeps "
        "'The routine at 0x5a10 was not read [ev_0107].' naming no source, but listed.1, "
        f"answered.1, inv.1 speaks of what it names: {_UNKEPT}. {_LEFT_OUT}, and "
        f"{_NOT_PRINTED}. {_BULLET_IS}.",
    ],
    "bullet unread | drop, naming a passage as its source | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than capability_summary.1, but only the facts, the section 5 "
        "passages and the debate rounds listed are sources. Name the sources by their ids. "
        f"{_BULLET_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
        "agreement.unread_standing at held.capability_summary.1: capability_summary.1: 'The "
        "routine at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW} "
        f"{_BULLET_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet unread | rewrite, calling listed code not read | not printed": [
        "agreement.unread_standing at sentences.0.rewrite: capability_summary.1: the rewrite "
        "'The routine at 0x5a10 was not read [ev_0107].' of 'The routine at 0x5a10 was not "
        "read [ev_0107].' still calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.rewrite: row 1: capability_summary.1 rewrites "
        "'The routine at 0x5a10 was not read [ev_0107].' into the same words, which keeps it, "
        "on listed.1, but the best sentence of those sources states no absence, while the "
        f"sentence states one: {_UNKEPT}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
        "agreement.unread_standing at sentences.0.decision: capability_summary.1: 'The routine "
        "at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.absence_kept at sentences.0.rewrite: row 1: the rewrite of "
        "capability_summary.1 still states 'The routine at 0x5a10 was not read.', which "
        "listed.1 states otherwise. Leave that clause out and state what the fact states, "
        "keeping what else the sentence says that no source contradicts.",
        "report.absence_contradicts_ledger at sentences.0.rewrite: row 1: The text says 0x5a10 "
        "was not read ('The routine at 0x5a10 was not read [ev_0107].'); ev_0107 "
        "(lift_routine) holds it in this run. State what that entry shows, or say exactly what "
        f"is absent. {_BULLET_IS}.",
    ],
    "bullet unread | rows naming no sentence of it | not printed": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in capability_summary.1 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in capability_summary.1 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in capability_summary.1 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.unread_standing at held.capability_summary.1: capability_summary.1: 'The "
        "routine at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW} "
        f"{_BULLET_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "bullet unread | no row | not printed": [
        "agreement.unread_standing at held.capability_summary.1: capability_summary.1: 'The "
        "routine at 0x5a10 was not read [ev_0107].' calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW} "
        f"{_BULLET_IS}: {_UNKEPT}. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "conclusion failed | keep, no source, no reason | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.keep_unquoted at sentences.0.sources: row 1: conclusion keeps 'The "
        "decompile of 0x5a10 failed [ev_0101].' naming no source, but answered.1, inv.1 "
        f"speaks of what it names: {_UNKEPT}.",
        "agreement.failure_redone at sentences.0.decision: row 1: conclusion keeps the "
        "sentence, but it says a call failed or a reading could not be made, while a later call "
        "redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it answered, "
        "or drop it.",
    ],
    "conclusion failed | keep, no source, a reason | left out": [
        "agreement.keep_unquoted at sentences.0.sources: row 1: conclusion keeps 'The "
        "decompile of 0x5a10 failed [ev_0101].' naming no source, but answered.1, inv.1 "
        f"speaks of what it names: {_UNKEPT}.",
        "agreement.failure_redone at sentences.0.decision: row 1: conclusion keeps the "
        "sentence, but it says a call failed or a reading could not be made, while a later call "
        "redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it answered, "
        "or drop it.",
    ],
    "conclusion failed | rewrite, the same words cited | left out": [
        "agreement.failure_redone at sentences.0.decision: row 1: conclusion rewrites the "
        "sentence into the same words, which keeps it, but it says a call failed or a reading "
        "could not be made, while a later call redid it (ev_0101 by ev_0107). Rewrite it citing "
        "ev_0107 and saying what it answered, or drop it. A keep of it is refused whatever it "
        "names, and the same words with a citation added are a keep; rewrite it on the source "
        'that states otherwise, citing an entry that source cites, or drop it with "reason".',
    ],
    "conclusion failed | rewrite, misreading entries | left out": [
        "agreement.unread_standing at sentences.0.rewrite: conclusion: the rewrite 'Routine "
        "0x5a10 calls `QueryHostMode` [ev_0107]. Entry ev_0107 is empty [ev_0107]. Routine "
        "0x5a10 was not read [ev_0107].' of 'The decompile of 0x5a10 failed [ev_0101].' still "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        "that fact cites, or drop it; refused, a rewrite resting on the sources it names "
        f"leaves it out of the report. {_EVERY_ROW}",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0101, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        f"report.citation_wrong_entry at sentences.0.rewrite: {_WRONG_ENTRY}",
        f"report.entry_contents_misstated at sentences.0.rewrite: {_MISSTATED}",
        f"report.absence_contradicts_ledger at sentences.0.rewrite: {_NOT_READ} A keep of it is "
        "refused whatever it names, and the same words with a citation added are a keep; "
        "rewrite it on the source that states otherwise, citing an entry that source cites, or "
        'drop it with "reason".',
    ],
    "conclusion failed | no row | as written": [
        "agreement.held_unlisted at held.conclusion: conclusion holds a sentence of a closing "
        "section, every one of which is answered, and no row lists this sentence: 'The "
        f"decompile of 0x5a10 failed [ev_0101].'. List it: {_UNKEPT}. {_EVERY_ROW}",
    ],
    "conclusion count | keep, no source, no reason | as written": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.failure_count at sentences.0.rewrite: row 1: conclusion gives failed calls a "
        "number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        "not. State the ledger's count, or no number. A keep of it is refused whatever it "
        "names, and the same words with a citation added are a keep; rewrite it on the source "
        'that states otherwise, citing an entry that source cites, or drop it with "reason".',
    ],
    "conclusion count | keep, no source, a reason | as written": [
        "agreement.failure_count at sentences.0.rewrite: row 1: conclusion gives failed calls a "
        "number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        "not. State the ledger's count, or no number. A keep of it is refused whatever it "
        "names, and the same words with a citation added are a keep; rewrite it on the source "
        'that states otherwise, citing an entry that source cites, or drop it with "reason".',
    ],
    "conclusion count | keep, a quote too short | left out": [
        "agreement.keep_unquoted at sentences.0.quote: row 1: conclusion keeps 'Five tool "
        "calls failed [ev_0107].' on string_resolution, but its quote is shorter than 12 "
        f"characters, so it quotes nothing: {_UNKEPT}.",
        "agreement.failure_count at sentences.0.rewrite: row 1: conclusion gives failed calls a "
        "number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        "not. State the ledger's count, or no number.",
    ],
    "conclusion count | no row | as written": [
        "agreement.held_unlisted at held.conclusion: conclusion holds a sentence of a closing "
        "section, every one of which is answered, and no row lists this sentence: 'Five tool "
        f"calls failed [ev_0107].'. List it: {_UNKEPT}. {_EVERY_ROW}",
    ],
    "conclusion unread | keep, no source, no reason | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.unread_standing at sentences.0.decision: conclusion: 'The routine at 0x5a10 "
        "was not read [ev_0107].' calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; a keep of it is refused "
        f"whatever it names, and leaves it out of the report. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: conclusion keeps 'The routine "
        "at 0x5a10 was not read [ev_0107].' naming no source, but listed.1, answered.1, "
        f"inv.1 speaks of what it names: {_UNKEPT}.",
    ],
    "conclusion unread | keep, no source, a reason | left out": [
        "agreement.unread_standing at sentences.0.decision: conclusion: 'The routine at 0x5a10 "
        "was not read [ev_0107].' calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; a keep of it is refused "
        f"whatever it names, and leaves it out of the report. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: conclusion keeps 'The routine "
        "at 0x5a10 was not read [ev_0107].' naming no source, but listed.1, answered.1, "
        f"inv.1 speaks of what it names: {_UNKEPT}.",
    ],
    "conclusion unread | drop, naming a passage as its source | appended": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as what "
        "states otherwise than conclusion, but only the facts, the section 5 passages and the "
        "debate rounds listed are sources. Name the sources by their ids. A keep of it is "
        "refused whatever it names, and the same words with a citation added are a keep; "
        "rewrite it on the source that states otherwise, citing an entry that source cites, or "
        'drop it with "reason".',
        "agreement.unread_standing at held.conclusion: conclusion: 'The routine at 0x5a10 was "
        "not read [ev_0107].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        "citing an entry that fact cites, or drop it; refused, a drop leaves it standing, and "
        f"the platform appends the ledger's listing fact to it. {_EVERY_ROW} A keep of it is "
        "refused whatever it names, and the same words with a citation added are a keep; "
        "rewrite it on the source that states otherwise, citing an entry that source cites, or "
        'drop it with "reason".',
    ],
    "conclusion unread | rewrite, citing an entry not shown | left out": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor conclusion cite. Cite only what the sources you "
        "name, or the passage itself, cite.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0107, which the rewrite does not. Keep every id the sentence cites, or drop it.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite. Cite the entry a source rests on, or drop it.",
        "agreement.unread_standing at held.conclusion: conclusion: 'The routine at 0x5a10 was "
        "not read [ev_0107].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        "citing an entry that fact cites, or drop it; refused, a rewrite resting on the "
        f"sources it names leaves it out of the report. {_EVERY_ROW} A keep of it is refused "
        "whatever it names, and the same words with a citation added are a keep; rewrite it on "
        "the source that states otherwise, citing an entry that source cites, or drop it with "
        '"reason".',
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN} A keep of it is "
        "refused whatever it names, and the same words with a citation added are a keep; "
        "rewrite it on the source that states otherwise, citing an entry that source cites, or "
        'drop it with "reason".',
    ],
    "conclusion unread | rewrite, calling listed code not read | left out": [
        "agreement.unread_standing at sentences.0.rewrite: conclusion: the rewrite 'The "
        "routine at 0x5a10 was not read [ev_0107].' of 'The routine at 0x5a10 was not read "
        "[ev_0107].' still calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        "citing an entry that fact cites, or drop it; refused, a rewrite resting on the "
        f"sources it names leaves it out of the report. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.rewrite: row 1: conclusion rewrites 'The "
        "routine at 0x5a10 was not read [ev_0107].' into the same words, which keeps it, on "
        "listed.1, but the best sentence of those sources states no absence, while the "
        f"sentence states one: {_UNKEPT}.",
        "agreement.unread_standing at sentences.0.decision: conclusion: 'The routine at 0x5a10 "
        "was not read [ev_0107].' calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; refused, a rewrite "
        f"resting on the sources it names leaves it out of the report. {_EVERY_ROW}",
        "agreement.absence_kept at sentences.0.rewrite: row 1: the rewrite of conclusion still "
        "states 'The routine at 0x5a10 was not read.', which listed.1 states otherwise. Leave "
        "that clause out and state what the fact states, keeping what else the sentence says "
        "that no source contradicts.",
        "report.absence_contradicts_ledger at sentences.0.rewrite: row 1: The text says 0x5a10 "
        "was not read ('The routine at 0x5a10 was not read [ev_0107].'); ev_0107 (lift_routine) "
        "holds it in this run. State what that entry shows, or say exactly what is absent.",
    ],
    "conclusion unread | rewrite, no source, calling listed code not read | appended": [
        "agreement.unread_standing at sentences.0.rewrite: conclusion: the rewrite 'The "
        "routine at 0x5a10 was not read [ev_0107].' of 'The routine at 0x5a10 was not read "
        "[ev_0107].' still calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        "citing an entry that fact cites, or drop it; refused, a rewrite naming no source, or "
        "one that is no fact, section 5 passage or debate round, leaves it standing, and the "
        f"platform appends the ledger's listing fact to it. {_EVERY_ROW}",
        "agreement.unknown_source at sentences.0.sources: row 1 names no source. Name the ids "
        "of the sources you read for the sentence of conclusion, or, leaving it out, give the "
        "reason.",
        "agreement.keep_unquoted at sentences.0.rewrite: row 1: conclusion rewrites 'The "
        "routine at 0x5a10 was not read [ev_0107].' into the same words, which keeps it, on , "
        "but the best sentence of those sources no sentence of the sources it names states it: "
        f"{_UNKEPT}.",
        "agreement.unread_standing at sentences.0.decision: conclusion: 'The routine at 0x5a10 "
        "was not read [ev_0107].' calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; refused, a rewrite naming "
        "no source, or one that is no fact, section 5 passage or debate round, leaves it "
        f"standing, and the platform appends the ledger's listing fact to it. {_EVERY_ROW}",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        "the ids its sources cite, and sources that cite none ground no rewrite. Cite the entry "
        "a source rests on, or drop it.",
        "report.absence_contradicts_ledger at sentences.0.rewrite: row 1: The text says 0x5a10 "
        "was not read ('The routine at 0x5a10 was not read [ev_0107].'); ev_0107 (lift_routine) "
        "holds it in this run. State what that entry shows, or say exactly what is absent.",
    ],
    "conclusion unread | rows naming no sentence of it | appended": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in conclusion as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in conclusion as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in conclusion as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.unread_standing at held.conclusion: conclusion: 'The routine at 0x5a10 was "
        "not read [ev_0107].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        "citing an entry that fact cites, or drop it; left with no row, the platform appends "
        f"the ledger's listing fact to it. {_EVERY_ROW} A keep of it is refused whatever it "
        "names, and the same words with a citation added are a keep; rewrite it on the source "
        'that states otherwise, citing an entry that source cites, or drop it with "reason".',
    ],
    "conclusion unread | no row | appended": [
        "agreement.unread_standing at held.conclusion: conclusion: 'The routine at 0x5a10 was "
        "not read [ev_0107].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        "citing an entry that fact cites, or drop it; left with no row, the platform appends "
        f"the ledger's listing fact to it. {_EVERY_ROW} A keep of it is refused whatever it "
        "names, and the same words with a citation added are a keep; rewrite it on the source "
        'that states otherwise, citing an entry that source cites, or drop it with "reason".',
    ],
    "limitations count | keep, no source, no reason | as written": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.failure_count at sentences.0.rewrite: row 1: limitations gives failed calls "
        "a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        "not. State the ledger's count, or no number. A keep of it is refused whatever it "
        "names, and the same words with a citation added are a keep; rewrite it on the source "
        'that states otherwise, citing an entry that source cites, or drop it with "reason".',
    ],
    "limitations count | keep, no source, a reason | as written": [
        "agreement.failure_count at sentences.0.rewrite: row 1: limitations gives failed calls "
        "a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        "not. State the ledger's count, or no number. A keep of it is refused whatever it "
        "names, and the same words with a citation added are a keep; rewrite it on the source "
        'that states otherwise, citing an entry that source cites, or drop it with "reason".',
    ],
    "limitations count | no row | as written": [
        "agreement.held_unlisted at held.limitations: limitations holds a sentence of a "
        "closing section, every one of which is answered, and no row lists this sentence: "
        f"'Five tool calls failed [ev_0107].'. List it: {_UNKEPT}. {_EVERY_ROW}",
    ],
    "limitations unread | keep, no source, no reason | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.unread_standing at sentences.0.decision: limitations: 'The routine at "
        "0x6100 was not read [ev_0112].' calls code not read that the ledger lists (listed.2: "
        "0x2476100 (offset 0x6100): ev_0112 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; a keep of it is refused "
        f"whatever it names, and leaves it out of the report. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: limitations keeps 'The routine "
        "at 0x6100 was not read [ev_0112].' naming no source, but listed.2 speaks of what it "
        f"names: {_UNKEPT}.",
    ],
    "limitations unread | keep, no source, a reason | left out": [
        "agreement.unread_standing at sentences.0.decision: limitations: 'The routine at "
        "0x6100 was not read [ev_0112].' calls code not read that the ledger lists (listed.2: "
        "0x2476100 (offset 0x6100): ev_0112 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; a keep of it is refused "
        f"whatever it names, and leaves it out of the report. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: limitations keeps 'The routine "
        "at 0x6100 was not read [ev_0112].' naming no source, but listed.2 speaks of what it "
        f"names: {_UNKEPT}.",
    ],
    "limitations unread | drop, naming a passage as its source | appended": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as what "
        "states otherwise than limitations, but only the facts, the section 5 passages and the "
        "debate rounds listed are sources. Name the sources by their ids. A keep of it is "
        "refused whatever it names, and the same words with a citation added are a keep; "
        "rewrite it on the source that states otherwise, citing an entry that source cites, or "
        'drop it with "reason".',
        "agreement.unread_standing at held.limitations: limitations: 'The routine at 0x6100 "
        "was not read [ev_0112].' calls code not read that the ledger lists (listed.2: "
        "0x2476100 (offset 0x6100): ev_0112 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; refused, a drop leaves it "
        f"standing, and the platform appends the ledger's listing fact to it. {_EVERY_ROW} A "
        "keep of it is refused whatever it names, and the same words with a citation added are "
        "a keep; rewrite it on the source that states otherwise, citing an entry that source "
        'cites, or drop it with "reason".',
    ],
    "limitations unread | rewrite, its absence again on the listing | left out": [
        "agreement.unread_standing at sentences.0.rewrite: limitations: the rewrite 'The "
        "routine at 0x6100 was not read [ev_0112] [ev_0107].' of 'The routine at 0x6100 was "
        "not read [ev_0112].' still calls code not read that the ledger lists (listed.2: "
        "0x2476100 (offset 0x6100): ev_0112 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; refused, a rewrite "
        f"resting on the sources it names leaves it out of the report. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.rewrite: row 1: limitations rewrites 'The "
        "routine at 0x6100 was not read [ev_0112].' into the same words, which keeps it, on "
        "listed.2, but the best sentence of those sources states no absence, while the "
        f"sentence states one: {_UNKEPT}.",
        "agreement.unread_standing at sentences.0.decision: limitations: 'The routine at "
        "0x6100 was not read [ev_0112].' calls code not read that the ledger lists (listed.2: "
        "0x2476100 (offset 0x6100): ev_0112 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; refused, a rewrite "
        f"resting on the sources it names leaves it out of the report. {_EVERY_ROW}",
        "agreement.absence_kept at sentences.0.rewrite: row 1: the rewrite of limitations still "
        "states 'The routine at 0x6100 was not read.', which listed.2 states otherwise. Leave "
        "that clause out and state what the fact states, keeping what else the sentence says "
        "that no source contradicts.",
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0107, which neither its sources nor limitations cite. Cite only what the sources "
        "you name, or the passage itself, cite.",
        "report.absence_contradicts_ledger at sentences.0.rewrite: row 1: The text says 0x6100 "
        "was not read ('The routine at 0x6100 was not read [ev_0112] [ev_0107].'); ev_0112 "
        "(lift_routine) holds it in this run. State what that entry shows, or say exactly what "
        "is absent.",
    ],
    "limitations unread | rows naming no sentence of it | appended": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.unread_standing at held.limitations: limitations: 'The routine at 0x6100 "
        "was not read [ev_0112].' calls code not read that the ledger lists (listed.2: "
        "0x2476100 (offset 0x6100): ev_0112 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; left with no row, the "
        f"platform appends the ledger's listing fact to it. {_EVERY_ROW} A keep of it is "
        "refused whatever it names, and the same words with a citation added are a keep; "
        "rewrite it on the source that states otherwise, citing an entry that source cites, or "
        'drop it with "reason".',
    ],
    "limitations unread | no row | appended": [
        "agreement.unread_standing at held.limitations: limitations: 'The routine at 0x6100 "
        "was not read [ev_0112].' calls code not read that the ledger lists (listed.2: "
        "0x2476100 (offset 0x6100): ev_0112 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        "can still say, citing an entry that fact cites, or drop it; left with no row, the "
        f"platform appends the ledger's listing fact to it. {_EVERY_ROW} A keep of it is "
        "refused whatever it names, and the same words with a citation added are a keep; "
        "rewrite it on the source that states otherwise, citing an entry that source cites, or "
        'drop it with "reason".',
    ],
    "limitations one failed call | keep, on the failed call's fact | left out": [
        "agreement.failure_redone at sentences.0.decision: row 1: limitations keeps the "
        "sentence, but it says a call failed or a reading could not be made, while a later call "
        "redid it (ev_0101 by ev_0107). Cite ev_0107 and say what it answered, or keep the "
        "sentence.",
    ],
    "held cell twice | keep, no source, no reason | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.unread_standing at sentences.0.decision: communications.1.encryption: "
        "'Which export the loader calls is not established, the routine at 0x5a10 was not "
        "read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        f"that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: communications.1.encryption "
        "keeps 'Which export the loader calls is not established, the routine at 0x5a10 was "
        "not read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] "
        "[ev_0104].' naming no source, but ledger.1, listed.1, answered.1, 1 more speaks of "
        "what it names: it names what ledger.1 holds lines on: a keep of it as written is "
        "refused, and the same words with a citation added are a keep; rewrite it in your own "
        "words on the lines shown, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
        "agreement.failure_redone at sentences.0.decision: row 1: communications.1.encryption "
        "keeps the sentence, but it says a call failed or a reading could not be made, while a "
        "later call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        "answered, or drop it.",
        "agreement.failure_count at sentences.0.rewrite: row 1: communications.1.encryption "
        "gives failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, "
        f"0 not redone) does not. State the ledger's count, or no number. {_CELL_IS}.",
    ],
    "held cell twice | keep, no source, a reason | -": [
        "agreement.unread_standing at sentences.0.decision: communications.1.encryption: "
        "'Which export the loader calls is not established, the routine at 0x5a10 was not "
        "read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        f"that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: communications.1.encryption "
        "keeps 'Which export the loader calls is not established, the routine at 0x5a10 was "
        "not read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] "
        "[ev_0104].' naming no source, but ledger.1, listed.1, answered.1, 1 more speaks of "
        "what it names: it names what ledger.1 holds lines on: a keep of it as written is "
        "refused, and the same words with a citation added are a keep; rewrite it in your own "
        "words on the lines shown, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
        "agreement.failure_redone at sentences.0.decision: row 1: communications.1.encryption "
        "keeps the sentence, but it says a call failed or a reading could not be made, while a "
        "later call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        "answered, or drop it.",
        "agreement.failure_count at sentences.0.rewrite: row 1: communications.1.encryption "
        "gives failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, "
        f"0 not redone) does not. State the ledger's count, or no number. {_CELL_IS}.",
    ],
    "held cell twice | drop, naming a passage as its source | -": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than communications.1.encryption, but only the facts, the "
        "section 5 passages and the debate rounds listed are sources. Name the sources by "
        f"their ids. {_CELL_IS}: it names what ledger.1 holds lines on: a keep of it as written "
        "is refused, and the same words with a citation added are a keep; rewrite it in your "
        "own words on the lines shown, citing the entry they come from, saying what the lines "
        f"show and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
        "agreement.unread_standing at held.communications.1.encryption: "
        "communications.1.encryption: 'Which export the loader calls is not established, the "
        "routine at 0x5a10 was not read, the decompile of 0x5a10 failed and five tool calls "
        "failed [ev_0101] [ev_0104].' calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        f"can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW} {_CELL_IS}: "
        "it names what ledger.1 holds lines on: a keep of it as written is refused, and the "
        "same words with a citation added are a keep; rewrite it in your own words on the "
        "lines shown, citing the entry they come from, saying what the lines show and what "
        f"stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
    ],
    "held cell twice | rewrite, misreading entries | -": [
        "agreement.unread_standing at sentences.0.rewrite: communications.1.encryption: the "
        "rewrite 'Routine 0x5a10 calls `QueryHostMode` [ev_0107]. Entry ev_0107 is empty "
        "[ev_0107]. Routine 0x5a10 was not read [ev_0107].' of 'Which export the loader calls "
        "is not established, the routine at 0x5a10 was not read, the decompile of 0x5a10 "
        "failed and five tool calls failed [ev_0101] [ev_0104].' still calls code not read "
        "that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code "
        "(decompiled or disassembled)). Rewrite it in your own words to state that the code "
        "was read and what the sentence can still say, citing an entry that fact cites, or "
        f"drop it. {_EVERY_ROW}",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite of "
        "communications.1.encryption denies something in '. Routine 0x5a10 was not read' and no "
        "entry shown for the sentence follows that denial at once: in a rewrite of this "
        "sentence each denial is followed at once by the entry it rests on, cited in square "
        "brackets, one of ev_0104, ev_0109.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0101, ev_0104, which the rewrite does not. Keep every id the sentence cites, or "
        "drop it.",
        f"report.citation_wrong_entry at sentences.0.rewrite: {_WRONG_ENTRY}",
        f"report.entry_contents_misstated at sentences.0.rewrite: {_MISSTATED}",
        f"report.absence_contradicts_ledger at sentences.0.rewrite: {_NOT_READ} {_CELL_IS}: it "
        "names what ledger.1 holds lines on: a keep of it as written is refused, and the same "
        "words with a citation added are a keep; rewrite it in your own words on the lines "
        "shown, citing the entry they come from, saying what the lines show and what stays "
        f"unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
    ],
    "held cell twice | rewrite, its absence again on the listing | -": [
        "agreement.unread_standing at sentences.0.rewrite: communications.1.encryption: the "
        "rewrite 'Which export the loader calls is not established, the routine at 0x5a10 was "
        "not read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] "
        "[ev_0104] [ev_0107].' of 'Which export the loader calls is not established, the "
        "routine at 0x5a10 was not read, the decompile of 0x5a10 failed and five tool calls "
        "failed [ev_0101] [ev_0104].' still calls code not read that the ledger lists "
        "(listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or "
        "disassembled)). Rewrite it in your own words to state that the code was read and what "
        f"the sentence can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.rewrite: row 1: communications.1.encryption "
        "rewrites 'Which export the loader calls is not established, the routine at 0x5a10 was "
        "not read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] "
        "[ev_0104].' into the same words, which keeps it, on listed.1, but the best sentence "
        "of those sources states no absence, while the sentence states one: it names what "
        "ledger.1 holds lines on: a keep of it as written is refused, and the same words with "
        "a citation added are a keep; rewrite it in your own words on the lines shown, citing "
        "the entry they come from, saying what the lines show and what stays unknown, "
        f"{_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
        "agreement.unread_standing at sentences.0.decision: communications.1.encryption: "
        "'Which export the loader calls is not established, the routine at 0x5a10 was not "
        "read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        f"that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.failure_count at sentences.0.rewrite: row 1: communications.1.encryption "
        "gives failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 "
        "not redone) does not. State the ledger's count, or no number.",
        "agreement.absence_kept at sentences.0.rewrite: row 1: the rewrite of "
        "communications.1.encryption still states 'the routine at 0x5a10 was not read', which "
        "listed.1 states otherwise. Leave that clause out and state what the fact states, "
        f"keeping what else the sentence says that no source contradicts. {_CELL_IS}.",
    ],
    "held cell twice | rows naming no sentence of it | -": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in communications.1.encryption as copied. Copy the whole sentence as the passage "
        "writes it; it must stand there once.",
        "agreement.unread_standing at held.communications.1.encryption: "
        "communications.1.encryption: 'Which export the loader calls is not established, the "
        "routine at 0x5a10 was not read, the decompile of 0x5a10 failed and five tool calls "
        "failed [ev_0101] [ev_0104].' calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        f"can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW} {_CELL_IS}: "
        "it names what ledger.1 holds lines on: a keep of it as written is refused, and the "
        "same words with a citation added are a keep; rewrite it in your own words on the "
        "lines shown, citing the entry they come from, saying what the lines show and what "
        f"stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
    ],
    "held cell twice | no row | -": [
        "agreement.unread_standing at held.communications.1.encryption: "
        "communications.1.encryption: 'Which export the loader calls is not established, the "
        "routine at 0x5a10 was not read, the decompile of 0x5a10 failed and five tool calls "
        "failed [ev_0101] [ev_0104].' calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        f"can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW} {_CELL_IS}: "
        "it names what ledger.1 holds lines on: a keep of it as written is refused, and the "
        "same words with a citation added are a keep; rewrite it in your own words on the "
        "lines shown, citing the entry they come from, saying what the lines show and what "
        f"stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_DASH}.",
    ],
    "held bullet twice | keep, no source, no reason | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        "out, give the reason.",
        "agreement.unread_standing at sentences.0.decision: capability_summary.2: 'Which "
        "export the loader calls is not established, the routine at 0x5a10 was not read, the "
        "decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: capability_summary.2 keeps "
        "'Which export the loader calls is not established, the routine at 0x5a10 was not "
        "read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' "
        "naming no source, but ledger.1, listed.1, answered.1, 1 more speaks of what it names: "
        "it names what ledger.1 holds lines on: a keep of it as written is refused, and the "
        "same words with a citation added are a keep; rewrite it in your own words on the "
        "lines shown, citing the entry they come from, saying what the lines show and what "
        f"stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
        "agreement.failure_redone at sentences.0.decision: row 1: capability_summary.2 keeps "
        "the sentence, but it says a call failed or a reading could not be made, while a later "
        "call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        "answered, or drop it.",
        "agreement.failure_count at sentences.0.rewrite: row 1: capability_summary.2 gives "
        "failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not "
        f"redone) does not. State the ledger's count, or no number. {_HELD_BULLET_IS}.",
    ],
    "held bullet twice | keep, no source, a reason | not printed": [
        "agreement.unread_standing at sentences.0.decision: capability_summary.2: 'Which "
        "export the loader calls is not established, the routine at 0x5a10 was not read, the "
        "decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.sources: row 1: capability_summary.2 keeps "
        "'Which export the loader calls is not established, the routine at 0x5a10 was not "
        "read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' "
        "naming no source, but ledger.1, listed.1, answered.1, 1 more speaks of what it names: "
        "it names what ledger.1 holds lines on: a keep of it as written is refused, and the "
        "same words with a citation added are a keep; rewrite it in your own words on the "
        "lines shown, citing the entry they come from, saying what the lines show and what "
        f"stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
        "agreement.failure_redone at sentences.0.decision: row 1: capability_summary.2 keeps "
        "the sentence, but it says a call failed or a reading could not be made, while a later "
        "call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        "answered, or drop it.",
        "agreement.failure_count at sentences.0.rewrite: row 1: capability_summary.2 gives "
        "failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not "
        f"redone) does not. State the ledger's count, or no number. {_HELD_BULLET_IS}.",
    ],
    "held bullet twice | drop, naming a passage as its source | not printed": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than capability_summary.2, but only the facts, the section 5 "
        "passages and the debate rounds listed are sources. Name the sources by their ids. "
        f"{_HELD_BULLET_IS}: it names what ledger.1 holds lines on: a keep of it as written is "
        "refused, and the same words with a citation added are a keep; rewrite it in your own "
        "words on the lines shown, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
        "agreement.unread_standing at held.capability_summary.2: capability_summary.2: 'Which "
        "export the loader calls is not established, the routine at 0x5a10 was not read, the "
        "decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW} {_HELD_BULLET_IS}: it names what ledger.1 holds lines "
        "on: a keep of it as written is refused, and the same words with a citation added are "
        "a keep; rewrite it in your own words on the lines shown, citing the entry they come "
        f"from, saying what the lines show and what stays unknown, {_DENIAL}, or drop it. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held bullet twice | rewrite, misreading entries | not printed": [
        "agreement.unread_standing at sentences.0.rewrite: capability_summary.2: the rewrite "
        "'Routine 0x5a10 calls `QueryHostMode` [ev_0107]. Entry ev_0107 is empty [ev_0107]. "
        "Routine 0x5a10 was not read [ev_0107].' of 'Which export the loader calls is not "
        "established, the routine at 0x5a10 was not read, the decompile of 0x5a10 failed and "
        "five tool calls failed [ev_0101] [ev_0104].' still calls code not read that the "
        "ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled "
        "or disassembled)). Rewrite it in your own words to state that the code was read and "
        "what the sentence can still say, citing an entry that fact cites, or drop it. "
        f"{_EVERY_ROW}",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite of "
        "capability_summary.2 denies something in '. Routine 0x5a10 was not read' and no entry "
        "shown for the sentence follows that denial at once: in a rewrite of this sentence each "
        "denial is followed at once by the entry it rests on, cited in square brackets, one of "
        "ev_0104, ev_0109.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0101, ev_0104, which the rewrite does not. Keep every id the sentence cites, or "
        "drop it.",
        f"report.citation_wrong_entry at sentences.0.rewrite: {_WRONG_ENTRY}",
        f"report.entry_contents_misstated at sentences.0.rewrite: {_MISSTATED}",
        f"report.absence_contradicts_ledger at sentences.0.rewrite: {_NOT_READ} "
        f"{_HELD_BULLET_IS}: it names what ledger.1 holds lines on: a keep of it as written is "
        "refused, and the same words with a citation added are a keep; rewrite it in your own "
        "words on the lines shown, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_DENIAL}, or drop it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held bullet twice | rewrite, its absence again on the listing | not printed": [
        "agreement.unread_standing at sentences.0.rewrite: capability_summary.2: the rewrite "
        "'Which export the loader calls is not established, the routine at 0x5a10 was not "
        "read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104] "
        "[ev_0107].' of 'Which export the loader calls is not established, the routine at "
        "0x5a10 was not read, the decompile of 0x5a10 failed and five tool calls failed "
        "[ev_0101] [ev_0104].' still calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        f"can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW}",
        "agreement.keep_unquoted at sentences.0.rewrite: row 1: capability_summary.2 rewrites "
        "'Which export the loader calls is not established, the routine at 0x5a10 was not "
        "read, the decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' "
        "into the same words, which keeps it, on listed.1, but the best sentence of those "
        "sources states no absence, while the sentence states one: it names what ledger.1 "
        "holds lines on: a keep of it as written is refused, and the same words with a "
        "citation added are a keep; rewrite it in your own words on the lines shown, citing "
        "the entry they come from, saying what the lines show and what stays unknown, "
        f"{_DENIAL}, or drop it. {_LEFT_OUT}, and {_NOT_PRINTED}.",
        "agreement.unread_standing at sentences.0.decision: capability_summary.2: 'Which "
        "export the loader calls is not established, the routine at 0x5a10 was not read, the "
        "decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW}",
        "agreement.failure_count at sentences.0.rewrite: row 1: capability_summary.2 gives "
        "failed calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not "
        "redone) does not. State the ledger's count, or no number.",
        "agreement.absence_kept at sentences.0.rewrite: row 1: the rewrite of "
        "capability_summary.2 still states 'the routine at 0x5a10 was not read', which "
        "listed.1 states otherwise. Leave that clause out and state what the fact states, "
        f"keeping what else the sentence says that no source contradicts. {_HELD_BULLET_IS}.",
    ],
    "held bullet twice | rows naming no sentence of it | not printed": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in capability_summary.2 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in capability_summary.2 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in capability_summary.2 as copied. Copy the whole sentence as the passage writes "
        "it; it must stand there once.",
        "agreement.unread_standing at held.capability_summary.2: capability_summary.2: 'Which "
        "export the loader calls is not established, the routine at 0x5a10 was not read, the "
        "decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW} {_HELD_BULLET_IS}: it names what ledger.1 holds lines "
        "on: a keep of it as written is refused, and the same words with a citation added are "
        "a keep; rewrite it in your own words on the lines shown, citing the entry they come "
        f"from, saying what the lines show and what stays unknown, {_DENIAL}, or drop it. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held bullet twice | no row | not printed": [
        "agreement.unread_standing at held.capability_summary.2: capability_summary.2: 'Which "
        "export the loader calls is not established, the routine at 0x5a10 was not read, the "
        "decompile of 0x5a10 failed and five tool calls failed [ev_0101] [ev_0104].' calls "
        "code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 "
        "lists its code (decompiled or disassembled)). Rewrite it in your own words to state "
        "that the code was read and what the sentence can still say, citing an entry that fact "
        f"cites, or drop it. {_EVERY_ROW} {_HELD_BULLET_IS}: it names what ledger.1 holds lines "
        "on: a keep of it as written is refused, and the same words with a citation added are "
        "a keep; rewrite it in your own words on the lines shown, citing the entry they come "
        f"from, saying what the lines show and what stays unknown, {_DENIAL}, or drop it. "
        f"{_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held limitations twice | keep, no source, no reason | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        f"out, give the reason. {_LEFT_OUT}.",
        "agreement.unread_standing at sentences.0.decision: limitations: 'The decompile of "
        "0x5a10 failed [ev_0101], so the routine at 0x5a10 was not read, and five tool calls "
        "failed.' calls code not read that the ledger lists (listed.1: 0x2475a10 (offset "
        "0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own "
        "words to state that the code was read and what the sentence can still say, citing an "
        f"entry that fact cites, or drop it. {_EVERY_ROW} {_LEFT_OUT}.",
        "agreement.keep_unquoted at sentences.0.sources: row 1: limitations keeps 'The "
        "decompile of 0x5a10 failed [ev_0101], so the routine at 0x5a10 was not read, and five "
        "tool calls failed.' naming no source, but listed.1, answered.1, inv.1 speaks of "
        "what it names: it names a call that failed and a later call redid: a keep of it as "
        "written is refused; rewrite it in your own words on what ev_0107 answered, citing it, "
        f"{_DENIAL}, or drop it; the same words with a citation added are a keep. {_LEFT_OUT}.",
        "agreement.failure_redone at sentences.0.decision: row 1: limitations keeps the "
        "sentence, but it says a call failed or a reading could not be made, while a later "
        "call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        f"answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
        "agreement.failure_count at sentences.0.rewrite: row 1: limitations gives failed calls "
        "a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        f"not. State the ledger's count, or no number. {_LEFT_OUT}.",
    ],
    "held limitations twice | keep, no source, a reason | left out": [
        "agreement.unread_standing at sentences.0.decision: limitations: 'The decompile of "
        "0x5a10 failed [ev_0101], so the routine at 0x5a10 was not read, and five tool calls "
        "failed.' calls code not read that the ledger lists (listed.1: 0x2475a10 (offset "
        "0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own "
        "words to state that the code was read and what the sentence can still say, citing an "
        f"entry that fact cites, or drop it. {_EVERY_ROW} {_LEFT_OUT}.",
        "agreement.keep_unquoted at sentences.0.sources: row 1: limitations keeps 'The "
        "decompile of 0x5a10 failed [ev_0101], so the routine at 0x5a10 was not read, and five "
        "tool calls failed.' naming no source, but listed.1, answered.1, inv.1 speaks of "
        "what it names: it names a call that failed and a later call redid: a keep of it as "
        "written is refused; rewrite it in your own words on what ev_0107 answered, citing it, "
        f"{_DENIAL}, or drop it; the same words with a citation added are a keep. {_LEFT_OUT}.",
        "agreement.failure_redone at sentences.0.decision: row 1: limitations keeps the "
        "sentence, but it says a call failed or a reading could not be made, while a later "
        "call redid it (ev_0101 by ev_0107). Rewrite it citing ev_0107 and saying what it "
        f"answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
        "agreement.failure_count at sentences.0.rewrite: row 1: limitations gives failed calls "
        "a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        f"not. State the ledger's count, or no number. {_LEFT_OUT}.",
    ],
    "held limitations twice | drop, naming a passage as its source | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than limitations, but only the facts, the section 5 passages "
        "and the debate rounds listed are sources. Name the sources by their ids. It names a "
        "call that failed and a later call redid: a keep of it as written is refused; rewrite "
        f"it in your own words on what ev_0107 answered, citing it, {_DENIAL}, or drop it; the "
        f"same words with a citation added are a keep. {_LEFT_OUT}.",
        "agreement.unread_standing at held.limitations: limitations: 'The decompile of 0x5a10 "
        "failed [ev_0101], so the routine at 0x5a10 was not read, and five tool calls failed.' "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        f"that fact cites, or drop it. {_EVERY_ROW} It names a call that failed and a later "
        "call redid: a keep of it as written is refused; rewrite it in your own words on what "
        f"ev_0107 answered, citing it, {_DENIAL}, or drop it; the same words with a citation "
        f"added are a keep. {_LEFT_OUT}.",
    ],
    "held limitations twice | rewrite, its absence again on the listing | left out": [
        "agreement.unread_standing at sentences.0.rewrite: limitations: the rewrite 'The "
        "decompile of 0x5a10 failed [ev_0101], so the routine at 0x5a10 was not read, and five "
        "tool calls failed [ev_0107].' of 'The decompile of 0x5a10 failed [ev_0101], so the "
        "routine at 0x5a10 was not read, and five tool calls failed.' still calls code not "
        "read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): ev_0107 lists its "
        "code (decompiled or disassembled)). Rewrite it in your own words to state that the "
        "code was read and what the sentence can still say, citing an entry that fact cites, "
        f"or drop it. {_EVERY_ROW} {_LEFT_OUT}.",
        "agreement.keep_unquoted at sentences.0.rewrite: row 1: limitations rewrites 'The "
        "decompile of 0x5a10 failed [ev_0101], so the routine at 0x5a10 was not read, and five "
        "tool calls failed.' into the same words, which keeps it, on listed.1, but the best "
        "sentence of those sources states no absence, while the sentence states one: it names "
        "a call that failed and a later call redid: a keep of it as written is refused; "
        f"rewrite it in your own words on what ev_0107 answered, citing it, {_DENIAL}, or drop "
        f"it; the same words with a citation added are a keep. {_LEFT_OUT}.",
        "agreement.unread_standing at sentences.0.decision: limitations: 'The decompile of "
        "0x5a10 failed [ev_0101], so the routine at 0x5a10 was not read, and five tool calls "
        "failed.' calls code not read that the ledger lists (listed.1: 0x2475a10 (offset "
        "0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own "
        "words to state that the code was read and what the sentence can still say, citing an "
        f"entry that fact cites, or drop it. {_EVERY_ROW} {_LEFT_OUT}.",
        "agreement.failure_count at sentences.0.rewrite: row 1: limitations gives failed calls "
        "a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) does "
        f"not. State the ledger's count, or no number. {_LEFT_OUT}.",
        "agreement.absence_kept at sentences.0.rewrite: row 1: the rewrite of limitations "
        "still states 'the routine at 0x5a10 was not read', which listed.1 states otherwise. "
        "Leave that clause out and state what the fact states, keeping what else the sentence "
        f"says that no source contradicts. {_LEFT_OUT}.",
        "report.absence_contradicts_ledger at sentences.0.rewrite: row 1: The text says 0x5a10 "
        "was not read ('The decompile of 0x5a10 failed [ev_0101], so the routine at 0x5a10 was "
        "not read, and five tool calls failed [ev_0107].'); ev_0107 (lift_routine) holds it in "
        f"this r… {_LEFT_OUT}.",
    ],
    "held limitations twice | rows naming no sentence of it | left out": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in limitations as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.unread_standing at held.limitations: limitations: 'The decompile of 0x5a10 "
        "failed [ev_0101], so the routine at 0x5a10 was not read, and five tool calls failed.' "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        f"that fact cites, or drop it. {_EVERY_ROW} It names a call that failed and a later "
        "call redid: a keep of it as written is refused; rewrite it in your own words on what "
        f"ev_0107 answered, citing it, {_DENIAL}, or drop it; the same words with a citation "
        f"added are a keep. {_LEFT_OUT}.",
    ],
    "held limitations twice | no row | left out": [
        "agreement.unread_standing at held.limitations: limitations: 'The decompile of 0x5a10 "
        "failed [ev_0101], so the routine at 0x5a10 was not read, and five tool calls failed.' "
        "calls code not read that the ledger lists (listed.1: 0x2475a10 (offset 0x5a10): "
        "ev_0107 lists its code (decompiled or disassembled)). Rewrite it in your own words to "
        "state that the code was read and what the sentence can still say, citing an entry "
        f"that fact cites, or drop it. {_EVERY_ROW} It names a call that failed and a later "
        "call redid: a keep of it as written is refused; rewrite it in your own words on what "
        f"ev_0107 answered, citing it, {_DENIAL}, or drop it; the same words with a citation "
        f"added are a keep. {_LEFT_OUT}.",
    ],
    "held body twice | keep, no source, no reason | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names no source; leaving it "
        f"out, give the reason. {_LEFT_OUT}.",
        "agreement.keep_unquoted at sentences.0.sources: row 1: introduction keeps 'The "
        "runtime result of `QueryHostMode` is not known, the routine at 0x5a10 was not read "
        "and five tool calls failed [ev_0109].' naming no source, but ledger.1, entry.1 speaks "
        "of what it names: it names what ledger.1 holds lines on: a keep of it is refused "
        "whatever it names; rewrite it in your own words on the lines shown, citing an entry "
        f"the fact cites, {_DENIAL}; or drop it. {_LEFT_OUT}.",
        "agreement.failure_count at sentences.0.rewrite: row 1: introduction gives failed "
        "calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) "
        f"does not. State the ledger's count, or no number. {_LEFT_OUT}.",
        "agreement.unread_standing at held.introduction: introduction: 'The runtime result of "
        "`QueryHostMode` is not known, the routine at 0x5a10 was not read and five tool calls "
        "failed [ev_0109].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW} It names what ledger.1 "
        "holds lines on: a keep of it is refused whatever it names; rewrite it in your own "
        f"words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop it. "
        f"{_LEFT_OUT}.",
    ],
    "held body twice | keep, no source, a reason | left out": [
        "agreement.keep_unquoted at sentences.0.sources: row 1: introduction keeps 'The "
        "runtime result of `QueryHostMode` is not known, the routine at 0x5a10 was not read "
        "and five tool calls failed [ev_0109].' naming no source, but ledger.1, entry.1 speaks "
        "of what it names: it names what ledger.1 holds lines on: a keep of it is refused "
        "whatever it names; rewrite it in your own words on the lines shown, citing an entry "
        f"the fact cites, {_DENIAL}; or drop it. {_LEFT_OUT}.",
        "agreement.failure_count at sentences.0.rewrite: row 1: introduction gives failed "
        "calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) "
        f"does not. State the ledger's count, or no number. {_LEFT_OUT}.",
        "agreement.unread_standing at held.introduction: introduction: 'The runtime result of "
        "`QueryHostMode` is not known, the routine at 0x5a10 was not read and five tool calls "
        "failed [ev_0109].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW} It names what ledger.1 "
        "holds lines on: a keep of it is refused whatever it names; rewrite it in your own "
        f"words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop it. "
        f"{_LEFT_OUT}.",
    ],
    "held body twice | drop, naming a passage as its source | left out": [
        "agreement.unknown_source at sentences.0.sources: row 1 names executive_summary as "
        "what states otherwise than introduction, but only the facts, the section 5 passages "
        "and the debate rounds listed are sources. Name the sources by their ids. It names "
        "what ledger.1 holds lines on: a keep of it is refused whatever it names; rewrite it "
        f"in your own words on the lines shown, citing an entry the fact cites, {_DENIAL}; or "
        f"drop it. {_LEFT_OUT}.",
        "agreement.unread_standing at held.introduction: introduction: 'The runtime result of "
        "`QueryHostMode` is not known, the routine at 0x5a10 was not read and five tool calls "
        "failed [ev_0109].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW} It names what ledger.1 "
        "holds lines on: a keep of it is refused whatever it names; rewrite it in your own "
        f"words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop it. "
        f"{_LEFT_OUT}.",
    ],
    "held body twice | rewrite, citing an entry not shown | left out": [
        "agreement.rewrite_cites_elsewhere at sentences.0.rewrite: row 1: the rewrite cites "
        "ev_0999, which neither its sources nor introduction cite. Cite only what the sources "
        f"you name, or the passage itself, cite. {_LEFT_OUT}.",
        "agreement.rewrite_drops_citation at sentences.0.rewrite: row 1: the sentence cites "
        "ev_0109, which the rewrite does not. Keep every id the sentence cites, or drop it. "
        f"{_LEFT_OUT}.",
        "agreement.rewrite_ungrounded at sentences.0.rewrite: row 1: the rewrite cites none of "
        f"the ids its sources cite. Cite the entry a source rests on, or drop it. {_LEFT_OUT}.",
        "agreement.unread_standing at held.introduction: introduction: 'The runtime result of "
        "`QueryHostMode` is not known, the routine at 0x5a10 was not read and five tool calls "
        "failed [ev_0109].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW} It names what ledger.1 "
        "holds lines on: a keep of it is refused whatever it names; rewrite it in your own "
        f"words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop it. "
        f"{_LEFT_OUT}.",
        f"report.citation_not_evidence at sentences.0.rewrite: {_NOT_SHOWN} It names what "
        "ledger.1 holds lines on: a keep of it is refused whatever it names; rewrite it in "
        f"your own words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop "
        f"it. {_LEFT_OUT}.",
    ],
    "held body twice | rewrite, its absence again on the listing | left out": [
        "agreement.unread_standing at sentences.0.rewrite: introduction: the rewrite 'The "
        "runtime result of `QueryHostMode` is not known, the routine at 0x5a10 was not read "
        "and five tool calls failed [ev_0109] [ev_0107].' of 'The runtime result of "
        "`QueryHostMode` is not known, the routine at 0x5a10 was not read and five tool calls "
        "failed [ev_0109].' still calls code not read that the ledger lists (listed.1: "
        "0x2475a10 (offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). "
        "Rewrite it in your own words to state that the code was read and what the sentence "
        f"can still say, citing an entry that fact cites, or drop it. {_EVERY_ROW} {_LEFT_OUT}.",
        "agreement.keep_unquoted at sentences.0.quote: row 1: introduction rewrites 'The "
        "runtime result of `QueryHostMode` is not known, the routine at 0x5a10 was not read "
        "and five tool calls failed [ev_0109].' into the same words, which keeps it, on "
        "listed.1, but gives no quote: it names what ledger.1 holds lines on: a keep of it is "
        "refused whatever it names; rewrite it in your own words on the lines shown, citing an "
        f"entry the fact cites, {_DENIAL}; or drop it. {_LEFT_OUT}.",
        "agreement.failure_count at sentences.0.rewrite: row 1: introduction gives failed "
        "calls a number the ledger's count (calls.1: 1 failed, 1 of them redone, 0 not redone) "
        f"does not. State the ledger's count, or no number. {_LEFT_OUT}.",
        "agreement.absence_kept at sentences.0.rewrite: row 1: the rewrite of introduction "
        "still states 'the routine at 0x5a10 was not read and five tool calls failed.', which "
        "listed.1 states otherwise. Leave that clause out and state what the fact states, "
        f"keeping what else the sentence says that no source contradicts. {_LEFT_OUT}.",
    ],
    "held body twice | rows naming no sentence of it | left out": [
        "agreement.sentence_not_found at sentences.0.sentence: row 1: the sentence does not "
        "stand in introduction as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.1.sentence: row 2: the sentence does not "
        "stand in introduction as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.sentence_not_found at sentences.2.sentence: row 3: the sentence does not "
        "stand in introduction as copied. Copy the whole sentence as the passage writes it; it "
        "must stand there once.",
        "agreement.unread_standing at held.introduction: introduction: 'The runtime result of "
        "`QueryHostMode` is not known, the routine at 0x5a10 was not read and five tool calls "
        "failed [ev_0109].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW} It names what ledger.1 "
        "holds lines on: a keep of it is refused whatever it names; rewrite it in your own "
        f"words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop it. "
        f"{_LEFT_OUT}.",
    ],
    "held body twice | no row | left out": [
        "agreement.unread_standing at held.introduction: introduction: 'The runtime result of "
        "`QueryHostMode` is not known, the routine at 0x5a10 was not read and five tool calls "
        "failed [ev_0109].' calls code not read that the ledger lists (listed.1: 0x2475a10 "
        "(offset 0x5a10): ev_0107 lists its code (decompiled or disassembled)). Rewrite it in "
        "your own words to state that the code was read and what the sentence can still say, "
        f"citing an entry that fact cites, or drop it. {_EVERY_ROW} It names what ledger.1 "
        "holds lines on: a keep of it is refused whatever it names; rewrite it in your own "
        f"words on the lines shown, citing an entry the fact cites, {_DENIAL}; or drop it. "
        f"{_LEFT_OUT}.",
    ],
}

# The answers that record what the round did; every other agreement code refuses an answer.
_RECORDS = frozenset(
    {
        agreement.REWRITTEN_CODE,
        agreement.LISTED_CODE,
        agreement.DROPPED_CODE,
        agreement.QUALIFIED_CODE,
        agreement.HELD_KEPT_CODE,
    }
)
# The report rounds' prose checks, run on every rewrite; and a procedure's own checks.
_PROSE = frozenset(
    {
        CITATION_NOT_EVIDENCE_CODE,
        CITATION_WRONG_ENTRY_CODE,
        ENTRY_CONTENTS_MISSTATED_CODE,
        ABSENCE_CONTRADICTS_LEDGER_CODE,
    }
)
_PROCEDURE = frozenset({PROSE_SHAPE_CODE, VALUE_NOT_CARRIED_CODE})
_REWRITE_ONLY = frozenset(
    {
        agreement.REWRITE_CITES_ELSEWHERE_CODE,
        agreement.REWRITE_DROPS_CITATION_CODE,
        agreement.REWRITE_UNGROUNDED_CODE,
        agreement.ABSENCE_KEPT_CODE,
        *_PROSE,
    }
)
CODES = sorted(
    {
        value
        for name, value in vars(agreement).items()
        if name.endswith("_CODE") and isinstance(value, str) and value.startswith("agreement.")
    }
    - _RECORDS
    | _PROSE
    | _PROCEDURE
)


def _cannot(kind: str, code: str, decision: str) -> str:
    """Why ``code`` cannot be raised for a sentence of ``kind`` by ``decision``; ``""`` where
    it can, and the table raises it."""
    if code == agreement.SCHEMA_CODE:
        return "the schema check reads the whole answer: a row that does not fit answers nothing"
    if code == agreement.UNKNOWN_PASSAGE_CODE and not (kind == S5_ABSENCE and decision == "drop"):
        return (
            "a row naming a passage not shown answers none; none of these kinds is shown for "
            "reading only; each may be dropped (closing, or held by the ledger), and a drop of "
            "the body naming no sentence of its passage is refused for that alone"
        )
    if code in _PROCEDURE:
        return "a procedure's own checks hold an ATT&CK procedure alone, none of these kinds"
    if code in _REWRITE_ONLY and decision != "rewrite":
        return "only a rewrite is read for what it cites and states"
    if code in (
        agreement.KEEP_UNQUOTED_CODE,
        agreement.FAILURE_COUNT_CODE,
        agreement.FAILURE_REDONE_CODE,
    ) and decision in ("drop", "none"):
        return "only a keep, or a rewrite, says the sentence again"
    if code == agreement.HELD_UNLISTED_CODE and decision != "none":
        return "a row lists the sentence"
    if code in (agreement.SENTENCE_NOT_FOUND_CODE, agreement.UNKNOWN_SOURCE_CODE) and (
        decision == "none"
    ):
        return "no row names a sentence or a source"
    if code == agreement.FAILURE_REDONE_CODE and decision == "keep" and kind == HELD_BODY:
        return "a body keep is held to no failure check: only a closing keep is"
    return ""


def _key(key: str) -> tuple[str, str, str]:
    subject, answer, end = key.split(" | ")
    return subject, answer, end


def test_the_table_walks_every_refusal_by_kind_and_answer() -> None:
    covered = set().union(
        *(_cells(SUBJECTS[s], _ANSWERS[a](SUBJECTS[s])) for s, a, _end_ in map(_key, TABLE))
    )
    space = {(k, c, d) for k in KINDS for c in CODES for d in DECISIONS}
    assert covered <= space
    # Each combination is raised by a row of the table, or cannot be raised, never both.
    assert [cell for cell in sorted(space) if (cell in covered) == bool(_cannot(*cell))] == []
    # A keep refused for every sentence no keep passes for: the end it is not offered.
    assert {s for s, a, _end_ in map(_key, TABLE) if a == "keep, no source, a reason"} == (
        set(SUBJECTS) - _KEPT
    )


_STATES = {
    "-": _DASH,
    "not printed": _NOT_PRINTED,
    "left out": "out of the report",
    "appended": "the platform appends the ledger's listing fact to it",
}
_HELD_KINDS = (HELD_CELL, HELD_BULLET, HELD_LIMITATIONS, HELD_BODY, VALUE_CELL, BULLET)


def _ends_failing(name: str) -> list[tuple[str, list[tuple[str, str, str]]]]:
    """Each end offered for the subject's sentence that the checks refuse, with why."""
    subject = SUBJECTS[name]
    return [
        (end, found) for end, answer in _ends(name).items() if (found := _refusals(subject, answer))
    ]


_FAILING = {name: _ends_failing(name) for name in SUBJECTS}


def _assert_the_end_said(subject: _Subject, answer: Any, end: str | None = None) -> None:
    """What the refusals of ``answer`` say becomes of the subject's sentence where no answer
    passes is what the round does (``end``, where the table states it)."""
    said = [message for _code, _path, message in _refusals(subject, answer)]
    done = _end(subject, answer)
    assert end is None or done == end
    stated = {e for e, words in _STATES.items() if any(words in s for s in said)}
    if not said:
        return
    if done in ("-", "not printed"):
        assert stated == {done, "left out"}
    elif subject.kind in _HELD_KINDS:
        assert stated == {done}
    else:
        # A sentence of the conclusion or the limitations no hold or keep refusal says the
        # end of ends as dev ends it, unsaid.
        assert stated <= {done}


@pytest.mark.parametrize("key", list(TABLE))
def test_every_refusal_is_true_of_the_ends_it_offers_and_of_its_end(key: str) -> None:
    name, answer_name, end = _key(key)
    subject = SUBJECTS[name]
    answer = _ANSWERS[answer_name](subject)
    # (a) The whole of every refusal, the field's ends said once, on the row's last refusal.
    found = _refusals(subject, answer)
    said = [f"{code} at {path}: {message}" for code, path, message in found]
    assert said == TABLE[key]
    if subject.kind in (VALUE_CELL, BULLET, HELD_CELL, HELD_BULLET):
        for index, row in enumerate(_rows_of(answer)):
            told = [m for _c, p, m in found if p.startswith(f"sentences.{index}.")]
            if row["sentence"] == subject.sentence and told:
                assert [f"{subject.pid} is a " in m for m in told] == [False] * (len(told) - 1) + [
                    True
                ]
    # (b) Every end a refusal of the subject's sentence offers passes every check.
    assert _FAILING[name] == []
    # (c) What the refusals say becomes of it where no answer passes is what the round does.
    _assert_the_end_said(subject, answer, end)


# The answers a refusal can offer: a row's decision, or "own", the decision of the row the
# refusal is on, its fault mended.
_KEEP, _REWRITE, _DROP, _OWN = "keep", "rewrite", "drop", "own"
# Each text by which the round offers an end, as the module writes it, and the answers it
# offers: what a message offers is read off the message by these alone.
_OFFERS: dict[str, frozenset[str]] = {
    agreement._WHOLE_ENDS: frozenset({_KEEP, _REWRITE, _DROP}),
    agreement._UNKEPT_ENDS: frozenset({_REWRITE, _DROP}),
    agreement._HELD_NAME_BODY_ENDS: frozenset({_KEEP, _REWRITE, _DROP}),
    agreement._HELD_UNKEPT_BODY_ENDS: frozenset({_REWRITE, _DROP}),
    agreement._OR_DROP: frozenset({_DROP}),
    agreement._OR_KEEP: frozenset({_KEEP}),
    agreement._OR_KEEP_NAMING: frozenset({_KEEP}),
    agreement._ON_THE_LINES: frozenset({_REWRITE}),
    agreement._ON_THE_REDO: frozenset({_REWRITE}),
    agreement._CITING_THE_REDO: frozenset({_REWRITE}),
    agreement._SAY_THE_REDO: frozenset({_REWRITE}),
    agreement._LEAVING_REASON: frozenset({_DROP}),
    agreement._REASON_KEEPING: frozenset({_KEEP, _DROP}),
    agreement._REASON_ABSENCE: frozenset({_KEEP}),
    agreement._NAME_THE_SOURCES_READ: frozenset({_OWN}),
    agreement._NAME_THE_SOURCES: frozenset({_OWN}),
    agreement._COPY_THE_SENTENCE: frozenset({_OWN}),
    agreement._KEEP_OR_REWRITE: frozenset({_KEEP, _REWRITE}),
    agreement._CITE_ONLY: frozenset({_REWRITE}),
    agreement._KEEP_EVERY_ID: frozenset({_REWRITE}),
    agreement._CITE_A_SOURCE: frozenset({_REWRITE}),
    agreement._EACH_DENIAL_CITED: frozenset({_REWRITE}),
    agreement._LEAVE_THE_CLAUSE: frozenset({_REWRITE}),
    agreement._STATE_THE_READING: frozenset({_REWRITE}),
    agreement._STATE_THE_COUNT: frozenset({_REWRITE}),
    agreement._QUOTE_MEND: frozenset({_KEEP}),
    agreement._QUOTE_OR_REWRITE: frozenset({_KEEP, _REWRITE}),
    agreement._NAME_AND_QUOTE: frozenset({_KEEP, _REWRITE}),
    agreement._TO_THE_SOURCES: frozenset({_REWRITE, _DROP}),
    agreement._ON_THE_ROWS: frozenset({_REWRITE, _DROP}),
    agreement._ON_A_CANDIDATE: frozenset({_KEEP, _REWRITE, _DROP}),
    agreement._ON_THE_ONE: frozenset({_REWRITE}),
    agreement._LIST_IT: frozenset({_REWRITE, _KEEP}),
    agreement._LIST_IT_LEAVING: frozenset({_DROP}),
    agreement._LIST_IT_ABSENCE: frozenset({_KEEP}),
}
# The report rounds' prose checks write their own findings, each mending the rewrite it reads.
_MENDS_THE_REWRITE = _PROSE
# The plain sentences: of the conclusion or the limitations, nothing holds them and a keep of
# them passes; and a held absence of section 5, which nothing but its shape holds.
_PLAIN = frozenset(
    name
    for name, subject in SUBJECTS.items()
    if subject.kind in (CONCLUSION, LIMITATIONS, S5_ABSENCE) and name in _KEPT
)
# Dev's own end texts: each stands verbatim in origin/dev's round. A refusal of a plain
# sentence whose ends are only these, or a prose check's own finding, offers what dev's round
# offers, fewer ends than pass at times (T-613); any other refusal offers every end that passes.
_DEV_ENDS = frozenset(
    {
        agreement._OR_DROP,
        agreement._OR_KEEP,
        agreement._OR_KEEP_NAMING,
        agreement._SAY_THE_REDO,
        agreement._REASON_KEEPING,
        agreement._REASON_ABSENCE,
        agreement._NAME_THE_SOURCES_READ,
        agreement._NAME_THE_SOURCES,
        agreement._COPY_THE_SENTENCE,
        agreement._KEEP_OR_REWRITE,
        agreement._CITE_ONLY,
        agreement._KEEP_EVERY_ID,
        agreement._CITE_A_SOURCE,
        agreement._LEAVE_THE_CLAUSE,
        agreement._STATE_THE_READING,
        agreement._STATE_THE_COUNT,
        agreement._QUOTE_OR_REWRITE,
        agreement._NAME_AND_QUOTE,
        agreement._TO_THE_SOURCES,
        agreement._ON_THE_ROWS,
        agreement._ON_A_CANDIDATE,
        agreement._ON_THE_ONE,
        agreement._LIST_IT,
        agreement._LIST_IT_LEAVING,
        agreement._LIST_IT_ABSENCE,
    }
)


# Held open, not dev's: a plain keep refused for a quote too short, or none, is told the floor
# beside dev's own ends, which offer no drop; a drop offered there would change dev's ends for
# a plain sentence, and leaving the floor out its message.
_OPEN = frozenset({agreement._QUOTE_MEND})


# Each answer for a plain sentence whose refusals, dev's own, leave an end that passes
# unoffered, with the ends they leave: none other may, and these leave exactly these.
_DEV_UNOFFERED: dict[str, frozenset[str]] = {
    "conclusion | keep, no source, no reason": frozenset({_REWRITE}),
    "conclusion | keep, a source, no quote": frozenset({_DROP}),
    "conclusion | keep, a quote of a blank": frozenset({_DROP}),
    "conclusion | keep, a quote no source holds": frozenset({_DROP}),
    "conclusion | drop, naming a passage as its source": frozenset({_KEEP, _REWRITE}),
    "conclusion | rewrite, citing an entry not shown": frozenset({_DROP}),
    "conclusion | rewrite, misreading entries": frozenset({_KEEP, _DROP}),
    "conclusion | rewrite, saying a redone call failed": frozenset({_DROP}),
    "conclusion | rewrite, a count the ledger does not hold": frozenset({_KEEP, _DROP}),
    "conclusion | rewrite, calling listed code not read": frozenset({_KEEP}),
    "conclusion | rewrite, a denial no entry follows": frozenset({_DROP}),
    "conclusion | keep, a quote too short": frozenset({_DROP}),
    "limitations | keep, no source, no reason": frozenset({_REWRITE}),
    "limitations | keep, a source, no quote": frozenset({_DROP}),
    "limitations | keep, a quote of a blank": frozenset({_DROP}),
    "limitations | keep, a quote no source holds": frozenset({_DROP}),
    "limitations | drop, naming a passage as its source": frozenset({_KEEP, _REWRITE}),
    "limitations | rewrite, citing an entry not shown": frozenset({_DROP}),
    "limitations | rewrite, misreading entries": frozenset({_KEEP, _DROP}),
    "limitations | rewrite, saying a redone call failed": frozenset({_DROP}),
    "limitations | rewrite, a count the ledger does not hold": frozenset({_KEEP, _DROP}),
    "limitations | rewrite, calling listed code not read": frozenset({_KEEP}),
    "limitations | rewrite, a denial no entry follows": frozenset({_DROP}),
    "limitations | keep, a quote too short": frozenset({_DROP}),
    "limitations one failed call | keep, no source, no reason": frozenset({_REWRITE}),
    "limitations one failed call | keep, a source, no quote": frozenset({_DROP}),
    "limitations one failed call | keep, a quote of a blank": frozenset({_DROP}),
    "limitations one failed call | keep, on the failed call's fact": frozenset({_DROP}),
    "limitations one failed call | keep, a quote no source holds": frozenset({_DROP}),
    "limitations one failed call | drop, naming a passage as its source": frozenset(
        {_KEEP, _REWRITE}
    ),
    "limitations one failed call | rewrite, citing an entry not shown": frozenset({_DROP}),
    "limitations one failed call | rewrite, misreading entries": frozenset({_KEEP, _DROP}),
    "limitations one failed call | rewrite, saying a redone call failed": frozenset({_DROP}),
    "limitations one failed call | rewrite, a count the ledger does not hold": frozenset(
        {_KEEP, _DROP}
    ),
    "limitations one failed call | rewrite, calling listed code not read": frozenset({_KEEP}),
    "limitations one failed call | rewrite, a denial no entry follows": frozenset({_DROP}),
    "limitations one failed call | keep, a quote too short": frozenset({_DROP}),
    # A prose check's own finding mends the rewrite it reads, as for any plain sentence.
    "section 5 absence | rewrite, misreading entries": frozenset({_KEEP}),
    "section 5 absence | rewrite, a count the ledger does not hold": frozenset({_KEEP}),
    "section 5 absence | rewrite, calling listed code not read": frozenset({_KEEP}),
}


def _dev_text(code: str, message: str) -> bool:
    """Whether ``message`` offers its ends in dev's own end texts alone (or beside one held
    open, :data:`_OPEN`)."""
    ends = {words for words in _OFFERS if _said(message, words)}
    return code in _MENDS_THE_REWRITE or bool(ends - _OPEN) and ends <= _DEV_ENDS | _OPEN


def _said(text: str, words: str) -> bool:
    """Whether ``text`` writes ``words``, at the start of a sentence too."""
    return words in text or f"{words[:1].upper()}{words[1:]}" in text


def _offered(code: str, message: str, decision: str) -> frozenset[str] | None:
    """The answers ``message``, a refusal of a row deciding ``decision``, offers, read off it
    by the module's own texts (:data:`_OFFERS`); ``None`` where it holds none of them."""
    kinds = {kind for words, offers in _OFFERS.items() if _said(message, words) for kind in offers}
    if code in _MENDS_THE_REWRITE:
        kinds.add(_OWN)
    if not kinds:
        return None
    return frozenset(decision if kind == _OWN else kind for kind in kinds)


def _offers_of(subject: _Subject, answer: Any) -> list[tuple[str, str, frozenset[str] | None]]:
    """Each refusal of ``answer`` about the subject's sentence (its own rows' and the ones
    asked of it), by code and message, with the answers it offers; a refusal of a row naming
    another sentence, with what it offers that row."""
    rows = _rows_of(answer)
    out = []
    for code, path, message in _refusals(subject, answer):
        row = rows[int(path.split(".")[1])] if path.startswith("sentences.") else None
        offered = _offered(code, message, row["decision"] if row is not None else "none")
        about = row is None or row["sentence"] == subject.sentence
        out.append((code if about else "", message, offered))
    return out


@pytest.mark.parametrize("name", list(SUBJECTS))
def test_every_message_offers_exactly_the_ends_that_pass(name: str) -> None:
    """(b) Over every answer the table holds, every refusal offers at least one end, read off
    it; each end offered for the subject's sentence passes when given, and every end that
    passes for it is offered, but by dev's own end texts for a sentence nothing holds. What
    the refusals say becomes of it where no answer passes is what the round does, and none is
    one the table says cannot be raised. Ends are read as answer kinds (keep, rewrite, drop):
    which entries a rewrite must cite, or which sources a keep names, is not read here."""
    subject = SUBJECTS[name]
    passing = _ends(name)
    for answer_name, given in _ANSWERS.items():
        answer = given(subject)
        assert [cell for cell in _cells(subject, answer) if _cannot(*cell)] == [], answer_name
        _assert_the_end_said(subject, answer)
        found = _offers_of(subject, answer)
        assert [m for _c, m, offered in found if offered is None] == [], answer_name
        about = [(code, message, offered) for code, message, offered in found if code]
        union: set[str] = set().union(*(offered or () for _c, _m, offered in about))
        for kind in union:
            assert kind in passing, (answer_name, kind, [m for _c, m, _o in about])
            assert _refusals(subject, passing[kind]) == []
        unoffered = set(passing) - union if about else set()
        # Only a plain sentence leaves an end unoffered, only in dev's own end texts, and
        # exactly the ends listed for that answer.
        assert unoffered == _DEV_UNOFFERED.get(f"{name} | {answer_name}", set()), answer_name
        if unoffered:
            assert name in _PLAIN, (answer_name, unoffered)
            assert [m for c, m, _o in about if not _dev_text(c, m)] == [], (answer_name, unoffered)


def _question_lines(subject: _Subject) -> list[str]:
    """The lines of the round's first turn that show the subject's passage and ask of it."""
    passages = passages_of(_report_of(subject), entries=_ledger())
    return [
        line
        for line in agreement.prompt_text(passages).splitlines()
        if line.startswith((f"- [{subject.pid}]", f"  [{subject.pid}]"))
    ]


# The first turn's lines on the passage of a sentence of each kind: a sentence no keep passes
# for, and one the ledger's lines hold, listed under the ends that pass for it.
PROMPTED: dict[str, list[str]] = {
    "cell failed": [
        "- [communications.1.encryption] 5. Technical analysis, channel row 1, encryption "
        '(cites ev_0101): "The decompile of 0x5a10 failed [ev_0101]."',
        f'  [communications.1.encryption] "The decompile of 0x5a10 failed [ev_0101].": {_UNKEPT}. '
        f"{_LEFT_OUT}, and {_DASH}.",
    ],
    "bullet unread": [
        "- [capability_summary.1] 1. Executive summary, capability bullet 1 (cites ev_0107): "
        '"The routine at 0x5a10 was not read [ev_0107]."',
        f'  [capability_summary.1] "The routine at 0x5a10 was not read [ev_0107].": {_UNKEPT}. '
        f"{_LEFT_OUT}, and {_NOT_PRINTED}.",
    ],
    "held cell": [
        "- [communications.1.encryption] 5. Technical analysis, channel row 1, encryption "
        '(cites ev_0104): "Which export the loader calls is not established [ev_0104]."',
        "  [communications.1.encryption] each of these denies something and names what a "
        "ledger.N fact shows (an API's call lines, an export, a decoded text); a keep of it as "
        "written is refused, and the same words with a citation added are a keep; rewrite it "
        "in your own words on the lines shown, citing the entry they come from, saying what "
        f"the lines show and what stays unknown, {_DENIAL}, or drop it; if no answer for it "
        'passes the checks, it is left out of the report: "Which export the loader calls is '
        'not established [ev_0104]." (ledger.1)',
    ],
    "held bullet": [
        "- [capability_summary.2] 1. Executive summary, capability bullet 2 (cites ev_0104, "
        'ev_0107): "Which export the loader calls is not established [ev_0104]."',
        "  [capability_summary.2] each of these denies something and names what a ledger.N fact "
        "shows (an API's call lines, an export, a decoded text); a keep of it as written is "
        "refused, and the same words with a citation added are a keep; rewrite it in your own "
        "words on the lines shown, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_DENIAL}, or drop it; if no answer for it passes the checks, "
        'it is left out of the report: "Which export the loader calls is not established '
        '[ev_0104]." (ledger.1)',
    ],
    "conclusion count": [
        '- [conclusion] 7. Conclusion (cites ev_0107): "Five tool calls failed [ev_0107]."',
        "  [conclusion] answer every sentence of this passage, one row each (1 sentence), as the "
        "TASK asks.",
        f'  [conclusion] "Five tool calls failed [ev_0107].": {_UNKEPT}.',
    ],
    "limitations unread": [
        "- [limitations] 11. Limitations, the composed paragraph (each sentence saying a call "
        "failed or a reading could not be made is held to the failed calls, the tools not run, "
        "the recorded limitations and the open questions among the facts) (cites ev_0101, "
        'ev_0112): "The decompile of 0x5a10 failed [ev_0101]. The routine at 0x6100 was not '
        'read [ev_0112]."',
        "  [limitations] answer every sentence of this passage, one row each (2 sentences), as "
        "the TASK asks.",
        '  [limitations] "The decompile of 0x5a10 failed [ev_0101].": it says a call failed that '
        "a later call redid: a keep of it as written is refused; rewrite it citing ev_0107 and "
        f"saying what it answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
        f'  [limitations] "The routine at 0x6100 was not read [ev_0112].": {_UNKEPT}.',
    ],
    "held limitations": [
        "- [limitations] 11. Limitations, the composed paragraph (each sentence saying a call "
        "failed or a reading could not be made is held to the failed calls, the tools not run, "
        "the recorded limitations and the open questions among the facts) (cites ev_0101, "
        'ev_0107): "The decompile of 0x5a10 failed [ev_0101]. The gate reads a host mode '
        '[ev_0107]."',
        "  [limitations] answer every sentence of this passage, one row each (2 sentences), as "
        "the TASK asks.",
        '  [limitations] "The decompile of 0x5a10 failed [ev_0101].": it says a call failed that '
        "a later call redid: a keep of it as written is refused; rewrite it citing ev_0107 and "
        f"saying what it answered, {_DENIAL}, or drop it. {_LEFT_OUT}.",
    ],
    "held body": [
        '- [introduction] 12.3 Background (cites ev_0109): "The runtime result of '
        '`QueryHostMode` is not known [ev_0109]."',
        "  [introduction] each of these denies something and names what a ledger.N fact shows "
        "(an API's call lines, an export, a decoded text); keep it naming that fact, with "
        '"quote": words inside one of its rows that name what the sentence names, copied '
        "exactly; or rewrite it in your own words on the lines shown, citing an entry the fact "
        f"cites, {_DENIAL}; or drop it; if no answer for it passes the checks, it is left out "
        'of the report: "The runtime result of `QueryHostMode` is not known [ev_0109]." '
        "(ledger.1)",
    ],
    "held body twice": [
        '- [introduction] 12.3 Background (cites ev_0109): "The runtime result of '
        "`QueryHostMode` is not known, the routine at 0x5a10 was not read and five tool calls "
        'failed [ev_0109]."',
        "  [introduction] each of these denies something and names what a ledger.N fact shows "
        "(an API's call lines, an export, a decoded text); a keep of it is refused whatever it "
        "names; rewrite it in your own words on the lines shown, citing an entry the fact "
        f"cites, {_DENIAL}; or drop it; if no answer for it passes the checks, it is left out "
        'of the report: "The runtime result of `QueryHostMode` is not known, the routine at '
        '0x5a10 was not read and five tool calls failed [ev_0109]." (ledger.1)',
    ],
}


@pytest.mark.parametrize("name", list(PROMPTED))
def test_the_first_turn_offers_exactly_the_ends_that_pass(name: str) -> None:
    subject = SUBJECTS[name]
    lines = _question_lines(subject)
    assert lines == PROMPTED[name]
    # Each line asking of the sentence (the passage's own line shows it) offers every end that
    # passes for it, and only those.
    asked = [line for line in lines[1:] if agreement.quoted_value(subject.sentence) in line]
    assert asked
    for line in asked:
        assert _offered("", line, "none") == frozenset(_ends(name))


def test_a_held_absence_of_section_5_is_offered_a_keep_on_the_words_stating_it() -> None:
    """The excerpt that speaks states the checks; the keep offered quotes the clause of the
    same source that states the absence, and passes (T-652)."""
    subject = SUBJECTS["section 5 absence"]
    found = _refusals(subject, _ANSWERS["keep, no source, a reason"](subject))
    (message,) = [m for code, _path, m in found if code == agreement.KEEP_UNQUOTED_CODE]
    assert 'speak of it: [introduction] "Routine 0x5a10 runs timing and locale checks' in message
    assert message.endswith(
        "or keep it naming the one you read, quoting its words that state the same absence: "
        f'[introduction] "{_ABSENT_QUOTE}".'
    )
    assert _refusals(subject, _ends("section 5 absence")["keep"]) == []
