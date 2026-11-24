"""A sentence kept as written on its quote prints with the platform's mark beside it.

Where the agreement round's check refused a closing keep only on the words of what the sentence
denies, and the whole quote stands in one sentence of a section 5 passage the round leaves as it
is, the composer's sentence stands as written (``KEPT_ON_ITS_QUOTE_CODE``, T-736). The report
printed it exactly like a sentence the check agreed to; the record stood only in the bundle's
list. Now every surface printing it prints it as written with one platform mark beside it, in one
set of words (``KEPT_ON_ITS_QUOTE_MARK``): after the sentence in the conclusion, the limitations
and a capability bullet, after the cell in a value cell, in the analyst report, its HTML and the
single-file report the bundle prints. The mark is drawn from the round's own record when the
report is rendered: the report document gains nothing, a stored report prints it too, a record
whose sentence the text no longer holds prints nothing (no mark, and not the passage note,
``KEPT_IN_PASSAGE_NOTE``), and no other end of the round and nothing a model reads changes
(T-881). Every sentence, quote and id is made up.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from malspark.pipeline.validation import ValidationTally
from malspark.reporting import section_agreement
from malspark.reporting.models import (
    C2Channel,
    CapabilityBullet,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE, FULL
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.section_agreement import (
    AGREEMENT_PRODUCER,
    DROPPED_CODE,
    KEPT_IN_PASSAGE_NOTE,
    KEPT_ON_ITS_QUOTE_CODE,
    KEPT_ON_ITS_QUOTE_MARK,
    agreement_violations,
    apply_rows,
    passages_of,
    prompt_text,
)

MARK = f"**[{KEPT_ON_ITS_QUOTE_MARK}]**"
RELAY = (
    "The sample opens a listener on its own host [ev_0031]. The relay branch that forwards "
    "traffic to a second host was never reached in the sandbox [ev_0032]. It logs each request "
    "to a local file [ev_0033]."
)
QUOTE = "was never reached in the sandbox"
KEPT = (
    "The forwarding of captured traffic to a remote collector was not seen during the "
    "detonation [ev_0032]."
)
LONG = (
    "The forwarding of captured traffic to a remote collector, the second listener the relay "
    "branch would open, the rotation of its session key and the upload of the request log were "
    "not seen during the detonation, which ran the file once without its options [ev_0032]."
)
LEFT = "The listener port is chosen at random on every start of the file [ev_0031]."
BULLET = "Forwarding to a remote collector was not observed while the file ran [ev_0032]."
CELL = "The cipher of the forwarding link was not identified while the file ran"


def _report(limitations: str = LONG) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="f" * 64), file_type="PE32 executable"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(
                title="C2", body=RELAY, evidence_refs=["ev_0031"]
            ),
            capability_summary=[CapabilityBullet(text=BULLET)],
            analyst_conclusion=TechnicalSubsection(title="Conclusion", body=f"{LEFT} {KEPT}"),
            analyst_limitations=TechnicalSubsection(title="Limitations", body=limitations),
        ),
        c2_channels=[C2Channel(name="relay", encryption=CELL)],
    )


def _keep(passage: str, sentence: str) -> dict[str, Any]:
    return {
        "passage": passage,
        "sentence": sentence,
        "decision": "keep",
        "sources": ["command_and_control"],
        "quote": QUOTE,
    }


def _rounded(report: MalwareReport) -> list[dict[str, Any]]:
    """The round applied to ``report``, its records stored as the run summary keeps them."""
    rows = [
        _keep("conclusion", KEPT),
        _keep("limitations", LONG),
        _keep("capability_summary.1", BULLET),
        _keep("communications.1.encryption", CELL),
        {"passage": "conclusion", "sentence": LEFT, "decision": "drop", "reason": "unsure"},
    ]
    _counts, found = apply_rows({"sentences": rows}, passages_of(report))
    tally = ValidationTally()
    tally.record_unresolved(AGREEMENT_PRODUCER, found)
    report.run_summary = {"validation": tally.to_dict()}
    return tally.unresolved


def _marked_after(text: str, words: str) -> bool:
    """Whether the mark follows the sentence ending in ``words`` in ``text``: right after its end
    mark, its citation's note read past."""
    cited = r"(?:\[\[\d+\]\]\([^)\s]*\))?"
    return re.search(re.escape(words) + cited + re.escape(". " + MARK), text) is not None


def _surfaces(report: MalwareReport) -> dict[str, str]:
    return {
        "analyst": MarkdownRenderer(layout=ANALYST).render(report),
        "analyst.html": HtmlRenderer(layout=ANALYST).render(report, embed_figures=False),
        "full": MarkdownRenderer(layout=FULL).render(report),
        "bundle": MarkdownRenderer(layout=BUNDLE).render(report),
    }


def test_each_kept_sentence_prints_as_written_with_one_mark_beside_it() -> None:
    report = _report()
    rows = _rounded(report)
    assert [row["code"] for row in rows].count(KEPT_ON_ITS_QUOTE_CODE) == 4
    assert len(LONG) > 200 and LONG not in str(rows)
    shown = _surfaces(report)
    analyst = shown["analyst"]
    assert analyst.count(MARK) == 4
    # Every record found its sentence: no passage carries the note.
    assert all(KEPT_IN_PASSAGE_NOTE not in text for text in shown.values())
    # In prose the mark follows its sentence, a long one whose record holds it cut among them.
    for said in ("was not seen during the detonation", "without its options", "while the file ran"):
        assert _marked_after(analyst, said)
    assert analyst.count(f". {MARK}") == 3
    # A value cell's mark follows the cell, as a flagged sentence's does.
    assert f"{CELL} {MARK}" in analyst
    assert shown["analyst.html"].count(f"<strong>[{KEPT_ON_ITS_QUOTE_MARK}]</strong>") == 4
    # The single-file report, which the bundle prints, prints the value cells.
    for name in ("full", "bundle"):
        assert shown[name].count(MARK) == 1 and f"{CELL} {MARK}" in shown[name]


def test_no_other_end_prints_the_mark() -> None:
    report = _report()
    rows = _rounded(report)
    assert DROPPED_CODE in [row["code"] for row in rows]
    shown = _surfaces(report)
    # The sentence left out is not printed in the analyst report, and nothing marks its place.
    assert LEFT[:40] not in shown["analyst"]
    assert shown["analyst"].count(MARK) == 4
    unmarked = _report()
    unmarked.run_summary = {
        "validation": {"unresolved": [r for r in rows if r["code"] != KEPT_ON_ITS_QUOTE_CODE]}
    }
    assert all(KEPT_ON_ITS_QUOTE_MARK not in text for text in _surfaces(unmarked).values())


def test_a_record_naming_a_sentence_the_text_no_longer_holds_prints_nothing() -> None:
    report = _report()
    _rounded(report)
    ta = report.technical_analysis
    assert ta is not None and ta.analyst_conclusion is not None
    ta.analyst_conclusion.body = KEPT.replace("remote collector", "remote host")
    ta.capability_summary[0].text = "Forwarding was not observed [ev_0032]."
    report.c2_channels[0].encryption = "Not identified"
    shown = _surfaces(report)
    assert shown["analyst"].count(MARK) == 1
    assert _marked_after(shown["analyst"], "without its options")
    assert all(KEPT_ON_ITS_QUOTE_MARK not in shown[name] for name in ("full", "bundle"))
    # No passage or cell it names prints the passage note: none prints the sentence.
    assert all(KEPT_IN_PASSAGE_NOTE not in text for text in shown.values())
    # A record another writer wrote, or one naming a passage the report does not hold, names none.
    report.run_summary = {
        "validation": {
            "unresolved": [
                {"agent": "agreement", "code": KEPT_ON_ITS_QUOTE_CODE, "message": f"{KEPT} kept."},
                {
                    "agent": "agreement",
                    "code": KEPT_ON_ITS_QUOTE_CODE,
                    "message": (
                        "The agreement question keeps a sentence of 7. Conclusion, line 9 as "
                        "written on command_and_control, quoting 'x', which stands whole in one "
                        "sentence there, though the keep was refused only on the words of what "
                        "the sentence denies something of (agreement.keep_unquoted): "
                        f"{LONG!r} stands as written."
                    ),
                },
            ]
        }
    }
    assert section_agreement.kept_on_its_quote(report) == {}
    assert all(KEPT_ON_ITS_QUOTE_MARK not in text for text in _surfaces(report).values())
    assert all(KEPT_IN_PASSAGE_NOTE not in text for text in _surfaces(report).values())


def test_the_report_document_gains_nothing_and_a_stored_report_prints_the_mark() -> None:
    report = _report()
    _rounded(report)
    stored = report.model_dump(mode="json")
    _surfaces(report)
    assert report.model_dump(mode="json") == stored
    assert KEPT_ON_ITS_QUOTE_MARK not in str(stored)
    again = MalwareReport.model_validate(stored)
    assert MarkdownRenderer(layout=ANALYST).render(again).count(MARK) == 4


def test_nothing_a_model_reads_carries_the_mark() -> None:
    report = _report()
    passages = passages_of(report)
    asked = prompt_text(passages)
    told = agreement_violations({"sentences": [_keep("conclusion", KEPT)]}, passages)
    assert KEPT_ON_ITS_QUOTE_MARK not in asked
    assert all(KEPT_ON_ITS_QUOTE_MARK not in v.message for v in told)


def test_the_module_says_what_it_does() -> None:
    said = " ".join(str(section_agreement.__doc__).split())
    assert "``KEPT_ON_ITS_QUOTE_CODE``, T-736), and every report printing it prints" in said
    assert "``KEPT_ON_ITS_QUOTE_MARK``" in said
