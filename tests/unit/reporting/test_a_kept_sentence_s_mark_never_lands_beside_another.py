"""A kept sentence's mark never lands beside another sentence, nor anything on agreed words.

A sentence the agreement round kept as written on its quote prints with the platform's mark
after it (``KEPT_ON_ITS_QUOTE_MARK``), found by the words its record holds. The record holds the
sentence bounded and cleaned as every finding row is (``events.safe_finding_value``): a long one
cut, a path shortened. Where the cut copy fits two sentences of a passage, neither sentence nor
the passage's end takes the mark; where the record's copy differs from the printed sentence only
by that cleaning, the sentence is found in the form the record stores it. Where two different
printed sentences answer a record, the passage ends in one note of its own
(``KEPT_IN_PASSAGE_NOTE``), however many such records it has, which names no sentence. Where no
printed sentence answers it (another rule left the sentence out, or the text changed), nothing
is printed: no mark, no note, on a passage as on a value cell. In prose a passage's trailing note
marker stands before the mark, so the note is not read as citing it. The run comparison shows
the mark beside a channel cell, shown and never compared (T-881). Every sentence, quote and id
is made up.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from malspark.pipeline.validation import ValidationTally
from malspark.reporting.models import (
    C2Channel,
    FileHashes,
    FlaggedStatement,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.run_diff import CHANGED, UNCHANGED, RunRecord, diff_runs
from malspark.reporting.section_agreement import (
    AGREEMENT_PRODUCER,
    KEPT_IN_PASSAGE_NOTE,
    KEPT_ON_ITS_QUOTE_CODE,
    KEPT_ON_ITS_QUOTE_MARK,
    apply_rows,
    channel_cell_label,
    kept_on_its_quote,
    kept_places,
    passages_of,
)

MARK = f"**[{KEPT_ON_ITS_QUOTE_MARK}]**"
NOTE = f"**[{KEPT_IN_PASSAGE_NOTE}]**"
RELAY = (
    "The sample opens a listener on its own host [ev_0031]. The relay branch that forwards "
    "traffic to a second host was never reached in the sandbox [ev_0032]. It logs each request "
    "to a local file [ev_0033]."
)
QUOTE = "was never reached in the sandbox"
# Two sentences longer than a record's bound that share their first 200 characters.
HEAD = (
    "The forwarding of captured traffic to a remote collector, the second listener the relay "
    "branch would open on a port drawn at start, the rotation of its session key every hour and "
    "the compression of each batch it queues "
)
FIRST = HEAD + "were not seen during the detonation, which ran the file once [ev_0032]."
SECOND = HEAD + "were not seen in the memory image taken after the run either [ev_0032]."
THIRD = "The listener port is chosen at random on every start of the file [ev_0031]."
OPENING = "The file copies itself into the profile folder of the user it runs as [ev_0031]."
MIDDLE = "The forwarding of captured traffic was not seen during the detonation [ev_0032]."
# A sentence the record stores with its path shortened, as every finding row stores one.
PATHED = (
    "The loader was not started from C:\\Users\\analyst\\AppData\\Local\\Temp\\relay.exe "
    "during the detonation [ev_0032]."
)
# A sentence the record names, and a longer one in the same passage that it opens.
SHORT = "The relay link was not keyed."
LONGER = "The relay link was not keyed by the loader at any point of the detonation [ev_0032]."
CELL = "The cipher of the forwarding link was not identified while the file ran"
# A note marker as the analyst report writes one.
CITE = r"\[\[\d+\]\]\([^)\s]*\)"


def _report(conclusion: str, limitations: str = "", cell: str = "") -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_type="PE32 executable"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(
                title="C2", body=RELAY, evidence_refs=["ev_0031"]
            ),
            analyst_conclusion=TechnicalSubsection(
                title="Conclusion", body=conclusion, evidence_refs=["ev_0040"]
            ),
            analyst_limitations=(
                TechnicalSubsection(title="Limitations", body=limitations) if limitations else None
            ),
        ),
        c2_channels=[
            C2Channel(name=""),
            C2Channel(name="relay", encryption=cell or None),
        ],
    )


def _keep(passage: str, sentence: str) -> dict[str, Any]:
    return {
        "passage": passage,
        "sentence": sentence,
        "decision": "keep",
        "sources": ["command_and_control"],
        "quote": QUOTE,
    }


def _rounded(report: MalwareReport, *rows: dict[str, Any]) -> list[dict[str, Any]]:
    """The round applied to ``report``, its records stored as the run summary keeps them."""
    _counts, found = apply_rows({"sentences": list(rows)}, passages_of(report))
    tally = ValidationTally()
    tally.record_unresolved(AGREEMENT_PRODUCER, found)
    report.run_summary = {"validation": tally.to_dict()}
    kept = [row for row in tally.unresolved if row["code"] == KEPT_ON_ITS_QUOTE_CODE]
    assert len(kept) == len(rows)
    return kept


def _analyst(report: MalwareReport) -> str:
    return MarkdownRenderer(layout=ANALYST).render(report)


def _after(text: str, words: str, what: str) -> bool:
    """Whether ``what`` follows the sentence ending in ``words`` in ``text``, its citation's
    note and a passage's trailing note marker read past."""
    cited = f"(?:{CITE})?"
    found = re.search(re.escape(words) + cited + r"\." + cited + re.escape(" " + what), text)
    return found is not None


def test_a_cut_copy_that_fits_two_sentences_marks_neither_nor_the_passage_s_end() -> None:
    assert len(FIRST) > 200 and len(SECOND) > 200 and FIRST[:200] == SECOND[:200]
    report = _report(f"{FIRST} {SECOND} {THIRD}")
    [row] = _rounded(report, _keep("conclusion", FIRST))
    assert FIRST not in row["message"]
    shown = _analyst(report)
    assert MARK not in shown
    assert KEPT_ON_ITS_QUOTE_MARK not in HtmlRenderer(layout=ANALYST).render(
        report, embed_figures=False
    )
    # The refusal is said once, at the passage's end, after its note marker; no sentence is named.
    assert shown.count(NOTE) == 1
    assert re.search(
        "on every start of the file" + CITE + r"\." + CITE + " " + re.escape(NOTE), shown
    )
    said = kept_on_its_quote(report)["conclusion"]
    assert kept_places([f"{FIRST} {SECOND} {THIRD}"], said) == ([[]], KEPT_IN_PASSAGE_NOTE)


def test_one_note_for_a_passage_however_many_records_find_no_sentence() -> None:
    report = _report(f"{FIRST} {SECOND}\n\n{THIRD}")
    _rounded(report, _keep("conclusion", FIRST), _keep("conclusion", SECOND))
    shown = _analyst(report)
    assert MARK not in shown and shown.count(NOTE) == 1
    # It stands after the passage's last paragraph, not after the paragraph the records name.
    assert shown.index(NOTE) > shown.index("on every start of the file")


def test_a_sentence_is_found_in_the_form_its_record_stores_it() -> None:
    report = _report(f"{OPENING} {PATHED} {THIRD}")
    [row] = _rounded(report, _keep("conclusion", PATHED))
    assert "C:\\Users" not in row["message"] and "relay.exe during" in row["message"]
    shown = _analyst(report)
    assert shown.count(MARK) == 1 and NOTE not in shown
    assert _after(shown, "during the detonation", MARK)
    assert not _after(shown, "runs as", MARK) and not _after(shown, "start of the file", MARK)


def test_a_record_whose_sentence_the_passage_no_longer_holds_prints_nothing() -> None:
    report = _report(f"{OPENING} {MIDDLE} {THIRD}", cell=CELL)
    _rounded(report, _keep("conclusion", MIDDLE), _keep("communications.2.encryption", CELL))
    unrecorded = _report(f"{OPENING} {THIRD}")
    unrecorded.c2_channels[1].encryption = "Not identified"
    ta = report.technical_analysis
    assert ta is not None and ta.analyst_conclusion is not None
    ta.analyst_conclusion.body = f"{OPENING} {THIRD}"
    report.c2_channels[1].encryption = "Not identified"
    # The passage and the cell print only words the check agreed to: nothing is printed beside
    # them, so no printed sentence is taken for the refused one.
    for layout in (ANALYST, BUNDLE):
        shown = MarkdownRenderer(layout=layout).render(report)
        assert MARK not in shown and NOTE not in shown
        assert "Not identified" in shown
    assert _analyst(report) == _analyst(_with_summary(unrecorded, report))
    text = f"{OPENING} {THIRD}"
    assert kept_places([text], kept_on_its_quote(report)["conclusion"]) == ([[]], "")
    assert kept_places(["", " "], ["Any sentence."]) == ([[], []], "")


def test_a_kept_sentence_another_rule_leaves_out_prints_nothing() -> None:
    report = _report(f"{OPENING} {MIDDLE} {THIRD}")
    _rounded(report, _keep("conclusion", MIDDLE))
    # A check flags the kept sentence: the analyst report leaves it out and prints the others.
    report.flagged_statements = [
        FlaggedStatement(sentence=MIDDLE, code="report.unsupported_x", label="x")
    ]
    shown = _analyst(report)
    assert "not seen during the detonation" not in shown
    assert "runs as" in shown and "start of the file" in shown
    assert MARK not in shown and NOTE not in shown


def test_only_the_sentence_a_record_names_is_marked() -> None:
    report = _report(f"{OPENING} {MIDDLE} {THIRD}", limitations=f"{LONGER} {SHORT}")
    _rounded(report, _keep("conclusion", MIDDLE), _keep("limitations", SHORT))
    shown = _analyst(report)
    assert shown.count(MARK) == 2 and NOTE not in shown
    assert _after(shown, "not seen during the detonation", MARK)
    assert not _after(shown, "runs as", MARK)
    assert not _after(shown, "start of the file", MARK)
    # A longer sentence the record's sentence opens is not it: only the exact one is marked.
    assert _after(shown, "relay link was not keyed", MARK)
    assert not _after(shown, "any point of the detonation", MARK)
    said = kept_on_its_quote(report)
    text = f"{OPENING} {MIDDLE} {THIRD}"
    assert kept_places([text], said["conclusion"]) == ([[text.index(THIRD) - 1]], "")
    text = f"{LONGER} {SHORT}"
    assert kept_places([text], said["limitations"]) == ([[len(text)]], "")


def test_a_paragraph_s_note_marker_stands_before_a_mark_that_ends_it() -> None:
    report = _report(f"{OPENING} {MIDDLE}")
    _rounded(report, _keep("conclusion", MIDDLE))
    shown = _analyst(report)
    assert shown.count(MARK) == 1
    # The conclusion cites ev_0040, which no sentence of it writes: its marker ends the
    # paragraph, before the mark, never after it.
    assert re.search(
        "during the detonation" + CITE + r"\." + CITE + " " + re.escape(MARK) + "$", shown, re.M
    )
    assert re.search(re.escape(MARK) + r"\[\[", shown) is None


def _with_summary(report: MalwareReport, source: MalwareReport) -> MalwareReport:
    """``report`` carrying ``source``'s run summary, the agreement round's records among it."""
    report.run_summary = source.run_summary
    return report


def _record(report: MalwareReport, job: str) -> RunRecord:
    return RunRecord(
        report_id=job,
        job_id=job,
        malware_report=report.model_dump(mode="json"),
        run_summary=report.run_summary,
    )


def test_the_run_comparison_shows_a_kept_cell_s_mark_and_never_compares_it() -> None:
    kept = _report(OPENING, cell=CELL)
    [record] = _rounded(kept, _keep("communications.2.encryption", CELL))
    plain = _report(OPENING, cell=CELL)
    # The second channel is numbered 2, the first one, which has no name, counted.
    assert channel_cell_label(2, "encryption") in record["message"]
    diff = diff_runs(_record(plain, "a"), _record(kept, "b"))
    [section] = [s for s in diff["sections"] if s["key"] == "c2_channels"]
    [row] = section["rows"]
    assert row["status"] == UNCHANGED and row["changes"] == [] and row["note"] is None
    assert row["b"]["encryption_mark"] == KEPT_ON_ITS_QUOTE_MARK
    assert "encryption_mark" not in row["a"] and "protocol_mark" not in row["b"]
    # A cell that differs is still a change, and the mark beside it is not one.
    moved = _report(OPENING, cell=CELL.replace("forwarding link", "relay link"))
    diff = diff_runs(_record(moved, "a"), _record(kept, "b"))
    [row] = [s for s in diff["sections"] if s["key"] == "c2_channels"][0]["rows"]
    assert row["status"] == CHANGED
    assert [change["field"] for change in row["changes"]] == ["encryption"]
    # A cell that no longer holds its recorded sentence shows nothing beside it.
    changed = _report(OPENING, cell="Not identified")
    changed.run_summary = kept.run_summary
    diff = diff_runs(_record(plain, "a"), _record(changed, "b"))
    [row] = [s for s in diff["sections"] if s["key"] == "c2_channels"][0]["rows"]
    assert "encryption_mark" not in row["b"] and row["note"] is None
