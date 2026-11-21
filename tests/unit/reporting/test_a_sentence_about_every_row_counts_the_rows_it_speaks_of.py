"""A platform sentence that states a property of every row it speaks of is a count of them.

A fixed sentence of the reports said of every run what holds of some: every tool server
named, a sandbox that recorded the sample's behaviour, a judge that stated the STIX bundle,
every value of an analyst's table in the indicator section as the analyst's, every cited
id linked, every listed note cited, every rule's body in the appendix, every value with the
publish rule's answer absent from the machine-readable outputs, every row of the
dropped-files list dropped. Each is now printed word for word where the rows it speaks of
hold no exception, and as a count or a list read from those same rows otherwise. A judge's
reason the analyst report shortens to fit says so under the list (T-780).
"""

from __future__ import annotations

import json
import re

from malspark.pipeline.validation import ValidationTally
from malspark.reporting.judge_reasons import (
    JUDGE_REASON_WIDTH,
    judge_reason_spans,
    reason_marks,
    reasons_cut,
    status_cuts,
    status_parts,
)
from malspark.reporting.models import (
    CapabilityCell,
    DetectionRule,
    DynamicBehavior,
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    InventoryCall,
    LimitationInventory,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    ProcessNode,
    SampleIdentity,
    SandboxSignature,
    StaticAnalysis,
    StringIOC,
    TechnicalAnalysis,
    TechnicalSubsection,
    TechniqueProcedure,
)
from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer
from malspark.reporting.renderers.analyst import CitationNote, _left_out_marks
from malspark.reporting.renderers.bundle import NOTES_TITLE, _notes_section, bundle_json, note_ids
from malspark.reporting.renderers.html import _notes_in_the_document
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.renderers.markdown import INDICATORS_TITLE, analyst_list_note
from malspark.reporting.renderers.prose_forms import section_reference
from malspark.reporting.section_agreement import AGREEMENT_PRODUCER, apply_rows, passages_of
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)


def _report(**fields: object) -> MalwareReport:
    base: dict[str, object] = {
        "identity": SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="s.exe"),
        "verdict": "Malware",
    }
    base.update(fields)
    return MalwareReport.model_validate(base)


def _line(markdown: str, start: str) -> str:
    return next(line for line in markdown.splitlines() if line.startswith(start))


# -- tool servers ------------------------------------------------------------


def test_every_call_naming_a_server_lists_the_servers_as_before() -> None:
    report = _report(
        evidence_index=[
            EvidenceIndexRow(id="ev_0001", server="ghidra", tool="decompile"),
            EvidenceIndexRow(id="ev_0002", server="capa", tool="capa"),
        ]
    )
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    assert _line(bundle, "- Tool servers called:") == "- Tool servers called: capa, ghidra"


def test_a_provider_in_the_source_is_named_and_a_call_naming_none_is_counted() -> None:
    report = _report(
        evidence_index=[
            EvidenceIndexRow(id="ev_0001", server="ghidra", tool="decompile"),
            EvidenceIndexRow(id="ev_0002", tool="analyze", source="provider:r2"),
            EvidenceIndexRow(id="ev_0003", tool="sandbox_report", source="sandbox"),
            EvidenceIndexRow(id="ev_0004", tool="read_evidence"),
        ]
    )
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    assert _line(bundle, "- Tool servers called:") == (
        "- Tool servers called: ghidra, r2; 2 calls record no server"
    )


def test_calls_that_name_no_server_at_all_are_counted_and_none_named() -> None:
    report = _report(evidence_index=[EvidenceIndexRow(id="ev_0001", tool="read_evidence")])
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    assert _line(bundle, "- Tool servers called:") == (
        "- Tool servers called: none named; 1 call records no server"
    )


# -- the sandbox -------------------------------------------------------------


def _sandboxed() -> MalwareReport:
    child = ProcessNode(pid=2, name="b.exe")
    return _report(
        evidence_index=[EvidenceIndexRow(id="ev_0001", server="sandbox", tool="detonate")],
        dynamic=DynamicBehavior(
            process_tree=[ProcessNode(pid=1, name="a.exe", children=[child])],
            sandbox_signatures=[SandboxSignature(name="sig")],
            file_operations=[{"operation": "write", "path": "C:\\x.dat"}],
        ),
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="a.example", source="sandbox")]),
    )


def test_a_held_sandbox_report_is_counted_and_never_said_to_record_the_sample() -> None:
    report = _sandboxed()
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    analyst = MarkdownRenderer(layout=ANALYST).render(report)

    said = (
        "A sandbox report is held listing 2 processes, 1 signature and 1 file-operation row, "
        "and the sandbox is the source of 1 network row."
    )
    assert said in bundle
    assert said in analyst
    assert _line(bundle, "- Sandbox:") == (
        "- Sandbox: a report is held listing 2 processes, 1 signature and 1 file-operation "
        "row; the source of 1 network row"
    )
    assert "recorded the sample's behaviour" not in bundle + analyst


def test_network_rows_alone_are_counted_as_the_sandbox_s() -> None:
    report = _report(
        evidence_index=[EvidenceIndexRow(id="ev_0001", server="sandbox", tool="detonate")],
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="a.example", source="sandbox")]),
    )
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    assert "The sandbox is the source of 1 network row." in bundle
    assert _line(bundle, "- Sandbox:") == "- Sandbox: the source of 1 network row"


def test_a_sandbox_not_called_is_said_as_before() -> None:
    report = _report(evidence_index=[EvidenceIndexRow(id="ev_0001", server="x", tool="strings")])
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    assert _line(bundle, "- Sandbox:") == "- Sandbox: not called"


# -- the judge and the STIX bundle -------------------------------------------


def _method(summary: dict[str, object]) -> str:
    bundle = MarkdownRenderer(layout=BUNDLE).render(_report(run_summary=summary))
    return _line(bundle, "This report was produced")


def test_a_judge_bundle_the_size_of_the_exported_one_is_said_as_before() -> None:
    line = _method({"judge_stix_object_count": 27, "stix_object_count": 27})

    assert "a judge stated the verdict and the STIX bundle, and a report model wrote" in line
    assert "The judge's STIX bundle holds" not in line


def test_a_judge_bundle_of_another_size_is_counted_beside_the_exported_one() -> None:
    smaller = _method({"judge_stix_object_count": 16, "stix_object_count": 9})
    empty = _method({"judge_stix_object_count": 0, "stix_object_count": 18})

    for line in (smaller, empty):
        assert "a judge stated the verdict, and a report model wrote the assessed prose." in line
        assert "the STIX bundle," not in line
    assert "The judge's STIX bundle holds 16 objects; the exported one holds 9 objects." in smaller
    assert "The judge's STIX bundle holds no object; the exported one holds 18 objects." in empty


def test_a_run_that_recorded_no_count_of_the_judge_s_says_nothing_of_the_bundle() -> None:
    line = _method({"stix_object_count": 33})

    assert "a judge stated the verdict, and a report model wrote the assessed prose." in line
    assert "STIX" not in line


def test_the_analyst_scope_says_no_judge_stated_a_verdict_on_a_stopped_run() -> None:
    stopped = _report(verdict_not_assessed="the run was stopped before its verdict stage ran")
    analyst = MarkdownRenderer(layout=ANALYST).render(stopped)
    judged = MarkdownRenderer(layout=ANALYST).render(_report())

    assert (
        "it is partial: the run was stopped before its verdict stage ran, so no judge stated "
        "a verdict."
    ) in analyst
    assert "a judge stated the verdict" not in analyst
    assert "a judge stated the verdict and a report model wrote the assessed prose." in judged


# -- an analyst's table of values --------------------------------------------


def test_every_typed_value_shown_as_the_analyst_s_keeps_the_sentence() -> None:
    note = analyst_list_note(["static"], "iocs", (2, 2, 0))
    where = section_reference(INDICATORS_TITLE)

    assert analyst_list_note(["static"], "iocs") == note
    assert f"Each value it types as an indicator is in {where} as the analyst's" in note


def test_values_shown_under_another_source_or_not_at_all_are_counted() -> None:
    note = analyst_list_note(["static"], "iocs", (4, 1, 2))
    one = analyst_list_note(["static"], "iocs", (1, 0, 1))
    where = section_reference(INDICATORS_TITLE)

    assert "Each value" not in note
    assert (
        f"Of the 4 values it types as an indicator, 1 is in {where} as the analyst's, with the "
        f"publish rule's answer; 2 are in {where} under another source; 1 is not in {where}."
    ) in note
    assert f"The value it types as an indicator is in {where} under another source." in one


def test_a_table_the_report_reads_no_value_of_says_so() -> None:
    note = analyst_list_note(["static"], "iocs", (0, 0, 0))

    assert "it types as an indicator" not in note
    assert "The report reads no value of it as an indicator." in note


def test_a_label_column_naming_no_indicator_kind_gives_no_value_and_says_so() -> None:
    # The value is in the indicator section, under the file's strings and not as
    # the analyst's: the line names no place for it.
    line = _listed(
        ["Email in signer subject", "cert@signer.example"],
        columns=["Label", "Value"],
        static=StaticAnalysis(
            interesting_strings=[StringIOC(kind="email", value="cert@signer.example")]
        ),
    )

    assert "as the analyst's" not in line
    assert "The report reads no value of it as an indicator." in line


def _listed(*rows: list[str], columns: list[str] | None = None, **fields: object) -> str:
    section = EvidenceSection(
        key="artifact_iocs",
        title="IOCs",
        kind="table",
        columns=columns or ["type", "value"],
        rows=list(rows),
        source="artifact:static",
    )
    bundle = MarkdownRenderer(layout=BUNDLE).render(_report(sections=[section], **fields))
    return _line(bundle, "_Listed by the static analyst")


def test_the_count_is_read_from_the_table_and_the_indicator_rows() -> None:
    alone = _listed(["mutex", "Global\\only-listed"], ["mutex", "Global\\also-listed"])
    shared = _listed(
        ["mutex", "Global\\only-listed"],
        ["mutex", "Global\\seen"],
        ["domain", "evil.example"],
        evidence_index=[EvidenceIndexRow(id="ev_0001", server="sandbox", tool="detonate")],
        dynamic=DynamicBehavior(file_operations=[{"operation": "mutex", "name": "Global\\seen"}]),
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="evil.example", source="sandbox")]),
    )

    assert "Each value it types as an indicator is in §9 as the analyst's" in alone
    assert (
        "Of the 3 values it types as an indicator, 1 is in §9 as the analyst's, with the publish "
        "rule's answer; 2 are in §9 under another source."
    ) in shared


# -- the notes of the analyst report -----------------------------------------


def _bundle_with(*notes: CitationNote, uncited: int = 0) -> str:
    report = _report(
        evidence_index=[EvidenceIndexRow(id=f"ev_000{n}", tool="t") for n in (1, 2, 3)]
    )
    return str(_notes_section(report, list(notes), uncited))


def test_ids_a_note_joins_are_each_linked() -> None:
    notes = [
        CitationNote(1, ("ev_0001; ev_0002",), "c2"),
        CitationNote(2, ("ev_0002, ev_0003",), "c2"),
    ]
    text = _bundle_with(*notes)

    assert "**Note 1** (Command and control): [ev_0001](#ev_0001), [ev_0002](#ev_0002)" in text
    assert "**Note 2** (Command and control): [ev_0002](#ev_0002), [ev_0003](#ev_0003)" in text
    assert "no entry of the evidence index carries" not in text
    assert "each linked to its row in Appendix A._" in text


def test_an_unknown_part_of_a_joined_id_is_named_and_the_caption_says_so() -> None:
    text = _bundle_with(CitationNote(1, ("ev_0001; ev_9999",), "c2"))

    note = _line(text, "- **Note 1**")
    assert note.startswith("- **Note 1** (Command and control): [ev_0001](#ev_0001), ")
    assert "9999](" not in note
    assert "_9999**: no entry of the evidence index carries this id." in text
    assert "each the evidence index holds linked to its row in Appendix A._" in text
    assert "rests on, each linked to its row" not in text


def test_each_id_the_citation_reader_finds_in_an_item_is_linked() -> None:
    forms = {
        "ev_0001, ev_0002": ["ev_0001", "ev_0002"],
        "ev_0001; ev_0002": ["ev_0001", "ev_0002"],
        "EV_0001; EV_0002": ["ev_0001", "ev_0002"],
        "ev_0001, ev_0002;": ["ev_0001", "ev_0002"],
        "ev_0001 and ev_0002": ["ev_0001", "ev_0002"],
    }
    for item, ids in forms.items():
        text = _bundle_with(CitationNote(1, (item,), "c2"))

        assert note_ids(CitationNote(1, (item,), "c2")) == ids, item
        assert "**Note 1** (Command and control): [ev_0001](#ev_0001), [ev_0002](#ev_0002)" in (
            text
        ), item
        assert "no entry of the evidence index carries" not in text, item


def test_an_item_holding_more_than_ids_links_its_ids_and_names_itself_as_written() -> None:
    note = CitationNote(1, ("ev_0001 and more",), "c2")
    text = _bundle_with(note)

    assert note_ids(note) == ["ev_0001", "ev_0001 and more"]
    assert _line(text, "- **Note 1**") == (
        "- **Note 1** (Command and control): [ev_0001](#ev_0001), ev_0001 and more"
    )
    assert "- **ev_0001 and more**: no entry of the evidence index carries this id." in text


def test_an_item_the_citation_reader_reads_no_id_in_is_named_as_written() -> None:
    note = CitationNote(1, ("ev_1, ev_2;",), "c2")

    assert note_ids(note) == ["ev_1, ev_2;"]
    assert "**ev_1, ev_2;**: no entry of the evidence index carries this id." in (
        _bundle_with(note)
    )


def test_every_bundle_surface_carries_each_id_of_a_joined_item() -> None:
    report = _report(
        technical_analysis=TechnicalAnalysis(
            packing_obfuscation=TechnicalSubsection(
                title="Packing", body="Strings are decoded.", evidence_refs=["ev_0001; ev_0002"]
            )
        ),
        evidence_index=[EvidenceIndexRow(id=f"ev_000{n}", tool="t") for n in (1, 2)],
    )
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    document = json.loads(bundle_json(report))

    assert "[ev_0001](#ev_0001), [ev_0002](#ev_0002)" in bundle
    assert "no entry of the evidence index carries" not in bundle
    assert ["ev_0001", "ev_0002"] in [note["evidence_ids"] for note in document["notes"]]


def test_a_note_no_marker_cites_is_counted_not_listed() -> None:
    listed = _bundle_with(CitationNote(1, ("ev_0001",), "c2"), uncited=1)
    whole = _bundle_with(CitationNote(1, ("ev_0001",), "c2"))

    assert (
        "1 further note was numbered for a passage the analyst report does not print; no marker "
        "cites it, and it is not listed."
    ) in listed
    assert "further note" not in whole


def test_the_pdf_notes_list_only_the_notes_its_body_cites() -> None:
    body = '<p>x<sup class="cite"><a href="evidence-bundle.html#cite-1">1</a></sup></p>'
    notes = [CitationNote(1, ("ev_0001",), "c2"), CitationNote(2, ("ev_0002",), "c2")]
    html = _notes_in_the_document(body, notes, None, {1})
    whole = _notes_in_the_document(body, notes[:1], None, {1})

    assert '<li id="note-1">1. ev_0001</li>' in html
    assert "note-2" not in html
    assert "1 further note was numbered for a passage this report does not print" in html
    assert "further note" not in whole


def test_the_pdf_notes_list_prints_each_id_of_a_joined_item_as_the_bundle_does() -> None:
    body = '<p>x<sup class="cite"><a href="evidence-bundle.html#cite-1">1</a></sup></p>'
    note = CitationNote(1, ("EV_0001; ev_0002",), "c2")

    listed = _notes_in_the_document(body, [note], None, {1})

    assert '<li id="note-1">1. ev_0001, ev_0002</li>' in listed


def _dropped(summary: str = "") -> MalwareReport:
    """A report whose ATT&CK row prints the written procedure on the first writing and the
    claim sentence on the second: the procedure's note is numbered and no marker cites it."""
    return _report(
        executive_summary=summary,
        evidence_index=[EvidenceIndexRow(id=f"ev_000{n}", tool="t") for n in (1, 2)],
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1134",
                technique_name="Access Token Manipulation",
                evidence=["The code at 0x00401a2b calls AdjustTokenPrivileges [ev_0001]."],
            )
        ],
        technical_analysis=TechnicalAnalysis(
            technique_procedures=[
                TechniqueProcedure(
                    technique_id="T1134",
                    procedure="The sample adjusts its own token privileges.",
                    evidence_refs=["ev_0002"],
                )
            ]
        ),
    )


def _cited_sets(report: MalwareReport) -> tuple[set[int], set[int], set[int], str]:
    """The notes the bundle's Markdown lists, those its HTML lists, those the self-contained
    analyst report lists, and the bundle's Markdown."""
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    bundle_html = HtmlRenderer(layout=BUNDLE).render(report)
    alone = HtmlRenderer(layout=ANALYST, self_contained=True).render(report)
    listed = {int(n) for n in re.findall(r"^- \*\*Note (\d+)\*\*", bundle, re.MULTILINE)}
    listed_html = {int(n) for n in re.findall(r'<li id="cite-(\d+)"', bundle_html)}
    listed_alone = {int(n) for n in re.findall(r'<li id="note-(\d+)"', alone)}
    return listed, listed_html, listed_alone, bundle


def test_a_note_whose_marked_passage_is_dropped_is_counted_not_listed() -> None:
    report = _dropped()
    _md, notes = MarkdownRenderer(layout=ANALYST).render_with_notes(report)
    listed, listed_html, marked, bundle = _cited_sets(report)
    document = json.loads(bundle_json(report))
    appendix = next(s["markdown"] for s in document["sections"] if s["title"] == NOTES_TITLE)

    assert len(notes) == 2
    assert listed == listed_html == marked == {2}
    assert "1 further note was numbered for a passage the analyst report does not print" in (bundle)
    assert "1 further note was numbered" in appendix
    assert "**Note 1**" not in appendix


def test_model_text_naming_a_note_anchor_cites_no_note() -> None:
    written = (
        "See #cite-1 here, `#cite-1` in a span and [[1]](evidence-bundle.html#cite-1) as a link."
    )
    listed, listed_html, marked, bundle = _cited_sets(_dropped(written))

    assert "#cite-1" in MarkdownRenderer(layout=ANALYST).render(_dropped(written))
    assert listed == listed_html == marked == {2}
    assert "1 further note was numbered for a passage the analyst report does not print" in (bundle)


def test_every_form_of_the_notes_list_lists_the_notes_the_markers_cite() -> None:
    report = _report(
        technical_analysis=TechnicalAnalysis(
            packing_obfuscation=TechnicalSubsection(
                title="Packing", body="Strings are decoded [ev_0001].", evidence_refs=["ev_0002"]
            )
        ),
        evidence_index=[EvidenceIndexRow(id=f"ev_000{n}", tool="t") for n in (1, 2)],
    )
    listed, listed_html, marked, _bundle = _cited_sets(report)
    _md, _notes, cited = MarkdownRenderer(layout=ANALYST).render_with_citations(report)

    assert listed
    assert listed == listed_html == marked == cited


def test_the_bundle_speaks_of_its_notes_as_the_list_it_prints() -> None:
    bundle = MarkdownRenderer(layout=BUNDLE).render(_dropped())

    assert "and a list of the notes the analyst report cites (Appendix E)" in bundle
    assert "_Each note the analyst report cites, the section it stands in" in bundle
    assert "Each numbered note of the analyst report" not in bundle


# -- the analyst report's section 8 ------------------------------------------


def test_the_indicator_closing_sentence_makes_no_claim_about_each_answered_value() -> None:
    analyst = MarkdownRenderer(layout=ANALYST).render(_sandboxed())

    assert "is not in the machine-readable outputs" not in analyst
    assert "Network values are defanged for reading. The machine-readable outputs carry" in (
        analyst
    )


def test_a_rule_body_the_appendix_leaves_out_is_counted() -> None:
    printed = DetectionRule(kind="sigma", name="behaviour", body="title: x")
    unchecked = DetectionRule(kind="yara", name="unchecked", body="rule x { condition: true }")
    some = MarkdownRenderer(layout=ANALYST).render(
        _report(detection_signatures=[printed, unchecked])
    )
    every = MarkdownRenderer(layout=ANALYST).render(_report(detection_signatures=[printed]))

    assert (
        "The bodies of 1 of these 2 rules are in the appendix, the others' in the bundle. Test a "
        "rule before deploying it."
    ) in some
    assert "The rule bodies are in the appendix. Test a rule before deploying it." in every


def test_a_row_of_the_dropped_files_list_says_where_it_is_listed() -> None:
    analyst = MarkdownRenderer(layout=ANALYST).render(_sandboxed())

    assert "| in the sandbox's dropped-files list |" in analyst
    assert "dropped while a sandbox watched" not in analyst


# -- a judge's reason the analyst report shortens ----------------------------


def _held(reason: str) -> CapabilityCell:
    return CapabilityCell(
        tactic="TA0002",
        tactic_name="Execution",
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        not_published=f"the judge dropped it ({reason})",
    )


_LONG = " ".join(f"Sentence number {n} gives one more reason." for n in range(12))
_ONE_CUT = (
    "_1 reason above is shortened to fit this page where it shows …; the JSON report "
    "(`/reports/{report_id}/full`) carries it whole, under `capability_matrix`._"
)


def _cuts_note(count: int) -> str:
    return (
        f"_The reasons above are shortened to fit this page in {count} places, each "
        "where it shows …; the JSON report (`/reports/{report_id}/full`) carries each whole, "
        "under `capability_matrix`._"
    )


def _published(reason: str) -> CapabilityCell:
    return CapabilityCell(
        tactic="TA0002",
        tactic_name="Execution",
        technique_id="T1106",
        technique_name="Native API",
        evidence=["The code calls CreateProcessW."],
        note=f"the ATT&CK check found no catalogue term; kept by the judge when asked ({reason})",
    )


def test_a_reason_cut_to_fit_is_counted_under_the_list() -> None:
    analyst = MarkdownRenderer(layout=ANALYST).render(_report(capability_matrix=[_held(_LONG)]))

    assert status_cuts(_held(_LONG).not_published, JUDGE_REASON_WIDTH) == 1
    assert _ONE_CUT in analyst


def test_a_published_row_s_judge_note_cut_to_fit_is_counted() -> None:
    alone = MarkdownRenderer(layout=ANALYST).render(_report(capability_matrix=[_published(_LONG)]))
    both = MarkdownRenderer(layout=ANALYST).render(
        _report(capability_matrix=[_published(_LONG), _held(_LONG)])
    )

    assert reasons_cut(_published(_LONG).note) == 1
    assert "Sentence number 0 gives one more reason." in alone
    assert _ONE_CUT in alone
    assert _cuts_note(2) in both


def test_a_reason_printed_whole_carries_no_note_even_with_the_judge_s_own_ellipsis() -> None:
    reason = "The sample calls cmd.exe … and nothing else."
    report = _report(capability_matrix=[_held(reason), _published(reason)])
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    assert not status_cuts(_held(reason).not_published, JUDGE_REASON_WIDTH)
    assert not reasons_cut(_published(reason).note)
    assert "shortened to fit this page" not in analyst + bundle


def test_a_reason_whose_working_sentences_are_left_out_is_a_cut() -> None:
    assert status_cuts("the judge dropped it (Wait, let me think. No support.)", 200) == 1
    assert status_cuts("the judge dropped it (No support.)", JUDGE_REASON_WIDTH) == 0


def test_each_reason_a_status_prints_in_part_and_its_cut_tail_are_one_cut_each() -> None:
    two = f"the judge dropped it ({_LONG}); kept by the judge when asked ({_LONG})"
    tail = f"the judge dropped it ({_LONG}), asked after {_LONG}"

    assert reasons_cut(two) == 2
    assert status_cuts(two, JUDGE_REASON_WIDTH) == 2
    assert reasons_cut(tail) == 1
    assert status_cuts(tail, JUDGE_REASON_WIDTH) == 2


def test_the_bundle_counts_each_judge_reason_its_attack_section_shortens() -> None:
    held = MarkdownRenderer(layout=BUNDLE).render(_report(capability_matrix=[_held(_LONG)]))
    published = MarkdownRenderer(layout=BUNDLE).render(
        _report(capability_matrix=[_published(_LONG)])
    )

    # The table's status cell and the list of claims not published each print it in part.
    assert _cuts_note(2) in held
    assert _ONE_CUT in published


# The sentences of ``_LONG`` its printed reason holds, and a second reason worded apart.
_PRINTED = [f"Sentence number {n} gives one more reason." for n in range(4)]
_OTHER = " ".join(f"Clause number {n} adds one more ground." for n in range(12))


def _round_left_out(held: str, note: str = "", *sentences: str) -> MalwareReport:
    """A report holding ``held`` as T1055's reason and ``note`` as T1622's, after a round that
    left out each of ``sentences`` of the one that holds it, its record stored."""
    report = report_of()
    cells = [cell for cell in report.capability_matrix if cell.technique_id == "T1057"]
    cells.append(
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id="T1055",
            technique_name="Process Injection",
            not_published=held,
        )
    )
    if note:
        cells.append(
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1622",
                technique_name="Debugger Evasion",
                evidence=["Routine 0x5b20 returns -1 [ev_0103]."],
                note=note,
            )
        )
    report.capability_matrix = cells
    pid = "attack_note.T1622" if note else "attack_note.T1055"
    rows = [
        {
            "passage": pid,
            "sentence": sentence,
            "decision": "drop",
            "sources": ["string_resolution"],
            "reason": "Not so.",
        }
        for sentence in sentences
    ]
    counts, found = apply_rows({"sentences": rows}, passages_of(report))
    assert counts["dropped"] == len(sentences)
    tally = ValidationTally()
    tally.record_unresolved(AGREEMENT_PRODUCER, found)
    report.run_summary = {
        **(report.run_summary or {}),
        "validation": {"unresolved": tally.unresolved},
    }
    return report


def _attack_section(page: str) -> str:
    """The ATT&CK section of a Markdown or an HTML page."""
    html = "<h2" in page
    return next(
        part
        for part in page.split("<h2" if html else "\n## ")
        if "ATT&CK mapping" in part.split("</h2>" if html else "\n")[0].replace("&amp;", "&")
    )


def _counted_and_printed(page: str) -> tuple[int, int]:
    """The number the cut line of ``page``'s ATT&CK section states, and the cut marks the
    section prints beside it, the one in the line itself not among them."""
    section = _attack_section(page)
    stated = re.search(r"in (\d+) places|(1) reason above is shortened", section)
    number = int(next(group for group in stated.groups() if group)) if stated else 0
    return number, section.count("…") - (1 if stated else 0)


def test_a_cut_in_a_reason_the_round_leaves_out_whole_is_not_counted() -> None:
    report = _round_left_out(f"the judge dropped it ({_LONG}), asked after {_LONG}", "", *_PRINTED)
    analyst = MarkdownRenderer(layout=ANALYST).render(report)

    # The bracket goes whole, its cut with it; the tail's cut is printed and counted.
    assert "claimed, not published: the judge dropped it, asked…" in analyst
    assert _ONE_CUT in analyst
    assert _counted_and_printed(analyst) == (1, 1)


def test_a_cut_beside_a_reason_the_round_leaves_out_whole_is_counted() -> None:
    held = f"the judge dropped it (No write is shown.); kept by the judge when asked ({_LONG})"
    analyst = MarkdownRenderer(layout=ANALYST).render(
        _round_left_out(held, "", "No write is shown.")
    )

    assert "No write is shown." not in _attack_section(analyst)
    assert _ONE_CUT in analyst
    assert _counted_and_printed(analyst) == (1, 1)


def test_only_the_cut_beside_a_reason_left_out_whole_is_counted() -> None:
    held = f"the judge dropped it ({_LONG}); kept by the judge when asked ({_OTHER})"
    analyst = MarkdownRenderer(layout=ANALYST).render(_round_left_out(held, "", *_PRINTED))

    assert "Sentence number" not in _attack_section(analyst)
    assert "Clause number 0 adds one more ground." in analyst
    assert _ONE_CUT in analyst
    assert _counted_and_printed(analyst) == (1, 1)


def test_a_note_s_reason_left_out_whole_takes_its_cut_and_the_judge_s_own_ellipsis_is_none() -> (
    None
):
    note = (
        f"the ATT&CK check found no catalogue term; kept by the judge when asked ({_LONG}); "
        "kept by the judge when asked (It holds … as written.)"
    )
    analyst = MarkdownRenderer(layout=ANALYST).render(
        _round_left_out("the judge dropped it (No write is shown.)", note, *_PRINTED)
    )

    assert "(It holds … as written.)" in analyst
    assert "shortened to fit this page" not in analyst


def test_each_surface_counts_the_cut_marks_it_prints() -> None:
    held = f"the judge dropped it ({_LONG}); kept by the judge when asked ({_OTHER}), {_LONG}"
    report = _round_left_out(held, "", *_PRINTED)
    pages = (
        MarkdownRenderer(layout=ANALYST).render(report),
        HtmlRenderer(layout=ANALYST).render(report),
        HtmlRenderer(layout=ANALYST, self_contained=True).render(report),
        MarkdownRenderer(layout=BUNDLE).render(report),
    )

    for page in pages:
        number, printed = _counted_and_printed(page)
        assert number == printed and number


# A reason whose printed brackets pair otherwise than the stored ones: the span the left-out
# step reads runs past the platform's cut mark, into the sentence it stands in.
_UNPAIRED = "the judge dropped it (One (two. Three … four. Five six.)"
_MARK = _UNPAIRED.index("…")


def _left(printed: str, marks: list[int], *sentences: str) -> tuple[str, int, int]:
    return _left_out_marks(printed, judge_reason_spans(printed), sentences, marks)


def test_a_mark_in_the_sentence_a_partial_trim_takes_is_not_printed_and_not_counted() -> None:
    out, cut, printed = _left(_UNPAIRED, [_MARK], "Three … four.")

    assert (out, cut, printed) == ("the judge dropped it (One (two. Five six.)", 1, 0)


def test_a_mark_in_the_part_a_partial_trim_keeps_is_counted() -> None:
    out, cut, printed = _left(_UNPAIRED, [_MARK], "One (two.")

    assert (out, cut, printed) == ("the judge dropped it (Three … four. Five six.)", 1, 1)


def test_a_mark_in_a_reason_left_out_whole_is_not_counted() -> None:
    out, cut, printed = _left(_UNPAIRED, [_MARK], "One (two.", "Three … four.", "Five six.)")

    assert (out, cut, printed) == ("the judge dropped it", 3, 0)


def test_each_cut_of_a_status_cut_twice_is_counted_where_it_still_prints() -> None:
    status = f"the judge dropped it ({_LONG}), asked after {_LONG}"
    raw = "".join(piece for piece, _set in status_parts(status, JUDGE_REASON_WIDTH, _whole))
    marks = [*reason_marks(status), raw.rindex("…")]

    assert raw.count("…") == 2
    assert _left(raw, marks)[2] == 2
    assert _left(raw, marks, _PRINTED[1])[2] == 2
    assert _left(raw, marks, *_PRINTED)[2] == 1


def _whole(text: str) -> list[tuple[str, bool]]:
    return [(text, False)]


def test_a_model_s_ellipsis_beside_a_trimmed_cut_reason_is_never_counted() -> None:
    held = f"the judge dropped it (It holds … as written. {_LONG}), asked after {_LONG}"
    analyst = MarkdownRenderer(layout=ANALYST).render(_round_left_out(held, "", _PRINTED[1]))
    line = _line(analyst, "- T1055")

    # The judge's "…", the reason's cut and the status's cut: two of them the platform's.
    assert _PRINTED[1] not in line and _PRINTED[2] in line
    assert line.count("…") == 3
    assert _cuts_note(2) in analyst


# -- the title block's line on the limitations -------------------------------


def _title(inventory: LimitationInventory | None) -> str:
    report = _report(
        degradation_reasons=["one reason the run recorded"], limitation_inventory=inventory
    )
    return _line(MarkdownRenderer(layout=BUNDLE).render(report), "**Notes:**")


def test_a_run_with_no_inventory_counts_its_recorded_reasons_as_before() -> None:
    assert _title(None) == "**Notes:** this run recorded 1 limitation; see §13."


def test_an_inventory_stating_no_limit_keeps_the_line() -> None:
    assert _title(LimitationInventory(withheld=3, sandbox_observed=True)) == (
        "**Notes:** this run recorded 1 limitation; see §13."
    )


def test_the_measured_limits_are_counted_beside_the_recorded_reasons() -> None:
    inventory = LimitationInventory(
        entries=10,
        withheld=3,
        sandbox_observed=True,
        failed=[InventoryCall(entry="ev_0001", tool="t")],
    )

    assert _title(inventory) == (
        "**Notes:** §13 states 1 measured limitation of this run (of its 2 measured rows) and "
        "1 limitation the run recorded."
    )
