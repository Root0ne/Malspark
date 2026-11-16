"""A source cited to state an absence is shown apart from a technique's evidence (T-708).

A claim may name a technique and cite the places it searched to say the
behaviour's traces are not there: "the endpoints do not appear in the capture
... [ev_0203] DNS names (no match)". Those sources are cited, and they are no
evidence of the behaviour. The corroboration row carries, per source, whether
every statement that cites it for the technique cites it for an absence: the
clause of a sentence or evidence-line item that writes the citation reads as a
denial. "No match" and "does not appear" deny only for an entry whose own
stored answer found nothing, read through its declaration; no word decides it.
A technique's evidence prints the other sources, and the absence-cited ones
apart under their own label. A source cited both ways is evidence. Every id,
name and sentence here is made up for the test.
"""

from __future__ import annotations

import json

from malspark.extractors.capability_matrix import build_capability_matrix
from malspark.pipeline.validation import (
    _cited_for_an_absence,
    _cites_to_negate,
    _denies,
    _negated_for_its_technique,
    _negates,
    answer_found_nothing,
    corroboration,
)
from malspark.reporting.models import TTPMapping
from malspark.reporting.technique_evidence import (
    ABSENCE_LABEL,
    technique_evidence_ids,
    technique_evidence_words,
    technique_sandbox_items,
)
from malspark.schemas.evidence import LedgerEntry, not_shown_record
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

CLAIM = (
    "The negotiation endpoints are static strings only. chat.example, the onion address and "
    "the mailbox do not appear in the capture's DNS names, HTTP hosts, TLS SNI or sandbox "
    "network items. In this run they were not contacted."
)
REF = (
    '[ev_0006] IOC strings "chat.example", "https://chat.example/download.html"; '
    "[ev_0203] DNS names (no match); [ev_0204] HTTP hosts (no match); "
    "[ev_0202] TLS SNI (no match); [ev_0201] net:1–net:8 (no match)."
)
SAID = f"{CLAIM} {REF}"


def _searched(entry_id: str, tool: str, rows: list[dict[str, str]]) -> LedgerEntry:
    """An entry whose tool declares where its answer's rows sit, holding ``rows`` there."""
    answer = {"matches": rows}
    return LedgerEntry(
        id=entry_id,
        tool=tool,
        args={},
        output=json.dumps(answer),
        structured=answer,
        facts={"v": 1, "kind": "search_matches", "rows": "/matches/*"},
    )


# The searches the claim cites found nothing: their answers hold no row.
LEDGER = [
    LedgerEntry(
        id="ev_0006",
        tool="iocs_from_file",
        args={},
        output=json.dumps({"iocs": [{"value": "chat.example"}]}),
    ),
    _searched("ev_0202", "list_sni", []),
    _searched("ev_0203", "list_dns", []),
    _searched("ev_0204", "list_hosts", []),
]
# The same searches, each answering with rows: what they found is not what the
# claim names, and the record states no absence.
HELD = [
    LEDGER[0],
    _searched("ev_0202", "list_sni", [{"name": "login.example"}]),
    _searched("ev_0203", "list_dns", [{"name": "update.example"}]),
    _searched("ev_0204", "list_hosts", [{"name": "a.example"}]),
]


def test_an_answer_whose_declared_rows_are_empty_found_nothing() -> None:
    assert answer_found_nothing(LEDGER[2])
    assert not answer_found_nothing(HELD[2])
    # No declaration of its rows, or no answer stored: nothing is stated.
    assert not answer_found_nothing(LEDGER[0])
    assert not answer_found_nothing(
        LedgerEntry(id="ev_0207", tool="list_dns", args={}, output="", facts=LEDGER[2].facts)
    )
    # An entry that stored no declaration is never read by its tool's name.
    unrecorded = LedgerEntry(
        id="ev_0208",
        tool="resolve_api_hashes",
        args={},
        output=json.dumps({"hits": []}),
        structured={"hits": []},
    )
    assert not answer_found_nothing(unrecorded)
    # The declared place itself missing from the answer states nothing either.
    missing = LEDGER[2].model_copy(update={"structured": {"other": []}})
    assert not answer_found_nothing(missing)


def test_an_answer_that_failed_was_cut_or_repeats_states_nothing() -> None:
    empty = LEDGER[2]
    assert answer_found_nothing(empty)
    assert not answer_found_nothing(empty.model_copy(update={"ok": False}))
    assert not answer_found_nothing(empty.model_copy(update={"truncated": True}))
    assert not answer_found_nothing(empty.model_copy(update={"repeated_of": "ev_0001"}))
    # An answer the conversation had no room for (it is cut, too).
    not_shown = empty.model_copy(update={"truncated": True, "output": not_shown_record(900)})
    assert not answer_found_nothing(not_shown)


def test_a_declared_place_that_is_no_list_or_object_states_nothing() -> None:
    held = LEDGER[2].model_copy(update={"structured": {"matches": "none"}})
    assert not answer_found_nothing(held)


def test_a_rows_path_of_one_segment_reads_the_answer_itself() -> None:
    facts = {"v": 1, "kind": "search_matches", "rows": "/*"}
    empty = LedgerEntry(
        id="ev_0209", tool="list_dns", args={}, output="[]", structured=[], facts=facts
    )
    held = empty.model_copy(update={"structured": [{"name": "a.example"}]})
    assert answer_found_nothing(empty)
    assert not answer_found_nothing(held)


def test_no_match_and_does_not_appear_are_forms_of_denial_read_by_the_clause() -> None:
    assert _denies("[ev_0203] DNS names (no match)")
    assert _denies("no matches in the hosts")
    assert _denies("the addresses do not appear in the capture")
    assert _denies("the name never appears in the strings")
    assert not _denies("[ev_0006] IOC strings chat.example")
    # The sentence reader keeps its own forms: these are the clause reader's alone.
    assert not _negates("[ev_0203] DNS names (no match)")
    assert not _negates("the addresses do not appear in the capture")


def test_a_denial_form_reaches_only_the_source_its_clause_cites() -> None:
    said = "ev_0050 encrypts files - ev_0051 (no match)"
    assert not _cites_to_negate(said, "ev_0050")
    assert not _negated_for_its_technique(said, "ev_0050", found_nothing=True)
    assert _negated_for_its_technique(said, "ev_0051", found_nothing=True)


def test_a_denial_form_denies_nothing_for_an_entry_whose_answer_holds_rows() -> None:
    said = "ev_0050 encrypts files - ev_0051 (no match)"
    assert not _negated_for_its_technique(said, "ev_0051")
    assert not _cited_for_an_absence(said, "ev_0051")


def test_a_denial_in_another_sentence_of_the_claim_negates_no_evidence_line_citation() -> None:
    claim = "The sample encrypts files with AES. The note does not appear in the sandbox capture."
    said = f"{claim} ev_0010 AES S-box constants"
    assert not _cites_to_negate(said, "ev_0010", claim)
    assert not _negated_for_its_technique(said, "ev_0010", claim, found_nothing=True)


# Statements that assert what a routine does, in the words of a denial. ("The
# resolver returns NULL when the hash has no match" is not here: "has no" is the
# base reader's own form, which reads it as it always did.)
ASSERTIONS = (
    "The encryptor [ev_0050] encrypts every file with no match in its exclusion list.",
    "If the mutex does not appear in the registry the payload runs [ev_0050].",
    "The loop [ev_0050] repeats until no match is left.",
    "[ev_0050] skips a file whose extension does not appear in the target list.",
    "The dropper [ev_0050] only proceeds if the sandbox artefact does not appear on disk.",
)
# Statements that a searched place holds nothing.
ABSENCES = (
    "The domain [ev_0203] does not appear as a DNS name.",
    "The domain [ev_0203] does not appear elsewhere in the capture.",
    "The domain [ev_0203] does not appear despite the 300 s run.",
    "The domain [ev_0203] never appears before the reboot.",
)
ROUTINES = [
    _searched("ev_0050", "list_routines", [{"name": "encrypt_files"}]),
    _searched("ev_0060", "list_routines", [{"name": "resolve_by_hash"}]),
]


def test_an_assertion_never_moves_its_source_apart() -> None:
    from malspark.pipeline.validation import technique_absence_sources, technique_sources

    for said in ASSERTIONS:
        isrs = {"static": AgentISR(agent_id="static", domain="static", claims=[_claim(said, "")])}
        assert technique_absence_sources(isrs, [*HELD, *ROUTINES]) == {}, said
        plain = said.replace("no match", "a match").replace("does not appear", "appears")
        plain_isrs = {
            "static": AgentISR(agent_id="static", domain="static", claims=[_claim(plain, "")])
        }
        assert technique_sources(isrs, [*HELD, *ROUTINES]) == technique_sources(
            plain_isrs, [*HELD, *ROUTINES]
        ), said


def test_an_absence_is_read_where_the_cited_answer_found_nothing() -> None:
    from malspark.pipeline.validation import technique_absence_sources

    for said in ABSENCES:
        isrs = {
            "network": AgentISR(agent_id="network", domain="network", claims=[_claim(said, "")])
        }
        assert technique_absence_sources(isrs, LEDGER) == {"T1486": ["ev_0203"]}, said
        assert technique_absence_sources(isrs, HELD) == {}, said


def test_a_quoted_denial_is_no_statement_of_the_clause() -> None:
    for said in (
        "The config holds the string 'no match found' [ev_0203].",
        'The config holds the string "no match found" [ev_0203].',
    ):
        assert not _cited_for_an_absence(said, "ev_0203", found_nothing=True), said


def test_each_citation_is_read_by_the_clause_that_writes_it() -> None:
    for citation in ("ev_0202", "ev_0203", "ev_0204"):
        assert _cited_for_an_absence(SAID, citation, found_nothing=True), citation
    # Cited for the strings it holds, in a sentence of its own.
    assert not _cited_for_an_absence(SAID, "ev_0006", found_nothing=True)
    # A negation in another clause of the same sentence governs nothing here.
    said = "Each is built by the constructor [ev_0177], and run by a routine which was not read."
    assert not _cited_for_an_absence(said, "ev_0177")
    # One id written inside a longer one is not that id.
    assert not _cited_for_an_absence("[ev_0201] net:10 (no match)", "net:1", found_nothing=True)


def _claim(text: str, ref: str, tid: str = "T1486") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.8, technique_id=tid)


def test_the_corroboration_row_names_the_sources_cited_for_an_absence() -> None:
    isrs = {"network": AgentISR(agent_id="network", domain="network", claims=[_claim(CLAIM, REF)])}
    row = corroboration(isrs, LEDGER)["T1486"]
    assert set(row["sources"]) >= {"ev_0006", "ev_0202", "ev_0203", "ev_0204"}
    assert row["absence_sources"] == ["ev_0202", "ev_0203", "ev_0204"]


def test_a_source_cited_both_ways_is_evidence() -> None:
    other = _claim("The resolver asked for update.example during the run.", "[ev_0203] DNS names")
    isrs = {
        "network": AgentISR(
            agent_id="network", domain="network", claims=[_claim(CLAIM, REF), other]
        )
    }
    row = corroboration(isrs, LEDGER)["T1486"]
    assert row["absence_sources"] == ["ev_0202", "ev_0204"]


def test_the_claim_cites_nothing_apart_where_its_searches_answered_with_rows() -> None:
    isrs = {"network": AgentISR(agent_id="network", domain="network", claims=[_claim(CLAIM, REF)])}
    assert "absence_sources" not in corroboration(isrs, HELD)["T1486"]


def test_a_technique_with_no_absence_cited_source_carries_no_list() -> None:
    claim = _claim("The capture resolves update.example.", "[ev_0203] DNS names")
    isrs = {"network": AgentISR(agent_id="network", domain="network", claims=[claim])}
    assert "absence_sources" not in corroboration(isrs, LEDGER)["T1486"]


def test_the_matrix_carries_the_absence_cited_sources_to_the_published_row() -> None:
    isrs = {"network": AgentISR(agent_id="network", domain="network", claims=[_claim(CLAIM, REF)])}
    cells, mappings = build_capability_matrix(stix_output=None, isr_reports=isrs, ledger=LEDGER)
    (cell,) = [c for c in cells if c.technique_id == "T1486"]
    assert cell.absence_sources == ["ev_0202", "ev_0203", "ev_0204"]
    for row in (cell, *(m for m in mappings if m.technique_id == "T1486")):
        assert "ev_0203" in row.sources
        assert technique_evidence_ids(row) == ["ev_0006"]


def test_the_evidence_prints_absence_cited_sources_apart() -> None:
    row = TTPMapping(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="TA0040",
        sources=["ev_0006", "ev_0203", "net:1", "net:3", "net:8"],
        evidence_ids=["ev_0006", "ev_0203"],
        absence_sources=["ev_0203", "net:1", "net:8"],
    )
    assert technique_evidence_ids(row) == ["ev_0006"]
    assert list(technique_sandbox_items(row)) == ["net:3"]
    assert technique_evidence_words(row) == (
        f"ev_0006; sandbox items: net:3; {ABSENCE_LABEL}: ev_0203, net:1, net:8"
    )
    # Nothing is lost from the record: every source stays on the row.
    dumped = row.model_dump(mode="json")
    assert dumped["sources"] == ["ev_0006", "ev_0203", "net:1", "net:3", "net:8"]
    assert dumped["evidence_ids"] == ["ev_0006", "ev_0203"]


def test_a_technique_cited_only_for_an_absence_says_so_and_no_entry_besides() -> None:
    row = TTPMapping(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="TA0040",
        sources=["ev_0203", "net:1"],
        evidence_ids=["ev_0203"],
        absence_sources=["ev_0203", "net:1"],
    )
    assert technique_evidence_words(row) == f"no ledger entry; {ABSENCE_LABEL}: ev_0203, net:1"


def test_a_row_without_the_list_prints_as_it_did() -> None:
    row = TTPMapping(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="TA0040",
        sources=["ev_0006", "net:3"],
        evidence_ids=["ev_0006"],
    )
    assert technique_evidence_words(row) == "ev_0006; sandbox items: net:3"
    assert "absence_sources" not in row.model_dump(mode="json")


def test_a_citation_written_in_the_claim_s_sentence_is_read_there() -> None:
    from malspark.pipeline.validation import technique_absence_sources

    claim = _claim("The hosts give no match for the mailbox [ev_0204].", "")
    isrs = {"network": AgentISR(agent_id="network", domain="network", claims=[claim])}
    assert technique_absence_sources(isrs, LEDGER) == {"T1486": ["ev_0204"]}


def test_a_finding_that_cites_a_source_for_the_behaviour_keeps_it_evidence() -> None:
    from malspark.pipeline.validation import technique_absence_sources
    from malspark.schemas.isr_models import Finding

    finding = Finding(
        title="Encryption of user files",
        detail="The files are rewritten",
        technique_ids=["T1486"],
        evidence_ids=["ev_0203"],
        confidence=0.8,
    )
    isrs = {
        "network": AgentISR(
            agent_id="network", domain="network", claims=[_claim(CLAIM, REF)], findings=[finding]
        )
    }
    assert technique_absence_sources(isrs, LEDGER) == {"T1486": ["ev_0202", "ev_0204"]}


def test_a_row_stored_before_the_set_leaves_the_absence_cited_entries_out() -> None:
    row = {"sources": ["ev_0006", "ev_0203"], "absence_sources": ["ev_0203"]}
    assert technique_evidence_ids(row) == ["ev_0006"]
    assert technique_evidence_ids({"sources": ["ev_0203"], "absence_sources": ["ev_0203"]}) is None


def test_an_asserting_entry_whose_rows_name_the_technique_is_evidence() -> None:
    from malspark.core.declared_reading import shipped_by_name, stored_record
    from malspark.pipeline.validation import technique_absence_sources

    answer = {"matches": [{"rule": "example_rule", "meta": {"technique_id": "T1486"}}]}
    rules = LedgerEntry(
        id="ev_0300",
        tool="yara_scan",
        args={},
        output=json.dumps(answer),
        structured=answer,
        facts=stored_record(shipped_by_name()["yara_scan"]),
    )
    claim = _claim(
        "Nothing is encrypted.", "[ev_0300] rules (no match); [ev_0204] hosts (no match)"
    )
    isrs = {"network": AgentISR(agent_id="network", domain="network", claims=[claim])}
    assert technique_absence_sources(isrs, [*LEDGER, rules]) == {"T1486": ["ev_0204"]}


def test_the_judge_s_summary_names_the_absence_cited_sources_apart() -> None:
    from malspark.pipeline.evidence_summary import _source_facts

    row = {
        "sources": ["ev_0006", "ev_0007", "ev_0203", "net:1"],
        "absence_sources": ["ev_0203", "net:1"],
        "independent_sources": 1,
    }
    assert _source_facts(row) == (
        " [traced to 2 cited source(s), each counted once: ev_0006, ev_0007; 1 of them "
        f"independent, sources reading one place counted once; {ABSENCE_LABEL}: ev_0203, net:1]"
    )
    only = {"sources": ["ev_0203"], "absence_sources": ["ev_0203"], "independent_sources": 0}
    assert _source_facts(only) == f" [{ABSENCE_LABEL}: ev_0203]"
    # Independent as many as the traced sources: nothing more is said of them.
    same = {
        "sources": ["ev_0006", "ev_0007", "ev_0203"],
        "absence_sources": ["ev_0203"],
        "independent_sources": 2,
    }
    assert _source_facts(same) == (
        f" [traced to 2 cited source(s), each counted once: ev_0006, ev_0007; {ABSENCE_LABEL}: "
        "ev_0203]"
    )
    # A row without the list reads as it did.
    plain = {"sources": ["ev_0006", "ev_0007"], "independent_sources": 2}
    assert _source_facts(plain) == (
        " [traced to 2 cited source(s), each counted once: ev_0006, ev_0007]"
    )


def test_a_finding_s_title_is_read_for_an_absence() -> None:
    from malspark.pipeline.validation import technique_absence_sources
    from malspark.schemas.isr_models import Finding

    finding = Finding(
        title="The hosts give no match [ev_0204]",
        detail="The files are rewritten",
        technique_ids=["T1486"],
        evidence_ids=["ev_0204"],
        confidence=0.8,
    )
    isrs = {"network": AgentISR(agent_id="network", domain="network", findings=[finding])}
    assert technique_absence_sources(isrs, LEDGER) == {"T1486": ["ev_0204"]}


def test_a_claim_whose_technique_is_invalid_is_not_read_for_an_absence() -> None:
    from malspark.pipeline.validation import technique_absence_sources

    claim = _claim("The hosts give no match for the mailbox [ev_0204].", "")
    claim.technique_id_valid = False
    isrs = {"network": AgentISR(agent_id="network", domain="network", claims=[claim])}
    assert technique_absence_sources(isrs, LEDGER) == {}


def test_the_judge_s_summary_shows_one_total_beside_the_support_sentence() -> None:
    from malspark.analysis.corroboration import support_sentence
    from malspark.pipeline.evidence_summary import _source_facts

    kinds = {"artefact": 2, "unplaced": 1}
    row = {
        "sources": ["ev_0006", "ev_0007", "ev_0203"],
        "absence_sources": ["ev_0203"],
        "independent_sources": 2,
        "support": "capability",
        "source_kinds": kinds,
    }
    sentence = support_sentence("capability", kinds, 3)
    qualified = support_sentence("capability", kinds, 3, absent=1)
    assert qualified == sentence.replace(
        "3 sources:", "3 sources (1 of them cited for an absence):"
    )
    assert _source_facts(row) == (
        " [traced to 2 cited source(s), each counted once: ev_0006, ev_0007; "
        f"{qualified}; {ABSENCE_LABEL}: ev_0203]"
    )
    # With nothing cited for an absence, the sentence stands as it is.
    plain = {k: v for k, v in row.items() if k != "absence_sources"}
    plain["independent_sources"] = 3
    assert _source_facts(plain) == (
        f" [traced to 3 cited source(s), each counted once: ev_0006, ev_0007, ev_0203; {sentence}]"
    )


def test_a_rule_that_matched_stays_a_rule_match_when_a_clause_writes_no_match() -> None:
    from malspark.analysis.evidence_roots import READING_RULE
    from malspark.core.declared_reading import shipped_by_name, stored_record
    from malspark.pipeline.validation import technique_sources

    answer = {"matches": [{"rule": "example_rule", "meta": {"technique_id": "T1486"}}]}
    rules = LedgerEntry(
        id="ev_0300",
        tool="yara_scan",
        args={},
        output=json.dumps(answer),
        structured=answer,
        facts=stored_record(shipped_by_name()["yara_scan"]),
    )
    claim = _claim("The files are encrypted.", "[ev_0300] rules (no match)")
    isrs = {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}
    assert technique_sources(isrs, [*LEDGER, rules])["T1486"]["ev_0300"][0] == READING_RULE
