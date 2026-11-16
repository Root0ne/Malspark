"""A source cited to state an absence is shown apart from a technique's evidence (T-708).

A claim may name a technique and cite the places it searched to say the
behaviour's traces are not there: "the endpoints do not appear in the capture
... [ev_0203] DNS names (no match)". Those sources are cited, and they are no
evidence of the behaviour. The corroboration row carries, per source, whether
every statement that cites it for the technique cites it for an absence: the
clause of a sentence or evidence-line item that writes the citation reads as a
denial. A technique's evidence prints the other sources, and the absence-cited
ones apart under their own label. A source cited both ways is evidence. A range
of items is read by its ends, as the item reader reads it. Every id, name and
sentence here is made up for the test.
"""

from __future__ import annotations

import json

from malspark.extractors.capability_matrix import build_capability_matrix
from malspark.pipeline.validation import _cited_for_an_absence, _negates, corroboration
from malspark.reporting.models import TTPMapping
from malspark.reporting.technique_evidence import (
    ABSENCE_LABEL,
    technique_evidence_ids,
    technique_evidence_words,
    technique_sandbox_items,
)
from malspark.schemas.evidence import LedgerEntry
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


def test_no_match_and_does_not_appear_are_forms_of_denial() -> None:
    assert _negates("[ev_0203] DNS names (no match)")
    assert _negates("no matches in the hosts")
    assert _negates("the addresses do not appear in the capture")
    assert _negates("the name never appears in the strings")
    assert not _negates("[ev_0006] IOC strings chat.example")


def test_each_citation_is_read_by_the_clause_that_writes_it() -> None:
    for citation in ("ev_0201", "ev_0202", "ev_0203", "ev_0204", "net:1", "net:8"):
        assert _cited_for_an_absence(SAID, citation), citation
    # Cited for the strings it holds, in a sentence of its own.
    assert not _cited_for_an_absence(SAID, "ev_0006")
    # A negation in another clause of the same sentence governs nothing here.
    said = "Each is built by the constructor [ev_0177], and run by a routine which was not read."
    assert not _cited_for_an_absence(said, "ev_0177")
    # One id written inside a longer one is not that id.
    assert not _cited_for_an_absence("[ev_0201] net:10 (no match)", "net:1")


def _entry(entry_id: str, tool: str, output: str) -> LedgerEntry:
    return LedgerEntry(id=entry_id, tool=tool, args={}, output=output)


LEDGER = [
    _entry("ev_0006", "iocs_from_file", json.dumps({"iocs": [{"value": "chat.example"}]})),
    _entry("ev_0202", "pcap_summary", "1419 packets read."),
    _entry("ev_0203", "extract_dns", "1419 packets read.\nupdate.example.\n"),
    _entry("ev_0204", "extract_http", "1419 packets read.\nGET / HTTP/1.1 | Host: a.example\n"),
]


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
