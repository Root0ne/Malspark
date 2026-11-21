"""mitre.json describes each technique with the text the analyst report's ATT&CK table prints.

The description of a published technique is read off the same render that prints the
table: the words its procedure cell keeps after the agreement question's left-out step and
the flagged-statement gate, plain text, without the note markers, ``""`` where the row
prints ``-`` (T-727). Every surface that hands mitre.json out derives it from the report it
renders its report text from at that moment: the worker from the report it stores, ``/mitre``
from the served report, the enrichment write from the payload it writes, whose amendment
covers the column. A stored report that does not validate serves its stored column as stored.
Every comparison below is against the render, never against fixed state words.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.models.report import AnalysisReport
from app.services import audit_chain, ledger_chain
from app.services.report_service import ReportService
from app.worker.analysis_worker import _extract_mitre, _store_the_report
from app.worker.enrich_worker import enrichment_laid_over, write_under_lock
from malspark.core.config import Settings
from malspark.pipeline.validation import (
    PROCESS_WORDS_CODE,
    record_flagged_statements,
    unpublished_value_violations,
)
from malspark.reporting.models import (
    CapabilityCell,
    EvidenceSection,
    FlaggedStatement,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    TechnicalAnalysis,
    TechnicalSubsection,
    TechniqueProcedure,
    TTPMapping,
    key_ordered,
)
from malspark.reporting.narrative_agent import published_answers
from malspark.reporting.renderers import analyst as analyst_module
from malspark.reporting.renderers.layout import ANALYST
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.section_agreement import DROPPED_CODE, apply_rows, passages_of
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for
from tests.unit.reporting.test_the_analyst_report_prose_is_held_to_its_style import (
    _composed,
    _report,
)

CLAIM = "Encrypts each file with ChaCha20 [ev_0002]. Then renames it."
FIRST = "Encrypts each file with ChaCha20."
KEY = ledger_chain.derive_key("technique-description-test-material")
NOW = datetime(2026, 11, 21, 9, 0, tzinfo=UTC)

_MARKER = re.compile(r"\[\[\d+\]\]\(evidence-bundle\.html#cite-\d+\)")
_DEFANGED = {"[.]": ".", "[:]": ":", "[@]": "@", "hxxp": "http"}


def _base(**over: Any) -> MalwareReport:
    report = _report(**over)
    report.ttp_mappings = [
        TTPMapping(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="TA0040",
            tactic_name="Impact",
            evidence_quotes=[CLAIM],
        )
    ]
    return report


def _rendered(report: MalwareReport) -> str:
    return str(MarkdownRenderer(layout=ANALYST).render(report.model_copy(deep=True)))


def _raw_cell(markdown: str, technique_id: str) -> str:
    """The Procedure cell of the technique's row in section 10, before its status."""
    section = markdown.split("## 10. MITRE ATT&CK mapping", 1)[1].split("\n## ", 1)[0]
    row = next(line for line in section.splitlines() if f"| {technique_id} |" in line)
    cells = re.split(r"(?<!\\)\|", row.strip())[1:-1]
    procedure = cells[3].strip()
    status = procedure.find(" _(")
    return procedure[:status] if status >= 0 and procedure.endswith(")_") else procedure


def _cell(markdown: str, technique_id: str) -> str:
    """The cell's words as the page reads them: no note markers, no defang, ``""`` for ``-``."""
    words = _MARKER.sub("", _raw_cell(markdown, technique_id)).replace("\\|", "|")
    for written, read in _DEFANGED.items():
        words = words.replace(written, read)
    words = " ".join(words.split())
    return "" if words == "-" else words


def _description(report: MalwareReport | dict[str, Any], technique_id: str) -> str:
    document = report if isinstance(report, dict) else report.model_dump(mode="json")
    rows = _extract_mitre({"malware_report": document}) or []
    [row] = [r for r in rows if r["technique_id"] == technique_id]
    assert "description" in row, "the key is never left out"
    return str(row["description"])


def _left_out_by_the_round(report: MalwareReport) -> MalwareReport:
    """The claim's first sentence left out through the round's own code: a keep on a quote
    no check passes."""
    row = {
        "passage": "attack_claim.T1486",
        "sentence": FIRST,
        "decision": "keep",
        "sources": ["executive_summary"],
        "quote": "Routine 0x5b20 returns zero",
    }
    counts, _found = apply_rows({"sentences": [row]}, passages_of(report))
    assert counts["dropped"] == 1
    assert [f.left_out for f in report.flagged_statements] == [["attack_claim.T1486"]]
    return report


# ---------------------------------------------------------------------------
# The description is the cell
# ---------------------------------------------------------------------------


def test_the_description_is_the_cell_the_table_prints() -> None:
    report = _base()
    cell = _cell(_rendered(report), "T1486")
    assert cell
    assert _description(report, "T1486") == cell


def test_a_sentence_the_round_left_out_is_not_described() -> None:
    report = _left_out_by_the_round(_base())
    assert _raw_cell(_rendered(report), "T1486") == "-"
    # The claim's first sentence, which a reader without the left-out step would print, is
    # not the description: the row prints "-", so the description is empty.
    assert _description(report, "T1486") == ""
    assert _description(report, "T1486") != FIRST


def test_with_a_written_procedure_the_left_out_sentence_gives_way_to_it() -> None:
    procedures = [TechniqueProcedure(technique_id="T1486", procedure="Encrypts files.")]
    report = _left_out_by_the_round(
        _base(technical_analysis=TechnicalAnalysis(technique_procedures=procedures))
    )
    cell = _cell(_rendered(report), "T1486")
    assert cell
    assert FIRST not in cell
    assert _description(report, "T1486") == cell


def test_a_flagged_first_sentence_is_not_described() -> None:
    report = _base()
    report.flagged_statements = [
        FlaggedStatement(sentence=f"{FIRST[:-1]} [ev_0002].", code=PROCESS_WORDS_CODE, label="x")
    ]
    assert _raw_cell(_rendered(report), "T1486") == "-"
    assert _description(report, "T1486") == ""
    report.technical_analysis = TechnicalAnalysis(
        technique_procedures=[TechniqueProcedure(technique_id="T1486", procedure="Encrypts files.")]
    )
    cell = _cell(_rendered(report), "T1486")
    assert cell
    assert _description(report, "T1486") == cell


def test_a_procedure_the_round_left_out_is_not_described() -> None:
    report = _base(
        technical_analysis=TechnicalAnalysis(
            technique_procedures=[TechniqueProcedure(technique_id="T1486", procedure="")]
        )
    )
    report.run_summary = {
        "validation": {
            "unresolved": [
                {"code": DROPPED_CODE, "subject": "procedures.1", "message": "x", "agent": "x"}
            ]
        }
    }
    assert _raw_cell(_rendered(report), "T1486") == "-"
    assert _description(report, "T1486") == ""


def test_a_first_sentence_kept_over_the_written_procedure_is_the_description() -> None:
    """The second writing of the section keeps a first sentence naming a value printed
    nowhere else; the description follows that writing."""
    report = _composed(
        technique_procedures=[TechniqueProcedure(technique_id="T1486", procedure="Encrypts.")]
    )
    report.ttp_mappings[0].evidence_quotes = [CLAIM]
    cell = _cell(_rendered(report), "T1486")
    assert "ChaCha20" in cell
    assert _description(report, "T1486") == cell


def test_a_long_procedure_is_described_whole() -> None:
    long = "Encrypts " + ", ".join(f"folder{n:03d}" for n in range(80)) + " with ChaCha20."
    assert len(long) > 700
    report = _base(
        technical_analysis=TechnicalAnalysis(
            technique_procedures=[TechniqueProcedure(technique_id="T1486", procedure=long)]
        )
    )
    described = _description(report, "T1486")
    assert described == _cell(_rendered(report), "T1486") == long
    assert " | " not in described


# ---------------------------------------------------------------------------
# A value flagged as unpublished, before and after the enrichment publishes it
# ---------------------------------------------------------------------------

DOMAIN = "cdn-update-check.top"
BEACON = f"The sample beacons to {DOMAIN} over HTTPS every 60 seconds [ev_0002]."


def _beaconing() -> MalwareReport:
    cell = CapabilityCell(
        tactic="TA0011",
        tactic_name="Command and Control",
        technique_id="T1071.001",
        technique_name="Web Protocols",
        evidence=[BEACON],
    )
    mapping = TTPMapping(
        technique_id="T1071.001",
        technique_name="Web Protocols",
        tactic="TA0011",
        tactic_name="Command and Control",
        evidence_quotes=[BEACON],
    )
    report = _report(
        capability_matrix=[cell],
        ttp_mappings=[mapping],
        network=NetworkIOCs(domains=[NetworkDomain(fqdn=DOMAIN, source="strings")]),
    )
    record_flagged_statements(
        report, unpublished_value_violations({"body": BEACON}, published_answers(report))
    )
    assert report.flagged_statements
    return report


def _enriched(document: dict[str, Any]) -> dict[str, Any]:
    out = dict(document)
    network = dict(out["network"])
    network["domains"] = [
        {
            **row,
            "reputation": {"source": "reputation_provider", "malicious": 7, "harmless": 0},
            "is_suspicious": True,
        }
        for row in network["domains"]
    ]
    out["network"] = network
    return out


def _served(document: dict[str, Any]) -> MalwareReport:
    return MalwareReport.model_validate(key_ordered(document))


def test_a_sentence_flagged_for_an_unpublished_value_is_described_as_its_cell() -> None:
    report = _beaconing()
    cell = _cell(_rendered(report), "T1071.001")
    assert cell
    assert _description(report, "T1071.001") == cell


class _Session:
    def __init__(self, report: AnalysisReport) -> None:
        self.report = report

    async def get(self, *args: Any, **kwargs: Any) -> AnalysisReport:
        return self.report

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        return None

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def _sealed(document: dict[str, Any]) -> AnalysisReport:
    job_id = uuid.uuid4()
    report = AnalysisReport(
        job_id=job_id,
        verdict="Malware",
        malware_report=document,
        mitre_techniques=_extract_mitre({"malware_report": document}),
    )
    report.run_summary = {"evidence": {"entries": 1}}
    report.id = uuid.uuid4()
    seal = ledger_chain.seal(
        job_id,
        [],
        ledger_chain.genesis(job_id, KEY),
        report_sha256=ledger_chain.report_digest(report),
        sealed_at=NOW,
        key=KEY,
        report_id=report.id,
    )
    report.ledger_seal = seal
    report.malware_report = ledger_chain.with_seal(document, seal)
    report.run_summary = ledger_chain.with_seal(report.run_summary, seal)
    return report


async def _mitre(report: AnalysisReport) -> Any:
    service = ReportService(None)  # type: ignore[arg-type]

    async def _get(*_args: Any, **_kwargs: Any) -> AnalysisReport:
        return report

    service.get_report = _get  # type: ignore[method-assign]
    return await service.get_mitre_techniques(report.id, None)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_after_the_enrichment_publishes_the_value_every_surface_follows_the_served_cell(
    monkeypatch: Any,
) -> None:
    async def _append(db: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(audit_chain, "append", _append)
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    document = _beaconing().model_dump(mode="json")
    report = _sealed(document)
    built = report.mitre_techniques[0]["description"]
    assert built == _cell(_rendered(_served(document)), "T1071.001")

    enriched = _enriched(document)
    assert await write_under_lock(
        lambda: _Session(report),
        uuid.uuid4(),
        lambda stored, column: (enrichment_laid_over(stored, enriched), None),
    )
    served_cell = _cell(_rendered(_served(report.malware_report)), "T1071.001")
    assert served_cell != built, "the enrichment changed what the table prints"
    # The stored column follows the payload written, and the amendment covers it.
    assert report.mitre_techniques[0]["description"] == served_cell
    [record] = report.malware_report[ledger_chain.AMENDMENTS_KEY]
    assert record["report_sha256_after"] == ledger_chain.report_digest(report)
    # /mitre follows the served report.
    [row] = await _mitre(report)
    assert row["description"] == served_cell


@pytest.mark.asyncio
async def test_a_stored_column_older_than_its_report_is_served_as_the_served_cell() -> None:
    document = _beaconing().model_dump(mode="json")
    report = _sealed(document)
    report.mitre_techniques = [
        {**row, "description": "an earlier description | cut"} for row in report.mitre_techniques
    ]
    report.malware_report = _enriched(document)
    [row] = await _mitre(report)
    assert row["description"] == _cell(_rendered(_served(report.malware_report)), "T1071.001")


@pytest.mark.asyncio
async def test_a_stored_report_that_does_not_validate_serves_its_column_as_stored() -> None:
    stored = [{"technique_id": "T1486", "name": "x", "description": "as the build wrote it"}]
    report = AnalysisReport(
        job_id=uuid.uuid4(),
        malware_report={"ttp_mappings": [{"technique_id": "T1486"}]},
        mitre_techniques=stored,
    )
    report.id = uuid.uuid4()
    assert await _mitre(report) == stored


@pytest.mark.asyncio
async def test_a_column_the_stix_fallback_wrote_is_served_as_stored() -> None:
    stored = [{"technique_id": "T1055", "name": "x", "description": "the judge's description"}]
    document = _base().model_dump(mode="json")
    document["ttp_mappings"] = []
    report = AnalysisReport(job_id=uuid.uuid4(), malware_report=document, mitre_techniques=stored)
    report.id = uuid.uuid4()
    assert await _mitre(report) == stored


# ---------------------------------------------------------------------------
# The pack spelling of a recorded text
# ---------------------------------------------------------------------------


def _spelled(claim: str) -> MalwareReport:
    section = EvidenceSection(
        key="decoded_strings",
        title="Decoded strings",
        source="tool",
        kind="table",
        columns=["Text"],
        rows=[["C:\\Users\\Public\\"], ["\\\\files.corp-share.top\\drop\\"]],
        evidence_ids=["ev_0001"],
    )
    spec = {
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1547",
        "technique_name": "Boot or Logon Autostart Execution",
    }
    return _report(
        capability_matrix=[CapabilityCell(**spec, evidence=[claim])],
        ttp_mappings=[TTPMapping(**spec, evidence_quotes=[claim])],
        sections=[section],
    )


def test_a_pack_spelling_reads_as_the_recorded_text_in_the_cell_and_the_description() -> None:
    report = _spelled("Writes C:\\Users\\Public\\x5c as its folder [ev_0002].")
    raw = _raw_cell(_rendered(report), "T1547")
    described = _description(report, "T1547")
    assert "x5c" not in raw
    assert "x5c" not in described
    assert "C:\\Users\\Public\\" in described


def test_a_doubled_backslash_spelling_reads_the_same_in_the_cell_and_the_description() -> None:
    report = _spelled("Writes C:\\\\Users\\\\Public\\\\x5c as its folder [ev_0002].")
    raw = _raw_cell(_rendered(report), "T1547")
    described = _description(report, "T1547")
    assert "x5c" not in raw
    assert "x5c" not in described
    assert "C:\\\\Users\\\\Public\\\\" in raw
    assert "C:\\\\Users\\\\Public\\\\" in described


def test_a_spelling_the_defang_hides_from_the_cell_is_the_recorded_text_in_the_description() -> (
    None
):
    """The page defangs a host inside a path before it reads pack spellings, so the cell
    keeps the spelling; the description holds the recorded text, the truer of the two."""
    report = _spelled("Copies itself to \\\\files.corp-share.top\\drop\\x5c on start [ev_0002].")
    raw = _raw_cell(_rendered(report), "T1547")
    described = _description(report, "T1547")
    assert "x5c" in raw
    assert "\\\\files.corp-share.top\\drop\\ on start" in described
    assert "x5c" not in described


def _impact(claim: str) -> MalwareReport:
    report = _base()
    [mapping] = report.ttp_mappings
    mapping.evidence_quotes = [claim]
    report.capability_matrix = [
        CapabilityCell(
            tactic=mapping.tactic,
            tactic_name=mapping.tactic_name,
            technique_id=mapping.technique_id,
            technique_name=mapping.technique_name,
            evidence=[claim],
        )
    ]
    return report


def test_the_description_lists_every_caller_where_the_cell_shortens_the_callers() -> None:
    """The cell shortens the clause on a routine with no listed code to its first callers
    and a count; the description lists every caller, the truer of the two."""
    callers = ["0x402000", "0x403000", "0x404000", "0x405000", "0x406000"]
    clause = (
        f"the routine at 0x401000, called by the read routines at {', '.join(callers)}, "
        "has no listed code (decompiled or disassembled)"
    )
    report = _impact(f"Encrypts each file with ChaCha20 in {clause} [ev_0002].")
    ta = report.technical_analysis or TechnicalAnalysis()
    ta.payloads = TechnicalSubsection(
        title="Payloads", body=f"The payload encrypts files; {clause} [ev_0002]."
    )
    report.technical_analysis = ta
    raw = _raw_cell(_rendered(report), "T1486")
    described = _description(report, "T1486")
    assert "called by 5 read routines" in raw
    assert not all(caller in raw for caller in callers)
    assert f"called by the read routines at {', '.join(callers)}," in described


def test_the_description_keeps_a_group_of_bare_entry_ids_the_cell_prints_as_a_marker() -> None:
    """The cell prints a group of bare entry ids as a note marker; the description keeps
    the group as written."""
    report = _impact("Encrypts files read by get_file_report, ev_0002, ev_0003 with ChaCha20.")
    raw = _raw_cell(_rendered(report), "T1486")
    described = _description(report, "T1486")
    assert _MARKER.search(raw) and "ev_0003" not in raw
    assert described == "Encrypts files read by get_file_report, ev_0002, ev_0003 with ChaCha20."


# ---------------------------------------------------------------------------
# A writing or a render that raises
# ---------------------------------------------------------------------------


def _two_techniques() -> MalwareReport:
    specs = [
        ("TA0002", "Execution", "T1059.001", "PowerShell", "Runs powershell -enc AAAA [ev_0002]."),
        ("TA0040", "Impact", "T1486", "Data Encrypted for Impact", "Encrypts files [ev_0003]."),
    ]
    return _report(
        capability_matrix=[
            CapabilityCell(
                tactic=t, tactic_name=n, technique_id=tid, technique_name=name, evidence=[ev]
            )
            for t, n, tid, name, ev in specs
        ],
        ttp_mappings=[
            TTPMapping(
                technique_id=tid, technique_name=name, tactic=t, tactic_name=n, evidence_quotes=[ev]
            )
            for t, n, tid, name, ev in specs
        ],
    )


def test_a_table_section_that_raises_describes_no_technique(monkeypatch: Any) -> None:
    report = _two_techniques()
    original = analyst_module._Analyst._evidence
    calls = {"n": 0}

    def _raising(self: Any, row: Any) -> str:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("a later cell raises")
        return str(original(self, row))

    monkeypatch.setattr(analyst_module._Analyst, "_evidence", _raising)
    markdown = _rendered(report)
    assert "section 'analyst_attack' rendering failed" in markdown
    calls["n"] = 0
    rows = _extract_mitre({"malware_report": report.model_dump(mode="json")}) or []
    assert [row["description"] for row in rows] == ["", ""]


@pytest.mark.asyncio
async def test_a_render_that_raises_keeps_the_run_and_records_why(monkeypatch: Any) -> None:
    def _raising(_report: Any) -> dict[str, str]:
        raise RuntimeError("the render raised")

    monkeypatch.setattr(analyst_module, "printed_procedures", _raising)
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    async with factory() as db:
        report = await _store_the_report(
            db,
            job_uuid=job.id,
            job_id=str(job.id),
            pipeline_result={
                "evidence_ledger": [],
                "malware_report": _base().model_dump(mode="json"),
            },
            stix_bundle=None,
            run_summary={},
            transcript=[],
            core_settings=Settings(_env_file=None),
        )
    assert [row["description"] for row in report.mitre_techniques] == [""]
    [reason] = report.run_summary["degradation_reasons"]
    assert "RuntimeError" in reason
    assert "mitre.json" in reason


def test_every_store_reads_the_column_on_a_worker_thread_before_its_transaction() -> None:
    import inspect

    from app.worker import analysis_worker

    assert "asyncio.to_thread(_mitre_column" in inspect.getsource(analysis_worker._technique_column)
    source = inspect.getsource(analysis_worker)
    calls = [m.start() for m in re.finditer(r"await _store_the_report\(", source)]
    assert len(calls) == 3
    previous = 0
    for call in calls:
        opened = source.rindex("async with db_session() as db:", 0, call)
        assert source.find("await _technique_column(", previous, opened) >= 0
        assert "technique_column=" in source[call : source.index("\n            )", call)]
        previous = call


def test_a_report_that_publishes_no_technique_says_so_and_describes_none() -> None:
    report = _report(capability_matrix=[], ttp_mappings=[])
    assert "No ATT&CK technique is published in this run." in _rendered(report)
    assert _extract_mitre({"malware_report": report.model_dump(mode="json")}) is None
