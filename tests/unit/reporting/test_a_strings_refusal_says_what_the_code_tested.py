"""A value the string sweep holds and nothing admitted is refused with what the code tested.

The answer is built clause by clause, each naming a test and its result in the
record's own names, every finding the publish rule's. The first clause, one
refusing part, names the row the value is from (by the tool and the entry it
records, or by what it records where it records no entry) and what the deciding
test found: for a path, a key, a mutex or a mailbox, that the publish rule's
lookup found no second source; for a domain, an address or a URL, what the
publish rule read — a recovery of it, and a reputation record for it (one that
names its source or a count), said as given or not. It never says what the file
holds, what the run holds or what nobody cites. Each holder an analyst section
cites is a fact after it, by tool and entry id: on another row with its kind's
standing, on a network row with the plain fact that the publish rule does not
ask which entries hold a network value.

Each truth test reads the record the clause names (the ledger entry, the
analyst section's citations, the network row, the build's per-entry record),
never the function the sentence comes from. No decision changes: every answer
here refuses, as before.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.ledger_projection import static_from_ledger
from malspark.reporting.models import (
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkURL,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.publish_parts import answer_state, refusing_parts
from malspark.reporting.renderers.stix_renderer import publishes, second_source_reads
from malspark.schemas.evidence import LedgerEntry

PATH = "C:\\ProgramData\\Relay\\relay.cfg"
HOST = "relay-alpha.example.net"
URL = f"http://{HOST}/gate.php"
SWEEP = "ev_0006"


def _sweep(*rows: tuple[str, str], entry: str = SWEEP, kind: str = "file_iocs") -> LedgerEntry:
    tool = "iocs_from_file" if kind == "file_iocs" else "iocs_from_text"
    payload = {"iocs": [{"kind": k, "value": v} for k, v in rows]}
    return LedgerEntry(
        id=entry,
        agent="static",
        tool=tool,
        source="mcp:example",
        facts={"v": 1, "kind": kind},
        args={"text": " ".join(v for _k, v in rows)} if kind == "text_iocs" else {},
        output=json.dumps(payload),
        structured=payload,
    )


def _holder(entry: str, tool: str, kind: str, text: str) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        agent="static",
        tool=tool,
        source="mcp:example",
        facts={"v": 1, "kind": kind},
        output=text,
    )


def _index(entry: LedgerEntry) -> EvidenceIndexRow:
    return EvidenceIndexRow(
        id=entry.id, agent=entry.agent, tool=entry.tool, source=entry.source, facts=entry.facts
    )


def _finding(*entries: str) -> EvidenceSection:
    return EvidenceSection(
        key="findings",
        title="Findings",
        kind="table",
        columns=["Agent", "Finding"],
        rows=[["static", "the routine reads its configuration"]],
        evidence_ids=list(entries),
        source="finding",
    )


def _built(ledger: list[LedgerEntry], *, cited: tuple[str, ...] = (), **over: Any) -> MalwareReport:
    """A report as the build makes it: the sweep's rows projected from the ledger, each with
    its entry, and the per-entry record read entry by entry."""
    static = static_from_ledger(ledger) or StaticAnalysis()
    report = MalwareReport(
        verdict="Malware",
        overall_confidence=0.8,
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_name="sample.bin"),
        static=static,
        sections=[_finding(*cited)] if cited else [],
        evidence_index=[_index(entry) for entry in ledger],
        executive_summary="",
        **over,
    )
    report.second_source_reads = second_source_reads(report, ledger)
    return report


def _answer(report: MalwareReport, value: str) -> Any:
    (row,) = [row for row in build_consolidated_iocs(report) if row.value == value]
    assert not publishes(row.published), row.published
    return row.published


def _sweep_rows_of(report: MalwareReport, value: str) -> list[StringIOC]:
    assert report.static is not None
    return [row for row in report.static.interesting_strings if row.value == value]


def _entry_holds(ledger: list[LedgerEntry], entry: str, value: str) -> bool:
    (held,) = [item for item in ledger if item.id == entry]
    structured = held.structured if isinstance(held.structured, dict) else {}
    return value.lower() in (held.output or "").lower() or any(
        str(row.get("value")) == value
        for row in structured.get("iocs", [])
        if isinstance(row, dict)
    )


def _cites(report: MalwareReport, entry: str) -> bool:
    return any(
        entry in (section.evidence_ids or [])
        for section in report.sections
        if section.source in ("finding", "artifact")
    )


def _standing(report: MalwareReport, entry: str) -> str:
    (read,) = [read for read in report.second_source_reads or [] if read.entry == entry]
    return str(read.standing)


class TestTheFirstClauseNamesTheRowItIsFrom:
    def test_a_path_names_the_sweep_s_row_and_its_entry(self) -> None:
        ledger = [_sweep(("path", PATH))]
        report = _built(ledger)

        answer = _answer(report, PATH)

        parts = refusing_parts(answer)
        assert parts is not None
        (first,) = parts
        assert first == (
            "the row from iocs_from_file (ev_0006) holds it and the publish rule's lookup found "
            "no second source"
        )
        # True of the record it names: the row records ev_0006, whose answer holds the value.
        (row,) = _sweep_rows_of(report, PATH)
        assert row.entry == SWEEP and _entry_holds(ledger, SWEEP, PATH)
        assert "file's strings" not in str(answer)
        assert " only " not in str(answer)

    def test_a_row_from_an_extractor_fed_a_model_s_text_names_that_extractor(self) -> None:
        ledger = [_sweep(("path", PATH), entry="ev_0054", kind="text_iocs")]
        report = _built(ledger)

        answer = _answer(report, PATH)

        assert str(answer_state(answer)) == (
            "no: the row from iocs_from_text (ev_0054) holds it and the publish rule's lookup "
            "found no second source"
        )
        # The entry it names is an extractor's that read the text it was given.
        (row,) = _sweep_rows_of(report, PATH)
        (entry,) = ledger
        assert row.entry == entry.id and PATH in str(entry.args.get("text"))
        assert "file" not in str(answer) and "sweep" not in str(answer)

    def test_a_row_stored_before_its_entry_was_recorded_says_what_it_records(self) -> None:
        report = _built([])
        report.static = StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=PATH)])

        answer = _answer(report, PATH)

        assert str(answer) == (
            "no: its row records no entry and its source is strings and the publish rule's lookup "
            "found no second source"
        )
        (row,) = [row for row in build_consolidated_iocs(report) if row.value == PATH]
        assert row.source == "strings"
        assert _sweep_rows_of(report, PATH)[0].entry is None

    def test_the_first_clause_holds_no_semicolon_and_no_comma(self) -> None:
        for value, kind in ((PATH, "path"), (HOST, "domain"), (URL, "url")):
            report = _built([_sweep((kind, value))])
            for part in refusing_parts(_answer(report, value)) or ():
                assert ";" not in part and "," not in part, part


class TestANetworkRowSaysWhatTheNetworkRuleRead:
    def test_no_reputation_record_is_said_in_positive_terms(self) -> None:
        report = _built(
            [_sweep(("domain", HOST))],
            network=NetworkIOCs(domains=[NetworkDomain(fqdn=HOST, source="strings")]),
        )

        answer = _answer(report, HOST)

        assert str(answer_state(answer)) == (
            "no: the row from iocs_from_file (ev_0006) holds it and the publish rule found no "
            "recovery of it and read no reputation record for it"
        )
        # The network row the rule read carries no reputation record, and the run's
        # recovery record holds nothing.
        assert report.network is not None and report.network.domains[0].reputation is None
        assert report.emulated_strings is None
        assert "mark" not in str(answer)

    def test_a_reputation_record_given_is_named_with_its_result(self) -> None:
        reputation = {"malicious": 0, "suspicious": 0, "harmless": 60}
        report = _built(
            [_sweep(("url", URL))],
            network=NetworkIOCs(
                domains=[NetworkDomain(fqdn=HOST, source="strings", reputation=reputation)],
                urls=[NetworkURL(url=URL, source="strings")],
            ),
        )

        answer = _answer(report, URL)

        assert str(answer_state(answer)).endswith(
            "and the publish rule found no recovery of it and read a reputation record for its "
            "host with no malicious or suspicious count above zero"
        )
        assert report.network is not None
        given = report.network.domains[0].reputation or {}
        assert given["malicious"] == 0 and given["suspicious"] == 0

    def test_a_network_row_no_sweep_row_holds_says_its_row_s_source(self) -> None:
        report = _built(
            [], network=NetworkIOCs(domains=[NetworkDomain(fqdn=HOST, source="strings")])
        )

        answer = _answer(report, HOST)

        assert str(answer_state(answer)) == (
            "no: its row's source is strings and no row of the string sweep holds it and the "
            "publish rule found no recovery of it and read no reputation record for it"
        )
        # The record: no sweep row holds the value, and the network row's source is the sweep's.
        assert _sweep_rows_of(report, HOST) == []
        assert report.network is not None and report.network.domains[0].source == "strings"


class TestEachCitedHolderIsAFact:
    def test_a_cited_reading_of_the_bytes_is_named_with_its_entry_and_standing(self) -> None:
        holder = _holder("ev_0068", "batch_decompile", "decompile", f'path = "{PATH}"')
        ledger = [_sweep(("path", PATH)), holder]
        report = _built(ledger, cited=("ev_0068",))

        answer = _answer(report, PATH)

        assert answer.facts == (
            "batch_decompile (ev_0068) holds it in an entry an analyst section cites, of a kind "
            "the publish rule counts as confirming nothing",
        )
        assert _entry_holds(ledger, "ev_0068", PATH)
        assert _cites(report, "ev_0068")
        assert _standing(report, "ev_0068") == "rereads"
        assert "file's text again" not in str(answer)

    def test_an_entry_no_analyst_section_cites_is_not_named(self) -> None:
        uncited = _holder("ev_0055", "extract_iocs", "", f"{PATH}")
        report = _built([_sweep(("path", PATH)), uncited])

        answer = _answer(report, PATH)

        assert not _cites(report, "ev_0055")
        assert answer.facts == ()
        assert "ev_0055" not in str(answer) and "extract_iocs" not in str(answer)

    def test_a_cited_holder_of_a_reputation_kind_on_a_network_row(self) -> None:
        lookup = _holder(
            "ev_0028", "get_domain_report", "indicator_report", json.dumps({"domain": HOST})
        )
        ledger = [_sweep(("domain", HOST)), lookup]
        report = _built(
            ledger,
            cited=("ev_0028",),
            network=NetworkIOCs(domains=[NetworkDomain(fqdn=HOST, source="strings")]),
        )

        answer = _answer(report, HOST)

        assert answer.facts == (
            "get_domain_report (ev_0028) holds it in an entry an analyst section cites, and the "
            "publish rule does not ask which entries hold a network value",
        )
        assert "file's text" not in str(answer)
        # The first clause speaks of the reputation record the network rule was given:
        # the row carries none, whatever an analyst's lookup holds.
        assert str(answer_state(answer)).endswith("read no reputation record for it")
        assert report.network is not None and report.network.domains[0].reputation is None
        assert _cites(report, "ev_0028") and _standing(report, "ev_0028") == "rereads"

    @pytest.mark.parametrize(("tool", "kind"), [("extract_dns", "dns"), ("my_watcher", "")])
    def test_a_cited_observing_or_undeclared_holder_on_a_network_row(
        self, tool: str, kind: str
    ) -> None:
        watcher = _holder("ev_0053", tool, kind, f"query {HOST}")
        ledger = [_sweep(("domain", HOST), ("path", PATH)), watcher]
        report = _built(
            ledger,
            cited=("ev_0053",),
            network=NetworkIOCs(domains=[NetworkDomain(fqdn=HOST, source="strings")]),
        )

        answer = _answer(report, HOST)

        assert answer.facts == (
            f"{tool} (ev_0053) holds it in an entry an analyst section cites, and the publish rule "
            "does not ask which entries hold a network value",
        )
        assert _entry_holds(ledger, "ev_0053", HOST) and _cites(report, "ev_0053")
        assert _standing(report, "ev_0053") in ("observes", "undeclared")
        # What the network rule does not ask, the path rule does: the same cited entry
        # holding the path confirms it.
        holding_the_path = _holder("ev_0053", tool, kind, f"query {HOST} wrote {PATH}")
        path_report = _built(
            [_sweep(("domain", HOST), ("path", PATH)), holding_the_path], cited=("ev_0053",)
        )
        (row,) = [row for row in build_consolidated_iocs(path_report) if row.value == PATH]
        assert publishes(row.published)


class TestNothingDecidesDifferently:
    def test_the_holder_clauses_reach_no_state(self) -> None:
        holder = _holder("ev_0068", "batch_decompile", "decompile", PATH)
        report = _built([_sweep(("path", PATH)), holder], cited=("ev_0068",))

        answer = _answer(report, PATH)

        assert "batch_decompile" not in str(answer_state(answer))
        assert len(refusing_parts(answer) or ()) == 1

    def test_the_also_plain_form_says_no_absence(self) -> None:
        from malspark.reporting.renderers.stix_renderer import publish_answer

        answer = publish_answer("domain", HOST, "strings", also_plain="ev_0005")

        assert str(answer) == (
            "no: also a plain string in the file (ev_0005), so not a value the sample hid"
        )


class TestTheRecordNamedIsTheRecordRead:
    def test_an_entry_the_index_names_no_tool_for_stands_after_the_named(self) -> None:
        from malspark.reporting.renderers.stix_renderer import SecondSources, publish_answer

        swept = {PATH.lower(): (("", "ev_0009"), ("iocs_from_file", SWEEP))}
        answer = publish_answer("path", PATH, "strings", corroborating=SecondSources(swept=swept))

        assert str(answer) == (
            "no: the rows from iocs_from_file (ev_0006) and ev_0009 hold it and the publish "
            "rule's lookup found no second source"
        )

    @pytest.mark.parametrize("shell", [{}, {"harmless": 3}, {"source": ""}])
    def test_an_empty_reputation_shell_is_no_record(self, shell: dict[str, Any]) -> None:
        report = _built(
            [_sweep(("domain", HOST))],
            network=NetworkIOCs(
                domains=[NetworkDomain(fqdn=HOST, source="strings", reputation=shell)]
            ),
        )

        assert str(answer_state(_answer(report, HOST))).endswith(
            "found no recovery of it and read no reputation record for it"
        )

    def test_a_record_naming_its_source_is_a_record(self) -> None:
        report = _built(
            [_sweep(("domain", HOST))],
            network=NetworkIOCs(
                domains=[
                    NetworkDomain(fqdn=HOST, source="strings", reputation={"source": "provider"})
                ]
            ),
        )

        assert str(answer_state(_answer(report, HOST))).endswith(
            "read a reputation record for it with no malicious or suspicious count above zero"
        )

    def test_a_cited_section_on_a_network_row_is_named_without_a_kind_s_standing(self) -> None:
        # A report stored before the per-entry record: the cited section of a tool that
        # rereads the file is read from the sections, and the network rule asks it nothing.
        from malspark.reporting.renderers.stix_renderer import SecondSources, publish_answer

        record = SecondSources(
            swept={HOST: (("iocs_from_file", SWEEP),)},
            rereads=(("batch_decompile", f"host = {HOST}"),),
            uncited=(("strings", f"{HOST} beside"),),
        )
        answer = publish_answer("domain", HOST, "strings", corroborating=record)

        assert answer.facts == (
            "batch_decompile prints it in a section holding an entry an analyst section cites, "
            "and the publish rule does not ask which entries hold a network value",
            "strings prints it in a section holding an entry an analyst section cites beside "
            "one no analyst section cites, and the publish rule does not ask which entries hold "
            "a network value",
        )
        assert "confirming nothing" not in str(answer)
        # The same sections on a path keep their kind's standing.
        path = publish_answer(
            "path",
            PATH,
            "strings",
            corroborating=SecondSources(
                swept={PATH.lower(): (("iocs_from_file", SWEEP),)},
                rereads=(("batch_decompile", f'path = "{PATH.lower()}"'),),
            ),
        )
        assert path.facts == (
            "batch_decompile prints it in a section holding an entry an analyst section cites, of "
            "a kind the publish rule counts as confirming nothing",
        )


class TestANamedRestatementCarriesEachNegation:
    def test_a_restatement_dropping_one_of_two_negations_is_no_restatement(self) -> None:
        from malspark.pipeline.validation import _states_publish_state
        from malspark.reporting.publish_parts import refused

        state = (
            "the row from iocs_from_file (ev_0006) holds it and the publish rule found no "
            "recovery of it and read no reputation record for it"
        )
        answer = refused(state)
        wrong = state.replace("read no reputation record", "read a reputation record")

        assert _states_publish_state(f" (publish state: {state}) is a host.", answer)
        assert _states_publish_state(f" ({state}) is a host.", answer)
        assert not _states_publish_state(f" (publish state: {wrong}) is a host.", answer)
