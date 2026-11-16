"""A value taken from the file's text is confirmed only by an observation independent of that text.

A string row (a path, a registry key, a mutex) is published when a second
source holds it whole. What confirms it: a record of the sandbox or of
persistence, or an entry an analyst claim cites whose declaration says it
observes the sample or recovers the value (emulation, decoding, a transform
that ran a step, a kind that states ``observes``), or of a tool that declares
no kind, which is used at full strength and named in the reason. Another
declared kind — a decompile, a string search, a byte read, an extractor —
reads the file's text again and confirms nothing.

The decision is per entry and is recorded once at build time, so the IOC
table, the feed and the export read one record. A value the sweep cut out of
a longer token is confirmed only where an observation holds it as a whole
token of its own. Each refusal states its reason in its first clause.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.agents.run_evidence_corpus import RunEvidenceCorpus
from malspark.core.builtin_declarations import OBSERVING_KINDS
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.models import (
    DynamicBehavior,
    EmulatedStrings,
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    ProcessNode,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.renderers.stix_renderer import (
    ExtendedSTIXRenderer,
    confirmed_only_by_undeclared,
    corroborating_values,
    publish_answer,
    publishes,
    second_source_reads,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.tools.strings import iter_string_iocs

# This run's example: a runtime metric name the sweep cut out of its table.
RUNTIME_PATH = "/cpu/classes/total"
# A made-up value of another shape.
REGISTRY_KEY = "HKCU\\Software\\Vendor\\Relay\\State"


def _row(entry: str, tool: str, kind: str | None) -> EvidenceIndexRow:
    facts: dict[str, Any] = {"v": 1} if kind is None else {"v": 1, "kind": kind}
    return EvidenceIndexRow(id=entry, agent="static", tool=tool, source="mcp:example", facts=facts)


def _tool(tool: str, entries: list[str], *items: str) -> EvidenceSection:
    return EvidenceSection(
        key=f"tool_{tool}",
        title=tool,
        kind="list",
        items=list(items),
        evidence_ids=entries,
        source=f"tool:{tool}",
    )


def _finding(*entries: str) -> EvidenceSection:
    return EvidenceSection(
        key="findings",
        title="Findings",
        kind="table",
        columns=["Agent", "Finding"],
        rows=[["static", "the routine builds its working directory"]],
        evidence_ids=list(entries),
        source="finding",
    )


def _report(
    ioc: StringIOC,
    *sections: EvidenceSection,
    index: list[EvidenceIndexRow] | None = None,
    **over: Any,
) -> MalwareReport:
    return MalwareReport(
        verdict="Malware",
        overall_confidence=0.8,
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_name="sample.bin"),
        static=StaticAnalysis(interesting_strings=[ioc]),
        sections=list(sections),
        evidence_index=index or [],
        executive_summary="",
        **over,
    )


def _answer(report: MalwareReport, value: str) -> str:
    rows = [row for row in build_consolidated_iocs(report) if row.value == value]
    assert rows, value
    return str(rows[0].published)


def _exported(report: MalwareReport, value: str) -> bool:
    escaped = value.replace("\\", "\\\\")
    bundle = ExtendedSTIXRenderer().render(report)
    return any(
        escaped in str(getattr(obj, "pattern", ""))
        for obj in bundle.objects
        if getattr(obj, "type", "") == "indicator"
    )


def _held_by(kind: str | None, value: str, kind_of_row: str = "path") -> MalwareReport:
    return _report(
        StringIOC(kind=kind_of_row, value=value),  # type: ignore[arg-type]
        _tool("reader", ["ev_0040"], f'local_58 = "{value}"'),
        _finding("ev_0040"),
        index=[_row("ev_0040", "reader", kind)],
    )


class TestAnotherReadingOfTheBytesConfirmsNothing:
    @pytest.mark.parametrize(
        "kind", ["decompile", "decompile_batch", "listing", "string_search", "iocs_with_context"]
    )
    def test_a_cited_reading_holding_the_path_whole(self, kind: str) -> None:
        report = _held_by(kind, RUNTIME_PATH)

        answer = _answer(report, RUNTIME_PATH)
        assert not publishes(answer), answer
        assert "reads the file's text again" in answer

    def test_a_registry_key_a_listing_holds(self) -> None:
        report = _held_by("listing", REGISTRY_KEY, "registry")

        assert not publishes(_answer(report, REGISTRY_KEY))
        assert not _exported(report, REGISTRY_KEY)


class TestAnObservationConfirms:
    def test_a_cited_decoder_entry(self) -> None:
        report = _held_by("decoded_strings", REGISTRY_KEY, "registry")

        assert publishes(_answer(report, REGISTRY_KEY))
        assert _exported(report, REGISTRY_KEY)

    def test_a_cited_sandbox_entry(self) -> None:
        report = _held_by("sandbox_registry", REGISTRY_KEY, "registry")

        assert publishes(_answer(report, REGISTRY_KEY))

    def test_the_sandbox_s_own_record(self) -> None:
        report = _report(
            StringIOC(kind="registry", value=REGISTRY_KEY),
            dynamic=DynamicBehavior(
                process_tree=[
                    ProcessNode(pid=4, name="reg.exe", command_line=f"reg add {REGISTRY_KEY}")
                ]
            ),
        )

        assert publishes(_answer(report, REGISTRY_KEY))


class TestTheDecisionIsPerEntry:
    def _shared(self) -> MalwareReport:
        # One section of a decoder's two entries; the claim cites the first.
        return _report(
            StringIOC(kind="registry", value=REGISTRY_KEY),
            _tool("decoder", ["ev_0050", "ev_0051"], f"result: {REGISTRY_KEY}"),
            _finding("ev_0050"),
            index=[
                _row("ev_0050", "decoder", "decoded_strings"),
                _row("ev_0051", "decoder", "decoded_strings"),
            ],
        )

    def test_a_section_standing_on_an_entry_nobody_cited_confirms_nothing(self) -> None:
        report = self._shared()

        answer = _answer(report, REGISTRY_KEY)
        assert not publishes(answer), answer
        assert not _exported(report, REGISTRY_KEY)

    def test_the_corpus_is_read_entry_by_entry(self) -> None:
        report = self._shared()
        ledger = [
            LedgerEntry(id="ev_0050", agent="static", tool="decoder"),
            LedgerEntry(id="ev_0051", agent="static", tool="decoder"),
        ]
        uncited = RunEvidenceCorpus(1 << 20)
        uncited.remember("ev_0050", "decoder", "result: nothing printable")
        uncited.remember("ev_0051", "decoder", f"result: {REGISTRY_KEY}")
        cited = RunEvidenceCorpus(1 << 20)
        cited.remember("ev_0050", "decoder", f"result: {REGISTRY_KEY}")

        def answer(corpus: RunEvidenceCorpus) -> str:
            recorded = report.model_copy(
                update={"second_source_reads": second_source_reads(report, ledger, corpus)}
            )
            return publish_answer(
                "registry",
                REGISTRY_KEY,
                "strings",
                corroborating=corroborating_values(recorded),
            )

        assert not publishes(answer(uncited))
        assert publishes(answer(cited))

    def test_a_cited_reading_the_corpus_holds_confirms_nothing(self) -> None:
        report = _report(
            StringIOC(kind="registry", value=REGISTRY_KEY),
            _finding("ev_0070"),
            index=[_row("ev_0070", "reader", "listing")],
        )
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0070", "reader", f"bytes: {REGISTRY_KEY}")
        ledger = [LedgerEntry(id="ev_0070", agent="static", tool="reader")]
        report.second_source_reads = second_source_reads(report, ledger, corpus)

        answer = publish_answer(
            "registry", REGISTRY_KEY, "strings", corroborating=corroborating_values(report)
        )
        assert not publishes(answer), answer
        assert "reads the file's text again" in answer

    def test_a_section_citing_no_entry_confirms_nothing(self) -> None:
        report = _report(
            StringIOC(kind="registry", value=REGISTRY_KEY),
            _tool("sandbox_network", [], f"key {REGISTRY_KEY}"),
            _finding("ev_0090"),
        )

        assert not publishes(_answer(report, REGISTRY_KEY))

    def test_the_recovery_record_names_the_entry_value_by_value(self) -> None:
        """A section prints both entries as one; the recovery record says which recovered it."""

        def answer(entry: str) -> str:
            report = self._shared().model_copy(
                update={"emulated_strings": EmulatedStrings(values={"global\\relaylock7": entry})}
            )
            return publish_answer(
                "mutex",
                "Global\\RelayLock7",
                "strings",
                corroborating=corroborating_values(report),
            )

        assert publishes(answer("ev_0050"))
        assert not publishes(answer("ev_0051"))


class TestAToolThatDeclaresNoKind:
    """A tool that declares no kind is used at full strength: its cited entry confirms."""

    MUTEX = "Global\\RelayLock7"
    INSTALLED = "C:\\ProgramData\\Relay\\relay.exe"

    def test_an_undeclared_sandbox_s_mutex(self) -> None:
        report = _report(
            StringIOC(kind="mutex", value=self.MUTEX),
            _tool("my_sandbox", ["ev_0001"], f"mutex created: {self.MUTEX}"),
            _finding("ev_0001"),
            index=[_row("ev_0001", "my_sandbox", None)],
        )

        answer = _answer(report, self.MUTEX)
        assert publishes(answer), answer
        assert _exported(report, self.MUTEX)
        # Said, so an operator sees what an undeclared tool confirmed.
        assert "my_sandbox records it and declares no kind" in answer
        assert confirmed_only_by_undeclared(answer)

    def test_an_undeclared_decoder_s_path(self) -> None:
        report = _report(
            StringIOC(kind="path", value=self.INSTALLED),
            _tool("my_decoder", ["ev_0002"], f"decoded: {self.INSTALLED}"),
            _finding("ev_0002"),
            index=[_row("ev_0002", "my_decoder", None)],
        )

        answer = _answer(report, self.INSTALLED)
        assert publishes(answer), answer
        assert confirmed_only_by_undeclared(answer)

    def test_a_made_up_key_the_build_s_record_holds(self) -> None:
        report = _report(
            StringIOC(kind="registry", value=REGISTRY_KEY),
            _finding("ev_0003"),
            index=[_row("ev_0003", "watcher", None)],
        )
        ledger = [LedgerEntry(id="ev_0003", agent="dynamic", tool="watcher", output=REGISTRY_KEY)]
        report.second_source_reads = second_source_reads(report, ledger)

        answer = _answer(report, REGISTRY_KEY)
        assert publishes(answer), answer
        assert _exported(report, REGISTRY_KEY)
        assert confirmed_only_by_undeclared(answer)

    def test_an_observation_beside_it_is_said_as_an_observation(self) -> None:
        report = _report(
            StringIOC(kind="mutex", value=self.MUTEX),
            _tool("my_sandbox", ["ev_0004"], f"mutex created: {self.MUTEX}"),
            _finding("ev_0004"),
            index=[_row("ev_0004", "my_sandbox", None)],
            dynamic=DynamicBehavior(
                process_tree=[ProcessNode(pid=4, name="a.exe", command_line=f"a.exe {self.MUTEX}")]
            ),
        )

        answer = _answer(report, self.MUTEX)
        assert publishes(answer)
        assert not confirmed_only_by_undeclared(answer)

    def test_the_build_counts_what_an_undeclared_tool_alone_confirmed(self) -> None:
        report = MalwareReportBuilder(
            file_hash="e" * 64,
            file_name="sample.bin",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.8,
            evidence_ledger=[],
        ).build_deterministic()

        assert report.run_summary["undeclared_confirmations"] == 0

    def test_the_count_is_the_table_s_rows_only_an_undeclared_tool_confirmed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting import builder
        from malspark.reporting.models import ConsolidatedIOC

        alone = "watcher records it and declares no kind"
        rows = [
            ConsolidatedIOC(
                type="Mutex",
                kind="mutex",
                value="Global\\RelayLock7",
                published=f"yes: a second source in this run records it; {alone}",
            ),
            ConsolidatedIOC(
                type="Mutex",
                kind="mutex",
                value="Global\\Other",
                published="yes: a second source in this run records it",
            ),
        ]
        monkeypatch.setattr(builder, "build_consolidated_iocs", lambda _report: rows)
        report = MalwareReportBuilder(
            file_hash="e" * 64,
            file_name="sample.bin",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.8,
            evidence_ledger=[],
        ).build_deterministic()

        assert report.run_summary["undeclared_confirmations"] == 1

    def test_it_confirms_a_value_the_file_s_text_does_not_hold(self) -> None:
        """Full strength: what an undeclared sandbox or decoder reports still confirms."""
        report = _report(
            StringIOC(kind="path", value="C:\\Users\\Public\\other.dll"),
            _tool("watcher", ["ev_0060"], "created Global\\RelayLock7"),
            _finding("ev_0060"),
            index=[_row("ev_0060", "watcher", None)],
        )

        answer = publish_answer(
            "mutex",
            "Global\\RelayLock7",
            "strings",
            corroborating=corroborating_values(report),
        )
        assert publishes(answer), answer

    def test_one_named_as_a_code_listing_reads_the_file_again(self) -> None:
        """A tool its source declares nothing for is read as a decompiler where its name says so."""
        report = _report(
            StringIOC(kind="path", value="C:\\Users\\Public\\other.dll"),
            _tool("decompile_function", ["ev_0061"], "created Global\\RelayLock7"),
            _finding("ev_0061"),
            index=[_row("ev_0061", "decompile_function", None)],
        )

        answer = publish_answer(
            "mutex", "Global\\RelayLock7", "strings", corroborating=corroborating_values(report)
        )
        assert not publishes(answer), answer


class TestACutIsNoWholeValue:
    def test_a_switch_cut_from_a_command_the_sandbox_ran(self) -> None:
        """The sandbox ran ``del /f /q C:\\…``; ``/f /q C`` is not a path it touched."""
        command = "del /f /q C:\\ProgramData\\Vendor\\Support\\*.*"
        rows = [
            StringIOC(**{key: row[key] for key in row if key in StringIOC.model_fields})
            for row in iter_string_iocs(b"\x00" + command.encode() + b"\x00", cuts=True)
            if row["kind"] == "path" and row["value"] == "/f /q C"
        ]
        assert rows
        report = _report(
            rows[0],
            dynamic=DynamicBehavior(
                process_tree=[ProcessNode(pid=9, name="cmd.exe", command_line=f"cmd /c {command}")]
            ),
        )

        answer = _answer(report, "/f /q C")
        assert not publishes(answer), answer
        assert "cut out of" in answer


def _exported_with(report: MalwareReport, value: str, corpus: RunEvidenceCorpus) -> bool:
    escaped = value.replace("\\", "\\\\")
    bundle = ExtendedSTIXRenderer().render(report, corpus=corpus)
    return any(
        escaped in str(getattr(obj, "pattern", ""))
        for obj in bundle.objects
        if getattr(obj, "type", "") == "indicator"
    )


class TestEverySurfaceReadsOneRecord:
    """The IOC table, the feed and the export decide from the same per-entry record."""

    def _split(self, kind: str, value: str) -> tuple[MalwareReport, RunEvidenceCorpus]:
        # One sandbox section of two entries; the claim cites the first, which
        # holds the value, and the run's corpus holds each entry apart.
        report = _report(
            StringIOC(kind=kind, value=value),  # type: ignore[arg-type]
            _tool("sbx", ["ev_0101", "ev_0102"], f"created: {value}", "other"),
            _finding("ev_0101"),
            index=[
                _row("ev_0101", "sbx", "sandbox_report_section"),
                _row("ev_0102", "sbx", "sandbox_report_section"),
            ],
        )
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0101", "sbx", f"created: {value}")
        corpus.remember("ev_0102", "sbx", "other")
        return report, corpus

    @pytest.mark.parametrize(
        ("kind", "value"),
        [("mutex", "Global\\RelayLock7"), ("registry", REGISTRY_KEY)],
    )
    def test_the_table_and_the_export_answer_the_same(self, kind: str, value: str) -> None:
        report, corpus = self._split(kind, value)

        answer = _answer(report, value)
        assert publishes(answer) == _exported_with(report, value, corpus), answer

    def test_the_reason_is_true_of_a_section_with_a_cited_entry(self) -> None:
        report, _corpus = self._split("mutex", "Global\\RelayLock7")

        answer = _answer(report, "Global\\RelayLock7")
        # The entry that holds it is cited: the section prints it beside one that is not.
        assert "only in entries no analyst claim cites" not in answer, answer
        assert "beside an entry no analyst claim cites" in answer, answer

    def _recorded(
        self, kind: str, value: str, output: str, corpus: RunEvidenceCorpus | None
    ) -> MalwareReport:
        report, _corpus = self._split(kind, value)
        ledger = [
            LedgerEntry(id="ev_0101", agent="dynamic", tool="sbx", output=output),
            LedgerEntry(id="ev_0102", agent="dynamic", tool="sbx", output="other"),
        ]
        report.second_source_reads = second_source_reads(report, ledger, corpus)
        return report

    @pytest.mark.parametrize(
        ("kind", "value"),
        [("mutex", "Global\\RelayLock7"), ("registry", REGISTRY_KEY)],
    )
    def test_the_build_s_record_reads_the_cited_entry_on_its_own(
        self, kind: str, value: str
    ) -> None:
        report = self._recorded(kind, value, f"created: {value}", None)

        assert publishes(_answer(report, value))
        assert _exported_with(report, value, RunEvidenceCorpus(1 << 20))

    def test_an_answer_the_byte_budget_blanked_is_read_from_the_corpus(self) -> None:
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0101", "sbx", f"created: {REGISTRY_KEY}")

        blanked = self._recorded("registry", REGISTRY_KEY, "", corpus)
        unread = self._recorded("registry", REGISTRY_KEY, "", None)

        assert publishes(_answer(blanked, REGISTRY_KEY))
        assert _exported_with(blanked, REGISTRY_KEY, RunEvidenceCorpus(1 << 20))
        assert not publishes(_answer(unread, REGISTRY_KEY))
        # The export decides from the report's record, not from a corpus it is handed.
        assert not _exported_with(unread, REGISTRY_KEY, corpus)


class TestAnObservationOutranksACut:
    """A value the sandbox recorded whole is confirmed, though the file's copy is a cut."""

    INSTALLED = "C:\\ProgramData\\Relay\\relay.exe"

    @pytest.mark.parametrize(
        "token",
        [
            f"InstallPath={INSTALLED}",
            f"{INSTALLED},1",
            f'"{INSTALLED}">nul',
            f"{INSTALLED};C:\\Windows\\system32",
        ],
    )
    def test_a_path_the_sandbox_wrote(self, token: str) -> None:
        report = _report(
            StringIOC(kind="path", value=self.INSTALLED, cut_from=token),
            dynamic=DynamicBehavior(
                file_operations=[{"operation": "create", "path": self.INSTALLED}]
            ),
        )

        answer = _answer(report, self.INSTALLED)
        assert publishes(answer), answer

    def test_a_key_of_another_shape_a_process_set(self) -> None:
        key = "HKCU\\Software\\Vendor\\Relay\\Updater"
        report = _report(
            StringIOC(kind="registry", value=key, cut_from=f"{key}=1"),
            dynamic=DynamicBehavior(
                process_tree=[
                    ProcessNode(pid=7, name="reg.exe", command_line=f'reg add "{key}" /f')
                ]
            ),
        )

        assert publishes(_answer(report, key))

    def test_a_fragment_the_observation_holds_only_inside_a_longer_token(self) -> None:
        report = _report(
            StringIOC(kind="path", value="C:\\Relay\\run", cut_from="C:\\Relay\\run_old"),
            dynamic=DynamicBehavior(
                file_operations=[{"operation": "create", "path": "C:\\Relay\\run_old"}]
            ),
        )

        answer = _answer(report, "C:\\Relay\\run")
        assert not publishes(answer), answer
        assert "cut out of" in answer

    def test_the_build_s_record_asks_a_cited_entry_the_same(self) -> None:
        value = "C:\\Relay\\run"
        report = _report(
            StringIOC(kind="path", value=value, cut_from="C:\\Relay\\run_old"),
            _finding("ev_0110", "ev_0111"),
            index=[
                _row("ev_0110", "sbx", "sandbox_dropped_files"),
                _row("ev_0111", "sbx2", "sandbox_dropped_files"),
            ],
        )
        inside = [
            LedgerEntry(
                id="ev_0110", agent="dynamic", tool="sbx", output="InstallPath=C:\\Relay\\run"
            )
        ]
        whole = [LedgerEntry(id="ev_0111", agent="dynamic", tool="sbx2", output=f"wrote {value}")]

        def answer(ledger: list[LedgerEntry]) -> str:
            recorded = report.model_copy(
                update={"second_source_reads": second_source_reads(report, ledger)}
            )
            return _answer(recorded, value)

        assert not publishes(answer(inside))
        assert publishes(answer(whole))


def _recorded_by(
    kind_of_row: str, value: str, entry: LedgerEntry, facts: dict[str, Any]
) -> MalwareReport:
    """A report whose claim cites ``entry``, recorded by the build entry by entry."""
    report = _report(
        StringIOC(kind=kind_of_row, value=value),  # type: ignore[arg-type]
        _finding(entry.id),
        index=[
            EvidenceIndexRow(
                id=entry.id, agent="static", tool=entry.tool, source="mcp:example", facts=facts
            )
        ],
    )
    report.second_source_reads = second_source_reads(report, [entry])
    return report


class TestATransformWithStepsRecovers:
    """A transform that ran a step recovered the value; a byte read without one read it again."""

    def _entry(self, value: str, steps: list[dict[str, Any]]) -> LedgerEntry:
        return LedgerEntry(
            id="ev_0120",
            agent="static",
            tool="transform_bytes",
            args={"offset": 4096, "length": 64, "steps": steps},
            output=f'{{"output": {{"ascii": "{value}"}}}}'.replace("\\", "\\\\"),
            structured={"steps": [{"step": n + 1, **step} for n, step in enumerate(steps)]},
        )

    @pytest.mark.parametrize(
        ("kind", "value"),
        [("path", "C:\\ProgramData\\Relay\\relay.exe"), ("registry", REGISTRY_KEY)],
    )
    def test_a_cited_transform_with_a_step_confirms(self, kind: str, value: str) -> None:
        entry = self._entry(value, [{"op": "xor", "key": "5a"}])
        report = _recorded_by(kind, value, entry, {"v": 1, "kind": "transform"})

        answer = _answer(report, value)
        assert publishes(answer), answer

    def test_a_byte_read_without_a_step_confirms_nothing(self) -> None:
        value = "C:\\ProgramData\\Relay\\relay.exe"
        entry = self._entry(value, [])
        report = _recorded_by("path", value, entry, {"v": 1, "kind": "transform"})

        answer = _answer(report, value)
        assert not publishes(answer), answer
        assert "reads the file's text again" in answer


class TestObservingIsDeclared:
    """Whether a kind observes is a fact its declaration states, read where standing is decided."""

    def _entry(self, value: str) -> LedgerEntry:
        return LedgerEntry(id="ev_0130", agent="dynamic", tool="trace_it", output=f"saw {value}")

    @pytest.mark.parametrize(
        ("kind", "value"), [("mutex", "Global\\RelayLock7"), ("registry", REGISTRY_KEY)]
    )
    def test_a_made_up_kind_that_states_it_observes_confirms(self, kind: str, value: str) -> None:
        facts = {"v": 1, "kind": "kernel_trace", "observes": True}
        report = _recorded_by(kind, value, self._entry(value), facts)

        assert publishes(_answer(report, value))

    def test_the_same_kind_stating_nothing_reads_again(self) -> None:
        value = "Global\\RelayLock7"
        report = _recorded_by("mutex", value, self._entry(value), {"v": 1, "kind": "kernel_trace"})

        assert not publishes(_answer(report, value))

    def test_a_declaration_states_it(self) -> None:
        from malspark.core.tool_declarations import ToolFacts

        assert ToolFacts(kind="kernel_trace", observes=True).observes
        assert not ToolFacts(kind="kernel_trace").observes


class TestEachReasonStatesItselfFirst:
    """The composer is quoted a refusal's first clause: each new reason says itself there."""

    def test_a_cut_s_first_clause(self) -> None:
        token = "/opt/relay/bin/agent:" + "x" * 500
        report = _report(StringIOC(kind="path", value="/opt/relay/bin/agent", cut_from=token))

        answer = _answer(report, "/opt/relay/bin/agent")
        first, _, rest = answer.partition(";")
        assert first == "no: cut out of a longer string in the file, so not a whole value"
        # The token is quoted after it, bounded.
        assert rest.strip().startswith('the string reads "/opt/relay/bin/agent:xx')
        assert len(answer) < 200

    def test_a_reading_again_keeps_the_reason_the_composer_was_given(self) -> None:
        answer = _answer(_held_by("listing", RUNTIME_PATH), RUNTIME_PATH)

        assert answer.split(";", 1)[0] == "no: seen only in the file's strings"

    def test_an_undeclared_confirmation_keeps_the_published_reason_first(self) -> None:
        answer = _answer(_held_by(None, RUNTIME_PATH), RUNTIME_PATH)

        assert answer.split(";", 1)[0] == "yes: a second source in this run records it"


# The platform's own kinds that watch the sample or recover a value, named
# here so a kind dropped from the shipped declaration is missed by a test.
PLATFORM_OBSERVING = frozenset(
    {
        "sandbox_registry",
        "sandbox_mutexes",
        "pcap",
        "packet_overview",
        "dns",
        "http",
        "event_rules",
        "behaviour_code_links",
        "emulated_strings",
        "decoded_strings",
        "api_hash_resolution",
    }
)


class TestTheRecordIsAskedForWholeValues:
    def test_an_observation_holding_only_a_longer_value_confirms_nothing(self) -> None:
        report = _report(
            StringIOC(kind="mutex", value="Global\\RelayLock7"),
            dynamic=DynamicBehavior(
                process_tree=[
                    ProcessNode(pid=4, name="a.exe", command_line="a.exe Global\\RelayLock77")
                ]
            ),
        )

        assert not publishes(_answer(report, "Global\\RelayLock7"))

    @pytest.mark.parametrize("kind", sorted(OBSERVING_KINDS | PLATFORM_OBSERVING))
    def test_every_observing_kind_of_the_platform_confirms(self, kind: str) -> None:
        report = _held_by(kind, REGISTRY_KEY, "registry")

        assert publishes(_answer(report, REGISTRY_KEY)), kind


class TestThePlatformsOwnToolsAreReadByTheirShippedKind:
    """An entry of the platform's own server that stored no kind is read by the kind it ships."""

    def _report(
        self,
        tool: str,
        value: str,
        steps: list[dict[str, Any]] | None = None,
        *,
        source: str = "mcp:analysis",
        kind_of_row: str = "path",
    ) -> MalwareReport:
        entry = LedgerEntry(
            id="ev_0140",
            agent="static",
            tool=tool,
            source=source,
            facts={"v": 1, "kind": ""},
            args={"steps": steps} if steps is not None else {},
            output=f"text: {value}",
        )
        report = _report(
            StringIOC(kind=kind_of_row, value=value),  # type: ignore[arg-type]
            _finding("ev_0140"),
            index=[
                EvidenceIndexRow(
                    id="ev_0140",
                    agent="static",
                    tool=tool,
                    source=source,
                    facts={"v": 1, "kind": ""},
                )
            ],
        )
        report.second_source_reads = second_source_reads(report, [entry])
        return report

    def test_its_string_listing_reads_the_file_again(self) -> None:
        answer = _answer(self._report("strings", "C:\\Temp"), "C:\\Temp")

        assert not publishes(answer), answer

    def test_its_byte_read_without_a_step_reads_the_file_again(self) -> None:
        value = "/f /q C"
        assert not publishes(_answer(self._report("transform_bytes", value, []), value))

    def test_its_transform_with_a_step_recovers(self) -> None:
        value = "C:\\ProgramData\\Relay\\relay.exe"
        report = self._report("transform_bytes", value, [{"op": "xor", "key": "5a"}])

        assert publishes(_answer(report, value))

    def test_an_operator_s_server_that_declares_nothing_keeps_full_strength(self) -> None:
        report = _held_by(None, RUNTIME_PATH)

        assert publishes(_answer(report, RUNTIME_PATH))

    def test_an_operator_s_tool_named_as_a_platform_tool_keeps_full_strength(self) -> None:
        # Its server is not the platform's own: what the platform ships for a
        # tool of that name is never read for it.
        answer = _answer(self._report("strings", "C:\\Temp", source="mcp:example"), "C:\\Temp")

        assert publishes(answer), answer
        assert confirmed_only_by_undeclared(answer)

    def test_its_capture_s_answer_is_an_observation(self) -> None:
        mutex = "Global\\RelayLock7"
        report = self._report("extract_dns", mutex, source="mcp:network", kind_of_row="mutex")

        answer = _answer(report, mutex)
        assert publishes(answer), answer
        assert not confirmed_only_by_undeclared(answer)

    def test_a_name_two_servers_share_reads_each_server_s_own_kind(self) -> None:
        # The network server ships ``pcap_summary``, the analysis server ships
        # no tool of that name: there it is a tool the declarations do not
        # know, used at full strength and said as one.
        mutex = "Global\\RelayLock7"

        def answer(source: str) -> str:
            report = self._report("pcap_summary", mutex, source=source, kind_of_row="mutex")
            return _answer(report, mutex)

        assert publishes(answer("mcp:network"))
        assert not confirmed_only_by_undeclared(answer("mcp:network"))
        assert publishes(answer("mcp:analysis"))
        assert confirmed_only_by_undeclared(answer("mcp:analysis"))

    def test_each_kind_is_read_from_the_server_s_shipped_declaration(self) -> None:
        from malspark.core.declared_reading import own_server_kind

        assert own_server_kind("network", "pcap_summary") == "pcap"
        assert own_server_kind("analysis", "pcap_summary") == ""
        assert own_server_kind("analysis", "strings") == "strings"
        assert own_server_kind("example", "strings") == ""
        # A name its server's own prefix renamed is that server's tool; another prefix is not.
        assert own_server_kind("network", "network__pcap_summary") == "pcap"
        assert own_server_kind("analysis", "network__pcap_summary") == ""
        assert own_server_kind("network", "analysis__release_job") == ""
        assert own_server_kind("analysis", "analysis__strings") == "strings"
        # A server is named by its key as written.
        assert own_server_kind("Analysis", "strings") == ""
        assert own_server_kind(" analysis", "strings") == ""

    def test_a_tool_offered_renamed_is_read_by_the_name_it_recorded_as_declared(self) -> None:
        from malspark.reporting.tool_kinds import stored_platform_kind

        entry = {
            "source": "mcp:network",
            "tool": "dns_names",
            "facts": {"v": 1, "kind": "", "declared_name": "extract_dns"},
        }
        assert stored_platform_kind(entry) == "dns"
        assert stored_platform_kind({**entry, "source": "provider:network"}) == ""
        # Another server's prefix is not taken off: that is a tool of another server.
        other = {
            "source": "mcp:network",
            "tool": "analysis__pcap_summary",
            "facts": {"v": 1, "kind": ""},
        }
        assert stored_platform_kind(other) == ""


class TestABuiltRecordIsTheOnlyRecord:
    """A report carrying the build's per-entry record decides from it, never from its sections."""

    def test_a_section_the_record_does_not_hold_the_value_in_confirms_nothing(self) -> None:
        # The section prints the value; the build read the cited entry and
        # found it not there (its answer was blanked by the byte budget).
        value = "Global\\RelayLock7"
        report = _report(
            StringIOC(kind="mutex", value=value),
            _tool("sbx", ["ev_0150"], f"created: {value}"),
            _finding("ev_0150"),
            index=[_row("ev_0150", "sbx", "sandbox_report_section")],
        )
        assert publishes(_answer(report, value))

        ledger = [LedgerEntry(id="ev_0150", agent="dynamic", tool="sbx", output="")]
        report.second_source_reads = second_source_reads(report, ledger)

        assert not publishes(_answer(report, value))
