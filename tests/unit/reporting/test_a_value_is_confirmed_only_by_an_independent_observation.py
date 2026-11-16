"""A value taken from the file's text is confirmed only by an observation independent of that text.

A string row (a path, a registry key, a mutex) is published when a second
source holds it whole. Every reading of the same bytes used to count as one —
a decompile, a string search, a byte read, an extractor, a strings tool that
declares no kind — and so did an entry nobody cited when another entry of its
section was cited. Five path fragments of a language runtime and of a
deletion command were published that way, entered the STIX bundle and the
drafted rules.

What confirms such a value: a record of the sandbox or of persistence, or an
entry an analyst claim cites whose declared kind observes the sample or
recovers the value (emulation, decoding). Another declared kind reads the
file's text again and confirms nothing. A tool that declares no kind is used
at full strength, except for a value that stands as plain text in the string
sweep's record: its entry then reads the file's own text, and the refusal
says so, so an operator can declare the tool. The decision is per entry: a
section that stands on an entry nobody cited confirms nothing by its text,
and the run's corpus is read entry by entry where it has one. A value the
sweep cut out of a longer token is no whole value, whatever holds it.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.agents.run_evidence_corpus import RunEvidenceCorpus
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.models import (
    DynamicBehavior,
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
    corroborating_values,
    publish_answer,
    publishes,
)
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
        uncited = RunEvidenceCorpus(1 << 20)
        uncited.remember("ev_0050", "decoder", "result: nothing printable")
        uncited.remember("ev_0051", "decoder", f"result: {REGISTRY_KEY}")
        cited = RunEvidenceCorpus(1 << 20)
        cited.remember("ev_0050", "decoder", f"result: {REGISTRY_KEY}")

        def answer(corpus: RunEvidenceCorpus) -> str:
            return publish_answer(
                "registry",
                REGISTRY_KEY,
                "strings",
                corroborating=corroborating_values(report, corpus),
            )

        assert not publishes(answer(uncited))
        assert publishes(answer(cited))


class TestAToolThatDeclaresNoKind:
    def test_it_does_not_confirm_a_value_that_stands_as_plain_text(self) -> None:
        report = _held_by(None, RUNTIME_PATH)

        answer = _answer(report, RUNTIME_PATH)
        assert not publishes(answer), answer
        # Named, so an operator can declare the tool.
        assert "reader declares no kind" in answer

    def test_the_same_for_a_made_up_key(self) -> None:
        report = _held_by(None, REGISTRY_KEY, "registry")

        assert not publishes(_answer(report, REGISTRY_KEY))
        assert not _exported(report, REGISTRY_KEY)

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


class TestACutIsNoWholeValue:
    def test_a_switch_cut_from_a_command_the_sandbox_ran(self) -> None:
        """The sandbox ran ``del /f /q C:\\…``; ``/f /q C`` is not a path it touched."""
        command = "del /f /q C:\\ProgramData\\Vendor\\Support\\*.*"
        rows = [
            StringIOC(**{key: row[key] for key in row if key in StringIOC.model_fields})
            for row in iter_string_iocs(b"\x00" + command.encode() + b"\x00")
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
