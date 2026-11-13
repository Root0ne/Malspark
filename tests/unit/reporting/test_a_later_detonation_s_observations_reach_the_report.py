"""What a later detonation observed reaches the report, marked with the detonation and its launch.

The platform reads each further detonation as the pack reads the job's own
(``pipeline.detonations.platform_reads``). The ledger projection keeps those
reads and marks each network, signature, dropped-file and mutex row with
every detonation that observed it; the IOC table, the published techniques,
the Markdown and analyst reports, the STIX export, the MISP attributes and
the ATT&CK layer say it. A run with only the job's own detonation states no
mark anywhere, and dumps as it did.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline.detonations import platform_reads
from malspark.providers import sandbox_tools
from malspark.providers.detonation import DetonationRecord
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.detonation_marks import observed_words, with_technique_marks
from malspark.reporting.ledger_projection import dynamic_from_ledger, network_from_ledger
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    ObservedIn,
    SampleIdentity,
    TTPMapping,
)
from malspark.reporting.navigator_layer import build_layer
from malspark.reporting.renderers import MarkdownRenderer
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.sandbox_report import LINEAGE_KEY, LINEAGE_LAUNCHER, LINEAGE_REASON_KEY

ARGS = "-p hunter2"
D1_REPORT: dict[str, Any] = {
    "behavior": {"processes": [{"pid": 4, "process_name": "x.exe"}]},
    "network": {
        "dns": [{"request": "c2.example.net", "type": "A"}],
        "tcp": [{"dst": "192.0.2.10", "dport": 443, "pid": 4}],
    },
    "signatures": [{"name": "checks_debugger", "severity": 2}],
    "dropped": [{"name": "a.tmp", "filepath": "C:\\t\\a.tmp", "sha256": "a" * 64}],
}
D2_REPORT: dict[str, Any] = {
    "behavior": {"processes": [{"pid": 9, "process_name": "x.exe"}]},
    "network": {
        "dns": [
            {"request": "c2.example.net", "type": "A"},
            {"request": "pay.example.org", "type": "A"},
        ],
        "tcp": [{"dst": "198.51.100.7", "dport": 443, "pid": 9}],
    },
    "signatures": [
        {"name": "ransomware_files", "severity": 3, "ttp": ["T1486"]},
        {"name": "checks_debugger", "severity": 2},
    ],
    "dropped": [
        {"name": "README.txt", "filepath": "C:\\u\\README.txt", "sha256": "b" * 64},
        # A generated launcher's script, the platform's file: never a row.
        {
            "name": "launch.ps1",
            "filepath": "C:\\l\\launch.ps1",
            "sha256": "c" * 64,
            LINEAGE_KEY: LINEAGE_LAUNCHER,
            LINEAGE_REASON_KEY: "the launcher's own file",
        },
    ],
}
SHA256 = "6" * 64
D2_MARK = ObservedIn(detonation="d2", launched_with=ARGS)
D1_MARK = ObservedIn(detonation="d1")


class _Container:
    event_sink = None
    detonations: list[Any] = []


def _pack_entries(report: dict[str, Any], start: int) -> list[LedgerEntry]:
    """The pack's reads of the job's own detonation, read as the built-ins of their names."""
    views = (
        ("sandbox_network", sandbox_tools.sandbox_network),
        ("sandbox_signatures", sandbox_tools.sandbox_signatures),
        ("sandbox_dropped_files", sandbox_tools.sandbox_dropped_files),
    )
    return [
        LedgerEntry(
            id=f"ev_{start + n:04d}",
            tool=tool,
            agent="pipeline",
            output=json.dumps(view(report)),
            structured=view(report),
        )
        for n, (tool, view) in enumerate(views)
    ]


def _ledger(*, later: bool = True) -> list[LedgerEntry]:
    ledger = _pack_entries(D1_REPORT, 11)
    if later:
        record = DetonationRecord(
            ordinal=2,
            origin="agent",
            arguments=ARGS,
            report=D2_REPORT,
            requested_by=[{"agent": "reversing", "cited_entries": ["ev_0001"]}],
        )
        ledger += [
            LedgerEntry.model_validate(row) for row in platform_reads(_Container(), record, "")
        ]
    return ledger


def _report(ledger: list[LedgerEntry]) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        network=network_from_ledger(ledger),
        dynamic=dynamic_from_ledger(ledger),
        ttp_mappings=[
            TTPMapping(technique_id="T1486", technique_name="Data Encrypted for Impact"),
            TTPMapping(technique_id="T1027", technique_name="Obfuscated Files or Information"),
        ],
    )
    with_technique_marks(report.ttp_mappings, report)
    return report


class TestTheProjectionMarksEachRow:
    def test_a_value_only_the_later_detonation_saw_is_marked_with_it(self) -> None:
        network = network_from_ledger(_ledger())
        assert network is not None
        ips = {ip.address: ip for ip in network.ips}
        domains = {d.fqdn: d for d in network.domains}
        assert ips["198.51.100.7"].observed_in == [D2_MARK]
        assert domains["pay.example.org"].observed_in == [D2_MARK]
        assert ips["198.51.100.7"].source == "sandbox"

    def test_a_value_both_detonations_saw_carries_each(self) -> None:
        network = network_from_ledger(_ledger())
        assert network is not None
        domains = {d.fqdn: d for d in network.domains}
        assert domains["c2.example.net"].observed_in == [D1_MARK, D2_MARK]
        # A value only the job's own detonation saw states nothing.
        ips = {ip.address: ip for ip in network.ips}
        assert ips["192.0.2.10"].observed_in == []
        assert "observed_in" not in ips["192.0.2.10"].model_dump()

    def test_signatures_and_written_files_carry_their_detonation(self) -> None:
        dynamic = dynamic_from_ledger(_ledger())
        assert dynamic is not None
        signatures = {s.name: s for s in dynamic.sandbox_signatures}
        assert signatures["ransomware_files"].observed_in == [D2_MARK]
        assert signatures["checks_debugger"].observed_in == [D1_MARK, D2_MARK]
        written = {op.get("name"): op for op in dynamic.file_operations}
        assert written["README.txt"]["observed_in"] == [D2_MARK.model_dump()]
        assert "observed_in" not in written["a.tmp"]
        # The launcher's own file never enters the block.
        assert "launch.ps1" not in written
        assert not any("__observed__" in op for op in dynamic.file_operations)

    def test_a_technique_a_later_detonation_s_signature_tags_is_marked(self) -> None:
        report = _report(_ledger())
        marked = {m.technique_id: m.observed_in for m in report.ttp_mappings}
        assert marked == {"T1486": [D2_MARK], "T1027": []}


class TestEverySurfaceSaysIt:
    def test_the_ioc_table_marks_each_value_with_every_detonation_that_saw_it(self) -> None:
        rows = {row.value: row for row in build_consolidated_iocs(_report(_ledger()))}
        assert rows["198.51.100.7"].observed_in == [D2_MARK]
        assert rows["c2.example.net"].observed_in == [D1_MARK, D2_MARK]
        assert rows["b" * 64].observed_in == [D2_MARK]
        assert rows["192.0.2.10"].observed_in == []
        assert "observed_in" not in rows["192.0.2.10"].model_dump()

    def test_the_words_name_the_detonation_and_its_launch(self) -> None:
        assert observed_words([D2_MARK]) == f"observed in detonation 2, launched with `{ARGS}`"
        assert observed_words([D1_MARK, D2_MARK]) == (
            f"observed in the job's own detonation and in detonation 2, launched with `{ARGS}`"
        )
        assert observed_words([]) == ""

    def test_the_markdown_report_says_it(self) -> None:
        text = MarkdownRenderer().render(_report(_ledger()))
        assert f"observed in detonation 2, launched with `{ARGS}`" in text
        assert "observed in the job's own detonation and in detonation 2" in text

    def test_the_analyst_report_says_it(self) -> None:
        from malspark.reporting.renderers.layout import ANALYST

        text = MarkdownRenderer(layout=ANALYST).render(_report(_ledger()))
        assert f"observed in detonation 2, launched with `{ARGS}`" in text

    def test_the_misp_attributes_and_the_layer_say_it(self) -> None:
        report = _report(_ledger())
        table = build_consolidated_iocs(report)
        comments = [a["comment"] for a in build_misp_attributes(report, table, owner="unit")]
        technique = next(c for c in comments if c.startswith("ATT&CK technique"))
        assert technique.endswith(f"observed in detonation 2, launched with `{ARGS}`")
        layer = build_layer(report.model_dump(mode="json"))
        (t1486,) = [t for t in layer["techniques"] if t["techniqueID"] == "T1486"]
        assert {"name": "observed in", "value": f"detonation 2, launched with `{ARGS}`"} in (
            t1486["metadata"]
        )
        (t1027,) = [t for t in layer["techniques"] if t["techniqueID"] == "T1027"]
        assert all(m["name"] != "observed in" for m in t1027["metadata"])

    def test_the_stix_export_carries_it_on_the_indicator_and_the_technique_edge(self) -> None:
        from malspark.reporting.renderers.stix_renderer import (
            _pattern_id_for,
            _with_the_detonations,
        )
        from malspark.schemas.stix_models import Indicator, Relationship

        report = _report(_ledger())
        table = build_consolidated_iocs(report)
        indicator = Indicator(
            name="IP 198.51.100.7",
            pattern="[ipv4-addr:value = '198.51.100.7']",
            description="Published because x.",
        )
        plain = Indicator(name="IP 192.0.2.10", pattern="[ipv4-addr:value = '192.0.2.10']")
        uses = Relationship(
            relationship_type="uses",
            source_ref="malware--00000000-0000-4000-8000-000000000000",
            target_ref=_pattern_id_for("T1486"),
        )
        marked, unmarked, edge = _with_the_detonations([indicator, plain, uses], table, report)
        assert marked.x_malspark_observed_in == [{"detonation": "d2", "launched_with": ARGS}]
        assert marked.description == (
            f"Published because x. Observed in detonation 2, launched with `{ARGS}`."
        )
        assert unmarked is plain
        assert edge.x_malspark_observed_in == [{"detonation": "d2", "launched_with": ARGS}]


class TestOneDetonationReadsAsBefore:
    def test_no_row_and_no_export_states_a_mark(self) -> None:
        from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

        report = _report(_ledger(later=False))
        dumped = report.model_dump_json()
        assert "observed_in" not in dumped
        table = build_consolidated_iocs(report)
        assert all(not row.observed_in for row in table)
        assert "observed in" not in MarkdownRenderer().render(report)
        bundle = ExtendedSTIXRenderer().render(report).model_dump_json()
        assert "x_malspark_observed_in" not in bundle
        comments = [a["comment"] for a in build_misp_attributes(report, table, owner="unit")]
        assert not any("observed in" in c for c in comments)


class TestTheStixObjectsStatingAValueCarryTheMark:
    """An object stating a value a later detonation observed carries its indicator's mark."""

    def test_an_observable_and_the_observed_data_naming_it_are_marked(self) -> None:
        from malspark.reporting.renderers.stix_renderer import _with_the_detonations
        from malspark.schemas.stix_models import File, ObservedData, _Observable

        report = _report(_ledger())
        table = build_consolidated_iocs(report)
        domain = _Observable(type="domain-name", id="domain-name--1", value="pay.example.org")
        address = _Observable(type="ipv4-addr", id="ipv4-addr--2", value="192.0.2.10")
        dropped = File(hashes={"SHA-256": "b" * 64})
        seen = ObservedData(object_refs=[domain.id])
        quiet = ObservedData(object_refs=[address.id])
        out = _with_the_detonations([domain, address, dropped, seen, quiet], table, report)
        marked = {getattr(o, "id", ""): getattr(o, "x_malspark_observed_in", None) for o in out}
        mark = [{"detonation": "d2", "launched_with": ARGS}]
        assert marked[domain.id] == mark
        assert marked[dropped.id] == mark
        assert marked[seen.id] == mark
        # A value only the job's own detonation saw, and what names only it, carry none.
        assert marked[address.id] is None and marked[quiet.id] is None
