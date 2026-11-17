"""The export, the IOC table and the feed read one publish decision.

A run exported two C2 names the judge read out of decoded strings while the
report's IOC section and ``/reports/{id}/iocs`` listed four hashes. The first
fix made both surfaces read the export, and the export did not ask the judge's
values the rule's second half: a certificate authority's host the judge copied
out of the strings table would have been published, fed and drafted an alert
for. Now the export asks every judge indicator the one publish rule — the judge
asserting a value is not a second source for it — and declines one the rule
refuses, with a record; the table and the feed ask the same rule of the same
values. The export is compared with the surfaces only as a consistency test.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.report_service import ioc_feed_rows
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.detection_signatures import build_detection_rules
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.renderers.stix_renderer import (
    UNPUBLISHED_VALUE_CODE,
    ExtendedSTIXRenderer,
    exported_indicator_values,
    indicator_publish_reason,
    publish_answer,
    publishes,
    rule_values,
)
from malspark.schemas.stix_models import Bundle

OBSERVED = "gate9.example.org"
SWEPT = "crl.example-authority.org"
SHA256 = "a" * 64
DROPPED = "b" * 64
FOREIGN = "d" * 64
# These reports are built without the build's search of the tool answers,
# so the refusal says only the answers such a report keeps were searched.
JUDGE_ONLY = (
    "no: named only by the judge's indicator; no tool answer this report keeps holds it, and "
    "no second source records it"
)


def _indicator(index: int, pattern: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--0f1e2d3c-4b5a-4968-8776-65544333221{index}",
        "name": f"judge indicator {index}",
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
        "valid_from": "2026-01-01T00:00:00Z",
    }


def _judge(*patterns: str) -> dict[str, Any]:
    return {"type": "bundle", "objects": [_indicator(i, p) for i, p in enumerate(patterns)]}


def _report(judge: dict[str, Any], **over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        malware_category="loader",
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn=OBSERVED, source="sandbox"),
                NetworkDomain(fqdn=SWEPT, source="strings"),
            ]
        ),
        judge_indicators=[
            JudgeIndicator(kind=v.kind, value=v.value, algorithm=v.algorithm)
            for v in exported_indicator_values(judge)
        ],
        **over,
    )


def _export(report: MalwareReport, judge: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    renderer = ExtendedSTIXRenderer()
    bundle = renderer.render(report, Bundle.model_validate(judge))
    return bundle.model_dump(mode="json"), renderer


def _row(report: MalwareReport, value: str) -> Any:
    (row,) = [r for r in build_consolidated_iocs(report) if r.value == value]
    return row


class TestAJudgeValueTheRuleRefuses:
    """sectigo-shaped: a host the judge copied out of the strings table."""

    def _setup(self) -> tuple[MalwareReport, dict[str, Any]]:
        judge = _judge(f"[domain-name:value = '{SWEPT}']")
        return _report(judge), judge

    def test_the_export_declines_it_with_a_record(self) -> None:
        report, judge = self._setup()
        exported, renderer = _export(report, judge)

        assert SWEPT not in str(exported)
        assert UNPUBLISHED_VALUE_CODE in [code for code, _why in renderer.declined]

    def test_the_table_prints_the_rule_s_refusal(self) -> None:
        report, _judge_bundle = self._setup()

        assert _row(report, SWEPT).published == "no: seen only in the file's strings"

    def test_the_feed_withholds_it(self) -> None:
        report, _judge_bundle = self._setup()

        out = ioc_feed_rows(report.model_dump(mode="json"))

        assert [row["published"] for row in out if row["value"] == SWEPT] == [False]

    def test_no_draft_alerts_on_it(self) -> None:
        report, judge = self._setup()
        report.stix_bundle_extended, _renderer = _export(report, judge)
        report.consolidated_iocs = build_consolidated_iocs(report)

        assert all(SWEPT not in rule.body for rule in build_detection_rules(report))

    def test_a_value_no_row_has_is_added_as_the_judge_s_refused_row(self) -> None:
        judge = _judge("[domain-name:value = 'only-judge.example.net']")
        report = _report(judge)

        row = _row(report, "only-judge.example.net")

        # The file's strings do not hold it: the judge's indicator is its only source.
        assert (row.source, row.published) == (
            "judge",
            JUDGE_ONLY,
        )

    def test_a_judge_value_the_file_s_strings_hold_is_said_to_be_seen_there(self) -> None:
        from malspark.reporting.models import StaticAnalysis, StringIOC

        judge = _judge("[domain-name:value = 'only-judge.example.net']")
        report = _report(
            judge,
            static=StaticAnalysis(
                interesting_strings=[StringIOC(kind="domain", value="only-judge.example.net")]
            ),
        )

        assert _row(report, "only-judge.example.net").published == (
            "no: seen only in the file's strings"
        )


class TestAJudgeValueTheRulePublishes:
    def test_everywhere(self) -> None:
        judge = _judge(f"[domain-name:value = '{OBSERVED}']")
        report = _report(judge)
        exported, renderer = _export(report, judge)

        assert OBSERVED in str(exported)
        assert publishes(_row(report, OBSERVED).published)
        assert not [code for code, _why in renderer.declined if code == UNPUBLISHED_VALUE_CODE]


class TestTheKindsTheRuleNowAnswers:
    def test_the_sample_s_own_hash_is_published(self) -> None:
        assert publishes(publish_answer("hash", SHA256, "identity"))

    def test_a_hash_no_second_source_records_is_not(self) -> None:
        judge = _judge(f"[file:hashes.'SHA-256' = '{FOREIGN}']")
        report = _report(judge)
        exported, renderer = _export(report, judge)

        assert FOREIGN not in str(exported)
        assert _row(report, FOREIGN).published == JUDGE_ONLY

    def test_a_hash_of_a_file_the_sandbox_saw_dropped_is(self) -> None:
        judge = _judge(f"[file:hashes.'SHA-256' = '{DROPPED}']")
        # The sample's process, staged under its digest, wrote the file the
        # judge names: the judge's keep of a row of its tree publishes it.
        dynamic = DynamicBehavior(
            process_tree=[{"pid": 1, "name": f"{SHA256}.exe"}],
            file_operations=[
                {"operation": "write", "path": "C:\\x\\a.bin", "sha256": DROPPED, "pid": 1}
            ],
        )
        report = _report(judge, dynamic=dynamic)
        exported, _renderer = _export(report, judge)

        assert DROPPED in str(exported)

    def test_a_truncated_digest_is_not(self) -> None:
        assert indicator_publish_reason("hash", "abc123", "identity") is None

    def test_a_command_line_is_never_published(self) -> None:
        judge = _judge("[process:command_line = 'cmd.exe /c example-tool --run']")
        report = _report(judge)
        exported, renderer = _export(report, judge)

        assert "example-tool" not in str(exported)
        assert publish_answer("command", "cmd.exe /c x", "judge").startswith(
            "no: a command line is not"
        )


class TestOneDecision:
    """The consistency test: what the export carries and what the table publishes agree."""

    @pytest.mark.parametrize(
        "patterns",
        [
            (f"[domain-name:value = '{OBSERVED}']", f"[domain-name:value = '{SWEPT}']"),
            (f"[file:hashes.'SHA-256' = '{SHA256}']", f"[file:hashes.'SHA-256' = '{FOREIGN}']"),
            ("[mutex:name = 'ExampleMarker']", f"[domain-name:value = '{OBSERVED}']"),
            ("[file:name = 'C:\\\\ProgramData\\\\relay.dat']",),
            (f"[domain-name:value IN ('{OBSERVED}', '{SWEPT}')]",),
            (f"[domain-name:value IN ('{OBSERVED}')]",),
            (f"[domain-name:value != '{SWEPT}']",),
            ("[process:command_line IN ('whoami /all')]",),
        ],
    )
    def test_the_export_and_the_table_agree(self, patterns: tuple[str, ...]) -> None:
        judge = _judge(*patterns)
        dynamic = DynamicBehavior(
            process_tree=[{"pid": 1, "name": "sample.exe"}],
            file_operations=[
                {"operation": "write", "path": "C:\\ProgramData\\relay.dat", "pid": 1}
            ],
        )
        report = _report(judge, dynamic=dynamic)
        exported, _renderer = _export(report, judge)
        report.stix_bundle_extended = exported
        table = build_consolidated_iocs(report)

        published = {(r.kind, r.value.lower()) for r in table if publishes(r.published)}
        carried = {(v.kind, v.value.lower()) for v in exported_indicator_values(exported)}
        judged = {(j.kind, j.value.lower()) for j in report.judge_indicators}
        # Every value any exported indicator names, whatever its operator.
        named = {
            (v.kind, v.value.lower())
            for obj in exported["objects"]
            if obj.get("type") == "indicator"
            for v in rule_values(str(obj.get("pattern") or ""))
        }

        # Every value the export carries is published in the table ...
        assert carried <= published
        assert named <= published
        # ... and every judge value the table publishes is in the export.
        assert (published & judged) <= carried


class TestEveryOperatorIsAskedTheRule:
    """An ``IN`` list, a ``!=`` or a ``>`` is declined as ``=`` is when the rule refuses it."""

    @pytest.mark.parametrize(
        "pattern",
        [
            f"[domain-name:value IN ('{SWEPT}')]",
            f"[domain-name:value IN ('{OBSERVED}', '{SWEPT}')]",
            f"[domain-name:value != '{SWEPT}']",
            "[ipv4-addr:value IN ('45.77.12.9')]",
            "[process:command_line IN ('whoami /all')]",
            "[process:command_line > 'whoami']",
        ],
    )
    def test_a_value_the_rule_refuses_is_declined_on_every_operator(self, pattern: str) -> None:
        judge = _judge(pattern)
        report = _report(judge)
        exported, renderer = _export(report, judge)

        assert pattern not in str(exported)
        assert UNPUBLISHED_VALUE_CODE in [code for code, _why in renderer.declined]
        # Each member of an ``IN`` list is a value the judge asserts and is listed
        # with the rule's answer; a ``!=`` or a ``>`` asserts none and lists nothing.
        listed = [indicator.value for indicator in report.judge_indicators]
        if " IN " in pattern:
            assert listed
            refused = [value for value in listed if value != OBSERVED]
            assert refused
            assert not any(publishes(_row(report, value).published) for value in refused)
        else:
            assert not listed

    def test_an_in_list_of_values_the_rule_publishes_is_carried(self) -> None:
        pattern = f"[domain-name:value IN ('{OBSERVED}')]"
        judge = _judge(pattern)
        report = _report(judge)
        exported, _renderer = _export(report, judge)

        assert pattern in str(exported)
        assert publishes(_row(report, OBSERVED).published)


class TestAStringPathIsAskedItsShapeByTheOneRule:
    """A path the string sweep read that a second source holds whole, without a listed extension.

    The export used to ask its shape and the table did not: the table published
    a source file's path a decompiler quoted back, and the export refused it.
    The shape is the one rule's question now, so both refuse it, with the reason.
    """

    PATH = "/opt/kit/notes.cfg"

    def _report(self, path: str) -> MalwareReport:
        from malspark.reporting.models import StaticAnalysis, StringIOC

        return _report(
            _judge(),
            static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=path)]),
            dynamic=DynamicBehavior(
                process_tree=[{"pid": 1, "name": "sample.exe", "command_line": path}]
            ),
        )

    def test_the_table_the_feed_and_the_export_refuse_it_alike(self) -> None:
        report = self._report(self.PATH)
        exported, _renderer = _export(report, _judge())

        assert _row(report, self.PATH).published == (
            "no: neither a listed file extension nor a system location, so not the shape of a "
            "file the sample uses"
        )
        assert [
            r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == self.PATH
        ] == [False]
        assert "notes.cfg" not in str(
            [obj for obj in exported["objects"] if obj.get("type") == "indicator"]
        )

    def test_a_path_of_a_listed_shape_is_published_by_all_three(self) -> None:
        path = "/opt/kit/stage.dat"
        report = self._report(path)
        exported, _renderer = _export(report, _judge())

        assert publishes(_row(report, path).published)
        assert [
            r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == path
        ] == [True]
        assert "stage.dat" in str(exported)


class TestNoSurfaceReadsTheCorpus:
    """A value held only in an entry's answer no section of the report keeps (T-713).

    The export used to read the run's in-memory corpus and the table did not,
    so a certificate subject's address in such an answer was in the bundle and
    refused by the feed. Neither reads it: both refuse it.
    """

    ADDRESS = "cert@issuer-example.com"

    def test_the_table_and_the_export_agree_with_the_corpus_given(self) -> None:
        from malspark.agents.run_evidence_corpus import RunEvidenceCorpus
        from malspark.reporting.models import StaticAnalysis, StringIOC

        report = _report(
            _judge(),
            static=StaticAnalysis(
                interesting_strings=[StringIOC(kind="email", value=self.ADDRESS)]
            ),
        )
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0007", "signing_info", f'{{"subject": "E={self.ADDRESS}"}}')

        exported = ExtendedSTIXRenderer().render(report, corpus=corpus).model_dump(mode="json")

        assert not publishes(_row(report, self.ADDRESS).published)
        assert self.ADDRESS not in str(exported)


class TestTheExportReadsTheRowAndAsksNothing:
    """A surface asking the rule itself would carry what the row withholds, or drop the rest."""

    def test_the_bundle_follows_the_row_not_the_rule(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from malspark.reporting import builder

        report = _report(_judge())
        table = builder.build_consolidated_iocs(report)
        # The row says no for a value the rule publishes, and yes for one it refuses.
        doctored = []
        for row in table:
            if row.value == OBSERVED:
                row = row.model_copy(
                    update={
                        "published": "no: withheld by the row",
                        "role": "listed",
                        "indicator_type": None,
                    }
                )
            elif row.value == SWEPT:
                row = row.model_copy(
                    update={
                        "published": "yes: published by the row",
                        "role": "indicator",
                        "indicator_type": "anomalous-activity",
                    }
                )
            doctored.append(row)
        monkeypatch.setattr(builder, "ioc_table", lambda *_a, **_k: doctored)

        exported, _renderer = _export(report, _judge())
        patterns = str(
            [o.get("pattern") for o in exported["objects"] if o.get("type") == "indicator"]
        )

        assert OBSERVED not in patterns
        assert SWEPT in patterns


class TestTheShapeQuestionBindsTheStringSweepOnly:
    """A path a sandbox watched the sample write is the sample's record, whatever its extension."""

    PATH = "/opt/kit/notes.cfg"

    def test_an_observed_path_without_a_listed_extension_stays_published(self) -> None:
        judge = _judge("[file:name = 'notes.cfg' AND file:parent_directory_ref.path = '/opt/kit']")
        report = _report(
            judge,
            # The sample's own process, staged under its digest, wrote it.
            dynamic=DynamicBehavior(
                process_tree=[{"pid": 1, "name": f"{SHA256}.exe"}],
                file_operations=[{"operation": "write", "path": self.PATH, "pid": 1}],
            ),
        )
        exported, _renderer = _export(report, judge)

        row = _row(report, self.PATH)
        assert (row.source, publishes(row.published)) == ("sandbox", True), row.published
        assert "notes.cfg" in str(
            [o.get("pattern") for o in exported["objects"] if o.get("type") == "indicator"]
        )


class TestTheNetworkRowsAreWrittenInTheNetworkBlocksOrder:
    def test_addresses_then_urls_then_names(self) -> None:
        from malspark.reporting.models import NetworkIP, NetworkURL

        flagged = {"source": "virustotal", "malicious": 9}
        report = _report(_judge())
        report.network = NetworkIOCs(
            domains=[NetworkDomain(fqdn=OBSERVED, source="sandbox")],
            ips=[NetworkIP(address="45.77.12.9", source="strings", reputation=flagged)],
            urls=[NetworkURL(url=f"https://{OBSERVED}/gate", source="sandbox")],
        )
        exported, _renderer = _export(report, _judge())

        kinds = [
            str(o["pattern"]).split(":", 1)[0].lstrip("[")
            for o in exported["objects"]
            if o.get("type") == "indicator" and not str(o["pattern"]).startswith("[file:")
        ]
        assert kinds == ["ipv4-addr", "url", "domain-name"]


class TestAValueOnlyTheJudgeRecordsIsTheJudgesIndicator:
    """A row the table holds because the judge named it is exported as the judge's own indicator."""

    def test_it_is_written_once_in_the_judge_s_spelling(self) -> None:
        judge = _judge("[mutex:name='runmark']")
        report = _report(
            judge,
            dynamic=DynamicBehavior(
                process_tree=[{"pid": 1, "name": "sample.exe", "command_line": "runmark"}]
            ),
        )
        # As the builder records them: each value with the type the judge gave it.
        report.judge_indicators = [
            JudgeIndicator(
                kind=v.kind,
                value=v.value,
                algorithm=v.algorithm,
                indicator_types=list(v.indicator_types),
            )
            for v in exported_indicator_values(judge)
        ]
        exported, _renderer = _export(report, judge)

        row = _row(report, "runmark")
        assert (row.source, publishes(row.published)) == ("judge", True), row.published
        assert row.indicator_type == "malicious-activity"
        naming = [
            o["pattern"]
            for o in exported["objects"]
            if o.get("type") == "indicator" and "runmark" in str(o.get("pattern"))
        ]
        assert naming == ["[mutex:name='runmark']"]


class TestTheShapeQuestionIsNotAskedOfAJudgesValue:
    """A value the judge names is not the string sweep's: its shape is not asked.

    The judge's file name, a second source holding it whole, is published on
    every surface as the judge's indicator; the same value held only in the
    file's text is the string sweep's, and its shape refuses it everywhere.
    """

    @pytest.mark.parametrize("value", ["/opt/relay/bin/agentd", "relay_agent"])
    def test_the_judge_s_value_is_published_everywhere(self, value: str) -> None:
        judge = _judge(f"[file:name = '{value}']")
        report = _report(
            judge,
            overall_confidence=0.9,
            dynamic=DynamicBehavior(
                process_tree=[{"pid": 1, "name": "s", "command_line": f"s {value}"}]
            ),
        )
        exported, _renderer = _export(report, judge)
        from malspark.reporting.misp import build_misp_attributes

        assert _row(report, value).published == "yes: a second source in this run records it"
        feed = [r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == value]
        assert feed == [True]
        misp = build_misp_attributes(report, build_consolidated_iocs(report), owner="r")
        assert any(a["value"] == value for a in misp)
        assert f"[file:name = '{value}']" in [
            o.get("pattern") for o in exported["objects"] if o.get("type") == "indicator"
        ]

    @pytest.mark.parametrize("value", ["/opt/relay/bin/agentd", "relay_agent"])
    def test_the_same_value_only_the_file_s_text_holds_is_refused_everywhere(
        self, value: str
    ) -> None:
        from malspark.reporting.models import StaticAnalysis, StringIOC

        report = _report(
            _judge(),
            overall_confidence=0.9,
            static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=value)]),
            dynamic=DynamicBehavior(
                process_tree=[{"pid": 1, "name": "s", "command_line": f"s {value}"}]
            ),
        )
        exported, _renderer = _export(report, _judge())

        assert not publishes(_row(report, value).published)
        feed = [r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == value]
        assert feed == [False]
        assert value not in str(
            [o.get("pattern") for o in exported["objects"] if o.get("type") == "indicator"]
        )


class TestAValueTheSweepAndTheJudgeBothHoldIsTheJudges:
    """The shape question binds a value the string sweep alone brought.

    The judge names a value the file's text holds too, and a second source in
    the run holds it whole: it is the judge's, published on every surface as
    the judge's own indicator, as on a run where the sweep never read it.
    """

    @pytest.mark.parametrize("value", ["/opt/relay/bin/agentd", "relay_agent", "Relay_Agent"])
    def test_it_is_published_everywhere_as_the_judge_s_indicator(self, value: str) -> None:
        from malspark.reporting.misp import build_misp_attributes
        from malspark.reporting.models import StaticAnalysis, StringIOC

        judge = _judge(f"[file:name = '{value}']")
        report = _report(
            judge,
            overall_confidence=0.9,
            static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=value)]),
            dynamic=DynamicBehavior(
                process_tree=[{"pid": 1, "name": "s", "command_line": f"s {value}"}]
            ),
        )
        report.judge_indicators = [
            JudgeIndicator(
                kind=v.kind,
                value=v.value,
                algorithm=v.algorithm,
                indicator_types=list(v.indicator_types),
            )
            for v in exported_indicator_values(judge)
        ]
        exported, _renderer = _export(report, judge)

        row = _row(report, value)
        assert row.published == "yes: a second source in this run records it"
        # Exported as the judge's indicator, so typed as the judge typed it.
        assert row.indicator_type == "malicious-activity"
        feed = [r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == value]
        assert feed == [True]
        misp = build_misp_attributes(report, build_consolidated_iocs(report), owner="r")
        assert any(a["value"] == value for a in misp)
        naming = [
            o.get("pattern")
            for o in exported["objects"]
            if o.get("type") == "indicator" and value.rsplit("/", 1)[-1] in str(o.get("pattern"))
        ]
        assert naming == [f"[file:name = '{value}']"]

    @pytest.mark.parametrize("value", ["/opt/relay/bin/agentd", "relay_agent"])
    def test_without_a_second_source_nothing_changes(self, value: str) -> None:
        from malspark.reporting.models import StaticAnalysis, StringIOC

        judge = _judge(f"[file:name = '{value}']")
        report = _report(
            judge,
            overall_confidence=0.9,
            static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=value)]),
        )
        exported, _renderer = _export(report, judge)

        assert not publishes(_row(report, value).published)
        assert value.rsplit("/", 1)[-1] not in str(
            [o.get("pattern") for o in exported["objects"] if o.get("type") == "indicator"]
        )


def test_a_network_value_the_judge_also_names_is_the_platform_s_indicator() -> None:
    """A name the network block records is written before the judge's indicator, as before."""
    from malspark.reporting.models import NetworkDomain

    judge = _judge("[domain-name:value = 'relay-c2.example.net']")
    report = _report(judge, overall_confidence=0.9)
    report.network = NetworkIOCs(
        domains=[
            NetworkDomain(
                fqdn="relay-c2.example.net",
                source="strings",
                reputation={"source": "virustotal", "malicious": 9},
            )
        ]
    )
    exported, _renderer = _export(report, judge)

    (named,) = [
        o["name"]
        for o in exported["objects"]
        if o.get("type") == "indicator" and "relay-c2" in str(o.get("pattern"))
    ]
    assert named == "Domain relay-c2.example.net"


# Ruling 18: "the judge names it" lifts the shape question and nothing else.
_RELAY = "C:\\ProgramData\\relay.dat"
_RELAY_PLATFORM = (
    "path C:\\ProgramData\\relay.dat",
    "[file:name = 'relay.dat' AND file:parent_directory_ref.path = 'C:\\\\ProgramData']",
)
_VERDICTS = [("Malware", 0.9), ("Suspicious", 0.9), ("Suspicious", None)]


def _both_hold(judge: dict[str, Any], verdict: str, confidence: float | None) -> MalwareReport:
    from malspark.reporting.models import StaticAnalysis, StringIOC

    report = _report(
        judge,
        overall_confidence=confidence,
        static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=_RELAY)]),
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": f"s.exe {_RELAY}"}]
        ),
    )
    report.verdict = verdict  # type: ignore[assignment]
    report.judge_indicators = [
        JudgeIndicator(
            kind=v.kind,
            value=v.value,
            algorithm=v.algorithm,
            indicator_types=list(v.indicator_types),
        )
        for v in exported_indicator_values(judge)
    ]
    return report


def _indicators_of(exported: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
    return [
        (o["name"], o["pattern"], o["indicator_types"])
        for o in exported["objects"]
        if o.get("type") == "indicator" and "relay" in str(o.get("pattern"))
    ]


class TestAValueTheJudgeNamesIsExportedAsBefore:
    """The bundle's objects, patterns and types for a value both hold are dev's."""

    @pytest.mark.parametrize(("verdict", "confidence"), _VERDICTS)
    def test_a_well_formed_judge_indicator_and_the_platform_s_both_stand(
        self, verdict: str, confidence: float | None
    ) -> None:
        judge = _judge(f"[file:name = '{_RELAY.replace(chr(92), chr(92) * 2)}']")
        report = _both_hold(judge, verdict, confidence)
        exported, _renderer = _export(report, judge)

        assert _indicators_of(exported) == [
            (*_RELAY_PLATFORM, ["anomalous-activity"]),
            (
                "judge indicator 0",
                "[file:name = 'C:\\\\ProgramData\\\\relay.dat']",
                ["malicious-activity"],
            ),
        ]
        assert _row(report, _RELAY).indicator_type == "anomalous-activity"

    @pytest.mark.parametrize(("verdict", "confidence"), _VERDICTS)
    def test_a_declined_judge_indicator_lends_no_type(
        self, verdict: str, confidence: float | None
    ) -> None:
        # Single backslashes: the grammar refuses the judge's pattern and the export declines it.
        judge = _judge(f"[file:name = '{_RELAY}']")
        report = _both_hold(judge, verdict, confidence)
        exported, _renderer = _export(report, judge)

        assert _indicators_of(exported) == [(*_RELAY_PLATFORM, ["anomalous-activity"])]
        assert _row(report, _RELAY).indicator_type == "anomalous-activity"


class TestTheJudgesValueIsTheSameKindAndText:
    def test_another_kind_with_the_same_text_lifts_no_shape_question(self) -> None:
        from malspark.reporting.models import StaticAnalysis, StringIOC

        judge = _judge("[mutex:name = 'relay_agent']")
        report = _report(
            judge,
            overall_confidence=0.9,
            static=StaticAnalysis(
                interesting_strings=[StringIOC(kind="path", value="relay_agent")]
            ),
            dynamic=DynamicBehavior(
                process_tree=[{"pid": 1, "name": "s", "command_line": "s relay_agent"}]
            ),
        )

        (row,) = [r for r in build_consolidated_iocs(report) if r.kind == "path"]
        assert not publishes(row.published), row.published


def test_a_network_row_the_judge_names_keeps_the_platform_s_type() -> None:
    from malspark.reporting.models import NetworkDomain

    judge = {
        "type": "bundle",
        "objects": [
            {
                **_indicator(0, "[domain-name:value = 'relay-c2.example.net']"),
                "indicator_types": ["compromised"],
            }
        ],
    }
    report = _report(judge, overall_confidence=0.9)
    report.judge_indicators = [
        JudgeIndicator(kind=v.kind, value=v.value, indicator_types=list(v.indicator_types))
        for v in exported_indicator_values(judge)
    ]
    report.network = NetworkIOCs(
        domains=[
            NetworkDomain(
                fqdn="relay-c2.example.net",
                source="strings",
                reputation={"source": "virustotal", "malicious": 9},
            )
        ]
    )

    assert _row(report, "relay-c2.example.net").indicator_type == "anomalous-activity"


def test_a_sweep_path_of_the_toolchain_s_shape_stays_refused_everywhere() -> None:
    from malspark.reporting.models import StaticAnalysis, StringIOC
    from malspark.reporting.renderers.stix_renderer import COMPILE_ARTIFACT_PATH

    path = "/usr/lib/gcc/x86_64-linux-gnu/12/librelay.so"
    report = _report(
        _judge(),
        overall_confidence=0.9,
        static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=path)]),
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s", "command_line": f"s {path}"}]
        ),
    )
    exported, _renderer = _export(report, _judge())

    assert _row(report, path).published == f"no: {COMPILE_ARTIFACT_PATH}"
    assert [r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == path] == [
        False
    ]
    assert "librelay" not in str(_indicators_of(exported))


def _recorded(judge: dict[str, Any]) -> list[JudgeIndicator]:
    """The judge's values as the builder records them (``exported_indicator_values``)."""
    return [
        JudgeIndicator(
            kind=v.kind,
            value=v.value,
            algorithm=v.algorithm,
            indicator_patterns=list(v.indicator_patterns),
            indicator_types=list(v.indicator_types),
        )
        for v in exported_indicator_values(judge)
    ]


def test_a_declined_judge_indicator_still_names_a_host_row() -> None:
    """Naming keeps the sandbox row, as before; the declined indicator lends it no type."""
    judge = _judge(f"[file:name = '{_RELAY}']")  # single backslashes: the grammar refuses it
    report = _report(
        judge,
        overall_confidence=0.9,
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": f"{SHA256}.exe"}],
            file_operations=[{"operation": "write", "path": _RELAY, "pid": 1}],
        ),
    )
    report.judge_indicators = _recorded(judge)
    exported, _renderer = _export(report, judge)
    from malspark.reporting.misp import build_misp_attributes

    row = _row(report, _RELAY)
    assert (row.source, publishes(row.published)) == ("sandbox", True), row.published
    assert row.indicator_type == "anomalous-activity"
    feed = [r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == _RELAY]
    assert feed == [True]
    misp = build_misp_attributes(report, build_consolidated_iocs(report), owner="r")
    assert any(a["value"] == _RELAY for a in misp)
    assert _indicators_of(exported) == [
        ("File path C:\\ProgramData\\relay.dat", _RELAY_PLATFORM[1], ["anomalous-activity"])
    ]


def test_a_sweep_path_a_declined_judge_indicator_names_is_as_before() -> None:
    """X5, as dev answered it: published on the judge's naming, and no object carries it."""
    from malspark.reporting.misp import build_misp_attributes

    value = "E:\\x\\agentd"
    judge = _judge(f"[file:name = '{value}']")  # single backslashes: the grammar refuses it
    report = _report(
        judge,
        overall_confidence=0.9,
        static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=value)]),
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": f"s.exe {value}"}]
        ),
    )
    report.judge_indicators = _recorded(judge)
    exported, _renderer = _export(report, judge)

    assert _row(report, value).published == "yes: a second source in this run records it"
    feed = [r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == value]
    assert feed == [True]
    misp = build_misp_attributes(report, build_consolidated_iocs(report), owner="r")
    assert any(a["value"] == value for a in misp)
    assert "agentd" not in str(
        [o.get("pattern") for o in exported["objects"] if o.get("type") == "indicator"]
    )


class TestADeclinedJudgeIndicatorLendsNoType:
    """It names its value, and lends no type, in either order."""

    DECLINED = f"[file:name = '{_RELAY}']"  # single backslashes: the grammar refuses it
    CARRIED = f"[file:name = '{_RELAY.replace(chr(92), chr(92) * 2)}']"

    @pytest.mark.parametrize("order", ["declined-first", "declined-second"])
    def test_the_type_is_the_carried_one_s(self, order: str) -> None:
        from malspark.reporting.models import ConsolidatedIOC
        from malspark.reporting.renderers.stix_renderer import carried_judge_type

        declined = {**_indicator(0, self.DECLINED), "indicator_types": ["compromised"]}
        carried = _indicator(1, self.CARRIED)
        objects = [declined, carried] if order == "declined-first" else [carried, declined]
        judge = {"type": "bundle", "objects": objects}
        report = _report(judge, overall_confidence=0.9)
        report.judge_indicators = _recorded(judge)
        row = ConsolidatedIOC(type="File path", kind="path", value=_RELAY, published="yes: x")

        (recorded,) = report.judge_indicators
        assert set(recorded.indicator_patterns) == {self.DECLINED, self.CARRIED}
        from malspark.reporting.renderers.stix_renderer import published_keys

        assert carried_judge_type(row, report, published_keys([row])) == "malicious-activity"


def test_a_host_row_is_written_after_the_judge_s_own_indicator() -> None:
    carved = "e" * 64
    # A file only the judge names, a second source holding it whole.
    judge = _judge(f"[file:name = '{_RELAY.replace(chr(92), chr(92) * 2)}']")
    report = _report(
        judge,
        overall_confidence=0.9,
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": f"s.exe {_RELAY}"}]
        ),
    )
    report.static = StaticAnalysis(
        embedded_resources=[{"id": "RCDATA/101", "carved": True, "sha256": carved}]
    )
    exported, _renderer = _export(report, judge)

    names = [o["name"] for o in exported["objects"] if o.get("type") == "indicator"]
    assert names.index("judge indicator 0") < next(
        i for i, n in enumerate(names) if carved[:12] in n
    )


def test_a_value_only_a_declined_one_value_judge_indicator_names_is_its_row() -> None:
    """The judge's statement about the value itself gives it a row, carried or not.

    Published by the evidence rule (a second source holds it), as before, and
    no object carries it: the platform mints none for a judge's row.
    """
    from malspark.reporting.misp import build_misp_attributes

    judge = _judge(f"[file:name = '{_RELAY}']")  # single backslashes: the grammar refuses it
    report = _report(
        judge,
        overall_confidence=0.9,
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": f"s.exe {_RELAY}"}]
        ),
    )
    report.judge_indicators = _recorded(judge)
    exported, _renderer = _export(report, judge)

    row = _row(report, _RELAY)
    assert (row.source, row.published) == ("judge", "yes: a second source in this run records it")
    assert [r["published"] for r in ioc_feed_rows(report.model_dump()) if r["value"] == _RELAY] == [
        True
    ]
    misp = build_misp_attributes(report, build_consolidated_iocs(report), owner="r")
    assert any(a["value"] == _RELAY for a in misp)
    assert _indicators_of(exported) == []


@pytest.mark.parametrize("joint", ["OR", "AND"])
def test_a_joint_judge_indicator_the_export_declines_gives_no_row(joint: str) -> None:
    """A joint statement is not a statement about each part (R8, R9)."""
    from malspark.reporting.misp import build_misp_attributes

    carried = _RELAY.replace(chr(92), chr(92) * 2)
    judge = _judge(
        f"[file:name = '{carried}'] {joint} [domain-name:value = 'nobody.example-c2.net']"
    )
    report = _report(
        judge,
        overall_confidence=0.9,
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": f"s.exe {_RELAY}"}]
        ),
    )
    report.judge_indicators = _recorded(judge)
    exported, _renderer = _export(report, judge)

    assert [r for r in build_consolidated_iocs(report) if r.value == _RELAY] == []
    assert [r for r in ioc_feed_rows(report.model_dump()) if r["value"] == _RELAY] == []
    misp = build_misp_attributes(report, build_consolidated_iocs(report), owner="r")
    assert not any(a["value"] == _RELAY for a in misp)
    assert _indicators_of(exported) == []


def test_a_file_named_with_its_directory_is_one_value_carried_or_not() -> None:
    """A file's name paired with its directory counts as one comparison (ii)."""
    # Single backslashes in the directory: the grammar refuses the pattern.
    judge = _judge(
        "[file:name = 'relay.dat' AND file:parent_directory_ref.path = 'C:\\ProgramData']"
    )
    report = _report(
        judge,
        overall_confidence=0.9,
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": f"s.exe {_RELAY}"}]
        ),
    )
    report.judge_indicators = _recorded(judge)

    assert _row(report, _RELAY).published == "yes: a second source in this run records it"


def test_a_shape_beside_a_value_the_export_declines_gives_no_row() -> None:
    """A ``LIKE`` beside the value: the export declines the indicator, and it names no one value."""
    judge = _judge("[mutex:name = 'relaymark' OR mutex:name LIKE '%relay%']")
    report = _report(
        judge,
        overall_confidence=0.9,
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": "relaymark"}]
        ),
    )
    report.judge_indicators = _recorded(judge)
    exported, renderer = _export(report, judge)

    assert [r for r in build_consolidated_iocs(report) if r.value == "relaymark"] == []
    assert "relaymark" not in str(
        [o.get("pattern") for o in exported["objects"] if o.get("type") == "indicator"]
    )


@pytest.mark.parametrize("confidence", [0.9, None])
def test_a_host_row_a_declined_judge_indicator_names_keeps_the_platform_s_type(
    confidence: float | None,
) -> None:
    """A Run key the judge names beside a ``MATCHES`` it is not carried for lends no type."""
    from malspark.reporting.models import PersistenceMechanism

    key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\relay"
    escaped = key.replace("\\", "\\\\")
    judge = _judge(
        f"[windows-registry-key:key = '{escaped}' OR windows-registry-key:key MATCHES '^HKCU']"
    )
    report = _report(
        judge,
        overall_confidence=confidence,
        persistence=[PersistenceMechanism(kind="registry_run", target=key, payload="relay.exe")],
    )
    report.verdict = "Suspicious"
    report.judge_indicators = _recorded(judge)
    exported, _renderer = _export(report, judge)

    row = _row(report, key)
    assert (row.source, publishes(row.published)) == ("persistence", True), row.published
    assert row.indicator_type == "anomalous-activity"
    assert [
        o["indicator_types"]
        for o in exported["objects"]
        if o.get("type") == "indicator" and "CurrentVersion" in str(o.get("pattern"))
    ] == [["anomalous-activity"]]


@pytest.mark.parametrize(
    ("pattern", "one"),
    [
        ("[file:name = 'x.exe']", True),
        ("[file:name IN ('x.exe')]", True),
        ("[file:name = 'x.exe' AND file:size > 10]", True),
        ("[file:name IN ('x.exe', 'y.exe')]", False),
        ("[file:name = 'x.exe' AND file:name != 'y.exe']", False),
        ("[file:name != 'x.exe']", False),
        ("[file:name > 'x.exe']", False),
    ],
)
def test_one_value_is_one_comparison_that_asserts_it(pattern: str, one: bool) -> None:
    from malspark.reporting.renderers.stix_renderer import names_one_value

    assert names_one_value(pattern) is one


@pytest.mark.parametrize("confidence", [0.9, None])
def test_a_host_value_a_carried_in_list_names_is_that_indicator(confidence: float | None) -> None:
    """Each member of a carried ``IN`` list is the judge's indicator; none is minted again."""
    second = "C:\\ProgramData\\b.dat"
    members = ", ".join(f"'{v.replace(chr(92), chr(92) * 2)}'" for v in (_RELAY, second))
    judge = _judge(f"[file:name IN ({members})]")
    report = _report(
        judge,
        overall_confidence=confidence,
        dynamic=DynamicBehavior(
            process_tree=[{"pid": 1, "name": f"{SHA256}.exe"}],
            file_operations=[
                {"operation": "write", "path": _RELAY, "pid": 1},
                {"operation": "write", "path": second, "pid": 1},
            ],
        ),
    )
    report.judge_indicators = _recorded(judge)
    exported, _renderer = _export(report, judge)

    assert [name for name, _pattern, _types in _indicators_of(exported)] == ["judge indicator 0"]
    for value in (_RELAY, second):
        row = _row(report, value)
        assert (row.source, publishes(row.published)) == ("sandbox", True), row.published
        assert row.indicator_type == "malicious-activity"
