"""A form row is exported as its form, with no suspicion flag or note on it (T-778).

A row of the file's strings that nothing in the run reads as its kind (a
*form row*, ``reporting.string_row_form``) prints its form in §9. The exports
say the same: ``/iocs`` (and the ``iocs.json`` written from it) and the
console's table carry the form as the row's ``kind`` and the printed form as
its ``type``, never ``email`` or ``domain``; the feed carries no suspicion
flag and no note on it, and a ``kind`` filter reads the exported kind. The
publish decision does not change, and the exports that publish (STIX, MISP,
the detection drafts) carry no form row before or after: they read the
table's own rows, whose kind stays the key of every lookup.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from app.services.report_service import ioc_feed_rows, with_current_iocs
from malspark.reporting.builder import ioc_table
from malspark.reporting.detection_signatures import build_detection_rules
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from malspark.reporting.string_row_form import (
    DOTTED_NAME,
    EXPORTED_FORM_KINDS,
    NAME_AT_DOMAIN_TEXT,
    NOT_A_PLAIN_HOST_BY_FORM,
    PATH_IN_A_LONGER_STRING,
    string_row_forms,
)

_DGA = "DGA-like (score 0.82: entropy 0.94, bigram-rarity 1.00)"


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        verdict="Malware",
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_name="sample.bin"),
        executive_summary="",
        **over,
    )


def _swept(**over: Any) -> MalwareReport:
    """Strings rows of every form, beside rows something in the run reads as their kind."""
    return _report(
        static=StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="email", value="aes128-gcm@openssh.com"),
                StringIOC(kind="domain", value="g59bq3uukp.j52keb9e.name"),
                StringIOC(kind="path", value="/lib/libx.so"),
                StringIOC(kind="path", value="/dd/yy", cut_from="MM/dd/yy"),
            ]
        ),
        network=NetworkIOCs(
            domains=[
                NetworkDomain(
                    fqdn="g59bq3uukp.j52keb9e.name",
                    source="strings",
                    is_suspicious=True,
                    reason=_DGA,
                    dga_score=0.82,
                ),
                NetworkDomain(fqdn="\\\\.\\pipe\\relay-share", source="strings"),
                NetworkDomain(
                    fqdn="qx7rk2vbn9.example-c2.net",
                    source="sandbox",
                    is_suspicious=True,
                    reason=_DGA,
                ),
            ]
        ),
        **over,
    )


def _feed(report: MalwareReport, kind: str | None = None) -> dict[str, dict[str, Any]]:
    return {row["value"]: row for row in ioc_feed_rows(report.model_dump(mode="json"), kind)}


def _section_9_types(report: MalwareReport) -> dict[str, str]:
    """Each §9 row's value and its printed Type cell."""
    markdown = MarkdownRenderer().render(report)
    start = markdown.index("## 9.")
    end = markdown.find("\n## ", start + 1)
    out: dict[str, str] = {}
    for line in markdown[start:end].splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[1].startswith("`"):
            value = cells[1].strip("`").replace("[.]", ".").replace("[@]", "@")
            out[value] = cells[0]
    return out


_FORMED = {
    "aes128-gcm@openssh.com": NAME_AT_DOMAIN_TEXT,
    "g59bq3uukp.j52keb9e.name": DOTTED_NAME,
    "\\\\.\\pipe\\relay-share": NOT_A_PLAIN_HOST_BY_FORM,
    "/dd/yy": PATH_IN_A_LONGER_STRING,
}


class TestTheFeedSaysTheForm:
    def test_each_form_row_is_served_under_its_form_kind_and_type(self) -> None:
        feed = _feed(_swept())
        for value, label in _FORMED.items():
            assert feed[value]["kind"] == EXPORTED_FORM_KINDS[label]
            assert feed[value]["type"] == label

    def test_the_exported_type_is_the_one_section_9_prints(self) -> None:
        report = _swept()
        printed = _section_9_types(report)
        feed = _feed(report)
        for value in _FORMED:
            assert feed[value]["type"] == printed[value]

    def test_a_form_row_carries_no_suspicion_flag_or_note(self) -> None:
        row = _feed(_swept())["g59bq3uukp.j52keb9e.name"]
        assert row["is_suspicious"] is False
        assert row["notes"] is None

    def test_a_row_the_run_reads_as_its_kind_keeps_kind_flag_and_note(self) -> None:
        feed = _feed(_swept())
        sandbox = feed["qx7rk2vbn9.example-c2.net"]
        assert (sandbox["kind"], sandbox["is_suspicious"], sandbox["notes"]) == (
            "domain",
            True,
            _DGA,
        )
        assert "type" not in sandbox
        whole = feed["/lib/libx.so"]
        assert whole["kind"] == "path" and "type" not in whole

    def test_every_other_field_and_the_publish_decision_are_as_before(self) -> None:
        report = _swept()
        table = {row.value: row for row in ioc_table(report)}
        for value, row in _feed(report).items():
            if value not in table:
                continue
            assert row["published"] is False or value not in _FORMED
            assert row["publish_answer"] == table[value].published
            assert row["source"] == table[value].source
            assert row["evidence_ids"] == list(table[value].evidence_ids)

    def test_a_kind_filter_reads_the_exported_kind(self) -> None:
        report = _swept()
        assert "g59bq3uukp.j52keb9e.name" not in _feed(report, "domain")
        assert "aes128-gcm@openssh.com" not in _feed(report, "email")
        assert "/dd/yy" not in _feed(report, "path")
        assert set(_feed(report, "dotted_name")) == {"g59bq3uukp.j52keb9e.name"}
        assert set(_feed(report, "path_shaped_text")) == {"/dd/yy"}
        assert "qx7rk2vbn9.example-c2.net" in _feed(report, "domain")

    def test_each_form_row_stands_on_the_sweep_s_record_alone(self) -> None:
        """Truth against the record: the row's value is a string the sweep typed by form,
        and no other reader in the run holds it under that kind."""
        report = _swept()
        swept = {(s.kind, s.value) for s in report.static.interesting_strings}
        swept |= {("domain", d.fqdn) for d in report.network.domains if d.source == "strings"}
        table = ioc_table(report)
        forms = string_row_forms(report, table)
        for row in table:
            if row.value not in _FORMED:
                continue
            assert row.source == "strings" and (row.kind, row.value) in swept
            assert not any(
                other.value == row.value and other.source != "strings" for other in table
            )
            assert forms
        assert len(forms) == len(_FORMED)

    def test_a_value_the_judge_names_keeps_its_kind_and_one_row(self) -> None:
        report = _swept(
            judge_indicators=[JudgeIndicator(kind="email", value="aes128-gcm@openssh.com")]
        )
        rows = [
            row
            for row in ioc_feed_rows(report.model_dump(mode="json"))
            if row["value"] == "aes128-gcm@openssh.com"
        ]
        assert [row["kind"] for row in rows] == ["email"]
        assert "type" not in rows[0]

    @pytest.mark.parametrize(
        ("kind", "value", "cut_from", "printed"),
        [
            ("path", "C:\\Users\\Public\\relay.exe", "x=C:\\Users\\Public\\relay.exe", "File path"),
            ("registry", "HKCU\\Software\\Relay\\Run", "zHKCU\\Software\\Relay\\Run", None),
        ],
    )
    def test_a_cut_value_the_judge_names_keeps_its_kind_on_every_edge(
        self, kind: str, value: str, cut_from: str, printed: str | None
    ) -> None:
        report = _report(
            static=StaticAnalysis(
                interesting_strings=[StringIOC(kind=kind, value=value, cut_from=cut_from)]
            ),
            judge_indicators=[JudgeIndicator(kind=kind, value=value)],
        )
        feed = [
            row for row in ioc_feed_rows(report.model_dump(mode="json")) if row["value"] == value
        ]
        assert [row["kind"] for row in feed] == [kind]
        assert "type" not in feed[0]
        assert value in _feed(report, kind)
        served, _note = with_current_iocs(report.model_dump(mode="json"), "r")
        rows = [row for row in served["consolidated_iocs"] if row["value"] == value]
        assert [row["kind"] for row in rows] == [kind]
        assert rows[0]["type"] not in EXPORTED_FORM_KINDS
        section_9 = MarkdownRenderer().render(report).split("## 9.", 1)[1].split("\n## ", 1)[0]
        assert PATH_IN_A_LONGER_STRING not in section_9
        assert "in a longer string" not in section_9
        if printed:
            assert _section_9_types(report)[value] == printed

    def test_no_value_is_served_under_two_kinds(self) -> None:
        values = [row["value"].lower() for row in ioc_feed_rows(_swept().model_dump(mode="json"))]
        assert len(values) == len(set(values))


class TestTheConsoleTableSaysTheForm:
    def test_the_served_table_carries_the_form_kind_type_and_no_network_mark(self) -> None:
        served, _note = with_current_iocs(_swept().model_dump(mode="json"), "r")
        rows = {row["value"]: row for row in served["consolidated_iocs"]}
        for value, label in _FORMED.items():
            assert rows[value]["kind"] == EXPORTED_FORM_KINDS[label]
            assert rows[value]["type"] == label
            assert rows[value]["is_network"] is False

    def test_every_other_served_row_is_the_table_s_own(self) -> None:
        report = _swept()
        served, _note = with_current_iocs(report.model_dump(mode="json"), "r")
        table = [row.model_dump(mode="json") for row in ioc_table(report)]
        assert len(served["consolidated_iocs"]) == len(table)
        for got, want in zip(served["consolidated_iocs"], table, strict=True):
            if want["value"] in _FORMED:
                keep = {"kind", "type", "is_network"}
                assert {k: v for k, v in got.items() if k not in keep} == {
                    k: v for k, v in want.items() if k not in keep
                }
            else:
                assert got == want

    def test_the_misp_attributes_are_built_from_the_table_s_own_rows(self) -> None:
        report = _swept()
        mr = report.model_dump(mode="json")
        mr["misp_attributes"] = None
        served, _note = with_current_iocs(mr, "r")
        assert served["misp_attributes"] == build_misp_attributes(
            report, ioc_table(report), owner="r"
        )


def _scored(**over: Any) -> MalwareReport:
    """A form row and a row the run reads as a domain, both with a generated-name note."""
    return _report(
        network=NetworkIOCs(
            domains=[
                NetworkDomain(
                    fqdn="g59bq3uukp.j52keb9e.name",
                    source="strings",
                    is_suspicious=True,
                    reason=_DGA,
                    dga_score=0.82,
                    queried_pids=[4242],
                ),
                NetworkDomain(fqdn="k3v9q.example.org", source="strings", dga_score=0.41),
                NetworkDomain(
                    fqdn="qx7rk2vbn9.example-c2.net",
                    source="sandbox",
                    is_suspicious=True,
                    reason=_DGA,
                    dga_score=0.82,
                ),
            ]
        ),
        **over,
    )


def _section_9_line(report: MalwareReport, value: str) -> str:
    markdown = MarkdownRenderer().render(report)
    section = markdown[markdown.index("## 9.") :]
    defanged = value.replace(".", "[.]")
    return next(line for line in section.splitlines() if f"`{defanged}`" in line)


class TestTheContextCellOfAFormRowSaysNoHostReading:
    def test_the_table_s_context_of_a_form_row_holds_no_generated_name_note_or_score(
        self,
    ) -> None:
        rows = {row.value: row for row in ioc_table(_scored())}
        for value in ("g59bq3uukp.j52keb9e.name", "k3v9q.example.org"):
            assert "DGA" not in rows[value].context
            assert "DGA" not in rows[value].description
        assert rows["g59bq3uukp.j52keb9e.name"].context == "queried by pid 4242"
        assert rows["k3v9q.example.org"].context == ""

    def test_a_row_the_run_reads_as_a_domain_keeps_its_note_and_score(self) -> None:
        rows = {row.value: row for row in ioc_table(_scored())}
        assert rows["qx7rk2vbn9.example-c2.net"].context == f"{_DGA}; DGA score 0.82"

    def test_a_judge_named_value_keeps_its_note_and_score(self) -> None:
        report = _scored(
            judge_indicators=[JudgeIndicator(kind="domain", value="g59bq3uukp.j52keb9e.name")]
        )
        rows = {row.value: row for row in ioc_table(report)}
        assert rows["g59bq3uukp.j52keb9e.name"].context == (
            f"{_DGA}; DGA score 0.82; queried by pid 4242"
        )

    def test_section_9_and_the_served_table_print_the_same_cell(self) -> None:
        report = _scored()
        line = _section_9_line(report, "g59bq3uukp.j52keb9e.name")
        assert "DGA" not in line and "queried by pid 4242" in line
        assert "DGA-like" in _section_9_line(report, "qx7rk2vbn9.example-c2.net")
        served, _note = with_current_iocs(report.model_dump(mode="json"), "r")
        context = {row["value"]: row["context"] for row in served["consolidated_iocs"]}
        assert context["g59bq3uukp.j52keb9e.name"] == "queried by pid 4242"
        assert context["k3v9q.example.org"] == ""
        assert context["qx7rk2vbn9.example-c2.net"] == f"{_DGA}; DGA score 0.82"

    def test_a_form_row_keeps_its_look_alike_target_and_resolved_addresses(self) -> None:
        report = _report(
            network=NetworkIOCs(
                domains=[
                    NetworkDomain(
                        fqdn="xn--pple-43d.com",
                        source="strings",
                        is_suspicious=True,
                        reason="look-alike of apple.com",
                        dga_score=0.5,
                        is_punycode=True,
                        homograph_target="apple.com",
                        resolved_ips=["203.0.113.7"],
                        queried_pids=[1234],
                    )
                ]
            )
        )
        cell = "punycode resembling apple.com; resolved to 203.0.113.7; queried by pid 1234"
        row = next(r for r in ioc_table(report) if r.value == "xn--pple-43d.com")
        assert row.context == cell and row.description == cell
        served, _note = with_current_iocs(report.model_dump(mode="json"), "r")
        served_row = next(
            r for r in served["consolidated_iocs"] if r["value"] == "xn--pple-43d.com"
        )
        assert served_row["kind"] == EXPORTED_FORM_KINDS[DOTTED_NAME]
        assert served_row["context"] == cell

    def test_every_row_is_kept_as_written_and_logged_when_the_forms_cannot_be_read(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        def unreadable(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("forms unreadable")

        monkeypatch.setattr("malspark.reporting.string_row_form.string_row_forms", unreadable)
        with caplog.at_level(logging.ERROR, logger="malspark"):
            rows = {row.value: row for row in ioc_table(_scored())}
        assert rows["g59bq3uukp.j52keb9e.name"].context == (
            f"{_DGA}; DGA score 0.82; queried by pid 4242"
        )
        assert rows["k3v9q.example.org"].context == "DGA score 0.41"
        assert rows["qx7rk2vbn9.example-c2.net"].context == f"{_DGA}; DGA score 0.82"
        assert "the IOC table's form rows could not be read" in caplog.text


class TestThePublishingExportsCarryNoFormRow:
    @pytest.fixture
    def report(self) -> MalwareReport:
        return _swept()

    def test_misp(self, report: MalwareReport) -> None:
        values = {a["value"] for a in build_misp_attributes(report, ioc_table(report), owner="r")}
        assert not values & set(_FORMED)

    def test_stix(self, report: MalwareReport) -> None:
        bundle = json.dumps(ExtendedSTIXRenderer().render(report).model_dump(mode="json"))
        assert not any(value in bundle for value in _FORMED if "\\" not in value)
        assert "relay-share" not in bundle

    def test_detection_drafts(self, report: MalwareReport) -> None:
        text = json.dumps([rule.model_dump(mode="json") for rule in build_detection_rules(report)])
        assert not any(value in text for value in _FORMED if "\\" not in value)
