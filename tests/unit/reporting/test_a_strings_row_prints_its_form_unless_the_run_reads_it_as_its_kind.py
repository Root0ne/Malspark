"""A strings row prints its form unless something in the run reads it as its kind (T-778).

The string sweep types a token by its form: ``aes128-gcm@openssh.com`` is a
name@domain text, ``end.next`` a dotted name. A row of source ``strings``
that nothing in the run reads as its kind — not published, held by no row of
another source, named by no judge indicator, the host of no URL row, recovered
by no tool with a host's spelling — prints its form in §9 and in the strings
table, sits in its own §9 table after the network indicators, and is no
endpoint of the network figure. A path or registry row the extractor recorded
taking out of a longer string prints that it is text of that shape in a longer
string. Its kind stays the key of every lookup.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from malspark.reporting.builder import ioc_table
from malspark.reporting.figures import build_network_graph
from malspark.reporting.ledger_projection import (
    FORM_DEVICE,
    FORM_ESCAPED,
    FORM_LOCAL,
    FORM_OTHER,
    FORM_REGISTRY,
    FORM_SHARE,
    FORM_SLASHES,
    FORM_URL,
    FORM_VOLUME,
    path_or_host_form,
)
from malspark.reporting.models import (
    ConsolidatedIOC,
    DynamicBehavior,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkURL,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.renderers.markdown import FORM_ROWS_TITLE, MarkdownRenderer
from malspark.reporting.string_row_form import (
    DOTTED_NAME,
    NAME_AT_DOMAIN_TEXT,
    NOT_A_PLAIN_HOST_BY_FORM,
    PATH_IN_A_LONGER_STRING,
    REGISTRY_KEY_IN_A_LONGER_STRING,
    string_row_forms,
)
from malspark.tools.strings import iter_string_iocs

_SWEPT = "no: seen only in the file's strings"


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        verdict="Malware",
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_name="sample.bin"),
        executive_summary="",
        **over,
    )


def _row(kind: str, value: str, source: str = "strings", **over: Any) -> ConsolidatedIOC:
    fields: dict[str, Any] = {"published": _SWEPT, **over}
    return ConsolidatedIOC(type=kind.title(), kind=kind, value=value, source=source, **fields)


def _forms(rows: list[ConsolidatedIOC], **over: Any) -> dict[tuple[str, str], str]:
    return string_row_forms(_report(**over), rows)


class TestWhichRowIsAFormRow:
    def test_a_name_at_domain_text_nothing_reads_is_a_form_row(self) -> None:
        rows = [_row("email", "aes128-gcm@openssh.com")]
        assert _forms(rows) == {("email", "aes128-gcm@openssh.com"): NAME_AT_DOMAIN_TEXT}

    def test_a_dotted_name_nothing_reads_is_a_form_row(self) -> None:
        assert _forms([_row("domain", "end.next")]) == {("domain", "end.next"): DOTTED_NAME}

    # One value or more per form the form reader returns. Only the plain form
    # is a dotted name; every other form holds a character no plain host name
    # holds, and its label says that and nothing of whether it names a host.
    _FORMS = (
        ("\\\\.\\pipe\\relay-share", FORM_DEVICE),
        ("\\\\?\\C:\\relay\\x.dat", FORM_VOLUME),
        ("C:\\relay\\x.dat", FORM_VOLUME),
        ("\\relay\\x.dat", FORM_LOCAL),
        ("%APPDATA%\\relay.dat", FORM_LOCAL),
        ("~/relay.dat", FORM_LOCAL),
        ("./relay.dat", FORM_LOCAL),
        ("HKLM\\Software\\relay.dat", FORM_REGISTRY),
        ("\\\\srv\\share\\file.txt", FORM_SHARE),
        ("\\\\?\\UNC\\srv.corp\\s", FORM_SHARE),
        ("//cdn.example.com/x", FORM_SLASHES),
        ("http:\\\\relay.example.net\\a", FORM_URL),
        ("file:\\\\\\C:\\x.dll", FORM_URL),
        ("relay\\.example\\.net", FORM_ESCAPED),
        ("HKEY_USERS\\.DEFAULT", FORM_ESCAPED),
        ("C:\\.ssh", FORM_ESCAPED),
        ("~\\.ssh", FORM_ESCAPED),
        ("end.next", FORM_OTHER),
    )

    @pytest.mark.parametrize(("value", "form"), _FORMS)
    def test_each_form_prints_the_label_true_of_it(self, value: str, form: str) -> None:
        assert path_or_host_form(value).form == form
        [label] = _forms([_row("domain", value)]).values()
        plain = re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", value) is not None
        if form == FORM_OTHER:
            # Labels of letters, digits and hyphens joined by dots: a dotted name.
            assert label == DOTTED_NAME and plain
        else:
            # A backslash, a slash, a colon, a percent sign or a tilde: no
            # plain host name holds one, so the text is none.
            assert label == NOT_A_PLAIN_HOST_BY_FORM and not plain

    def test_a_published_row_keeps_its_kind(self) -> None:
        rows = [_row("domain", "c2.example.net", published="yes: recovered by emulation")]
        assert _forms(rows) == {}

    def test_a_row_another_source_holds_keeps_its_kind(self) -> None:
        rows = [_row("domain", "relay.example.net"), _row("domain", "relay.example.net", "sandbox")]
        assert _forms(rows) == {}

    def test_another_source_s_host_with_a_port_is_the_same_host(self) -> None:
        rows = [
            _row("domain", "relay.example.net"),
            _row("domain", "relay.example.net:8080", "sandbox"),
        ]
        assert _forms(rows) == {}

    def test_the_host_of_a_url_row_keeps_its_kind(self) -> None:
        rows = [_row("domain", "relay.example.net"), _row("url", "https://Relay.example.net/a")]
        assert _forms(rows) == {}

    @pytest.mark.parametrize(
        ("url", "judged"),
        [
            ("//relay.example-c2.top/gate.php", True),
            ("https://relay.example-c2.top/a", False),
            ("relay.example-c2.top/gate.php", False),
            ("relay.example-c2.top/gate.php", True),
            ("mailto:ops@relay.example-c2.top", False),
            ("evil.net\\@relay.example-c2.top", False),
            ("http:\\\\relay.example-c2.top\\a", False),
        ],
    )
    def test_a_url_holds_the_domain_exactly_when_the_platform_reads_it_as_the_host(
        self, url: str, judged: bool
    ) -> None:
        from malspark.extractors.network_extractor import url_host
        from malspark.reporting.builder import ioc_table

        domain = "relay.example-c2.top"
        report = _report(
            network=NetworkIOCs(
                domains=[
                    NetworkDomain(fqdn=domain, source="strings"),
                    NetworkDomain(fqdn="seen.example.org", source="sandbox"),
                ],
                urls=[] if judged else [NetworkURL(url=url, source="sandbox")],
            ),
            judge_indicators=[JudgeIndicator(kind="url", value=url)] if judged else [],
        )
        held = url_host(url) == domain
        assert (string_row_forms(report, ioc_table(report)) == {}) is held
        figure = build_network_graph(report)
        assert figure is not None and figure.legend is not None
        assert ("relay[.]example-c2[.]top" in figure.content) is held
        if not held:
            # The legend's sentence holds of the row: the host the platform
            # reads from the URL is not the domain.
            assert "it is not the host the platform reads from a URL of this run" in figure.legend

    def test_a_value_a_judge_indicator_names_under_its_kind_keeps_it(self) -> None:
        rows = [_row("email", "ops@example.org")]
        judged = [JudgeIndicator(kind="email", value="ops@example.org")]
        assert _forms(rows, judge_indicators=judged) == {}

    def test_a_judge_indicator_of_another_kind_does_not_keep_it(self) -> None:
        rows = [_row("domain", "end.next")]
        judged = [JudgeIndicator(kind="url", value="end.next")]
        assert _forms(rows, judge_indicators=judged) == {("domain", "end.next"): DOTTED_NAME}

    def test_a_recovery_spelled_as_a_host_keeps_its_kind(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting import string_row_form

        monkeypatch.setattr(string_row_form, "_spelled", lambda _report, value: value)
        rows = [_row("domain", "relay.example.net", recovered_by="emulation")]
        assert _forms(rows) == {}

    def test_a_recovery_spelled_as_code_is_a_form_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting import string_row_form

        monkeypatch.setattr(string_row_form, "_spelled", lambda _report, _value: "time.Date")
        rows = [_row("domain", "time.date", recovered_by="emulation")]
        assert _forms(rows) == {("domain", "time.date"): DOTTED_NAME}

    def test_a_recovered_name_at_domain_text_keeps_its_kind(self) -> None:
        assert _forms([_row("email", "ops@example.org", recovered_by="emulation")]) == {}

    def test_a_row_of_another_source_is_never_a_form_row(self) -> None:
        assert _forms([_row("email", "ops@example.org", "analyst")]) == {}

    @pytest.mark.parametrize(
        "text",
        [
            b"LD_PRELOAD=/lib/libx.so",
            b"--output=/tmp/payload.bin",
            b"key=C:\\Windows\\System32\\evil.exe",
            b"ImagePath:C:\\ProgramData\\svc\\svc.exe",
        ],
    )
    def test_a_path_the_extractor_took_from_a_longer_string_says_so(self, text: bytes) -> None:
        swept = [row for row in iter_string_iocs(b"\x00" + text + b"\x00", cuts=True)]
        paths = [row for row in swept if row["kind"] == "path"]
        assert paths
        for row in paths:
            # The extractor records the longer string it took the path from:
            # the path stands inside it, and the string holds more than the path.
            assert row.get("cut_from") == text.decode()
            assert row["value"] in row["cut_from"] and len(row["cut_from"]) > len(row["value"])
        static = StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="path", value=row["value"], cut_from=row["cut_from"])
                for row in paths
            ]
        )
        rows = [_row("path", row["value"]) for row in paths]
        # True of a whole path standing in ``NAME=…`` as of a fragment: the
        # label says where the text stands, not that it is incomplete.
        assert set(_forms(rows, static=static).values()) == {PATH_IN_A_LONGER_STRING}

    def test_a_path_with_no_record_of_a_longer_string_keeps_its_kind(self) -> None:
        static = StaticAnalysis(interesting_strings=[StringIOC(kind="path", value="/lib/libx.so")])
        assert _forms([_row("path", "/lib/libx.so")], static=static) == {}

    def test_a_registry_key_the_extractor_took_from_a_longer_string_says_so(self) -> None:
        text = b"key=HKLM\\Software\\Relay"
        swept = [row for row in iter_string_iocs(b"\x00" + text + b"\x00", cuts=True)]
        keys = [row for row in swept if row["kind"] == "registry"]
        assert [row.get("cut_from") for row in keys] == [text.decode()]
        static = StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="registry", value=keys[0]["value"], cut_from=keys[0]["cut_from"])
            ]
        )
        rows = [_row("registry", keys[0]["value"])]
        assert list(_forms(rows, static=static).values()) == [REGISTRY_KEY_IN_A_LONGER_STRING]

    def test_a_row_of_another_source_never_takes_the_label(self) -> None:
        static = StaticAnalysis(
            interesting_strings=[StringIOC(kind="path", value="/dd/yy", cut_from="MM/dd/yy")]
        )
        assert _forms([_row("path", "/dd/yy", "sandbox")], static=static) == {}

    def test_the_rows_are_not_changed(self) -> None:
        rows = [_row("email", "aes128-gcm@openssh.com"), _row("domain", "end.next")]
        before = [row.model_dump() for row in rows]
        _forms(rows)
        assert [row.model_dump() for row in rows] == before


def _swept_report() -> MalwareReport:
    return _report(
        static=StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="email", value="aes128-gcm@openssh.com"),
                StringIOC(kind="domain", value="end.next"),
                StringIOC(kind="path", value="/lib/libx.so"),
                StringIOC(kind="path", value="/dd/yy", cut_from="MM/dd/yy"),
            ]
        ),
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn="end.next", source="strings"),
                NetworkDomain(fqdn="seen.example", source="sandbox"),
            ]
        ),
    )


def _section(markdown: str, heading: str) -> str:
    start = markdown.index(heading)
    end = markdown.find("\n### ", start + 1)
    end = min(e for e in (end, markdown.find("\n## ", start + 1)) if e > 0)
    return markdown[start:end]


class TestTheReportPrintsTheForm:
    def test_section_9_prints_form_rows_in_their_own_table(self) -> None:
        markdown = MarkdownRenderer().render(_swept_report())
        network = _section(markdown, "### Network indicators")
        formed = _section(markdown, f"### {FORM_ROWS_TITLE}")
        assert "seen[.]example" in network
        assert "end[.]next" not in network and "openssh" not in network
        assert f"| {DOTTED_NAME} | `end[.]next` |" in formed
        assert f"| {NAME_AT_DOMAIN_TEXT} | `aes128-gcm[@]openssh[.]com` |" in formed
        assert markdown.index("### Network indicators") < markdown.index(f"### {FORM_ROWS_TITLE}")

    def test_a_whole_path_keeps_its_type(self) -> None:
        host = _section(MarkdownRenderer().render(_swept_report()), "### File and host indicators")
        assert "| File path | `/lib/libx.so` |" in host

    def test_a_path_taken_from_a_longer_string_prints_where_it_stands(self) -> None:
        markdown = MarkdownRenderer().render(_swept_report())
        host = _section(markdown, "### File and host indicators")
        assert f"| {PATH_IN_A_LONGER_STRING} | `/dd/yy` |" in host
        assert "fragment" not in markdown.lower()

    def test_a_row_of_another_source_with_the_same_value_prints_its_type(self) -> None:
        # The table keeps a sandbox-written path and the strings path spelled
        # with other separators as two rows of one lookup key; only the
        # strings row carries the extractor's record of a longer string.
        report = _report(
            static=StaticAnalysis(
                interesting_strings=[
                    StringIOC(kind="path", value="C:/x/a.exe", cut_from="key=C:/x/a.exe")
                ]
            ),
            dynamic=DynamicBehavior(
                file_operations=[{"operation": "write", "path": "C:\\x\\a.exe"}]
            ),
        )
        assert {(row.source, row.value) for row in ioc_table(report) if row.kind == "path"} == {
            ("sandbox", "C:\\x\\a.exe"),
            ("strings", "C:/x/a.exe"),
        }
        host = _section(MarkdownRenderer().render(report), "### File and host indicators")
        assert "| File path | `C:\\x\\a.exe` |" in host
        assert f"| {PATH_IN_A_LONGER_STRING} | `C:/x/a.exe` |" in host

    def test_the_strings_table_prints_the_form_as_the_kind(self) -> None:
        strings = _section(MarkdownRenderer().render(_swept_report()), "Strings of note")
        assert f"| `end[.]next` | {DOTTED_NAME} |" in strings
        assert f"| `aes128-gcm[@]openssh[.]com` | {NAME_AT_DOMAIN_TEXT} |" in strings
        assert "| `/lib/libx.so` | path |" in strings
        assert f"| `/dd/yy` | {PATH_IN_A_LONGER_STRING} |" in strings

    def test_the_table_s_kind_and_type_are_unchanged(self) -> None:
        report = _swept_report()
        rows = {row.value: (row.kind, row.type) for row in ioc_table(report)}
        assert rows["end.next"] == ("domain", "Domain")
        assert rows["aes128-gcm@openssh.com"] == ("email", "Email")
        assert rows["/dd/yy"] == ("path", "File path")

    def test_a_run_with_no_form_row_prints_no_form_table(self) -> None:
        report = _report(network=NetworkIOCs(domains=[NetworkDomain(fqdn="seen.example")]))
        assert FORM_ROWS_TITLE not in MarkdownRenderer().render(report)


class TestTheFigureDrawsNoFormRow:
    def test_a_form_row_is_counted_not_drawn(self) -> None:
        figure = build_network_graph(_swept_report())
        assert figure is not None
        assert "end[.]next" not in figure.content
        assert "seen[.]example" in figure.content
        assert figure.legend is not None
        assert (
            "1 value read from the file's strings is not drawn: it is not published, it is "
            "neither a domain row of another source nor a domain the judge named, it is not the "
            "host the platform reads from a URL of this run, and it was not recovered with a "
            "spelling that reads as a host. The JSON report holds the 1 endpoint and the 1 value."
            in figure.legend
        )

    def test_the_legend_says_what_was_checked_not_that_nothing_reads_it(self) -> None:
        # An analyst artifact keeping the value is no reader the rule checks:
        # the legend names the readers it checked, and claims nothing of others.
        report = _report(
            network=NetworkIOCs(
                domains=[
                    NetworkDomain(
                        fqdn="c2.evil-relay.top",
                        source="strings",
                        kept_by=["an analyst artifact"],
                        mentioned_by=["a claim by the static analyst"],
                    ),
                    NetworkDomain(fqdn="seen.example.org", source="sandbox"),
                ]
            )
        )
        figure = build_network_graph(report)
        assert figure is not None and figure.legend is not None
        assert "evil-relay" not in figure.content
        assert "nothing in this run" not in figure.legend
        assert "it is not the host the platform reads from a URL of this run" in figure.legend

    def test_the_legend_s_counts_add_up_to_what_the_json_report_holds(self) -> None:
        drawable = [NetworkDomain(fqdn=f"h{n}.example.org", source="sandbox") for n in range(15)]
        formed = [NetworkDomain(fqdn=f"f{n}.next", source="strings") for n in range(4)]
        report = _report(network=NetworkIOCs(domains=[*drawable, *formed]))
        figure = build_network_graph(report)
        assert figure is not None and figure.legend is not None
        assert "3 more endpoints are not drawn." in figure.legend
        assert "4 values read from the file's strings are not drawn: none is published" in (
            figure.legend
        )
        assert " only " not in figure.legend
        assert figure.legend.endswith("The JSON report holds all 15 endpoints and the 4 values.")
        assert len(report.network.domains) == 15 + 4

    def test_a_strings_name_a_url_row_holds_is_drawn(self) -> None:
        report = _report(
            static=StaticAnalysis(
                interesting_strings=[StringIOC(kind="url", value="https://relay.example.net/a")]
            ),
            network=NetworkIOCs(
                domains=[NetworkDomain(fqdn="relay.example.net", source="strings")]
            ),
        )
        figure = build_network_graph(report)
        assert figure is not None
        assert "relay[.]example[.]net" in figure.content
        assert "not drawn" not in (figure.legend or "")


class TestTheAppendixSaysWhoseKindItPrints:
    def test_the_tool_s_indicator_table_is_headed_by_the_tool_s_kind(self) -> None:
        import json

        from malspark.reporting.ledger_report import build_sections
        from malspark.schemas.evidence import build_entry

        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="static",
            tool="iocs_from_file",
            args={},
            server="analysis",
            output=json.dumps({"iocs": [{"kind": "email", "value": "aes128-gcm@openssh.com"}]}),
        )
        tables = [
            s for s in build_sections([entry]) if s.title == "Indicators recovered from the sample"
        ]
        assert tables
        assert tables[0].columns[0] == "Kind (as the tool typed it)"
