"""The benchmark evidence the docs publish is defanged and carries no internal name.

The docs page links the scored run's report, ledger, evidence bundle, STIX
bundle and ATT&CK mapping. Those copies are written by
``scripts.benchmark.publish_evidence`` from the runner's own folder; a live C2
address served from the docs site gets the site flagged, and a local path or a
run tag in them says nothing a reader can use. The rules are checked on
invented text, and the published copies are checked by a scan of their own,
written apart from the sanitiser's patterns so that a gap in those is caught.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from scripts.benchmark.publish_evidence import (
    JSON_FILES,
    OUT,
    TEXT_FILES,
    Sanitiser,
    layout,
    publish,
    run_indicators,
)

from malspark.core.previous_name import PREVIOUS_NAME
from tests.credential_shapes import lowercase_body

JOB = "11111111-2222-4333-8444-555555555555"
OLD = PREVIOUS_NAME


def clean(text: str, indicators: frozenset[str] = frozenset()) -> str:
    return Sanitiser({JOB: "<job>"}, indicators).text(text)


# --- The rules, on invented text ---------------------------------------------


def test_an_indicator_url_is_defanged_and_a_reference_link_is_not() -> None:
    assert clean("POST https://bad-host.top/live/ now") == "POST hxxps://bad-host[.]top/live/ now"
    assert clean("http://198.51.100.7:8080/x") == "hxxp://198[.]51[.]100[.]7:8080/x"
    reference = "https://www.virustotal.com/gui/file/abc"
    assert clean(reference) == reference
    # A reference link that names an indicator keeps its own host and defangs the indicator.
    assert clean("https://www.virustotal.com/gui/domain/bad-host.top") == (
        "https://www.virustotal.com/gui/domain/bad-host[.]top"
    )


def test_a_host_under_any_delegated_top_level_domain_is_defanged() -> None:
    assert clean('content:"bad-host.top"; dns') == 'content:"bad-host[.]top"; dns'
    assert clean("Host: c.pki.goog\n") == "Host: c[.]pki[.]goog\n"
    assert clean("the sandbox at tria.ge, then evil.de.") == (
        "the sandbox at tria[.]ge, then evil[.]de."
    )
    assert clean("resolved 192.0.2.10.") == "resolved 192[.]0[.]2[.]10."


def test_a_file_name_a_label_and_a_rule_keyword_are_not_hosts() -> None:
    for text in (
        "update_data.dat",
        "rundll32.exe",
        "UpdaterTag.dll",
        "files/bp.dat",
        "setup.py",
        "notes.zip",
        "version 10.0.19041.1",
        "Trojan.Win64.Agent",
        "http.host; content",
        "nav.toc",
    ):
        assert clean(text) == text
    # Already defanged text is left as it is.
    assert clean("ocsp[.]digicert[.]com") == "ocsp[.]digicert[.]com"


def test_the_run_s_own_indicators_are_defanged_whatever_their_ending() -> None:
    indicators = frozenset({"c2.internal-zone", "Odd.Host.Zz"})
    assert clean("beacon to c2.internal-zone and odd.host.zz", indicators) == (
        "beacon to c2[.]internal-zone and odd[.]host[.]zz"
    )


def test_a_hex_run_that_holds_an_indicator_is_re_encoded_defanged() -> None:
    raw = b"https://bad-host.top/live/\x00\x01junk"
    out = clean(f'"hex_head": "{raw.hex()}"')
    decoded = bytes.fromhex(out.split('"')[3]).decode("latin-1")
    assert decoded == "hxxps://bad-host[.]top/live/\x00\x01junk"
    digest = "ab" * 32
    assert clean(digest) == digest


def test_a_capitalised_host_is_defanged_and_a_capitalised_label_is_not() -> None:
    assert clean('$s1 = "EVIL.COM" ascii') == '$s1 = "EVIL[.]COM" ascii'
    assert clean("Trojan.Win64.IcedID") == "Trojan.Win64.IcedID"


def test_bytes_shown_as_utf16le_that_hold_an_indicator_are_rebuilt_defanged() -> None:
    raw = b"https://bad-host.top/live/\x00\x60"
    shown = raw.decode("utf-16le")
    out = clean(f'"utf16le": "{shown}"').split('"')[3]
    assert out.encode("utf-16le").rstrip(b"\x00") == b"hxxps://bad-host[.]top/live/\x00\x60"


def test_a_local_path_keeps_only_its_file_name() -> None:
    assert clean('"path": "/home/someone/work/data/samples/.tmp/abc.exe"') == '"path": "abc.exe"'
    assert clean("Analyzing: \\n/tmp/scratch/abc.exe\\n") == "Analyzing: \\nabc.exe\\n"
    assert clean("/data/samples/abc.exe") == "/data/samples/abc.exe"


def test_ids_run_tags_and_the_former_name_are_replaced() -> None:
    assert clean(f"job {JOB} done") == "job <job> done"
    assert clean("scored as run97, beside local98, hk99 and run 97") == (
        "scored as <run>, beside <run>, <run> and <run>"
    )
    assert clean("the empty collections store_hk99*") == "the empty collections <run>"
    upper, title = OLD.upper(), OLD.capitalize()
    assert clean(f"{title}_AutoGen_x, {OLD}-evidence-bundle/1, {upper}") == (
        "Malspark_AutoGen_x, malspark-evidence-bundle/1, MALSPARK"
    )
    # A decompiler's local and a model id are not run tags.
    assert clean("local_18 = 0; model claude-haiku-5-5") == "local_18 = 0; model claude-haiku-5-5"


def test_a_credential_shaped_value_is_redacted() -> None:
    token = lowercase_body(40)
    assert token not in clean(f"Authorization: Bearer {token}")
    assert clean(f"api_key={token}") == "api_key=<redacted>"


def test_an_html_copy_writes_its_placeholders_escaped() -> None:
    assert Sanitiser({JOB: "<job>"}).text(f"<p>job {JOB}</p>", html=True) == (
        "<p>job &lt;job&gt;</p>"
    )


def test_a_ledger_entry_drops_its_row_id_and_keeps_its_entry_id() -> None:
    entry = {"id": JOB.replace("1", "9"), "entry_id": "ev_0001", "args": {"path": "/home/a/b.exe"}}
    assert Sanitiser({}).json({"items": [entry]}) == {
        "items": [{"entry_id": "ev_0001", "args": {"path": "b.exe"}}]
    }
    # A STIX object's id is part of the bundle and stays.
    stix = {"id": "indicator--" + JOB, f"x_{OLD}_confidence": 0.9}
    assert Sanitiser({}).json(stix) == {"id": "indicator--" + JOB, "x_malspark_confidence": 0.9}


def test_the_report_s_marking_banner_reads_clear() -> None:
    for level in ("AMBER", "AMBER+STRICT", "AMBER_STRICT", "RED", "GREEN", "WHITE", "CLEAR"):
        assert clean(f"**TLP:{level}** · Report X") == "**TLP:CLEAR** · Report X"
    assert clean("<p><strong>TLP:RED</strong> · Report X") == (
        "<p><strong>TLP:CLEAR</strong> · Report X"
    )
    # A level the banner does not print is not partly rewritten.
    assert clean("**TLP:AMBER-STRICT**") == "**TLP:AMBER-STRICT**"


def test_a_tlp_mention_outside_the_banner_stays_as_written() -> None:
    for text in (
        "The vendor's note was shared under TLP:RED.",
        "the rule matches `TLP:AMBER` in the mail header",
        "<code>TLP:AMBER</code>",
    ):
        assert clean(text) == text
    # Evidence bytes shown as hex are decoded only to defang an indicator.
    for raw in (b"TLP:AMBER sample string padding".hex(), b"**TLP:AMBER** sample padding".hex()):
        assert Sanitiser({}).text(raw) == raw


def test_a_tlp_field_of_a_json_copy_reads_clear_in_its_own_case() -> None:
    sanitiser = Sanitiser({})
    assert sanitiser.json({"tlp": "AMBER", "front_matter": {"TLP": "red"}}) == {
        "tlp": "CLEAR",
        "front_matter": {"TLP": "clear"},
    }
    assert sanitiser.json({"tlp": "clear"}) == {"tlp": "clear"}
    assert sanitiser.counts == {("tlp", "AMBER"): 1, ("tlp", "red"): 1}
    # A field that is not a marking level is sanitised as any other.
    assert Sanitiser({}).json({"tlp": "see evil.de"}) == {"tlp": "see evil[.]de"}


def test_the_platform_still_escalates_and_the_public_copy_reads_clear() -> None:
    from malspark.reporting.builder import MalwareReportBuilder
    from malspark.reporting.models import (
        FileHashes,
        MalwareReport,
        NetworkIOCs,
        NetworkIP,
        SampleIdentity,
    )

    builder = MalwareReportBuilder(
        file_hash="a" * 64,
        file_name=None,
        sample_path=None,
        sandbox_report=None,
        reports={},
        isr_reports={},
        stix_output=None,
        run_summary=None,
        discussion_history=None,
        final_decision="Malware",
    )
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        network=NetworkIOCs(ips=[NetworkIP(address="198.51.100.7", port=443)]),
    )
    tlp = builder._build_front_matter(report).tlp
    # The report kept in the platform holds live C2, so it is marked AMBER ...
    assert tlp == "AMBER"
    # ... and the copy written for open publication is not.
    assert clean(f"**TLP:{tlp}** · Report X") == "**TLP:CLEAR** · Report X"


@pytest.mark.parametrize("indent", [1, 2, None])
def test_a_json_copy_keeps_the_original_layout(indent: int | None) -> None:
    data = {"a": ["é", 1]}
    for ascii_only in (True, False):
        assert layout(json.dumps(data, indent=indent, ensure_ascii=ascii_only), data) == (
            indent,
            ascii_only,
        )


def test_a_run_folder_is_published_whole(tmp_path: Path) -> None:
    run, out = tmp_path / "run", tmp_path / "out"
    run.mkdir()
    (run / "job.json").write_text(json.dumps({"id": JOB}), encoding="utf-8")
    (run / "iocs.json").write_text(
        json.dumps({"items": [{"kind": "domain", "value": "odd.zz"}]}), encoding="utf-8"
    )
    sandbox = {"facts": {"kind": "sandbox_network"}, "structured": {"tcp": [{"dst": "zz.yy:443"}]}}
    for name in TEXT_FILES:
        (run / name).write_text(
            f"**TLP:AMBER** job {JOB} beacons to https://bad-host.top/live/ via odd.zz and zz.yy\n",
            encoding="utf-8",
        )
    for name in JSON_FILES:
        body = (
            {"items": [sandbox]}
            if name == "evidence.json"
            else {"url": "https://bad-host.top/", "tlp": "RED", "markdown": "**TLP:AMBER**"}
        )
        (run / name).write_text(json.dumps(body, indent=1), encoding="utf-8")
    assert run_indicators(run) == {"odd.zz", "zz.yy"}
    publish(run, out)
    for name in TEXT_FILES:
        job = "&lt;job&gt;" if name.endswith(".html") else "<job>"
        assert (out / name).read_text(encoding="utf-8") == (
            f"**TLP:CLEAR** job {job} beacons to hxxps://bad-host[.]top/live/"
            " via odd[.]zz and zz[.]yy\n"
        )
    assert json.loads((out / "stix-bundle.json").read_text(encoding="utf-8")) == {
        "url": "hxxps://bad-host[.]top/",
        "tlp": "CLEAR",
        "markdown": "**TLP:CLEAR**",
    }


# --- The published copies, scanned apart from the sanitiser ------------------

# Links that are not indicators of the sample.
REFERENCE = ("virustotal.com", "bazaar.abuse.ch", "attack.mitre.org", "w3.org")
# Dotted names that end in a file extension are files. An extension that is
# also a top-level domain (.zip, .md, .py ...) is not listed: a file name with
# one is allowed by name in NOT_HOSTS.
EXTENSIONS = frozenset(
    "dll exe dat sys txt json html htm js css pyc ps1 bat cmd vbs lnk ini cfg log xml yaml "
    "yml csv tmp bin rar gz tar pdf doc docx xls xlsx png jpg gif svg ico msi db elf "
    "apk jar crl cer crt".split()
)
# Dotted names in the copies that are no host, each read where it stands: CSS
# selectors of the HTML report, keywords of the Suricata, Sigma and YARA rules
# it prints, keys of the sandbox's own records, a truncated command line, the
# detection labels of the reputation answers, and file names whose extension
# is also a top-level domain (a tool's script, certificate lists the sandbox
# fetched). The two detection labels that end in a top-level domain,
# ``Malware.Win64.Gen.tr`` and ``Latrodectus.CPA``, are defanged instead.
NOT_HOSTS = frozenset(
    {
        "Agent.bxh",
        "Backdoor.Win64.Agent.khs",
        "Backdoor.Win64.Latrodectus.Volu",
        "Trojan.Agent.Latrodectus",
        "Trojan.Banker",
        "Trojan.Banker.IcedID.all",
        "Trojan.Coinminer",
        "Trojan.IcedId",
        "Trojan.Latrodectus",
        "Trojan.Malware.74412563.susgen",
        "Trojan.Win32.GenusT.FFRA",
        "Trojan.Win64.IcedID",
        "Trojan.Win64.Ulise.kqlkfh",
        "W32.Trojan.Gen",
        "Win32.Lactrodectus",
        "Windows.Trojan.Latrodectus",
        "authrootstl.cab",
        "disallowedcertstl.cab",
        "pinrulesstl.cab",
        "qu1cksc0pe.py",
        "agreement.dropped",
        "agreement.listed",
        "agreement.rewritten",
        "attack.discovery",
        "attack.execution",
        "attack.stealth",
        "cmd.ex",
        "dns.query",
        "gcp.audit",
        "header.cover",
        "http.host",
        "http.uri",
        "nav.toc",
        "network.icmp",
        "network.tls",
        "ol.notes",
        "pe.imphash",
        "sup.cite",
        "task.analysis",
        "task.network.ips",
        "task.sample",
        "task.task",
        "task.version",
    }
)
# Public ids the copies carry outside a STIX ``type--uuid``: the Sigma rule id
# the sandbox matched, the generated Sigma rule's id and a CDN file path the
# sandbox recorded.
PUBLIC_IDS = frozenset(
    {
        "e79a9e79-eb72-4e78-a628-0e7e8f59e89c",
        "a6e1bfe4-ea83-11e9-45a2-abee89f6f77f",
        "315ca852-f356-4361-8815-086f38f13875",
    }
)

_NAME = re.compile(r"(?<![\w.\-\[\]])((?:[a-z0-9-]+\.)+([a-z]{2,24}))(?![\w-]|\.\w)", re.IGNORECASE)
_LIVE_URL = re.compile(r"https?://([^/\s\"'<>\\)]+)", re.IGNORECASE)
_ADDRESS = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
_RUN_TAG = re.compile(r"\b(?:haiku|run|local|hk)[ _-]?\d[\w-]*", re.IGNORECASE)
_ID = re.compile(
    r"(?<![\w-])([a-z][a-z0-9-]*--)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
_HEX_RUN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){12,}(?![0-9a-fA-F])")
# Bytes read back as UTF-16LE show as a run of characters above U+00FF.
_WIDE_RUN = re.compile("[\u0100-\ud7ff\ue000-\uffff]{8,}")


def _reference(host: str) -> bool:
    host = host.lower().split(":")[0]
    return any(host == ref or host.endswith("." + ref) for ref in REFERENCE)


def live_names(text: str) -> list[str]:
    """Every live dotted name in ``text`` that is not a file, a known non-host or a reference."""
    return [
        m.group(1)
        for m in _NAME.finditer(text)
        if m.group(2).lower() not in EXTENSIONS
        and m.group(1) not in NOT_HOSTS
        and not _reference(m.group(1))
    ]


def live_urls(text: str) -> list[str]:
    return [m.group(0) for m in _LIVE_URL.finditer(text) if not _reference(m.group(1))]


def test_the_scan_catches_a_live_host_put_back() -> None:
    for host in ("evil.de", "c.pki.goog", "bad-host.top", "EVIL.COM", "evil.zip"):
        assert live_names(f'"dst": "{host}", text') == [host]
    assert live_urls("GET https://evil.de/x") == ["https://evil.de"]
    assert _ADDRESS.findall("to 203.0.113.9.") == ["203.0.113.9"]


def _copies() -> list[tuple[str, str]]:
    return [(name, (OUT / name).read_text(encoding="utf-8")) for name in TEXT_FILES + JSON_FILES]


@pytest.mark.parametrize(("name", "text"), _copies(), ids=[n for n, _ in _copies()])
def test_the_published_copy_holds_no_live_indicator(name: str, text: str) -> None:
    assert live_names(text) == []
    assert live_urls(text) == []
    assert _ADDRESS.findall(text) == []


@pytest.mark.parametrize(("name", "text"), _copies(), ids=[n for n, _ in _copies()])
def test_the_published_copy_holds_no_internal_name_path_or_server_id(name: str, text: str) -> None:
    assert not re.search(rf"{PREVIOUS_NAME}|/home/|/tmp/", text, re.IGNORECASE)
    tags = {
        m.group(0)
        for m in _RUN_TAG.finditer(text)
        # A decompiler's locals and the model's id are not run tags.
        if not re.fullmatch(r"local_[0-9a-f]+", m.group(0))
        and not m.group(0).startswith("haiku-5-5")
    }
    assert tags == set()
    ids = {m.group(2) for m in _ID.finditer(text) if not m.group(1)}
    assert ids <= PUBLIC_IDS


@pytest.mark.parametrize(("name", "text"), _copies(), ids=[n for n, _ in _copies()])
def test_the_published_copy_carries_no_restricted_tlp_marking(name: str, text: str) -> None:
    # The copies are published openly; a limited-distribution marking contradicts that.
    banners = _BANNER.findall(text)
    if name in BANNERED:
        assert banners, "the report's marking banner is missing"
    assert {level.upper() for level in banners} <= {"CLEAR"}
    if name.endswith(".json"):
        assert {str(v).upper() for v in _tlp_fields(json.loads(text))} <= {"CLEAR"}


# The report's marking banner as the Markdown prints it and the HTML renders it,
# whatever the level reads; the copies that print the report carry one.
_BANNER = re.compile(r"(?:\*\*|<strong>)TLP:([^*<\s]+)(?=\*\*|</strong>)", re.IGNORECASE)
BANNERED = frozenset({"report.md", "report.html", "evidence-bundle.html", "evidence-bundle.json"})


def test_the_banner_scan_reads_the_banner_the_sanitiser_rewrites() -> None:
    for banner in ("**TLP:AMBER**", "<strong>tlp:red</strong>", "**TLP:AMBER+STRICT**"):
        assert _BANNER.findall(banner) and _BANNER.findall(clean(banner)) == ["CLEAR"]
    prose = "shared under TLP:RED. and `TLP:AMBER`"
    assert _BANNER.findall(prose) == [] and clean(prose) == prose


def _tlp_fields(value: object) -> list[object]:
    """The value of every ``tlp`` field in a parsed JSON value."""
    if isinstance(value, dict):
        own = [v for k, v in value.items() if str(k).lower() == "tlp"]
        return own + [f for v in value.values() for f in _tlp_fields(v)]
    if isinstance(value, list):
        return [f for v in value for f in _tlp_fields(v)]
    return []


@pytest.mark.parametrize("name", [n for n in TEXT_FILES if n.endswith(".html")])
def test_the_published_html_holds_no_raw_placeholder(name: str) -> None:
    text = (OUT / name).read_text(encoding="utf-8")
    assert not re.search(r"<(?:job|report|sample|run|redacted)>", text)


@pytest.mark.parametrize("name", JSON_FILES)
def test_a_hex_field_of_the_published_copy_decodes_to_no_live_indicator(name: str) -> None:
    text = (OUT / name).read_text(encoding="utf-8")
    for match in _HEX_RUN.finditer(text):
        decoded = bytes.fromhex(match.group(0)).decode("latin-1")
        assert live_urls(decoded) == [], match.group(0)[:40]
        assert live_names(decoded) == [], match.group(0)[:40]


@pytest.mark.parametrize("name", JSON_FILES)
def test_a_utf16le_field_of_the_published_copy_decodes_to_no_live_indicator(name: str) -> None:
    for string in _strings(json.loads((OUT / name).read_text(encoding="utf-8"))):
        for match in _WIDE_RUN.finditer(string):
            decoded = match.group(0).encode("utf-16le").decode("latin-1")
            assert live_urls(decoded) == [], decoded[:40]
            assert live_names(decoded) == [], decoded[:40]


def _strings(value: object) -> list[str]:
    """Every string in a parsed JSON value, keys included."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


# --- The environment block's model identifiers ------------------------------


def test_a_run_summary_s_model_strings_skip_the_host_and_run_name_rules() -> None:
    # Model names that look like a host name or a run tag: those rules would
    # rewrite them, and a reader stating the configuration would then quote a
    # model that does not exist.
    agents = {
        "static": {
            "requests": [{"position": 0, "provider": "openai", "model": "x-ai/grok-4.fast"}],
            "response_models": {"hk14-model": 1, "deepseek.chat": 2},
            "response_models_reduced": ["run7-model.gguf"],
        }
    }
    summary = {"environment": {"agents": agents}, "note": "see deepseek.chat"}
    copy = Sanitiser({JOB: "<job>"}).run_summary(summary)
    assert copy["environment"]["agents"] == agents
    # The same strings elsewhere in the summary are still the run's text.
    assert copy["note"] == "see deepseek[.]chat"


def test_the_local_path_rule_applies_at_a_kept_path() -> None:
    # A server with no alias, configured by the file it loads, in the user's home.
    summary = {
        "environment": {
            "agents": {
                "static": {
                    "requests": [{"model": "/home/alice/models/Qwen3.6.gguf"}],
                    "response_models": {"/home/alice/models/Qwen3.6.gguf": 1},
                }
            }
        }
    }
    copy = Sanitiser({}).run_summary(summary)["environment"]["agents"]["static"]
    assert copy == {"requests": [{"model": "Qwen3.6.gguf"}], "response_models": {"Qwen3.6.gguf": 1}}


def test_an_address_at_a_kept_path_is_still_defanged() -> None:
    summary = {
        "environment": {"agents": {"x": {"response_models": {"http://evil.example.com/c2": 1}}}}
    }
    copy = Sanitiser({}).run_summary(summary)["environment"]["agents"]["x"]
    assert copy["response_models"] == {"hxxp://evil[.]example[.]com/c2": 1}


def test_the_same_shape_in_evidence_or_deeper_is_the_run_s_text() -> None:
    # The kept paths are matched from a run summary's root, and only in one.
    environment = {
        "agents": {
            "x": {
                "response_models": {"http://evil.example.com/c2": 1, "evil.example.com": 1},
                "requests": [{"model": "185.1.2.3"}],
            }
        }
    }
    evidence = {"entries": [{"tool": "strings", "output": {"environment": environment}}]}
    for copy in (
        Sanitiser({}).json(evidence)["entries"][0]["output"]["environment"],
        Sanitiser({}).json({"environment": environment})["environment"],
        Sanitiser({}).run_summary({"output": {"environment": environment}})["output"][
            "environment"
        ],
    ):
        assert copy["agents"]["x"]["response_models"] == {
            "hxxp://evil[.]example[.]com/c2": 1,
            "evil[.]example[.]com": 1,
        }
        assert copy["agents"]["x"]["requests"] == [{"model": "185[.]1[.]2[.]3"}]


def test_only_the_model_paths_are_kept() -> None:
    copy = Sanitiser({JOB: "<job>"}).run_summary(
        {"environment": {"agents": {"static": {"requests": [{"provider": "hk14"}]}}}}
    )
    assert copy["environment"]["agents"]["static"]["requests"] == [{"provider": "<run>"}]
