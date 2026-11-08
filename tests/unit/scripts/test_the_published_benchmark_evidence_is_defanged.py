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


def test_a_local_path_keeps_only_its_file_name() -> None:
    assert clean('"path": "/home/someone/work/data/samples/.tmp/abc.exe"') == '"path": "abc.exe"'
    assert clean("Analyzing: \\n/tmp/scratch/abc.exe\\n") == "Analyzing: \\nabc.exe\\n"
    assert clean("/data/samples/abc.exe") == "/data/samples/abc.exe"


def test_ids_run_tags_and_the_former_name_are_replaced() -> None:
    assert clean(f"job {JOB} done") == "job <job> done"
    assert clean("scored as run9, beside local7, hk5 and run 7") == (
        "scored as <run>, beside <run>, <run> and <run>"
    )
    assert clean("the empty collections store_hk5*") == "the empty collections <run>"
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
            f"job {JOB} beacons to https://bad-host.top/live/ via odd.zz and zz.yy\n",
            encoding="utf-8",
        )
    for name in JSON_FILES:
        body = {"items": [sandbox]} if name == "evidence.json" else {"url": "https://bad-host.top/"}
        (run / name).write_text(json.dumps(body, indent=1), encoding="utf-8")
    assert run_indicators(run) == {"odd.zz", "zz.yy"}
    publish(run, out)
    for name in TEXT_FILES:
        job = "&lt;job&gt;" if name.endswith(".html") else "<job>"
        assert (out / name).read_text(encoding="utf-8") == (
            f"job {job} beacons to hxxps://bad-host[.]top/live/ via odd[.]zz and zz[.]yy\n"
        )
    assert json.loads((out / "stix-bundle.json").read_text(encoding="utf-8")) == {
        "url": "hxxps://bad-host[.]top/"
    }


# --- The published copies, scanned apart from the sanitiser ------------------

# Links that are not indicators of the sample.
REFERENCE = ("virustotal.com", "bazaar.abuse.ch", "attack.mitre.org", "w3.org")
# Dotted names that end in a file extension are files.
EXTENSIONS = frozenset(
    "dll exe dat sys txt json md html htm js css py pyc ps1 bat cmd vbs lnk ini cfg log xml yaml "
    "yml csv tmp bin cab zip rar gz tar pdf doc docx xls xlsx png jpg gif svg ico msi db so elf "
    "apk jar crl cer crt".split()
)
# Dotted names in the copies that are no host, each read where it stands: CSS
# selectors of the HTML report, keywords of the Suricata, Sigma and YARA rules
# it prints, keys of the sandbox's own records, and a truncated command line.
NOT_HOSTS = frozenset(
    {
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

_NAME = re.compile(r"(?<![\w.\-\[\]])((?:[a-z0-9-]+\.)+([a-z]{2,24}))(?![\w-]|\.\w)")
_LIVE_URL = re.compile(r"https?://([^/\s\"'<>\\)]+)", re.IGNORECASE)
_ADDRESS = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
_RUN_TAG = re.compile(r"\b(?:haiku|run|local|hk)[ _-]?\d[\w-]*", re.IGNORECASE)
_ID = re.compile(
    r"(?<![\w-])([a-z][a-z0-9-]*--)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
_HEX_RUN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){12,}(?![0-9a-fA-F])")


def _reference(host: str) -> bool:
    host = host.lower().split(":")[0]
    return any(host == ref or host.endswith("." + ref) for ref in REFERENCE)


def live_names(text: str) -> list[str]:
    """Every live dotted name in ``text`` that is not a file, a known non-host or a reference."""
    return [
        m.group(1)
        for m in _NAME.finditer(text)
        if m.group(2) not in EXTENSIONS
        and m.group(1) not in NOT_HOSTS
        and not _reference(m.group(1))
    ]


def live_urls(text: str) -> list[str]:
    return [m.group(0) for m in _LIVE_URL.finditer(text) if not _reference(m.group(1))]


def test_the_scan_catches_a_live_host_put_back() -> None:
    for host in ("evil.de", "c.pki.goog", "bad-host.top"):
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
