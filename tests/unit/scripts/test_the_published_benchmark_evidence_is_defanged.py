"""The benchmark evidence the docs publish is defanged and carries no internal name.

The docs page links the scored run's report, ledger, evidence bundle, STIX
bundle and ATT&CK mapping. Those copies are written by
``scripts.benchmark.publish_evidence`` from the runner's own folder; a live C2
address served from the docs site gets the site flagged, and a local path or a
run name in them says nothing a reader can use. The rules are checked on
invented text, and the published copies themselves are checked for what must
never be in them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from scripts.benchmark.publish_evidence import (
    _DOMAIN,
    _IPV4,
    _URL,
    JSON_FILES,
    OUT,
    TEXT_FILES,
    Sanitiser,
    _is_reference,
    layout,
    publish,
)

from tests.credential_shapes import lowercase_body

JOB = "11111111-2222-4333-8444-555555555555"


def clean(text: str) -> str:
    return Sanitiser({JOB: "<job>"}).text(text)


def test_an_indicator_url_is_defanged_and_a_reference_link_is_not() -> None:
    assert clean("POST https://bad-host.top/live/ now") == "POST hxxps://bad-host[.]top/live/ now"
    assert clean("http://198.51.100.7:8080/x") == "hxxp://198[.]51[.]100[.]7:8080/x"
    reference = "https://www.virustotal.com/gui/file/abc"
    assert clean(reference) == reference
    # A reference link that names an indicator keeps its own host and defangs the indicator.
    assert clean("https://www.virustotal.com/gui/domain/bad-host.top") == (
        "https://www.virustotal.com/gui/domain/bad-host[.]top"
    )


def test_a_bare_host_and_an_address_are_defanged_and_a_file_name_is_not() -> None:
    assert clean('content:"bad-host.top"; dns') == 'content:"bad-host[.]top"; dns'
    assert clean("Host: cdn.files.example-cdn.net\n") == "Host: cdn[.]files[.]example-cdn[.]net\n"
    assert clean("resolved 192.0.2.10.") == "resolved 192[.]0[.]2[.]10."
    for name in (
        "update_data.dat",
        "rundll32.exe",
        "UpdaterTag.dll",
        "files/bp.dat",
        "version 10.0.19041.1",
    ):
        assert clean(name) == name
    # Already defanged text is left as it is.
    assert clean("ocsp[.]digicert[.]com") == "ocsp[.]digicert[.]com"


def test_a_local_path_keeps_only_its_file_name() -> None:
    assert clean('"path": "/home/someone/work/data/samples/.tmp/abc.exe"') == '"path": "abc.exe"'
    assert clean("Analyzing: \\n/tmp/scratch/abc.exe\\n") == "Analyzing: \\nabc.exe\\n"
    assert clean("/data/samples/abc.exe") == "/data/samples/abc.exe"


def test_ids_run_names_and_the_former_name_are_replaced() -> None:
    assert clean(f"job {JOB} done") == "job <job> done"
    assert (
        clean("scored as haiku13, beside run4 and local3")
        == "scored as <run>, beside <run> and <run>"
    )
    assert clean("Maljan_AutoGen_x, maljan-evidence-bundle/1, MALJAN") == (
        "Malspark_AutoGen_x, malspark-evidence-bundle/1, MALSPARK"
    )
    assert clean("model claude-haiku-5-5") == "model claude-haiku-5-5"


def test_a_credential_shaped_value_is_redacted() -> None:
    token = lowercase_body(40)
    assert token not in clean(f"Authorization: Bearer {token}")
    assert clean(f"api_key={token}") == "api_key=<redacted>"


def test_a_ledger_entry_drops_its_row_id_and_keeps_its_entry_id() -> None:
    entry = {"id": JOB.replace("1", "9"), "entry_id": "ev_0001", "args": {"path": "/home/a/b.exe"}}
    assert Sanitiser({}).json({"items": [entry]}) == {
        "items": [{"entry_id": "ev_0001", "args": {"path": "b.exe"}}]
    }
    # A STIX object's id is part of the bundle and stays.
    stix = {"id": "indicator--" + JOB, "x_maljan_confidence": 0.9}
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
    for name in TEXT_FILES:
        (run / name).write_text(
            f"job {JOB} beacons to https://bad-host.top/live/\n", encoding="utf-8"
        )
    for name in JSON_FILES:
        (run / name).write_text(
            json.dumps({"url": "https://bad-host.top/"}, indent=1), encoding="utf-8"
        )
    publish(run, out)
    for name in TEXT_FILES:
        assert (out / name).read_text(
            encoding="utf-8"
        ) == "job <job> beacons to hxxps://bad-host[.]top/live/\n"
    for name in JSON_FILES:
        assert json.loads((out / name).read_text(encoding="utf-8")) == {
            "url": "hxxps://bad-host[.]top/"
        }


@pytest.mark.parametrize("name", TEXT_FILES + JSON_FILES)
def test_the_published_copy_holds_no_live_indicator_or_internal_name(name: str) -> None:
    text = (OUT / name).read_text(encoding="utf-8")
    live_urls = [m.group(0) for m in _URL.finditer(text) if not _is_reference(m.group(2))]
    live_hosts = [m.group(1) for m in _DOMAIN.finditer(text) if not _is_reference(m.group(1))]
    assert live_urls == []
    assert live_hosts == []
    assert not _IPV4.search(text)
    assert not re.search(r"maljan|/home/|/tmp/|\bhaiku\d", text, re.IGNORECASE)
