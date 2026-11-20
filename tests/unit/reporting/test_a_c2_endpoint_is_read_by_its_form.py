"""A C2 endpoint the report model wrote is read by its form before it is read as a host.

A value with no scheme is a name on the analysed machine (a device or pipe
name, a file on a local volume, a rooted, environment, home, relative or
registry path), a network path (a share, its long-path spelling, its WebDAV
spelling, a ``//`` path), a URL written with backslashes, or a host. Only a
host form is defanged and asked whether a host outside the analysed network
could answer: a name on the machine prints as written, with no mark; a network
path keeps its host defanged and asks the mark of that host alone; a URL
written with backslashes prints as written, defanged as a URL, its host read
from the URL its forward slashes spell. Everything else reads as it did.
"""

from __future__ import annotations

import pytest

from malspark.reporting.ledger_projection import path_or_host_form
from malspark.reporting.renderers.markdown import _endpoint

HOST_MARK = " (not a host outside the analysed network)"
ADDRESS_MARK = " (not an address this run may publish)"


# Written from the forms a value takes (a namespace prefix, a drive, a share,
# a hive, the separators), not from the code: (value, form, host).
FORMS = [
    (r"\\.\pipe\putty-connshare", "device", ""),
    ("//./pipe/x", "device", ""),
    (r"\\.\PhysicalDrive0", "device", ""),
    (r"\??\pipe\x", "device", ""),
    (r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\x.exe", "device", ""),
    (r"\\?\C:\x\a.exe", "volume", ""),
    (r"\??\C:\Windows\a.sys", "volume", ""),
    (r"\\.\C:\x.dll", "volume", ""),
    (r"\\?\UNC\evil.com\share\x", "share", "evil.com"),
    (r"\??\UNC\203.0.113.7\s\x", "share", "203.0.113.7"),
    (r"\\evil.com\share\x", "share", "evil.com"),
    (r"\\fileserver.corp.example\share\a.exe", "share", "fileserver.corp.example"),
    (r"\\203.0.113.7@80\DavWWWRoot\x.dll", "share", "203.0.113.7"),
    (r"\\evil.com@SSL@443\DavWWWRoot\x", "share", "evil.com"),
    ("//evil.com/a", "slashes", "evil.com"),
    # A host written with a port is the host without it.
    ("//evil.com:8080/a", "slashes", "evil.com"),
    (r"\\evil.com:445\s", "share", "evil.com"),
    (r"\\?\UNC\evil.com:445\s", "share", "evil.com"),
    (r"\\[2001:4860::1]:445\s", "share", "[2001:4860::1]"),
    (r"\\[2001:4860::1]\s", "share", "[2001:4860::1]"),
    (r"\\2001:4860::1\s", "share", "2001:4860::1"),
    (r"http:\\evil.com\gate.php", "url", "evil.com"),
    (r"https:/\evil.com/a", "url", "evil.com"),
    (r"evil\.com", "escaped", ""),
    (r"sub\.evil\.com", "escaped", ""),
    (r"C:\Users\a\b.exe", "volume", ""),
    ("C:/Users/a/b.exe", "volume", ""),
    (r"C:\\Users\\a\\b.exe", "volume", ""),
    ("/tmp/.x/run.sh", "local", ""),
    (r"\Device\HarddiskVolume1\x.exe", "local", ""),
    (r"%APPDATA%\x\y.dll", "local", ""),
    ("~/.config/x.sh", "local", ""),
    ("./payload.bin", "local", ""),
    ("../lib/x.so", "local", ""),
    (r"HKLM\Software\a.b", "registry", ""),
    ("HKCU/Software/a.b", "registry", ""),
    ("evil.com", "other", ""),
    ("update.zip", "other", ""),
    ("evil.com:8443", "other", ""),
    ("evil.com/path/a.php", "other", ""),
    (r"evil.com\gate.php", "other", ""),
    ("pipe/putty-connshare.1", "other", ""),
]


@pytest.mark.parametrize(("value", "form", "host"), FORMS)
def test_each_form_is_read_with_the_host_it_names(value: str, form: str, host: str) -> None:
    read = path_or_host_form(value)
    assert (read.form, read.host) == (form, host)
    if host:
        start, end = read.at
        # The host's place in the value as written, so it can be defanged there.
        assert value[start:end].replace("[.]", ".") == host


def test_a_url_with_a_scheme_is_not_a_form_this_reads() -> None:
    assert path_or_host_form("http://evil.com/a").form == "other"


@pytest.mark.parametrize(
    "value",
    [
        r"\\.\pipe\putty-connshare",
        "//./pipe/x",
        r"\\.\PhysicalDrive0",
        r"\\?\C:\x\a.exe",
        r"C:\Users\a\b.exe",
        "/tmp/.x/run.sh",
        r"%APPDATA%\x\y.dll",
        "./payload.bin",
        r"HKLM\Software\a.b",
    ],
)
def test_a_name_on_the_analysed_machine_prints_as_written_with_no_mark(value: str) -> None:
    assert _endpoint(value) == f"`{value}`"


@pytest.mark.parametrize(
    ("value", "printed"),
    [
        (r"\\evil.com\share\a.exe", r"`\\evil[.]com\share\a.exe`"),
        (r"\\?\UNC\evil.com\share\x", r"`\\?\UNC\evil[.]com\share\x`"),
        (
            r"\\fileserver.corp.example\share\a.exe",
            r"`\\fileserver[.]corp[.]example\share\a.exe`" + HOST_MARK,
        ),
        (r"\\10.1.2.3\pipe\x", r"`\\10[.]1[.]2[.]3\pipe\x`" + ADDRESS_MARK),
        (
            r"\\203.0.113.7@80\DavWWWRoot\x.dll",
            r"`\\203[.]0[.]113[.]7@80\DavWWWRoot\x.dll`" + ADDRESS_MARK,
        ),
        ("//evil.com/a", "`//evil[.]com/a`"),
        # The port stays as written beside the host; the mark is the host's.
        ("//evil.com:8080/a", "`//evil[.]com:8080/a`"),
        (r"\\evil.com:445\s", r"`\\evil[.]com:445\s`"),
        (r"\\10.1.2.3:445\s", r"`\\10[.]1[.]2[.]3:445\s`" + ADDRESS_MARK),
        (r"\\[2001:4860::1]:445\s", r"`\\[2001[:]4860::1]:445\s`"),
        # An address in brackets is defanged as the address; its brackets stay
        # where they are written.
        (r"\\[2001:4860::1]\s", r"`\\[2001[:]4860::1]\s`"),
        (r"\\[::1]\s", r"`\\[[:]:1]\s`" + ADDRESS_MARK),
    ],
)
def test_a_network_path_keeps_its_host_defanged_and_asks_the_mark_of_it(
    value: str, printed: str
) -> None:
    assert _endpoint(value) == printed


@pytest.mark.parametrize(
    ("value", "printed"),
    [
        (r"http:\\evil.com\gate.php", r"`hxxp:\\evil[.]com\gate.php`"),
        (r"https:/\evil.com/a", r"`hxxps:/\evil[.]com/a`"),
        (r"http:\\10.1.2.3\gate.php", r"`hxxp:\\10[.]1[.]2[.]3\gate.php`" + ADDRESS_MARK),
        # Its slash twin's host reads as none, as that URL's does.
        (r"hxxp:\\evil[.]com\a", r"`hxxp:\\evil[.]com\a`" + HOST_MARK),
    ],
)
def test_a_url_written_with_backslashes_prints_as_written_with_its_host_read(
    value: str, printed: str
) -> None:
    assert _endpoint(value) == printed


@pytest.mark.parametrize(
    ("value", "printed"),
    [
        ("evil.com", "`evil[.]com`"),
        ("10.0.0.5", "`10[.]0[.]0[.]5`" + ADDRESS_MARK),
        ("http://evil.com/gate.php", "`hxxp://evil[.]com/gate.php`"),
        (r"evil\.com", r"`evil\[.]com`" + HOST_MARK),
        ("evil.com:8443", "`evil[.]com:8443`"),
    ],
)
def test_a_host_an_address_and_a_url_read_as_they_did(value: str, printed: str) -> None:
    assert _endpoint(value) == printed


def _channel_report() -> object:
    from malspark.reporting.models import C2Channel, FileHashes, MalwareReport, SampleIdentity

    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
        verdict="Malware",
        c2_channels=[
            C2Channel(
                name="pipe channel",
                protocol="SMB",
                endpoints=[r"\\.\pipe\putty-connshare", r"\\evil.com\share\a.exe"],
            )
        ],
    )


@pytest.mark.parametrize("layout", ["full", "analyst"])
def test_the_channel_table_prints_each_endpoint_by_its_form(layout: str) -> None:
    from malspark.reporting.renderers.layout import ANALYST
    from malspark.reporting.renderers.markdown import MarkdownRenderer

    renderer = MarkdownRenderer(layout=ANALYST) if layout == "analyst" else MarkdownRenderer()
    text = renderer.render(_channel_report())  # type: ignore[arg-type]
    (row,) = [line for line in text.splitlines() if line.startswith("| pipe channel")]
    assert r"`\\.\pipe\putty-connshare`" in row
    assert r"\\[.]\pipe" not in row
    assert HOST_MARK not in row
    assert r"`\\evil[.]com\share\a.exe`" in row


def test_the_html_report_prints_the_share_host_defanged() -> None:
    from malspark.reporting.renderers.html import HtmlRenderer

    out = HtmlRenderer(layout="analyst").render(_channel_report(), embed_figures=False)  # type: ignore[arg-type]
    assert r"\\evil[.]com\share\a.exe" in out
    assert r"\\[.]\pipe" not in out
