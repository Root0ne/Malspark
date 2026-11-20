"""A refused host is given the reason of the test that refused it (T-782a).

One function gives the reason and the decision is that function:
``host_is_public(h)`` is ``host_failure(h) == ""``. Each test the rule asks has
its own reason, naming the test and what it read, in the order the tests run;
a URL's and a mailbox's own steps come before the host test. A quoted value is
written one-to-one: a character the writer writes out is ``{U+XXXX}``, never an
escape with no end, and a refused character is named by its code point too.
Every decline the export records and the mark beside a model-written endpoint
print that reason; no renderer words a host reason of its own.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from pathlib import Path
from typing import Any

import pytest

from malspark.extractors import network_extractor as ne
from malspark.extractors.network_extractor import (
    host_failure,
    host_is_public,
    quoted_host_text,
    url_failure,
    url_host,
)
from malspark.reporting.renderers.markdown import _endpoint
from malspark.reporting.renderers.stix_renderer import (
    email_failure,
    email_is_publishable,
    pattern_problem,
    unpublishable_domain_sentence,
)

LABEL_SET = "which is not a letter a-z, a digit or a hyphen"
LAST_LABEL = "is neither two or more letters a-z nor an xn-- label"


def _onion(version: int = 3, *, good_checksum: bool = True) -> str:
    key = bytes(range(32))
    checksum = hashlib.sha3_256(b".onion checksum" + key + bytes([version])).digest()[:2]
    if not good_checksum:
        checksum = bytes([checksum[0] ^ 1, checksum[1]])
    return base64.b32encode(key + checksum + bytes([version])).decode().lower() + ".onion"


# (host, reason): every return of the host test, written from the tests the
# rule asks rather than from the code.
REASONS = [
    ("", "it names no host"),
    (" . ", "it names no host"),
    # A name the second reading strips to nothing.
    (". .", "it names no host"),
    ("x..onion", 'its label before ".onion" is empty'),
    (
        "abcdefghijklmno1.onion",
        'its .onion label "abcdefghijklmno1" holds "1" (U+0031), which is not in the base32 '
        "alphabet a-z, 2-7",
    ),
    (
        "abcdefgh.onion",
        'its .onion label "abcdefgh" is 8 characters long, and this rule accepts 16 or 56',
    ),
    ("abcdefghijklmnop.onion", ""),
    (_onion(), ""),
    (
        _onion(4),
        f'its .onion label "{_onion(4)[:40]}…" carries version 4, and this rule accepts 3',
    ),
    (
        _onion(good_checksum=False),
        f'its .onion label "{_onion(good_checksum=False)[:40]}…" fails the hidden-service checksum',
    ),
    ("127.0.0.1", '"127.0.0.1" is a loopback address'),
    ("::", '"::" is the unspecified address'),
    ("0.0.0.0", '"0.0.0.0" is the unspecified address'),
    ("[FE80::1]", '"fe80::1" (read in lower case) is a link-local address'),
    ("8.8.8.8", ""),
    ("10.0.0.5", ""),
    ("INTRANET", '"intranet" (read in lower case) is a single label'),
    ("3271", '"3271" is a single label'),
    ("localhost.localdomain", '"localhost.localdomain" is a name this rule lists as reserved'),
    ("printer.local", 'it ends in ".local", a suffix this rule lists as reserved'),
    ("8.8.8.8.in-addr.arpa", 'it ends in ".arpa", a suffix this rule lists as reserved'),
    (
        "fileserver.corp.internal",
        'it ends in ".internal", a suffix this rule lists as not public',
    ),
    ("x.alt", 'it ends in ".alt", a suffix this rule lists as not public'),
    ("a..b.com", "it has an empty label"),
    ("example.com:443", f'its label "com:443" holds ":" (U+003A), {LABEL_SET}'),
    ("a" * 64 + ".com", f'its label "{"a" * 40}…" is 64 characters long, more than 63'),
    ("-a.com", 'its label "-a" starts or ends with a hyphen'),
    ("ABC-.abc-x.com", 'its label "abc-" (read in lower case) starts or ends with a hyphen'),
    ("ocsp.sectigo.com0", f'its last label "com0" {LAST_LABEL}'),
    ("x.COM0", f'its last label "com0" (read in lower case) {LAST_LABEL}'),
    ("example.com", ""),
    ("xn--bcher-kva.de", ""),
    # A suffix is quoted by what the value writes at its place.
    ("x.LOCAL", 'it ends in ".local" (read in lower case), a suffix this rule lists as reserved'),
    (
        "x.Home.Arpa",
        'it ends in ".arpa" (read in lower case), a suffix this rule lists as reserved',
    ),
    ("x.CORP", 'it ends in ".corp" (read in lower case), a suffix this rule lists as not public'),
    # A character the label test refused is the one the value writes.
    (
        "İ" * 16 + ".com",
        f'its label "{"i{U+0307}" * 4}i…" (read in lower case) holds "İ" (U+0130), {LABEL_SET}',
    ),
    # A final sigma is lowered by its place in the whole name.
    ("ΑΣ.com", f'its label "ασ" (read in lower case) holds "Α" (U+0391), {LABEL_SET}'),
    # The .onion label is quoted by its position in what the value writes.
    (
        "ABCD.onion",
        'its .onion label "abcd" (read in lower case) is 4 characters long, and this rule '
        "accepts 16 or 56",
    ),
    (
        "İ" * 16 + ".onion",
        f'its .onion label "{"i{U+0307}" * 4}i…" (read in lower case) holds "İ" (U+0130), '
        "which is not in the base32 alphabet a-z, 2-7",
    ),
    ("ABCDEFGHIJKLMNOP.ONION", ""),
    (_onion().upper(), ""),
    (
        _onion(4).upper(),
        f'its .onion label "{_onion(4)[:40]}…" (read in lower case) carries version 4, and this '
        "rule accepts 3",
    ),
]

# A mixed-case fifty-six-character label with one character the alphabet refuses.
_MIXED = _onion()[:10].upper() + "Ä" + _onion()[11:56].upper() + ".Onion"
REASONS.append(
    (
        _MIXED,
        f'its .onion label "{_MIXED[:40].lower()}…" (read in lower case) holds "Ä" (U+00C4), '
        "which is not in the base32 alphabet a-z, 2-7",
    )
)


@pytest.mark.parametrize(("host", "reason"), REASONS)
def test_each_test_of_the_rule_gives_its_own_reason(host: str, reason: str) -> None:
    assert host_failure(host) == reason
    assert host_is_public(host) is (reason == "")


def test_a_name_that_will_not_decode_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    # Fifty-six base32 characters always decode; the reason stands for the
    # decoder refusing them all the same.
    def refuse(_text: Any) -> bytes:
        raise ValueError("refused")

    monkeypatch.setattr(base64, "b32decode", refuse)
    assert host_failure(_onion()).endswith("does not decode as base32")


def test_a_reserved_name_the_second_reading_reaches_is_named() -> None:
    # The private-use reading keeps its own reserved-name test; the earlier
    # reading takes every name that reaches it today, so it is asked directly.
    assert ne._private_use_failure("localhost", "LOCALHOST") == (
        '"localhost" (read in lower case) is a name this rule lists as reserved'
    )


# The old decision, written out: the reasons above must never change it.
def _old_onion(name: str) -> bool:
    label = name[: -len(".onion")].rsplit(".", 1)[-1]
    if not label or set(label) - set("abcdefghijklmnopqrstuvwxyz234567"):
        return False
    if len(label) == 16:
        return True
    if len(label) != 56:
        return False
    decoded = base64.b32decode(label.upper())
    if len(decoded) != 35 or decoded[34] != 3:
        return False
    key, checksum = decoded[:32], decoded[32:34]
    return checksum == hashlib.sha3_256(b".onion checksum" + key + bytes([3])).digest()[:2]


def _old_host_is_public(host: Any) -> bool:
    name = str(host or "").strip().lower().rstrip(".")
    if not name:
        return False
    if name.endswith(".onion"):
        return _old_onion(name)
    try:
        address = ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        pass
    else:
        return not (address.is_loopback or address.is_unspecified or address.is_link_local)
    if not ne._is_emittable_domain(name) or ne.host_is_private_use(name):
        return False
    labels = name.split(".")
    if not all(re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", label) for label in labels):
        return False
    return bool(re.match(r"^(?:[a-z]{2,}|xn--[a-z0-9-]+)$", labels[-1]))


# Where the order of the tests matters (a second reading strips again), and the
# values a quoted span has to survive.
CONSTRUCTIONS = [
    *(host for host, _ in REASONS),
    "printer.local.\t.",
    "intranet. .",
    "x.corp.\t.",
    "x.alt. .",
    "a.com\n.",
    "ab\n.com",
    "a" * 63 + "\n.com",
    "localhost.localdomain. .",
    "Kaspersky.com",
    "bücher.de",
    "pаypal.com",
    "İstanbul.com",
    "a​b.com",
    "a‮b.com",
    "a;b.com",
    "x;y",
    'a"b.com',
    "a`b.com",
    "\\\\.\\pipe\\x",
    ";" * 70 + ".com",
    "a.com　.",
    "a.com̀0",
    "::ffff:127.0.0.1",
    "fe80::1%eth0",
    "x.home.arpa",
    "a.onion.",
    "x" * 5000,
]


@pytest.mark.parametrize("host", CONSTRUCTIONS)
def test_the_decision_is_the_one_the_rule_made_before(host: str) -> None:
    assert host_is_public(host) is _old_host_is_public(host)
    assert (host_failure(host) == "") is _old_host_is_public(host)
    assert ne.tor_hidden_service(host) is (
        host.strip().lower().rstrip(".").endswith(".onion")
        and _old_onion(host.strip().lower().rstrip("."))
    )


@pytest.mark.parametrize(
    "host",
    [
        "a;b.com",
        "x;y",
        'a"b.com',
        "a‮b.com",
        "a​b.com",
        "a`b.com",
        "\\\\.\\pipe\\x",
        ";" * 70 + ".com",
        "a\r\nb.com",
        "a{U+0062}.com",
    ],
)
def test_a_reason_quotes_its_value_as_text_of_one_reading(host: str) -> None:
    reason = host_failure(host)
    assert reason
    assert ";" not in reason
    assert reason.isprintable()
    assert len(reason) <= 200


def test_two_values_never_print_as_one_span() -> None:
    # An ideographic space, and a combining grave before a zero.
    assert quoted_host_text("com　") != quoted_host_text("com̀0")
    assert quoted_host_text("com　") == '"com{U+3000}"'
    assert quoted_host_text("com̀0") == '"com{U+0300}0"'
    # A written brace opens no escape of its own.
    assert quoted_host_text("{U+0062}") == '"{U+007B}U+0062{U+007D}"'
    assert quoted_host_text("…") == '"{U+2026}"'


def test_a_look_alike_letter_is_named_by_its_code_point() -> None:
    assert host_failure("pаypal.com") == f'its label "pаypal" holds "а" (U+0430), {LABEL_SET}'


def test_a_long_span_stops_on_a_whole_escape() -> None:
    written = quoted_host_text("a" * 35 + "​" * 3)
    assert written == '"' + "a" * 35 + "…" + '"'


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("ocsp.x/y", "it is not a URL — it has no scheme — so there is no host in it to ask about"),
        ("mailto:x@y.com", 'it holds no "://", so there is no host in it to ask about'),
        ("gate9.example.org:443/x", 'it holds no "://", so there is no host in it to ask about'),
        ("http://[::1/", "the URL parser could not read its host"),
        ("http:///x", "the URL parser read no host from it"),
        ("://localhost", "the URL parser read no host from it"),
        ("//localhost/x", 'its host fails the host test: "localhost" is a single label'),
        ("http://3271", 'its host fails the host test: "3271" is a single label'),
        (
            "HTTP://LOCALHOST/",
            'its host fails the host test: "localhost" (read in lower case) is a single label',
        ),
        (
            "http://a.c\t0m/",
            f'its host fails the host test: its last label "c0m" (read with U+0009 removed) '
            f"{LAST_LABEL}",
        ),
        (
            "http://ocsp.sectigo.com0",
            f'its host fails the host test: its last label "com0" {LAST_LABEL}',
        ),
        (
            "http://[FE80::1]/",
            'its host fails the host test: "fe80::1" (read in lower case) is a link-local address',
        ),
        ("\x01//localhost/x", 'its host fails the host test: "localhost" is a single label'),
        ("http://evil.com/x", ""),
        ("//evil.com/x", ""),
    ],
)
def test_a_url_is_given_the_reason_of_the_step_that_refused_it(url: str, reason: str) -> None:
    assert url_failure(url) == reason
    assert host_is_public(url_host(url)) is (reason == "")


SINGLE = 'its host fails the host test: "localhost" is a single label'
LOWER = 'its host fails the host test: "localhost" (read in lower case) is a single label'


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("//localhost/?u=http://evil.com", SINGLE),
        (
            "//a_b.com/?r=http://ok.com",
            f'its host fails the host test: its label "a_b" holds "_" (U+005F), {LABEL_SET}',
        ),
        ("\x01//localhost/?q=http://a.com", SINGLE),
        ("//u@LOCALHOST/?u=http://evil.com", LOWER),
        ("http://LOCALHOST://x@evil.com/", LOWER),
        ("//LOCALHOST#http://evil.com", LOWER),
        ("HTTP://LOCALHOST/?u=ftp://x.com", LOWER),
        ("h\tttp://LOCALHOST/?u=http://evil.com", LOWER),
        ("http:/\t/LOCALHOST/?u=http://evil.com", LOWER),
        ("\t//LOCALHOST/?u=http://evil.com", LOWER),
        # A scheme starts with a letter, so the parser reads none here, and no host.
        ("1http://LOCALHOST/", "the URL parser read no host from it"),
        (
            "http://LOCAL\tHOST/?u=http://evil.com",
            'its host fails the host test: "localhost" (read in lower case, with U+0009 removed) '
            "is a single label",
        ),
        (
            "http://[FE80::1%ETH0]/?u=http://a.com",
            'its host fails the host test: "fe80::1%eth0" (read in lower case) is a link-local '
            "address",
        ),
        ("//evil.com/?u=http://localhost", ""),
    ],
)
def test_a_url_s_host_is_found_where_the_parser_finds_it(url: str, reason: str) -> None:
    # Whatever a path, a query, a fragment or the user part holds after the host,
    # the host quoted is the parser's and its note is how the parser read it.
    assert url_failure(url) == reason
    assert "read from" not in url_failure(url)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("x@a.com0", f'its domain part fails the host test: its last label "com0" {LAST_LABEL}'),
        ("x@localhost", 'its domain part fails the host test: "localhost" is a single label'),
        ("x..y@a.com", "it is not a mailbox by its syntax"),
        ("x@a_b.com", "it is not a mailbox by its syntax"),
        ("x@example.com", ""),
    ],
)
def test_a_mailbox_is_asked_its_syntax_before_the_host_test(value: str, reason: str) -> None:
    assert email_failure(value) == reason
    assert email_is_publishable(value) is (reason == "")


HINT = "; a host is written as domain-name:value. It is unchanged in the judge's own bundle."


@pytest.mark.parametrize(
    ("pattern", "said"),
    [
        (
            "[url:value = 'gate9.example.org']",
            "it is not a URL — it has no scheme — so there is no host in it to ask about" + HINT,
        ),
        (
            "[url:value = 'gate9.example.org:443/x']",
            'it holds no "://", so there is no host in it to ask about' + HINT,
        ),
        (
            "[url:value = '//localhost/x']",
            'its host fails the host test: "localhost" is a single label' + HINT,
        ),
        (
            "[url:value = 'http://3271']",
            'its host fails the host test: "3271" is a single label. It is unchanged in the '
            "judge's own bundle.",
        ),
        (
            "[domain-name:value = 'printer.local']",
            'it fails the host test: it ends in ".local", a suffix this rule lists as reserved. '
            "It is unchanged in the judge's own bundle.",
        ),
        (
            "[network-traffic:dst_ref.value = 'intranet']",
            'it fails the host test: "intranet" is a single label. It is unchanged in the '
            "judge's own bundle.",
        ),
        (
            "[email-addr:value = 'x@localhost']",
            'its domain part fails the host test: "localhost" is a single label. It is '
            "unchanged in the judge's own bundle.",
        ),
        (
            "[email-addr:value = 'x@a_b.com']",
            "it is not a mailbox by its syntax. It is unchanged in the judge's own bundle.",
        ),
    ],
)
def test_a_judge_decline_prints_the_reason_of_the_test_that_ran(pattern: str, said: str) -> None:
    problem = pattern_problem(pattern)
    assert problem is not None
    assert problem[1].endswith("is not in the exported bundle: " + said)


def test_an_address_the_address_question_refused_keeps_its_own_sentence() -> None:
    problem = pattern_problem("[ipv4-addr:value = '127.0.0.1']")
    assert problem is not None
    said = "it is not a name or address that could exist outside the analysed network"
    assert said in problem[1]


def test_an_observed_name_keeps_the_trailer_of_its_network_block() -> None:
    assert unpublishable_domain_sentence("printer.local") == (
        "the domain indicator for 'printer.local' is not in the exported bundle: it fails the "
        'host test: it ends in ".local", a suffix this rule lists as reserved. The report\'s '
        "network block keeps the row with the source that saw it."
    )


def test_an_observed_url_decline_prints_its_host_reason() -> None:
    from malspark.reporting.models import MalwareReport, NetworkIOCs, NetworkURL
    from malspark.reporting.renderers.stix_renderer import _unpublishable_endpoints

    report = MalwareReport.model_construct(
        network=NetworkIOCs(urls=[NetworkURL(url="http://printer.local/x", source="sandbox")])
    )
    (row,) = _unpublishable_endpoints(report, [])
    assert row[1].endswith(
        'is not in the exported bundle: its host fails the host test: it ends in ".local", a '
        "suffix this rule lists as reserved. It is unchanged in the report's network block."
    )


@pytest.mark.parametrize(
    ("value", "printed"),
    [
        ("http://[::1/", "`hxxp://[::1/` (the URL parser could not read its host)"),
        (
            "http://localhost/x",
            '`hxxp://localhost/x` (its host fails the host test: "localhost" is a single label)',
        ),
        ("intranet", '`intranet` (fails the host test: "intranet" is a single label)'),
        # A name on the analysed machine is no host, and is marked with nothing.
        ("\\\\.\\pipe\\x", "`\\\\.\\pipe\\x`"),
    ],
)
def test_the_mark_beside_an_endpoint_is_the_rules_reason(value: str, printed: str) -> None:
    assert _endpoint(value) == printed


def test_no_renderer_words_a_host_reason_of_its_own() -> None:
    src = Path(ne.__file__).resolve().parents[1]
    words = re.compile(
        r"a suffix this rule lists as|is not a letter a-z|not a host outside the analysed network"
    )
    found = [
        str(path.relative_to(src))
        for path in src.rglob("*.py")
        if path.name != "network_extractor.py" and words.search(path.read_text(encoding="utf-8"))
    ]
    assert found == []


def test_a_judge_url_holding_a_second_scheme_is_declined_by_its_own_host() -> None:
    problem = pattern_problem("[url:value = '//localhost/?u=http://evil.com']")
    assert problem is not None
    assert problem[1].endswith(
        'is not in the exported bundle: its host fails the host test: "localhost" is a single '
        "label. It is unchanged in the judge's own bundle."
    )
    marked = _endpoint("//a_b.com/?r=http://ok.com")
    assert marked.startswith(
        "`//a_b.com/?r=http://ok.com` (its host fails the host test: its label"
    )
    assert marked.endswith(f"(U+005F), {LABEL_SET})")


def test_a_url_the_rule_publishes_keeps_the_sentence_it_was_given_before() -> None:
    # Both callers ask only about a URL the rule refused; asked about one it
    # publishes, the sentence prints the clause it always printed, never an
    # empty reason.
    from malspark.reporting.renderers.stix_renderer import impossible_host_sentence

    assert impossible_host_sentence("http://evil.com/x", "W").endswith(
        " is not in the exported bundle: its host is not a name or address that could exist "
        "outside the analysed network. It is unchanged in W."
    )
    assert impossible_host_sentence("//evil.com/x", "W").endswith(
        " is not in the exported bundle: it is not a URL — it has no scheme — so there is no "
        "host in it to ask about; a host is written as domain-name:value. It is unchanged in W."
    )


# URLs the export decides on, written to reach every step: no scheme, a second
# scheme after the host, a stripped or removed character, user parts, ports,
# brackets, fragments and the stored forms (a host and port, a string cut).
URL_CONSTRUCTIONS = [
    *(url for url, _ in [("http://evil.com/x", 0), ("//evil.com/x", 0)]),
    "//localhost/?u=http://evil.com",
    "//a_b.com/?r=http://ok.com",
    "\x01//localhost/?q=http://a.com",
    "//x.local/x?y=ftp://z.com",
    "//evil.com/?u=http://localhost",
    "//LOCALHOST/a",
    "http://u:p@localhost:80/",
    "http://[::1]:80/",
    "http://[FE80::1]/",
    "http://[::1",
    "http://a.com:99999/",
    "HtTp://LocalHost/",
    "http://ho\nst/",
    "http://ho\tst.local/",
    "http://A\t.B/",
    "http:\\\\evil.com\\a",
    "://localhost",
    "mailto:x@localhost",
    "host:80/path",
    "gate9.example.org:443/x",
    "1.2.3.4:80/x",
    "C:\\x",
    "",
    " ",
    "http://",
    "http://.",
    "http://..",
    "http://a..com/",
    "http://-a.com/",
    "http://a.com./",
    "http://a.com../",
    "http://a.com. ./",
    "http://a.com.\t./",
    "http://x\u3000y.com/",
    "http://xn--/",
    "http://%41.com/",
    "http://a{b}.com/",
    "http://a|b.com/",
    "http://a;b.com/",
    "http://" + "a" * 64 + ".com/",
    "http://user@a@b.local/",
    "http://a.local#@evil.com",
    "http://a.local\\@evil.com/",
    "http://evil.com\\@a.local/",
    " http://LOCALHOST/",
    "\x01http://localhost/",
    "\thttp://lo\tcalhost/",
    "h\tttp://LOCALHOST/?u=http://evil.com",
    "http:/\t/LOCALHOST/?u=http://evil.com",
    "http://LOCALHOST://x@evil.com/",
    "//LOCALHOST#http://evil.com",
    "1http://evil.com/",
    "http://[v1.x]/",
    "http://[]/",
    "http:///x",
    "ftp://1.2.3.4.5/",
    "http://0x7f.1/",
    "http://127.1/",
    "http://[::ffff:127.0.0.1]/",
    "http://a.co\u0130/",
    "http://ABCD.onion/",
    f"http://{_onion().upper()}/x",
    f"http://{_onion(4)}/x",
    "http://ocsp.sectigo.com0",
    "http://8.8.8.8/x",
    "http://[2001:4860::8888]/",
    "http://update.example.invalid/x",
    "http://bücher.de/",
    "http://xn--bcher-kva.de/",
]


@pytest.mark.parametrize("url", URL_CONSTRUCTIONS)
def test_one_function_decides_a_url_and_the_decision_is_the_one_made_before(url: str) -> None:
    from malspark.reporting.models import MalwareReport, NetworkIOCs, NetworkURL
    from malspark.reporting.renderers.stix_renderer import (
        _endpoint_is_publishable,
        _unpublishable_endpoints,
    )

    before = _old_host_is_public(url_host(url))
    assert (url_failure(url) == "") is before
    assert _endpoint_is_publishable("url", url) is before
    report = MalwareReport.model_construct(
        network=NetworkIOCs(urls=[NetworkURL(url=url, source="sandbox")])
    )
    assert (_unpublishable_endpoints(report, []) == []) is before


# ---------------------------------------------------------------------------
# Every quoted span is the written text, or says how it was read
# ---------------------------------------------------------------------------

_PIECES = [
    *"abcdefgxyzABCXYZ0123456789",
    *'..--_:@/?#[]%{};`"\\',
    "\t",
    "\n",
    "\r",
    " ",
    "\x01",
    "\u3000",
    "\u0301",
    "\u200b",
    "\u202e",
    "\u0130",
    "\u212a",
    "\u03a3",
    "\u0391",
    "\u00df",
    "\u00c4",
    "\u2026",
    "U+0041",
    "://",
    "//",
    "localhost",
    "LOCALHOST",
    "local",
    ".LOCAL",
    ".home.ARPA",
    ".Corp",
    ".com",
    ".COM0",
    ".onion",
    ".ONION",
    "xn--",
    "abcdefghijklmnop",
    "a" * 60,
    "FE80::1",
    "127.0.0.1",
]
_SCHEMES = ["", "http://", "HTTP://", "//", "\x01//", " h\tttp://", "http:/\t/", "x1+.-:"]
_READ_NOTE = re.compile(r" \(read (?:in lower case|with )")


def _hostile(rng: Any) -> str:
    return "".join(rng.choice(_PIECES) for _ in range(rng.randint(1, 9)))


def _values() -> list[tuple[str, str]]:
    import random

    rng = random.Random(782)
    out: list[tuple[str, str]] = []
    for _ in range(300):
        out.append(("host", _hostile(rng)))
        tail = rng.choice(["", "/", "/?u=http://evil.com", "#ftp://x", ":80/", "\t."])
        out.append(("url", rng.choice(_SCHEMES) + _hostile(rng) + tail))
        out.append(("mailbox", _hostile(rng) + "@" + _hostile(rng)))
    for _ in range(60):
        out.append(
            ("host", _onion().upper()[: rng.randint(10, 56)] + rng.choice(_PIECES) + ".onion")
        )
    return out


def _unwritten(span: str) -> str:
    """A quoted span with the writer's own ``…`` taken off and each ``{U+XXXX}`` undone."""
    span = span.removesuffix("…")
    return re.sub(r"\{U\+([0-9A-F]{4,6})\}", lambda m: chr(int(m.group(1), 16)), span)


# The rule's own words in quotes, which no value supplies.
_RULE_QUOTES = {'".onion"', '"://"'}


@pytest.mark.parametrize(("kind", "value"), _values())
def test_every_quoted_span_is_the_written_text_or_says_how_it_was_read(
    kind: str, value: str
) -> None:
    if kind == "host":
        reason = host_failure(value)
    elif kind == "url":
        reason = url_failure(value)
    else:
        reason = email_failure(value)
    # A reading is named by what changed, never by another text it came from.
    assert " (read from " not in reason, (reason, value)
    host = ""
    if kind == "url":
        from urllib.parse import urlsplit

        try:
            host = (urlsplit(value).hostname or "").casefold()
        except ValueError:
            host = ""
    for found in re.finditer(r'"[^"]*"', reason):
        span = _unwritten(found.group(0)[1:-1])
        if found.group(0) in _RULE_QUOTES:
            continue
        if kind == "url":
            # A URL's quoted span lies in the host the parser reads at its place.
            read_span = "".join(ch for ch in span if ch not in "\t\r\n").casefold()
            assert read_span in host, (reason, value)
        note = _READ_NOTE.match(reason, found.end())
        if note is None:
            assert span in value, (reason, value)
            continue
        # A span read another way is that reading of the written text.
        read = value
        if "removed" in reason[found.end() :].split(")", 1)[0]:
            read = "".join(ch for ch in value if ch not in "\t\r\n")
        assert span.casefold() in read.casefold(), (reason, value)
