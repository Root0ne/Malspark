"""Score a domain, and decide whether an address is worth reporting.

This module used to pull the whole network section out of a sandbox report
inside the report builder. It does not any more — the report is assembled from
what the agents' tools returned — and what is left is the part that was never
extraction: the DGA scorer, the IDN homograph check and the emittable-address
rules that decide whether an observed indicator is worth reporting at all.

``reporting.ledger_projection`` applies the scorer to the domains a run
actually observed, and the score reaches the report as the ``is_suspicious``
flag on an observed domain — a described property of something a tool saw, not
a technique claim asserted over an analyst's head.
"""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from dataclasses import dataclass, replace
from typing import Any

# Domains we never want to flag as suspicious — common SaaS / OS update
# infrastructure, whose content is the provider's own. Extend rather than
# replace; a name under which tenants publish their own content belongs in
# ``_SHARED_HOSTING_DOMAINS`` instead, never here.
_BENIGN_DOMAINS: frozenset[str] = frozenset(
    {
        "microsoft.com",
        "windowsupdate.com",
        "windows.com",
        "msftncsi.com",
        "msftconnecttest.com",
        "apple.com",
        "icloud.com",
        "google.com",
        "gstatic.com",
        "cloudflare.com",
        "gvt1.com",
        "ntp.org",
        "pool.ntp.org",
        "debian.org",
        "ubuntu.com",
        "archlinux.org",
    }
)


# Multi-tenant hosting: cloud storage, CDN edges and package CDNs, where anyone
# publishes their own content under the provider's name. Two tiers, as data:
#
# - a provider service host, the provider's own endpoint (``storage.``
#   ``googleapis.com``, ``s3.us-east-1.amazonaws.com``, ``cdn.jsdelivr.net``),
#   is well-known benign as before: published only as itself, never through a
#   URL on it. ``service`` fully matches the part of such a host left of the
#   registered name (``""`` is the bare registered name);
# - every other name under it is a tenant's (a bucket, a CloudFront
#   distribution, a Fastly customer name, an Akamai edge label): assessed like
#   any other name, marked shared hosting, and published only on evidence of
#   its own, never because a URL on it is. Where the provider, not the tenant,
#   assigns those labels (``assigned`` fully matches the part left of the
#   registered name), no DGA score is taken from them: a distribution id is
#   random by construction.
@dataclass(frozen=True)
class _SharedHosting:
    service: re.Pattern[str]
    assigned: re.Pattern[str] | None = None


_AWS_REGION = r"[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d"
_SHARED_HOSTING: dict[str, _SharedHosting] = {
    # One label under googleapis.com is a Google API endpoint (www, storage,
    # fonts, update, safebrowsing); a bucket is ``<bucket>.storage...``.
    "googleapis.com": _SharedHosting(re.compile(r"[a-z0-9-]*")),
    # S3's and every service's own endpoints, global or regional, dual-stack
    # or not; buckets, EC2 instance names and API ids sit left of them.
    "amazonaws.com": _SharedHosting(
        re.compile(
            rf"(?:[a-z0-9-]+(?:\.dualstack)?(?:\.{_AWS_REGION})?"
            rf"|s3[.-](?:dualstack\.)?{_AWS_REGION})?"
        ),
        assigned=re.compile(
            r"ec2-\d{1,3}(?:-\d{1,3}){3}\..+|[a-z0-9]{10}\.execute-api\..+"
            r"|[a-z0-9]{32}\.lambda-url\..+"
        ),
    ),
    "cloudfront.net": _SharedHosting(re.compile(r""), assigned=re.compile(r".+")),
    "akamaiedge.net": _SharedHosting(re.compile(r""), assigned=re.compile(r".+")),
    "akamai.net": _SharedHosting(re.compile(r""), assigned=re.compile(r".+")),
    # Fastly's own map and SNI names; ``<customer>.global.ssl.fastly.net`` is
    # a name the customer chose.
    "fastly.net": _SharedHosting(
        re.compile(
            r"(?:(?:[a-z0-9-]+\.)?(?:sni\.)?global(?:\.prod)?|global\.ssl"
            r"|(?:dualstack\.)?(?:[a-z0-9-]+\.)*map|freetls|prod)?"
        )
    ),
    # jsDelivr's own CDN endpoints; it gives no tenant a name of its own.
    "jsdelivr.net": _SharedHosting(
        re.compile(r"(?:cdn|fastly|gcore|testingcf|quantil|originfastly|data|purge|www)?")
    ),
}
SHARED_HOSTING_REASON = "shared hosting: its tenants publish their own content under it"
SHARED_HOSTING_MARK = "(shared hosting)"


# Public resolvers a sample asks to test its connectivity: an address on
# this list is benign infrastructure the way a listed name is.
_PUBLIC_RESOLVERS = frozenset(
    {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "149.112.112.112",
        "208.67.222.222",
        "208.67.220.220",
    }
)


def is_public_resolver(address: Any) -> bool:
    """Whether ``address`` is one of the public DNS resolvers this list names."""
    return str(address or "").strip().strip("[]") in _PUBLIC_RESOLVERS


# Second-level labels a country code registers names under: ``example.co.uk``
# is the registered name, not ``co.uk``.
_SECOND_LEVEL_LABELS = frozenset({"co", "com", "net", "org", "ac", "gov", "edu", "or", "ne"})


def is_well_known_benign_host(host: str) -> bool:
    """Whether ``host`` sits under a registered name of the benign-infrastructure list.

    The registered name is the last two labels, or the last three under a
    country code's second level (``*.co.uk``). An address is benign when it
    is a public resolver's.
    """
    text = str(host or "").strip().lower().rstrip(".")
    if text in _PUBLIC_RESOLVERS:
        return True
    return _registered_name(text) in _BENIGN_DOMAINS or _shared_tier(text) == "service"


def _shared_tier(text: str) -> str:
    """``"service"``, ``"tenant"`` or ``"assigned"`` (a tenant's provider-assigned
    name) for a lowercased host on shared hosting; ``""`` for any other host."""
    registered = _registered_name(text)
    hosting = _SHARED_HOSTING.get(registered)
    if hosting is None:
        return ""
    left = text[: -len(registered)].rstrip(".")
    if hosting.service.fullmatch(left):
        return "service"
    if hosting.assigned is not None and hosting.assigned.fullmatch(left):
        return "assigned"
    return "tenant"


def _host_text(host: Any) -> str:
    return str(host or "").strip().lower().rstrip(".")


def _registered_name(text: str) -> str:
    """The registered name of a lowercased host: the last two labels, or three
    under a country code's second level; ``""`` for a single label."""
    parts = text.split(".")
    if len(parts) < 2:
        return ""
    registered = ".".join(parts[-2:])
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL_LABELS:
        registered = ".".join(parts[-3:])
    return registered


def is_shared_hosting(host: str) -> bool:
    """Whether ``host`` sits under a multi-tenant hosting name (``_SHARED_HOSTING``)."""
    return bool(_shared_tier(_host_text(host)))


def is_shared_hosting_tenant(host: str) -> bool:
    """Whether ``host`` is a tenant's name on shared hosting, not the provider's endpoint.

    Such a name is published on evidence of its own (a model or the judge
    keeping it, the sample's own resolution or connection, a recovery), never
    because a published URL carries it.
    """
    return _shared_tier(_host_text(host)) in ("tenant", "assigned")


def host_rides_a_url(host: str) -> bool:
    """Whether a published URL on ``host`` publishes ``host`` too.

    Not for a well-known benign host (a CDN's or a cloud API's endpoint is
    not the sample's C2 because a URL on it is), nor for a tenant's name on
    shared hosting, which needs evidence of its own.
    """
    return not is_well_known_benign_host(host) and not is_shared_hosting_tenant(host)


# RFC 6761/6762 reserved suffixes that must never be emitted as network IOCs.
_RESERVED_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".localhost",
    ".test",
    ".example",
    ".invalid",
    ".arpa",
)

# The suffixes no public DNS answers under: the ones a private network names its
# own machines with, and one for names outside the DNS. Publishing one is
# a low-value indicator in a shared bundle and a small disclosure of how the
# analysis network is named, so no export carries one — but that is an export
# decision and not a projection one. A sandbox that resolved
# ``fileserver.corp.internal`` watched the sample resolve it, which is the
# thing an analyst reading a lateral-movement case most needs to see, and the
# report's network block keeps the row with its source. ``host_is_private_use``
# is the one reader of these, and it is asked where an indicator is minted and
# where a name is about to be sent to a reputation provider.
#
# ``.internal`` and ``.home.arpa`` are reserved for private networks' own names,
# and ``.alt`` for names that are not DNS names at all (RFC 9476), so none of the
# three is ever looked up in the DNS. The rest are not reserved by anybody and are
# used for private names anyway, and none of the four has ever been delegated, so
# a name under one cannot be looked up from outside the network that invented it.
_PRIVATE_USE_SUFFIXES: tuple[str, ...] = (
    ".internal",
    ".alt",
    ".home.arpa",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
)
_RESERVED_DOMAIN_NAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain"})


def host_is_private_use(host: Any) -> bool:
    """Whether this name belongs to a private network rather than to the internet.

    One list, two readers. The export asks it before minting an indicator and
    the enrichment asks it before sending a name to a reputation provider, and
    the two answering differently is how ``x.alt`` and
    ``localhost.localdomain`` were held out of one bundle and posted to a
    public provider in the same run.
    """
    name = str(host or "").strip().rstrip(".").lower()
    if not name:
        return True
    if name in _RESERVED_DOMAIN_NAMES:
        return True
    return any(
        name.endswith(suffix) for suffix in _RESERVED_DOMAIN_SUFFIXES + _PRIVATE_USE_SUFFIXES
    )


# Substrings that strongly suggest C2 / commodity-malware infra (``.bit`` is a TLD, tested apart).
_SUSPICIOUS_DOMAIN_TOKENS: tuple[str, ...] = (
    ".onion",
    "duckdns",
    "no-ip",
    "ddns.net",
    "ngrok.io",
    "pastebin",
    "transfer.sh",
    "anonfiles",
    "tempuri.org",
)

# ---------------------------------------------------------------------------
# DGA scoring
# ---------------------------------------------------------------------------
# A label whose composite score (Shannon entropy + bigram rarity + supporting
# signals) clears this threshold is treated as algorithmically generated
# (surfaced as ``is_suspicious`` in the NETWORK tab).
_DGA_SCORE_THRESHOLD: float = 0.55
# Labels shorter than this are never scored as DGA. Short brandable names
# (e.g. "facebook", "telegram") have inflated normalised entropy simply
# because they have few repeated characters, so scoring them invites false
# positives. 10 matches the legacy heuristic's floor.
_DGA_MIN_LABEL_LEN: int = 10

# Most-common English letter bigrams. A natural-language label is dense in
# these; a random/DGA label is sparse — the classic "gibberish detector"
# signal. Membership-based (not full log-prob) to keep the table compact and
# the result deterministic + trivially testable.
_COMMON_BIGRAMS: frozenset[str] = frozenset(
    {
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "io",
        "le",
        "ve",
        "co",
        "me",
        "de",
        "hi",
        "ri",
        "ro",
        "ic",
        "ne",
        "ea",
        "ra",
        "ce",
        "li",
        "ch",
        "ll",
        "be",
        "ma",
        "si",
        "om",
        "ur",
        "ca",
        "el",
        "ta",
        "la",
        "ns",
        "di",
        "fo",
        "ho",
        "pe",
        "ec",
        "pr",
        "no",
        "ct",
        "us",
        "ac",
        "ot",
        "il",
        "tr",
        "ly",
        "nc",
        "et",
        "ut",
        "ss",
        "so",
        "rs",
        "un",
        "lo",
        "wa",
        "ge",
        "ie",
        "wh",
        "ee",
        "wi",
        "em",
        "ad",
        "ol",
        "rt",
        "po",
        "we",
        "na",
        "ul",
        "ni",
        "ts",
        "mo",
        "ow",
        "pa",
        "im",
        "mi",
        "ai",
        "sh",
        "ir",
        "su",
        "id",
        "os",
        "ia",
        "am",
        "fi",
        "ci",
        "ig",
        "ab",
        "ap",
        "do",
        "ds",
        "ru",
        "tu",
        "ess",
        "men",
    }
)

# Vowels used by the consonant-run / vowel-ratio supporting signals.
_VOWELS: frozenset[str] = frozenset("aeiou")

# ---------------------------------------------------------------------------
# IDN / punycode homograph
# ---------------------------------------------------------------------------
# Confusable (Cyrillic / Greek) -> ASCII skeleton. Used to decide whether a
# decoded IDN label is a look-alike of a well-known brand. Kept compact; the
# common Latin look-alikes cover the overwhelming majority of homograph abuse.
_CONFUSABLE_TO_ASCII: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ѕ": "s",
    "һ": "h",
    "ј": "j",
    "ӏ": "i",
    "ԁ": "d",
    "ԛ": "q",
    "ɡ": "g",
    # Greek
    "ο": "o",
    "α": "a",
    "ρ": "p",
    "ν": "v",
    "ι": "i",
}

# Brand "skeletons" (ASCII, no TLD) worth flagging as homograph targets.
_HOMOGRAPH_BRANDS: frozenset[str] = frozenset(
    {
        "paypal",
        "google",
        "apple",
        "microsoft",
        "amazon",
        "facebook",
        "binance",
        "netflix",
        "instagram",
        "whatsapp",
        "coinbase",
        "github",
        "dropbox",
        "linkedin",
        "twitter",
        "outlook",
        "office",
        "yahoo",
        "wellsfargo",
        "chase",
        "steamcommunity",
        "steampowered",
    }
)


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DomainVerdict:
    """Outcome of scoring one FQDN — the single source of truth for the
    sandbox-report extractor so every domain is judged identically."""

    suspicious: bool
    reason: str | None = None
    dga_score: float | None = None
    is_punycode: bool = False
    homograph_target: str | None = None


def _assess_domain(fqdn: str) -> _DomainVerdict:
    """``_scored_domain``, with shared hosting read by its tier (``_SHARED_HOSTING``).

    A provider's service host is benign, as a listed name is. A tenant's name
    is scored on its own labels only, and on none the provider assigned (no
    DGA score from a distribution id); the homograph and token checks read
    the whole name as for any other. A suspicious one keeps its reason with
    ``(shared hosting)`` after it; one found not suspicious carries
    ``SHARED_HOSTING_REASON``.
    """
    text = _host_text(fqdn)
    tier = _shared_tier(text)
    if not tier:
        return _scored_domain(fqdn)
    if tier == "service":
        return _DomainVerdict(suspicious=False)
    left = text[: -len(_registered_name(text))].rstrip(".")
    verdict = _scored_domain(fqdn, dga_labels=[] if tier == "assigned" else left.split("."))
    reason = (
        f"{verdict.reason} {SHARED_HOSTING_MARK}" if verdict.suspicious else SHARED_HOSTING_REASON
    )
    return replace(verdict, reason=reason)


def _scored_domain(fqdn: str, dga_labels: list[str] | None = None) -> _DomainVerdict:
    """Score an FQDN for suspicion. Order: benign allowlist -> IDN/punycode
    homograph -> C2/commodity tokens -> DGA score.

    Homograph and DGA checks scan every label except the trailing TLD (not
    just the leftmost), so a look-alike or algorithmic label that sits in a
    subdomain — ``login.pаypal.com`` — or under a multi-level public suffix —
    ``xjqz8frandom.co.uk`` — is still caught. ``dga_labels``, when given, are
    the only labels the DGA score reads (none: no score, ``dga_score`` None).
    """
    lower = fqdn.lower()
    parts = lower.rstrip(".").split(".")
    # Strip subdomains for the benign check.
    if len(parts) >= 2:
        registered = ".".join(parts[-2:])
        if registered in _BENIGN_DOMAINS:
            return _DomainVerdict(suspicious=False)

    # Labels to inspect: everything except the trailing TLD label.
    labels = parts[:-1] if len(parts) >= 2 else parts

    # IDN / punycode homograph — scan all inspected labels (checked before
    # tokens so a look-alike of a benign brand is still flagged).
    is_puny_any = False
    for label in labels:
        is_puny, homograph = _idn_assessment(label)
        is_puny_any = is_puny_any or is_puny
        if homograph is not None:
            kind = "punycode IDN" if is_puny else "mixed-script"
            return _DomainVerdict(
                suspicious=True,
                reason=f"IDN homograph ({kind}, looks like '{homograph}')",
                is_punycode=is_puny,
                homograph_target=homograph,
            )

    # ``.bit`` is a TLD (Namecoin), so it is read as the last label: as a
    # substring it also flagged bitdefender.com and bitbucket.org.
    if parts[-1] == "bit" and len(parts) >= 2:
        return _DomainVerdict(suspicious=True, reason="contains '.bit'", is_punycode=is_puny_any)
    for token in _SUSPICIOUS_DOMAIN_TOKENS:
        if token in lower:
            return _DomainVerdict(
                suspicious=True, reason=f"contains '{token}'", is_punycode=is_puny_any
            )

    # DGA — score each inspected label and keep the most suspicious one.
    best_label, best_score = "", 0.0
    scored = labels if dga_labels is None else dga_labels
    if not scored:
        return _DomainVerdict(suspicious=False, is_punycode=is_puny_any)
    for label in scored:
        s = _dga_score(label)
        if s > best_score:
            best_score, best_label = s, label
    if best_score >= _DGA_SCORE_THRESHOLD:
        ent = _normalised_entropy(best_label)
        rarity = _bigram_rarity(best_label)
        return _DomainVerdict(
            suspicious=True,
            reason=(
                f"DGA-like (score {best_score:.2f}: entropy {ent:.2f}, bigram-rarity {rarity:.2f})"
            ),
            dga_score=round(best_score, 3),
            is_punycode=is_puny_any,
        )

    return _DomainVerdict(suspicious=False, dga_score=round(best_score, 3), is_punycode=is_puny_any)


def _normalised_entropy(label: str) -> float:
    """Shannon entropy of the label's character distribution, normalised to
    [0,1] by the maximum entropy for its length (random strings -> ~1.0)."""
    chars = [c for c in label if c != "."]
    n = len(chars)
    if n < 2:
        return 0.0
    counts: dict[str, int] = {}
    for c in chars:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum((k / n) * math.log2(k / n) for k in counts.values())
    max_entropy = math.log2(n)
    return entropy / max_entropy if max_entropy > 0 else 0.0


def _bigram_rarity(label: str) -> float:
    """Fraction of adjacent letter-bigrams NOT in the common-English set
    (1.0 -> every bigram is unusual; 0.0 -> all natural-language-like)."""
    letters = [c for c in label if c.isalpha()]
    if len(letters) < 2:
        return 0.0
    bigrams = ["".join(letters[i : i + 2]) for i in range(len(letters) - 1)]
    rare = sum(1 for bg in bigrams if bg not in _COMMON_BIGRAMS)
    return rare / len(bigrams)


def _max_consonant_run(label: str) -> int:
    run = best = 0
    for c in label:
        if c.isalpha() and c not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _dga_score(label: str) -> float:
    """Composite DGA likelihood in [0,1] for a single domain label.

    Combines normalised Shannon entropy, common-bigram rarity, digit ratio,
    a long-consonant-run signal, and the legacy consonant ratio. Deterministic
    and dependency-free so it is trivially testable and reproducible.
    """
    if len(label) < _DGA_MIN_LABEL_LEN:
        return 0.0
    alpha = [c for c in label if c.isalpha()]
    if not alpha:
        return 0.0

    entropy = _normalised_entropy(label)
    rarity = _bigram_rarity(label)
    digits = sum(1 for c in label if c.isdigit())
    digit_ratio = digits / len(label)
    consonants = sum(1 for c in alpha if c not in _VOWELS)
    consonant_ratio = consonants / len(alpha)
    long_run = 1.0 if _max_consonant_run(label) >= 5 else 0.0

    # Weighted blend. Bigram rarity is the strongest discriminator; entropy is
    # weighted down because it saturates for short distinct strings; the legacy
    # consonant ratio is retained as a minor contributor for continuity.
    score = (
        0.50 * rarity
        + 0.20 * entropy
        + 0.12 * min(digit_ratio * 2.0, 1.0)
        + 0.10 * long_run
        + 0.08 * consonant_ratio
    )
    return min(score, 1.0)


def _idn_assessment(label: str) -> tuple[bool, str | None]:
    """Detect IDN/punycode homographs on a single domain label.

    Returns ``(is_punycode, homograph_target)``. ``homograph_target`` is set
    when the label:

      * skeletonises (via the confusable map) onto a known brand — this also
        catches a fully non-Latin spoof such as an all-Cyrillic ``paypal``; or
      * mixes scripts (Latin + Cyrillic/Greek letters in the same label) — the
        defining signature of a homograph attack, even when it doesn't match a
        brand.

    A pure-ASCII label, or a legitimate single-script IDN (e.g. an all-Cyrillic
    Russian word that isn't a brand spoof), is never flagged.
    """
    is_puny = label.startswith("xn--")
    decoded = label
    if is_puny:
        try:
            decoded = label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            # Undecodable punycode is itself anomalous, but we have no target.
            return True, None

    # Plain ASCII (and not punycode) carries no homograph risk.
    if decoded.isascii() and not is_puny:
        return False, None

    skeleton = "".join(_CONFUSABLE_TO_ASCII.get(c, c) for c in decoded)
    skeleton_ascii = skeleton if skeleton.isascii() else None

    # Brand spoof — works for mixed-script *and* all-confusable single-script
    # look-alikes (e.g. an all-Cyrillic rendering of "paypal").
    if skeleton_ascii is not None:
        core = skeleton_ascii.strip("-")
        if core in _HOMOGRAPH_BRANDS:
            return is_puny, core

    # Mixed-script homograph: a single label containing BOTH Latin and
    # non-Latin letters is the classic look-alike signature.
    has_latin = any(ch.isalpha() and _is_latin(ch) for ch in decoded)
    has_non_latin = any(ch.isalpha() and not _is_latin(ch) for ch in decoded)
    if has_latin and has_non_latin:
        return is_puny, skeleton_ascii or decoded

    return is_puny, None


def _is_latin(ch: str) -> bool:
    try:
        return "LATIN" in unicodedata.name(ch)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# IPs
# ---------------------------------------------------------------------------


def _is_emittable_ip(ip: str) -> bool:
    """True only for routable public addresses worth emitting as an IOC.

    Drops private / loopback / multicast / reserved / link-local / unspecified /
    broadcast — these are sandbox/test noise, never malware infrastructure, and
    pollute CTI feeds + waste threat-intel API budget.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_unspecified
    ):
        return False
    return str(addr) != "255.255.255.255"


def is_private_flow_address(ip: str) -> bool:
    """Whether ``ip`` is a private, loopback or link-local unicast address.

    Not an indicator — ``_is_emittable_ip`` keeps those out of every export —
    but a flow to one is a fact about the run: lateral movement and a local
    C2 or proxy live there. Multicast, broadcast, unspecified and reserved
    addresses are none of these.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


# A v3 onion address is the base32 of a 32-byte key, a 2-byte checksum over
# it and a version byte; v2 is sixteen base32 characters and carries no
# checksum, so length and alphabet are all there is to check.
_TOR_SUFFIX = ".onion"
_TOR_V3_LENGTH = 56
_TOR_V2_LENGTH = 16
_TOR_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_TOR_V3_VERSION = 3
_TOR_CHECKSUM_SALT = b".onion checksum"


def tor_hidden_service(fqdn: Any) -> bool:
    """Whether ``fqdn`` is a syntactically valid Tor onion address.

    Checked rather than assumed: a v3 address carries its own checksum, so
    fifty-six characters of the right alphabet are not enough — the last three
    bytes have to check out against the first thirty-two, which is what makes
    the name impossible to produce by accident.
    """
    name = str(fqdn or "").strip().lower().rstrip(".")
    return name.endswith(_TOR_SUFFIX) and not _onion_failure(name)


def _onion_failure(name: str, written_name: str | None = None) -> str:
    """Why a name ending in ``.onion`` is no hidden-service address, ``""`` when it is one.

    One reason per test, in the order :func:`tor_hidden_service` asks them.
    ``written_name`` is the name as it was written, whose label at the same
    place is quoted with how it was read (:func:`host_failure`).
    """
    import base64
    import hashlib

    label = name[: -len(_TOR_SUFFIX)].rsplit(".", 1)[-1]
    if not label:
        return 'its label before ".onion" is empty'
    given = _written_labels(name.split("."), written_name)[-2]
    written = _quoted_as_read(label, given)
    stray = _refused_character(label, given, _TOR_ALPHABET)
    if stray:
        return (
            f"its .onion label {written} holds {quoted_host_text(stray)} ({code_point(stray)}), "
            "which is not in the base32 alphabet a-z, 2-7"
        )
    if len(label) == _TOR_V2_LENGTH:
        return ""
    if len(label) != _TOR_V3_LENGTH:
        return (
            f"its .onion label {written} is {len(label)} characters long, and this rule "
            f"accepts {_TOR_V2_LENGTH} or {_TOR_V3_LENGTH}"
        )
    try:
        # Fifty-six base32 characters are exactly thirty-five bytes, so the
        # encoding needs no padding and adding any would corrupt it.
        decoded = base64.b32decode(label.upper())
    except Exception:  # noqa: BLE001 — a name that will not decode is not one
        decoded = b""
    if len(decoded) != 35:
        return f"its .onion label {written} does not decode as base32"
    if decoded[34] != _TOR_V3_VERSION:
        return (
            f"its .onion label {written} carries version {decoded[34]}, and this rule "
            f"accepts {_TOR_V3_VERSION}"
        )
    public_key, checksum = decoded[:32], decoded[32:34]
    expected = hashlib.sha3_256(
        _TOR_CHECKSUM_SALT + public_key + bytes([_TOR_V3_VERSION])
    ).digest()[:2]
    if checksum == expected:
        return ""
    return f"its .onion label {written} fails the hidden-service checksum"


def corroboration_reason(source: Any, reputation: Any, fqdn: Any = "") -> str | None:
    """Why this name may be published, or ``None`` when nothing says it may.

    Named rather than left implicit because one of the answers is surprising:
    a Tor address is published on the strength of its own syntax, and a reader
    finding it in a bundle beside no sandbox observation is owed the reason.
    """
    if source != "strings":
        return str(source) if source else "recorded without a source"
    if tor_hidden_service(fqdn):
        return "tor hidden service address, valid on its own syntax"
    if isinstance(reputation, dict):
        for key in ("malicious", "suspicious"):
            try:
                if int(reputation.get(key) or 0) > 0:
                    return "a reputation provider has a record of it"
            except (TypeError, ValueError):
                continue
    return None


def url_host(raw_url: Any) -> str:
    """The host of a URL, lowercased, or ``""`` when it has none."""
    from urllib.parse import urlparse

    try:
        return (urlparse(str(raw_url or "")).hostname or "").strip().lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


def host_form(value: Any) -> str:
    """One host in the form two writers of it share, ``""`` for none.

    A host as a sandbox or a URL writes it: a port is split off (``host:443``,
    ``[2001:db8::1]:443``), IPv6 brackets are taken off, a trailing dot is
    dropped, an address is written in its canonical form (``2001:DB8:0::1`` is
    ``2001:db8::1``), an internationalised name in its IDNA (punycode) form and
    every name in lower case. Read the same way on both sides of a comparison,
    so a name in DNS and the host of a URL are one value when they are one host.
    """
    text = str(value or "").strip()
    if text.startswith("["):
        inner, bracket, _rest = text[1:].partition("]")
        text = inner if bracket else text
    else:
        try:
            return str(ipaddress.ip_address(text.rstrip(".")))
        except ValueError:
            pass
        name, colon, port = text.rpartition(":")
        if colon and port.isdigit() and ":" not in name:
            text = name
    text = text.rstrip(".")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    try:
        return text.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return text.lower()


# One DNS label: letters, digits and hyphens, not starting or ending with a
# hyphen, at most sixty-three characters. The internet's own rule, which is the
# only rule that can be applied to a name nobody has tried to resolve.
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_LABEL_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")

# The last label of a name that could exist: two or more letters, or a
# punycode label. Deliberately a shape and not a list — a 136-entry list of
# TLDs omits `gov`, `edu`, `mobi`, every punycode TLD and most African and
# Middle-Eastern ccTLDs, and a sandbox-observed request to a university host is
# not a string sweep's cut-off.
_PUBLIC_SUFFIX_RE = re.compile(r"^(?:[a-z]{2,}|xn--[a-z0-9-]+)$")


def host_is_public(host: Any) -> bool:
    """Whether ``host`` is a name or address that could exist on the internet.

    A string sweep cuts hostnames wherever the surrounding bytes end, and the
    pieces are shaped like URLs: ``http://localho``, ``https://q``,
    ``http://3271``. Five of them were published as STIX indicators in one live
    run, each one something a consumer would block on.

    This asks one question only — could anything ever answer for this host —
    and it is deliberately the weakest question in the chain. Whether an
    endpoint that *could* exist is published is
    :func:`corroboration_reason`'s decision, not this one, so a plausible name
    the file's bytes alone know about is still held back for want of a second
    source rather than for the shape of its name.

    A Tor address is first, and for the reason it is first everywhere else:
    ``.onion`` never resolves, its own checksum is the only thing that can
    confirm it, and holding it to any other rule makes the strongest
    string-derived indicator there is unpublishable by every path.

    The answer is :func:`host_failure`'s, so the reason a refused host is
    given and the decision are one reading.
    """
    return host_failure(host) == ""


# How a value is quoted inside a reason the rule gives. Each character prints as
# itself except those written out as ``{U+XXXX}``: every one that is not
# printable, whitespace, a combining mark, the quote, the backslash, ``;``, the
# backtick, ``…`` and the two braces. The braces are written out so that a ``{``
# in a quoted span always opens an escape and its ``}`` always closes it: two
# values never print as one span, and an escape never runs into the digits after
# it. A span stops before the character that would take it past forty written
# characters, and the ``…`` after it is the writer's own (a value's is written out).
_QUOTE_WRITTEN_OUT = frozenset('"\\;`…{}')
_QUOTE_LIMIT = 40


def code_point(ch: str) -> str:
    """One character's code point, as ``U+0430``."""
    return f"U+{ord(ch):04X}"


def _quoted_char(ch: str) -> str:
    if (
        ch in _QUOTE_WRITTEN_OUT
        or ch.isspace()
        or not ch.isprintable()
        or unicodedata.category(ch).startswith("M")
    ):
        return "{" + code_point(ch) + "}"
    return ch


def quoted_host_text(span: str) -> str:
    """``span`` quoted as a reason of the host rule prints it (the table above)."""
    out: list[str] = []
    size = 0
    for ch in str(span):
        written = _quoted_char(ch)
        if size + len(written) > _QUOTE_LIMIT:
            out.append("…")
            break
        out.append(written)
        size += len(written)
    return '"' + "".join(out) + '"'


# The characters the URL parser removes wherever they stand in a URL, and those
# it strips from the front of one (the C0 controls and the space).
_URL_REMOVED = "\t\r\n"
_URL_STRIPPED = "".join(chr(code) for code in range(0x21))


def _lowered(written: str, read: str) -> bool:
    """Whether ``read`` is ``written`` in lower case, a final sigma lowered by its place."""
    return written.lower() == read or written.casefold() == read.casefold()


def _read_note(written: str | None, read: str) -> str:
    """What the host test read differently from what was written, as `` (read …)``.

    ``""`` where the two are one text or nothing written is known. ``read`` is
    ``written`` as the test reads it, so the note is named by what changed:
    the case folded, a tab or line break the URL parser removed.
    """
    if written is None or written == read:
        return ""
    if _lowered(written, read):
        return " (read in lower case)"
    cleaned = "".join(ch for ch in written if ch not in _URL_REMOVED)
    changes = ["in lower case"] if cleaned != read else []
    removed = sorted({ch for ch in written if ch in _URL_REMOVED})
    changes.append("with " + " and ".join(code_point(ch) for ch in removed) + " removed")
    return f" (read {', '.join(changes)})"


def _quoted_as_read(read: str, written: str | None) -> str:
    return quoted_host_text(read) + _read_note(written, read)


def _written_labels(labels: list[str], written: str | None) -> list[str | None]:
    """The written name's labels at the places of ``labels``; ``None`` each where none is known."""
    parts: list[str | None] = list(written.split(".")) if written is not None else []
    return parts if len(parts) == len(labels) else [None] * len(labels)


def _refused_character(read: str, written: str | None, allowed: frozenset[str]) -> str:
    """The first character of ``read`` outside ``allowed``, named as the value writes it.

    The written character whose reading holds it: a capital the test read in
    lower case is named as written, and a character the URL parser removed is
    passed over. ``""`` where every character is allowed.
    """
    stray = next((ch for ch in read if ch not in allowed), "")
    if not stray or written is None:
        return stray
    passed = set(_URL_REMOVED) - set(read)
    return next(
        (
            ch
            for ch in written
            if ch not in passed and any(one not in allowed for one in ch.lower())
        ),
        stray,
    )


def host_failure(host: Any, given: Any = None) -> str:
    """Why ``host`` is no name or address that could exist on the internet, ``""`` when it is one.

    The tests :func:`host_is_public` answers by, in the order they run, each
    with its own reason naming the test and what it read. ``given`` is the
    host as a URL writes it, when the caller read ``host`` out of a URL (the
    parser lowers its host and removes a tab or a line break wherever it
    stands); without it ``host`` is its own written form. A quoted span is the
    written text at the place of what the test read, and one that is not that
    text verbatim says how it was read.
    """
    text = str(host or "")
    removed = "" if given is None else _URL_REMOVED
    written_name = str(text if given is None else given).strip().rstrip("." + removed)
    name = text.strip().lower().rstrip(".")
    if not name:
        return "it names no host"
    if name.endswith(_TOR_SUFFIX):
        # The suffix is reserved for hidden services and nothing else can ever
        # answer under it, so the checksum is the whole question: a valid
        # address is a host, and a name that merely ends in ``.onion`` is not.
        return _onion_failure(name, written_name)
    try:
        address = ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        pass
    else:
        read = _quoted_as_read(name.strip("[]"), written_name.strip("[]"))
        if address.is_loopback:
            return f"{read} is a loopback address"
        if address.is_unspecified:
            return f"{read} is the unspecified address"
        if address.is_link_local:
            return f"{read} is a link-local address"
        return ""
    if not _is_emittable_domain(name):
        return _reserved_failure(name, written_name, removed)
    if host_is_private_use(name):
        return _private_use_failure(name, written_name, removed)
    labels = name.split(".")
    written_labels = _written_labels(labels, written_name)
    for label, written in zip(labels, written_labels, strict=True):
        if not _LABEL_RE.match(label):
            return _label_failure(label, written)
    if not _PUBLIC_SUFFIX_RE.match(labels[-1]):
        return (
            f"its last label {_quoted_as_read(labels[-1], written_labels[-1])} is neither "
            "two or more letters a-z nor an xn-- label"
        )
    return ""


def _quoted_suffix(suffix: str, name: str, written: str) -> str:
    """A listed suffix ``name`` ends in, quoted by what the written name holds at its place."""
    places = _written_labels(name.split("."), written)[len(name.split(".")) - suffix.count(".") :]
    given = None if None in places else "." + ".".join(str(part) for part in places)
    return _quoted_as_read(suffix, given)


def _reserved_failure(name: str, written: str, removed: str = "") -> str:
    """The reason :func:`_is_emittable_domain` refuses ``name`` by, read as it reads it.

    ``removed`` holds the characters the reader of ``written`` removed (:func:`host_failure`).
    """
    lower = name.lower().strip().rstrip(".")
    shown = written.strip().rstrip("." + removed)
    if not lower:
        return "it names no host"
    if "." not in lower:
        return f"{_quoted_as_read(lower, shown)} is a single label"
    if lower in _RESERVED_DOMAIN_NAMES:
        return f"{_quoted_as_read(lower, shown)} is a name this rule lists as reserved"
    suffix = next((s for s in _RESERVED_DOMAIN_SUFFIXES if lower.endswith(s)), "")
    return (
        f"it ends in {_quoted_suffix(suffix, lower, shown)}, a suffix this rule lists as reserved"
    )


def _private_use_failure(name: str, written: str, removed: str = "") -> str:
    """The reason :func:`host_is_private_use` refuses ``name`` by, read as it reads it.

    ``removed`` holds the characters the reader of ``written`` removed (:func:`host_failure`).
    """
    lower = name.strip().rstrip(".").lower()
    shown = written.strip().rstrip("." + removed)
    if lower in _RESERVED_DOMAIN_NAMES:
        return f"{_quoted_as_read(lower, shown)} is a name this rule lists as reserved"
    suffix = next(
        (s for s in _RESERVED_DOMAIN_SUFFIXES + _PRIVATE_USE_SUFFIXES if lower.endswith(s)), ""
    )
    listed = "reserved" if suffix in _RESERVED_DOMAIN_SUFFIXES else "not public"
    return (
        f"it ends in {_quoted_suffix(suffix, lower, shown)}, a suffix this rule lists as {listed}"
    )


def _label_failure(label: str, written: str | None) -> str:
    """The reason ``_LABEL_RE`` refuses ``label`` by: exactly one of its four failures."""
    if not label:
        return "it has an empty label"
    shown = _quoted_as_read(label, written)
    stray = _refused_character(label, written, _LABEL_CHARACTERS)
    if stray:
        return (
            f"its label {shown} holds {quoted_host_text(stray)} ({code_point(stray)}), which is "
            "not a letter a-z, a digit or a hyphen"
        )
    if len(label) > 63:
        return f"its label {shown} is {len(label)} characters long, more than 63"
    return f"its label {shown} starts or ends with a hyphen"


def _written_url_host(text: str) -> str | None:
    """The host of a URL as its text writes it, found where the URL parser finds it.

    The parser strips the C0 controls and spaces from the front, removes every
    tab and line break, takes a scheme (a letter, then letters, digits, ``+``,
    ``-`` or ``.``) before the first ``:``, and reads an authority only where
    ``//`` follows: up to the first ``/``, ``?`` or ``#``, after its last ``@``,
    inside brackets or before a ``:``. Read the same way here, by position, so
    a ``://`` later in the value is never taken for the host's; the span keeps
    a tab or line break that stands inside the host. ``None`` for no host.
    """
    from urllib.parse import scheme_chars

    first = len(text) - len(text.lstrip(_URL_STRIPPED))
    at = [i for i in range(first, len(text)) if text[i] not in _URL_REMOVED]
    seen = "".join(text[i] for i in at)
    begin = 0
    colon = seen.find(":")
    if (
        colon > 0
        and seen[0].isascii()
        and seen[0].isalpha()
        and all(ch in scheme_chars for ch in seen[:colon])
    ):
        begin = colon + 1
    if seen[begin : begin + 2] != "//":
        return None
    begin += 2
    end = next((i for i in range(begin, len(seen)) if seen[i] in "/?#"), len(seen))
    begin = max(begin, seen.rfind("@", begin, end) + 1)
    bracket = seen.find("[", begin, end)
    if bracket >= 0:
        begin = bracket + 1
        close = seen.find("]", begin, end)
        stop = close if close >= 0 else end
    else:
        stop = seen.find(":", begin, end)
        stop = stop if stop >= 0 else end
    if stop <= begin:
        return None
    return text[at[begin] : at[stop - 1] + 1]


def url_failure(raw_url: Any) -> str:
    """Why this URL names no host that could exist, ``""`` when it names one.

    The question :func:`url_host` and :func:`host_is_public` answer together,
    with the reason of whichever step refused it: the parser, a value with no
    ``://`` and no host read from it, an empty host, or the host test. The
    host is quoted as the URL writes it where that text, read the parser's
    way, is the host the test read (:func:`_written_url_host`).
    """
    from urllib.parse import urlparse

    text = str(raw_url or "")
    try:
        parsed = urlparse(text)
        host = (parsed.hostname or "").strip().lower().rstrip(".")
    except (ValueError, TypeError):
        return "the URL parser could not read its host"
    if host:
        given = _written_url_host(text)
        if given is not None:
            given = given.strip().rstrip("." + _URL_REMOVED)
            if "".join(ch for ch in given if ch not in _URL_REMOVED).lower() != host:
                given = None
        reason = host_failure(host, given)
        return f"its host fails the host test: {reason}" if reason else ""
    if "://" not in text:
        if not parsed.scheme:
            return "it is not a URL — it has no scheme — so there is no host in it to ask about"
        return 'it holds no "://", so there is no host in it to ask about'
    return "the URL parser read no host from it"


def url_corroboration_reason(raw_url: Any, source: Any, reputation: Any = None) -> str | None:
    """Why this URL may be published, or ``None`` when nothing says it may.

    The same rule the domains go through, asked of the URL's host, plus the
    syntactic question above — which no source can answer for: a cut-off host
    is not an endpoint whoever recorded it meant, whatever recorded it.
    """
    host = url_host(raw_url)
    if not host_is_public(host):
        return None
    return corroboration_reason(source, reputation, host)


# The addresses a document, a specification or an example reserves. Python reads
# them as private, which is not the same answer: a private address a sandbox
# really watched is lateral traffic worth publishing, and one of these is
# nobody's infrastructure whoever recorded it.
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# The shared address space a carrier puts between its subscribers and the
# internet. It is somebody's infrastructure the way a private range is — the
# sandbox can really reach one — and it is nobody's the way a version number
# is, so it belongs beside the private ranges rather than among the addresses
# that are never published. Named rather than reached through ``is_private``,
# which answers False for it.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")

# The address every reader of the report would recognise as not an endpoint.
_BROADCAST_ADDRESS = "255.255.255.255"


def address_is_publishable(address: Any, source: Any = None) -> bool:
    """Whether this address could be infrastructure somebody should act on.

    The classes that are never an indicator, whoever recorded them: loopback,
    unspecified, link-local, multicast, the broadcast address, anything the
    registries reserve, and the ranges a document or an example is written
    with. A private address is the one that depends on who saw it — a sandbox
    watching a sample reach 10.0.0.5 is lateral movement and worth publishing,
    while the same run of digits out of a string sweep is a version number
    somebody typed with dots in it.
    """
    try:
        parsed = ipaddress.ip_address(str(address or "").strip().strip("[]"))
    except ValueError:
        return False
    if (
        parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_link_local
        or parsed.is_unspecified
        or parsed.is_reserved
        or str(parsed) == _BROADCAST_ADDRESS
    ):
        return False
    if any(parsed in network for network in _DOCUMENTATION_NETWORKS):
        return False
    if parsed.is_private or parsed in _SHARED_ADDRESS_SPACE:
        return str(source or "").strip().lower() not in ("", "strings")
    return True


def ip_corroboration_reason(address: Any, source: Any, reputation: Any = None) -> str | None:
    """Why this address may be published, or ``None`` when nothing says it may.

    The predicate the domains and the URLs already go through, asked of an
    address, so the three network kinds answer one rule rather than three. A
    string sweep turns any run of digits with dots in it into an "IP" — one
    live bundle published ``6.0.0.0``, a version number out of the strings
    table — and until this the IPs were the one kind with no gate at all.
    """
    if not address_is_publishable(address, source):
        return None
    return corroboration_reason(source, reputation, str(address))


def domain_is_corroborated(source: Any, reputation: Any, fqdn: Any = "") -> bool:
    """Whether anything but the sample's own byte image knows this name.

    A string sweep turns any run of bytes shaped like a hostname into a
    "domain": a truncated resource left `rosoft.com` beside `microsoft.com`,
    an identifier table left `jector.SA`. Those are strings, and the report
    prints them as strings. Publishing them as indicators, or spending a paid
    reputation lookup on each, states something no one observed.

    Corroboration is a second source: the sandbox resolved the name, an
    analyst put it in an artefact, or a reputation provider has a record that
    names it. A source this layer does not know about is left alone — only
    ``strings`` is held back.

    A Tor address is the exception, and it has to be: `.onion` does not
    resolve, so no sandbox can ever confirm one, and holding it to this rule
    made the strongest string-derived indicator there is unpublishable by any
    path. Its own syntax is the second source. It stays labelled ``strings``
    and it is still never sent to a paid provider, which has no record of a
    hidden service either.
    """
    return corroboration_reason(source, reputation, fqdn) is not None


def _is_emittable_domain(fqdn: str) -> bool:
    """True only for FQDNs worth emitting as an IOC.

    Drops RFC 6761/6762 reserved names/suffixes (localhost, *.local, *.test,
    *.example, *.invalid, *.arpa) and single-label hostnames (no dot) which are
    local resolutions, not external infrastructure.
    """
    lower = fqdn.lower().strip().rstrip(".")
    if not lower or "." not in lower:
        return False
    if lower in _RESERVED_DOMAIN_NAMES:
        return False
    return not any(lower.endswith(suffix) for suffix in _RESERVED_DOMAIN_SUFFIXES)
