"""The benchmark's evidence as the docs publish it: defanged, with internal names removed.

The docs benchmark page links the scored run's report, its evidence ledger,
the evidence bundle the report cites, the STIX 2.1 bundle and the ATT&CK
mapping, so a reader can check every verdict. The run folder those come from
is the runner's own record and is never published as it is. This step writes
the published copies from it, and does nothing else to them:

- local file-system paths (``/home/...``, ``/tmp/...``) keep only their last
  component, the file name;
- the job, report and sample ids the server gave the run (read from the run
  folder's ``job.json`` and ``meta.json``) become ``<job>``, ``<report>`` and
  ``<sample>``, and a ledger entry's row id is dropped (its ``entry_id``,
  ``ev_0001`` ..., is what the report cites and stays);
- run tags (a word such as ``run``, ``local`` or ``hk`` followed by digits,
  ``run97``, ``run 97``, ``local98``, and a collection name built on one,
  ``<prefix>_hk99*``) become ``<run>``; the product's former name
  (``malspark.core.previous_name``) becomes Malspark;
- a value shaped like a credential (a bearer token, an API key, a cookie) is
  replaced by ``<redacted>``;
- every network indicator is defanged: ``http`` becomes ``hxxp`` and the dots
  of a host name or an IPv4 address become ``[.]``, in URLs and in plain text,
  so the docs site never serves a live malicious address. A host name is any
  dotted name whose last label is a top-level domain in IANA's list
  (``tlds.txt`` beside this file) and not a common file extension; every
  domain, address and URL of the run's ``iocs.json`` and of its sandbox and
  capture records is defanged as well, whatever its ending. A hex run whose
  decoded bytes hold an indicator is replaced by the hex of the defanged text.
  Links to the public reference services in ``REFERENCE_HOSTS`` stay as they
  are;
- a defanged copy made for open publication is marked TLP:CLEAR, whatever
  Traffic Light Protocol marking the report kept in the platform carries (the
  platform escalates it to AMBER when the report holds live network
  indicators): the report's marking banner (``**TLP:AMBER**``, in HTML
  ``<strong>TLP:AMBER</strong>``) and every ``tlp`` field of a JSON copy read
  CLEAR; a mention of TLP in prose, in code or in decoded evidence bytes stays
  as written;
- in an HTML copy each placeholder is written escaped (``&lt;job&gt;``);
- in a run summary a caller sanitises with :meth:`Sanitiser.run_summary` (the
  files :func:`publish` itself publishes carry none today), the strings
  at the key paths of ``KEPT_AS_RECORDED``, each matched in full from the
  summary's root (the model identifiers its ``environment`` block records),
  are exempt from the host and run-name rules: they name models, and those
  rules would rewrite a model name that looks like a host or a run tag. Every
  other rule applies to them, the local-path rule first (the record keeps a
  path-shaped identifier by its base name already). The same shape anywhere
  else, in any other document, is the run's text.

Defanging changes bytes, so a published ledger entry no longer matches the
digest it carries; the docs say so and point at reproducing the run instead.
The step prints what it replaced, by rule and by value, for review.

    python -m scripts.benchmark.publish_evidence RUN_DIR [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME

OUT = Path(__file__).resolve().parents[2] / "apps" / "docs" / "public" / "assets" / "benchmark"

# The published files, under the names the report's own links use.
TEXT_FILES = ("report.md", "report.html", "evidence-bundle.html")
JSON_FILES = ("evidence.json", "evidence-bundle.json", "stix-bundle.json", "mitre.json")

# Public reference services the report links to for the sample or a technique;
# a link to one of them (or to a subdomain) is not an indicator of the sample.
REFERENCE_HOSTS = (
    "virustotal.com",
    "bazaar.abuse.ch",
    "attack.mitre.org",
    "w3.org",
)

# The top-level domains IANA delegates, one per line; a dotted name ending in
# anything else (a CSS class, a rule keyword, a detection label) is not a host.
TLDS = frozenset(
    line.strip().lower()
    for line in (Path(__file__).with_name("tlds.txt")).read_text(encoding="ascii").splitlines()
    if line.strip() and not line.startswith("#")
)

# Top-level domains that are also file extensions; a name ending in one is a file.
FILE_EXTENSIONS = frozenset(
    "zip mov py sh so md rs pl cab ps bat exe dll sys dat bin cmd js json log txt csv".split()
)

# Detection-rule keywords that end in a top-level domain (Suricata's
# ``http.host`` buffer); a rule the report prints keeps them.
RULE_KEYWORDS = frozenset({"http.host"})

# The run-folder records that hold network indicators, and the keys of a
# sandbox or capture record whose values are an address or a host name.
INDICATOR_KINDS = ("ip", "domain", "url")
NETWORK_RECORD_KINDS = ("sandbox_network", "pcap")
NETWORK_KEYS = frozenset({"dst", "src", "ip", "domain", "host", "hostname", "query", "url"})

# The key paths of a run summary, from its root, whose strings the host and
# run-name rules leave as recorded: ``*`` is any key, ``[]`` any item of a
# list. A key at a path is treated as its value is (the model identifiers that
# key a count).
_Paths = tuple[tuple[str, ...], ...]
KEPT_AS_RECORDED: _Paths = (
    ("environment", "agents", "*", "requests", "[]", "model"),
    ("environment", "agents", "*", "response_models", "*"),
    ("environment", "agents", "*", "response_models_reduced", "[]"),
)

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# A path starts a word, or follows a newline escape of text quoted twice.
_LOCAL_PATH = re.compile(
    r"(?:(?<![\w.~])|(?<=\\[nrt]))/(?:home|tmp|root|Users|var/folders)/[^\s\"'<>&|,;)\]}\\]*"
)
# A run tag: a tag word with digits joined on, or ``run`` / ``hk`` and a spaced
# number, with the collection prefix it was given. A Ghidra local such as
# ``local_18`` and a model id such as ``x-5-5`` are not run tags.
_RUN_NAME = re.compile(
    r"\b(?:[a-z][a-z0-9]*_)?(?:(?:haiku|hk|run|local)\d+|(?:run|hk) \d+\b)[a-z0-9_]*\*?",
    re.IGNORECASE,
)
_FORMER_NAME = re.compile(re.escape(PREVIOUS_NAME), re.IGNORECASE)
_SECRETS = (
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(
        r"(?i)\b((?:api[_-]?key|x-apikey|token|secret|password|cookie)[\"']?\s*[:=]\s*[\"']?)"
        r"[A-Za-z0-9._~+/=-]{16,}"
    ),
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
_URL = re.compile(r"\b[hH][tT][tT][pP]([sS]?)://([^/\s\"'<>&)\]\\]+)")
_DOMAIN = re.compile(
    r"(?<![\w.\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-]|\.[a-z0-9])",
    re.IGNORECASE,
)
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){12,}(?![0-9a-fA-F])")
# Bytes read back as UTF-16LE show as a run of characters above U+00FF.
_WIDE = re.compile("[\u0100-\ud7ff\ue000-\uffff]{8,}")
_PLACEHOLDER = re.compile(r"<(job|report|sample|run|redacted)>")
# The report's Traffic Light Protocol marking banner, at any level, as the
# Markdown prints it and the HTML renders it.
TLP_LEVELS = frozenset({"CLEAR", "WHITE", "GREEN", "AMBER", "AMBER+STRICT", "AMBER_STRICT", "RED"})
_TLP = re.compile(
    r"(\*\*|<strong>)TLP:(?:CLEAR|WHITE|GREEN|AMBER(?:\+STRICT|_STRICT)?|RED)"
    r"(?![\w+\-])(?=\*\*|</strong>)",
    re.IGNORECASE,
)
PUBLIC_TLP = "CLEAR"
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# An address may end a sentence; a fifth dotted number makes it something else.
_IPV4 = re.compile(rf"(?<!\d)(?<!\d\.)(?:{_OCTET}\.){{3}}{_OCTET}(?!\d|\.\d)")


def _is_reference(host: str) -> bool:
    host = host.lower().split(":")[0].rstrip(".")
    return any(host == ref or host.endswith("." + ref) for ref in REFERENCE_HOSTS)


def _is_host(name: str) -> bool:
    last = name.rsplit(".", 1)[-1].lower()
    return (
        last in TLDS
        and last not in FILE_EXTENSIONS
        and name.lower() not in RULE_KEYWORDS
        and not _is_reference(name)
    )


def _defang(value: str) -> str:
    return re.sub(r"^[hH][tT][tT][pP]", "hxxp", value).replace(".", "[.]")


def _former_name(match: re.Match[str]) -> str:
    word = match.group(0)
    if word.isupper():
        return CURRENT_NAME.upper()
    return CURRENT_NAME.capitalize() if word[0].isupper() else CURRENT_NAME


class Sanitiser:
    """Applies the rules above to text and counts each replacement by rule and value."""

    def __init__(self, ids: dict[str, str], indicators: frozenset[str] = frozenset()) -> None:
        self.ids = ids  # an id the server gave the run -> its placeholder
        self.counts: Counter[tuple[str, str]] = Counter()
        # The run's own indicators, longest first, so a URL goes before its host.
        literals = sorted((i for i in indicators if not _is_reference(i)), key=len, reverse=True)
        self.indicators = (
            re.compile(
                r"(?<![\w.\-])(?:" + "|".join(map(re.escape, literals)) + r")(?![\w-]|\.\w)",
                re.IGNORECASE,
            )
            if literals
            else None
        )

    def _sub(
        self, rule: str, pattern: re.Pattern[str], text: str, repl: Callable[[re.Match[str]], str]
    ) -> str:
        def counted(match: re.Match[str]) -> str:
            new = repl(match)
            if new != match.group(0):
                self.counts[(rule, match.group(0)[:80])] += 1
            return new

        return pattern.sub(counted, text)

    def text(self, text: str, html: bool = False) -> str:
        text = self._text(text)
        if html:
            text = _PLACEHOLDER.sub(r"&lt;\1&gt;", text)
        return text

    def _text(self, text: str, decode: bool = True, names: bool = True) -> str:
        """``text`` with the rules applied; without ``names``, the host and run-name rules
        are left out (:data:`KEPT_AS_RECORDED`)."""
        for value, placeholder in self.ids.items():
            if value in text:
                self.counts[("server id", placeholder)] += text.count(value)
                text = text.replace(value, placeholder)
        text = self._sub(
            "local path", _LOCAL_PATH, text, lambda m: m.group(0).rstrip("/").rsplit("/", 1)[-1]
        )
        if names:
            text = self._sub("run name", _RUN_NAME, text, lambda m: "<run>")
        text = self._sub("former name", _FORMER_NAME, text, _former_name)
        for pattern in _SECRETS:
            text = self._sub(
                "credential",
                pattern,
                text,
                lambda m: (m.group(1) if m.lastindex else "") + "<redacted>",
            )
        if decode:
            text = self._sub("tlp", _TLP, text, lambda m: f"{m.group(1)}TLP:{PUBLIC_TLP}")
            text = self._sub("hex", _HEX, text, self._defang_hex)
            text = self._sub("utf16le", _WIDE, text, self._defang_wide)
        text = self._sub("url", _URL, text, self._defang_url)
        if self.indicators:
            text = self._sub("indicator", self.indicators, text, lambda m: _defang(m.group(0)))
        if names:
            text = self._sub("host", _DOMAIN, text, self._defang_host)
        return self._sub("ipv4", _IPV4, text, lambda m: m.group(0).replace(".", "[.]"))

    def _defanged_bytes(self, data: bytes) -> bytes | None:
        """``data`` with the rules applied to it read as Latin-1; ``None`` when nothing changed."""
        decoded = data.decode("latin-1")
        sanitised = Sanitiser(self.ids)
        sanitised.indicators = self.indicators
        clean = sanitised._text(decoded, decode=False)
        return None if clean == decoded else clean.encode("latin-1", errors="replace")

    def _defang_hex(self, match: re.Match[str]) -> str:
        """A hex run whose bytes hold an indicator, as the hex of the defanged bytes."""
        raw = match.group(0)
        clean = self._defanged_bytes(bytes.fromhex(raw))
        if clean is None:
            return raw
        return clean.hex().upper() if raw.isupper() else clean.hex()

    def _defang_wide(self, match: re.Match[str]) -> str:
        """Bytes shown as UTF-16LE that hold an indicator, as the defanged bytes shown so."""
        clean = self._defanged_bytes(match.group(0).encode("utf-16le"))
        if clean is None:
            return match.group(0)
        if len(clean) % 2:
            clean += b"\x00"
        return clean.decode("utf-16le", errors="replace")

    @staticmethod
    def _defang_url(match: re.Match[str]) -> str:
        secure, host = match.group(1), match.group(2)
        if _is_reference(host):
            return match.group(0)
        return f"hxxp{secure}://{host.replace('.', '[.]')}"

    @staticmethod
    def _defang_host(match: re.Match[str]) -> str:
        host = match.group(1)
        return host.replace(".", "[.]") if _is_host(host) else host

    def json(self, value: Any) -> Any:
        """``value`` with every key and string sanitised; a ledger entry's row id is dropped.

        A ``tlp`` field that holds a marking level reads ``CLEAR``.
        """
        return self._json(value, (), ())

    def run_summary(self, summary: Any) -> Any:
        """A run summary as :meth:`json` sanitises it, the strings at the key paths of
        :data:`KEPT_AS_RECORDED` (from the summary's root) left by the host and run-name rules.

        The entry point for a caller that publishes a run summary: none of the
        files :func:`publish` writes (:data:`JSON_FILES`) carries one today.
        """
        return self._json(summary, (), KEPT_AS_RECORDED)

    def _key_or_string(self, value: str, path: tuple[str, ...], kept: _Paths) -> str:
        return self._text(value, names=not _kept(path, kept))

    def _json(self, value: Any, path: tuple[str, ...], kept: _Paths) -> Any:
        if isinstance(value, str):
            return self._key_or_string(value, path, kept)
        if isinstance(value, list):
            return [self._json(item, (*path, "[]"), kept) for item in value]
        if isinstance(value, dict):
            if "entry_id" in value and re.fullmatch(_UUID, str(value.get("id", ""))):
                value = {k: v for k, v in value.items() if k != "id"}
            return {
                self._key_or_string(k, (*path, k), kept): self._tlp_field(k, v, (*path, k), kept)
                for k, v in value.items()
            }
        return value

    def _tlp_field(self, key: str, value: Any, path: tuple[str, ...], kept: _Paths) -> Any:
        if key.lower() == "tlp" and isinstance(value, str) and value.upper() in TLP_LEVELS:
            if value.upper() != PUBLIC_TLP:
                self.counts[("tlp", value)] += 1
            return PUBLIC_TLP.lower() if value.islower() else PUBLIC_TLP
        return self._json(value, path, kept)


def _kept(path: tuple[str, ...], kept: _Paths) -> bool:
    """Whether ``path``, the keys from the document's root, is one of ``kept`` in full."""
    return any(
        len(pattern) == len(path)
        and all(
            want == got or (want == "*" and got != "[]")
            for want, got in zip(pattern, path, strict=True)
        )
        for pattern in kept
    )


def server_ids(run: Path) -> dict[str, str]:
    """The job, report and sample ids the server gave the run, each to its placeholder."""
    ids: dict[str, str] = {}
    for name in ("job.json", "meta.json"):
        path = run / name
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for key, placeholder in (
            ("id", "<job>"),
            ("job_id", "<job>"),
            ("report_id", "<report>"),
            ("sample_id", "<sample>"),
        ):
            value = data.get(key)
            if isinstance(value, str) and re.fullmatch(_UUID, value):
                ids[value] = placeholder
    return ids


def run_indicators(run: Path) -> frozenset[str]:
    """Every domain, address and URL of the run's IOC list, sandbox and capture records."""
    found: set[str] = set()
    iocs = run / "iocs.json"
    if iocs.exists():
        for item in json.loads(iocs.read_text(encoding="utf-8")).get("items", []):
            if item.get("kind") in INDICATOR_KINDS and isinstance(item.get("value"), str):
                found.add(item["value"])
    ledger = run / "evidence.json"
    if ledger.exists():
        for entry in json.loads(ledger.read_text(encoding="utf-8")).get("items", []):
            if (entry.get("facts") or {}).get("kind") in NETWORK_RECORD_KINDS:
                found.update(_network_values(entry.get("structured")))
    return frozenset(found)


def _network_values(value: Any, key: str = "") -> set[str]:
    """The addresses and host names (a port dropped) under a network record's address keys."""
    if isinstance(value, dict):
        return {found for k, v in value.items() for found in _network_values(v, str(k).lower())}
    if isinstance(value, list):
        return {found for v in value for found in _network_values(v, key)}
    if isinstance(value, str) and key in NETWORK_KEYS and "." in value:
        return {re.sub(r":\d+$", "", value.strip())}
    return set()


def publish(run: Path, out: Path) -> Sanitiser:
    """Writes the published copies of ``run``'s files into ``out``; returns the counts."""
    sanitiser = Sanitiser(server_ids(run), run_indicators(run))
    out.mkdir(parents=True, exist_ok=True)
    for name in TEXT_FILES:
        text = (run / name).read_text(encoding="utf-8")
        (out / name).write_text(sanitiser.text(text, html=name.endswith(".html")), encoding="utf-8")
    for name in JSON_FILES:
        original = (run / name).read_text(encoding="utf-8")
        data = json.loads(original)
        indent, ascii_only = layout(original, data)
        text = json.dumps(sanitiser.json(data), ensure_ascii=ascii_only, indent=indent)
        (out / name).write_text(text + ("\n" if original.endswith("\n") else ""), encoding="utf-8")
    return sanitiser


def layout(original: str, data: Any) -> tuple[int | None, bool]:
    """The indent and ASCII escaping ``original`` was written with.

    The copy is written the same way, so it differs from the original only where it was sanitised.
    """
    for indent in (1, 2, None):
        for ascii_only in (True, False):
            if json.dumps(data, ensure_ascii=ascii_only, indent=indent) == original.rstrip("\n"):
                return indent, ascii_only
    return 1, False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("run", type=Path, help="the scored run's folder")
    parser.add_argument("--out", type=Path, default=OUT, help=f"where to write (default {OUT})")
    args = parser.parse_args(argv)
    sanitiser = publish(args.run, args.out)
    by_rule: Counter[str] = Counter()
    for (rule, value), count in sorted(sanitiser.counts.items()):
        by_rule[rule] += count
        print(f"{rule:12} {count:5}  {value}")
    print(", ".join(f"{rule}: {count}" for rule, count in sorted(by_rule.items())))
    for name in TEXT_FILES + JSON_FILES:
        print(f"{(args.out / name).stat().st_size:>10,}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
