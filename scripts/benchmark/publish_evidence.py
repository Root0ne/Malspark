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
- run and test names (``haiku13``, ``run4``, ``local3``), the runner's
  collection names and the product's former name (now Malspark) are replaced;
- a value shaped like a credential (a bearer token, an API key, a cookie) is
  replaced by ``<redacted>``;
- every network indicator is defanged: ``http`` becomes ``hxxp`` and the dots
  of a host name or an IPv4 address become ``[.]``, in URLs and in plain text,
  so the docs site never serves a live malicious address. Links to the public
  reference services in ``REFERENCE_HOSTS`` stay as they are.

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
    "oasis-open.org",
)

# Top-level domains a bare host name is recognised by. File extensions such as
# .dll, .exe or .dat are not among them, so a file name is never taken for a host.
TLDS = (
    "com|net|org|top|io|ru|su|ch|info|biz|xyz|me|cc|site|online|club|shop|pw|tk|icu|cn|"
    "live|store|space|fun|digital|cloud|app|dev|link|click|work"
)

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# A path starts a word, or follows a newline escape of text quoted twice.
_LOCAL_PATH = re.compile(
    r"(?:(?<![\w.~])|(?<=\\[nrt]))/(?:home|tmp|root|Users|var/folders)/[^\s\"'<>&|,;)\]}\\]*"
)
_RUN_NAME = re.compile(r"\b(?:haiku|run|local)\d+[a-z0-9_*]*\b", re.IGNORECASE)
_FORMER_NAME = re.compile(r"maljan", re.IGNORECASE)
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
    rf"(?<![\w.\-])((?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{TLDS}))(?![\w-]|\.[a-z0-9])",
    re.IGNORECASE,
)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# An address may end a sentence; a fifth dotted number makes it something else.
_IPV4 = re.compile(rf"(?<!\d)(?<!\d\.)(?:{_OCTET}\.){{3}}{_OCTET}(?!\d|\.\d)")


def _is_reference(host: str) -> bool:
    host = host.lower().split(":")[0].rstrip(".")
    return any(host == ref or host.endswith("." + ref) for ref in REFERENCE_HOSTS)


def _former_name(match: re.Match[str]) -> str:
    word = match.group(0)
    if word.isupper():
        return "MALSPARK"
    return "Malspark" if word[0].isupper() else "malspark"


class Sanitiser:
    """Applies the rules above to text and counts each replacement by rule and value."""

    def __init__(self, ids: dict[str, str]) -> None:
        self.ids = ids  # an id the server gave the run -> its placeholder
        self.counts: Counter[tuple[str, str]] = Counter()

    def _sub(
        self, rule: str, pattern: re.Pattern[str], text: str, repl: Callable[[re.Match[str]], str]
    ) -> str:
        def counted(match: re.Match[str]) -> str:
            new = repl(match)
            if new != match.group(0):
                self.counts[(rule, match.group(0)[:80])] += 1
            return new

        return pattern.sub(counted, text)

    def text(self, text: str) -> str:
        for value, placeholder in self.ids.items():
            if value in text:
                self.counts[("server id", placeholder)] += text.count(value)
                text = text.replace(value, placeholder)
        text = self._sub(
            "local path", _LOCAL_PATH, text, lambda m: m.group(0).rstrip("/").rsplit("/", 1)[-1]
        )
        text = self._sub("run name", _RUN_NAME, text, lambda m: "<run>")
        text = self._sub("former name", _FORMER_NAME, text, _former_name)
        for pattern in _SECRETS:
            text = self._sub(
                "credential",
                pattern,
                text,
                lambda m: (m.group(1) if m.lastindex else "") + "<redacted>",
            )
        text = self._sub("url", _URL, text, self._defang_url)
        text = self._sub("host", _DOMAIN, text, self._defang_host)
        return self._sub("ipv4", _IPV4, text, lambda m: m.group(0).replace(".", "[.]"))

    @staticmethod
    def _defang_url(match: re.Match[str]) -> str:
        secure, host = match.group(1), match.group(2)
        if _is_reference(host):
            return match.group(0)
        return f"hxxp{secure}://{host.replace('.', '[.]')}"

    @staticmethod
    def _defang_host(match: re.Match[str]) -> str:
        host = match.group(1)
        return host if _is_reference(host) else host.replace(".", "[.]")

    def json(self, value: Any) -> Any:
        """``value`` with every key and string sanitised; a ledger entry's row id is dropped."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.json(item) for item in value]
        if isinstance(value, dict):
            if "entry_id" in value and re.fullmatch(_UUID, str(value.get("id", ""))):
                value = {k: v for k, v in value.items() if k != "id"}
            return {self.text(k): self.json(v) for k, v in value.items()}
        return value


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


def publish(run: Path, out: Path) -> Sanitiser:
    """Writes the published copies of ``run``'s files into ``out``; returns the counts."""
    sanitiser = Sanitiser(server_ids(run))
    out.mkdir(parents=True, exist_ok=True)
    for name in TEXT_FILES:
        text = (run / name).read_text(encoding="utf-8")
        (out / name).write_text(sanitiser.text(text), encoding="utf-8")
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
