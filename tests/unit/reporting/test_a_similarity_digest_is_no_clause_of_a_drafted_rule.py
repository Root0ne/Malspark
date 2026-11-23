"""A digest that also matches files that are not the sample is no clause of a drafted rule.

The import-table digest of a sample is shared by every program whose import
table is the same set, so a drafted YARA rule is never satisfied by it, alone
or beside another clause: the condition is the sha256 comparison alone, or the
sha256 comparison or the strings clause. The value is kept in the rule's
``meta:``, on the line after the sha256, and the rule imports no module it does
not use. The probe ruleset is written from the same declarations, so it holds
no part for the digest either, and a new record's ``matched_by`` names the
sha256 and the strings only. ``imphash`` stays a legal stored clause: a record
that holds it prints as it was stored (T-867).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, get_args

import pytest

from malspark.reporting import detection_signatures as drafts
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.detection_signatures import OwnSample, build_detection_rules
from malspark.reporting.models import (
    DetectionRule,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    RuleClause,
    SampleIdentity,
    SampleString,
)
from malspark.reporting.renderers.markdown import MarkdownRenderer

needs_engine = pytest.mark.skipif(not drafts._YARA_AVAILABLE, reason="yara-python is not installed")

SHA256 = "c" * 64
DIGEST = "d" * 32
NAMES = ("gate9.example.org", "relay4.example.net")
SEEDS = [("$d0", bytes.fromhex("6c1dc22e"))]
HASHES = [("$h0", bytes.fromhex("f4a54fc2")), ("$h1", bytes.fromhex("0badf00d"))]
SHA256_CLAUSE = f'(hash.sha256(0, filesize) == "{SHA256}")'
SAID = "Run against the sample it was drafted from: "

# Each shape a draft's condition takes: no strings, published strings, and
# published strings with the values the sample stores.
SHAPES = {
    "no strings": ({"strings": []}, SHA256_CLAUSE),
    "published strings": (
        {"strings": [(f"$s{n}", name) for n, name in enumerate(NAMES)]},
        f"{SHA256_CLAUSE} or (2 of them)",
    ),
    "strings and stored values": (
        {
            "strings": [(f"$s{n}", name) for n, name in enumerate(NAMES)],
            "seeds": SEEDS,
            "hashes": HASHES,
        },
        f"{SHA256_CLAUSE} or ((2 of ($s*)) or (all of ($d*) and all of ($h*)))",
    ),
}


def _rendered(shape: str, imphash: str | None) -> Any:
    declared, _condition = SHAPES[shape]
    return drafts._render_yara(
        rule_name="Malspark_AutoGen_loader",
        sha256=SHA256,
        imphash=imphash,
        family="loader",
        verdict="Malware",
        generated_at_iso="2000-01-01T00:00:00+00:00",
        **declared,
    )


def _condition(draft: str) -> str:
    return draft.split("    condition:\n", 1)[1].splitlines()[0].strip()


@pytest.mark.parametrize("imphash", [DIGEST, "f34d", None])
@pytest.mark.parametrize("shape", list(SHAPES))
class TestTheConditionHoldsTheSha256AndTheStringsOnly:
    def test_the_condition_is_the_sha256_or_the_strings_clause(
        self, shape: str, imphash: str | None
    ) -> None:
        draft = _rendered(shape, imphash).draft

        assert _condition(draft) == SHAPES[shape][1]
        assert "pe." not in draft.split("    condition:\n", 1)[1]

    def test_the_digest_is_on_the_meta_line_after_the_sha256(
        self, shape: str, imphash: str | None
    ) -> None:
        lines = _rendered(shape, imphash).draft.splitlines()
        after = lines[lines.index(f'        sha256 = "{SHA256}"') + 1]

        if imphash:
            assert after == f'        imphash = "{imphash}"'
            assert sum(1 for line in lines if imphash in line) == 1
        else:
            assert after.startswith("        generated_at = ")
            assert not [line for line in lines if "imphash" in line]

    def test_no_module_the_rule_does_not_use_is_imported(
        self, shape: str, imphash: str | None
    ) -> None:
        rendered = _rendered(shape, imphash)

        for source in (rendered.draft, rendered.probe):
            imports = [line for line in source.splitlines() if line.startswith("import ")]
            assert imports == ['import "hash"']

    def test_the_probe_holds_no_part_for_the_digest(self, shape: str, imphash: str | None) -> None:
        rendered = _rendered(shape, imphash)
        parts = ("sha256", "strings") if SHAPES[shape][0]["strings"] else ("sha256",)

        assert rendered.parts == parts
        assert "imphash" not in rendered.probe
        assert re.findall(r"^rule probe_part_(\w+) ", rendered.probe, re.M) == list(parts)


def _report(sha256: str, imphash: str | None, names: tuple[str, ...] = NAMES) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=sha256, imphash=imphash)),
        verdict="Malware",
        malware_category="loader",
        network=NetworkIOCs(domains=[NetworkDomain(fqdn=name, source="sandbox") for name in names]),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _engine_imphash(blob: bytes) -> str:
    """The import hash as the engine itself computes it, read through its console module."""
    import yara

    said: list[str] = []
    rules = yara.compile(
        source='import "pe"\nimport "console"\nrule r { condition: console.log(pe.imphash()) }\n',
        includes=False,
    )
    rules.match(data=blob, console_callback=said.append)
    return said[0]


@needs_engine
class TestTheEngineNeverHoldsTheDigest:
    """Over a sample with an import table, and its own import digest given to the draft."""

    @pytest.mark.parametrize("names", [NAMES, ()])
    def test_a_draft_of_another_file_with_the_sample_s_digest_does_not_match(
        self, tmp_path: Path, names: tuple[str, ...]
    ) -> None:
        from scripts.rehearsal.sample import sample_bytes

        image = sample_bytes()
        path = tmp_path / "sample.bin"
        path.write_bytes(image)
        digest = _engine_imphash(image)
        report = _report(SHA256, digest, names)
        sample = OwnSample(path=str(path), budget_seconds=60)
        (rule,) = [r for r in build_detection_rules(report, sample) if r.kind == "yara"]

        assert rule.compile_error is None
        assert (rule.matches_sample, rule.matched_by) == (False, [])
        assert f'        imphash = "{digest}"' in rule.body.splitlines()

    def test_the_sample_s_own_draft_matches_by_its_sha256_only(self, tmp_path: Path) -> None:
        import hashlib

        from scripts.rehearsal.sample import sample_bytes

        image = sample_bytes()
        path = tmp_path / "sample.bin"
        path.write_bytes(image)
        report = _report(hashlib.sha256(image).hexdigest(), _engine_imphash(image))
        report.detection_signatures = build_detection_rules(
            report, OwnSample(path=str(path), budget_seconds=60)
        )
        (rule,) = [r for r in report.detection_signatures if r.kind == "yara"]

        assert rule.matched_by == ["sha256"]
        markdown = MarkdownRenderer().render(report)
        assert (
            f"{SAID}the rule matches it by its sha256 only; its strings do not "
            "(0 of 2 strings found)."
        ) in markdown


class TestAStoredRecordHoldingTheDigestPrintsAsStored:
    @pytest.mark.parametrize(
        ("matched_by", "strings", "said"),
        [
            (
                ["sha256", "imphash"],
                [SampleString(identifier="$s0")],
                "the rule matches it by its sha256 and imphash only; its strings do not "
                "(0 of 1 strings found).",
            ),
            (
                ["sha256", "imphash", "strings"],
                [SampleString(identifier="$s0", offset=16)],
                "its strings match it (1 of 1 strings found), and so do its sha256 and imphash.",
            ),
        ],
    )
    def test_the_report_prints_the_stored_clauses(
        self, matched_by: list[str], strings: list[SampleString], said: str
    ) -> None:
        stored = {
            "kind": "yara",
            "name": "Malspark_AutoGen_loader",
            "body": "rule Malspark_AutoGen_loader { condition: true }\n",
            "matches_sample": True,
            "matched_by": matched_by,
            "sample_strings": [s.model_dump(mode="json") for s in strings],
        }
        report = _report(SHA256, DIGEST)
        report.detection_signatures = [DetectionRule.model_validate(stored)]

        assert report.detection_signatures[0].matched_by == matched_by
        assert f"{SAID}{said}" in MarkdownRenderer().render(report)

    def test_the_digest_stays_a_legal_clause(self) -> None:
        assert set(get_args(RuleClause)) == {"sha256", "imphash", "strings"}
