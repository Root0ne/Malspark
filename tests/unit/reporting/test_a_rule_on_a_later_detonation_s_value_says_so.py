"""A drafted rule resting on a value only a later detonation observed says so.

Each draft (YARA, Sigma, Suricata) names, beside the value it is built on, the
detonation and the launch the value was observed in, in the rule language's
own comment or metadata, where every detonation that observed the value is a
further one an agent asked for (``ObservedIn``). A value the job's own
detonation observed too carries no mark, and the rule's matching logic is the
same either way. A run with one detonation drafts the same bytes (T-679).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest
import yaml

from malspark.reporting import detection_signatures as drafts
from malspark.reporting.detection_signatures import build_detection_rules
from malspark.reporting.models import (
    ConsolidatedIOC,
    FamilyAttribution,
    FileHashes,
    MalwareReport,
    ObservedIn,
    SampleIdentity,
)

ARGS = "-p hunter2"
D1 = ObservedIn(detonation="d1")
D2 = ObservedIn(detonation="d2", launched_with=ARGS)
MARK = f"observed in detonation 2, launched with `{ARGS}`"
SHA256 = "7" * 64
DOMAIN_LATER, DOMAIN_BOTH = "pay.example.org", "c2.example.net"
URL_LATER = "http://pay.example.org/gate.php"
AGENT_LATER = "MalAgent/1.0 (later)"
PATH_LATER = "C:\\Users\\Public\\Vendor\\drop.exe"
IP_FIRST = "203.0.113.9"


def _row(kind: str, kind_type: str, value: str, source: str, marks: list[ObservedIn]) -> Any:
    return ConsolidatedIOC(
        type=kind_type,
        kind=kind,
        value=value,
        source=source,
        is_network=kind in {"domain", "ip", "url"},
        published=f"yes: the {source} recorded it",
        observed_in=marks,
    )


def _report(*, later: bool = True, launch: str = ARGS) -> MalwareReport:
    mark = [ObservedIn(detonation="d2", launched_with=launch)] if later else []
    both = [D1, ObservedIn(detonation="d2", launched_with=launch)] if later else []
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        attribution=FamilyAttribution(family="Fixturelock", family_grounded=True),
        generated_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        consolidated_iocs=[
            _row("domain", "Domain", DOMAIN_LATER, "sandbox", mark),
            _row("domain", "Domain", DOMAIN_BOTH, "sandbox", both),
            _row("url", "URL", URL_LATER, "sandbox", mark),
            _row("ip", "IPv4", IP_FIRST, "sandbox", []),
            _row("user_agent", "User agent", AGENT_LATER, "sandbox", mark),
            _row("path", "Path", PATH_LATER, "analysis", mark),
        ],
    )


def _rules(report: MalwareReport) -> dict[str, Any]:
    return {rule.kind: rule for rule in build_detection_rules(report)}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TestOneDetonation:
    # The drafts as 8fe0ba5db writes them for this report: a run with one
    # detonation drafts the same bytes.
    PINNED = {
        "yara": "096459f5f57d2b9299a8fcc16f56d485e47a43d751194b83509d897ca5c10873",
        "sigma": "6d015935953fcdf5787f7ddc94b69307149eef35798e410bb2c4e37978f0208c",
        "suricata": "77aaea61719764d944e57ddd15162679f9f41ba58e17b13c4f2035c981bfd840",
    }

    def test_every_draft_is_the_one_drafted_before(self) -> None:
        rules = _rules(_report(later=False))
        bodies = {kind: rules[kind].body for kind in self.PINNED}
        if drafts._YARA_AVAILABLE is False:
            bodies.pop("yara")
        assert {kind: _digest(body) for kind, body in bodies.items()} == {
            kind: self.PINNED[kind] for kind in bodies
        }
        assert not any("observed in" in body for body in bodies.values())


class TestYara:
    def test_a_string_only_a_later_detonation_observed_says_so_on_its_line(self) -> None:
        body = _rules(_report())["yara"].body
        line = next(line for line in body.splitlines() if f'"{DOMAIN_LATER}"' in line)
        assert line.endswith(f"; {MARK}")
        assert "  // " in line

    def test_a_string_the_first_detonation_observed_too_carries_no_mark(self) -> None:
        body = _rules(_report())["yara"].body
        line = next(line for line in body.splitlines() if f'"{DOMAIN_BOTH}"' in line)
        assert "observed in" not in line

    def test_the_matching_logic_is_untouched(self) -> None:
        def _logic(body: str) -> list[str]:
            return [line.split("  // ", 1)[0] for line in body.splitlines()]

        marked = _rules(_report())["yara"].body
        plain = _rules(_report(later=False))["yara"].body
        assert _logic(marked) == _logic(plain)


class TestSigma:
    def test_a_selected_value_only_a_later_detonation_observed_is_named_in_the_description(
        self,
    ) -> None:
        sigma = [rule for rule in build_detection_rules(_report()) if rule.kind == "sigma"]
        parsed = [yaml.safe_load(rule.body) for rule in sigma]
        described = [doc["description"] for doc in parsed if "observed in" in doc["description"]]
        assert len(described) == 1
        assert described[0].endswith(f"{PATH_LATER}: {MARK}")

    def test_the_detection_is_untouched(self) -> None:
        def _docs(report: MalwareReport) -> list[dict[str, Any]]:
            docs = [
                yaml.safe_load(rule.body)
                for rule in build_detection_rules(report)
                if rule.kind == "sigma"
            ]
            for doc in docs:
                doc.pop("description")
            return docs

        assert _docs(_report()) == _docs(_report(later=False))


class TestSuricata:
    def test_a_rule_on_a_value_only_a_later_detonation_observed_says_so_above_it(self) -> None:
        lines = _rules(_report())["suricata"].body.splitlines()
        for value in (DOMAIN_LATER, AGENT_LATER):
            comment = next(
                line for line in lines if line.startswith("# ") and value.split(".")[0] in line
            )
            assert comment.endswith(f"; {MARK}"), comment

    def test_a_rule_on_a_value_the_first_detonation_observed_carries_no_mark(self) -> None:
        lines = _rules(_report())["suricata"].body.splitlines()
        for value in ("c2[.]example[.]net", "203[.]0[.]113[.]9"):
            comment = next(line for line in lines if line.startswith("# ") and value in line)
            assert "observed in" not in comment

    def test_the_rules_are_untouched(self) -> None:
        def _alerts(report: MalwareReport) -> list[str]:
            body = _rules(report)["suricata"].body
            return [line for line in body.splitlines() if not line.startswith("#")]

        assert _alerts(_report()) == _alerts(_report(later=False))


@pytest.mark.parametrize("kind", ["yara", "sigma", "suricata"])
def test_a_draft_with_a_mark_still_passes_its_own_check(kind: str) -> None:
    rules = [rule for rule in build_detection_rules(_report()) if rule.kind == kind]
    assert rules
    if kind == "yara" and not drafts._YARA_AVAILABLE:
        pytest.skip("yara-python is not installed")
    assert all(rule.compile_error is None for rule in rules)


D3 = ObservedIn(detonation="d3", launched_with="--silent")
MARK_3 = "detonation 3, launched with `--silent`"
PATH_SAME = "c:\\users\\public\\vendor\\DROP.exe"


def _drafted(rows: list[Any]) -> list[Any]:
    report = _report(later=False)
    report.consolidated_iocs = rows
    return build_detection_rules(report)


def _sigma_descriptions(rows: list[Any]) -> list[str]:
    return [yaml.safe_load(r.body)["description"] for r in _drafted(rows) if r.kind == "sigma"]


class TestEveryRowOfAValue:
    """A selected value is a later detonation's only where every row reducing to it is."""

    @pytest.mark.parametrize("first_later", [True, False])
    def test_one_row_of_the_job_s_own_detonation_removes_the_statement(
        self, first_later: bool
    ) -> None:
        later = _row("path", "Path", PATH_LATER, "analysis", [D2])
        own = _row("path", "Path", PATH_SAME, "analysis", [])
        rows = [later, own] if first_later else [own, later]
        assert not any("observed in" in said for said in _sigma_descriptions(rows))

    def test_rows_of_later_detonations_alone_name_each(self) -> None:
        rows = [
            _row("path", "Path", PATH_LATER, "analysis", [D2]),
            _row("path", "Path", PATH_SAME, "analysis", [D3]),
        ]
        (said,) = [d for d in _sigma_descriptions(rows) if "observed in" in d]
        assert said.endswith(f"{PATH_LATER}: {MARK} and in {MARK_3}")


class TestSeveralDetonations:
    def test_a_value_two_later_detonations_observed_names_both_launches(self) -> None:
        rows = [_row("domain", "Domain", DOMAIN_LATER, "sandbox", [D2, D3])]
        rules = {r.kind: r for r in _drafted(rows)}
        both = f"{MARK} and in {MARK_3}"
        yara = next(x for x in rules["yara"].body.splitlines() if f'"{DOMAIN_LATER}"' in x)
        assert yara.endswith(f"; {both}")
        suricata = next(
            x for x in rules["suricata"].body.splitlines() if x.startswith("# ") and "pay" in x
        )
        assert suricata.endswith(f"; {both}")

    def test_a_value_the_job_s_own_and_a_third_detonation_observed_is_no_later_only(self) -> None:
        rows = [
            _row("domain", "Domain", DOMAIN_LATER, "sandbox", [D1, D3]),
            _row("path", "Path", PATH_LATER, "analysis", [D1, D3]),
        ]
        assert not any("observed in" in r.body for r in _drafted(rows))

    def test_the_first_sigma_draft_names_a_registry_key_only_a_later_detonation_observed(
        self,
    ) -> None:
        key = "HKCU\\Software\\ExampleVendor7731"
        rows = [_row("registry", "Registry key", key, "analysis", [D3])]
        (doc,) = [yaml.safe_load(r.body) for r in _drafted(rows) if r.kind == "sigma"]
        assert doc["logsource"]["category"] == "registry_event"
        assert doc["description"].endswith(f"{key}: observed in {MARK_3}")
