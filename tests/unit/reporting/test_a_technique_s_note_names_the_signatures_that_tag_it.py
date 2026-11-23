"""A published technique is credited with a detonation only by that detonation's signatures' tags.

A technique row carries a detonation's mark only where a sandbox signature of
that detonation carries, in its own technique ids, the technique's id, a
sub-technique's, its parent's, or an id the vendored ATT&CK table says was
revoked in favour of one of these. The reads the row cites and the sandbox
items it names credit nothing. The mark lists those signatures with the id
each tags, and one function words it for every surface: what the sandbox
tagged, by detonation, launch and signature name, never that the behaviour
was observed. A mark stored before the signatures were recorded keeps the
words it was written in; an indicator's mark is untouched (T-871).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.detonation_marks import (
    observed_words,
    technique_words,
    with_technique_marks,
)
from malspark.reporting.evidence_bundles import bundle_for, technique_line
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    ConsolidatedIOC,
    DynamicBehavior,
    EvidenceIndexRow,
    FileHashes,
    MalwareReport,
    ObservedIn,
    SampleIdentity,
    SandboxSignature,
    TaggingSignature,
    TTPMapping,
)
from malspark.reporting.navigator_layer import build_layer
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST

ARGS = "--example-flag on"
D1 = ObservedIn(detonation="d1")
D2 = ObservedIn(detonation="d2", launched_with=ARGS)
CASES = json.loads(
    (Path(__file__).parents[2] / "fixtures" / "reporting" / "technique_note_cases.json").read_text(
        encoding="utf-8"
    )
)["cases"]


def _signature(name: str, tids: list[str], *marks: ObservedIn) -> SandboxSignature:
    return SandboxSignature(name=name, technique_ids=tids, observed_in=list(marks))


def _report(*rows: TTPMapping, signatures: list[SandboxSignature] | None = None) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64)),
        verdict="Malware",
        dynamic=DynamicBehavior(
            sandbox_signatures=signatures
            if signatures is not None
            else [
                _signature("Example signature alpha", ["T1490", "T1070.004"], D2),
                _signature("Example access change", ["T1222"], D2),
                _signature("Example guard switch-off", ["T1562.001"], D2),
                _signature("Example script host", ["T1059.001"], D1, D2),
                _signature("Example unsigned file", [], D1),
            ]
        ),
        evidence_index=[
            # A later detonation's whole signature list, and the job's own.
            EvidenceIndexRow(id="ev_0031", tool="sandbox_signatures", observed_in=[D2]),
            EvidenceIndexRow(id="ev_0014", tool="sandbox_signatures"),
        ],
        ttp_mappings=list(rows),
    )
    with_technique_marks(report.ttp_mappings, report)
    return report


def _marks(report: MalwareReport) -> dict[str, list[ObservedIn]]:
    return {m.technique_id: m.observed_in for m in report.ttp_mappings}


def _tagged(name: str, tid: str, revoked_by: str | None = None) -> TaggingSignature:
    return TaggingSignature(name=name, technique_id=tid, revoked_by=revoked_by)


class TestTheCredit:
    def test_a_signature_tagging_the_technique_s_own_id_credits_its_detonation(self) -> None:
        report = _report(TTPMapping(technique_id="T1490", technique_name="Inhibit System Recovery"))
        assert _marks(report)["T1490"] == [
            ObservedIn(
                detonation="d2",
                launched_with=ARGS,
                signatures=[_tagged("Example signature alpha", "T1490")],
            )
        ]

    def test_a_sub_technique_s_tag_credits_it(self) -> None:
        report = _report(TTPMapping(technique_id="T1070", technique_name="Indicator Removal"))
        assert _marks(report)["T1070"] == [
            ObservedIn(
                detonation="d2",
                launched_with=ARGS,
                signatures=[_tagged("Example signature alpha", "T1070.004")],
            )
        ]

    def test_a_parent_s_tag_credits_it(self) -> None:
        report = _report(TTPMapping(technique_id="T1222.001", technique_name="Windows Permissions"))
        assert _marks(report)["T1222.001"] == [
            ObservedIn(
                detonation="d2",
                launched_with=ARGS,
                signatures=[_tagged("Example access change", "T1222")],
            )
        ]

    def test_an_id_revoked_in_favour_of_it_credits_it(self) -> None:
        from malspark.memory.attck_loader import revoked_by

        successor = revoked_by("T1562.001")
        assert successor, "the vendored table revokes T1562.001"
        report = _report(TTPMapping(technique_id=successor, technique_name="x"))
        assert _marks(report)[successor] == [
            ObservedIn(
                detonation="d2",
                launched_with=ARGS,
                signatures=[_tagged("Example guard switch-off", "T1562.001", successor)],
            )
        ]

    def test_each_detonation_a_signature_is_marked_with_is_credited(self) -> None:
        report = _report(TTPMapping(technique_id="T1059", technique_name="x"))
        tagged = [_tagged("Example script host", "T1059.001")]
        assert _marks(report)["T1059"] == [
            ObservedIn(detonation="d1", signatures=tagged),
            ObservedIn(detonation="d2", launched_with=ARGS, signatures=tagged),
        ]

    def test_a_cited_read_of_a_detonation_credits_nothing(self) -> None:
        report = _report(
            TTPMapping(technique_id="T1486", technique_name="x", sources=["ev_0031", "ev_0014"])
        )
        assert _marks(report)["T1486"] == []

    def test_an_item_id_qualified_or_not_credits_nothing(self) -> None:
        report = _report(
            TTPMapping(technique_id="T1047", technique_name="x", sources=["d2/proc:3", "sig:4"])
        )
        assert _marks(report)["T1047"] == []

    def test_a_sibling_s_tag_credits_nothing(self) -> None:
        report = _report(TTPMapping(technique_id="T1059.003", technique_name="x"))
        assert _marks(report)["T1059.003"] == []

    def test_the_technique_s_own_id_is_listed_before_a_sub_technique_s_it_follows(self) -> None:
        report = _report(
            TTPMapping(technique_id="T1070", technique_name="x"),
            signatures=[_signature("Example signature gamma", ["T1070.004", "T1070"], D2)],
        )
        assert _marks(report)["T1070"] == [
            ObservedIn(
                detonation="d2",
                launched_with=ARGS,
                signatures=[_tagged("Example signature gamma", "T1070")],
            )
        ]

    def test_an_id_as_tagged_is_listed_before_a_revoked_one_it_follows(self) -> None:
        from malspark.memory import attck_loader

        rows = json.loads(attck_loader.RETIRED_IDS_FILE.read_text(encoding="utf-8"))
        retired, successor = next(
            (tid, attck_loader.revoked_by(tid))
            for tid in sorted(rows)
            if not tid.startswith("_") and attck_loader.revoked_by(tid)
        )
        report = _report(
            TTPMapping(technique_id=successor, technique_name="x"),
            signatures=[_signature("Example signature delta", [retired, successor], D2)],
        )
        assert _marks(report)[successor] == [
            ObservedIn(
                detonation="d2",
                launched_with=ARGS,
                signatures=[_tagged("Example signature delta", successor)],
            )
        ]

    def test_two_equal_signature_rows_of_one_detonation_are_listed_once(self) -> None:
        report = _report(
            TTPMapping(technique_id="T1490", technique_name="x"),
            signatures=[
                _signature("Example signature alpha", ["T1490"], D2),
                _signature("Example signature alpha", ["T1490"], D2),
            ],
        )
        assert _marks(report)["T1490"] == [
            ObservedIn(
                detonation="d2",
                launched_with=ARGS,
                signatures=[_tagged("Example signature alpha", "T1490")],
            )
        ]

    def test_a_sandbox_whose_signatures_carry_no_technique_ids_gives_no_note(self) -> None:
        report = _report(
            TTPMapping(technique_id="T1490", technique_name="x", sources=["ev_0031"]),
            signatures=[_signature("Example signature alpha", [], D2)],
        )
        assert _marks(report)["T1490"] == []
        assert "tags this technique" not in MarkdownRenderer().render(report)

    def test_a_run_with_one_detonation_states_no_mark(self) -> None:
        report = _report(
            TTPMapping(technique_id="T1490", technique_name="x"),
            signatures=[_signature("Example signature alpha", ["T1490"])],
        )
        assert _marks(report)["T1490"] == []
        assert "observed_in" not in json.dumps(report.model_dump(mode="json")["ttp_mappings"])


class TestTheWords:
    @pytest.mark.parametrize("case", CASES, ids=[case["case"] for case in CASES])
    def test_each_shape_says_what_the_shared_cases_say(self, case: dict[str, Any]) -> None:
        marks = [ObservedIn.model_validate(mark) for mark in case["observed_in"]]
        assert technique_words(case["technique_id"], marks) == case["words"]
        # A stored report's dicts read the same.
        assert technique_words(case["technique_id"], case["observed_in"]) == case["words"]

    @pytest.mark.parametrize("case", CASES, ids=[case["case"] for case in CASES])
    def test_a_mark_that_lists_its_signatures_never_says_observed(
        self, case: dict[str, Any]
    ) -> None:
        if any(mark.get("signatures") for mark in case["observed_in"]):
            assert "observed" not in case["words"].lower()

    def test_a_launch_text_and_a_name_are_set_as_the_surface_sets_them(self) -> None:
        marks = [ObservedIn(detonation="d2", launched_with="a", signatures=[_tagged("b", "T1490")])]
        said = technique_words("T1486", marks, lambda text: f"<{text}>")
        assert said == "in detonation 2, launched with <a>, the sandbox signature <b> tags T1490"


def _rows_marked() -> MalwareReport:
    return _report(
        TTPMapping(technique_id="T1490", technique_name="Inhibit System Recovery"),
        TTPMapping(technique_id="T1027", technique_name="Obfuscated Files or Information"),
    )


NOTE = (
    f"in detonation 2, launched with `{ARGS}`, the sandbox signature `Example signature alpha` "
    "tags this technique"
)


class TestEverySurfaceWritesIt:
    def test_the_markdown_and_analyst_reports(self) -> None:
        report = _rows_marked()
        assert NOTE in MarkdownRenderer().render(report)
        assert NOTE in MarkdownRenderer(layout=ANALYST).render(report)

    @pytest.mark.parametrize(
        ("section", "field"), [("executive_summary", "top_ttps"), ("mitigations", "ttps")]
    )
    def test_the_composer_s_technique_facts(self, section: str, field: str) -> None:
        listed = bundle_for(section, _rows_marked())["facts"][field]
        assert listed == [
            f"T1490 Inhibit System Recovery ({NOTE})",
            "T1027 Obfuscated Files or Information",
        ]

    def test_the_misp_attribute(self) -> None:
        report = _rows_marked()
        comments = [
            a["comment"]
            for a in build_misp_attributes(report, build_consolidated_iocs(report), owner="unit")
            if a["comment"].startswith("ATT&CK technique")
        ]
        assert any(c.endswith(f"; {NOTE}") for c in comments)
        assert not any("observed" in c for c in comments)

    def test_the_navigator_layer(self) -> None:
        layer = build_layer(_rows_marked().model_dump(mode="json"))
        (t1490,) = [t for t in layer["techniques"] if t["techniqueID"] == "T1490"]
        assert {"name": "sandbox signatures", "value": NOTE} in t1490["metadata"]
        assert all(m["name"] != "observed in" for m in t1490["metadata"])
        (t1027,) = [t for t in layer["techniques"] if t["techniqueID"] == "T1027"]
        assert all(m["name"] != "sandbox signatures" for m in t1027["metadata"])

    def test_the_stix_uses_edge(self) -> None:
        from malspark.reporting.renderers.stix_renderer import (
            _pattern_id_for,
            _with_the_detonations,
        )
        from malspark.schemas.stix_models import Relationship

        uses = Relationship(
            relationship_type="uses",
            source_ref="malware--00000000-0000-4000-8000-000000000000",
            target_ref=_pattern_id_for("T1490"),
        )
        (edge,) = _with_the_detonations([uses], [], _rows_marked())
        assert edge.x_malspark_observed_in == [
            {
                "detonation": "d2",
                "launched_with": ARGS,
                "signatures": [{"name": "Example signature alpha", "technique_id": "T1490"}],
            }
        ]
        assert edge.description == f"{NOTE[:1].upper()}{NOTE[1:]}."


def _stored() -> MalwareReport:
    """A report stored with a technique's mark from before its signatures were recorded."""
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64)),
        verdict="Malware",
        ttp_mappings=[
            TTPMapping(
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                observed_in=[D1, D2],
            )
        ],
    )


OLD = f"observed in the job's own detonation and in detonation 2, launched with `{ARGS}`"


class TestAStoredReportReadsAsWritten:
    def test_its_words_are_the_words_it_was_written_in(self) -> None:
        report = _stored()
        assert OLD in MarkdownRenderer().render(report)
        assert OLD in MarkdownRenderer(layout=ANALYST).render(report)
        assert technique_line(report.ttp_mappings[0]) == f"T1486 Data Encrypted for Impact ({OLD})"
        layer = build_layer(report.model_dump(mode="json"))
        assert {"name": "observed in", "value": OLD.removeprefix("observed in ")} in layer[
            "techniques"
        ][0]["metadata"]
        comments = [a["comment"] for a in build_misp_attributes(report, [], owner="unit")]
        assert any(c.endswith(f"; {OLD}") for c in comments)

    def test_its_stix_edge_carries_the_mark_and_no_words(self) -> None:
        from malspark.reporting.renderers.stix_renderer import (
            _pattern_id_for,
            _with_the_detonations,
        )
        from malspark.schemas.stix_models import Relationship

        uses = Relationship(
            relationship_type="uses",
            source_ref="malware--00000000-0000-4000-8000-000000000000",
            target_ref=_pattern_id_for("T1486"),
        )
        (edge,) = _with_the_detonations([uses], [], _stored())
        assert edge.x_malspark_observed_in == [
            {"detonation": "d1"},
            {"detonation": "d2", "launched_with": ARGS},
        ]
        assert edge.description is None


class TestAnIndicatorsMarkIsUntouched:
    def test_an_indicator_row_s_mark_and_words_are_as_they_were(self) -> None:
        row = ConsolidatedIOC(
            type="Domain", kind="domain", value="pay.example.org", observed_in=[D1, D2]
        )
        assert row.model_dump()["observed_in"] == [
            {"detonation": "d1"},
            {"detonation": "d2", "launched_with": ARGS},
        ]
        assert observed_words(row.observed_in) == OLD

    def test_a_technique_s_words_are_not_an_indicator_s(self) -> None:
        report = _rows_marked()
        (mark,) = report.ttp_mappings[0].observed_in
        bare = mark.model_copy(update={"signatures": []})
        # The indicator's writer words a technique's mark as an indicator's,
        # whatever it lists: the two writers are apart.
        assert observed_words([mark]) == observed_words([bare])


class TestTheSectionAgreementRoundIsShownNoTechniqueMark:
    def test_its_passages_are_the_same_with_and_without_the_marks(self) -> None:
        from malspark.reporting.section_agreement import passages_of

        marked = _rows_marked()
        bare = marked.model_copy(deep=True)
        for mapping in bare.ttp_mappings:
            mapping.observed_in = []
        assert marked.ttp_mappings[0].observed_in

        def texts(report: MalwareReport) -> list[str]:
            return [repr(passage) for passage in passages_of(report)]

        # The analyst report the round reads its verbatim texts off prints the note.
        assert NOTE in MarkdownRenderer(layout=ANALYST).render(marked)
        assert texts(marked) == texts(bare)
        assert "Example signature alpha" not in json.dumps(texts(marked))
