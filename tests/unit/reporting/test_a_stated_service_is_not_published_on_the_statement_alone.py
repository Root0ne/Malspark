"""A service the analysis states is not published on its statement alone.

A service row that every earlier check lets through (typed and stated as
created or written, held whole in an entry it cites, not a service Microsoft
ships as part of Windows, a verdict that publishes) is refused: the statement
does not tell a service the sample installed from one that already existed.
The refusal is a sentence about the rule and the statement, so it stays true
whatever the record holds, an entry that lists the name among the services
installed included, cited or not. The row leaves the IOC table's published
rows, ``/iocs`` and MISP, and the identifier table prints it with its refusal.

The earlier refusals keep their order and their words. Every other kind is
answered as before, a scheduled task of the same shape still builds its
creation draft, and no sentence is left that names where a published service
is carried. The refusal reaches no model: the prose check reads network values
only.
"""

from __future__ import annotations

import json

import pytest

from malspark.pipeline.validation import EntryTexts, unpublished_value_violations
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs, full_ioc_list
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.narrative_agent import published_answers
from malspark.reporting.renderers.stix_renderer import publishes
from malspark.reporting.stated_host_values import identifier_answers, with_held_in

REFUSED = (
    "no: a service is not published on the analysis's statement alone, since the statement "
    "does not tell a service the sample installed from one that already existed"
)
SERVICE = "ExampleBackupSvc"
TASK = "ExampleTask7731"
# Rows of the other kinds, each a value no list holds.
OTHERS = [
    ("alternate data stream", ":example7731"),
    ("named pipe", "\\\\.\\pipe\\examplepipe_7731"),
    ("file name", "example_data7731.dat"),
    ("folder", "C:\\ExampleStage7731"),
    ("registry value", "HKCU\\Software\\Example7731\\Stage"),
]
# Those of them STIX has no object for, whose answer closes with where the value is carried.
NO_STIX_OBJECT_KINDS = {"alternate data stream", "named pipe"}
# An entry that lists the name among the services installed, as an item of the
# platform's sandbox document carries its place.
INSTALLED = json.dumps(
    {
        "items": [
            {
                "kind": "created_services",
                "source": "behavior.summary.created_services[0]",
                "value": SERVICE,
            }
        ]
    }
).lower()


def _report(
    rows: list[tuple[str, str]],
    *,
    use: str = "creates/writes",
    verdict: str = "Malware",
    cited: str = "ev_0021",
    texts: dict[str, str] | None = None,
) -> MalwareReport:
    entries = EntryTexts(
        texts=texts or {"ev_0021": json.dumps([value for _, value in rows]).lower()}
    )
    identifiers = [
        HostIdentifier(kind=kind, value=value, use=use, evidence_refs=[cited])
        for kind, value in rows
    ]
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict=verdict,
        overall_confidence=0.9,
        malware_category="loader",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in(identifiers, entries)),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return MalwareReportBuilder.attach_detection_signatures(report)


def _answer(report: MalwareReport, value: str) -> str:
    return next(answer for stated, answer in identifier_answers(report) if stated.value == value)


def _sigma(report: MalwareReport) -> dict[str, str]:
    return {rule.name: rule.body for rule in report.detection_signatures if rule.kind == "sigma"}


class TestAStatedServiceIsRefused:
    def test_held_whole_and_stated_as_created_it_is_refused_with_the_rule_s_words(self) -> None:
        report = _report([("service", SERVICE)])
        (stated,) = [s for s, _ in identifier_answers(report)]

        assert stated.held_in == ("ev_0021",)
        assert _answer(report, SERVICE) == REFUSED

    def test_it_is_in_no_published_row_and_no_misp_attribute(self) -> None:
        report = _report([("service", SERVICE)])

        assert not [r for r in report.consolidated_iocs if r.value == SERVICE]
        assert not [a for a in build_misp_attributes(report, owner="test") if a["value"] == SERVICE]

    def test_the_full_list_keeps_it_unpublished_with_the_refusal(self) -> None:
        report = _report([("service", SERVICE)])
        (row,) = [r for r in full_ioc_list(report) if r.value == SERVICE]

        assert not publishes(row.published)
        assert row.published == REFUSED

    def test_a_cited_entry_that_lists_it_among_the_services_installed_changes_nothing(
        self,
    ) -> None:
        report = _report([("service", SERVICE)], texts={"ev_0021": INSTALLED})
        (stated,) = [s for s, _ in identifier_answers(report)]

        assert stated.held_in == ("ev_0021",)
        assert _answer(report, SERVICE) == REFUSED

    def test_an_uncited_entry_that_lists_it_among_the_services_installed_changes_nothing(
        self,
    ) -> None:
        texts = {"ev_0021": json.dumps([SERVICE]).lower(), "ev_0031": INSTALLED}
        report = _report([("service", SERVICE)], texts=texts)

        assert _answer(report, SERVICE) == REFUSED

    def test_the_words_speak_of_the_statement_never_of_the_record(self) -> None:
        assert "record" not in REFUSED
        assert "statement" in REFUSED

    def test_a_generic_named_service_is_refused_alike(self) -> None:
        report = _report([("service", "Updater")])

        assert _answer(report, "Updater") == REFUSED


class TestTheEarlierRefusalsKeepTheirWords:
    def test_a_service_microsoft_ships_keeps_the_list_s_criterion(self) -> None:
        report = _report([("service", "WbioSrvc")])

        assert _answer(report, "WbioSrvc") == "no: a service Microsoft ships as part of Windows"

    def test_a_use_the_analysis_does_not_show_keeps_its_words(self) -> None:
        report = _report([("service", SERVICE)], use="not shown")

        assert _answer(report, SERVICE) == (
            "no: the analysis does not show the sample creating or writing it"
        )

    def test_a_value_no_cited_entry_holds_keeps_its_words(self) -> None:
        report = _report([("service", SERVICE)], texts={"ev_0021": '["examplebackupsvc2"]'})

        assert _answer(report, SERVICE).startswith("no: a cited entry holds its text only inside")

    def test_a_benign_verdict_keeps_its_words(self) -> None:
        report = _report([("service", SERVICE)], verdict="Benign")

        assert _answer(report, SERVICE) == (
            "no: the verdict is Benign, which publishes no malicious indicator"
        )


class TestEveryOtherKindIsAnsweredAsBefore:
    def test_a_task_of_the_same_shape_publishes_and_builds_its_creation_draft(self) -> None:
        report = _report([("scheduled task", TASK), ("service", SERVICE)])
        date = report.generated_at.strftime("%Y/%m/%d")

        assert _answer(report, TASK) == (
            "yes: stated by the analysis (scheduled task, creates/writes), found whole in "
            "ev_0021; no STIX object for this kind; carried by /iocs, MISP and Sigma"
        )
        assert [
            a["to_ids"] for a in build_misp_attributes(report, owner="t") if a["value"] == TASK
        ] == [True]
        assert list(_sigma(report).values()) == [
            "title: Malspark AutoGen - loader (scheduled tasks)\n"
            "id: 5a1e035d-8ab6-0ded-5579-20e902131cf7\n"
            "status: experimental\n"
            "description: Auto-generated for sha256 777777777777\n"
            "author: Malspark Auto-Generator\n"
            f"date: {date}\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection_task:\n"
            "    EventID: 4698\n"
            "    TaskName|endswith:\n"
            "    - \\ExampleTask7731\n"
            "  condition: selection_task\n"
            "falsepositives:\n"
            "- Legitimate software installers\n"
            "- Unknown\n"
            "level: high\n"
        ]

    def test_a_pipe_beside_it_keeps_its_draft(self) -> None:
        report = _report([("named pipe", "\\\\.\\pipe\\examplepipe_7731"), ("service", SERVICE)])
        date = report.generated_at.strftime("%Y/%m/%d")

        assert list(_sigma(report).values()) == [
            "title: Malspark AutoGen - loader (named pipes)\n"
            "id: 67ac23b7-bd21-316a-45ba-4f20c8fcb14c\n"
            "status: experimental\n"
            "description: Auto-generated for sha256 777777777777\n"
            "author: Malspark Auto-Generator\n"
            f"date: {date}\n"
            "logsource:\n"
            "  product: windows\n"
            "  category: pipe_created\n"
            "detection:\n"
            "  selection_pipe:\n"
            "    PipeName:\n"
            "    - \\examplepipe_7731\n"
            "  condition: selection_pipe\n"
            "falsepositives:\n"
            "- Legitimate software installers\n"
            "- Unknown\n"
            "level: high\n"
        ]

    @pytest.mark.parametrize(("kind", "value"), OTHERS)
    def test_another_kind_is_published_as_before(self, kind: str, value: str) -> None:
        report = _report([(kind, value)])

        said = f"yes: stated by the analysis ({kind}, creates/writes), found whole in ev_0021"
        if kind in NO_STIX_OBJECT_KINDS:
            said += "; no STIX object for this kind; carried by /iocs, MISP and Sigma"
        assert _answer(report, value) == said

    def test_beside_a_service_the_other_kinds_keep_their_answers_drafts_and_attributes(
        self,
    ) -> None:
        alone = _report(OTHERS)
        beside = _report([*OTHERS, ("service", SERVICE)])

        assert [a for s, a in identifier_answers(beside) if s.value != SERVICE] == [
            a for _, a in identifier_answers(alone)
        ]
        assert _sigma(beside) == _sigma(alone)
        assert build_misp_attributes(beside, owner="t") == build_misp_attributes(alone, owner="t")


class TestNoSentenceOfAPublishedServiceIsLeft:
    def test_alone_the_no_draft_sentence_names_no_service(self) -> None:
        report = _report([("service", SERVICE)])

        assert _sigma(report) == {}
        (item,) = report.drafts_not_built
        assert item.why == (
            "no registry key, image path, file, folder, stream, scheduled task, service or "
            "named pipe that this run publishes or a sandbox watched is left to select on"
        )

    def test_a_generic_name_of_another_kind_keeps_its_clause_and_ends_the_sentence(self) -> None:
        report = _report([("scheduled task", "Updater"), ("service", SERVICE)])

        (item,) = report.drafts_not_built
        assert item.why.endswith(
            "; the value the analysis states is a name ordinary software also uses, which is "
            "never selected on alone"
        )

    def test_the_only_closing_clause_left_names_sigma(self) -> None:
        from malspark.reporting import stated_host_values

        assert not hasattr(stated_host_values, "NO_STIX_OBJECT_NO_SIGMA")
        assert (
            stated_host_values.NO_STIX_OBJECT
            == "no STIX object for this kind; carried by /iocs, MISP and Sigma"
        )

    def test_every_exported_kind_without_a_stix_object_is_one_a_draft_selects_on(self) -> None:
        from malspark.reporting.detection_signatures import (
            _STATED_FIELDS,
            _STATED_REGISTRY_KINDS,
        )
        from malspark.reporting.stated_host_values import host_kinds

        drafted = set(_STATED_FIELDS) | _STATED_REGISTRY_KINDS
        exported = {k.table_kind for k in host_kinds().values() if k.table_kind}
        # A mutex is a STIX indicator; a service is never exported.
        assert exported - drafted == {"mutex", "service"}


class TestTheRefusalReachesNoModel:
    def test_the_prose_check_tells_no_service_back(self) -> None:
        report = _report([("service", SERVICE)])
        payload = {
            "body": f"It stops {SERVICE} and sets its start to disabled.",
            "evidence_refs": [],
        }

        assert unpublished_value_violations(payload, published_answers(report)) == []

    def test_the_composer_s_text_holds_no_word_of_it(self) -> None:
        from malspark.reporting import composer

        shown = json.dumps(
            [composer._INSTRUCTIONS["host_identifiers"], composer._EXAMPLES["host_identifiers"]]
        )
        assert "statement alone" not in shown
