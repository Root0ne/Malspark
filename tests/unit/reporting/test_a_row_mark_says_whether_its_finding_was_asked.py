"""A configuration or identifier row's mark says whether its finding was ever asked.

A finding first raised by the answer to a section's only retry is recorded as
not asked (``"asked": "false"``), but the table rows it names printed the same
"(unresolved: …)" as a row the model was asked about and kept. The mark now
reads the row's record: a finding never asked says so. A row whose value a
cited entry holds only inside a longer run of text, kept after the run was
shown, is printed where its table prints, the analyst report too, with a mark
saying so; one first raised with no turn left is marked as not asked and left
to the bundle.
"""

from __future__ import annotations

from typing import Any

from malspark.pipeline.validation import (
    STATED_VALUE_INSIDE_A_TOKEN_CODE,
    STATED_VALUE_UNHELD_CODE,
    UNCITED_CONFIGURATION_CODE,
    UNCITED_IDENTIFIER_CODE,
)
from malspark.reporting.models import (
    ConfigItem,
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers.markdown import MarkdownRenderer


def _rendered(*rows: dict[str, Any]) -> tuple[str, str]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            configuration=[
                ConfigItem(
                    key="Interval",
                    value="7000",
                    how_obtained="decrypted",
                    evidence_refs=["ev_0020"],
                )
            ],
            host_identifiers=[
                HostIdentifier(kind="file name", value="ExampleNote.txt", evidence_refs=["ev_0005"])
            ],
        ),
        run_summary={
            "validation": {"unresolved": [{"agent": "composer:x", **row} for row in rows]}
        },
    )
    text = MarkdownRenderer().render(report)
    config = next(line for line in text.splitlines() if line.startswith("| Interval"))
    host = next(line for line in text.splitlines() if "ExampleNote.txt" in line)
    return config, host


def test_identifier_row_mark_says_not_asked_for_a_finding_born_in_the_retry() -> None:
    _config, host = _rendered(
        {
            "code": STATED_VALUE_UNHELD_CODE,
            "message": "identifier 1 (x: 'y') is in …",
            "asked": "false",
        },
        {
            "code": UNCITED_IDENTIFIER_CODE,
            "message": "identifier 1 cites nothing …",
            "asked": "false",
        },
    )

    assert f"(unresolved, not asked: {STATED_VALUE_UNHELD_CODE})" in host
    assert f"(unresolved, not asked: {UNCITED_IDENTIFIER_CODE})" in host


def test_configuration_row_mark_says_not_asked_for_a_finding_born_in_the_retry() -> None:
    config, _host = _rendered(
        {
            "code": STATED_VALUE_UNHELD_CODE,
            "message": "configuration items 1, 3 are each in none …",
            "asked": "false",
        },
        {
            "code": UNCITED_CONFIGURATION_CODE,
            "message": "configuration item 1 cites nothing …",
            "asked": "false",
        },
    )

    assert f"(unresolved, not asked: {STATED_VALUE_UNHELD_CODE})" in config
    assert f"(unresolved, not asked: {UNCITED_CONFIGURATION_CODE})" in config


def test_a_row_the_model_was_asked_about_keeps_its_mark() -> None:
    config, host = _rendered(
        {"code": STATED_VALUE_UNHELD_CODE, "message": "configuration item 1 (a: 'b') is in …"},
        {"code": STATED_VALUE_UNHELD_CODE, "message": "identifier 1 (a: 'b') is in …"},
    )

    assert f"ev_0020 (unresolved: {STATED_VALUE_UNHELD_CODE})" in config
    assert f"ev_0005 (unresolved: {STATED_VALUE_UNHELD_CODE})" in host
    assert "not asked" not in config + host


def test_one_asked_finding_naming_the_row_makes_its_mark_asked() -> None:
    _config, host = _rendered(
        {"code": STATED_VALUE_UNHELD_CODE, "message": "identifier 1 (a: 'b') is in …"},
        {
            "code": STATED_VALUE_UNHELD_CODE,
            "message": "identifier 1 (a: 'c') is in …",
            "asked": "false",
        },
    )

    assert f"(unresolved: {STATED_VALUE_UNHELD_CODE})" in host
    assert "not asked" not in host


def test_a_row_kept_after_the_run_was_shown_says_so() -> None:
    config, host = _rendered(
        {
            "code": STATED_VALUE_INSIDE_A_TOKEN_CODE,
            "message": "identifier 1 (file name: 'ExampleNote.txt') stands in ev_0005 …",
        },
    )

    assert (
        "ev_0005 (the cited entry holds this text inside a longer run; kept after the run was "
        f"shown: {STATED_VALUE_INSIDE_A_TOKEN_CODE})"
    ) in host
    assert STATED_VALUE_INSIDE_A_TOKEN_CODE not in config


def test_a_row_inside_a_run_never_asked_says_so() -> None:
    _config, host = _rendered(
        {
            "code": STATED_VALUE_INSIDE_A_TOKEN_CODE,
            "message": "identifier 1 (file name: 'ExampleNote.txt') stands in ev_0005 …",
            "asked": "false",
        },
    )

    assert (
        "ev_0005 (the cited entry holds this text inside a longer run; not asked: "
        f"{STATED_VALUE_INSIDE_A_TOKEN_CODE})"
    ) in host


def _two_tables(asked: bool) -> MalwareReport:
    flag = {} if asked else {"asked": "false"}
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            configuration=[
                ConfigItem(
                    key="Interval",
                    value="7000",
                    how_obtained="decrypted",
                    evidence_refs=["ev_0020"],
                ),
                ConfigItem(
                    key="Note",
                    value="ExampleNote.txt",
                    how_obtained="decrypted",
                    evidence_refs=["ev_0020"],
                ),
            ],
            host_identifiers=[
                HostIdentifier(
                    kind="file name",
                    value="ExampleKept.txt",
                    purpose="ransom note",
                    evidence_refs=["ev_0005"],
                ),
                HostIdentifier(
                    kind="file name",
                    value="ExampleRunOn.txt",
                    purpose="ransom note",
                    evidence_refs=["ev_0005"],
                ),
            ],
        ),
        run_summary={
            "validation": {
                "unresolved": [
                    {
                        "agent": "composer:host_identifiers",
                        "code": STATED_VALUE_INSIDE_A_TOKEN_CODE,
                        "message": "identifier 2 (file name: 'ExampleRunOn.txt') stands in …",
                        **flag,
                    },
                    {
                        "agent": "composer:configuration",
                        "code": STATED_VALUE_INSIDE_A_TOKEN_CODE,
                        "message": "configuration item 2 (Note: 'ExampleNote.txt') stands in …",
                        **flag,
                    },
                ]
            }
        },
    )


_KEPT_MARK = "the cited entry holds this text inside a longer run; kept after the run was shown"


def test_the_analyst_report_prints_a_row_kept_after_the_run_was_shown() -> None:
    from malspark.reporting.renderers.layout import ANALYST

    analyst = MarkdownRenderer(layout=ANALYST).render(_two_tables(asked=True))

    note = next(line for line in analyst.splitlines() if "ExampleNote.txt" in line)
    run_on = next(line for line in analyst.splitlines() if "ExampleRunOn.txt" in line)
    assert _KEPT_MARK in note
    assert _KEPT_MARK in run_on
    kept = next(line for line in analyst.splitlines() if "ExampleKept.txt" in line)
    assert _KEPT_MARK not in kept


def test_the_analyst_report_leaves_a_row_never_asked_to_the_bundle() -> None:
    from malspark.reporting.renderers.layout import ANALYST

    analyst = MarkdownRenderer(layout=ANALYST).render(_two_tables(asked=False))

    assert "7000" in analyst
    assert "ExampleNote.txt" not in analyst
    assert "ExampleKept.txt" in analyst
    assert "ExampleRunOn.txt" not in analyst
