"""The flagged statements the API serves are the marks the report prints (T-782b).

A stored mark of a value the run does not publish is read again against the
served IOC table, as the render reads it (``renderers.markdown``): a mark the
render drops is not served as standing, and a served label is the render's
label. Where the sentence cannot be read again the stored row is served as
stored, and the stored report is never rewritten. Every value here is a
neutral synthetic one.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from app.services import report_service
from app.services.report_service import with_current_iocs
from malspark.pipeline import validation
from malspark.reporting.models import (
    ConsolidatedIOC,
    FileHashes,
    FlaggedStatement,
    MalwareReport,
    SampleIdentity,
)
from malspark.reporting.renderers import stix_renderer as S

FACT = "the sandbox report does not say which process made the flows to it"
UNSTATED = "The sample asks 8.8.8.8 for names during the run."
STATED = f"The sample asks 8.8.8.8 for names (no: {S.PUBLIC_RESOLVER}) during the run."
OTHER = "It calls the routine at 0x401000 [ev_0001]."


def _stored() -> dict[str, Any]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        flagged_statements=[
            FlaggedStatement(
                sentence=UNSTATED,
                code=validation.UNPUBLISHED_VALUE_CODE,
                label=f"8.8.8.8 (no: {FACT})",
                asked=False,
            ),
            FlaggedStatement(
                sentence=STATED,
                code=validation.UNPUBLISHED_VALUE_CODE,
                label=f"8.8.8.8 (no: {FACT})",
            ),
            FlaggedStatement(
                sentence=OTHER, code="report.citation_wrong_entry", label=f"8.8.8.8 (no: {FACT})"
            ),
        ],
    )
    return report.model_dump(mode="json")


@pytest.fixture
def table(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = S.public_resolver_reason(FACT)
    rows = [
        ConsolidatedIOC(type="IPv4", kind="ip", value="8.8.8.8", source="sandbox", published=answer)
    ]
    monkeypatch.setattr(report_service, "ioc_table", lambda report: list(rows))


def _served(stored: dict[str, Any]) -> list[dict[str, Any]]:
    served, _note = with_current_iocs(stored, "a-report-id")
    return list(served["flagged_statements"])


@pytest.mark.usefixtures("table")
def test_a_stored_label_is_served_as_the_render_labels_it() -> None:
    served = _served(_stored())

    assert served[0] == {
        "sentence": UNSTATED,
        "code": validation.UNPUBLISHED_VALUE_CODE,
        "label": f"8.8.8.8 (no: {S.PUBLIC_RESOLVER})",
        "asked": False,
    }


@pytest.mark.usefixtures("table")
def test_a_mark_the_render_drops_is_not_served() -> None:
    served = _served(_stored())

    assert [row["sentence"] for row in served] == [UNSTATED, OTHER]


@pytest.mark.usefixtures("table")
def test_a_mark_of_another_code_is_served_as_stored() -> None:
    served = _served(_stored())

    assert served[-1]["label"] == f"8.8.8.8 (no: {FACT})"


@pytest.mark.usefixtures("table")
def test_a_sentence_that_cannot_be_read_again_is_served_as_stored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unread(*_args: Any) -> list[tuple[str, str, str]]:
        raise RuntimeError("unread")

    monkeypatch.setattr(validation, "_unstated_values", unread)
    stored = _stored()

    assert _served(stored) == stored["flagged_statements"]


@pytest.mark.usefixtures("table")
def test_the_stored_report_is_not_rewritten() -> None:
    stored = _stored()
    before = copy.deepcopy(stored)

    _served(stored)

    assert stored == before
