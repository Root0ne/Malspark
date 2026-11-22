"""A value only a sandbox signature's indicators hold keeps its standing; any other text does not.

A sighting gives a listed value the string sweep's standing (``strings``)
wherever an answer's text holds it, a sandbox's answer included: a
signature's description, a command line, the sample's strings a sandbox
re-serves, the file's own strings. The one exception is the part of an answer
its kind declares a structured record (``RECORD_PARTS_OF_KIND``: a signature
view's indicators): a value an analyst listed that an answer holds only there
keeps the analyst's standing and the decision it has where no answer holds it
(the judge's keep), and the reason still names the entry. The kind decides,
never the tool's name.

Every value here is synthetic: routable addresses the reference run never
reached, and example names.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.renderers.stix_renderer import publishes
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, Artifact

NAME = "relay-alpha-7f3c.top"
ADDRESS = "185.199.110.77"


# What the publish rule's whole-value search for a listed value read, as its fact names it.
SEARCH = (
    "the publish rule's whole-value search of the kept text of the run's successful tool "
    "answers, which sets apart an answer to a call whose arguments hold it,"
)


def _entry(entry_id: str, tool: str, structured: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="dynamic", tool=tool, structured=structured)


def _indicator_entry(entry_id: str = "ev_0007") -> LedgerEntry:
    """A signatures answer whose only mention of the values is one indicator's."""
    return _entry(
        entry_id,
        "sandbox_signatures",
        {
            "signatures": [{"name": "Contacts a host", "indicators": 1}],
            "total": 1,
            "indicators": [
                {
                    "signature": "Contacts a host",
                    "process": {"id": "84", "image": "powershell.exe"},
                    "values": {"domain": NAME, "dst": ADDRESS},
                }
            ],
        },
    )


def _strings_entry() -> LedgerEntry:
    """The file's strings, printing the name."""
    return _entry("ev_0002", "strings", {"strings": [{"offset": "0x40", "string": NAME}]})


def _kept() -> dict[str, Any]:
    patterns = [f"[domain-name:value = '{NAME}']", f"[ipv4-addr:value = '{ADDRESS}']"]
    return {
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--0f1e2d3c-4b5a-4968-8776-65544333221{i}",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": "2026-01-01T00:00:00Z",
            }
            for i, pattern in enumerate(patterns)
        ]
    }


def _listed() -> dict[str, Any]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            artifacts=[
                Artifact(
                    kind="endpoints",
                    rows=[["domain", NAME], ["ip", ADDRESS]],
                    evidence_ids=[],
                    source="static",
                )
            ],
        )
    }


def _build(
    ledger: list[LedgerEntry],
    listed: dict[str, Any] | None = None,
    kept: dict[str, Any] | None = None,
) -> Any:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=_listed() if listed is None else listed,
        stix_output=_kept() if kept is None else kept,
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=ledger,
    ).build_deterministic()


def _published(report: Any, value: str) -> str:
    (row,) = [r for r in report.consolidated_iocs if r.value == value]
    return str(row.published)


def _sources(report: Any) -> dict[str, str]:
    network = report.network
    assert network is not None
    return {
        **{d.fqdn: d.source for d in network.domains},
        **{i.address: i.source for i in network.ips},
    }


def _signatures_answer() -> dict[str, Any]:
    """The signature view's answer over a report whose marks alone name the two values."""
    from malspark.providers.sandbox.readers import required_reader
    from malspark.providers.sandbox_tools import sandbox_signatures
    from malspark.schemas.sandbox_document import sandbox_document

    payload = {
        "info": {"id": 7},
        "behavior": {"processes": [{"process_id": 1000, "parent_id": 4, "process_name": "a.exe"}]},
        "signatures": [
            {
                "name": "network_contact",
                "severity": 2,
                "description": "Contacts a host",
                "data": [
                    {"type": "ioc", "pid": 1000, "category": "domain", "ioc": NAME},
                    {"type": "ioc", "pid": 1000, "category": "ip", "ioc": ADDRESS},
                ],
            }
        ],
    }
    report = required_reader("cape2").read(payload, provider="cape")
    answer: dict[str, Any] = sandbox_signatures(
        sandbox_document(report), normalised_by=("cape", "cape2")
    )
    return answer


class TestTheSignatureView:
    """The view's own answer, as the ledger records it: decided as where no answer holds them."""

    def test_values_its_indicators_alone_hold_are_published_on_the_judge_s_keep(self) -> None:
        report = _build([_entry("ev_0007", "sandbox_signatures", _signatures_answer())])

        assert _sources(report) == {NAME: "analyst", ADDRESS: "analyst"}
        for value in (NAME, ADDRESS):
            assert publishes(_published(report, value)), value


class TestAValueOnlyTheIndicatorsHold:
    def test_it_keeps_the_analyst_s_standing_and_the_judge_s_keep_publishes_it(self) -> None:
        report = _build([_indicator_entry()])

        assert _sources(report) == {NAME: "analyst", ADDRESS: "analyst"}
        for value in (NAME, ADDRESS):
            assert publishes(_published(report, value)), value

    def test_it_decides_as_a_value_no_answer_holds(self) -> None:
        held = _build([_indicator_entry()])
        unheld = _build([])

        for value in (NAME, ADDRESS):
            assert _published(held, value) == _published(unheld, value), value

    def test_the_search_still_names_the_entry_that_holds_it(self) -> None:
        report = _build([_indicator_entry()])

        assert report.tool_sightings[NAME] == [("ev_0007", "sandbox_signatures")]


def _text_sightings() -> dict[str, LedgerEntry]:
    from tests.unit.reporting.test_a_text_sighting_is_no_sandbox_observation import (
        _TEXT_SIGHTINGS,
    )

    return {**_TEXT_SIGHTINGS, "the file's strings": _strings_entry()}


class TestEveryOtherText:
    """Kept by the judge, a value any other text holds is a string sighting, as it always was."""

    @pytest.mark.parametrize(
        "what",
        [
            "a signature's description",
            "a command line",
            "the sample's strings the sandbox re-serves",
            "the file's strings",
        ],
    )
    def test_it_is_a_string_sighting_and_not_published(self, what: str) -> None:
        entry = _text_sightings()[what]
        report = _build([entry])

        held = {NAME} if what == "the file's strings" else {NAME, ADDRESS}
        for value in held:
            assert _sources(report)[value] == "strings", value
            answer = _published(report, value)
            assert not publishes(answer), value
            assert answer.startswith("no: its row's source is strings and ")
            assert f"{SEARCH} found it in {entry.id} ({entry.tool})" in answer

    def test_a_signature_answer_holding_it_in_its_description_too_is_one(self) -> None:
        entry = _indicator_entry()
        assert isinstance(entry.structured, dict)
        entry.structured["signatures"][0]["description"] = f"Contacts {NAME}"
        report = _build([entry])

        assert _sources(report) == {NAME: "strings", ADDRESS: "analyst"}
        assert not publishes(_published(report, NAME))
        assert publishes(_published(report, ADDRESS))

    def test_beside_the_indicators_it_is_one(self) -> None:
        report = _build([_strings_entry(), _indicator_entry()])

        assert _sources(report) == {NAME: "strings", ADDRESS: "analyst"}
        assert _published(report, NAME).startswith("no: its row's source is strings and ")
        assert f"{SEARCH} found it in ev_0002 (strings)" in _published(report, NAME)


def _live_document(indicator: dict[str, Any]) -> dict[str, Any]:
    """The live Triage report, its write-into-memory signature holding ``indicator``."""
    import json
    from pathlib import Path

    from malspark.providers.sandbox.readers import required_reader
    from malspark.schemas.sandbox_document import sandbox_document

    live = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox" / "triage_live"
    task = json.loads((live / "behavioral1.json").read_text(encoding="utf-8"))
    overview = json.loads((live / "overview.json").read_text(encoding="utf-8"))
    (row,) = [s for s in task["signatures"] if s["name"] == "Suspicious use of WriteProcessMemory"]
    row["indicators"] = [indicator]
    report = required_reader("triage").read(
        overview, provider="triage", task_id="s1", task_reports={"behavioral1": task}
    )
    return sandbox_document(report)


class TestEveryViewOfTheIndicators:
    """The item reader and the paged call answer the same records, decided as none holds them."""

    INDICATOR = {"procid": 84, "procid_target": 86, "dst": ADDRESS, "domain": NAME}

    def test_the_item_reader_s_answer(self) -> None:
        from malspark.providers.sandbox_tools import sandbox_items

        answer = sandbox_items(
            _live_document(self.INDICATOR),
            "signatures",
            normalised_by=("triage", "triage", "tasks"),
        )
        report = _build([_entry("ev_0005", "sandbox_items", answer)])

        assert _sources(report) == {NAME: "analyst", ADDRESS: "analyst"}
        for value in (NAME, ADDRESS):
            assert publishes(_published(report, value)), value

    def test_the_paged_call_s_answer(self) -> None:
        from malspark.providers.sandbox_tools import sandbox_signatures

        answer = sandbox_signatures(
            _live_document(self.INDICATOR),
            normalised_by=("triage", "triage", "tasks"),
            signature="Suspicious use of WriteProcessMemory",
        )
        report = _build([_entry("ev_0006", "sandbox_signatures", answer)])

        for value in (NAME, ADDRESS):
            assert publishes(_published(report, value)), value


class TestAnotherSpellingOutsideTheIndicators:
    """Held outside the record in another spelling, a value is still a string sighting."""

    @pytest.mark.parametrize(
        ("value", "spelled"),
        [
            (ADDRESS, f"[{ADDRESS}]"),
            (NAME, NAME.upper()),
            (NAME, f"{NAME}."),
        ],
        ids=["bracketed address", "upper-case name", "name with a trailing dot"],
    )
    def test_it_is_a_string_sighting(self, value: str, spelled: str) -> None:
        entry = _indicator_entry()
        assert isinstance(entry.structured, dict)
        entry.structured["signatures"][0]["description"] = f"Contacts {spelled} now"
        report = _build([entry])

        assert _sources(report)[value] == "strings"
        assert not publishes(_published(report, value))


class TestAUrlOutsideTheIndicators:
    def test_a_url_a_description_holds_with_its_path_s_case_is_a_string_sighting(self) -> None:
        url = f"http://{NAME}/Gate.php"
        entry = _indicator_entry()
        assert isinstance(entry.structured, dict)
        entry.structured["signatures"][0]["description"] = f"Posts to {url}"
        listed = _listed()
        listed["static"].artifacts[0].rows.append(["url", url])
        report = MalwareReportBuilder(
            file_hash="a" * 64,
            file_name="fixture.bin",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports=listed,
            stix_output=_kept(),
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.8,
            sample_platform="windows",
            sample_file_type="PE",
            evidence_ledger=[entry],
        ).build_deterministic()
        assert report.network is not None
        (row,) = [u for u in report.network.urls if u.url == url]
        assert row.source == "strings"


def _listing(kind: str, value: str, pattern: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """An analyst listing ``value`` alone and the judge keeping it by ``pattern``."""
    listed = {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            artifacts=[
                Artifact(kind="endpoints", rows=[[kind, value]], evidence_ids=[], source="static")
            ],
        )
    }
    kept = {
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332210",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": "2026-01-01T00:00:00Z",
            }
        ]
    }
    return listed, kept


def _one_indicator(values: dict[str, str], description: str) -> LedgerEntry:
    """A signatures answer: one indicator stating ``values``, its signature described."""
    return _entry(
        "ev_0007",
        "sandbox_signatures",
        {
            "signatures": [
                {"name": "Contacts a host", "description": description, "indicators": 1}
            ],
            "total": 1,
            "indicators": [
                {
                    "signature": "Contacts a host",
                    "process": {"id": "84", "image": "powershell.exe"},
                    "values": values,
                }
            ],
        },
    )


class TestAValueEndingInADot:
    """Searched outside the record as the string sighting is searched: its trailing dot off."""

    URL = f"http://{NAME}/a"

    def test_a_url_whose_undotted_form_a_description_holds_is_a_string_sighting(self) -> None:
        listed, kept = _listing("url", f"{self.URL}.", f"[url:value = '{self.URL}.']")
        entry = _one_indicator({"url": f"{self.URL}."}, f"Contacted {self.URL} now")
        report = _build([entry], listed, kept)

        assert report.network is not None
        assert {u.url: u.source for u in report.network.urls} == {f"{self.URL}.": "strings"}
        assert not publishes(_published(report, f"{self.URL}."))
        # Nor is its host published on its strength.
        assert not publishes(_published(report, NAME))

    def test_a_url_ending_in_a_dot_only_the_indicators_hold_keeps_its_standing(self) -> None:
        listed, kept = _listing("url", f"{self.URL}.", f"[url:value = '{self.URL}.']")
        entry = _one_indicator({"url": f"{self.URL}."}, "Contacted a host")
        report = _build([entry], listed, kept)

        assert report.network is not None
        assert {u.url: u.source for u in report.network.urls} == {f"{self.URL}.": "analyst"}
        assert publishes(_published(report, f"{self.URL}."))

    def test_a_name_with_a_trailing_dot_a_description_holds_undotted_is_one(self) -> None:
        listed, kept = _listing("domain", f"{NAME}.", f"[domain-name:value = '{NAME}.']")
        entry = _one_indicator({"domain": f"{NAME}."}, f"Contacted {NAME} now")
        report = _build([entry], listed, kept)

        assert _sources(report) == {NAME: "strings"}
        rows = [r for r in report.consolidated_iocs if r.value.rstrip(".") == NAME]
        assert rows
        for row in rows:
            assert not publishes(str(row.published)), row.value


def _described_entry(entry_id: str = "ev_0007") -> LedgerEntry:
    """The indicator answer, its signature's description naming both values too."""
    entry = _indicator_entry(entry_id)
    assert isinstance(entry.structured, dict)
    entry.structured["signatures"][0]["description"] = f"Contacts {NAME} at {ADDRESS}"
    return entry


def _failed(entry: LedgerEntry) -> LedgerEntry:
    return LedgerEntry(**{**entry.model_dump(), "ok": False, "error": "the call failed"})


class TestEachEntryIsReadForItself:
    """Two entries never share a text: each is read for itself, whatever id they share.

    An agent run without a container numbers its own entries, so two entries
    may carry one id. A failed entry is no sighting and is never read.
    """

    @pytest.mark.parametrize("failed_first", [False, True], ids=["ok first", "failed first"])
    def test_a_failed_entry_of_the_id_does_not_hide_the_ok_one_s_text(
        self, failed_first: bool
    ) -> None:
        ledger = [_described_entry(), _failed(_indicator_entry())]
        report = _build(ledger[::-1] if failed_first else ledger)

        assert _sources(report) == {NAME: "strings", ADDRESS: "strings"}
        for value in (NAME, ADDRESS):
            assert not publishes(_published(report, value)), value

    @pytest.mark.parametrize("failed_first", [False, True], ids=["ok first", "failed first"])
    def test_a_failed_entry_s_text_is_no_sighting(self, failed_first: bool) -> None:
        ledger = [_indicator_entry(), _failed(_described_entry())]
        report = _build(ledger[::-1] if failed_first else ledger)

        assert _sources(report) == {NAME: "analyst", ADDRESS: "analyst"}
        for value in (NAME, ADDRESS):
            assert publishes(_published(report, value)), value

    @pytest.mark.parametrize("described_first", [False, True], ids=["record first", "text first"])
    def test_two_answers_of_one_id_one_holding_it_as_text_is_a_string_sighting(
        self, described_first: bool
    ) -> None:
        ledger = [_indicator_entry(), _described_entry()]
        report = _build(ledger[::-1] if described_first else ledger)

        assert _sources(report) == {NAME: "strings", ADDRESS: "strings"}
        for value in (NAME, ADDRESS):
            assert not publishes(_published(report, value)), value

    @pytest.mark.parametrize("strings_first", [False, True], ids=["record first", "strings first"])
    def test_another_tool_s_answer_of_the_id_holding_it_is_a_string_sighting(
        self, strings_first: bool
    ) -> None:
        strings = _entry("ev_0007", "strings", {"strings": [{"offset": "0x40", "string": NAME}]})
        ledger = [_indicator_entry(), strings]
        report = _build(ledger[::-1] if strings_first else ledger)

        assert _sources(report) == {NAME: "strings", ADDRESS: "analyst"}
        assert not publishes(_published(report, NAME))
        assert publishes(_published(report, ADDRESS))

    def test_two_answers_of_one_id_holding_it_only_in_records_keep_its_standing(self) -> None:
        report = _build([_indicator_entry(), _indicator_entry()])

        assert _sources(report) == {NAME: "analyst", ADDRESS: "analyst"}

    def test_a_second_record_answer_holding_it_as_text_too_is_read_for_itself(self) -> None:
        report = _build([_indicator_entry("ev_0007"), _described_entry("ev_0008")])

        assert _sources(report) == {NAME: "strings", ADDRESS: "strings"}
        for value in (NAME, ADDRESS):
            assert not publishes(_published(report, value)), value
