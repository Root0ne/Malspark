"""What a later detonation observed is read by the platform when its report comes back.

When a further detonation an agent asked for returns its report, the
platform makes of it the reads the triage pack makes of the job's first
(the sandbox views and the section index), recorded as the pack's entries
that state the detonation and its launch, and returned with the step's
update so a stored run holds them. A claim citing one of its items
(``d2/proc:9``) is then an item of the run for the analyst's validation and
the report's checks alike. Offline: the detonator is a stand-in.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from malspark.analysis import sandbox_sections as ss
from malspark.core.config import Settings
from malspark.pipeline import detonations as dt
from malspark.pipeline.triage_pack import PIPELINE, pack_entries
from malspark.providers.detonation import DetonationRecord
from malspark.providers.detonation_requests import ACCEPTED, DetonationRequest
from malspark.schemas.evidence import EvidenceCounter, LedgerEntry

ARGS = "-p hunter2"
D2_REPORT: dict[str, Any] = {
    "behavior": {
        "processes": [
            {"pid": 9, "ppid": 4, "process_name": "x.exe", "command_line": f"x.exe {ARGS}"},
        ],
        "summary": {"mutexes": ["Global\\locked"]},
    },
    "network": {
        "dns": [{"request": "c2.example.net", "type": "A"}],
        "tcp": [{"dst": "198.51.100.7", "dport": 443, "pid": 9}],
    },
    "signatures": [{"name": "ransomware_files", "severity": 3}],
}


def container_with_a_pending_request(report: dict[str, Any] | None = None) -> Any:
    """A job's container holding d1 and one accepted request for d2, with a stand-in detonator."""
    settings = Settings()
    profile = settings.agents.profiles[settings.agents.profile]
    counter = EvidenceCounter()
    events: list[tuple[str, dict[str, Any]]] = []
    detonated: list[str] = []

    async def _detonate(record: DetonationRecord) -> None:
        detonated.append(record.name)
        record.report = D2_REPORT if report is None else report
        record.task_id = "t-2"

    container = SimpleNamespace(
        config=settings,
        active_profile=lambda: profile,
        _agent_cache={},
        event_sink=lambda kind, data: events.append((kind, data)),
        detonations=[DetonationRecord(report={})],
        detonation_requests=[
            DetonationRequest(
                number=1,
                agent="reversing",
                stage="analysis",
                arguments=ARGS,
                reason="the password the sample checks",
                cited_entries=["ev_0001"],
                state=ACCEPTED,
                detonation="d2",
            )
        ],
        detonator=_detonate,
        detonations_seen={},
        further_turns=[],
        current_step="",
        get_evidence_counter=lambda: counter,
    )
    container.events = events
    container.detonated = detonated
    return container


def _entered_update(container: Any, state: dict[str, Any]) -> dict[str, Any]:
    """The update of a reading step entered with d2 pending, its own work returning nothing."""

    async def node(state: Any) -> dict[str, Any]:
        return {}

    entered = dt.on_entry(container, "judge", node, reading_agents=("judge",))
    out = asyncio.run(entered(state))
    assert isinstance(out, dict)
    return out


class TestThePlatformReadsALaterDetonation:
    def test_each_read_is_the_pack_s_entry_stating_the_detonation_and_its_launch(self) -> None:
        container = container_with_a_pending_request()
        out = _entered_update(container, {"evidence_ledger": []})
        rows = out["evidence_ledger"]
        entries = [LedgerEntry.model_validate(row) for row in rows]
        assert [e.tool for e in entries] == [
            "sandbox_processes",
            "sandbox_network",
            "sandbox_signatures",
            "sandbox_dropped_files",
            "sandbox_channels",
            ss.SECTIONS_TOOL,
        ]
        assert {e.agent for e in entries} == {PIPELINE}
        assert len(pack_entries(rows)) == len(rows)
        for entry in entries:
            assert entry.args == {"detonation": "d2"}
            assert isinstance(entry.structured, dict)
            assert entry.structured["detonation"] == "d2"
            assert entry.structured["launched_with"] == ARGS
            assert entry.structured["requested_by"][0]["agent"] == "reversing"
        index = entries[-1].structured
        assert index["sections"]["processes"]["items"] == 1
        # The ids each read has, issued by the job's counter after d1's.
        assert [e.id for e in entries] == [f"ev_{n:04d}" for n in range(1, 7)]

    def test_a_detonation_that_returned_nothing_is_read_for_nothing(self) -> None:
        container = container_with_a_pending_request()

        async def _nothing(record: DetonationRecord) -> None:
            record.failure = "the sandbox timed out"

        container.detonator = _nothing
        out = _entered_update(container, {"evidence_ledger": []})
        assert "evidence_ledger" not in out

    def test_a_step_with_nothing_pending_returns_no_entry(self) -> None:
        container = container_with_a_pending_request()
        container.detonation_requests = []
        assert _entered_update(container, {"evidence_ledger": []}) == {}


class TestALaterDetonationsItemIsCited:
    """B1: a claim citing ``d2/proc:9`` passes the analyst's validation and the report's checks."""

    def _state(self) -> tuple[Any, dict[str, Any]]:
        container = container_with_a_pending_request()
        first_index = LedgerEntry(
            id="ev_0000",
            tool=ss.SECTIONS_TOOL,
            agent=PIPELINE,
            structured=ss.section_index({"behavior": {"processes": [{"pid": 84}]}}),
        ).model_dump(mode="json")
        state: dict[str, Any] = {
            "evidence_ledger": [first_index],
            "sandbox_report": {"behavior": {"processes": [{"pid": 84}]}},
        }
        out = _entered_update(container, state)
        state["evidence_ledger"] = [first_index, *out["evidence_ledger"]]
        return container, state

    def test_the_analyst_s_validation_knows_the_later_item(self) -> None:
        from malspark.pipeline.validation import UNGROUNDED_TECHNIQUE_CODE, validate_isr
        from malspark.schemas.isr_models import AgentISR, ClaimEvidence

        _container, state = self._state()
        # What ``brief_agent`` hands an analyst, and what its validation reads.
        pack = pack_entries(state["evidence_ledger"])
        items = ss.item_index_of(pack)
        assert items is not None
        assert items.known("proc:84") and items.known("d2/proc:9")
        assert not items.known("d2/proc:84") and not items.known("d3/proc:9")

        def _claim(ref: str) -> AgentISR:
            return AgentISR(
                agent_id="dynamic",
                domain="dynamic",
                claims=[
                    ClaimEvidence(
                        claim="Encrypts the user's files once started with the password",
                        evidence_ref=ref,
                        confidence=0.8,
                        technique_id="T1486",
                    )
                ],
            )

        ids = [entry.id for entry in pack]
        held = validate_isr(_claim("process d2/proc:9"), ledger_ids=ids, items=items)
        assert not [v for v in held if v.code == UNGROUNDED_TECHNIQUE_CODE]
        (unheld,) = [
            v
            for v in validate_isr(_claim("process d2/proc:84"), ledger_ids=ids, items=items)
            if v.code == UNGROUNDED_TECHNIQUE_CODE
        ]
        assert "d2/proc:84" in unheld.message

    def test_the_report_s_citation_and_value_checks_read_the_later_item(self) -> None:
        from malspark.pipeline.nodes import sandbox_item_citations, with_item_texts
        from malspark.pipeline.validation import (
            EntryTexts,
            citation_violations,
            stated_value_violations,
        )

        container, state = self._state()
        container.sandbox_normalised = None
        items = sandbox_item_citations(state, container)
        assert items is not None
        assert citation_violations({"body": "x [d2/proc:9]"}, ["ev_0001"], items=items) == []
        (asked,) = citation_violations({"body": "x [d2/proc:99]"}, ["ev_0001"], items=items)
        assert "d2/proc:99" in asked.message
        entries = with_item_texts(EntryTexts.from_ledger(state["evidence_ledger"]), items)
        held = {
            "identifiers": [
                {"kind": "mutex", "value": "Global\\locked", "evidence_refs": ["d2/mutex:1"]}
            ]
        }
        assert stated_value_violations(held, entries) == []
        made_up = {
            "identifiers": [
                {"kind": "mutex", "value": "Global\\other", "evidence_refs": ["d2/mutex:1"]}
            ]
        }
        assert stated_value_violations(made_up, entries)
