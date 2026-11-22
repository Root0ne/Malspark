"""The refusal on an address no flow row reaches names the view the rule read (T-842).

The publish rule reads the sandbox's flow rows; an address the network block
took from a conversation of the capture has none there. The sentence says
what the rule read and what the reading gave, each half read from the row's
own record (``FlowReading``): the view by the views the reading records it read
(none, one detonation's, several), and beside it, as a fact the same record
holds, that the capture recorded a conversation with the address. An address
with neither a flow row nor a capture conversation claims neither; a reading
recorded before the views read were names neither. Every value is synthetic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from malspark.pipeline.validation import _unstated_values, unattributed_indicator_violations
from malspark.reporting.composer_pro import held_text
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.reporting.models import (
    FileHashes,
    FlowReading,
    MalwareReport,
    NetworkIP,
    SampleIdentity,
)
from malspark.reporting.publish_parts import refused
from malspark.reporting.renderers.stix_renderer import (
    address_flow_reason,
    sandbox_facts_for_the_judge,
)
from malspark.schemas.evidence import build_entry
from malspark.schemas.stix_models import Bundle

CAPTURED = "93.184.216.34"
HOSTED = "198.51.100.23"
FLOWED = "203.0.113.7"
INBOUND = "192.0.2.44"
RULE = "the publish rule "
IN_VIEW = "read the sandbox's network view and found no flow row to it"
CAPTURE = " while the capture recorded a conversation with it"


def _entry(data: Any, n: int, tool: str = "sandbox_network", **more: Any) -> Any:
    # A further detonation's view is the platform's own read of it.
    if more.pop("agent_source", False):
        more.update(agent="pipeline", source="pack")
    return build_entry(
        entry_id=f"ev_{n:04d}",
        seq=n,
        agent=more.pop("agent", "dynamic"),
        tool=tool,
        args=more.pop("args", {}),
        server=None,
        output=json.dumps(data),
        **more,
    )


_CAPTURE = {
    "conversations": [
        {"dst": CAPTURED, "dport": 80},
        {"dst": FLOWED, "dport": 443},
        {"dst": INBOUND, "dport": 51000, "inbound_only": True},
    ]
}
_VIEW = {"tcp": [{"dst": FLOWED, "dport": 443}], "hosts": [{"ip": HOSTED}]}


def _rows(*entries: Any) -> dict[str, NetworkIP]:
    network = network_from_ledger(list(entries))
    assert network is not None
    return {ip.address: ip for ip in network.ips}


def _said(*entries: Any, address: str = CAPTURED) -> str:
    return address_flow_reason(_rows(*entries)[address])


class TestEachHalfIsReadFromTheRowsRecord:
    def test_an_address_only_the_capture_recorded(self) -> None:
        said = _said(_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary"))
        assert said == RULE + IN_VIEW + CAPTURE

    def test_an_address_with_neither_a_flow_row_nor_a_conversation_claims_neither(self) -> None:
        said = _said(_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary"), address=HOSTED)
        assert said == RULE + IN_VIEW

    def test_no_network_view_read(self) -> None:
        assert _said(_entry(_CAPTURE, 1, "pcap_summary")) == (
            RULE + "read no network view of the sandbox" + CAPTURE
        )

    def test_a_conversation_the_capture_records_only_as_inbound_adds_no_row(self) -> None:
        assert INBOUND not in _rows(_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary"))

    def test_a_capture_conversation_and_a_flow_row_both_say_the_flow_reading(self) -> None:
        said = _said(_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary"), address=FLOWED)
        assert said == RULE + "read no process id from the flow to it"

    def test_a_page_of_the_view_is_said_as_a_part(self) -> None:
        page = _entry({**_VIEW, "tcp_total": 9}, 1, args={"offset": 0})
        assert _said(page, _entry(_CAPTURE, 2, "pcap_summary")) == (
            RULE + "read only part of the network view and found no flow row to it" + CAPTURE
        )

    def test_a_capture_read_only_in_part_still_recorded_the_conversation(self) -> None:
        part = _entry({**_CAPTURE, "conversations_total": 40}, 2, "pcap_summary")
        assert _said(_entry(_VIEW, 1), part) == RULE + IN_VIEW + CAPTURE

    def test_two_detonations_views_are_named_as_views(self) -> None:
        later = {"detonation": "d2", "launched_with": "-x", "tcp": []}
        row = _rows(
            _entry(_VIEW, 1),
            _entry(_CAPTURE, 2, "pcap_summary"),
            _entry(later, 3, agent_source=True),
        )[CAPTURED]
        assert address_flow_reason(row) == (
            RULE + "read the sandbox's network views and found no flow row to it" + CAPTURE
        )


class TestAReadingRecordedBeforeTheViewsRead:
    def test_names_neither_view_nor_capture(self) -> None:
        stored = NetworkIP(address=CAPTURED, source="sandbox", flow_reading=FlowReading())
        assert address_flow_reason(stored) == RULE + "found no flow row to it"

    def test_the_new_record_is_left_out_of_a_reading_with_flow_rows(self) -> None:
        row = _rows(_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary"))[FLOWED]
        dumped = json.loads(row.model_dump_json())["flow_reading"]
        assert "views_read" not in dumped and "capture_conversation" not in dumped

    def test_the_record_round_trips_and_no_decision_reads_it(self) -> None:
        rows = _rows(_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary"))
        row = rows[CAPTURED]
        again = NetworkIP.model_validate(json.loads(row.model_dump_json()))
        assert again.flow_reading == row.flow_reading
        bare = row.model_copy(update={"flow_reading": FlowReading()})
        for field in ("sample_process_tree", "source", "outside_processes"):
            assert getattr(bare, field) == getattr(row, field)


class TestTheFormsAndTheirReaders:
    def test_no_comma_or_semicolon_and_restated_word_for_word_passes(self) -> None:
        rows = _rows(_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary"))
        for address in (CAPTURED, HOSTED):
            said = address_flow_reason(rows[address])
            assert "," not in said and ";" not in said
            answer = refused(said)
            for sentence in (
                f"The sample reaches {address} ({said}).",
                f"The sample reaches {address}: {said}.",
                f"The sample reaches {address} and {said}.",
            ):
                found = _unstated_values(sentence, lambda _k, _v, a=answer: a)
                assert found == [], sentence

    def test_the_judge_s_question_carries_the_new_words(self) -> None:
        network = network_from_ledger([_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary")])
        bundle = Bundle.model_validate(
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332211",
                        "name": "judge indicator",
                        "pattern": f"[ipv4-addr:value = '{CAPTURED}']",
                        "pattern_type": "stix",
                        "indicator_types": ["malicious-activity"],
                        "valid_from": "2026-01-01T00:00:00Z",
                    }
                ],
            }
        )
        (found,) = unattributed_indicator_violations(bundle, sandbox_facts_for_the_judge(network))
        assert f"names '{CAPTURED}' and {RULE}{IN_VIEW}{CAPTURE}." in found.message

    def test_the_held_text_holds_no_reading(self) -> None:
        network = network_from_ledger([_entry(_VIEW, 1), _entry(_CAPTURE, 2, "pcap_summary")])
        built = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            overall_confidence=0.9,
            network=network,
        )
        assert "views_read" not in held_text(built)
        assert "capture_conversation" not in held_text(built)


class TestTheRecordsReaders:
    def test_only_the_sentence_reads_the_new_record(self) -> None:
        # The two fields are written by the projection and read by the rule's
        # sentence alone: no decision, no other surface and no console code.
        root = Path(__file__).resolve().parents[3]
        found: dict[str, set[str]] = {}
        for base in ("src", "apps/api", "apps/web/src"):
            for path in (root / base).rglob("*"):
                if path.suffix not in (".py", ".ts", ".tsx") or not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8")
                for field in (
                    '"views_read"',
                    '"capture_conversation"',
                    "views_read=",
                    ".views_read",
                ):
                    if field in text:
                        found.setdefault(str(path.relative_to(root)), set()).add(field)
        assert found == {
            "src/malspark/reporting/ledger_projection.py": {"views_read="},
            "src/malspark/reporting/renderers/stix_renderer.py": {
                '"views_read"',
                '"capture_conversation"',
            },
        }
