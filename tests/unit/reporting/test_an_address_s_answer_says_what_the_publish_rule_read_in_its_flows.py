"""An address's answer says what the publish rule read in the flow rows to it.

A sandbox address none of whose flows the rule placed in the sample's process
tree is refused, and the refusal says what the rule read: no flow row to it, flow
rows from which it read no process id, the processes it found the flows made by
under a kind, the processes the other flows name by id that it did not place.
Each number is named by the field its own row holds it under, the task where the
flows name more than one, a later detonation where the platform's reading gives
one; no count of flows is printed, and one flow is "a flow". One flow read again
in another view or a page is said once. A view read as a part is said so, by the
view it is. A row read from a report stored before the reading was recorded is
said by the decision alone, unless the job's stored network entries give the
words (the decision staying the stored row's).

The forms carry one subject, the publish rule, and no "," or ";" outside
brackets, so every reader of the clause after a value reads it whole. Every value
is synthetic; each truth test reads the rows of the view it builds.
"""

from __future__ import annotations

import json
import re
from typing import Any

from malspark.pipeline.triage_pack import _pcap
from malspark.pipeline.validation import (
    _states_publish_state,
    flow_voice_violations,
    unattributed_indicator_violations,
)
from malspark.reporting.builder import ioc_table
from malspark.reporting.composer_pro import held_text
from malspark.reporting.ledger_projection import (
    network_from_ledger,
    with_flow_readings,
)
from malspark.reporting.models import (
    FileHashes,
    FlowReading,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from malspark.reporting.publish_parts import refused
from malspark.reporting.renderers.stix_renderer import (
    FLOW_NOT_PLACED,
    UNATTRIBUTED_CAPTURE_VALUE,
    address_flow_reason,
    address_flow_words,
    disputed_flow_reason,
    sandbox_facts_for_the_judge,
    url_made_by_reason,
)
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_report import (
    FLOW_PROCESS_KEY,
    LINEAGE_DISPUTED_KEY,
    LINEAGE_KEY,
    LINEAGE_LAUNCHER_UNSETTLED,
    LINEAGE_MARKED_STORED,
    PROCESS_TASK_KEY,
    PROCESS_UNLISTED_KEY,
    SAMPLE_TREE_KEY,
    TRAFFIC_PROCESS_KEY,
)
from malspark.schemas.stix_models import Bundle

ADDRESS = "93.184.216.34"
RULE = "the publish rule "


def _entry(view: dict[str, Any], n: int, **more: Any) -> Any:
    return build_entry(
        entry_id=f"ev_{n:04d}",
        seq=n,
        agent=more.pop("agent", "dynamic"),
        tool=more.pop("tool", "sandbox_network"),
        args=more.pop("args", {}),
        server=None,
        output=json.dumps(view),
        **more,
    )


def _ledger(*views: dict[str, Any] | tuple[dict[str, Any], dict[str, Any]]) -> list[Any]:
    out = []
    for n, view in enumerate(views, start=1):
        data, more = view if isinstance(view, tuple) else (view, {})
        out.append(_entry(data, n, **more))
    return out


def _row(*views: Any, address: str = ADDRESS) -> NetworkIP:
    network = network_from_ledger(_ledger(*views))
    assert network is not None
    (row,) = [ip for ip in network.ips if ip.address == address]
    return row


def _said(*views: Any, address: str = ADDRESS) -> str:
    return address_flow_reason(_row(*views, address=address))


def _flow(**facts: Any) -> dict[str, Any]:
    return {"dst": ADDRESS, "dport": 443, **facts}


def _restated(fact: str) -> bool:
    answer = refused(fact, facts=["a listing does not change what the sandbox recorded about it"])
    return _states_publish_state(f" ({fact}) was contacted.", answer)


def _outside_brackets(text: str) -> str:
    depth, kept = 0, []
    for ch in text:
        depth += ch == "("
        if depth == 0:
            kept.append(ch)
        depth -= ch == ")" and depth > 0
    return "".join(kept)


class TestWhatTheRuleRead:
    def test_an_address_only_the_capture_holds(self) -> None:
        said = _said(
            {"tcp": []},
            ({"conversations": [{"dst": ADDRESS, "dport": 80}]}, {"tool": "pcap_summary"}),
        )
        assert said == RULE + "found no flow row to it"

    def test_a_flow_that_names_a_process_by_image_only(self) -> None:
        assert _said({"tcp": [_flow(**{FLOW_PROCESS_KEY: "svchost.exe"})]}) == (
            RULE + "read no process id from the flow to it"
        )

    def test_a_flow_whose_process_is_a_nested_object(self) -> None:
        nested = _flow(**{FLOW_PROCESS_KEY: {"pid": 2756, "name": "x.exe"}})
        assert _said({"tcp": [nested]}) == RULE + "read no process id from the flow to it"

    def test_two_identical_flows_in_one_view_are_two_flows(self) -> None:
        assert _said({"udp": [_flow(), _flow()]}) == (
            RULE + "read no process id from the flows to it"
        )

    def test_a_number_is_named_by_the_field_its_row_holds(self) -> None:
        assert _said({"tcp": [_flow(pid=2756)]}) == (
            RULE + "did not place the process a flow to it names by id (pid 2756)"
        )
        assert _said({"tcp": [_flow(process_id=2756)]}) == (
            RULE + "did not place the process a flow to it names by id (process_id 2756)"
        )
        assert _said({"tcp": [_flow(procid=47, pid=2780), _flow(procid=47, pid=2780)]}) == (
            RULE + "did not place the process the flows to it name by id (procid 47 pid 2780)"
        )

    def test_a_number_two_programs_hold_is_named_by_its_ids_alone(self) -> None:
        flows = [
            _flow(pid=5, **{FLOW_PROCESS_KEY: "x.exe"}),
            _flow(pid=5, dport=2, **{FLOW_PROCESS_KEY: "y.exe"}),
        ]
        assert _said({"tcp": flows}) == (
            RULE + "did not place the process the flows to it name by id (pid 5)"
        )
        assert _said({"tcp": [_flow(pid=5, **{FLOW_PROCESS_KEY: "x.exe"})]}) == (
            RULE + "did not place the process a flow to it names by id (x.exe pid 5)"
        )

    def test_one_number_under_two_tasks_keeps_its_task(self) -> None:
        flows = [
            _flow(procid=46, **{PROCESS_TASK_KEY: "behavioral1"}),
            _flow(procid=46, **{PROCESS_TASK_KEY: "behavioral2"}),
        ]
        assert _said({"tcp": flows}) == (
            RULE + "did not place the processes the flows to it name by id (procid 46 of task "
            "behavioral1 and procid 46 of task behavioral2)"
        )

    def test_a_flow_placed_under_a_kind_and_one_naming_no_id(self) -> None:
        unlisted = _flow(
            procid=46, pid=2756, **{TRAFFIC_PROCESS_KEY: 46, PROCESS_UNLISTED_KEY: True}
        )
        assert _said({"tcp": [unlisted, _flow()]}) == (
            RULE + "found a flow to it made by a process the report does not list (procid 46 "
            "pid 2756) and read no process id from its other flow"
        )

    def test_two_kinds_and_an_unplaced_number(self) -> None:
        outside = _flow(
            procid=12,
            pid=1300,
            **{TRAFFIC_PROCESS_KEY: 12, SAMPLE_TREE_KEY: False, FLOW_PROCESS_KEY: "svchost.exe"},
        )
        unlisted = _flow(
            procid=46, pid=2756, **{TRAFFIC_PROCESS_KEY: 46, PROCESS_UNLISTED_KEY: True}
        )
        said = _said({"tcp": [outside, unlisted, _flow(procid=91, pid=4976)]})
        assert said == (
            RULE + "found flows to it made by a process outside the sample's process tree "
            "(svchost.exe procid 12 pid 1300) and by a process the report does not list (procid "
            "46 pid 2756) and did not place the process the other flow to it names by id (procid "
            "91 pid 4976)"
        )
        assert _restated(said)

    def test_an_ipv6_address(self) -> None:
        flow = {"dst": "2001:DB8::30", "dport": 443, "pid": 2756}
        assert _said({"tcp": [flow]}, address="2001:db8::30") == (
            RULE + "did not place the process a flow to it names by id (pid 2756)"
        )


class TestOneFlowIsSaidOnce:
    def test_a_flow_read_whole_and_again_in_a_page(self) -> None:
        unlisted = _flow(
            procid=46, pid=2756, **{TRAFFIC_PROCESS_KEY: 46, PROCESS_UNLISTED_KEY: True}
        )
        said = _said({"tcp": [unlisted]}, ({"tcp": [unlisted]}, {"args": {"limit": 100}}))
        assert said == (
            RULE + "found a flow to it made by a process the report does not list (procid 46 "
            "pid 2756)"
        )
        assert "other" not in said

    def test_a_re_read_carrying_an_image_is_one_process(self) -> None:
        said = _said(
            {"tcp": [_flow(pid=5)]},
            ({"tcp": [_flow(pid=5, **{FLOW_PROCESS_KEY: "x.exe"})]}, {"args": {"limit": 10}}),
        )
        assert said == RULE + "did not place the process a flow to it names by id (x.exe pid 5)"

    def test_a_flow_outside_the_tree_with_no_id_read_whole_and_in_a_page(self) -> None:
        outside = _flow(**{SAMPLE_TREE_KEY: False, FLOW_PROCESS_KEY: "svc.exe"})
        said = _said({"tcp": [outside]}, ({"tcp": [outside]}, {"args": {"limit": 1}}))
        assert said == (
            RULE + "found a flow to it made by a process outside the sample's process tree "
            "(svc.exe)"
        )
        assert "other" not in said

    def test_a_later_detonation_s_flow_is_named_by_its_detonation(self) -> None:
        later = {
            "detonation": "d2",
            "launched_with": "-x",
            "tcp": [_flow(procid=77, pid=3100)],
        }
        said = _said({"tcp": [_flow()]}, (later, {"agent": "pipeline", "source": "pack"}))
        assert said == (
            RULE + "did not place the process a flow to it names by id (procid 77 pid 3100 in "
            "detonation d2) and read no process id from its other flow"
        )


class TestAViewReadAsAPart:
    def test_a_page_holding_no_flow_to_it(self) -> None:
        said = _said(
            ({"tcp": [{"dst": "198.51.100.9"}], "tcp_total": 9}, {"args": {"offset": 0}}),
            ({"conversations": [{"dst": ADDRESS, "dport": 80}]}, {"tool": "pcap_summary"}),
        )
        assert said == RULE + "read only part of the network view and found no flow row to it"

    def test_a_view_cut_as_text_was_read_as_a_part(self) -> None:
        view = {"tcp": [_flow(pid=2756)], "pad": "x" * 600}
        said = _said((view, {"max_chars": 200}))
        assert said == (
            RULE + "read the network view as a part and did not place the process a flow to it "
            "names by id (pid 2756)"
        )


def _page(flows: list[dict[str, Any]], offset: int, total: int) -> tuple[dict, dict]:
    return {"tcp": flows, "tcp_total": total}, {"args": {"offset": offset, "limit": len(flows)}}


class TestACountOverPagesIsNoCount:
    """Rows read in more than one part view and in no whole one: no count, no singular."""

    def test_two_pages_each_with_a_flow_naming_no_id(self) -> None:
        said = _said(_page([_flow(dport=1)], 0, 2), _page([_flow(dport=2)], 1, 2))
        assert said == (
            RULE + "read only part of the network view and read no process id from any flow "
            "row to it"
        )
        assert _restated(said)

    def test_two_pages_each_with_a_flow_of_one_number(self) -> None:
        said = _said(_page([_flow(dport=1, pid=7)], 0, 2), _page([_flow(dport=2, pid=7)], 1, 2))
        assert said == (
            RULE + "read only part of the network view and did not place the process the flow "
            "rows to it name by id (pid 7)"
        )
        assert _restated(said)

    def test_the_other_rows_over_two_pages(self) -> None:
        said = _said(
            _page([_flow(dport=1, pid=7), _flow(dport=3)], 0, 4),
            _page([_flow(dport=2, pid=7), _flow(dport=4)], 2, 4),
        )
        assert said == (
            RULE + "read only part of the network view and did not place the process the flow "
            "rows to it name by id (pid 7) and read no process id from any other flow row to it"
        )
        assert _restated(said)

    def test_a_disputed_process_over_two_pages(self) -> None:
        disputed = {
            "procid": 104,
            FLOW_PROCESS_KEY: "SearchHost.exe",
            LINEAGE_DISPUTED_KEY: LINEAGE_MARKED_STORED,
        }
        said = _said(
            _page([_flow(dport=1, **disputed)], 0, 2), _page([_flow(dport=2, **disputed)], 1, 2)
        )
        assert said.startswith(
            RULE + "read only part of the network view and found flow rows to it made by "
            "SearchHost.exe (procid 104), which "
        )
        assert _restated(said)

    def test_one_page_counts_its_own_rows(self) -> None:
        said = _said(_page([_flow(dport=1), _flow(dport=2)], 0, 3))
        assert said == (
            RULE + "read only part of the network view and read no process id from the flows to it"
        )


class TestTheDisputedSentence:
    def test_the_other_flows_to_a_disputed_address(self) -> None:
        disputed = _flow(
            procid=104,
            pid=3976,
            **{
                FLOW_PROCESS_KEY: "StartMenuExperienceHost.exe",
                LINEAGE_DISPUTED_KEY: LINEAGE_MARKED_STORED,
            },
        )
        said = _said({"tcp": [_flow(procid=92, pid=4268), disputed]})
        assert said.startswith(
            RULE + "found a flow to it made by StartMenuExperienceHost.exe (procid 104), which "
        )
        assert said.endswith(
            ", and did not place the process the other flow to it names by id (procid 92 pid 4268)"
        )
        first, whole = address_flow_words(_row({"tcp": [_flow(procid=92, pid=4268), disputed]}))
        assert whole == said
        assert first == (
            RULE + "found a flow to it made by a process whose lineage the report's two facts "
            "dispute"
        )


class TestAReadingNeverTakenIsKeptApart:
    def test_a_dumped_row_keeps_its_reading_and_a_stored_one_has_none(self) -> None:
        row = _row({"tcp": [_flow(pid=2756)]})
        again = NetworkIP.model_validate(json.loads(row.model_dump_json()))
        assert again.flow_reading == row.flow_reading
        stored = json.loads(row.model_dump_json())
        stored.pop("flow_reading")
        assert address_flow_reason(NetworkIP.model_validate(stored)) == FLOW_NOT_PLACED
        empty = NetworkIP(address=ADDRESS, source="sandbox", flow_reading=FlowReading())
        assert address_flow_reason(empty) == RULE + "found no flow row to it"

    def test_a_served_report_takes_its_words_from_the_job_s_entries(self) -> None:
        ledger = _ledger({"tcp": [_flow(procid=47, pid=2780)]})
        network = network_from_ledger(ledger)
        assert network is not None
        document = _stored_document(network)
        stored = ioc_table(MalwareReport.model_validate(document))
        served = ioc_table(MalwareReport.model_validate(with_flow_readings(document, ledger)))
        (old,) = [r for r in stored if r.value == ADDRESS]
        (new,) = [r for r in served if r.value == ADDRESS]
        assert FLOW_NOT_PLACED in str(old.published)
        assert "did not place the process a flow to it names by id (procid 47 pid 2780)" in str(
            new.published
        )
        assert old.published.startswith("no:") and new.published.startswith("no:")
        assert with_flow_readings(document, []) is document

    def test_a_stored_row_the_entries_decide_otherwise_keeps_no_reading(self) -> None:
        document = _stored_document(network_from_ledger(_ledger({"tcp": [_flow()]})))
        tree = _ledger({"tcp": [_flow(**{SAMPLE_TREE_KEY: True})]})
        (row,) = with_flow_readings(document, tree)["network"]["ips"]
        assert "flow_reading" not in row
        assert address_flow_reason(NetworkIP.model_validate(row)) == FLOW_NOT_PLACED

    def test_a_stored_list_the_entries_do_not_read_keeps_no_reading(self) -> None:
        unlisted = _flow(procid=36, **{TRAFFIC_PROCESS_KEY: 36, PROCESS_UNLISTED_KEY: True})
        document = _stored_document(network_from_ledger(_ledger({"tcp": [unlisted]})))
        (row,) = with_flow_readings(document, _ledger({"tcp": [_flow(pid=36)]}))["network"]["ips"]
        assert "flow_reading" not in row
        assert address_flow_reason(NetworkIP.model_validate(row)) == (
            RULE + "counted its flows as made by a process the report does not list (procid 36)"
        )

    def test_entries_with_no_whole_view_leave_the_document_as_stored(self) -> None:
        document = _stored_document(network_from_ledger(_ledger({"tcp": [_flow()]})))
        capture = ({"conversations": [{"dst": ADDRESS, "dport": 80}]}, {"tool": "pcap_summary"})
        page = ({"tcp": [{"dst": "198.51.100.9"}], "tcp_total": 9}, {"args": {"offset": 0}})
        blank = _entry({}, 1)
        blank = blank.model_copy(update={"structured": None})
        for ledger in (_ledger(capture), _ledger(page), [blank]):
            assert with_flow_readings(document, ledger) is document

    def test_a_view_whose_structure_is_no_object_is_read_as_a_part(self) -> None:
        capture = ({"conversations": [{"dst": ADDRESS, "dport": 80}]}, {"tool": "pcap_summary"})
        blank = _entry({}, 2).model_copy(update={"structured": [1, 2]})
        network = network_from_ledger([*_ledger(capture), blank])
        assert network is not None
        (row,) = [ip for ip in network.ips if ip.address == ADDRESS]
        assert address_flow_reason(row) == (
            RULE + "read only part of the network view and found no flow row to it"
        )
        whole = network_from_ledger([*_ledger({"tcp": [_flow()]}), blank])
        assert whole is not None
        (row,) = [ip for ip in whole.ips if ip.address == ADDRESS]
        assert address_flow_reason(row) == RULE + "read no process id from the flow to it"

    def test_a_made_by_row_with_no_reading_states_no_count(self) -> None:
        unlisted = _flow(procid=36, **{TRAFFIC_PROCESS_KEY: 36, PROCESS_UNLISTED_KEY: True})
        row = _row({"tcp": [unlisted, unlisted]})
        stored = NetworkIP.model_validate(
            {**json.loads(row.model_dump_json()), "flow_reading": None}
        )
        assert address_flow_reason(stored) == (
            RULE + "counted its flows as made by a process the report does not list (procid 36)"
        )
        outside = _flow(
            procid=12,
            **{TRAFFIC_PROCESS_KEY: 12, SAMPLE_TREE_KEY: False, FLOW_PROCESS_KEY: "s.exe"},
        )
        row = _row({"tcp": [outside]})
        stored = NetworkIP.model_validate(
            {**json.loads(row.model_dump_json()), "flow_reading": None}
        )
        said = address_flow_reason(stored)
        assert said == (
            RULE + "counted its flows as made by a process outside the sample's process tree "
            "(s.exe (procid 12))"
        )
        assert _restated(said)

    def test_a_disputed_row_with_no_reading_states_no_count(self) -> None:
        said = disputed_flow_reason(["SearchHost.exe (procid 104)"], [], "AcmeBox")
        assert said == (
            RULE + "counted flows to it as made by SearchHost.exe (procid 104), which AcmeBox "
            "marks as the sample's but which runs none of the submitted file's names and "
            "descends from none of its processes"
        )

    def test_a_disputed_row_with_no_reading_claims_no_other_flow(self) -> None:
        disputed = _flow(
            procid=104,
            **{
                FLOW_PROCESS_KEY: "StartMenuExperienceHost.exe",
                LINEAGE_DISPUTED_KEY: LINEAGE_MARKED_STORED,
            },
        )
        row = _row({"tcp": [disputed, _flow(procid=92, dport=2)]})
        stored = NetworkIP.model_validate(
            {**json.loads(row.model_dump_json()), "flow_reading": None}
        )
        said = address_flow_reason(stored)
        assert said.startswith(
            RULE + "counted flows to it as made by StartMenuExperienceHost.exe (procid 104), which "
        )
        assert "its flows" not in said and "other" not in said
        assert _restated(said)


def _stored_document(network: NetworkIOCs | None) -> dict[str, Any]:
    assert network is not None
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        overall_confidence=0.9,
        network=network,
    )
    document = json.loads(report.model_dump_json())
    for ip in document["network"]["ips"]:
        ip.pop("flow_reading", None)
    return document


class TestThePackWordsInTwoPasses:
    def test_a_list_never_takes_a_later_conversation_s_words(self) -> None:
        data = {
            "packets_read": 10,
            "packets_in_capture": 10,
            "bytes": 100,
            "duration_s": 1.0,
            "protocols": {"tcp": 10},
            "conversations": [
                {"dst": "198.51.100.1", "dport": 443, "proto": "tcp", "bytes": 50},
                {"dst": "198.51.100.2", "dport": 443, "proto": "tcp", "bytes": 40},
            ],
        }
        listed = RULE + "did not place the process a flow to it names by id (procid 1 pid 2)"
        words = {"198.51.100.1": ("", listed), "198.51.100.2": ("no flow row holds it",) * 2}
        bare = _pcap(data, None)
        room = len(bare) + len("; no flow row holds it") + 5
        line = _pcap(data, room, lambda address: words[address])
        assert line.endswith("no flow row holds it; contacts at a regular interval: none detected")
        assert listed not in line
        assert listed in _pcap(data, None, lambda address: words[address])


class TestTheFirstPassHoldsNoList:
    """The capture line's first pass carries no list of processes in any form."""

    def _forms(self) -> list[NetworkIP]:
        unlisted = _flow(procid=46, **{TRAFFIC_PROCESS_KEY: 46, PROCESS_UNLISTED_KEY: True})
        outside = _flow(
            procid=12,
            **{TRAFFIC_PROCESS_KEY: 12, SAMPLE_TREE_KEY: False, FLOW_PROCESS_KEY: "s.exe"},
        )
        unsettled = _flow(
            procid=8,
            **{FLOW_PROCESS_KEY: "wscript.exe", LINEAGE_KEY: LINEAGE_LAUNCHER_UNSETTLED},
        )
        disputed = _flow(
            procid=104,
            **{FLOW_PROCESS_KEY: "SearchHost.exe", LINEAGE_DISPUTED_KEY: LINEAGE_MARKED_STORED},
        )
        rows = [
            _row({"tcp": [unlisted]}),
            _row({"tcp": [outside]}),
            _row({"tcp": [unsettled]}),
            _row({"tcp": [disputed]}),
            _row({"tcp": [_flow(pid=7), _flow()]}),
        ]
        stored = [
            NetworkIP.model_validate({**json.loads(r.model_dump_json()), "flow_reading": None})
            for r in rows
        ]
        return rows + stored

    def test_every_form_s_first_part_names_no_process(self) -> None:
        forms = self._forms()
        for row in forms:
            first, whole = address_flow_words(row)
            assert whole == address_flow_reason(row)
            assert "(" not in first and "procid" not in first and ".exe" not in first, first
        # A list of the processes the flow rows name is spent whole, in the second pass.
        assert address_flow_words(forms[4])[0] == ""
        for row in forms[:4] + forms[5:]:
            assert address_flow_words(row)[0].startswith(RULE)

    def test_a_longer_first_part_never_takes_a_later_conversation_s_words(self) -> None:
        data = {
            "packets_read": 10,
            "packets_in_capture": 10,
            "bytes": 100,
            "duration_s": 1.0,
            "protocols": {"tcp": 10},
            "conversations": [
                {"dst": ADDRESS, "dport": 443, "proto": "tcp", "bytes": 50},
                {"dst": "198.51.100.2", "dport": 443, "proto": "tcp", "bytes": 40},
            ],
        }
        unlisted = _flow(procid=46, **{TRAFFIC_PROCESS_KEY: 46, PROCESS_UNLISTED_KEY: True})
        first, whole = address_flow_words(_row({"tcp": [unlisted]}))
        later = "no flow row holds it"
        words = {ADDRESS: (first, whole), "198.51.100.2": (later, later)}
        room = len(_pcap(data, None)) + len("; " + first) + len("; " + later)
        line = _pcap(data, room, lambda address: words[address])
        assert f"; {first} | " in line and f"; {later}; contacts" in line
        assert whole not in line


class TestTheFormsAndTheirReaders:
    def test_no_count_and_no_mark_outside_brackets(self) -> None:
        for said in (
            _said({"udp": [_flow(), _flow()]}),
            _said({"tcp": [_flow(procid=47, pid=2780), _flow()]}),
        ):
            outside = _outside_brackets(said)
            assert not re.search(r"\d", outside), said
            assert "," not in outside and ";" not in outside, said
            assert _restated(said)

    def test_the_judge_s_question_asserts_nothing_of_its_own(self) -> None:
        network = network_from_ledger(_ledger({"tcp": [_flow(procid=47, pid=2780)]}))
        facts = sandbox_facts_for_the_judge(network)
        bundle = Bundle.model_validate(
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332211",
                        "name": "judge indicator",
                        "pattern": f"[ipv4-addr:value = '{ADDRESS}']",
                        "pattern_type": "stix",
                        "indicator_types": ["malicious-activity"],
                        "valid_from": "2026-01-01T00:00:00Z",
                    }
                ],
            }
        )
        (found,) = unattributed_indicator_violations(bundle, facts)
        assert found.message == (
            f"the indicator 'judge indicator' names '{ADDRESS}' and the publish rule did not "
            "place the process a flow to it names by id (procid 47 pid 2780). The publish rule "
            "does not count it as the sample's own observation. Keep the indicator only if this "
            "run's evidence shows the sample itself reached it, and cite that entry in the "
            "indicator's description; otherwise remove the indicator."
        )

    def test_the_flow_voice_message_carries_the_fact_and_the_rule(self) -> None:
        payload = {
            "steps": [
                {
                    "action": f"beacons to {ADDRESS}",
                    "voice": "observed",
                    "evidence_refs": ["ev_0001"],
                }
            ]
        }
        (found,) = flow_voice_violations(
            payload,
            ["ev_0001"],
            flow_fact=lambda kind, value: "the publish rule found no flow row to it",
        )
        assert found.message == (
            f"step 1 is marked observed and names a network value with this fact ({ADDRESS}: "
            "the publish rule found no flow row to it). A network step is observed only for a "
            "value the sample's own process tree reached. Mark the step assessed, or leave the "
            "value out of the observed step."
        )

    def test_an_address_and_a_url_on_another_lineage_share_the_subject(self) -> None:
        unlisted = _flow(procid=46, **{TRAFFIC_PROCESS_KEY: 46, PROCESS_UNLISTED_KEY: True})
        assert _said({"tcp": [unlisted]}) == (
            RULE + "found a flow to it made by a process the report does not list (procid 46)"
        )
        assert url_made_by_reason({"unlisted": ["procid 46"]}) == (
            RULE + "counted its requests as made by a process the report does not list (procid 46)"
        )
        assert UNATTRIBUTED_CAPTURE_VALUE.startswith(RULE)


class TestTheHeldTextHoldsNoReading:
    def test_the_summary_check_s_held_text_is_the_one_without_the_reading(self) -> None:
        flows = {"tcp": [_flow(pid=2756, **{FLOW_PROCESS_KEY: "q.exe"})]}
        built = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            overall_confidence=0.9,
            network=network_from_ledger(_ledger(flows)),
        )
        assert built.network is not None and built.network.ips[0].flow_reading
        document = json.loads(built.model_dump_json())
        for ip in document["network"]["ips"]:
            ip.pop("flow_reading")
        stored = MalwareReport.model_validate(document)
        assert held_text(built) == held_text(stored)
        assert "q.exe" not in held_text(built)
