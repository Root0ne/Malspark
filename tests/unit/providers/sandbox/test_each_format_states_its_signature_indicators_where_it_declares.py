"""Each format's signature indicators are read where its reader declares them, and nowhere else.

The CAPE, Cuckoo and mock readers declare a signature's marks (``data`` in the
report's own arrangement): the process a mark names by the process list's id,
an API call's mark its API, an indicator's mark its category; the Triage
reader declares an overview row's marks and the task rows of the same name. A
mapped format declares its own through the mapping's ``field_names``
(``signatures.platform_indicators`` and the fields of each indicator), and its
reader writes them on the row in the neutral form. A format that states none
answers as before, and the generic view reads no format's own field name.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
from pathlib import Path
from typing import Any

import pytest

from malspark.core.report_mapping import RestMappingConfig
from malspark.providers.sandbox import readers
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import SignatureIndicators, sandbox_signatures
from malspark.schemas import signature_indicators
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import SandboxReport, SandboxSignatureRow
from malspark.schemas.signature_indicators import SIGNATURE_INDICATORS_KEY
from tests.linear_cost import assert_scales

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox"


def _view(report: SandboxReport, normalised_by: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    answer = sandbox_signatures(sandbox_document(report), normalised_by=normalised_by)
    return {row["name"]: row for row in answer["signatures"]}


def _cape_payload() -> dict[str, Any]:
    return {
        "info": {"id": 7},
        "behavior": {
            "processes": [
                {"process_id": 10, "parent_id": 4, "process_name": "a.exe"},
                {"process_id": 11, "parent_id": 10, "process_name": "notepad.exe"},
            ]
        },
        "signatures": [
            {
                "name": "injection_rwx",
                "severity": 3,
                "data": [
                    {
                        "type": "call",
                        "pid": 10,
                        "cid": 4,
                        "call": {"api": "WriteProcessMemory", "arguments": {"ProcessId": 11}},
                    },
                    {"type": "ioc", "category": "file", "ioc": "C:\\x\\y.dll"},
                    {"pid": 99, "description": "a process the report does not list"},
                ],
            }
        ],
    }


class TestCape:
    @pytest.mark.parametrize("reader", ["cape2", "cuckoo"])
    def test_a_call_mark_names_its_process_and_its_api(self, reader: str) -> None:
        report = required_reader(reader).read(_cape_payload(), provider="cape")
        call, ioc, unlisted = _view(report, ("cape", reader))["injection_rwx"]["indicators"]
        assert call["process"] == {"id": "10", "image": "a.exe"}
        assert call["event"] == "WriteProcessMemory"
        assert call["values"]["type"] == "call" and "ProcessId" in call["values"]["call"]
        assert ioc == {"event": "file", "values": {"type": "ioc", "ioc": "C:\\x\\y.dll"}}
        assert unlisted["process"] == {"id": "99", "not_listed": True}
        assert unlisted["description"] == "a process the report does not list"

    def test_the_mock_reader_reads_its_fixture_as_cape_does(self) -> None:
        report = required_reader("mock").read(_cape_payload(), provider="mock")
        (call, *_rest) = _view(report, ("mock", "mock"))["injection_rwx"]["indicators"]
        assert call["process"]["image"] == "a.exe"

    def test_a_report_laid_out_from_the_form_reads_its_marks(self) -> None:
        report = required_reader("cape2").read(_cape_payload(), provider="cape")
        report.arrangement = None
        report.signatures[0].marks = list(_cape_payload()["signatures"][0]["data"])
        (call, *_rest) = _view(report, ("cape", "cape2"))["injection_rwx"]["indicators"]
        assert call["event"] == "WriteProcessMemory"

    def test_the_stored_cape_report_s_values_are_its_indicators(self) -> None:
        payload = json.loads((FIXTURES / "cape2_report.json").read_text(encoding="utf-8"))
        report = required_reader("cape2").read(payload, provider="cape")
        rows = _view(report, ("cape", "cape2"))
        (pdb,) = rows["static_pe_pdbpath"]["indicators"]
        assert pdb == {
            "values": {"pdbpath": payload["signatures"][2]["data"][0]["pdbpath"]},
        }
        stated = len(payload["signatures"][0]["data"])
        network = rows["stealth_network"]
        assert network["indicators"][0] == {"values": {"ip": "119.29.29.29"}}
        assert network["indicators_total"] == stated
        assert network["indicators_left_out"] == stated - len(network["indicators"])


MAPPED = RestMappingConfig(
    processes="$.procs[*]",
    signatures="$.sigs[*]",
    field_names={
        "signatures.platform_indicators": "seen",
        "signatures.platform_indicators.process": "proc",
        "signatures.platform_indicators.target": "victim",
        "signatures.platform_indicators.event": "what.api",
    },
)


def _mapped_payload() -> dict[str, Any]:
    return {
        "procs": [
            {"pid": 10, "ppid": 0, "name": "C:\\u\\a.exe"},
            {"pid": 11, "ppid": 10, "name": "C:\\w\\notepad.exe"},
        ],
        "sigs": [
            {
                "name": "remote write",
                "seen": [{"proc": 10, "victim": "11", "what": {"api": "NtWriteVirtualMemory"}}],
            }
        ],
    }


class TestAMappedFormat:
    def test_its_declared_fields_are_read_into_the_neutral_form(self) -> None:
        report = required_reader("generic").read(
            _mapped_payload(), provider="upload", mapping=MAPPED
        )
        (indicator,) = _view(report, ("upload", "generic"))["remote write"]["indicators"]
        assert indicator["process"] == {"id": "10", "image": "a.exe"}
        assert indicator["target"] == {"id": "11", "image": "notepad.exe"}
        assert indicator["event"] == "NtWriteVirtualMemory"
        assert indicator["values"] == {"what": '{"api":"NtWriteVirtualMemory"}'}

    def test_a_mapping_declaring_none_carries_none(self) -> None:
        mapping = MAPPED.model_copy(update={"field_names": {}})
        report = required_reader("generic").read(
            _mapped_payload(), provider="upload", mapping=mapping
        )
        assert report.signatures[0].indicators == []
        assert "indicators" not in _view(report, ("upload", "generic"))["remote write"]

    def test_a_row_s_neutral_form_holding_anything_else_is_read_as_nothing(self) -> None:
        report = required_reader("generic").read(
            _mapped_payload(), provider="upload", mapping=MAPPED
        )
        report.signatures[0].indicators = [
            {"process": [10], "event": 5, "values": {"k": 3, "j": "v"}},
            "text",
        ]
        first, second = _view(report, ("upload", "generic"))["remote write"]["indicators"]
        assert first == {"values": {"j": "v"}} and second == {}


class TestAsBefore:
    def test_the_unread_format_carries_none(self) -> None:
        payload = json.loads((FIXTURES / "unread_flat_report.json").read_text(encoding="utf-8"))
        report = required_reader("unread").read(payload, provider="upload")
        reading = required_reader("unread").reading()
        assert reading.signature_indicators is None
        answer = sandbox_signatures(sandbox_document(report), normalised_by=("upload", "unread"))
        assert "indicators" not in json.dumps(answer)

    def test_a_signature_row_with_no_indicators_dumps_as_before(self) -> None:
        row = SandboxSignatureRow(name="x", marks=[{"pid": 1}])
        assert "indicators" not in row.model_dump()
        stored = {"name": "x", "description": "", "severity": 1, "marks": [], "ttp_tags": []}
        assert SandboxSignatureRow.model_validate(stored).model_dump() == stored

    def test_a_document_row_holds_the_neutral_key_only_where_a_reader_wrote_it(self) -> None:
        payload = json.loads((FIXTURES / "triage_overview.json").read_text(encoding="utf-8"))
        report = required_reader("triage").read(payload, provider="triage")
        rows = sandbox_document(report)["signatures"]
        assert rows and all(SIGNATURE_INDICATORS_KEY not in row for row in rows)


def _keys_read(source: str) -> set[str]:
    """The literal keys ``source`` reads: each ``.get("…")`` argument and ``[…]`` subscript."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        key: Any = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "get" and node.args:
                key = node.args[0]
        elif isinstance(node, ast.Subscript):
            key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            found.add(key.value)
    return found


def test_the_generic_reading_reads_no_format_s_own_field() -> None:
    """The declared field names live in the readers; the neutral reading reads none of them.

    ``name`` is the form's own field naming a signature, which every reader's
    row holds; a format whose task rows name their signature under the same
    word declares it all the same.
    """
    declared: set[str] = set()
    for reader_id in readers.report_reader_ids():
        fields = required_reader(reader_id).signature_indicators
        if fields is None or fields.neutral:
            continue
        declared.update(fields.lists + fields.process + fields.target + fields.description)
        declared.update(path.split(".")[0] for path in fields.event)
        declared.update(fields.task_lists + (fields.task_name, fields.task_channel))
    assert {"procid", "marks", "data", "call", "indicators"} <= declared
    read = _keys_read(inspect.getsource(signature_indicators))
    read |= _keys_read(textwrap.dedent(inspect.getsource(SignatureIndicators)))
    assert read & declared <= {"name"}


class TestTheCostIsLinear:
    @staticmethod
    def _cape(n: int) -> dict[str, Any]:
        payload = _cape_payload()
        payload["behavior"]["processes"] += [
            {"process_id": 100 + i, "parent_id": 10, "process_name": f"p{i}.exe"} for i in range(n)
        ]
        payload["signatures"] = [
            {
                "name": f"s{i}",
                "data": [
                    {"type": "call", "pid": 100 + (i + j) % n, "call": {"api": f"A{j}"}}
                    for j in range(4)
                ],
            }
            for i in range(n)
        ]
        return sandbox_document(required_reader("cape2").read(payload, provider="cape"))

    def test_a_cape_report_with_many_signatures_and_marks(self) -> None:
        assert_scales(
            self._cape,
            200,
            lambda doc: sandbox_signatures(doc, normalised_by=("c", "cape2")),
            factor=8,
        )

    def test_a_mapped_report_with_many_indicators(self) -> None:
        def make(n: int) -> dict[str, Any]:
            payload = _mapped_payload()
            payload["sigs"] = [
                {"name": f"s{i}", "seen": [{"proc": 10, "victim": 11, "x": j} for j in range(4)]}
                for i in range(n)
            ]
            return payload

        def read_and_view(payload: dict[str, Any]) -> Any:
            report = required_reader("generic").read(payload, provider="u", mapping=MAPPED)
            return sandbox_signatures(sandbox_document(report), normalised_by=("u", "generic"))

        assert_scales(make, 200, read_and_view, factor=8)
