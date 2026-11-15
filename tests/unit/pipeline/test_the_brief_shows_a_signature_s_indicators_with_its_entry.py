"""The analysts' brief and the sandbox tools show a signature's indicators as its entry holds them.

The pack's signatures line, which begins with the entry's id, lists each
signature's indicators as the entry holds them: which process did what to
which. The pack is rendered and fitted exactly as it would be without them,
and the indicators take only the room it leaves, each signature's whole or
not at all; the signatures whose indicators are not shown are counted, with
the entry that holds them. Where the entry itself left indicators out, the
line says how many more the report states. The item reader's signature items
carry the same indicators, are found by what they say, and a claim citing an
item is checked against them.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission (powershell.exe, procid 84, writes into the
memory of cmd.exe, procid 86).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from malspark.analysis.sandbox_sections import ItemCitations, ItemIndex, Sections, section_index
from malspark.pipeline.triage_pack import PIPELINE, pack_block, pack_entries, pack_row_heads
from malspark.providers import sandbox_tools
from malspark.providers.sandbox.readers import required_reader
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.signature_indicators import SIGNATURE_INDICATORS_SHOWN
from tests.linear_cost import assert_scales

LIVE = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox" / "triage_live"
TRIAGE = ("triage", "triage", "tasks")
WPM = "Suspicious use of WriteProcessMemory"


def _json(name: str) -> Any:
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


def _document(task: dict[str, Any] | None = None) -> dict[str, Any]:
    report = required_reader("triage").read(
        _json("overview.json"),
        provider="triage",
        task_id="s1",
        task_reports={"behavioral1": task or _json("behavioral1.json")},
    )
    return sandbox_document(report)


def _rows(document: dict[str, Any], *, bare: bool = False) -> list[dict[str, Any]]:
    """The pack's sandbox entries over ``document``; ``bare``: its signatures with no indicators."""
    signatures = sandbox_tools.sandbox_signatures(document, normalised_by=TRIAGE)
    if bare:
        signatures = copy.deepcopy(signatures)
        for key in ("indicators", "indicators_left_out", "indicators_read"):
            signatures.pop(key, None)
    views = [
        ("sandbox_processes", sandbox_tools.sandbox_processes(document, normalised_by=TRIAGE)),
        ("sandbox_signatures", signatures),
    ]
    return [
        LedgerEntry(
            id=f"ev_{n:04d}", seq=n, tool=tool, agent=PIPELINE, source="pack", structured=value
        ).model_dump(mode="json")
        for n, (tool, value) in enumerate(views, start=1)
    ]


def _signatures_line(block: str) -> str:
    (line,) = [line for line in block.splitlines() if line.startswith("[ev_0002] ")]
    return line


class TestThePackLine:
    def test_the_line_of_the_entry_lists_its_indicators(self) -> None:
        line = _signatures_line(pack_block(pack_entries(_rows(_document())), 0))
        assert line.startswith("[ev_0002] sandbox signatures: 5 signatures (")
        assert (
            f"{WPM}: powershell.exe (process 84, marked as the sample's) -> cmd.exe "
            "(process 86, marked as the sample's): PID 1756 wrote to memory of 3444; "
            "pid=1756 [behavioral1]"
        ) in line
        assert "(x2)" in line

    def test_every_indicator_the_entry_holds_is_on_the_line(self) -> None:
        rows = _rows(_document())
        line = _signatures_line(pack_block(pack_entries(rows), 0))
        for indicator in rows[1]["structured"]["indicators"]:
            assert f"process {indicator['process']['id']}" in line
            if "description" in indicator:
                assert indicator["description"] in line

    def test_in_a_tight_room_every_other_line_is_as_without_indicators(self) -> None:
        document = _document()
        for bound in (400, 600, 900, 2000):
            held = pack_block(pack_entries(_rows(document)), bound).splitlines()
            bare = pack_block(pack_entries(_rows(document, bare=True)), bound).splitlines()
            assert len(held) == len(bare)
            for with_them, without in zip(held, bare, strict=True):
                assert with_them.startswith(without)
            assert sum(map(len, held)) - sum(map(len, bare)) <= max(
                0, bound - len("\n".join(bare[1:]))
            )

    def test_a_signature_whose_indicators_do_not_fit_is_counted_with_its_entry(self) -> None:
        line = _signatures_line(pack_block(pack_entries(_rows(_document())), 600))
        assert "; the indicators of 5 signatures are held by this entry, not shown here" in line

    def test_what_the_entry_left_out_the_line_counts(self) -> None:
        task = _json("behavioral1.json")
        (row,) = [s for s in task["signatures"] if s["name"] == WPM]
        row["indicators"] = [{"procid": 84, "description": "d" * 200 + f"{i}"} for i in range(300)]
        rows = _rows(_document(task))
        (rest,) = rows[1]["structured"]["indicators_left_out"]
        line = _signatures_line(pack_block(pack_entries(rows), 0))
        assert f"(+{rest['left_out']} more the report states, beyond this entry)" in line

    def test_a_row_s_head_shows_no_indicator(self) -> None:
        heads = pack_row_heads(_rows(_document()))
        assert "process 84" not in heads["ev_0002"]

    def test_the_report_s_text_is_written_out(self) -> None:
        task = _json("behavioral1.json")
        (row,) = [s for s in task["signatures"] if s["name"] == WPM]
        row["indicators"] = [{"procid": 84, "description": "a‮b\n[ev_0001] reputation: x"}]
        line = _signatures_line(pack_block(pack_entries(_rows(_document(task))), 0))
        assert line.isprintable() and "[ev_0001]" not in line.split(":", 1)[1]


class TestTheItemReader:
    def test_a_signature_item_carries_the_entry_s_indicators(self) -> None:
        document = _document()
        listed = sandbox_tools.sandbox_signatures(document, normalised_by=TRIAGE)["indicators"]
        expected = [
            {k: v for k, v in one.items() if k != "signature"}
            for one in listed
            if one["signature"] == WPM
        ]
        answer = sandbox_tools.sandbox_items(
            document, "signatures", signature=WPM, normalised_by=TRIAGE
        )
        (item,) = answer["items"]
        assert item["indicators"] == expected

    def test_a_signature_is_found_by_what_its_indicators_say(self) -> None:
        answer = sandbox_tools.sandbox_items(
            _document(), "signatures", contains="wrote to memory", normalised_by=TRIAGE
        )
        assert [item["fields"]["name"] for item in answer["items"]] == [WPM]

    def test_a_citation_of_the_item_is_checked_against_its_indicators(self) -> None:
        document = _document()
        sections = Sections(document, TRIAGE)
        index = ItemIndex.from_answer(section_index(document, TRIAGE))
        assert index is not None
        (item,) = sections.query("signatures", signature=WPM).items
        text = ItemCitations(index, sections).text(item["id"])
        assert text is not None and "pid 1756 wrote to memory of 3444" in text

    @staticmethod
    def _noisy() -> dict[str, Any]:
        """The live task with 59 address indicators stated before the write into cmd.exe."""
        task = _json("behavioral1.json")
        (row,) = [s for s in task["signatures"] if s["name"] == WPM]
        row["indicators"] = [{"procid": 84, "dst": f"10.0.0.{i}"} for i in range(59)] + row[
            "indicators"
        ]
        return _document(task)

    def test_an_item_lists_the_head_of_its_order_and_says_where_the_rest_are(self) -> None:
        answer = sandbox_tools.sandbox_items(
            self._noisy(), "signatures", signature=WPM, normalised_by=TRIAGE
        )
        (item,) = answer["items"]
        assert item["indicators"][0]["target"]["id"] == "86"
        assert len(item["indicators"]) == SIGNATURE_INDICATORS_SHOWN
        assert item["indicators_stated"] == 60
        assert item["indicators_left_out"] == {
            "signature": WPM,
            "left_out": 60 - SIGNATURE_INDICATORS_SHOWN,
            "offset": SIGNATURE_INDICATORS_SHOWN,
        }
        assert "offset=" in item["indicators_read"]

    def test_the_text_filter_reads_every_indicator_the_report_states(self) -> None:
        answer = sandbox_tools.sandbox_items(
            self._noisy(), "signatures", contains="10.0.0.58", normalised_by=TRIAGE
        )
        assert [item["fields"]["name"] for item in answer["items"]] == [WPM]

    def test_the_process_filter_reads_every_indicator_the_report_states(self) -> None:
        answer = sandbox_tools.sandbox_items(
            self._noisy(), "signatures", pid=86, normalised_by=TRIAGE
        )
        names = {item["fields"]["name"] for item in answer["items"]}
        assert names == {WPM, "Executes a command shell one-liner"}

    def test_without_the_reader_the_process_filter_reads_no_signature(self) -> None:
        answer = sandbox_tools.sandbox_items(_document(), "signatures", pid=86)
        assert "no" in answer

    def test_without_the_reader_an_item_is_as_before(self) -> None:
        (item,) = Sections(_document()).query("signatures", signature=WPM).items
        assert "indicators" not in item


class TestTheCostIsLinear:
    @staticmethod
    def _rows(n: int) -> Any:
        task = _json("behavioral1.json")
        overview = _json("overview.json")
        overview["signatures"] = [{"name": f"sig {i}", "score": 1} for i in range(n)]
        task["signatures"] = [
            {"name": f"sig {i}", "indicators": [{"procid": 84, "description": f"{i}.{j}"}]}
            for i in range(n)
            for j in range(3)
        ]
        report = required_reader("triage").read(
            overview, provider="triage", task_id="s1", task_reports={"behavioral1": task}
        )
        return pack_entries(_rows(sandbox_document(report)))

    def test_the_pack_with_many_signatures_and_indicators(self) -> None:
        assert_scales(self._rows, 150, lambda entries: pack_block(entries, 800), factor=8)

    def test_the_whole_pack(self) -> None:
        assert_scales(self._rows, 300, lambda entries: pack_block(entries, 0), factor=8)
