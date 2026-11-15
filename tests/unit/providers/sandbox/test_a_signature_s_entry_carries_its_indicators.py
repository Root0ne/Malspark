"""A sandbox signature's ledger entry carries its indicators: which process did what to which.

The signature view (``sandbox_signatures``), whose answer is the signature's
ledger entry, lists each signature's indicators where the job's reader declares
its source states them: a signature row's own, and, where the source lists its
signatures again per task, those of every task row of the same name, each read
in its task. Every process an indicator names is resolved to the process row
of the same report and task (its image, its launch lineage or the sandbox's
mark); an id the task does not list is stated as not listed, never dropped.
Equal indicators are listed once with their count, and each row states how
many the report states (``indicators_stated``); every text is cut to its bound
with what was cut counted, and written out. A report read
with no declaration, and a stored document read without its reader, answer as
before.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission: an archive whose launcher (powershell.exe,
procid 84) starts cmd.exe (procid 86).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_signatures
from malspark.schemas.sandbox_document import sandbox_document
from malspark.schemas.sandbox_report import (
    LINEAGE_KEY,
    LINEAGE_LAUNCHER_UNSETTLED,
    LINEAGE_SAMPLE,
    SandboxReport,
    attribute_the_launcher,
)
from malspark.schemas.signature_indicators import (
    INDICATOR_TEXT_CHARS,
    INDICATOR_VALUES_SHOWN,
    SIGNATURE_INDICATORS_SHOWN,
)
from tests.linear_cost import assert_scales

LIVE = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox" / "triage_live"
TRIAGE = ("triage", "triage", "tasks")
WPM = "Suspicious use of WriteProcessMemory"
LAUNCHER = {
    "sample_member": "cmd.exe",
    "launcher_member": "launch.ps1",
    "script_host_images": ["powershell.exe", "pwsh.exe"],
    "launcher_sha256": "aba6bd87cb5e4c8d594551ce5194d6a120ca721d85d766c0317598e0b5754a6e",
    "sample_sha256": "",
}


def _json(name: str) -> Any:
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


def _read(task: dict[str, Any] | None = None, overview: dict[str, Any] | None = None) -> Any:
    return required_reader("triage").read(
        overview or _json("overview.json"),
        provider="triage",
        task_id="s1",
        task_reports={"behavioral1": task or _json("behavioral1.json")},
    )


def _rows(report: SandboxReport, normalised_by: Any = TRIAGE) -> dict[str, dict[str, Any]]:
    """Each row of the view by name, with the indicators listed after the rows under its name."""
    answer = sandbox_signatures(sandbox_document(report), normalised_by=normalised_by)
    rows = {row["name"]: row for row in answer["signatures"]}
    for listed in answer.get("indicators") or []:
        one = dict(listed)
        rows[one.pop("signature")].setdefault("indicators", []).append(one)
    return rows


def _with_signature(indicators: list[Any], name: str = WPM) -> dict[str, Any]:
    """The live task with the task row of ``name`` holding ``indicators``."""
    task = _json("behavioral1.json")
    (row,) = [s for s in task["signatures"] if s["name"] == name]
    row["indicators"] = indicators
    return task


class TestTheLiveReport:
    def test_the_write_into_another_process_names_both_processes(self) -> None:
        (indicator,) = _rows(_read())[WPM]["indicators"]
        assert indicator == {
            "task": "behavioral1",
            "process": {"id": "84", "image": "powershell.exe", "marked": True},
            "target": {"id": "86", "image": "cmd.exe", "marked": True},
            "description": "PID 1756 wrote to memory of 3444",
            "values": {"pid": "1756"},
        }

    def test_equal_indicators_are_listed_once_with_their_count(self) -> None:
        (indicator,) = _rows(_read())["Suspicious behavior: EnumeratesProcesses"]["indicators"]
        assert indicator["times"] == 2 and indicator["process"]["id"] == "84"

    def test_each_task_s_indicators_are_read_in_that_task(self) -> None:
        report = required_reader("triage").read(
            _json("overview.json"),
            provider="triage",
            task_id="s1",
            task_reports={
                "behavioral1": _json("behavioral1.json"),
                "behavioral2": _json("behavioral2.json"),
            },
        )
        indicators = _rows(report)[WPM]["indicators"]
        assert [(i["task"], i["process"]["id"], i["target"]["id"]) for i in indicators] == [
            ("behavioral1", "84", "86"),
            ("behavioral2", "87", "89"),
        ]
        assert indicators[1]["process"]["image"] == "PowerShell.exe"

    def test_a_signature_whose_task_rows_state_none_carries_none(self) -> None:
        rows = _rows(_read())
        held = [name for name, row in rows.items() if "indicators" in row]
        task = {s["name"] for s in _json("behavioral1.json")["signatures"] if s.get("indicators")}
        assert set(held) == task & set(rows)


class TestTheLaunchLineage:
    def test_a_launcher_run_states_each_process_s_lineage_as_the_process_view_does(self) -> None:
        report = _read()
        attribute_the_launcher(report, LAUNCHER)
        (indicator,) = _rows(report)["Executes a command shell one-liner"]["indicators"]
        assert indicator["process"] == {
            "id": "86",
            "image": "cmd.exe",
            LINEAGE_KEY: LINEAGE_SAMPLE,
            "marked": True,
        }

    def test_a_host_whose_attribution_is_not_established_says_so(self) -> None:
        task = _json("behavioral1.json")
        task["processes"].append(
            {"procid": 50, "procid_parent": 0, "pid": 500, "image": "C:\\Windows\\explorer.exe"}
        )
        for proc in task["processes"]:
            if proc["procid"] == 86:
                proc["procid_parent"] = 50
        report = _read(task)
        attribute_the_launcher(report, LAUNCHER)
        (indicator,) = _rows(report)[WPM]["indicators"]
        assert indicator["process"][LINEAGE_KEY] == LINEAGE_LAUNCHER_UNSETTLED
        assert "marked" not in indicator["process"]
        assert indicator["target"][LINEAGE_KEY] == LINEAGE_SAMPLE


class TestEveryIdIsStated:
    def test_an_id_the_task_does_not_list_is_stated_as_not_listed(self) -> None:
        task = _with_signature([{"procid": 84, "procid_target": 999, "description": "x"}])
        (indicator,) = _rows(_read(task))[WPM]["indicators"]
        assert indicator["target"] == {"id": "999", "not_listed": True}

    def test_an_id_listed_twice_in_its_task_is_stated_as_such(self) -> None:
        task = _with_signature([{"procid": 84, "procid_target": 86}])
        task["processes"].append({"procid": 86, "procid_parent": 84, "image": "C:\\x\\other.exe"})
        (indicator,) = _rows(_read(task))[WPM]["indicators"]
        assert indicator["target"]["id"] == "86" and "image" not in indicator["target"]
        assert "2 processes" in indicator["target"]["not_settled"]

    @pytest.mark.parametrize("value", [True, 1.5, [86], {"a": 86}, 10**30, "x", -3], ids=repr)
    def test_an_id_of_a_type_that_cannot_be_one_is_not_stated_and_kept_as_a_value(
        self, value: Any
    ) -> None:
        task = _with_signature([{"procid": 84, "procid_target": value}])
        (indicator,) = _rows(_read(task))[WPM]["indicators"]
        assert "target" not in indicator
        assert "procid_target" in indicator["values"]

    def test_an_indicator_naming_no_task_is_read_in_the_one_task_listing_its_id(self) -> None:
        overview = _json("overview.json")
        overview["signatures"].append(
            {"name": "own marks", "score": 1, "indicators": [{"procid": 86, "ioc": "a"}]}
        )
        (indicator,) = _rows(_read(overview=overview))["own marks"]["indicators"]
        assert "task" not in indicator
        assert indicator["process"] == {"id": "86", "image": "cmd.exe", "marked": True}
        assert indicator["values"] == {"ioc": "a"}


class TestTheBounds:
    def test_every_one_the_answer_holds_is_listed_and_the_count_stated(self) -> None:
        count = SIGNATURE_INDICATORS_SHOWN + 24
        task = _with_signature([{"procid": 84, "description": f"d{i}"} for i in range(count)])
        row = _rows(_read(task))[WPM]
        assert len(row["indicators"]) == count and row["indicators_stated"] == count

    def test_repeats_of_a_shown_indicator_are_counted_on_it(self) -> None:
        task = _with_signature([{"procid": 84}] * 40)
        row = _rows(_read(task))[WPM]
        assert row["indicators"] == [
            {
                "task": "behavioral1",
                "process": {"id": "84", "image": "powershell.exe", "marked": True},
                "times": 40,
            }
        ]
        assert "indicators_left_out" not in row

    def test_a_long_text_is_cut_and_what_was_cut_is_counted(self) -> None:
        task = _with_signature([{"procid": 84, "description": "a" * 10_000, "k": "b" * 500}])
        (indicator,) = _rows(_read(task))[WPM]["indicators"]
        assert indicator["description"] == "a" * INDICATOR_TEXT_CHARS + "…"
        assert indicator["chars_left_out"] == {
            "description": 10_000 - INDICATOR_TEXT_CHARS,
            "values.k": 500 - INDICATOR_TEXT_CHARS,
        }

    def test_past_the_values_bound_the_rest_are_counted(self) -> None:
        wide = {"procid": 84, **{f"v{i}": i for i in range(INDICATOR_VALUES_SHOWN + 5)}}
        (indicator,) = _rows(_read(_with_signature([wide])))[WPM]["indicators"]
        assert len(indicator["values"]) == INDICATOR_VALUES_SHOWN
        assert indicator["values_left_out"] == 5

    def test_a_nested_value_is_its_compact_json(self) -> None:
        task = _with_signature([{"procid": 84, "call": {"api": "NtWriteVirtualMemory"}}])
        (indicator,) = _rows(_read(task))[WPM]["indicators"]
        assert indicator["values"]["call"] == '{"api":"NtWriteVirtualMemory"}'


class TestTheTextIsTheReport_s:
    def test_controls_bidi_and_ledger_ids_are_written_out(self) -> None:
        said = "x\u202ey\nz [ev_0003] reputation"
        task = _with_signature([{"procid": 84, "description": said, said: said}])
        (indicator,) = _rows(_read(task))[WPM]["indicators"]
        for text in (indicator["description"], *indicator["values"], *indicator["values"].values()):
            assert text.isprintable() and "ev_0003" not in text
            assert "\\u202e" in text or "\\x" in text


class TestAsBefore:
    def test_without_the_reader_the_answer_is_as_before(self) -> None:
        rows = _rows(_read(), normalised_by=None)
        assert all("indicators" not in row for row in rows.values())

    def test_a_reader_declaring_none_answers_as_before(self) -> None:
        rows = _rows(_read(), normalised_by=("upload", "generic"))
        assert all("indicators" not in row for row in rows.values())

    def test_the_report_and_its_dump_are_unchanged(self) -> None:
        report = _read()
        before = copy.deepcopy(report.model_dump())
        document = sandbox_document(report)
        held = json.dumps(document, sort_keys=True, default=str)
        sandbox_signatures(document, normalised_by=TRIAGE)
        assert report.model_dump() == before
        assert json.dumps(document, sort_keys=True, default=str) == held


WEIRD = [None, True, -1, 10**30, 1.5, "", "x", [], [1], {}, {"a": 1}, float("nan")]


class TestAHostileReport:
    @pytest.mark.parametrize("value", WEIRD, ids=repr)
    @pytest.mark.parametrize("where", ["indicators", "indicator", "name", "channel"])
    def test_no_value_makes_the_view_raise(self, where: str, value: Any) -> None:
        task = _json("behavioral1.json")
        (row,) = [s for s in task["signatures"] if s["name"] == WPM]
        if where == "indicators":
            row["indicators"] = value
        elif where == "indicator":
            row["indicators"] = [value, {"procid": value, "procid_target": value, "x": value}]
        elif where == "name":
            row["name"] = value
        report = _read(task)
        if where == "channel":
            report.channels["task.signatures"] = value
        json.dumps(sandbox_signatures(sandbox_document(report), normalised_by=TRIAGE))


class TestTheCostIsLinear:
    """Many signatures, many indicators, one name many rows share: linear in the report."""

    @staticmethod
    def _report(n: int, *, one_name: bool = False) -> dict[str, Any]:
        overview = _json("overview.json")
        task = _json("behavioral1.json")
        task["processes"] += [
            {"procid": 1000 + i, "procid_parent": 84, "image": f"C:\\p\\{i}.exe"} for i in range(n)
        ]
        names = [WPM if one_name else f"sig {i}" for i in range(n)]
        overview["signatures"] = [{"name": name, "score": 1} for name in names]
        task["signatures"] = [
            {
                "name": name,
                "indicators": [
                    {"procid": 1000 + i, "procid_target": 1000 + (i * 7) % n, "description": f"{j}"}
                    for j in range(4)
                ],
            }
            for i, name in enumerate(names)
        ]
        return sandbox_document(_read(task, overview))

    def test_many_signatures_with_many_indicators(self) -> None:
        assert_scales(
            self._report, 150, lambda doc: sandbox_signatures(doc, normalised_by=TRIAGE), factor=8
        )

    def test_many_signatures_sharing_one_name(self) -> None:
        assert_scales(
            lambda n: self._report(n, one_name=True),
            150,
            lambda doc: sandbox_signatures(doc, normalised_by=TRIAGE),
            factor=8,
        )
