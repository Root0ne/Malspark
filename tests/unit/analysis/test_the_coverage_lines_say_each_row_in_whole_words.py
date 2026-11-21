"""The coverage block says each row of its record in whole words, and nothing for no record.

``analysis.coverage.coverage_lines`` prints three blocks at the end of the run
summary appendix: what the run could not establish, what each tool looked at
and over which input, and each negative claim's coverage. Each sentence is
pinned whole here, by the row of the record it is written from (T-770), so a
change of wording is a change this file sees.
"""

from __future__ import annotations

from typing import Any

from malspark.analysis.coverage import coverage_lines, input_phrase
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.markdown import MarkdownRenderer, _Context


def _code(text: str) -> str:
    return f"`{text}`"


def _lines(record: Any, **kw: Any) -> tuple[list[str], list[str], list[str]]:
    blocks: tuple[list[str], list[str], list[str]] = coverage_lines(
        record, _code, lambda text: text, **kw
    )
    return blocks


def _report(run_summary: dict[str, Any]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary=run_summary,
    )


LAYER = {"input": "layer", "path": "/j/l.bin", "from": "ev_0002", "from_tool": "unpack"}


def test_each_input_is_named_by_what_it_is() -> None:
    said = [
        input_phrase(label)
        for label in (
            {"input": "sample"},
            {"input": "sample", "filled": True},
            {"input": "capture", "filled": True},
            {"input": "sandbox_report"},
            LAYER,
            {"input": "file", "path": "/j/a.txt"},
            {"input": "role", "role": "pattern"},
            {"input": "undeclared"},
            {"input": "undeclared", "server_reads_staged_sample": True},
            {"input": "unnamed"},
            {"input": "none"},
            {},
        )
    ]

    assert said == [
        "the sample",
        "the sample (filled in by the platform)",
        "the packet capture (filled in by the platform)",
        "the sandbox report",
        "the layer `/j/l.bin` produced by entry `ev_0002` (`unpack`)",
        "the file `/j/a.txt`",
        "its `pattern` argument",
        "an input the tool does not declare",
        "an input the tool does not declare (its server is handed the staged sample)",
        "an input the call does not name",
        "no input it names (the call took no arguments)",
        "an input not recorded",
    ]


def test_what_could_not_be_established_is_said_row_by_row() -> None:
    record = {
        "v": 1,
        "partial_reason": "the job timed out",
        "not_established": [
            {
                "what": "call",
                "tool": "strings",
                "server": "analysis",
                "kind": "strings",
                "state": "cut",
                "entries": ["ev_0001", "ev_0003"],
                "over": [{"input": "sample"}],
                "dropped": 12000,
            },
            {
                "what": "call",
                "tool": "capa",
                "server": "analysis",
                "kind": "",
                "state": "failed",
                "entries": ["ev_0004"],
                "over": [],
                "reason": "timeout",
            },
            {"what": "layer", **LAYER},
            {"what": "input", "input": "sandbox_report", "reason": "no sandbox ran."},
            {"what": "input", "input": "capture"},
            {"what": "server", "reason": "vt: no key"},
            {"what": "server_rests", "count": 1},
            {"what": "server_rests", "count": 2},
            {"what": "unreadable_rows", "count": 1},
            {"what": "unreadable_rows", "count": 3},
            {"what": "shortened", "reason": "strings answer"},
            {"what": "something new"},
        ],
    }
    analysts = (["static"], {"network": "no capture", "intel": ""}, ["dynamic"])

    missing, looked, negatives = _lines(record, analysts=analysts)

    assert missing == [
        "This record may be incomplete: the job timed out, and what the step it stopped in "
        "did may not be in it.",
        "`strings` (kind `strings`) on `analysis` answered and was cut over the sample "
        "(entries `ev_0001`, `ev_0003`): 12,000 characters cut.",
        "`capa` on `analysis` failed over no input it names (entry `ev_0004`): `timeout`.",
        "The layer `/j/l.bin` produced by entry `ev_0002` (`unpack`) was never examined.",
        "No sandbox report: no sandbox ran.",
        "No packet capture: not recorded.",
        "Tool server not attached: `vt: no key`.",
        "1 tool server rest, listed with the run summary lines above.",
        "2 tool server rests, listed with the run summary lines above.",
        "1 ledger row could not be read; a claim citing it reads as citing no entry.",
        "3 ledger rows could not be read; a claim citing one reads as citing no entry.",
        "Input shortened: `strings answer`.",
        "Analyst `static` failed; what it would have read was not read.",
        "Analyst `network` was skipped (`no capture`).",
        "Analyst `intel` was skipped.",
        "Analyst `dynamic` ran and made no claims.",
    ]
    assert (looked, negatives) == ([], [])


def test_a_record_with_nothing_missing_says_so_and_no_record_says_nothing() -> None:
    assert _lines({"v": 1}) == (
        [
            "Nothing recorded as missing: no tool call failed, was refused by a guard, was not "
            "run, was cut by the platform or was kept from the model, and no input, layer, tool "
            "server or analyst was recorded missing; an answer its tool capped, paged or "
            "narrowed is not counted here."
        ],
        [],
        [],
    )
    assert _lines(None) == ([], [], [])
    assert _lines({"not_built": "the record could not be read"}) == ([], [], [])


def test_each_tool_is_said_with_its_calls_inputs_and_states() -> None:
    record = {
        "v": 1,
        "tools": [
            {
                "tool": "strings",
                "server": "analysis",
                "kind": "strings",
                "calls": 3,
                "guard_answers": 2,
                "states": {"answered": 1, "cut": 1, "failed": 1, "not_run": 0},
                "over": [{"input": "sample"}],
                "roles": {"pattern": 1, "offset": 2},
            },
            {
                "tool": "capa",
                "calls": 4,
                "states": {"not_shown": 1, "not_run": 2, "guard": 1},
            },
            {"tool": "hashes", "calls": 1, "guard_answers": 1},
        ],
    }

    _missing, looked, _negatives = _lines(record)

    assert looked == [
        "`strings` (kind `strings`) on `analysis`: 3 calls over the sample, 1 `pattern` value, "
        "2 `offset` values; 1 answered and was cut, 1 failed; 2 more answered by a guard with "
        "no tool run (counted apart from the calls, as the evidence counts are).",
        "`capa`: 4 calls; 1 answered and was not shown to the model, 2 was not run, 1 was "
        "refused by a guard, with no tool run.",
        "`hashes`: 1 call; 1 more answered by a guard with no tool run (counted apart from "
        "the calls, as the evidence counts are).",
    ]


def _call(entry: str, **kw: Any) -> dict[str, Any]:
    return {"tool": kw.pop("tool", "hashes"), "entry": entry, "state": "answered", **kw}


def test_a_negative_citing_nothing_the_ledger_holds_says_so() -> None:
    row = {
        "agent": "static",
        "negative": "no mutex",
        "coverage": "unknown",
        "looked": [],
        "not_in_ledger": ["ev_0099"],
    }

    assert _lines({"v": 1, "negatives": [row]})[2] == [
        "`static`: “no mutex”: coverage unknown: the negative clause cites no entry the ledger "
        "holds (it names entry `ev_0099`)."
    ]


def test_each_negative_is_said_with_its_coverage_and_what_looked() -> None:
    sample = [{"input": "sample"}]
    rows = [
        {
            "agent": "static",
            "claim": "The sample is not packed",
            "coverage": "full",
            "looked": [_call("ev_0001", kind="identity", server="analysis", over=sample)],
        },
        {
            "agent": "static",
            "negative": "no network",
            "coverage": "input_unknown",
            "looked": [
                _call("ev_0002", tool="x", over=[{"input": "undeclared"}], read="not_known")
            ],
        },
        {
            "agent": "dynamic",
            "negative": "no beacon",
            "coverage": "failed",
            "looked": [_call("ev_0005", tool="report", over=[{"input": "sandbox_report"}])],
            "why": {"input": "sandbox_report", "statement": "the sandbox report was not observed."},
        },
        {
            "agent": "static",
            "negative": "no overlay",
            "coverage": "unknown",
            "looked": [_call("ev_0006", over=sample), _call("ev_0007", over=sample)],
            "why": {"answer_shape": ["ev_0006", "ev_0007"]},
        },
    ]

    assert _lines({"v": 1, "negatives": rows})[2] == [
        "`static`: “The sample is not packed” (kept after the absence question): coverage full. "
        "`hashes` (kind `identity`) on `analysis` (entry `ev_0001`) looked over the sample.",
        "`static`: “no network”: coverage of the input unknown. `x` (entry `ev_0002`) looked "
        "over an input the tool does not declare, how much of it the record cannot tell (the "
        "tool declares nothing).",
        "`dynamic`: “no beacon”: coverage failed. `report` (entry `ev_0005`) looked over the "
        "sandbox report. The sandbox report's own record is incomplete: the sandbox report was "
        "not observed.",
        "`static`: “no overlay”: coverage unknown. `hashes` (entry `ev_0006`) looked over the "
        "sample; `hashes` (entry `ev_0007`) looked over the sample. The answer of entries "
        "`ev_0006`, `ev_0007` has no shape the record can read its truncation markers from.",
    ]


def test_a_partial_negative_names_each_gap() -> None:
    row = {
        "agent": "static",
        "negative": "not packed",
        "coverage": "partial",
        "looked": [
            _call(
                "ev_0001", tool="capa", over=[{"input": "sample"}], state="failed", reason="timeout"
            ),
            _call("ev_0003", over=[], state="cut"),
        ],
        "gaps": [
            {"gap": "cited", "entry": "ev_0001", "state": "failed"},
            {"gap": "narrowed", "entry": "ev_0002", "by": ["offset", "limit"]},
            {"gap": "capped", "entry": "ev_0003"},
            {"gap": "not_declared_whole", "entry": "ev_0004"},
            {"gap": "no_capture"},
            {"gap": "no_capture", "why": "the capture could not be fetched"},
            {"gap": "input_mismatch", "over": [{"input": "file", "path": "/j/a.txt"}]},
            {"gap": "same_kind_no_answer", "entries": ["ev_0008"]},
            {"gap": "same_kind_no_answer", "entries": ["ev_0008", "ev_0009"]},
            {"gap": "layer_never_examined", "path": "/j/l.bin", "from": "ev_0002"},
            {"gap": "layer_not_read", "path": "/j/l.bin", "from": "ev_0002"},
            {"gap": "odd"},
        ],
        "not_in_ledger": ["ev_0099"],
    }

    assert _lines({"v": 1, "negatives": [row]})[2] == [
        "`static`: “not packed”: coverage partial. `capa` (entry `ev_0001`) looked over the "
        "sample, and failed (`timeout`); `hashes` (entry `ev_0003`) looked over no input it "
        "names, and answered and was cut. Not covered: entry `ev_0001` failed; entry "
        "`ev_0002` was passed arguments no declaration marks as not narrowing (`offset`, "
        "`limit`); entry `ev_0003` says its answer holds part of the rows; entry `ev_0004` is "
        "of a tool no declaration says reads its whole input; the sandbox report names no "
        "packet capture; the capture could not be fetched; the calls read the file `/j/a.txt`, "
        "not the sample; 1 call of the same kind over the same input did not answer (listed "
        "under what this run could not establish); 2 calls of the same kind over the same "
        "input did not answer (listed under what this run could not establish); the layer "
        "`/j/l.bin` produced by entry `ev_0002` was never examined; the layer `/j/l.bin` "
        "produced by entry `ev_0002` was read by no call the clause cites; `odd`. It also "
        "names entry `ev_0099`, which the ledger does not hold."
    ]


def test_the_report_heads_each_block_and_points_to_it_from_a_nothing_recorded_line() -> None:
    record = {
        "v": 1,
        "tools": [{"tool": "hashes", "calls": 1}],
        "negatives": [
            {"agent": "static", "negative": "no mutex", "coverage": "unknown", "looked": []}
        ],
    }
    markdown = MarkdownRenderer().render(_report({"final_decision": "Malware", "coverage": record}))

    assert "\n**What this run could not establish:**\n" in markdown
    assert "\n**What each tool looked at, and over which input:**\n" in markdown
    assert (
        "\n**Negative findings and what looked** (a claim is read as negative from its wording, "
        "clause by clause, or because its analyst kept it after the absence question; coverage "
        "counts only the entries cited in the negative clause, and each call is named by its "
        "ledger entry, which holds its arguments):\n"
    ) in markdown

    with_record = _Context(_report({"final_decision": "Malware", "coverage": record}))
    without = _Context(_report({"final_decision": "Malware"}))
    with_record.file_tools = without.file_tools = ["strings"]
    pointer = (
        " What each tool looked at, and over which input, is under the coverage lines of "
        "Appendix B."
    )
    assert with_record.absence("mutex", sandbox=False).endswith(pointer)
    assert "coverage lines" not in without.absence("mutex", sandbox=False)
