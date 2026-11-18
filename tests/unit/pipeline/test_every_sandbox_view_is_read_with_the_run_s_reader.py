"""Every sandbox view is read with the run's reader, through one entry point.

The pack, the read of a later detonation and an analyst's call each read the
sandbox's views, and the reader that built the report declares what its rows
mean (``Reading``): which field of a dropped row is its guest path, which
names its writer. A read without that declaration printed a written file with
an empty path beside the analyst's row with its guest path, and the report
listed the one file twice. Every view is read through ``read_view``, which
takes the reader's declaration as a required argument: a call without it does
not run, and no module reads a view by its function.

The reports under ``fixtures/sandbox/triage_live`` are a public sandbox's
output for a harmless submission; the rows added here are synthetic.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from malspark.providers import sandbox_tools
from malspark.providers.detonation import DetonationRecord
from malspark.providers.sandbox_tools import read_view
from malspark.reporting.ledger_projection import dynamic_from_ledger
from malspark.schemas.evidence import LedgerEntry, build_entry
from malspark.schemas.sandbox_document import sandbox_document
from tests.unit.providers.test_the_dropped_files_view_keeps_each_row_s_path_origin_kind_and_writer import (  # noqa: E501
    NOTE,
    TASKS,
    WRITTEN,
    _report,
)

SRC = Path(sandbox_tools.__file__).resolve().parents[1]
# Every module that may read a view: the platform's and the API's.
ROOTS = (SRC, SRC.parents[1] / "apps" / "api" / "app")
_MODULE = "sandbox_tools"
# What no module but the entry point's own may take from it: a view by its
# function, and the table of views.
_TAKEN = frozenset(set(sandbox_tools.DETONATION_READERS) - {sandbox_tools.ITEMS_TOOL}) | {
    "_VIEWS",
    "_UNDECLARED_VIEWS",
}


def _names_the_module(name: str) -> bool:
    return name == _MODULE or name.endswith(f".{_MODULE}")


def _dotted(node: ast.AST) -> str:
    """``a.b.c`` for a name or a chain of attributes; ``""`` for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        return f"{head}.{node.attr}" if head else ""
    return ""


def view_reads(source: str) -> list[str]:
    """Where ``source`` takes a view or the views table from the entry point's module.

    Under any name: an import of a view or of the table from it, under any
    alias; an attribute of the module, however it was imported or named; any
    ``getattr`` on the module. Each as ``line name``.
    """
    tree = ast.parse(source)
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _names_the_module(alias.name):
                    aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == _MODULE:
                    aliases.add(alias.asname or alias.name)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and _names_the_module(node.module or ""):
            found += [
                f"{node.lineno} {a.name}" for a in node.names if a.name in _TAKEN or a.name == "*"
            ]
        elif isinstance(node, ast.Attribute) and node.attr in _TAKEN:
            head = _dotted(node.value)
            if head in aliases or _names_the_module(head):
                found.append(f"{node.lineno} {node.attr}")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and node.args
        ):
            head = _dotted(node.args[0])
            if head in aliases or _names_the_module(head):
                found.append(f"{node.lineno} getattr")
    return found


# Every function that takes the run's reader and hands it to a view, with
# where a call states it: the position of the argument, else its keyword. A
# call states it where it passes that argument, and not as a literal ``None``.
READER_TAKERS: dict[str, tuple[int | None, str]] = {
    "read_view": (2, ""),
    "network_view": (1, ""),
    "processes_view": (1, ""),
    "api_calls_view": (1, ""),
    "network_from_sandbox_report": (1, "normalised_by"),
    "network_from_ledger": (None, "normalised_by"),
    "judge_sandbox_facts": (None, "sandbox_normalised_by"),
    "MalwareReportBuilder": (None, "sandbox_normalised_by"),
    "sandbox_started_positions": (1, "normalised_by"),
    "address_flow_facts": (None, "normalised_by"),
    "pack_block": (None, "normalised_by"),
    "pack_row_heads": (None, "normalised_by"),
}


def _called(node: ast.Call) -> tuple[str, list[ast.expr]]:
    """The function a call calls, by its last name, and its positional arguments.

    A ``partial`` of a function is a call of it with the arguments given so far.
    """
    name = _dotted(node.func).rsplit(".", 1)[-1]
    if name == "partial" and node.args:
        return _dotted(node.args[0]).rsplit(".", 1)[-1], list(node.args[1:])
    return name, list(node.args)


def _says_unstated(node: ast.expr | None, names: frozenset[str] = frozenset()) -> bool:
    """Whether an expression is, or can yield, the pack's "no reader stated" mark.

    By any qualified name ending in ``UNSTATED``, a name of ``names`` (one
    bound to the mark in the source: an alias import or an assignment), a
    ``getattr`` of it, the enum or its member, or a conditional or a boolean
    expression one of whose values is one of those.
    """
    if node is None:
        return False
    if isinstance(node, ast.Name) and node.id in names:
        return True
    dotted = _dotted(node)
    if dotted.rsplit(".", 1)[-1].endswith("UNSTATED") or "_Unstated" in dotted.split("."):
        return True
    if isinstance(node, ast.Attribute) and node.attr.endswith("UNSTATED"):
        return True
    if isinstance(node, ast.Call):
        called = _dotted(node.func).rsplit(".", 1)[-1]
        if called == "_Unstated":
            return True
        if called == "getattr" and len(node.args) >= 2:
            named = node.args[1]
            return isinstance(named, ast.Constant) and str(named.value).endswith("UNSTATED")
        return False
    if isinstance(node, ast.IfExp):
        return _says_unstated(node.body, names) or _says_unstated(node.orelse, names)
    if isinstance(node, ast.BoolOp):
        return any(_says_unstated(value, names) for value in node.values)
    return False


def _unstated_names(tree: ast.AST) -> frozenset[str]:
    """The names ``tree`` binds to the mark: alias imports of it, and assignments, to a fixpoint."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names |= {
                alias.asname or alias.name
                for alias in node.names
                if alias.name.endswith("UNSTATED") or alias.name == "_Unstated"
            }
    assignments = [
        (target.id, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    ] + [
        (node.target.id, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign | ast.NamedExpr) and isinstance(node.target, ast.Name)
    ]
    grown = True
    while grown:
        grown = False
        for name, value in assignments:
            if name not in names and _says_unstated(value, frozenset(names)):
                names.add(name)
                grown = True
    return frozenset(names)


def readers_made_up(source: str) -> list[str]:
    """Where ``source`` calls a function of :data:`READER_TAKERS` with no reader stated.

    Each as ``line name``: the reader argument left out, given as a literal
    ``None``, or given as the pack's mark of no reader stated, directly or
    handed over (:func:`_says_unstated`).
    """
    found: list[str] = []
    tree = ast.parse(source)
    marks = _unstated_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name, args = _called(node)
        if name not in READER_TAKERS:
            continue
        position, keyword = READER_TAKERS[name]
        given: ast.expr | None = None
        if position is not None and len(args) > position:
            given = args[position]
        given = next((k.value for k in node.keywords if keyword and k.arg == keyword), given)
        if any(isinstance(a, ast.Starred) for a in args) or any(
            k.arg is None for k in node.keywords
        ):
            continue
        if (
            given is None
            or (isinstance(given, ast.Constant) and given.value is None)
            or _says_unstated(given, marks)
        ):
            found.append(f"{node.lineno} {name}")
    return found


def reader_calls(source: str) -> list[tuple[int, str, str]]:
    """Each call of a function of :data:`READER_TAKERS` in ``source``, with the reader it passes."""
    out: list[tuple[int, str, str]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name, args = _called(node)
        if name not in READER_TAKERS:
            continue
        position, keyword = READER_TAKERS[name]
        given = args[position] if position is not None and len(args) > position else None
        given = next((k.value for k in node.keywords if keyword and k.arg == keyword), given)
        out.append((node.lineno, name, ast.unparse(given) if given is not None else ""))
    return out


PACK_VIEWS = (
    "sandbox_processes",
    "sandbox_network",
    "sandbox_signatures",
    "sandbox_dropped_files",
    "sandbox_channels",
)


def _document() -> dict[str, Any]:
    return sandbox_document(_report(WRITTEN))


class TestOneEntryPoint:
    def test_a_view_is_not_read_without_the_reader_s_declaration(self) -> None:
        with pytest.raises(TypeError):
            read_view("sandbox_dropped_files", _document())  # type: ignore[call-arg]

    def test_no_module_reads_a_view_but_through_the_entry_point(self) -> None:
        found: list[str] = []
        for root in ROOTS:
            for path in sorted(root.rglob("*.py")):
                if path.resolve() == Path(sandbox_tools.__file__).resolve():
                    continue
                found += [
                    f"{path.relative_to(root.parent)}:{where}"
                    for where in view_reads(path.read_text(encoding="utf-8"))
                ]
        assert found == []

    @pytest.mark.parametrize(
        "source",
        [
            # The module under another name, a view taken from it.
            "import malspark.providers.sandbox_tools as st\nst.sandbox_processes(doc)\n",
            # A view imported under another name.
            "from malspark.providers.sandbox_tools import sandbox_dropped_files as d\n",
            # A view taken from the module by ``getattr``.
            "from malspark.providers import sandbox_tools\n"
            "getattr(sandbox_tools, 'sandbox_network')(doc)\n",
            # The views table imported.
            "from malspark.providers.sandbox_tools import _VIEWS\n",
            # The module under another name, the views table taken from it.
            "from malspark.providers import sandbox_tools as tools\ntools._VIEWS['x']\n",
            # Any ``getattr`` on the module, whatever it names.
            "import malspark.providers.sandbox_tools\n"
            "getattr(malspark.providers.sandbox_tools, name)\n",
        ],
    )
    def test_the_guard_finds_a_view_read_by_any_name(self, source: str) -> None:
        assert view_reads(source) != []

    def test_no_call_hands_a_view_a_reader_it_made_up(self) -> None:
        found: list[str] = []
        for root in ROOTS:
            for path in sorted(root.rglob("*.py")):
                if path.resolve() == Path(sandbox_tools.__file__).resolve():
                    continue
                found += [
                    f"{path.relative_to(root.parent)}:{where}"
                    for where in readers_made_up(path.read_text(encoding="utf-8"))
                ]
        assert found == []

    @pytest.mark.parametrize(
        "source",
        [
            "network_view(report, None)\n",
            "sandbox_tools.processes_view(report, None)\n",
            "sandbox_tools.api_calls_view(report)\n",
            "sandbox_tools.read_view('sandbox_processes', report)\n",
            "partial(read_view, tool, report)\n",
            "partial(sandbox_tools.read_view, tool, report, None)\n",
            "network_from_sandbox_report(report)\n",
            "network_from_ledger(ledger, isrs, sandbox_report=report)\n",
            "network_from_ledger(ledger, normalised_by=None)\n",
            "judge_sandbox_facts(ledger, isrs, report)\n",
            "MalwareReportBuilder(file_hash=h, sandbox_report=report)\n",
            "builder.MalwareReportBuilder(sandbox_normalised_by=None)\n",
            "sandbox_started_positions(report)\n",
            "sandbox_tools.sandbox_started_positions(report, None)\n",
            "address_flow_facts(ledger)\n",
            "address_flow_facts(ledger, normalised_by=None)\n",
            "pack_block(entries, chars)\n",
            "triage_pack.pack_block(entries, chars, normalised_by=None)\n",
            "pack_row_heads(ledger)\n",
            "pack_block(e, c, normalised_by=UNSTATED)\n",
            "triage_pack.pack_row_heads(rows, normalised_by=triage_pack.UNSTATED)\n",
            "pack_row_heads(rows, normalised_by=__import__('m', fromlist=['x']).UNSTATED)\n",
            # The mark handed over indirectly.
            "from malspark.pipeline.triage_pack import UNSTATED as NR\n"
            "pack_block(e, c, normalised_by=NR)\n",
            "from malspark.pipeline.triage_pack import UNSTATED as normalised_by\n"
            "pack_block(e, c, normalised_by=normalised_by)\n",
            "nb = UNSTATED\npack_block(e, c, normalised_by=nb)\n",
            "nb = triage_pack.UNSTATED\nother = nb\npack_row_heads(r, normalised_by=other)\n",
            "pack_block(e, c, normalised_by=getattr(triage_pack, 'UNSTATED'))\n",
            "pack_block(e, c, normalised_by=triage_pack._Unstated.READER)\n",
            "pack_block(e, c, normalised_by=_Unstated('unstated'))\n",
            "pack_block(e, c, normalised_by=r if r else UNSTATED)\n",
            "pack_block(e, c, normalised_by=r or UNSTATED)\n",
        ],
    )
    def test_the_guard_finds_a_reader_left_out_or_none(self, source: str) -> None:
        assert readers_made_up(source) != []

    @pytest.mark.parametrize(
        "source",
        [
            "network_view(report, normalised_by)\n",
            "sandbox_tools.processes_view(report, normalised_by)\n",
            "sandbox_tools.api_calls_view(report, self.inputs.sandbox_normalised_by)\n",
            "partial(read_view, tool, report, record.normalised_by)\n",
            "network_from_ledger(ledger, normalised_by=normalised_by_of(container))\n",
            "MalwareReportBuilder(sandbox_normalised_by=held)\n",
            "sandbox_started_positions(report, normalised_by)\n",
            "sandbox_started_positions(report, normalised_by=reading)\n",
            "address_flow_facts(list(entries), normalised_by=normalised_by)\n",
            "pack_block(entries, chars, normalised_by=_normalised_by_of(container))\n",
            "pack_row_heads(ledger, normalised_by=normalised_by_of(container))\n",
        ],
    )
    def test_the_guard_passes_a_reader_the_run_states(self, source: str) -> None:
        assert readers_made_up(source) == []

    def test_the_guard_reads_the_api_too(self) -> None:
        api = [root for root in ROOTS if root.parts[-3:] == ("apps", "api", "app")]
        assert api and any(api[0].rglob("*.py"))

    def test_the_guard_passes_the_entry_point(self) -> None:
        source = (
            "from malspark.providers import sandbox_tools as st\n"
            "from malspark.providers.sandbox_tools import read_view, network_view\n"
            "st.read_view('sandbox_processes', doc, None)\n"
        )
        assert view_reads(source) == []

    @pytest.mark.parametrize(
        "tool", sorted(set(sandbox_tools.DETONATION_READERS) - {sandbox_tools.ITEMS_TOOL})
    )
    def test_each_view_an_agent_is_offered_is_read_through_it(self, tool: str) -> None:
        asked = ("dropped",) if tool == "sandbox_report_section" else ()
        answer = read_view(tool, _document(), TASKS, *asked)

        assert isinstance(answer, dict) and not answer.get("error")


class TestThePackReadsEachViewAsAnAnalystDoes:
    def _pack(self, tmp_path: Path) -> dict[str, Any]:
        from malspark.agents.evidence_recorder import EvidenceRecorder
        from malspark.pipeline.triage_pack import PIPELINE, run_pack
        from malspark.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_triage_pack import _inputs, _write
        from tests.unit.tools.test_binary import _pe

        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        path = _write(tmp_path, "s.exe", _pe())
        result = run_pack(
            recorder,
            _inputs(path, "pe", sandbox_report=_document(), sandbox_normalised_by=TASKS),
        )
        return {e.tool: e for e in result.entries}

    @pytest.mark.parametrize("tool", PACK_VIEWS)
    def test_each_pack_view_answers_as_the_entry_point_does_with_the_run_s_reader(
        self, tool: str, tmp_path: Path
    ) -> None:
        entry = self._pack(tmp_path)[tool]

        assert entry.ok, entry.error
        assert entry.structured == read_view(tool, _document(), TASKS)


class _Container:
    event_sink = None
    detonations: list[Any] = []


def _later() -> list[LedgerEntry]:
    from malspark.pipeline.detonations import platform_reads

    record = DetonationRecord(ordinal=2, origin="agent", report=_document(), normalised_by=TASKS)
    return [LedgerEntry.model_validate(row) for row in platform_reads(_Container(), record, "")]


class TestALaterDetonationIsReadWithItsReader:
    def test_the_pack_s_read_of_a_later_detonation_states_the_guest_path(self) -> None:
        entry = next(e for e in _later() if e.tool == "sandbox_dropped_files")
        row = next(r for r in entry.structured["dropped"] if r["name"] == WRITTEN["name"])

        assert row["path"] == NOTE

    def test_every_view_of_a_later_detonation_is_read(self) -> None:
        read = {e.tool: e for e in _later()}

        assert all(read[tool].ok for tool in PACK_VIEWS), {
            tool: read[tool].error for tool in PACK_VIEWS
        }


class TestThePackAndAnAnalystGiveOneRow:
    def test_the_pack_and_an_analyst_read_of_one_task_give_one_dropped_row(self) -> None:
        pack = next(e for e in _later() if e.tool == "sandbox_dropped_files")
        analyst = build_entry(
            entry_id="ev_0149",
            seq=149,
            agent="dynamic",
            tool="sandbox_dropped_files",
            args={"detonation": "d2"},
            server="pipeline",
            output="{}",
        ).model_copy(update={"structured": read_view("sandbox_dropped_files", _document(), TASKS)})
        dynamic = dynamic_from_ledger([pack, analyst])
        assert dynamic is not None
        names = [op["name"] for op in dynamic.file_operations if op.get("operation") == "write"]

        assert names.count(WRITTEN["name"]) == 1
        assert len(names) == len(set(names))


class TestTheStartedRowsAreReadWithTheRunsReader:
    def test_the_started_rows_are_not_read_without_a_reader(self) -> None:
        with pytest.raises(TypeError):
            sandbox_tools.sandbox_started_positions(_document())  # type: ignore[call-arg]


class TestThePacksOwnReadsOfAViewAreTheRuns:
    def _tools(self, tmp_path: Path, normalised_by: Any) -> dict[str, Any]:
        from tests.unit.pipeline.test_triage_pack import SANDBOX_REPORT, _pack, _write
        from tests.unit.tools.test_binary import _pe

        path = _write(tmp_path, "s.exe", _pe())
        result = _pack(
            path, "pe", sandbox_report=SANDBOX_REPORT, sandbox_normalised_by=normalised_by
        )
        return {e.tool: e for e in result.entries}

    def test_a_process_list_the_reader_never_fills_is_looked_up_for_no_command(
        self, tmp_path: Path
    ) -> None:
        from malspark.core.report_formats import UNREAD_FORMAT

        read = self._tools(tmp_path, ("box", UNREAD_FORMAT))

        assert read["sandbox_processes"].structured.get("absent")
        assert "lolbin_lookup" not in read

    def test_a_process_list_the_reader_fills_is_looked_up(self, tmp_path: Path) -> None:
        read = self._tools(tmp_path, None)

        assert read["lolbin_lookup"].args == {"command_lines": ["rundll32.exe javascript:x"]}


# A capture beside a network view, whose one conversation no flow row holds:
# the capture line's words for it are ``NO_FLOW_ROW``, said only where the
# pack is written with a reader stated.
_FLOWED = "198.51.100.1"
_UNFLOWED = "198.51.100.3"
_RUN_READER = ("box", "box")


def _capture_rows(summary: str = "") -> list[LedgerEntry]:
    from tests.unit.pipeline.test_the_capture_line_says_what_the_sandbox_rows_say_of_each_address import (  # noqa: E501
        _capture,
        _entry,
    )

    capture = _capture(_FLOWED, _UNFLOWED)
    if summary:
        capture["summary"] = summary
    return [
        _entry("sandbox_network", {"tcp": [{"dst": _FLOWED, "dport": 80}]}, 13),
        _entry("pcap_summary", capture, 17),
    ]


def _container(**more: Any) -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(sandbox_normalised=_RUN_READER, config=None, **more)


class TestThePackTextTakesTheRunsReader:
    @pytest.mark.parametrize("for_reporter", [False, True], ids=["agents", "reporter"])
    def test_the_capture_line_of_the_pack_text_says_what_the_view_holds(
        self, for_reporter: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.pipeline import nodes
        from malspark.reporting.ledger_projection import NO_FLOW_ROW

        monkeypatch.setattr(nodes, "upstream_chars", lambda container, reporter=False: 0)
        monkeypatch.setattr(nodes, "earlier_run_text", lambda container, sha: "")
        state: Any = {"evidence_ledger": _capture_rows(), "file_hash": "x"}

        text = nodes.pack_text(state, _container(), for_reporter=for_reporter)

        line = next(line for line in text.splitlines() if line.startswith("[ev_0017]"))
        assert f"; {NO_FLOW_ROW}" in line


class TestTheJudgesPackHeadsTakeTheRunsReader:
    def test_a_head_shown_for_an_entry_shown_whole_says_what_the_view_holds(self) -> None:
        import asyncio
        from unittest.mock import MagicMock

        from malspark.agents.judge_agent import PACK_ROW_SHOWN_BELOW, JudgeAgent
        from malspark.pipeline.triage_pack import PACK_HEADING
        from malspark.reporting.ledger_projection import NO_FLOW_ROW
        from malspark.schemas.isr_models import AgentISR, ClaimEvidence
        from malspark.schemas.stix_models import Bundle

        class _Llm:
            def __init__(self) -> None:
                self.calls: list[list[Any]] = []

            async def ainvoke(self, messages: list[Any]) -> Any:
                self.calls.append(list(messages))
                return MagicMock(content="[]")

        # The capture's stored output is longer than its row, which is longer
        # than its head: the row is pointed below, and shows its head.
        rows = _capture_rows(summary="s" * 6000)
        facts = f"{PACK_HEADING}\n[ev_0017] pcap: {'r' * 3000}"
        claim = ClaimEvidence(
            claim="The sample beacons",
            evidence_ref="[ev_0017]",
            confidence=0.6,
            technique_id="T1071",
        )
        isrs = {"network": AgentISR(agent_id="network", domain="network", claims=[claim])}
        llm = _Llm()
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
        judge._container = _container()

        asyncio.run(
            judge.decide_techniques(
                Bundle.model_validate({"objects": []}),
                isrs,
                reports={"network": "report"},
                evidence_texts={"ev_0017": rows[1].output},
                facts_block=facts,
                run_state="the run state",
                ledger=rows,
            )
        )

        prompt = "\n".join(str(getattr(m, "content", m)) for m in llm.calls[0])
        line = next(line for line in prompt.splitlines() if line.startswith("[ev_0017] pcap"))
        assert PACK_ROW_SHOWN_BELOW in line
        assert f"; {NO_FLOW_ROW}" in line
