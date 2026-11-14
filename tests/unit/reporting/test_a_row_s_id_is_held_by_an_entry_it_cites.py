"""A table row's id is held by an entry the row cites.

A command row states the id the operator sends and cites entries, and nothing
compared that id with what the cited entries hold. The rule: a number is held
by a cited entry whose text writes it as a compared operand (an equality test,
a case label, a compare instruction), any other id by a cited entry whose text
writes it whole. A number none of its cited
entries holds is asked about only with the entry whose one compared expression
holds the most of the table's numbers, and not when a cited entry is code the
reader cannot read; any other id with every entry that writes it. A row kept
after the question is marked beside its evidence.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from malspark.pipeline.validation import (
    ASKED_BY_VALUE,
    ID_NOT_IN_CITED_ENTRY_CODE,
    KEPT_WITH_A_FINDING,
    MARKED_IN_PLACE,
    EntryTexts,
    cited_id_violations,
    record_flagged_statements,
)
from malspark.reporting.composer import ReportComposer, _CommandsOut
from malspark.reporting.models import (
    CommandRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.schemas.evidence import LedgerEntry
from tests.credential_shapes import prefixed_key
from tests.linear_cost import assert_scales

DISPATCHER = (
    "void dispatch(int param_2) {\n"
    "  switch (param_2) {\n"
    "  case 2: run_shell(); break;\n"
    "  case 0xc: upload(); break;\n"
    "  case 0x15: uninstall(); break;\n"
    "  }\n"
    "}\n"
)
HANDLER = "void upload(void) {\n  WriteFile(h, buf, n, &w, 0);\n}\n"


def _entry(entry_id: str, tool: str, output: str, *, truncated: bool = False) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent="pipeline", server="pipeline", tool=tool, output=output,
        truncated=truncated,
    )  # fmt: skip


def _texts(*, partial: bool = False) -> EntryTexts:
    # The code is stored as JSON, its line breaks escaped, as a tool's answer is.
    return EntryTexts.from_ledger(
        [
            _entry("ev_0010", "batch_decompile", json.dumps({"code": DISPATCHER})),
            _entry("ev_0011", "decompile_function", json.dumps({"code": HANDLER})),
            _entry("ev_0012", "strings", json.dumps({"strings": ["ERROR", "OK"]})),
            _entry(
                "ev_0013",
                "decompile_function",
                json.dumps({"code": "int f(void) {\n  return g(1);\n}\n"}),
                truncated=partial,
            ),
        ]
    )


def _commands(*rows: tuple[str, list[str]]) -> dict[str, Any]:
    return {
        "commands": [
            {"id": written, "name": f"command {written}", "evidence_refs": refs}
            for written, refs in rows
        ]
    }


def _table(first: tuple[str, list[str]]) -> dict[str, Any]:
    """``first`` as row 1 of a table whose other rows the dispatcher holds."""
    return _commands(first, ("2", ["ev_0010"]), ("0x15", ["ev_0010"]))


class TestANumberedId:
    def test_an_id_the_cited_code_compares_stands(self) -> None:
        assert cited_id_violations(_commands(("0xc", ["ev_0010"])), _texts()) == []

    def test_an_id_only_another_entry_s_code_compares_is_asked_naming_it(self) -> None:
        (found,) = cited_id_violations(_table(("0xc", ["ev_0011"])), _texts())

        assert found.code == ID_NOT_IN_CITED_ENTRY_CODE == "report.id_not_in_cited_entry"
        assert "Row 1 of commands" in found.message
        assert "ev_0010 (batch_decompile)" in found.message
        assert found.path == "commands.id"

    def test_an_id_read_as_its_last_word_and_in_any_base(self) -> None:
        payload = _commands(
            ("COMMAND 21", ["ev_0011"]), ("COMMAND 012", ["ev_0010"]), ("COMMAND 2", ["ev_0010"])
        )

        (found,) = cited_id_violations(payload, _texts())

        # 21 is 0x15, compared by ev_0010; 012 is octal 10, compared by none.
        assert found.message.startswith("Row 1 of commands")

    def test_rows_one_entry_holds_are_asked_together(self) -> None:
        payload = _commands(("2", ["ev_0011"]), ("0xc", ["ev_0012"]), ("0x15", ["ev_0010"]))

        (found,) = cited_id_violations(payload, _texts())

        assert found.message.startswith("Rows 1, 2 of commands")
        assert len(found.quoted) == 2

    def test_an_id_no_entry_s_code_compares_is_not_asked_here(self) -> None:
        assert cited_id_violations(_commands(("0x99", ["ev_0011"])), _texts()) == []

    def test_a_number_written_in_the_text_and_compared_by_no_code_is_not_held(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "strings", json.dumps({"strings": ["12"]})),
                _entry("ev_0002", "batch_decompile", json.dumps({"code": DISPATCHER})),
            ]
        )

        (found,) = cited_id_violations(
            _commands(("12", ["ev_0001"]), ("2", ["ev_0002"]), ("0x15", ["ev_0002"])), texts
        )

        assert "ev_0002" in found.message


class TestAnyOtherId:
    def test_an_id_a_cited_entry_writes_whole_stands(self) -> None:
        assert cited_id_violations(_commands(("ERROR", ["ev_0012"])), _texts()) == []

    def test_an_id_only_another_entry_writes_is_asked_naming_it(self) -> None:
        (found,) = cited_id_violations(_commands(("ERROR", ["ev_0011"])), _texts())

        assert "ev_0012 (strings)" in found.message

    def test_a_label_no_entry_writes_is_not_asked_here(self) -> None:
        assert cited_id_violations(_commands(("net_view", ["ev_0011"])), _texts()) == []


# A dispatcher on the command (4, 5, 6), and a runtime function whose small
# switch also has a case 4: it merely contains the number.
COMMAND_SWITCH = (
    "void on_command(int cmd) {\n"
    "  switch (cmd) {\n"
    "  case 4: download(); break;\n"
    "  case 5: upload(); break;\n"
    "  case 6: run(); break;\n"
    "  }\n"
    "}\n"
)
RUNTIME_SWITCH = (
    "int _setmode(int fd, int m) {\n"
    "  switch (m) {\n"
    "  case 0: a(); break;\n"
    "  case 1: b(); break;\n"
    "  case 2: c(); break;\n"
    "  case 4: d(); break;\n"
    "  }\n"
    "  return 0;\n"
    "}\n"
)


def _ledger(cited: str, *, tool: str = "decompile_function", dispatcher: bool = True) -> EntryTexts:
    entries = [
        _entry("ev_0001", tool, json.dumps({"code": cited})),
        _entry("ev_0002", "decompile_function", json.dumps({"code": RUNTIME_SWITCH})),
    ]
    if dispatcher:
        entries.append(
            _entry("ev_0003", "decompile_function", json.dumps({"code": COMMAND_SWITCH}))
        )
    return EntryTexts.from_ledger(entries)


def _rows(first: str, label: str = "") -> dict[str, Any]:
    return _commands((first, ["ev_0001"]), (f"{label}5", ["ev_0003"]), (f"{label}6", ["ev_0003"]))


class TestACitedEntryHoldsANumberItComparesInAnyForm:
    @pytest.mark.parametrize(
        "code",
        [
            "void handler(int cmd) {\n  if (cmd == 4) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == 0x4) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (4 == cmd) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd != 4) {\n    return;\n  }\n  download();\n}\n",
            "void handler(int cmd) {\n  switch (cmd >> 1) {\n  case 4:\n    download();\n  }\n}\n",
            "cmp eax, 4\njz 0x401000\ncmp eax, 9\njz 0x401100",
            "CMP dword ptr [EBP + -0x8],0x4\nJZ LAB_00401000",
            "0040100a  83 f8 04  cmp eax, 4h\n0040100d  74 10     je 0x40101f",
        ],
    )
    @pytest.mark.parametrize(
        ("written", "label"), [("4", ""), ("0x4", ""), ("04", ""), ("COMMAND 4", "COMMAND ")]
    )
    def test_the_row_stands(self, code: str, written: str, label: str) -> None:
        assert cited_id_violations(_rows(written, label), _ledger(code)) == []

    @pytest.mark.parametrize(
        "code",
        [
            "void handler(int cmd) {\n  if (cmd == 14) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == 0x40) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == 4096) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == -4) {\n    download();\n  }\n}\n",
            "void handler(int cmd) {\n  if (cmd == 4 + base) {\n    download();\n  }\n}\n",
            "cmp eax, 40h\njz 0x401000\ncmp eax, 9\njz 0x401100",
        ],
    )
    def test_a_number_that_is_not_the_whole_operand_is_not_held(self, code: str) -> None:
        (found,) = cited_id_violations(_rows("4"), _ledger(code))

        assert "ev_0003 (decompile_function)" in found.message

    def test_readable_code_comparing_other_values_is_asked(self) -> None:
        code = "void handler(int cmd) {\n  if (cmd == 9) {\n    download();\n  }\n}\n"

        (found,) = cited_id_violations(_rows("4"), _ledger(code))

        assert found.message.startswith("Row 1 of commands states the id '4'")

    def test_code_the_reader_cannot_read_is_never_asked_about(self) -> None:
        # Declared code, in no form the reader knows: a doubt is silence.
        code = "MATCH cmd WITH\n| 4 -> download\n| 5 -> upload"

        assert cited_id_violations(_rows("4"), _ledger(code)) == []
        assert cited_id_violations(_rows("4"), _ledger(code, tool="disassemble_function")) == []


class TestWhatIsNotAsked:
    def test_a_row_citing_no_entry_with_text_or_nothing(self) -> None:
        payload = _commands(("0xc", ["ev_0999"]), ("0xc", []), ("", ["ev_0011"]))

        assert cited_id_violations(payload, _texts()) == []

    def test_a_row_citing_a_partial_entry(self) -> None:
        payload = _table(("0xc", ["ev_0011", "ev_0013"]))

        assert cited_id_violations(payload, _texts(partial=True)) == []
        assert cited_id_violations(payload, _texts()) != []

    def test_without_the_entries_nothing_is_judged(self) -> None:
        assert cited_id_violations(_commands(("0xc", ["ev_0011"])), None) == []
        assert cited_id_violations(None, _texts()) == []

    def test_odd_rows_raise_nothing(self) -> None:
        payload = {
            "commands": [None, "row", {"id": 7, "evidence_refs": "ev_0011"}, {"id": None}],
            "Odd Key": [{"id": "0xc", "evidence_refs": ["ev_0011"]}],
            "flags": {"not": "a list"},
        }

        assert cited_id_violations(payload, _texts()) == []


class TestTheFindingIsKeptAndMarked:
    def test_the_code_is_kept_marked_and_asked_by_value(self) -> None:
        assert ID_NOT_IN_CITED_ENTRY_CODE in KEPT_WITH_A_FINDING
        assert ID_NOT_IN_CITED_ENTRY_CODE in MARKED_IN_PLACE
        assert ID_NOT_IN_CITED_ENTRY_CODE in ASKED_BY_VALUE

    def test_the_message_never_carries_a_secret(self) -> None:
        secret = prefixed_key("ghs_")
        texts = EntryTexts.from_ledger(
            [
                _entry("ev_0001", "strings", json.dumps({"strings": [f"token={secret}"]})),
                _entry("ev_0002", "strings", json.dumps({"strings": ["other"]})),
            ]
        )

        (found,) = cited_id_violations(_commands((f"token={secret}", ["ev_0002"])), texts)

        assert secret not in found.message

    def test_a_kept_row_is_marked_beside_its_evidence(self) -> None:
        rows = [
            CommandRow(id="0xc", name="upload", evidence_refs=["ev_0011"]),
            CommandRow(id="0x15", name="uninstall", evidence_refs=["ev_0010"]),
        ]
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            technical_analysis=TechnicalAnalysis(commands=rows),
        )
        payload = {"commands": [row.model_dump() for row in rows]}
        record_flagged_statements(report, cited_id_violations(payload, _texts()))

        text = MarkdownRenderer().render(report)

        upload = next(line for line in text.splitlines() if "| upload" in line)
        assert "an id none of its cited entries holds" in upload
        assert "ev_0010 (batch_decompile) holds it" in upload
        uninstall = next(line for line in text.splitlines() if "| uninstall" in line)
        assert "cited entries holds" not in uninstall


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


class TestTheComposer:
    def test_compose_puts_the_check_on_the_command_table(self) -> None:
        seen: dict[str, list[Any]] = {}

        async def _author(self: Any, section: str, *args: Any, validators: Any = None) -> None:
            seen[section] = list(validators or [])

        comp = ReportComposer(llm=_RawLLM(), per_section_timeout=5)  # type: ignore[arg-type]
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), verdict="Malware"
        )
        with patch.object(ReportComposer, "_author", _author):
            asyncio.run(comp.compose(report, evidence=_texts()))

        found = [v for check in seen["commands"] for v in check(_table(("0xc", ["ev_0011"])))]
        assert ID_NOT_IN_CITED_ENTRY_CODE in [v.code for v in found]

    def test_a_row_the_model_fixes_is_taken(self) -> None:
        from langchain_core.messages import HumanMessage

        wrong = json.dumps(_table(("0xc", ["ev_0011"])))
        right = json.dumps(_table(("0xc", ["ev_0010", "ev_0011"])))
        llm = _RawLLM(wrong, right)
        comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
        comp._entries = _texts()
        comp._citable = ["ev_0010", "ev_0011", "ev_0012", "ev_0013"]
        comp._report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), verdict="Malware"
        )
        with patch(
            "malspark.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            result = asyncio.run(
                comp._invoke(
                    [HumanMessage(content="write it")],
                    _CommandsOut,
                    section="commands",
                    validators=[lambda p: cited_id_violations(p, comp._entries)],
                )
            )

        assert len(llm.sent) == 2
        assert "ev_0010 (batch_decompile)" in str(llm.sent[1][-1].content)
        assert result is not None and result.commands[0].evidence_refs == ["ev_0010", "ev_0011"]
        assert comp.validation_tally.unresolved == []


def test_the_cost_grows_with_the_rows_and_the_entries_together() -> None:
    """Each entry's code is read once and each row looks its id up: no row reads every entry."""

    def build(size: int) -> Any:
        entries = [
            _entry(
                f"ev_{n:05d}",
                "decompile_function",
                json.dumps(
                    {"code": f"switch (p) {{ case {n}: a(); break; case {n + 1}: b(); break; }}"}
                ),
            )
            for n in range(1, size + 1)
        ]
        payload = _commands(*((str(n + 2), [f"ev_{n:05d}"]) for n in range(1, size + 1)))

        def call() -> list[Any]:
            return cited_id_violations(payload, EntryTexts.from_ledger(entries))

        return call

    assert_scales(build, 300)
