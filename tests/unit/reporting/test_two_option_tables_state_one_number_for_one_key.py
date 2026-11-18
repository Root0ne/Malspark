"""Rows of the two option tables that name one option and cite one entry state one number per key.

The commands table and the command-line flags table are written apart, at
once, and both may list one option. Where a commands row and a flags row name
the same option (its case kept: ``-t`` is not ``-T``) and cite a common entry,
a key both rows state a number for (a hex constant, a configuration name) must
carry the same numbers in both. Where it does not, the code cannot tell which
row is right: each section is asked once, shown both rows and the common
entry, and may correct its own row. A section that already spent its one
retry on other findings is not asked again: the finding is recorded
unresolved, not asked. Nothing is marked or left out.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from malspark.pipeline.validation import (
    ASKED_BY_VALUE,
    KEPT_WITH_A_FINDING,
    MARKED_IN_PLACE,
    OPTION_NUMBERS_DIFFER_CODE,
    feedback_text,
    option_number_violations,
)
from malspark.reporting.models import (
    CliFlag,
    CommandRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)

COMMAND = {
    "id": "-wirelog",
    "name": "-wirelog",
    "description": "Sets key 0x5c to 3 for -wirelog or 4 for -wirerawlog.",
    "evidence_refs": ["ev_0110"],
}
FLAG = {
    "flag": "-wirelog",
    "description": "Takes a log file name and stores it at key 0x5b, with log mode 4 at key 0x5c.",
    "evidence_ref": "ev_0110",
}


def _found(commands: list[dict[str, Any]], flags: list[dict[str, Any]]) -> list[Any]:
    return option_number_violations(commands, flags)


class TestTheCheck:
    def test_one_key_with_other_numbers_in_the_two_rows_is_asked_of_both_sections(
        self,
    ) -> None:
        found = _found([COMMAND], [FLAG])

        assert [v.code for v in found] == [OPTION_NUMBERS_DIFFER_CODE] * 2
        assert [v.path for v in found] == ["commands.0", "flags.0"]
        assert all(v.values == ("0x5c",) for v in found)

    def test_the_same_numbers_ask_nothing(self) -> None:
        flag = {
            **FLAG,
            "description": "Takes a log file name; sets key 0x5c to 3 here or 4 for -wirerawlog.",
        }

        assert _found([COMMAND], [flag]) == []

    def test_an_option_of_another_case_is_another_option(self) -> None:
        flag = {**FLAG, "flag": "-Wirelog"}

        assert _found([COMMAND], [flag]) == []

    def test_rows_citing_no_common_entry_ask_nothing(self) -> None:
        flag = {**FLAG, "evidence_ref": "ev_0111"}

        assert _found([COMMAND], [flag]) == []

    def test_a_number_in_another_clause_is_not_the_key_s(self) -> None:
        flag = {
            **FLAG,
            "description": "Stores the name at key 0x5c; the mode the log is written in is 4.",
        }

        assert _found([{**COMMAND, "description": "Sets key 0x5c to 3."}], [flag]) == []

    def test_its_code_is_kept_with_a_finding_only(self) -> None:
        assert OPTION_NUMBERS_DIFFER_CODE in KEPT_WITH_A_FINDING
        assert OPTION_NUMBERS_DIFFER_CODE not in MARKED_IN_PLACE
        assert OPTION_NUMBERS_DIFFER_CODE not in ASKED_BY_VALUE


class TestTheFindingAndItsQuestion:
    def test_the_message_states_the_fact(self) -> None:
        commands, flags = _found([COMMAND], [FLAG])

        fact = (
            "commands row 1 (-wirelog) and command-line flags row 1 (-wirelog) both name "
            "-wirelog and cite ev_0110, and state different numbers for 0x5c: 3, 4 in the "
            "commands row, 4 in the command-line flags row."
        )
        assert commands.message == fact
        assert flags.message == fact

    def test_each_section_is_shown_both_rows_and_the_entry_and_corrects_its_own(self) -> None:
        commands, flags = _found([COMMAND], [FLAG])

        assert commands.shown == (
            "Your commands row reads: '-wirelog: -wirelog. Sets key 0x5c to 3 for -wirelog or 4 "
            "for -wirerawlog.'. The command-line flags row reads: '-wirelog. Takes a log file "
            "name and stores it at key 0x5b, with log mode 4 at key 0x5c.'. Read ev_0110 again: "
            "where it shows another number for 0x5c than your row states, correct your row; "
            "where your row is right, keep it as written."
        )
        assert flags.shown.startswith("Your command-line flags row reads: '-wirelog. Takes")
        assert "The commands row reads: '-wirelog: -wirelog. Sets key" in flags.shown
        assert commands.shown in feedback_text([commands])
        assert "Read ev_0110" not in commands.message


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            commands=[CommandRow(**COMMAND)], cli_flags=[CliFlag(**FLAG)]
        ),
    )


class _RawLLM:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=self._answers.pop(0))


def _flags_answer(description: str) -> str:
    return json.dumps({"flags": [{**FLAG, "description": description}]})


def _commands_answer(description: str) -> str:
    return json.dumps({"commands": [{**COMMAND, "description": description}]})


def _compose_both(commands: list[str], flags: list[str]) -> tuple[_RawLLM, MalwareReport, Any]:
    """Both tables written through the manual path by one model, then read together.

    The model answers in the order it is asked: the commands table, the flags
    table and its own retry where ``flags`` holds three answers, then the
    question each section is asked once both are written.
    """
    from langchain_core.messages import HumanMessage

    from malspark.reporting.composer import ReportComposer, _CliFlagsOut, _CommandsOut

    report = _report()
    ta = report.technical_analysis
    assert ta is not None
    first_commands, *later_commands = commands
    first_flags, *later_flags = flags
    order = [first_commands, first_flags]
    if len(later_flags) > 1:
        order.append(later_flags.pop(0))
    order.extend([*later_commands, *later_flags])
    llm = _RawLLM(*order)
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    comp._report = report
    comp._entries = None
    comp._citable = ["ev_0110", "ev_0111"]
    comp._turn_left = {}

    def _apply(section: str, out: Any) -> None:
        if section == "commands":
            ta.commands = list(out.commands)
        else:
            ta.cli_flags = list(out.flags)

    async def _run() -> None:
        with patch(
            "malspark.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            for schema, section in ((_CommandsOut, "commands"), (_CliFlagsOut, "cli_flags")):
                out = await comp._invoke(
                    [HumanMessage(content=f"write {section}")], schema, section=section
                )
                _apply(section, out)
            await comp._tables_read_together(ta, _apply)

    asyncio.run(_run())
    return llm, report, comp


def _sent_to(llm: _RawLLM, section: str) -> list[list[Any]]:
    return [turns for turns in llm.sent if f"write {section}" in str(turns[0].content)]


class TestTheComposer:
    def test_each_section_is_asked_once_and_its_corrected_row_stands(self) -> None:
        fixed = (
            "Stores the log file name at key 0x5b; sets key 0x5c to 3 here or 4 for -wirerawlog."
        )
        llm, report, comp = _compose_both(
            [_commands_answer(COMMAND["description"]), _commands_answer(COMMAND["description"])],
            [_flags_answer(FLAG["description"]), _flags_answer(fixed)],
        )

        commands, flags = _sent_to(llm, "commands"), _sent_to(llm, "cli_flags")
        assert len(commands) == 2 and len(flags) == 2
        assert "[report.option_numbers_differ]" in str(commands[1][-1].content)
        assert "Your commands row reads" in str(commands[1][-1].content)
        assert "Your command-line flags row reads" in str(flags[1][-1].content)
        ta = report.technical_analysis
        assert ta is not None and ta.cli_flags[0].description == fixed
        assert not [
            row
            for row in comp.validation_tally.unresolved
            if row["code"] == OPTION_NUMBERS_DIFFER_CODE
        ]

    def test_a_kept_row_is_recorded_unresolved_as_asked(self) -> None:
        _llm, _report_, comp = _compose_both(
            [_commands_answer(COMMAND["description"]), _commands_answer(COMMAND["description"])],
            [_flags_answer(FLAG["description"]), _flags_answer(FLAG["description"])],
        )

        rows = [
            row
            for row in comp.validation_tally.unresolved
            if row["code"] == OPTION_NUMBERS_DIFFER_CODE
        ]
        assert sorted(row["agent"] for row in rows) == ["composer:cli_flags", "composer:commands"]
        assert all(row.get("asked") != "false" for row in rows)

    def test_a_section_that_spent_its_retry_is_not_asked_again(self) -> None:
        # The flags section's first answer cites an id the run did not issue: its one
        # retry goes to that question, and the option question is recorded, not asked.
        stray = json.dumps({"flags": [{**FLAG, "evidence_ref": "ev_0110, ev_0999"}]})
        llm, _report_, comp = _compose_both(
            [_commands_answer(COMMAND["description"]), _commands_answer(COMMAND["description"])],
            [stray, _flags_answer(FLAG["description"]), _flags_answer("never asked for")],
        )

        commands, flags = _sent_to(llm, "commands"), _sent_to(llm, "cli_flags")
        assert len(commands) == 2
        assert len(flags) == 2
        assert all("[report.option_numbers_differ]" not in str(t[-1].content) for t in flags)
        rows = {
            row["agent"]: row
            for row in comp.validation_tally.unresolved
            if row["code"] == OPTION_NUMBERS_DIFFER_CODE
        }
        assert rows["composer:cli_flags"]["asked"] == "false"
        assert rows["composer:commands"].get("asked") != "false"
