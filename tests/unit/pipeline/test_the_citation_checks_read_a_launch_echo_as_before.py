"""The shared echo predicate's second source, the launch text, is read on the publish route only.

A read of a further detonation states its launch text (``launched_with``, and
the end of the launched process's command line). The index the citation
checks and the cited tests read holds no launch (``EntryTexts.launches`` is
empty): such a read holds that text as it always did, and an analyst who
writes what the detonation was launched with, citing the read, is right. The
publish route's index (``EntryTexts.with_launch_echoes``) reads each such read
without it, through the same pair of texts the call's echo is read through.
"""

from __future__ import annotations

import json

from malspark.pipeline.validation import (
    ECHO_FREE_HOLDS_NONE,
    LAUNCH_FIELD,
    EntryTexts,
    _text_holds,
    _without_call_echoes,
    held_only_in_its_echo,
)
from malspark.schemas.evidence import LedgerEntry

LAUNCH = "--dir C:\\Landing\\inbox --tag amber7"
FOLDER = "c:\\landing\\inbox"


def _read(entry_id: str = "ev_0020", launch: str = LAUNCH) -> LedgerEntry:
    answer = {
        "detonation": "d2",
        LAUNCH_FIELD: launch,
        "processes": [
            {"pid": 9, "ppid": 4, "name": "x.exe", "command_line": f"x.exe {launch}"},
            {"pid": 10, "ppid": 9, "name": "cmd.exe", "command_line": "cmd.exe /c ver"},
        ],
    }
    return LedgerEntry(
        id=entry_id,
        tool="sandbox_processes",
        agent="pipeline",
        source="pack",
        output=json.dumps(answer),
        structured=answer,
    )


def _held(text: str) -> bool:
    return _text_holds(text, FOLDER)


class TestTheCitationChecksIndex:
    def test_it_holds_no_launch(self) -> None:
        assert EntryTexts.from_ledger([_read()]).launches == {}

    def test_a_read_holds_its_launch_text_as_before(self) -> None:
        entries = EntryTexts.from_ledger([_read()])
        assert entries.holds("ev_0020", FOLDER)
        assert held_only_in_its_echo(entries, "ev_0020", _held, [FOLDER]) == ""
        assert all(whole == rest for whole, rest in entries.echo_free_parts("ev_0020"))


class TestThePublishRouteIndex:
    def test_it_holds_the_read_s_detonation_and_launch_text(self) -> None:
        entries = EntryTexts.from_ledger([_read()]).with_launch_echoes()
        assert entries.launch_of("ev_0020") == ("d2", LAUNCH)

    def test_a_value_only_the_launch_text_holds_is_held_only_in_an_echo(self) -> None:
        entries = EntryTexts.from_ledger([_read()]).with_launch_echoes()
        assert held_only_in_its_echo(entries, "ev_0020", _held, [FOLDER]) == ECHO_FREE_HOLDS_NONE

    def test_without_the_launch_source_it_reads_as_the_citation_checks_do(self) -> None:
        entries = EntryTexts.from_ledger([_read()]).with_launch_echoes()
        plain = EntryTexts.from_ledger([_read()])
        assert entries.echo_free_parts("ev_0020", launch=False) == plain.echo_free_parts("ev_0020")
        assert held_only_in_its_echo(entries, "ev_0020", _held, [FOLDER], launch=False) == ""


class TestWhatStatesTheLaunchText:
    def test_the_field_and_the_command_line_s_end_are_taken_out(self) -> None:
        text = _read().output or ""
        rest = json.loads(_without_call_echoes(text, None, launch=LAUNCH))
        assert LAUNCH_FIELD not in rest
        assert [row["command_line"] for row in rest["processes"]] == ["x.exe", "cmd.exe /c ver"]

    def test_the_comparison_folds_case(self) -> None:
        text = _read().output or ""
        rest = json.loads(_without_call_echoes(text, None, launch=LAUNCH.upper()))
        assert LAUNCH_FIELD not in rest

    def test_a_field_stating_another_launch_text_stays(self) -> None:
        text = _read(launch="--tag amber7").output or ""
        rest = json.loads(_without_call_echoes(text, None, launch=LAUNCH))
        assert rest[LAUNCH_FIELD] == "--tag amber7"
        assert rest["processes"][0]["command_line"] == "x.exe --tag amber7"

    def test_a_command_line_ending_in_a_longer_word_keeps_it(self) -> None:
        answer = {
            "processes": [{"pid": 9, "ppid": 4, "command_line": "x.exe x--tag amber7"}],
        }
        rest = json.loads(_without_call_echoes(json.dumps(answer), None, launch="--tag amber7"))
        assert rest["processes"][0]["command_line"] == "x.exe x--tag amber7"

    def test_a_row_with_no_parent_is_no_process_row(self) -> None:
        answer = {"config": {"pid": 9, "command_line": f"x.exe {LAUNCH}"}}
        rest = json.loads(_without_call_echoes(json.dumps(answer), None, launch=LAUNCH))
        assert rest["config"]["command_line"] == f"x.exe {LAUNCH}"
