"""Which process runs the submitted file reads a command line word by word.

The lineage check names a process the sample's where a word of its command
line, split at spaces and commas, is the file the sample was submitted as.
A reading that joined the words of an unquoted path up to the first file name
swallowed a program written without its extension together with its
arguments (``C:\\Windows\\system32\\cmd /c sample.exe``), and the process that
ran the sample was no longer the sample's. The check reads every command line
as it always has; the rule drafter's own reading of a path is its own.
"""

from __future__ import annotations

import pytest

from malspark.schemas.sandbox_report import runs_the_submitted_file


@pytest.mark.parametrize(
    ("command_line", "name"),
    [
        ("C:\\Windows\\system32\\cmd /c sample.exe", "sample.exe"),
        ("C:\\Windows\\System32\\rundll32 sample.dll,#1", "sample.dll"),
        ("C:\\Windows\\system32\\regsvr32 /s sample.dll", "sample.dll"),
        ("%windir%\\System32\\wscript //B sample.vbs", "sample.vbs"),
    ],
)
def test_a_program_written_without_its_extension_runs_the_file_it_names(
    command_line: str, name: str
) -> None:
    assert runs_the_submitted_file("", command_line, name, "") is True


def test_an_unquoted_path_with_a_space_is_read_word_by_word() -> None:
    # Each word is a file name of its own, as the check always read it.
    command_line = "C:\\Program Files\\x\\svc host.exe /s"

    assert runs_the_submitted_file("", command_line, "host.exe", "") is True
    assert runs_the_submitted_file("", command_line, "svc host.exe", "") is False


def test_a_quoted_path_with_a_space_is_read_word_by_word_too() -> None:
    command_line = '"C:\\Program Files\\x\\svc host.exe" /s'

    assert runs_the_submitted_file("", command_line, "host.exe", "") is True
