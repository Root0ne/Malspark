"""A cited command line's argument holds a value; a refusal says what the one scan found (T-866).

A name, a folder or a file name is held where it is one whole argument of a
process command line a cited entry records in the platform's sandbox document
(a process row: one object stating its process id, its parent's id and its
command line under the document's own fields), arguments split as Windows
splits them, a quoted part one argument. Part of an argument is not held, and a
value between spaces anywhere else (a signature's description, a strings entry,
prose, an object with an id and a command line and no parent) is not held.

A row no cited entry holds whole is refused with what the same scan found: its
text only inside a longer run of letters or digits; only between spaces, which
this check does not count as a value's ends; somewhere else this check does not
count as the whole value; and the earlier words only where no cited entry holds
its text in any spelling. A row citing more entries than the check reads says
the count read and the count cited. A row whose record holds no word of what the
scan found (a report stored before it recorded one) says only what its record
holds. One scan writes ``held_in`` and the words, and every surface prints the
one answer.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.builder import build_consolidated_iocs, full_ioc_list
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.stix_renderer import publishes
from malspark.reporting.stated_host_values import (
    AS_BYTES,
    BETWEEN_SPACES,
    INSIDE_A_LONGER_RUN,
    MAX_CITED,
    NOT_IN_THE_CITED,
    NOT_IN_THE_READ,
    NOT_RECORDED_AS_HELD,
    NOT_WHOLE,
    NOWHERE,
    ONLY_IN_ITS_CALL,
    ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE,
    READ_OF_THE_CITED,
    UNHELD_WORDS,
    command_line_arguments,
    identifier_answers,
    scan_cited,
    with_held_in,
)
from malspark.schemas.sandbox_report import SandboxProcess, SandboxReport

TASK = "NightlyRefresh7731"
FOLDER = "C:\\Staging7731"


def _document(*lines: str) -> str:
    """A sandbox entry's text: the platform's own sandbox document, as the ledger keeps it."""
    from malspark.schemas.sandbox_document import sandbox_document

    report = SandboxReport(
        provider="example",
        source_format="example",
        processes=[
            SandboxProcess(pid=400 + at, ppid=88, name="example7731.exe", command_line=line)
            for at, line in enumerate(lines)
        ],
    )
    return json.dumps({"launched_with": f"--path {FOLDER}", **sandbox_document(report)}).lower()


def _row(kind: str, value: str) -> HostIdentifier:
    return HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=["ev_0001"])


def _scan(kind: str, value: str, text: str) -> Any:
    return scan_cited(EntryTexts(texts={"ev_0001": text}), _row(kind, value))


class TestAWholeArgumentOfARecordedCommandLine:
    @pytest.mark.parametrize(
        ("kind", "value", "line"),
        [
            ("scheduled task", TASK, f"schtasks /Create /SC ONSTART /TN {TASK} /TR x.exe"),
            ("scheduled task", TASK, f"schtasks /Delete /TN {TASK} /F"),
            ("folder", FOLDER, f"icacls {FOLDER} /grant users:r"),
            ("folder", FOLDER, f"icacls  {FOLDER}  /grant x"),
            ("folder", "C:\\My Data7731", 'icacls "C:\\My Data7731" /grant x'),
            ("file name", "note7731.txt", 'example7731.exe "note7731.txt"'),
            ("service", "ExampleSvc7731", "sc start ExampleSvc7731"),
        ],
    )
    def test_is_held(self, kind: str, value: str, line: str) -> None:
        scan = _scan(kind, value, _document(line))

        assert scan.held == ("ev_0001",)
        assert scan.unheld_as == ""

    @pytest.mark.parametrize(
        ("kind", "value", "line", "found"),
        [
            # Part of an argument: a letter runs on.
            ("scheduled task", TASK, f"schtasks /TN {TASK}X /F", INSIDE_A_LONGER_RUN),
            # Part of an argument: a further component of a path.
            ("folder", FOLDER, f"icacls {FOLDER}\\sub /grant x", NOT_WHOLE),
            # Part of a quoted argument, between spaces inside it.
            ("scheduled task", TASK, f'schtasks /TN "my {TASK} task" /F', NOT_WHOLE),
        ],
    )
    def test_part_of_an_argument_is_not_held(
        self, kind: str, value: str, line: str, found: str
    ) -> None:
        scan = _scan(kind, value, _document(line))

        assert scan.held == ()
        assert scan.unheld_as == found

    def test_the_launch_argument_beside_the_rows_is_no_command_line(self) -> None:
        # The document's launch argument is recorded beside the process rows.
        assert _scan("folder", FOLDER, _document("cmd /c ver")).held == ()

    def test_a_command_line_field_outside_a_process_row_is_none(self) -> None:
        text = json.dumps({"rows": [{"command_line": f"icacls {FOLDER} /grant x"}]}).lower()

        assert command_line_arguments(text) == ()
        assert _scan("folder", FOLDER, text).held == ()

    def test_a_tool_nobody_declared_holding_process_rows_is_read_at_full_strength(self) -> None:
        # No tool is named: a process row under the document's fields is read
        # wherever it stands in an answer, under the source's own arrangement too.
        row = {"process_id": 7, "parent_id": 3, "environ": {"CommandLine": f"x {TASK}"}}
        text = json.dumps({"answer": {"items": [row]}}).lower()

        assert _scan("scheduled task", TASK, text).held == ("ev_0001",)

    @pytest.mark.parametrize(
        "document",
        [
            # A configuration's own entries, parsed out of a file: an id and a
            # command line, no parent.
            {"config": {"tasks": [{"pid": 0, "cmd": f"persist {TASK}"}]}},
            # A tool's echo of the arguments it was called with.
            {"called_with": {"pid": 4, "cmd": f"note {TASK} here"}, "result": "ok"},
        ],
    )
    def test_an_object_with_an_id_and_a_command_line_and_no_parent_is_no_process_row(
        self, document: dict[str, Any]
    ) -> None:
        text = json.dumps(document).lower()

        assert command_line_arguments(text) == ()
        assert _scan("scheduled task", TASK, text).held == ()

    @pytest.mark.parametrize(
        ("line", "arguments"),
        [
            ('a "b c" d', ("a", "b c", "d")),
            ('a \\"b c\\" d', ("a", '"b', 'c"', "d")),
            ('a "b \\\\" c', ("a", "b \\", "c")),
            ('"c:\\program files\\x.exe" -y', ("c:\\program files\\x.exe", "-y")),
            ('a "b ""c"" d"', ("a", 'b "c" d')),
            ("  a\tb  ", ("a", "b")),
        ],
    )
    def test_arguments_are_split_as_windows_splits_them(
        self, line: str, arguments: tuple[str, ...]
    ) -> None:
        text = json.dumps([{"pid": 1, "ppid": 0, "command_line": line}])

        assert command_line_arguments(text) == (arguments,)


class TestARefusalSaysWhatTheScanFound:
    @pytest.mark.parametrize(
        ("text", "found"),
        [
            # A string pool written with no separator.
            (json.dumps({"strings": [f"closed{TASK}backup"]}).lower(), INSIDE_A_LONGER_RUN),
            # A value at the end of a longer run.
            (json.dumps({"strings": [f"x{TASK}"]}).lower(), INSIDE_A_LONGER_RUN),
            # A signature's description, between spaces.
            (
                json.dumps({"name": "x", "description": f"creates task {TASK} at boot"}).lower(),
                BETWEEN_SPACES,
            ),
            # A strings entry, between spaces.
            (json.dumps({"strings": [{"text": f"run {TASK} now"}]}).lower(), BETWEEN_SPACES),
            # A full stop after it: neither a run nor two spaces.
            (json.dumps({"strings": [f"{TASK}."]}).lower(), NOT_WHOLE),
            # A space at one end only.
            (json.dumps({"strings": [f"{TASK} now"]}).lower(), NOT_WHOLE),
            # Not there in any spelling.
            (json.dumps({"strings": ["OtherMarker"]}).lower(), NOWHERE),
        ],
    )
    def test_the_finding(self, text: str, found: str) -> None:
        scan = _scan("scheduled task", TASK, text)

        assert scan.held == ()
        assert scan.unheld_as == found

    def test_an_entry_holding_it_only_in_a_run_beside_one_between_spaces(self) -> None:
        entries = EntryTexts(
            texts={
                "ev_0001": json.dumps([f"pool{TASK}pool"]).lower(),
                "ev_0002": json.dumps([f"run {TASK} now"]).lower(),
            }
        )
        row = HostIdentifier(
            kind="scheduled task",
            value=TASK,
            use="creates/writes",
            evidence_refs=["ev_0001", "ev_0002"],
        )

        assert scan_cited(entries, row).unheld_as == INSIDE_A_LONGER_RUN

    def test_the_words(self) -> None:
        assert UNHELD_WORDS == {
            ONLY_IN_ITS_CALL: (
                "a cited entry holds it whole only where its answer repeats what its call asked for"
            ),
            ONLY_IN_ITS_CALL_ELSEWHERE_INSIDE: (
                "a cited entry holds it whole only where its answer repeats what its call asked "
                "for; elsewhere only inside a longer run of text"
            ),
            AS_BYTES: (
                "a cited entry writes its whole value only as bytes, which the export does not "
                "read as a host value"
            ),
            INSIDE_A_LONGER_RUN: (
                "a cited entry holds its text only inside a longer run of letters or digits"
            ),
            BETWEEN_SPACES: (
                "the cited entries hold it only between spaces, which this check does not count "
                "as a value's ends"
            ),
            NOT_WHOLE: (
                "a cited entry holds its text, but nowhere this check counts as the whole value"
            ),
        }
        assert NOT_IN_THE_CITED == "its whole value is in none of the entries it cites"
        assert NOT_RECORDED_AS_HELD == "no cited entry is recorded as holding its whole value"
        assert NOT_IN_THE_READ.format(read=16, cited=20) == (
            "its whole value is in none of the first 16 of the 20 entries it cites, "
            "which are the entries this check reads"
        )
        assert READ_OF_THE_CITED.format(read=16, cited=20) == (
            "this check reads the first 16 of the 20 entries it cites"
        )


def _report(rows: list[HostIdentifier], texts: dict[str, str]) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="ransomware",
        technical_analysis=TechnicalAnalysis(
            host_identifiers=with_held_in(rows, EntryTexts(texts=texts))
        ),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


class TestOneScanOneAnswerOnEverySurface:
    def test_held_in_and_the_words_come_from_the_one_scan(self) -> None:
        text = json.dumps({"strings": [f"closed{TASK}backup"]}).lower()
        report = _report([_row("scheduled task", TASK)], {"ev_0001": text})

        (row,) = report.technical_analysis.host_identifiers  # type: ignore[union-attr]
        assert row.held_in == []
        assert row.unheld_as == INSIDE_A_LONGER_RUN
        ((_, answer),) = identifier_answers(report)
        assert answer == f"no: {UNHELD_WORDS[INSIDE_A_LONGER_RUN]}"

    def test_every_surface_prints_the_one_answer(self) -> None:
        text = json.dumps({"description": f"creates task {TASK} at boot"}).lower()
        report = _report([_row("scheduled task", TASK)], {"ev_0001": text})
        answer = f"no: {UNHELD_WORDS[BETWEEN_SPACES]}"

        ((_, said),) = identifier_answers(report)
        assert said == answer
        assert answer in MarkdownRenderer().render(report)
        (listed,) = [row for row in full_ioc_list(report) if row.value == TASK]
        assert listed.published == answer

    def test_a_value_no_cited_entry_holds_in_any_spelling_keeps_the_earlier_words(self) -> None:
        # The cited entry holds nothing of it, whatever another entry holds.
        report = _report(
            [_row("scheduled task", TASK)],
            {"ev_0001": json.dumps(["OtherMarker"]), "ev_0002": json.dumps([TASK]).lower()},
        )

        (row,) = report.technical_analysis.host_identifiers  # type: ignore[union-attr]
        assert row.unheld_as == NOWHERE
        ((_, answer),) = identifier_answers(report)
        assert answer == f"no: {NOT_IN_THE_CITED}"

    def test_a_held_argument_publishes_the_row(self) -> None:
        text = _document(f"schtasks /Create /SC ONSTART /TN {TASK} /TR x.exe")
        report = _report([_row("scheduled task", TASK)], {"ev_0001": text})

        ((stated, answer),) = identifier_answers(report)
        assert stated.held_in == ("ev_0001",)
        assert publishes(answer)

    def test_a_stored_row_without_the_finding_says_only_what_its_record_holds(self) -> None:
        # A row as a report stored before the scan recorded its finding keeps
        # it: held_in written and empty, no word of what the scan found.
        stored = {
            "kind": "scheduled task",
            "value": TASK,
            "use": "creates/writes",
            "evidence_refs": ["ev_0001"],
            "held_in": [],
        }
        row = HostIdentifier.model_validate(stored)
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
            verdict="Malware",
            overall_confidence=0.9,
            technical_analysis=TechnicalAnalysis(host_identifiers=[row]),
        )

        ((_, answer),) = identifier_answers(report)
        assert answer == f"no: {NOT_RECORDED_AS_HELD}"
        assert NOT_IN_THE_CITED not in str(answer)
        assert "unheld_as" not in row.model_dump()

    def test_a_row_citing_more_entries_than_the_check_reads_says_so(self) -> None:
        cited = MAX_CITED + 4
        refs = [f"ev_{at:04d}" for at in range(1, cited + 1)]
        # The only entry holding the value whole is past the ones read.
        texts = {ref: json.dumps(["OtherMarker"]) for ref in refs}
        texts[refs[-1]] = json.dumps([TASK]).lower()
        row = HostIdentifier(
            kind="scheduled task", value=TASK, use="creates/writes", evidence_refs=refs
        )
        report = _report([row], texts)

        ((_, answer),) = identifier_answers(report)
        assert answer == f"no: {NOT_IN_THE_READ.format(read=MAX_CITED, cited=cited)}"
        assert NOT_IN_THE_CITED not in str(answer)

    def test_a_finding_on_a_row_citing_more_than_are_read_says_the_counts(self) -> None:
        cited = MAX_CITED + 1
        refs = [f"ev_{at:04d}" for at in range(1, cited + 1)]
        texts = {ref: json.dumps([f"closed{TASK}backup"]).lower() for ref in refs}
        row = HostIdentifier(
            kind="scheduled task", value=TASK, use="creates/writes", evidence_refs=refs
        )
        report = _report([row], texts)

        ((_, answer),) = identifier_answers(report)
        read = READ_OF_THE_CITED.format(read=MAX_CITED, cited=cited)
        assert answer == f"no: {UNHELD_WORDS[INSIDE_A_LONGER_RUN]} ({read})"

    def test_the_finding_is_never_in_the_model_s_schema(self) -> None:
        assert "unheld_as" not in json.dumps(HostIdentifier.model_json_schema())
