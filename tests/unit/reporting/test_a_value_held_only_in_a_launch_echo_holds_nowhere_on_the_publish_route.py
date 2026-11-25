"""A value a read of a further detonation holds only where it states its launch text has no holder.

A read of a further detonation states the launch text it was made with (its
``launched_with`` field, and the end of the launched process's command line).
That text is the run's own input, not an observation: on the publish route
(``stated_host_values.scan_cited``) and the second-source route
(``stix_renderer.second_source_reads``) it is a second echo of the shared
pair-of-texts predicate (``validation.held_only_in_its_echo``), beside the
echo of the entry's own call. A cited read holding the value whole only there
is no holder, and the refusal says so, naming the detonation and its launch
text; a holding outside it stands, and so does a spelling at a place no
letter, digit or ``_`` of the decoded run touches (the predicate's decoded-run
exception). A row's detonation mark is the platform's words and confirms
nothing. An index with no read of a launched detonation reads as before.
"""

from __future__ import annotations

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    SecondSourceRead,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.renderers.stix_renderer import (
    corroborating_values,
    second_source,
    second_source_reads,
    second_source_refusal_parts,
)
from malspark.reporting.stated_host_values import (
    ONLY_IN_ITS_LAUNCH,
    with_held_in,
)

from ._launch_runs import (
    answer_for,
    built,
    further_reads,
    further_report,
    own_reads,
    request,
    stated,
    static,
)

FOLDER = "C:\\Landing\\inbox"
LAUNCH = f"--dir {FOLDER}"


def _ledger(
    *,
    holder: object = None,
    signature: str = "",
    written: tuple[str, ...] = (),
    children: tuple[tuple[str, str], ...] = (),
) -> list:
    before = [holder] if holder is not None else [static("ev_0001", {"strings": ["unrelated"]})]
    reads = further_reads(
        LAUNCH,
        further_report(
            command=f"x.exe {LAUNCH}", signature=signature, written=written, children=children
        ),
    )
    return [*before, *own_reads(), request(LAUNCH), *reads]


class TestThePublishRoute:
    def test_a_value_held_only_in_the_launch_echo_has_no_holder(self) -> None:
        (row,) = with_held_in(
            [stated("folder", FOLDER, "ev_0020")], EntryTexts.from_ledger(_ledger())
        )
        assert row.held_in == []
        assert row.unheld_as == f"{ONLY_IN_ITS_LAUNCH}:d2"

    def test_the_refusal_names_the_detonation_and_its_launch_text(self) -> None:
        # Another entry holds the folder, so the launch-supplied rule does not
        # decide: the cited read's own finding is the refusal.
        ledger = _ledger(holder=static("ev_0001", {"strings": [FOLDER]}))
        report = built(ledger, (stated("folder", FOLDER, "ev_0020"),))
        assert answer_for(report, FOLDER) == (
            "no: a cited entry holds it whole only where it states the launch text of detonation "
            f"2 (`{LAUNCH}`), which the request for that detonation supplied"
        )

    def test_a_holding_outside_the_launch_echo_stands(self) -> None:
        ledger = _ledger(written=(f"{FOLDER}\\readme.txt",))
        (row,) = with_held_in([stated("folder", FOLDER, "ev_0023")], EntryTexts.from_ledger(ledger))
        assert row.held_in == ["ev_0023"]

    def test_a_spelling_no_run_touches_keeps_the_answer_read_with_the_echo(self) -> None:
        # A started process's name holds the folder where the scan does not
        # count it whole (a space runs on after it), at a place no letter,
        # digit or ``_`` touches: the read holds it as it did with its launch
        # echo read.
        ledger = _ledger(children=((f"{FOLDER} tool.exe", "tool.exe"),))
        (row,) = with_held_in([stated("folder", FOLDER, "ev_0020")], EntryTexts.from_ledger(ledger))
        assert row.held_in == ["ev_0020"]
        # Without that place, the launch echo was its only holding.
        (row,) = with_held_in(
            [stated("folder", FOLDER, "ev_0020")], EntryTexts.from_ledger(_ledger())
        )
        assert row.held_in == []

    def test_an_index_with_no_launched_read_is_the_same_index(self) -> None:
        entries = EntryTexts.from_ledger([static("ev_0001", {"strings": [FOLDER]}), *own_reads()])
        assert entries.with_launch_echoes() is entries


def _strings_report(value: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)),
        verdict="Malware",
        static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=value)]),
    )


class TestTheSecondSourceRoute:
    def test_a_read_holding_a_value_only_in_its_launch_text_records_it_apart(self) -> None:
        reads = {
            read.entry: read for read in second_source_reads(_strings_report(FOLDER), _ledger())
        }
        assert reads["ev_0020"].holds == []
        assert reads["ev_0020"].launch_echo == [FOLDER.lower()]
        assert reads["ev_0020"].detonation == "d2"

    def test_a_holding_outside_the_launch_text_is_kept(self) -> None:
        ledger = _ledger(signature=f"wrote {FOLDER}")
        reads = {read.entry: read for read in second_source_reads(_strings_report(FOLDER), ledger)}
        assert reads["ev_0022"].holds == [FOLDER.lower()]
        assert reads["ev_0022"].launch_echo == []

    def test_it_confirms_nothing_and_the_refusal_names_it(self) -> None:
        report = _strings_report(FOLDER)
        report.second_source_reads = [
            SecondSourceRead(
                entry="ev_0020",
                tool="sandbox_processes",
                standing="observes",
                cited=True,
                launch_echo=[FOLDER.lower()],
                detonation="d2",
            )
        ]
        record = corroborating_values(report)
        assert second_source(FOLDER, record, path=True) == ""
        assert second_source_refusal_parts(FOLDER, record, path=True) == (
            "sandbox_processes (ev_0020) holds it only in the launch text of detonation 2, which "
            "the request for that detonation supplied",
        )


class TestADetonationMarkIsNoObservation:
    def test_a_row_s_mark_does_not_confirm_a_value_its_launch_text_holds(self) -> None:
        report = built(_ledger(written=("C:\\Elsewhere\\x.txt",)))
        assert report.dynamic is not None
        assert any(op.get("observed_in") for op in report.dynamic.file_operations)
        assert second_source(FOLDER, corroborating_values(report), path=True) == ""
