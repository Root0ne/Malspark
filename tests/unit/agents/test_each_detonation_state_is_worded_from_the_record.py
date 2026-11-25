"""The run-state line of the job's detonations says what each record holds, and nothing more.

A requested detonation is "asked for by <agent> (<request>) with <launch
text>"; "launched with" is said only where the sandbox honoured the launch;
the state is made and reported, submitted with no report (the failure as
recorded), not made (the failure), being carried out now, or accepted and not
carried out yet; the job's own detonation with no record yet says so; the
line counts how many more the job can accept. Every value is made up.
"""

from __future__ import annotations

import pytest

from malspark.pipeline.events import scrub
from malspark.pipeline.triage_pack import LAUNCH_SHOWN_ESCAPED
from malspark.providers.detonation import AGENT_ORIGIN, DetonationRecord
from malspark.providers.detonation_requests import (
    ACCEPTED,
    JOINED,
    REFUSED,
    DetonationRequest,
    detonations_left,
    detonations_line,
)
from malspark.reporting.detonation_marks import launch_text
from tests.credential_shapes import prefixed_key

from .holder_shapes import container, first_detonation

HEAD = "detonations: the job can accept {left} more (its ceiling is 4, the job's own included); "
D1 = "d1, the job's own, launched without arguments: made, reported"


def _request(job: object, number: int, agent: str, arguments: str, state: str, name: str) -> None:
    job.detonation_requests.append(  # type: ignore[attr-defined]
        DetonationRequest(
            number=number,
            agent=agent,
            stage="dynamic",
            arguments=arguments,
            reason="found",
            cited_entries=["ev_0002"],
            state=state,
            detonation=name,
        )
    )


def _further(arguments: str = "--key k1", **fields: object) -> DetonationRecord:
    record = DetonationRecord(
        ordinal=2,
        origin=AGENT_ORIGIN,
        arguments=arguments,
        requested_by=[{"request": "r1", "agent": "dynamic"}],
    )
    for key, value in fields.items():
        setattr(record, key, value)
    return record


class TestTheJobsOwn:
    def test_reported_and_launched_without_arguments(self) -> None:
        assert detonations_line(container()) == HEAD.format(left=3) + D1

    def test_no_record_yet_is_said_so(self) -> None:
        line = detonations_line(container(detonations=[]))
        assert line == HEAD.format(left=3) + "d1, the job's own: no record yet"

    def test_not_submitted_is_not_made_with_its_failure(self) -> None:
        record = DetonationRecord(failure="the sandbox refused the upload")
        line = detonations_line(container(detonations=[record]))
        assert line.endswith("d1, the job's own: not made (the sandbox refused the upload)")

    def test_launch_arguments_honoured_are_launched_with(self) -> None:
        record = first_detonation()
        record.arguments, record.launch = "/quiet", {"honoured": True}
        line = detonations_line(container(detonations=[record]))
        assert line.endswith("d1, the job's own, launched with `/quiet`: made, reported")

    def test_an_escaped_launch_text_of_the_job_s_own_carries_no_hint(self) -> None:
        """The job's own detonation's escaped launch text is shown without the pack's hint."""
        record = first_detonation()
        record.arguments, record.launch = "/k `x`", {"honoured": True}
        line = detonations_line(container(detonations=[record]))
        assert line.endswith(
            f"d1, the job's own, launched with `{launch_text('/k `x`')}`: made, reported"
        )
        assert launch_text("/k `x`") != "/k `x`"
        assert LAUNCH_SHOWN_ESCAPED.format(name="d1") not in line and "shown escaped" not in line

    def test_launch_arguments_not_passed_are_never_launched_with(self) -> None:
        record = first_detonation()
        record.arguments, record.launch = "/quiet", {"honoured": False}
        line = detonations_line(container(detonations=[record]))
        assert "launched with" not in line
        assert line.endswith(
            "d1, the job's own, submitted without its arguments (the provider did not pass "
            "them): made, reported"
        )


class TestARequestedOne:
    def test_accepted_and_not_carried_out_yet(self) -> None:
        job = container()
        _request(job, 1, "dynamic", "--key k1", ACCEPTED, "d2")
        assert detonations_line(job) == HEAD.format(left=2) + (
            f"{D1}; d2, asked for by dynamic (r1) with `--key k1`: accepted, not carried out yet"
        )
        assert "launched with `--key" not in detonations_line(job)

    def test_a_joined_request_names_every_asker(self) -> None:
        job = container()
        _request(job, 1, "dynamic", "--key k1", ACCEPTED, "d2")
        _request(job, 2, "network", "--key k1", JOINED, "d2")
        assert detonations_line(job).endswith(
            "d2, asked for by dynamic (r1) and network (r2) with `--key k1`: accepted, not "
            "carried out yet"
        )

    def test_a_refused_request_is_no_detonation(self) -> None:
        job = container()
        _request(job, 1, "dynamic", "--key k1", REFUSED, "")
        assert detonations_line(job) == HEAD.format(left=3) + D1
        assert detonations_left(job) == 3

    def test_being_carried_out_now(self) -> None:
        job = container()
        job.detonations.append(_further(running=True))
        assert detonations_line(job).endswith(
            "d2, asked for by dynamic (r1) with `--key k1`: being carried out now"
        )

    def test_made_and_reported(self) -> None:
        job = container()
        job.detonations.append(_further(report={}, submit_returned=True, launch={"honoured": True}))
        assert detonations_line(job) == HEAD.format(left=2) + (
            f"{D1}; d2, asked for by dynamic (r1) with `--key k1`: made, reported"
        )

    def test_submitted_with_no_report_says_the_failure_as_recorded(self) -> None:
        job = container()
        job.detonations.append(
            _further(submit_returned=True, launch={"honoured": True}, failure="it failed: Boom")
        )
        assert detonations_line(job).endswith(
            "d2, asked for by dynamic (r1) with `--key k1`: submitted, no report (it failed: Boom)"
        )

    def test_a_failed_detonation_not_submitted_is_not_made(self) -> None:
        job = container()
        failure = "not run: the job's time limit leaves 0 seconds, and a detonation may take 600"
        job.detonations.append(_further(failure=failure))
        line = detonations_line(job)
        assert line.endswith(f"d2, asked for by dynamic (r1) with `--key k1`: not made ({failure})")
        assert "made, " not in line.split("; d2")[1]

    def test_submitted_without_its_arguments(self) -> None:
        job = container()
        job.detonations.append(
            _further(report={}, submit_returned=True, launch={"honoured": False})
        )
        assert detonations_line(job).endswith(
            "d2, asked for by dynamic (r1) with `--key k1`, submitted without its arguments "
            "(the provider did not pass them): made, reported"
        )

    def test_the_count_follows_the_ceiling_and_every_one_held(self) -> None:
        job = container()
        for number, arguments in enumerate(("-a", "-b", "-c"), start=1):
            _request(job, number, "dynamic", arguments, ACCEPTED, f"d{number + 1}")
        assert detonations_line(job).startswith(HEAD.format(left=0))
        assert detonations_left(job) == 0


class TestTheLaunchText:
    @pytest.mark.parametrize("hostile", ["--k `x` {y}", "--k a\nb", "--k d3/proc:1", "--k |a|"])
    def test_a_hostile_launch_text_is_written_as_every_surface_writes_it(
        self, hostile: str
    ) -> None:
        job = container()
        _request(job, 1, "dynamic", hostile, ACCEPTED, "d2")
        line = detonations_line(job)
        assert f"with `{launch_text(hostile)}`" in line
        assert "\n" not in line and "d3/proc:1" not in line

    def test_an_escaped_text_of_a_reported_one_carries_the_pack_s_hint(self) -> None:
        job = container()
        job.detonations.append(
            _further("--k `x`", report={}, submit_returned=True, launch={"honoured": True})
        )
        assert LAUNCH_SHOWN_ESCAPED.format(name="d2") in detonations_line(job)

    def test_an_escaped_text_with_no_read_yet_names_no_read(self) -> None:
        job = container()
        _request(job, 1, "dynamic", "--k `x`", ACCEPTED, "d2")
        assert "launched_with of any read" not in detonations_line(job)

    def test_a_text_shown_as_written_carries_no_hint(self) -> None:
        job = container()
        job.detonations.append(_further(report={}, submit_returned=True, launch={"honoured": True}))
        assert "shown escaped" not in detonations_line(job)

    def test_a_credential_shaped_launch_text_is_shown_and_masked_as_the_mark_s(self) -> None:
        from malspark.pipeline.triage_pack import _mark_of
        from malspark.schemas.evidence import LedgerEntry

        key = prefixed_key("sk-")
        arguments = f"--token {key}"
        job = container()
        job.detonations.append(
            _further(arguments, report={}, submit_returned=True, launch={"honoured": True})
        )
        line = detonations_line(job)
        read = LedgerEntry(
            id="ev_0009",
            tool="sandbox_processes",
            agent="pipeline",
            output="{}",
            structured={"detonation": "d2", "launched_with": arguments},
        )
        read.source = "pack"
        mark = _mark_of(read)
        # The model reads the launch text as the pack's mark shows it ...
        assert f"`{launch_text(arguments)}`" in line and f"`{launch_text(arguments)}`" in mark
        # ... and the event scrub masks the key in the line as it does in the mark.
        assert key not in scrub(line) and key not in scrub(mark)
