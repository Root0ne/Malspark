"""A value a further detonation's launch text supplies is not published as the sample's.

An agent may ask for a further detonation with launch arguments. A value is
refused where all three hold: a further detonation's mark stands on it (a row
of the report or a read of that detonation holds it); it stands whole in that
detonation's launch text in a form a command line writes a value in (one
argument, the host of ``user@host``, a switch's value written against it, a
path's leading part or component, the end after an environment variable, an
address the detonation resolved for a host the launch text holds; ``/`` read
as ``\\`` and case folded); and no entry of the run holds it whole outside the
reads of the detonations launched with it, what an entry's own call asked
for, and a call given their launch text. A value the job's own detonation
observed, a value the file, a decoded string or a reverser's read holds, and a
value the sample produced under a launch value publish as before. The rule
also holds for a value the judge names, and every surface follows the one
answer.
"""

from __future__ import annotations

import pytest

from malspark.reporting.detection_signatures import build_detection_rules, sigma_admits
from malspark.reporting.detonation_marks import observed_words
from malspark.reporting.launch_echo import (
    LAUNCH_SUPPLIED,
    launch_supplied_refusal,
    launch_tails,
    launch_values,
)
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import MalwareReport, ObservedIn
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer, publishes
from malspark.schemas.stix_models import Indicator
from tests.credential_shapes import prefixed_key

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

FOLDER = "C:\\Landing\\out"
WRITTEN = "C:\\Landing\\out\\readme.txt"
HOST = "relay.example.net"
ADDRESS = "185.23.44.10"
KEY = "HKCU\\Software\\Amber"
OTHER = static("ev_0001", {"strings": ["unrelated text"]})


def _run(
    launch: str,
    report: dict[str, object],
    *,
    identifiers: tuple[object, ...] = (),
    judged: tuple[tuple[str, str], ...] = (),
    before: tuple[object, ...] = (OTHER,),
    own: dict[str, object] | None = None,
    after: tuple[object, ...] = (),
) -> MalwareReport:
    ledger = [*before, *own_reads(own), request(launch), *further_reads(launch, report), *after]
    return built(ledger, identifiers, judged)  # type: ignore[arg-type]


def _folder_run(launch: str, *, before: tuple[object, ...] = (OTHER,)) -> MalwareReport:
    return _run(
        launch,
        further_report(command=f"x.exe {launch}", written=(WRITTEN,)),
        identifiers=(stated("folder", FOLDER, "ev_0023"),),
        before=before,
    )


def _refused(answer: str) -> bool:
    return answer.startswith(f"no: {LAUNCH_SUPPLIED}: ")


class TestTheFormsACommandLineWritesAValueIn:
    @pytest.mark.parametrize(
        ("launch", "value"),
        [
            ("--dir C:\\Landing\\out", "c:\\landing\\out"),
            ("-ssh ops@relay.example.net -batch hostname", "relay.example.net"),
            ("x bundle.7z -oC:\\Landing\\out -y", "c:\\landing\\out"),
            ("/S /D=C:\\Landing\\out", "c:\\landing\\out"),
            ("/path:C:\\Landing\\out /q", "c:\\landing\\out"),
            ("--dir=C:\\Landing\\out", "c:\\landing\\out"),
            ("--dir C:/Landing/out", "c:\\landing\\out"),
            ("--out C:\\Landing\\out\\ledger.ini", "c:\\landing\\out"),
            ("--out C:\\Landing\\out\\ledger.ini", "ledger.ini"),
            ('--out "C:\\Landing Zone\\ledger.ini"', "c:\\landing zone"),
            ("--url http://relay.example.net:8080/gate", "relay.example.net"),
            ("--peer relay.example.net:8443", "relay.example.net"),
        ],
    )
    def test_a_value_the_launch_text_holds_whole(self, launch: str, value: str) -> None:
        assert value in launch_values(launch)

    @pytest.mark.parametrize(
        ("launch", "value"),
        [
            ("--dir C:\\Landing\\out", "c:\\landing\\out\\readme.txt"),
            ("--key HKCU\\Software\\Quill", "hkcu\\software\\quill\\run2"),
            ("--dir C:\\Landing\\outer", "c:\\landing\\out"),
            ("--url http://relay.example.net/gate", "gate"),
        ],
    )
    def test_a_value_it_does_not_hold_whole(self, launch: str, value: str) -> None:
        assert value not in launch_values(launch)

    def test_the_end_after_an_environment_variable(self) -> None:
        assert launch_tails("--out %APPDATA%\\Quillbox\\ledger.ini") == [
            ("%appdata%", "\\quillbox"),
            ("%appdata%", "\\quillbox\\ledger.ini"),
        ]


class TestAValueOnlyTheLaunchedDetonationsObservedIsRefused:
    @pytest.mark.parametrize(
        "launch",
        [
            "--dir C:\\Landing\\out",
            "x bundle.7z -oC:\\Landing\\out -y",
            "/S /D=C:\\Landing\\out",
            "/path:C:\\Landing\\out /q",
            "--dir C:/Landing/out",
            "--out C:\\Landing\\out\\readme.txt",
        ],
    )
    def test_a_folder_the_launch_text_supplies(self, launch: str) -> None:
        assert _refused(answer_for(_folder_run(launch), FOLDER))

    def test_the_host_of_user_at_host_the_judge_names(self) -> None:
        launch = f"-ssh ops@{HOST} -batch hostname"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", dns=((HOST, ADDRESS),)),
            judged=(("domain", HOST),),
        )
        assert _refused(answer_for(report, HOST))

    def test_an_address_the_detonation_resolved_for_a_launch_host(self) -> None:
        launch = f"--host {HOST}"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", dns=((HOST, ADDRESS),)),
            judged=(("ip", ADDRESS),),
        )
        answer = answer_for(report, ADDRESS)
        assert _refused(answer)
        assert f"detonation 2 resolved it for `{HOST}`" in answer

    def test_a_folder_an_environment_variable_of_the_launch_expands_to(self) -> None:
        expanded = "C:\\Users\\Admin\\AppData\\Roaming\\Quillbox"
        launch = "--dir %APPDATA%\\Quillbox"
        report = _run(
            launch,
            further_report(command=f"x.exe --dir {expanded}", written=(f"{expanded}\\a.txt",)),
            identifiers=(stated("folder", expanded, "ev_0023"),),
        )
        answer = answer_for(report, expanded)
        assert _refused(answer)
        assert "its end after the environment variable `%appdata%`" in answer

    def test_a_file_name_of_a_typed_path(self) -> None:
        launch = "--out C:\\Landing\\out\\ledger.ini"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", written=("C:\\Landing\\out\\ledger.ini",)),
            identifiers=(stated("file name", "ledger.ini", "ev_0023"),),
        )
        assert _refused(answer_for(report, "ledger.ini"))

    def test_a_key_nothing_else_holds(self) -> None:
        launch = f"--key {KEY}"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", signature=f"set {KEY}"),
            identifiers=(stated("registry key", KEY, "ev_0022"),),
        )
        assert _refused(answer_for(report, KEY))


class TestAValueTheSampleHoldsPublishesAsBefore:
    def test_a_value_the_job_s_own_detonation_observed(self) -> None:
        own = {
            "behavior": {
                "processes": [
                    {
                        "pid": 4,
                        "ppid": 1,
                        "process_name": "cmd.exe",
                        "command_line": f"cmd.exe /c mkdir {FOLDER}",
                    }
                ]
            }
        }
        launch = f"--dir {FOLDER}"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}"),
            identifiers=(stated("folder", FOLDER, "ev_0002"),),
            own=own,
        )
        assert publishes(answer_for(report, FOLDER))

    @pytest.mark.parametrize("tool", ["strings", "floss_decoded", "decompile_function"])
    def test_a_launch_value_the_file_holds(self, tool: str) -> None:
        launch = f"--key {KEY}"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", signature=f"set {KEY}"),
            identifiers=(stated("registry key", KEY, "ev_0022"),),
            before=(static("ev_0001", {"text": KEY}, tool=tool),),
        )
        assert publishes(answer_for(report, KEY))

    def test_a_host_a_reverser_decoded_and_the_launch_passed_back(self) -> None:
        host = f"c2.{HOST}"
        launch = f"--server {host}"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", dns=((host, ADDRESS),)),
            judged=(("domain", host),),
            before=(static("ev_0001", {"decoded": [host]}, tool="decompile_function"),),
        )
        assert publishes(answer_for(report, host))

    def test_a_file_and_a_folder_the_sample_made_under_a_typed_folder(self) -> None:
        launch = f"--dir {FOLDER}"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", written=(f"{FOLDER}\\cache\\readme.txt",)),
            identifiers=(
                stated("file name", "readme.txt", "ev_0023"),
                stated("folder", f"{FOLDER}\\cache", "ev_0023"),
            ),
        )
        assert publishes(answer_for(report, "readme.txt"))
        assert publishes(answer_for(report, f"{FOLDER}\\cache"))

    def test_a_subkey_the_sample_set_under_a_typed_key(self) -> None:
        launch = "--key HKCU\\Software\\Quill"
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", signature="set HKCU\\Software\\Quill\\Run2"),
            identifiers=(stated("registry key", "HKCU\\Software\\Quill\\Run2", "ev_0022"),),
        )
        assert publishes(answer_for(report, "HKCU\\Software\\Quill\\Run2"))

    def test_a_value_of_one_launch_a_detonation_launched_without_it_observed(self) -> None:
        launch = f"--dir {FOLDER}"
        third = further_reads(
            "--mode quiet",
            further_report(command="x.exe --mode quiet", written=(WRITTEN,)),
            ordinal=3,
            start=40,
        )
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}"),
            identifiers=(stated("folder", FOLDER, "ev_0043"),),
            after=tuple(third),
        )
        assert publishes(answer_for(report, FOLDER))

    def test_the_request_and_a_call_given_the_launch_text_hold_nothing(self) -> None:
        # The request's own call holds the launch text: it is no holder, so the
        # folder is refused exactly as without it.
        assert _refused(answer_for(_folder_run(f"--dir {FOLDER}"), FOLDER))


class TestTheWords:
    def test_a_value_the_launch_text_holds(self) -> None:
        launch = f"--dir {FOLDER}"
        assert answer_for(_folder_run(launch), FOLDER) == (
            f"no: {LAUNCH_SUPPLIED}: detonation 2's launch text holds it, read without case "
            f"and with / as \\ (`{launch}`), and the run's search found it whole in no entry "
            "but the reads of detonation 2, entries whose call was given that launch text and "
            "entries holding it only where their answer repeats their own call"
        )

    def test_two_detonations_launched_with_it(self) -> None:
        launch = f"--dir {FOLDER}"
        third = further_reads(
            launch,
            further_report(command=f"x.exe {launch}", written=(WRITTEN,)),
            ordinal=3,
            start=40,
        )
        report = _run(
            launch,
            further_report(command=f"x.exe {launch}", written=(WRITTEN,)),
            identifiers=(stated("folder", FOLDER, "ev_0023"),),
            after=(*third, request(launch, "ev_0039")),
        )
        assert answer_for(report, FOLDER).endswith(
            "found it whole in no entry but the reads of detonations 2 and 3, entries whose call "
            "was given one of their launch texts and entries holding it only where their answer "
            "repeats their own call"
        )

    def test_a_launch_text_is_written_as_every_surface_writes_one(self) -> None:
        launch = f"--dir {FOLDER} --note `x`"
        answer = answer_for(_folder_run(launch), FOLDER)
        assert "(`--dir C:\\Landing\\out --note \\x60x\\x60`)" in answer


class TestTheRuleReadsTheRecord:
    def test_a_run_with_one_detonation_records_nothing(self) -> None:
        report = built([OTHER, *own_reads()])
        assert report.launch_values == []
        assert "launch_values" not in report.model_dump()

    def test_a_value_a_row_of_the_job_s_own_detonation_holds_is_never_refused(self) -> None:
        report = _folder_run(f"--dir {FOLDER}")
        assert launch_supplied_refusal(report, "folder", FOLDER)
        # A domain row of the network block with no mark is the job's own.
        assert not launch_supplied_refusal(report, "domain", "cdn.example.org")


class TestEverySurfaceFollowsTheAnswer:
    def _host_run(self) -> MalwareReport:
        launch = f"-ssh ops@{HOST} -batch hostname"
        return _run(
            launch,
            further_report(command=f"x.exe {launch}", dns=((HOST, ADDRESS),)),
            judged=(("domain", HOST),),
        )

    def test_no_stix_object_names_it(self) -> None:
        bundle = ExtendedSTIXRenderer().render(self._host_run(), base_bundle=None)
        patterns = " ".join(o.pattern for o in bundle.objects if isinstance(o, Indicator))
        assert HOST not in patterns

    def test_no_misp_attribute_carries_it(self) -> None:
        attributes = build_misp_attributes(self._host_run(), owner="job-1")
        assert all(HOST not in str(attribute.get("value")) for attribute in attributes)

    def test_no_rule_draft_names_it(self) -> None:
        bodies = " ".join(rule.body for rule in build_detection_rules(self._host_run()))
        assert HOST not in bodies

    def test_sigma_admits_no_sandbox_row_the_launch_supplied(self) -> None:
        launch = f"--out {WRITTEN}"
        report = _run(launch, further_report(command=f"x.exe {launch}", written=(WRITTEN,)))
        rows = {row.value: row for row in report.consolidated_iocs}
        assert rows[WRITTEN].source == "sandbox"
        assert WRITTEN.lower() not in sigma_admits(report)


class TestACredentialShapedLaunchText:
    def test_the_refusal_writes_it_as_the_mark_does(self) -> None:
        launch = f"--dir {FOLDER} --token {prefixed_key('ghp_', 36)}"
        answer = answer_for(_folder_run(launch), FOLDER)
        mark = observed_words([ObservedIn(detonation="d2", launched_with=launch)])
        shown = mark.removeprefix("observed in detonation 2, launched with ")
        assert f"({shown})" in answer
