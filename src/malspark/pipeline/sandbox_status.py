"""Whether a sandbox ran, read once, in the words every reader of the report uses.

A run's sandbox report is one of three things, and their sections read alike.
A live sandbox's report is an observation, empty or not. The mock sandbox's
recorded fixture is an observation too, but of some earlier detonation, not of
this run. And when the mock has no fixture for the sample it answers with an
empty stand-in, marked ``synthetic``, which is no observation at all.

The pack, the in-process sandbox tools, the degradation reasons, the run
summary and the report all ask this module rather than the report's keys, so
each says the same true thing: no sandbox ran, or the report is a recorded
fixture and not a live detonation, or nothing is added to what a sandbox
observed.

A live or attached report whose sandbox names a target SHA-256 that is not
the sample's is still an observation, and reads as one everywhere; the run marks it before
the graph runs (``app.MalsparkApp``), and its status carries the sentence that
says so, for the pack to hand the analysts and the judge. What it touches is
theirs to decide.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# The marks are the document's (``schemas.sandbox_document.PLATFORM_MARKS``):
# the mock sandbox's stand-in carries ``SYNTHETIC_KEY`` (``MockSandboxClient``),
# a report it read from a fixture file ``FIXTURE_KEY``, and a live or attached
# report whose sandbox names another target than the sample ``TARGET_KEY`` (set by the run,
# ``app.MalsparkApp._tell_the_target``). Named here as every reader of the status
# has always imported them.
from malspark.schemas.sandbox_document import FIXTURE_KEY, LAUNCH_KEY, SYNTHETIC_KEY, TARGET_KEY

__all__ = ["FIXTURE_KEY", "LAUNCH_KEY", "SYNTHETIC_KEY", "TARGET_KEY"]

# The three answers. Words rather than codes because they are written into
# the ledger entry and the run summary, where a reader meets them as they are.
NOT_RUN = "not run"
RECORDED_FIXTURE = "recorded fixture"
OBSERVED = "observed"

# Where the md5, sha1 and size of a marked report's identity came from
# (:func:`sample_file_identity`): the sample's own bytes, or nowhere, the
# router's values standing alone. Never a field of the block, only which
# header the judge's block is written under.
IDENTITY_SOURCE_KEY = "identity_source"
FROM_SAMPLE_BYTES = "sample_bytes"
FROM_ROUTER_ONLY = "router_only"

# The tool name of the pack entry that states the status. Named like the
# sandbox views so the console files it with them.
STATUS_TOOL = "sandbox_status"

_NO_REPORT = (
    "No sandbox ran on this run: there is no sandbox report, so nothing here was "
    "observed by executing the sample."
)
_STAND_IN = (
    "No sandbox ran for this sample: the mock sandbox has no recorded report for it "
    "and answered with an empty stand-in, so nothing here was observed by executing "
    "the sample."
)
_FIXTURE = (
    "The sandbox report is a recorded fixture the mock sandbox returned for this "
    "sample, not a live detonation in this run."
)


@dataclass(frozen=True)
class SandboxStatus:
    """What a run's sandbox report is, and the one sentence that says so."""

    status: str
    statement: str

    def as_entry(self) -> dict[str, str]:
        """The ledger entry's answer: the status word and the sentence."""
        return {"sandbox": self.status, "statement": self.statement}


def sandbox_status(report: Any) -> SandboxStatus:
    """What ``report`` — the run's sandbox report document, or ``None`` — is."""
    if not isinstance(report, dict) or not report:
        return SandboxStatus(NOT_RUN, _NO_REPORT)
    launch = launch_statement(report.get(LAUNCH_KEY), launcher_attribution(report))
    if report.get(SYNTHETIC_KEY):
        return SandboxStatus(NOT_RUN, _joined(_STAND_IN, launch))
    if report.get(FIXTURE_KEY):
        return SandboxStatus(RECORDED_FIXTURE, _joined(_FIXTURE, launch))
    return SandboxStatus(OBSERVED, _joined(_target_statement(report.get(TARGET_KEY)), launch))


def _joined(*sentences: str) -> str:
    return " ".join(sentence for sentence in sentences if sentence)


# The platform's mark on a report a generated launcher's run produced: whether
# the launcher's processes could be told from the sample's ("established", or
# "not established: <reason>"), set where the report is read
# (``schemas.sandbox_report.attribute_the_launcher``).
LAUNCHER_ATTRIBUTION_KEY = "launcher_attribution"
ATTRIBUTION_ESTABLISHED = "established"


def launcher_attribution(report: Any) -> str:
    """The report's launcher attribution mark, ``""`` where it carries none.

    Read at the document's top level, or in its ``cti`` block.
    """
    if not isinstance(report, Mapping):
        return ""
    value = report.get(LAUNCHER_ATTRIBUTION_KEY)
    if value is None and isinstance(report.get("cti"), Mapping):
        value = report["cti"].get(LAUNCHER_ATTRIBUTION_KEY)
    return value.strip() if isinstance(value, str) else ""


def launcher_attribution_reason(report: Any) -> str | None:
    """The limitation where a launcher run's processes could not be told apart; else ``None``."""
    mark = launcher_attribution(report)
    if not mark or mark == ATTRIBUTION_ESTABLISHED:
        return None
    why = mark.removeprefix("not established").lstrip(": ").strip()
    return (
        "the launcher's processes could not be told from the sample's in the sandbox report"
        + (f": {why}" if why else "")
        + "; only the script host's own processes are marked as the launcher's"
    )


def launch_statement(record: Any, attribution: str = "") -> str:
    """What a report's launch mark says: the job's launch arguments, verbatim, and their fate.

    ``""`` with no mark, so a job that asked for none reads as it always did.
    The arguments are the operator's run configuration and are written whole,
    as one code span (:func:`_code`, ids and control characters written out),
    never masked. What is stated is what is known: the provider sent them in
    its submission, and through which option or field; whether the started
    program read them is the sandbox's, and is not claimed.
    """
    if not isinstance(record, Mapping) or "arguments" not in record:
        return ""
    arguments = _code(str(record.get("arguments") or ""))
    provider = _code(str(record.get("provider") or "sandbox"))
    note = str(record.get("note") or "").strip()
    if record.get("honoured") is True:
        tail = f" ({note})" if note else ""
        via = str(record.get("via") or "").strip()
        through = f" through {via}" if via else ""
        return (
            f"{_asked(record)} to launch the sample with the arguments {arguments}; "
            f"the {provider} provider sent them in its submission{through}{tail}. Whether the "
            "started program read them is the sandbox's, and is not established here."
            + _launcher_statement(record.get("launcher"), attribution)
        )
    tail = f": {note}" if note else ""
    return (
        f"{_asked(record)} to launch the sample with the arguments {arguments}; "
        f"they were not honoured by the {provider} provider{tail}. Nothing here was "
        "observed with those arguments."
    )


def _asked(record: Mapping[str, Any]) -> str:
    """Who asked for the launch: the job, or the agents that asked for a further detonation."""
    name = str(record.get("detonation") or "")
    if not name:
        return "The job asked the sandbox"
    askers = ", ".join(str(a) for a in record.get("requested_by") or () if a) or "an agent"
    number = name[1:] if name.startswith("d") else name
    return f"For detonation {number}, {askers} asked the sandbox"


def _launcher_statement(launcher: Any, attribution: str = "") -> str:
    """The sentences of a launch mark whose arguments were carried by a generated launcher.

    ``""`` for a mark with none. They state what the reader must know: the
    sample was started by a script, not directly; the archive is what was
    disclosed; the process tree starts at the script host; and that nothing
    here shows the launcher ran, which only the sandbox's report can.
    """
    if not isinstance(launcher, Mapping) or not launcher.get("launcher_text"):
        return ""
    host = str(launcher.get("script_host") or "script")
    return (
        f" The sample was not submitted bare: it was launched through a generated {host} "
        f"launcher ({_code(str(launcher.get('launcher_member') or ''))}, "
        f"{str(launcher.get('launcher_encoding') or 'text')}) that starts the sample's copy "
        f"{_code(str(launcher.get('sample_member') or ''))} "
        f"(SHA-256 {_code(str(launcher.get('sample_sha256') or ''))}) with the arguments; its "
        f"exact text is {_code(str(launcher['launcher_text']))}. The submitted archive "
        f"(SHA-256 {_code(str(launcher.get('archive_sha256') or ''))}), with the launcher and "
        "the arguments in it, is what was disclosed to the sandbox, and on a sandbox that "
        "publishes its submissions it is public. The sandbox was told which member to run "
        f"by {launcher.get('picked_by') or 'the submission'}. "
        + _lineage_statement(launcher, host, attribution)
        + " A target the sandbox names by "
        "the archive's SHA-256 is the submitted archive holding the sample, not another "
        "target, and its file facts are the archive's. The sandbox's own score and family are "
        "its analysis of the archive run from the picked launcher script. Nothing here shows "
        "the launcher ran; that can only be read from the sandbox's report."
    )


def _lineage_statement(launcher: Mapping[str, Any], host: str, attribution: str) -> str:
    """Where the sample's processes start in a launcher run, as far as it was established.

    With the attribution not established, only the script host's own
    processes are the launcher's and nothing is said of where the sample's
    start. A report with no mark reads as before the mark existed.
    """
    member = _code(str(launcher.get("sample_member") or ""))
    if attribution and attribution != ATTRIBUTION_ESTABLISHED:
        why = attribution.removeprefix("not established").lstrip(": ").strip()
        return (
            f"The sandbox's process tree starts at {host}, not at the sample, but which of "
            "its processes are the sample's could not be established"
            + (f" ({why})" if why else "")
            + f": only the {host} processes themselves are marked as the launcher's, and the "
            "processes, flows and signatures past them are not attributed either way."
        )
    return (
        f"The sandbox's process tree therefore starts at {host}, not at the sample: the "
        "processes the launcher ran, the flows they made and the signatures seen only in them "
        "are marked as the launcher's and are not the sample's, and the sample's own start at "
        f"the process that runs {member}."
    )


def target_mark(record: Mapping[str, Any]) -> dict[str, Any]:
    """The mark a report carries for ``record``, a ``sandbox_target_record``: its two hashes."""
    mark: dict[str, Any] = {
        "expected_sha256": str(record.get("expected_sha256") or ""),
        "sandbox_sha256": str(record.get("sandbox_sha256") or ""),
    }
    if record.get("sandbox_sha256_valid") is False:
        mark["sandbox_sha256_valid"] = False
    return mark


def _target_statement(mark: Any) -> str:
    """The sentences of a report's target mark; ``""`` with none.

    Both values are kept again as the record keeps a sandbox's value, whoever
    wrote the mark: a value that is not a SHA-256 is one bounded line. Each is
    written as a code span (:func:`_code`), so the sandbox's text reads as a
    value in the pack and in the report, never as their markup.
    """
    from malspark.analysis.sample_integrity import (
        kept_hash,
        sandbox_target_lines,
        sandbox_target_record,
    )

    if not isinstance(mark, Mapping):
        return ""
    expected = kept_hash(str(mark.get("expected_sha256") or ""))
    record = sandbox_target_record(expected, mark.get("sandbox_sha256"))
    if record is None and expected and mark.get("sandbox_sha256_valid") is False:
        # A target that held no printable character: kept empty, still said.
        record = {"expected_sha256": expected, "sandbox_sha256": "", "sandbox_sha256_valid": False}
    return " ".join(sandbox_target_lines(record, _code))


def _code(text: str) -> str:
    """``text`` as one code span, fenced longer than any backtick run inside it.

    Its ledger ids, run-state markers and chat-template control tokens are
    written out first, as a sample's text is wherever a line holds it.
    """
    from malspark.utils.written_forms import sample_written_out, template_tokens_written_out

    # A chat template's control token is written out as a prompt hint writes it.
    written = template_tokens_written_out(sample_written_out(text))
    longest = max((len(run) for run in re.findall(r"`+", written)), default=0)
    if not longest:
        return f"`{written}`"
    fence = "`" * (longest + 1)
    return f"{fence} {written} {fence}"


def launch_arguments_reason(record: Any) -> str | None:
    """The run's limitation where its launch arguments were not passed; ``None`` otherwise.

    ``record`` is the run's own record (``container.launch_record``), which
    exists whether or not a report does.
    """
    from malspark.providers.submission import not_honoured_reason

    return not_honoured_reason(record)


def observed_report(report: Any) -> dict[str, Any] | None:
    """``report`` when a sandbox produced it, ``None`` when none ran."""
    if sandbox_status(report).status == NOT_RUN:
        return None
    return report if isinstance(report, dict) else None


def names_another_target(report: Any) -> bool:
    """Whether the target ``report`` names is not the sample.

    The run's mark (its sandbox named a target that is not the sample), or a
    launch mark whose arguments a generated launcher carried: the sandbox was
    handed the archive, so the target it names is that archive. Nothing the
    report says of its target's file is then the sample's: not its hashes and
    size, nor its file type or operating system.
    """
    if not isinstance(report, dict):
        return False
    if isinstance(report.get(TARGET_KEY), Mapping):
        return True
    launch = report.get(LAUNCH_KEY)
    return isinstance(launch, Mapping) and isinstance(launch.get("launcher"), Mapping)


def sample_file_identity(report: Any, sample_path: Any, expected: str) -> dict[str, Any]:
    """The md5, sha1 and size the judge is given as the sample's own; ``{}`` with none.

    From the report's own file block, as the sandbox gave it, when the report
    carries no target mark. A marked report's block is of the target its
    sandbox named, not of the sample, so none of it is given as the sample's:
    the values are read from the sample's own bytes instead, and only where
    that copy still reads ``expected``, the intake SHA-256
    (``analysis.sample_integrity.sample_fingerprints``). Values so read carry
    :data:`IDENTITY_SOURCE_KEY` as :data:`FROM_SAMPLE_BYTES`; a copy that gave
    none carries it as :data:`FROM_ROUTER_ONLY` and no value, and the caller
    takes no size from it either (:func:`names_another_target`).
    """
    if names_another_target(report):
        from malspark.analysis.sample_integrity import sample_fingerprints

        read = sample_fingerprints(sample_path, expected)
        return {**read, IDENTITY_SOURCE_KEY: FROM_SAMPLE_BYTES if read else FROM_ROUTER_ONLY}
    target = report.get("target") if isinstance(report, dict) else None
    sandbox_file = target.get("file") if isinstance(target, dict) else None
    if not isinstance(sandbox_file, dict):
        return {}
    return {
        "md5": str(sandbox_file.get("md5") or ""),
        "sha1": str(sandbox_file.get("sha1") or ""),
        "size_bytes": sandbox_file.get("size") or "",
    }
