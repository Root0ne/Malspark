"""A generated launcher: launch arguments carried by a script inside the submitted archive.

A sandbox whose submission API has no command-line field, but which runs a
script picked from a submitted archive, can still start a sample with a job's
launch arguments: the archive holds the sample beside a launcher script that
starts it, and the submission names the script as the file to run. This module
is the provider-independent half: a pure builder from the sample's bytes, its
name, the arguments and a script type to the archive's bytes and a record of
what was built. A provider declares that it honours arguments this way
(:class:`LauncherSupport`) and sends the archive; nothing here knows a product.

The build is deterministic: member names are generated (the sample as
``sample.exe``, the launcher under a neutral name),
members are stored in a fixed order, uncompressed, with fixed timestamps,
attributes and creating system, so the same inputs give the same archive and
digest on any platform. Standard library only; no shell and no subprocess: the
arguments are never executed or interpreted here, only written into the
launcher text with the quoting its script type needs.

Script types:

* ``ps1`` (PowerShell). The script resolves its own folder from
  ``$MyInvocation.MyCommand.Path`` (set from PowerShell 2.0 on for a script
  started from its file, where ``$PSScriptRoot`` is not); where its content is
  run some other way there is no script path, and the folder is the current
  location. The sample is started by ``System.Diagnostics.Process.Start``
  with a ``ProcessStartInfo`` whose ``FileName`` is the sample's path in that
  folder (joined by ``System.IO.Path``, never read as a wildcard pattern),
  whose ``WorkingDirectory`` is that folder, whose ``UseShellExecute`` is off
  (no shell association is consulted) and whose ``Arguments`` is ONE string.
  That string is the process's argument string as it stands: it is not split
  or re-quoted, so the program reads exactly what the operator typed after
  its name. In a single-quoted literal nothing is expanded (no ``$``,
  backtick or ``%``); the only escape is a doubled quote, and PowerShell reads
  four typographic marks (U+2018, U+2019, U+201A, U+201B) as single quotes as
  well, so each is doubled too. The file is UTF-8 with a byte order mark, which
  Windows PowerShell 5 needs to read non-ASCII text as it is.
* A batch launcher is not built: ``cmd`` expands ``%`` and treats ``^``, ``&``,
  ``|``, ``<``, ``>`` and ``!`` as its own syntax inside a script, and reads its
  file in the console's code page, so arguments could not pass through it
  as they were typed.

A value a script type cannot carry faithfully is refused with its reason
(:class:`LauncherRefused`), never guessed at.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from malspark.providers.submission import LaunchArgumentsAnswer, launch_arguments_problem

PS1 = "ps1"

# Typographic marks PowerShell reads as a single quote inside a literal.
_PS_QUOTES = "'‘’‚‛"
_BOM = b"\xef\xbb\xbf"
_LAUNCHER_STEM = "launch"
# The sample's generated name: the builder starts only a PE program that is
# not a DLL, and a program started by its path needs the extension Windows
# runs it by, whatever the upload was called.
SAMPLE_MEMBER = "sample.exe"
# 1980-01-01 is the earliest time a zip member can carry.
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)

SCRIPT_HOSTS = {PS1: "PowerShell"}
# The image names of each script type's host, as a sandbox's process list names
# the process that runs the launcher (``schemas.sandbox_report.attribute_the_launcher``).
SCRIPT_HOST_IMAGES = {PS1: ("powershell.exe", "pwsh.exe")}
# How the record and the report name the launcher, by script type.
LAUNCHER_PHRASES = {PS1: "a generated PowerShell launcher in the submitted archive"}


class LauncherRefused(ValueError):
    """The arguments, the sample or the script type cannot be carried by a launcher; says why."""


@dataclass(frozen=True)
class LauncherSupport:
    """What a provider declares when it honours launch arguments through a launcher.

    ``script_types`` are the script types its sandbox can run when picked from
    an archive, in order of preference; ``picked_by`` says how the submission
    tells the sandbox which member to run, in the words the record states.
    """

    script_types: tuple[str, ...]
    picked_by: str


@dataclass(frozen=True)
class BuiltLauncher:
    """The archive to submit and the record of what it holds.

    The archive, about the sample's size, is left out of the default repr.
    """

    archive: bytes = field(repr=False)
    record: dict[str, Any]


def _is_pe_program(sample: bytes) -> bool:
    """Whether ``sample`` is a PE image that is not a DLL: a program a launcher starts."""
    if sample[:2] != b"MZ" or len(sample) < 0x40:
        return False
    offset = int.from_bytes(sample[0x3C:0x40], "little")
    if offset + 24 > len(sample) or sample[offset : offset + 4] != b"PE\0\0":
        return False
    characteristics = int.from_bytes(sample[offset + 22 : offset + 24], "little")
    return not characteristics & 0x2000


def powershell_literal(text: str) -> str:
    """``text`` as one PowerShell single-quoted literal: each quote mark doubled, nothing else."""
    return "'" + "".join(ch * 2 if ch in _PS_QUOTES else ch for ch in text) + "'"


def launcher_text(script_type: str, sample_member: str, arguments: str) -> str:
    """The launcher's exact text for ``script_type``, ending in a line break."""
    if script_type != PS1:
        raise LauncherRefused(
            f"no {script_type!r} launcher is built (only {PS1}): a batch launcher would let "
            "cmd expand % and read ^, &, | and non-ASCII text as its own"
        )
    return "".join(
        f"{line}\r\n"
        for line in (
            "$s = $MyInvocation.MyCommand.Path",
            "if ($s) { $d = [IO.Path]::GetDirectoryName($s) } "
            "else { $d = (Get-Location).ProviderPath }",
            "$i = New-Object Diagnostics.ProcessStartInfo",
            f"$i.FileName = [IO.Path]::Combine($d, {powershell_literal(sample_member)})",
            f"$i.Arguments = {powershell_literal(arguments)}",
            "$i.WorkingDirectory = $d",
            "$i.UseShellExecute = $false",
            "[void][Diagnostics.Process]::Start($i)",
        )
    )


def build_launcher_archive(
    sample: bytes, sample_name: str, arguments: str, script_type: str = PS1
) -> BuiltLauncher:
    """The archive holding ``sample`` and a launcher that starts it with ``arguments``.

    ``sample_name`` is the upload's own name, which the archive never carries:
    the sample's member is always :data:`SAMPLE_MEMBER`.

    Raises :class:`LauncherRefused` with the reason for a value the script type
    cannot carry faithfully: arguments that are not one command line
    (``providers.submission.launch_arguments_problem``) or that cannot be
    written as UTF-8, a sample that is not a Windows program (a launcher starts
    a program, and a DLL has no entry to start), an unknown script type.
    """
    problem = launch_arguments_problem(arguments)
    if problem:
        raise LauncherRefused(f"the arguments {problem}")
    try:
        text = launcher_text(script_type, SAMPLE_MEMBER, arguments)
        body = _BOM + text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LauncherRefused(
            "the arguments hold a character that cannot be written as UTF-8 text"
        ) from exc
    if not _is_pe_program(sample):
        raise LauncherRefused(
            "the sample is not a Windows program (a PE image that is not a DLL), "
            "which is all a launcher starts"
        )
    sample_member = SAMPLE_MEMBER
    launcher_member = f"{_LAUNCHER_STEM}.{script_type}"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for member, data in ((sample_member, sample), (launcher_member, body)):
            info = zipfile.ZipInfo(member, date_time=_FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    blob = buffer.getvalue()
    return BuiltLauncher(
        archive=blob,
        record={
            "script_type": script_type,
            "script_host": SCRIPT_HOSTS[script_type],
            "script_host_images": list(SCRIPT_HOST_IMAGES[script_type]),
            "launcher_member": launcher_member,
            "launcher_text": text,
            "launcher_encoding": "UTF-8 with a byte order mark",
            "launcher_sha256": hashlib.sha256(body).hexdigest(),
            "sample_member": sample_member,
            "archive_sha256": hashlib.sha256(blob).hexdigest(),
            "archive_bytes": len(blob),
            "sample_sha256": hashlib.sha256(sample).hexdigest(),
        },
    )


def build_for_submission(
    support: LauncherSupport, sample_path: str | Path, arguments: str
) -> BuiltLauncher:
    """The archive a provider submits in place of the bare sample, with its record.

    Reads the sample at ``sample_path`` and builds with the first script type of
    ``support`` that the builder knows; the record also names how the
    submission picks the launcher. Raises :class:`LauncherRefused`.
    """
    script_type = next((kind for kind in support.script_types if kind in SCRIPT_HOSTS), None)
    if script_type is None:
        raise LauncherRefused(
            f"none of the script types the provider runs ({', '.join(support.script_types)}) "
            "is one a launcher is built for"
        )
    path = Path(sample_path)
    try:
        sample = path.read_bytes()
    except OSError as exc:
        raise LauncherRefused(f"the sample could not be read ({type(exc).__name__})") from exc
    built = build_launcher_archive(sample, path.name, arguments, script_type)
    built.record["picked_by"] = support.picked_by
    return built


def launcher_answer(
    support: LauncherSupport, arguments: str, sample_path: str | Path | None
) -> LaunchArgumentsAnswer:
    """A provider's answer for arguments it carries through a launcher.

    Honoured, with the record of the archive that would be built, or not
    honoured with the reason a launcher cannot carry them.
    """
    if sample_path is None:
        return LaunchArgumentsAnswer(
            honoured=False,
            note="a launcher is built from the sample, and no sample file was given, "
            "so the sample was detonated without the arguments",
        )
    try:
        built = build_for_submission(support, sample_path, arguments)
    except LauncherRefused as exc:
        return LaunchArgumentsAnswer(
            honoured=False,
            note=f"a launcher cannot carry them: {exc}; the sample was detonated without them",
        )
    return LaunchArgumentsAnswer(
        honoured=True,
        via=LAUNCHER_PHRASES[str(built.record["script_type"])],
        launcher=built.record,
        built=built,
    )
