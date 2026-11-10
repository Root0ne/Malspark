"""Project path resolution utilities.

Provides a central, robust helper for discovering the project root directory
at runtime.  This eliminates the brittle ``os.path.dirname(...)`` chains that
break whenever a module is moved, and guarantees that relative paths in
configuration files are resolved against the actual project root — never
against the current working directory.
"""

from __future__ import annotations

import ntpath
import os
import posixpath
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

from malspark.core.exceptions import ProjectRootNotFoundError

# Markers that identify the project root directory
_ROOT_MARKERS: tuple[str, ...] = ("pyproject.toml", ".git")


def get_project_root(max_up: int = 8) -> Path:
    """Resolve the project root by walking up from this file.

    The search starts at the directory containing *this* module and walks
    upward until one of the :data:`_ROOT_MARKERS` files is found.  This is
    deterministic regardless of where the application is launched from.

    Args:
        max_up: Maximum number of parent directories to traverse.

    Returns:
        Absolute :class:`~pathlib.Path` to the project root.

    Raises:
        RuntimeError: If no root marker is found within ``max_up`` levels.
    """
    current = Path(__file__).resolve().parent
    for _ in range(max_up):
        if any((current / marker).exists() for marker in _ROOT_MARKERS):
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    raise ProjectRootNotFoundError(f"Could not locate project root (looked for {_ROOT_MARKERS})")


def resolve_data(path_like: str | Path) -> Path:
    """Resolve a relative ``data/...`` path against the project root.

    Returns absolute paths untouched (operator opt-out). Relative paths
    are joined onto :func:`get_project_root` so an arq worker started from
    ``apps/api/`` still finds ``data/sigma_rules`` at the repo root.

    Args:
        path_like: A string or :class:`~pathlib.Path` (e.g. from config).

    Returns:
        Absolute :class:`~pathlib.Path`.
    """
    p = Path(path_like)
    return p if p.is_absolute() else get_project_root() / p


def resolve_mcp_args(args: list[str]) -> list[str]:
    """Resolve relative paths inside MCP ``args`` against the project root.

    An argument is rooted at the project directory by the rule
    :func:`resolve_mcp_command` roots a command by, only when it is a relative
    path into it: it contains ``/`` (or ``\\`` where that is the platform's
    separator), is not absolute, carries no scheme or other colon
    (``https://…``, ``git+https://…``, an image reference's ``:tag``), does not
    start with ``-``, ``@`` (an npm ``@scope/pkg``) or ``~`` and holds no
    ``=``, its first component past any leading ``.`` exists under the project
    root, and the rooted path stays inside it (``scripts/dev/ghidra_manager.py``,
    ``./tools/x``, ``data/out/new.json``). Anything else — a package or image
    name, a URL, ``owner/repo``, a CLI flag, ``../x`` or ``scripts/../../x`` —
    reaches the child exactly as written; :func:`mcp_paths_leaving_project`
    names the last kind, so the launch can say it left them.

    This allows ``.env`` files to store portable relative paths such as
    ``scripts/dev/ghidra_manager.py`` instead of hard-coding host-specific
    absolute paths like ``/mnt/d/MyCodes/Malspark/scripts/dev/ghidra_manager.py``.

    Args:
        args: Raw argument list from :class:`~malspark.core.config.MCPServerConfig`.

    Returns:
        A new list with relative project paths resolved to absolute paths.
    """
    project_root = get_project_root()
    return [_rooted(arg, project_root)[0] for arg in args]


def mcp_paths_leaving_project(values: list[str]) -> list[str]:
    """The ``values`` written as a relative path that leaves the project, which are not rooted.

    ``../x``, ``./../x``, ``scripts/../../x``, or a path through a link that
    points outside the project: :func:`resolve_mcp_args` and
    :func:`resolve_mcp_command` leave each as written, read from the child's
    own working directory, rather than root it at the project as they root a
    relative path into it.
    """
    project_root = get_project_root()
    return [value for value in values if _rooted(value, project_root)[1]]


def resolve_mcp_command(command: str) -> str:
    """An MCP ``command`` rooted at the project root when it is a relative path into it.

    The rule :func:`resolve_mcp_args` roots an argument by: a value with no
    path separator (a bare program name such as ``npx`` or ``uvx``, looked up
    on the child's ``PATH``), an absolute path, ``~``, a scheme or option is
    left as written; ``\\`` is a separator only where the platform's is. A
    relative path is rooted only when its first component past any leading
    ``.`` exists under the project root and the rooted path stays inside it,
    so ``../x``, ``./../x`` and ``./missing/x`` are left as written, as the
    child reads them.
    """
    return _rooted(command)[0]


def _rooted(value: str, project_root: Path | None = None) -> tuple[str, bool]:
    """``value`` rooted at the project root when it is a relative path into it, else as written.

    With whether ``value`` was left as written because it is a relative path
    that leaves the project: by its ``..`` components, or through a link, as
    its real path is read (``link/passwd`` where ``link`` points outside),
    the containment ``launch_cwd`` reads a working directory by. A value whose
    path cannot be read here (too long, say) is left as written.
    ``project_root`` defaults to :func:`get_project_root`, read only for a
    value written as a path.
    """
    if not value or value.startswith(("-", "@", "~")) or ":" in value or "=" in value:
        return value, False
    written = value.replace("\\", "/") if os.sep == "\\" else value
    if "/" not in written or Path(written).is_absolute():
        return value, False
    parts = [part for part in written.split("/") if part]
    while parts and parts[0] == ".":
        parts.pop(0)
    if not parts:
        return value, False
    if parts[0] == "..":
        return value, True
    root = get_project_root() if project_root is None else project_root
    rooted = Path(os.path.normpath(root / written))
    if not rooted.is_relative_to(root):
        return value, True
    try:
        if not (root / parts[0]).exists():
            return value, False
        if not Path(os.path.realpath(rooted)).is_relative_to(root.resolve()):
            return value, True
    except (OSError, ValueError):
        return value, False
    return str(rooted), False


# A segment of a path in free text.
_SEGMENT = r"[\w.@%+~-]+"

# A Windows separator: a slash, or a run of backslashes (an OSError's repr and
# a JSON-escaped message write each backslash twice), read whole so a match
# never ends inside a run.
_WINDOWS_SEP = r"(?:\\++|/)"
# A device or long-path prefix before a drive: ``\\?\`` or ``\\.\``, either
# written once or with every backslash doubled.
_DEVICE = r"\\\\(?:\\\\)?[?.]\\\\?"
# The start of a Windows path: a drive letter, a colon and a separator, after
# a device prefix, or not after an ASCII letter or digit (``https:/``,
# ``error:\n`` are not drives) but after anything else (``a.C:\``,
# ``path:C:\``, ``日本C:\``, a JSON line break ``\nC:\``); or the two
# backslashes of a UNC path, not after another backslash.
_DRIVE_HEAD = rf"(?:(?<!\\){_DEVICE}|(?<![A-Za-z0-9])|(?<=\\[nrt]))[A-Za-z]:{_WINDOWS_SEP}"
_UNC_HEAD = r"(?<!\\)\\\\(?:\\\\)?"
# A character of a Windows file name: any a name may hold but ``( ) , ; '``,
# and never the letter that starts another drive (``a.C:\``).
_WINDOWS_CHAR = r"(?:(?![A-Za-z]:[\\/])[\w.@%+~$!#&^{}\[\]=-])"
_WINDOWS_MARK = r"[(),;']"
# A directory of a Windows path: a separator follows it, so its marks are its
# own, and it may hold up to eight single spaces (``John Smith``).
_WINDOWS_DIR = (
    rf"(?:{_WINDOWS_CHAR}|{_WINDOWS_MARK})+"
    rf"(?:[ \u00a0](?:{_WINDOWS_CHAR}|{_WINDOWS_MARK})+){{0,8}}(?={_WINDOWS_SEP})"
)
# The last name of a Windows path: ``( ) , ; '`` only before more of the name
# (``a(b)``, ``alice's``, ``(1).txt``, ``x,.'y``) that is not dots alone (a
# name never ends in one), so a mark or a full stop after the path stays
# outside it.
_WINDOWS_NAME = (
    rf"{_WINDOWS_MARK}*{_WINDOWS_CHAR}+"
    rf"(?:(?:\.*{_WINDOWS_MARK})+\.*(?!\.){_WINDOWS_CHAR}+)*"
)
# What follows a Windows path's head. A separator before a quote is the
# quote's escape in a JSON string (``\"``), never the path's.
_WINDOWS_TAIL = rf"(?:{_WINDOWS_DIR}{_WINDOWS_SEP}(?!\"))*(?:{_WINDOWS_NAME})?"
# A path past a server's name: the server, a separator and a name.
_SERVER_TAIL = (
    rf"{_WINDOWS_DIR}{_WINDOWS_SEP}(?!\")"
    rf"(?=[\w(),;'$!#&^{{}}\[\]=@%+~.-]){_WINDOWS_TAIL}"
)
# A ``file:`` URL naming a Windows path: a drive (``file:///C:/``) or another
# machine (``file://server/``, ``file:////server/``, ``file:\\server\``).
_WINDOWS_URL = rf"file:(?://(?:localhost)?/?[A-Za-z]:{_WINDOWS_SEP}|//(?!/|localhost/)|////|\\\\)"
# The start of a quoted Windows path.
_QUOTED_HEAD = rf"(?:{_DRIVE_HEAD}|{_UNC_HEAD}[?.\w]|{_WINDOWS_URL})"
_CLOSING = "\u2019\u201d\u00bb"

# An absolute path in free text, in either system's form:
#
# * a ``file://`` URL, read as its path: ``file:///C:/x`` as the drive path,
#   ``file://server/share``, ``file:////server/share`` and
#   ``file:\\server\share`` as a path on another machine;
# * a Windows path that follows a quote (``'``, ``"``, a backtick, ``‘``,
#   ``“`` or ``«``) and runs to its closing quote, spaces and all
#   (``'C:\Users\John Smith\x'``), as an OSError prints its name; the
#   backslash escaping a JSON quote (``\"``) stays outside it;
# * a Windows path: a drive (``C:\Users\x``, ``D:/a/b``, ``\\?\C:\x``) or a
#   UNC path (``\\server\share\x``, ``\\?\UNC\server\share``), its
#   separators single or doubled;
# * a POSIX path: a slash not after a word character, a colon, a dot or
#   another slash (a URL's ``//`` and a relative ``a/b`` are not one), then
#   path characters. A quoted POSIX path stops at a space, as it always has.
_ABSOLUTE_PATH = re.compile(
    rf"file://(?:localhost)?/?(?P<winurl>[A-Za-z]:{_WINDOWS_SEP}{_WINDOWS_TAIL})"
    rf"|file:(?://(?!/|localhost/)|////|\\\\(?:\\\\)?)"
    rf"(?P<remote>{_SERVER_TAIL}|{_WINDOWS_NAME})"
    r"|file://(?:localhost)?(?P<url>/[^\s'\"<>()]*)"
    rf"|(?<=(?P<quote>['\"`]))(?P<quoted>{_QUOTED_HEAD}"
    r"(?:(?!\\*(?P=quote))[^\r\n])*)(?=\\*(?P=quote))"
    rf"|(?<=[\u2018\u201c\u00ab])(?P<typographic>{_QUOTED_HEAD}[^\r\n{_CLOSING}]*)"
    rf"(?=[{_CLOSING}])"
    rf"|(?P<drive>{_DRIVE_HEAD}{_WINDOWS_TAIL})"
    rf"|(?P<unc>{_UNC_HEAD}(?:[?.]{_WINDOWS_SEP})?{_SERVER_TAIL})"
    rf"|(?<![\w:./])(?P<path>/{_SEGMENT}(?:/{_SEGMENT})*/?)"
)

# A Windows path: a drive letter, a colon and a separator, after an optional
# device prefix.
_DRIVE = re.compile(rf"(?:{_DEVICE})?[A-Za-z]:{_WINDOWS_SEP}")

# The Windows path a quoted span starts with, read as an unquoted one is: the
# rest of the span is words, read again in the form they are written in.
_SPAN_PATH = re.compile(
    rf"file://(?:localhost)?/?(?P<url>[A-Za-z]:{_WINDOWS_SEP}{_WINDOWS_TAIL})"
    rf"|{_DRIVE_HEAD}{_WINDOWS_TAIL}|{_UNC_HEAD}(?:[?.]{_WINDOWS_SEP})?{_SERVER_TAIL}"
)

# Inside a quoted span, past its own head: another drive, another URL, or a
# run of backslashes before a name (a UNC or device head) at least twice as
# long as the span's shortest separator, so a span written with doubled
# separators is read in its own style.
_SPAN_LEAD = re.compile(r"(?:file:(?://(?:localhost)?/?|[\\/]*))?\\*(?:[?.]\\*)?(?:[A-Za-z]:)?")
_ANOTHER_HEAD = re.compile(r"(?:(?<![A-Za-z0-9])|(?<=\\[nrt]))[A-Za-z]:[\\/]|file:[\\/]")
_BACKSLASHES = re.compile(r"\\+")
_BACKSLASHES_BEFORE_A_NAME = re.compile(r"(?<!\\)\\{2,}(?=[?.\w])")


def _holds_another_path(span: str) -> bool:
    """Whether a quoted span starting with a Windows path holds another one.

    The span is then not one path, and where each ends cannot be read (a name
    may hold a space), so it is masked whole rather than shown in part.
    """
    lead = _SPAN_LEAD.match(span)
    end = lead.end() if lead else 0
    if _ANOTHER_HEAD.search(span, end):
        return True
    runs = [len(run.group()) for run in _BACKSLASHES.finditer(span)]
    if span.startswith("\\"):  # a UNC or device head: two separators' worth
        runs[0] //= 2
    width = max(1, min(runs, default=1))
    return any(
        len(run.group()) >= 2 * width for run in _BACKSLASHES_BEFORE_A_NAME.finditer(span, end)
    )


# The directories a host keeps its own files under. A path that starts with one
# of them is the host's layout; anything else that reads as one (an HTTP route,
# ``/api/v1/jobs``) is left as written. Nothing is looked up on the host, so
# the same words mask the same way wherever they are rendered. The list is the
# union of the layouts a host may have, not the running host's alone: the
# second line is macOS's (its temporary and variable directories resolve under
# /private, its users under /Users), so a path written there is masked too. A
# Windows path (``C:\...``) is the host's layout on any drive.
HOST_ROOTS = (
    *("/home", "/tmp", "/opt", "/var", "/root", "/srv", "/mnt", "/media", "/usr", "/etc"),
    *("/private", "/Users", "/Volumes", "/Library", "/System", "/Applications"),
)

# What a path off the project is shown as: the host's layout is not the reader's.
OUTSIDE_PROJECT = "a path outside the project"


def _written_path(written: str) -> PurePosixPath | PureWindowsPath:
    """A path read from words, in the form it is written in rather than the host's.

    A Windows path's separators are read single, a device prefix (``\\\\?\\``,
    ``\\\\.\\``) is dropped before a drive, and ``\\\\?\\UNC\\`` is read as the
    UNC path it names, so a root written either way is the same root.
    """
    if not (_DRIVE.match(written) or written.startswith("\\")):
        return PurePosixPath(posixpath.normpath(written))
    unc = written.startswith("\\")
    body = re.sub(r"\\+", r"\\", written.replace("/", "\\"))
    if unc:
        if body[1:3] in ("?\\", ".\\"):
            rest = body[3:]
            if rest[:4].upper() == "UNC\\":
                body = "\\\\" + rest[4:]
            elif _DRIVE.match(rest):
                body = rest
            else:  # a device other than a drive: never a path in the project
                body = "\\\\.\\" + rest
        else:
            body = "\\" + body
    return PureWindowsPath(ntpath.normpath(body))


def _from_root(
    path: PurePosixPath | PureWindowsPath, root: PurePosixPath | PureWindowsPath
) -> str | None:
    """``path`` as written from ``root`` when it is strictly inside it, else ``None``.

    Compared part by part: ``is_relative_to`` walks every parent of the path,
    each built anew, so a path of many parts (tool output can be hostile)
    costs the square of its length.
    """
    count = len(root.parts)
    if type(path) is not type(root) or len(path.parts) <= count:
        return None
    if type(path)(*path.parts[:count]) != root:
        return None
    return type(path)(*path.parts[count:]).as_posix()


def host_paths_masked(text: str, project_root: Path | None = None) -> str:
    """``text`` with each host path shown from the project root, or masked outside it.

    For words a report or an answer to any signed-in user carries: a path in
    the project reads as the operator wrote it relative to the root
    (``data/sigma_rules``), and a host path outside it as
    :data:`OUTSIDE_PROJECT`, never as the host's own layout. A host path is
    one under :data:`HOST_ROOTS` or one of the project's parents, or any
    Windows path (a drive, a UNC or a device path), on any host; a
    ``file://`` URL is read as its path. Anything else that
    starts with a slash (an HTTP route) is kept. Read from the words alone,
    never from the host's files, and in the form each path is written in, so a
    reason masked when it is written reads the same wherever it is shown, and
    a Windows project's paths are read as a POSIX project's are.
    """
    root = _written_path(str(get_project_root() if project_root is None else project_root))
    parents = tuple(
        str(parent)
        for parent in root.parents
        if isinstance(root, PurePosixPath) and parent != PurePosixPath(parent.anchor)
    )

    def shown(match: re.Match[str]) -> str:
        quoted = match.group("quoted") or match.group("typographic")
        if quoted:
            return spanned(quoted)
        if match.group("remote"):  # a path on another machine
            return OUTSIDE_PROJECT
        windows = match.group("winurl") or match.group("drive") or match.group("unc")
        path = _written_path(windows or match.group("url") or match.group("path"))
        relative = _from_root(path, root)
        if relative is not None:
            # A name holding a space may run into the words after it; one
            # that reaches another path is not shown in part.
            spaced = windows and re.search(r"[ \u00a0]", windows)
            return OUTSIDE_PROJECT if spaced and _holds_another_path(windows) else relative
        if isinstance(path, PureWindowsPath) or match.group("url"):
            return OUTSIDE_PROJECT
        text = str(path)
        held = any(text == top or text.startswith(top + "/") for top in (*HOST_ROOTS, *parents))
        return OUTSIDE_PROJECT if held else match.group(0)

    def spanned(span: str) -> str:
        """A quoted span starting with a Windows path, spaces and all.

        Outside the project, or holding a second path, it is masked whole:
        where each path ends cannot be read (a name may hold a space). A path
        in the project is shown from the root, and the words after it in the
        span are read again as written, so nothing path-shaped in them is left.
        """
        head = None if _holds_another_path(span) else _SPAN_PATH.match(span)
        written = head and (head.group("url") or head.group())
        relative = _from_root(_written_path(written), root) if written else None
        if head is None or relative is None:
            return OUTSIDE_PROJECT
        return relative + _ABSOLUTE_PATH.sub(shown, span[head.end() :])

    return _ABSOLUTE_PATH.sub(shown, str(text or ""))
