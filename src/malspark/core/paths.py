"""Project path resolution utilities.

Provides a central, robust helper for discovering the project root directory
at runtime.  This eliminates the brittle ``os.path.dirname(...)`` chains that
break whenever a module is moved, and guarantees that relative paths in
configuration files are resolved against the actual project root — never
against the current working directory.
"""

from __future__ import annotations

import ast
import functools
import json
import ntpath
import os
import posixpath
import re
import warnings
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

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
_DRIVE_START = r"(?:(?<!\\)" + _DEVICE + r"|(?<![A-Za-z0-9])|(?<=\\[nrt]))"
_DRIVE_HEAD = rf"{_DRIVE_START}[A-Za-z]:{_WINDOWS_SEP}"
# A UNC path starts with backslashes in pairs: two as written, four in a
# repr or a JSON string, eight in a repr of one.
_UNC_HEAD = r"(?<!\\)(?:\\\\)++"
# A space inside a name: an ASCII, no-break, thin or other fixed-width space,
# every space separator but a line's or a paragraph's.
_WINDOWS_SPACES = " \u00a0\u1680\u2000-\u200a\u202f\u205f\u3000"
_WINDOWS_SPACE = rf"[{_WINDOWS_SPACES}]"
# One of them that is not the ASCII space: a name may start or end with it
# (Windows trims no such space), where an ASCII space ends the words.
_WINDOWS_EDGE_SPACE = rf"[{_WINDOWS_SPACES[1:]}]?"
# A character of a Windows file name: any Windows does not forbid in one
# (``< > : " / \ | ? *`` and control characters), but a space and the marks
# below, and never the letter that starts another drive (``a.C:\``).
_WINDOWS_CHAR = r"(?:(?![A-Za-z]:[\\/])[^\s<>:\"/\\|?*\x00-\x1f(),;'`\u2019\u201d\u00bb])"
# A mark a name may hold that also closes words: ``( ) , ; '``, a backtick and
# a closing typographic quote.
_WINDOWS_MARK = r"[(),;'`\u2019\u201d\u00bb]"
# What an escaped text writes after the backslashes of an escape that is part
# of a name: a character by its code (``\u00e9``) or an apostrophe (``\'``).
_ESCAPED = r"(?:u[0-9A-Fa-f]{4}|')"


@dataclass(frozen=True)
class _Writing:
    """What follows a Windows path's head, for one way its backslashes are written.

    A text writes a path as it is (``C:\\Users\\x``), or escaped once or more:
    a repr or a JSON string doubles each backslash and writes a character
    that is not ASCII as ``\\uXXXX``, and a repr of that doubles them again.
    So a path's own separators say how to read a backslash inside it: in a
    path written as it is, every run of backslashes separates two names
    (``John Smith\\uabcd.txt`` is two names); in a path whose separators are
    ``width`` backslashes, a shorter run before ``uXXXX`` or an apostrophe is
    that character, part of the name (the text was escaped after the path
    was written), and any other run separates. A path written with slashes
    shows no width, so there any run before ``uXXXX`` or an apostrophe is
    the character. No run of backslashes ends a path but the one escaping a
    JSON quote.
    """

    separator: str
    char: str
    mark: str

    @classmethod
    def of(cls, width: int | None) -> _Writing:
        """A path whose separators are ``width`` backslashes; ``None`` for slashes."""
        if width == 1:
            return cls(r"(?:/?\\++/?|/)", _WINDOWS_CHAR, _WINDOWS_MARK)
        run = r"\\++" if width is None else rf"(?<!\\)\\{{1,{width - 1}}}"
        escape = rf"{run}(?={_ESCAPED})"
        return cls(
            rf"(?:/?(?!{escape})\\++/?|/)",
            rf"(?:{run}u[0-9A-Fa-f]{{4}}|{_WINDOWS_CHAR})",
            rf"(?:{run}'|{_WINDOWS_MARK})",
        )

    @property
    def directory(self) -> str:
        """A directory: a separator follows it, so its marks are its own, and it
        may hold up to eight single spaces (``John Smith``)."""
        word = rf"(?:{self.char}|{self.mark})+"
        return (
            rf"{_WINDOWS_EDGE_SPACE}{word}(?:{_WINDOWS_SPACE}{word}){{0,8}}"
            rf"{_WINDOWS_EDGE_SPACE}(?={self.separator})"
        )

    @property
    def name(self) -> str:
        """The last name: a mark only before more of the name (``a(b)``,
        ``alice's``, ``(1).txt``, ``.(x)``) and dots only before more of it (a
        name never ends in one), so a mark or a full stop after the path
        stays outside it."""
        run = rf"(?:\.*+(?!\.){self.char})+"
        return rf"{_WINDOWS_EDGE_SPACE}(?:\.*+{self.mark})*{run}(?:(?:\.*{self.mark})+{run})*"

    @property
    def tail(self) -> str:
        """What follows the head. A separator before a quote is the quote's
        escape in a JSON string (``\\"``), never the path's."""
        return rf"(?:{self.directory}{self.separator}(?!\"))*+(?:{self.name})?"

    @property
    def server(self) -> str:
        """A path past a server's name: the server, a separator and a name."""
        return (
            rf"{self.directory}{self.separator}(?!\")"
            rf"(?={_WINDOWS_EDGE_SPACE}(?:{self.char}|{self.mark})){self.tail}"
        )


_AS_WRITTEN = _Writing.of(1)
_ESCAPED_ONCE = _Writing.of(2)
_ESCAPED_TWICE = _Writing.of(4)
_ESCAPED_MORE = _Writing.of(8)
# The separator a head ends with, and the writing it shows: one backslash is
# a path as written, two or three one escaped once, four to seven twice,
# more than that further still; a slash shows none.
_BY_SEPARATOR_BACK = (
    (r"\\(?!\\)/?", _AS_WRITTEN),
    (r"\\{2,3}(?!\\)", _ESCAPED_ONCE),
    (r"\\{4,7}(?!\\)", _ESCAPED_TWICE),
    (r"\\{8,}+", _ESCAPED_MORE),
)


class _Slashed(_Writing):
    @property
    def tail(self) -> str:
        backs = "|".join(rf"{sep}(?!\"){how.tail}" for sep, how in _BY_SEPARATOR_BACK)
        return (
            rf"(?:{self.directory}/(?![\\\"]))*+(?:(?:{self.directory}/?)?(?:{backs})|{self.name})?"
        )


_SLASHED = _Slashed(**vars(_Writing.of(None)))
_BY_SEPARATOR = (*_BY_SEPARATOR_BACK, (r"/", _SLASHED))
# The backslashes a UNC path starts with, in pairs, and the writing they show.
# In an escaped text one more may follow them: the backslash of the escape
# the server's name starts with (``\\\\\u00e9tage`` in a JSON string).
_ESCAPE_NEXT = rf"\\(?={_ESCAPED})"
_BY_UNC_HEAD = (
    (r"\\\\(?!\\)", _AS_WRITTEN),
    (rf"(?:\\\\){{2,3}}(?:(?!\\)|{_ESCAPE_NEXT})", _ESCAPED_ONCE),
    (rf"(?:\\\\){{4,7}}(?:(?!\\)|{_ESCAPE_NEXT})", _ESCAPED_TWICE),
    (rf"(?:\\\\){{8,}}+(?:{_ESCAPE_NEXT})?", _ESCAPED_MORE),
)


def _after_separator(*, quote_guard: bool = False) -> str:
    """A head's last separator and the path after it, in the writing it shows."""
    guard = r"(?!\")" if quote_guard else ""
    return "(?:" + "|".join(rf"{sep}{guard}{how.tail}" for sep, how in _BY_SEPARATOR) + ")"


# A UNC path past its backslashes: an optional device mark (``?`` or ``.``)
# and its separator, then the server and a name.
# Two backslashes are a UNC path as written or one backslash escaped once
# (a registry key or a regex in a JSON string): the separator after the
# server tells which.
_BY_SERVER_SEPARATOR = "|".join(
    rf"{_AS_WRITTEN.directory}{sep}(?!\")(?={_WINDOWS_EDGE_SPACE}(?:{how.char}|{how.mark})){how.tail}"
    for sep, how in (*_BY_SEPARATOR_BACK, (r"/", _AS_WRITTEN))
)
_AFTER_UNC_HEAD = (
    r"(?<!\\)(?:"
    + rf"\\\\(?!\\)(?:[?.]{_AS_WRITTEN.separator}{_AS_WRITTEN.server}|(?:{_BY_SERVER_SEPARATOR}))|"
    + "|".join(rf"{head}(?:[?.]{how.separator})?{how.server}" for head, how in _BY_UNC_HEAD[1:])
    + ")"
)
# A character or a mark a name may start with in any writing, to tell a head
# from a run of backslashes before something else.
_ANY_CHAR = rf"(?:\\*+u[0-9A-Fa-f]{{4}}|{_WINDOWS_CHAR})"
# A ``file:`` URL naming a Windows path: a drive (``file:///C:/``) or another
# machine (``file://server/``, ``file:////server/``, ``file:\\server\``).
# The scheme is read in any case (``File:``, ``FILE:``).
_FILE = r"(?i:file):"
_WINDOWS_URL = rf"{_FILE}(?://(?:localhost)?/?[A-Za-z]:{_WINDOWS_SEP}|//(?!/|localhost/)|////|\\\\)"
# The start of a quoted Windows path.
_QUOTED_HEAD = rf"(?:{_DRIVE_HEAD}|{_UNC_HEAD}(?:[?.]|{_ANY_CHAR})|{_WINDOWS_URL})"
_OPENING = "\u2018\u201c\u00ab"
_CLOSING = "\u2019\u201d\u00bb"
# A machine's name and path in a ``file:`` URL, in the writing its head shows:
# slashes, two backslashes (as written) or four (escaped once).
_REMOTE = (
    rf"(?:(?<=/)(?:{_SLASHED.server}|{_SLASHED.name})"
    rf"|(?<=:\\\\)(?:{_AS_WRITTEN.server}|{_AS_WRITTEN.name})"
    rf"|(?<=:\\\\\\\\)(?:{_ESCAPED_ONCE.server}|{_ESCAPED_ONCE.name}))"
)

# An absolute path in free text, in either system's form:
#
# * a Windows path that follows a quote (``'``, ``"``, a backtick, ``‘``,
#   ``“`` or ``«``) and runs to its closing quote, spaces and all
#   (``'C:\Users\John Smith\x'``), as an OSError prints its name; the
#   backslash escaping a JSON quote (``\"``) stays outside it;
# * a ``file://`` URL, read as its path: ``file:///C:/x`` as the drive path,
#   ``file://server/share``, ``file:////server/share`` and
#   ``file:\\server\share`` as a path on another machine;
# * the host's home directory as written in the text, its whole name a path
#   even where it holds a space (``C:\Users\John Smith``), and the path
#   after it read as any other;
# * a Windows path: a drive (``C:\Users\x``, ``D:/a/b``, ``\\?\C:\x``) or a
#   UNC path (``\\server\share\x``, ``\\?\UNC\server\share``), its
#   separators written once or escaped;
# * a POSIX path: a slash not after a word character, a colon, a dot or
#   another slash (a URL's ``//`` and a relative ``a/b`` are not one), then
#   path characters. A quoted POSIX path stops at a space, as it always has.
#
# Each text is read once over: a quoted span reads a run of backslashes
# whole, and a typographic one never runs past another opening quote, so no
# character is read again from each quote or backslash before it.
_BEFORE_HOME = (
    rf"(?<=(?P<quote>['\"`]))(?P<quoted>{_QUOTED_HEAD}"
    r"(?:(?!(?P=quote))[^\\\r\n]|\\++(?!(?P=quote)))*+)(?=\\*(?P=quote))"
    rf"|(?<=[{_OPENING}])(?P<typographic>{_QUOTED_HEAD}[^\r\n{_OPENING}{_CLOSING}]*+)"
    rf"(?=[{_CLOSING}])"
    rf"|{_FILE}//(?:localhost)?/?(?P<winurl>[A-Za-z]:{_after_separator()})"
    rf"|{_FILE}(?://(?!/|localhost/)|////|\\\\(?:\\\\)?)(?P<remote>{_REMOTE})"
    r"|file://(?:localhost)?(?P<url>/[^\s'\"<>()]*)"
)
_AFTER_HOME = (
    rf"(?P<drive>{_DRIVE_START}[A-Za-z]:{_after_separator()})"
    rf"|(?P<unc>{_AFTER_UNC_HEAD})"
    rf"|(?<![\w:./])(?P<path>/{_SEGMENT}(?:/{_SEGMENT})*/?)"
)


def _home_literal(home: str) -> str:
    """The pattern of the home directory ``home`` as a text may write it, or one matching nothing.

    A Windows home is read without case, with any separator style and after
    the head a drive path has; a POSIX one as written. Either holds the whole
    of its last name, so ``/home/John Smith`` is not ``/home/John Smithy``.
    """
    written = _written_path(home) if home else PurePosixPath("/")
    names = [name for name in written.parts[1:] if name]
    if not names or not written.is_absolute():
        return "(?!)"
    if isinstance(written, PurePosixPath):
        body = "".join("/" + re.escape(name) for name in names)
        return rf"(?<![\w:./]){body}(?!\.*+[\w@%+~-])(?:/{_SEGMENT})*/?"
    anchor = written.drive
    if _DRIVE.match(anchor + "\\"):
        head = rf"{_DRIVE_START}(?i:{re.escape(anchor)})"
    else:  # a UNC home: \\server\share
        server, share = anchor.strip("\\").split("\\", 1)
        head = rf"{_UNC_HEAD}(?i:{re.escape(server)}){_WINDOWS_SEP}(?i:{re.escape(share)})"
    body = "".join(rf"{_WINDOWS_SEP}(?i:{re.escape(name)})" for name in names)
    return (
        rf"{head}{body}(?!(?:\.|{_WINDOWS_MARK})*+(?!\.){_WINDOWS_CHAR})"
        rf"{_after_separator(quote_guard=True)}?"
    )


@functools.lru_cache(maxsize=8)
def _absolute_path(home: str) -> re.Pattern[str]:
    """Every absolute path in free text, the home directory ``home`` among them."""
    return re.compile(rf"{_BEFORE_HOME}|(?P<home>{_home_literal(home)})|{_AFTER_HOME}")


# A Windows path: a drive letter, a colon and a separator, after an optional
# device prefix.
_DRIVE = re.compile(rf"(?:{_DEVICE})?[A-Za-z]:{_WINDOWS_SEP}")

# The Windows path a quoted span starts with, read as an unquoted one is: the
# rest of the span is words, read again in the form they are written in.
_SPAN_PATH = re.compile(
    rf"{_FILE}//(?:localhost)?/?(?P<url>[A-Za-z]:{_after_separator()})"
    rf"|{_DRIVE_START}[A-Za-z]:{_after_separator()}|{_AFTER_UNC_HEAD}"
)

# Inside a quoted span, past its own head: another drive, another URL, or a
# run of backslashes before a name (a UNC or device head) at least twice as
# long as the span's shortest separator, so a span written with doubled
# separators is read in its own style.
_SPAN_LEAD = re.compile(rf"(?:{_FILE}(?://(?:localhost)?/?|[\\/]*))?\\*(?:[?.]\\*)?(?:[A-Za-z]:)?")
_ANOTHER_HEAD = re.compile(rf"(?:(?<![A-Za-z0-9])|(?<=\\[nrt]))[A-Za-z]:[\\/]|{_FILE}[\\/]")
_BACKSLASHES = re.compile(r"\\+")
_SPACE = re.compile(_WINDOWS_SPACE)
_BACKSLASHES_BEFORE_A_NAME = re.compile(rf"(?<!\\)\\{{2,}}+(?=[?.]|{_ANY_CHAR})")


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


def _read_root(
    project_root: PurePath | None,
) -> tuple[PurePosixPath | PureWindowsPath, tuple[str, ...]]:
    """The project root as written, and the parents a POSIX root's host keeps."""
    root = _written_path(str(get_project_root() if project_root is None else project_root))
    parents = tuple(
        str(parent)
        for parent in root.parents
        if isinstance(root, PurePosixPath) and parent != PurePosixPath(parent.anchor)
    )
    return root, parents


def _held(path: PurePosixPath, parents: tuple[str, ...]) -> bool:
    """Whether a POSIX path is the host's layout: under a host root or a project parent."""
    text = str(path)
    return any(text == top or text.startswith(top + "/") for top in (*HOST_ROOTS, *parents))


# A text that writes another: a JSON document, or one Python string literal.
# Its strings are read as the words they write, so a path in them is read in
# the form it was written in before the text was escaped, however many times.
_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*+"', re.DOTALL)
# Where a Windows-form path may start: a drive, two backslashes or a ``file:``
# URL. Only a string holding one is read through its escapes; any other reads
# as the text writes it.
_WINDOWS_FORM = re.compile(rf"[A-Za-z]:[\\/]|\\\\|{_FILE}")
_STARTS_QUOTED = re.compile(_QUOTED_HEAD)
# How deep a text written inside a text is followed.
_WRITTEN_DEPTH = 4
# A drive whose separator the string writes once: in a string that escapes
# its backslashes, a path written as it is (``D:\new\report.txt``).
_WRITTEN_AS_IT_IS = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:\\(?![\\/])")
# Half of a pair: a JSON string may write one escaped, and no UTF-8 text holds it.
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _json_document(text: str) -> bool:
    """Whether ``text`` is one JSON document holding a string."""
    if text.lstrip()[:1] not in ("{", "[", '"'):
        return False
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return False
    return True


def _string_literal(text: str) -> str | None:
    """The string ``text`` writes when it is the repr of one, else ``None``.

    Only a repr as Python writes it: words in quotes that merely parse as a
    literal (``'\\\\srv\\share'`` does, a backslash before ``s`` being kept)
    are words in quotes, read as they stand.
    """
    stripped = text.strip()
    if len(stripped) < 2 or stripped[0] not in "'\"" or stripped[-1] != stripped[0]:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            value = ast.literal_eval(stripped)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None
    return value if isinstance(value, str) and repr(value) == stripped else None


def _home() -> str:
    """The running host's home directory, or nothing where it cannot be read."""
    try:
        return str(Path.home())
    except (RuntimeError, KeyError, OSError):
        return ""


def host_path_masked(path: str | os.PathLike[str], project_root: PurePath | None = None) -> str:
    """One path a caller holds, shown from the project root, or masked outside it.

    The whole value is the path, whatever characters it holds (a space, a
    parenthesis, a quote), never words: inside the project it reads relative
    to the root (``data/capa-rules``); any other absolute path, in either
    system's form and under any directory, and a path from a home directory
    (``~/x``) read as :data:`OUTSIDE_PROJECT`. A relative path is kept.
    """
    written = os.fspath(path)
    root, _parents = _read_root(project_root)
    read = _written_path(written)
    relative = _from_root(read, root)
    if relative is not None:
        return relative
    if isinstance(read, PureWindowsPath) or read.is_absolute() or written.startswith("~"):
        return OUTSIDE_PROJECT
    return written


def host_paths_masked(
    text: str, project_root: PurePath | None = None, home: PurePath | str | None = None
) -> str:
    """``text`` with each host path shown from the project root, or masked outside it.

    For words a report or an answer to any signed-in user carries: a path in
    the project reads as the operator wrote it relative to the root
    (``data/sigma_rules``), and a host path outside it as
    :data:`OUTSIDE_PROJECT`, never as the host's own layout. A host path is
    one under :data:`HOST_ROOTS` or one of the project's parents, the home
    directory (``home``, the running host's by default) written whole, spaces
    and all, or any Windows path (a drive, a UNC or a device path), on any
    host; a ``file://`` URL is read as its path. Anything else that
    starts with a slash (an HTTP route) is kept. Read from the words alone,
    never from the host's files, and in the form each path is written in, so a
    reason masked when it is written reads the same wherever it is shown, and
    a Windows project's paths are read as a POSIX project's are. A text that
    writes another (a JSON document, a Python string literal) and holds a
    Windows-form path is read through its escapes, each string as the words
    it writes, and written back the same way, so it is still that document.
    A caller holding one path rather than words masks it with
    :func:`host_path_masked`.
    """
    root, parents = _read_root(project_root)
    pattern = _absolute_path(_home() if home is None else str(home))

    def shown(match: re.Match[str]) -> str:
        quoted = match.group("quoted") or match.group("typographic")
        if quoted:
            return spanned(quoted)
        if match.group("remote"):  # a path on another machine
            return OUTSIDE_PROJECT
        homed = match.group("home")
        windows = match.group("winurl") or match.group("drive") or match.group("unc")
        if homed and (_DRIVE.match(homed) or homed.startswith("\\")):
            windows = homed
        path = _written_path(windows or homed or match.group("url") or match.group("path"))
        relative = _from_root(path, root)
        if relative is not None:
            # A name holding a space may run into the words after it; one
            # that reaches another path is not shown in part.
            spaced = windows and _SPACE.search(windows)
            return OUTSIDE_PROJECT if spaced and _holds_another_path(windows) else relative
        if homed or isinstance(path, PureWindowsPath) or match.group("url"):
            return OUTSIDE_PROJECT
        return OUTSIDE_PROJECT if _held(path, parents) else match.group(0)

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
        return relative + pattern.sub(shown, span[head.end() :])

    def within(words: str, depth: int) -> str:
        """The words a string writes: a path it starts with is the whole of it,
        as a quoted span's is; otherwise they are read as any text."""
        return spanned(words) if _STARTS_QUOTED.match(words) else read(words, depth)

    def read(words: str, depth: int) -> str:
        """``words`` masked, an escaped text read as the text it writes.

        A string of a JSON object or array that writes a Windows-form path is
        read as those words and written back escaped the same way; one that
        writes none is read as it stands. A text that is one string in quotes
        (a JSON string, a repr) may be an escaped text or words in quotes
        (``"C:\\new\\table"`` is both a string writing a line break and a
        path in quotes), so it is read both ways: what either shows is masked.
        """
        if depth < _WRITTEN_DEPTH and _WINDOWS_FORM.search(words):
            if _json_document(words):

                def string(token: re.Match[str]) -> str:
                    written = json.loads(token.group())
                    if not _WINDOWS_FORM.search(written):
                        return pattern.sub(shown, token.group())
                    said = within(written, depth + 1)
                    shows = token.group()
                    if said != written:
                        shows = _LONE_SURROGATE.sub(
                            lambda half: f"\\u{ord(half.group()):04x}",
                            json.dumps(said, ensure_ascii=shows.isascii()),
                        )
                    if _WRITTEN_AS_IT_IS.search(token.group()):
                        return pattern.sub(shown, shows)
                    return shows

                masked = _JSON_STRING.sub(string, words)
                if not words.lstrip().startswith('"'):
                    return masked
                words = masked
            else:
                written = _string_literal(words)
                if written is not None and _WINDOWS_FORM.search(written):
                    said = within(written, depth + 1)
                    if said != written:
                        lead = words[: len(words) - len(words.lstrip())]
                        words = lead + repr(said) + words[len(words.rstrip()) :]
        return pattern.sub(shown, words)

    return read(str(text or ""), 0)
