"""A Windows path in free text never leaves a name of its own behind (T-591).

Shapes patched one by one leave the next shape open, so the paths here are
built from a grammar: every head a Windows path starts with, every separator
style, segments from the whole legal file-name alphabet, and every context a
tool's error or a report writes a path in. Each path carries a marker as its
user-name segment and as its last one; once masked, no marker of a path
outside the project is left, a path inside it shows its project-relative part
alone, and masked JSON still parses. The cases are seeded, so a failure names
a case that is built again the same way.

Text without a Windows-form path is pinned too: a fixed corpus and the output
it has always had, on Linux and everywhere else.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import pytest

from malspark.core.paths import OUTSIDE_PROJECT, host_paths_masked

ROOT_NAME = "projroot"
ROOT = Path(f"D:\\{ROOT_NAME}")
SEED = 591
CASES = 4000

# The legal file-name alphabet: letters (some not ASCII), digits, and every
# mark a Windows name may hold.
_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789éüçğışÅñ日本語"
_MARKS = "$!#&^{}[](),;'=@%+~.-"

# How a path's separators are written: once, doubled (an OSError's repr, a
# JSON string), as slashes, or mixed.
STYLES = ("single", "doubled", "slash", "mixed")


@dataclass(frozen=True)
class Head:
    name: str
    # The head's words for a separator style: the backslash prefix as the
    # style writes it, then the head's own components.
    words: Callable[[str], tuple[str, list[str]]]
    url: bool = False
    drive: bool = False


def _prefix(style: str, backslashes: int) -> str:
    return "\\" * (backslashes * (2 if style == "doubled" else 1))


HEADS = (
    Head("drive", lambda s: ("", ["C:"]), drive=True),
    Head("drive lower", lambda s: ("", ["c:"]), drive=True),
    Head("unc", lambda s: (_prefix(s, 2), ["server", "share"])),
    Head("unc ip admin share", lambda s: (_prefix(s, 2), ["10.0.0.1", "c$"])),
    Head("long drive", lambda s: (_prefix(s, 2) + "?" + _prefix(s, 1), ["C:"])),
    Head(
        "long unc",
        lambda s: (_prefix(s, 2) + "?" + _prefix(s, 1), ["UNC", "server", "share"]),
    ),
    Head("device drive", lambda s: (_prefix(s, 2) + "." + _prefix(s, 1), ["C:"])),
    Head(
        "volume",
        lambda s: (_prefix(s, 2) + "?" + _prefix(s, 1), ["Volume{1234abcd-5e6f-7a8b}"]),
    ),
    Head("file drive url", lambda s: ("file:///", ["C:"]), url=True),
    Head("file host url", lambda s: ("file://", ["server", "share"]), url=True),
    Head("file four-slash url", lambda s: ("file:////", ["server", "share"]), url=True),
    Head("file backslash url", lambda s: ("file:" + _prefix(s, 2), ["server", "share"]), url=True),
)


def _sep(rng: random.Random, style: str) -> str:
    if style == "mixed":
        style = rng.choice(STYLES[:3])
    return {"single": "\\", "doubled": "\\\\", "slash": "/"}[style]


def _segment(rng: random.Random, banned: str, spaced: bool) -> str:
    """A legal name: never all dots, never ending in a dot or a space."""
    while True:
        chars = [
            rng.choice(_MARKS if rng.random() < 0.3 else _LETTERS) for _ in range(rng.randint(1, 7))
        ]
        chars = [c for c in chars if c not in banned]
        if spaced and len(chars) > 1 and rng.random() < 0.5:
            chars.insert(rng.randint(1, len(chars) - 1), " ")
        word = "".join(chars)
        if word.strip(".") and not word.endswith((".", " ")) and "  " not in word:
            return word


def _marked(rng: random.Random, marker: str, banned: str, spaced: bool) -> str:
    """The marker, with legal name characters on either side or none."""
    before = _segment(rng, banned + " ", False) if rng.random() < 0.4 else ""
    after = _segment(rng, banned + " ", False) if rng.random() < 0.4 else ""
    word = before + marker + after
    if spaced and rng.random() < 0.3:
        word = f"{word} {_segment(rng, banned + ' ', False)}"
    return word


def build_path(
    rng: random.Random,
    head: Head,
    style: str,
    markers: tuple[str, str],
    *,
    banned: str = "",
    spaced: bool = True,
    inside: bool = False,
) -> str:
    """A path from the grammar; ``spaced`` lets the last segment hold a space."""
    if head.url:
        spaced, banned = False, banned + " "
    prefix, parts = head.words(style)
    if inside:
        parts = [parts[0][0].replace("C", "D").replace("c", "d") + ":", ROOT_NAME]
    middle = [_segment(rng, banned, True) for _ in range(rng.randint(0, 2))]
    tail = [_segment(rng, banned, True) for _ in range(rng.randint(0, 2))]
    last = _marked(rng, markers[1], banned, spaced)
    if rng.random() < 0.3:
        last += "." + rng.choice(("txt", "yml", "exe", "log"))
    words = [*parts, *middle, _marked(rng, markers[0], banned, True), *tail, last]
    path = prefix + words[0]
    for word in words[1:]:
        path += _sep(rng, style) + word
    return path


@dataclass(frozen=True)
class Context:
    name: str
    # Whether the path is quoted right where it starts (a space in its last
    # segment is then the path's) and which characters its names cannot hold.
    quoted: bool
    banned: str
    write: Callable[[str], str]
    json: bool = False
    glued: bool = False


def _oserror(path: str) -> str:
    return str(FileNotFoundError(2, "No such file or directory", path))


CONTEXTS = (
    Context("bare", False, "", lambda p: f"open {p}"),
    Context("bare, then a reason", False, "", lambda p: f"open {p}: access denied"),
    Context("in parentheses", False, "", lambda p: f"(see {p}) failed"),
    Context("before a comma", False, "", lambda p: f"read {p}, then stopped"),
    Context("before a full stop", False, "", lambda p: f"Wrote {p}."),
    Context("after a word", False, "", lambda p: f"path{p} x", glued=True),
    Context("after a digit", False, "", lambda p: f"7{p} x", glued=True),
    Context("after an underscore", False, "", lambda p: f"x_{p} x"),
    Context("after a dot", False, "", lambda p: f"a.{p} x"),
    Context("after a colon", False, "", lambda p: f"path:{p} x"),
    Context("after CJK", False, "", lambda p: f"日本{p} x"),
    Context("after an accent", False, "", lambda p: f"café{p} x"),
    Context("single quotes", True, "'", lambda p: f"open '{p}' failed"),
    Context("double quotes", True, "", lambda p: f'open "{p}" failed'),
    Context("backticks", True, "`", lambda p: f"open `{p}` failed"),
    Context("typographic single", True, "", lambda p: f"open \u2018{p}\u2019 failed"),
    Context("typographic double", True, "", lambda p: f"open \u201c{p}\u201d failed"),
    Context("guillemets", True, "", lambda p: f"open \u00ab{p}\u00bb failed"),
    Context("an OSError", True, "", _oserror),
    Context("an OSError's repr", True, "", lambda p: repr(OSError(p))),
    Context(
        "JSON, the path its value",
        True,
        "",
        lambda p: json.dumps({"path": p}, ensure_ascii=False),
        json=True,
    ),
    Context(
        "JSON, the path in escaped quotes",
        True,
        "",
        lambda p: json.dumps({"msg": f'open "{p}": denied'}, ensure_ascii=False),
        json=True,
    ),
    Context(
        "JSON, the path in words",
        False,
        "",
        lambda p: json.dumps({"error": f"cannot open {p}"}, ensure_ascii=False),
        json=True,
    ),
)

# Two paths in one quoted span, in every order.
SPANS = (
    lambda a, b: f"{a} and {b}",
    lambda a, b: f"{a}, {b}",
    lambda a, b: f"{a} (copied from {b})",
    lambda a, b: f"{a} then path:{b}",
)


@dataclass(frozen=True)
class Case:
    category: str
    text: str
    outside: tuple[str, ...]
    is_json: bool


def _markers(number: int) -> tuple[str, str]:
    return f"qx{number:05d}u", f"qx{number:05d}e"


def _case(rng: random.Random, number: int) -> Case:
    head = rng.choice(HEADS)
    style = rng.choice(STYLES)
    if rng.random() < 0.15:
        return _span_case(rng, number, head, style)
    context = rng.choice(CONTEXTS)
    # A drive glued after an ASCII word or digit reads as a URL's scheme
    # (``https://``) or a word's (``error:\n``), and is not a path.
    while context.glued and head.drive:
        context = rng.choice(CONTEXTS)
    inside = (head.drive or head.name in ("long drive", "file drive url")) and rng.random() < 0.25
    markers = _markers(number)
    path = build_path(
        rng,
        head,
        style,
        markers,
        banned=context.banned,
        spaced=context.quoted,
        inside=inside,
    )
    return Case(
        f"{head.name} / {context.name}",
        context.write(path),
        () if inside else markers,
        context.json,
    )


def _span_case(rng: random.Random, number: int, head: Head, style: str) -> Case:
    quote = rng.choice(("'", '"'))
    first, second = _markers(number), _markers(number + CASES)
    inside = rng.random() < 0.5
    project = build_path(rng, HEADS[0], style, first, banned=quote, inside=inside)
    other = build_path(rng, head, style, second, banned=quote)
    order = rng.random() < 0.5
    span = rng.choice(SPANS)(*((project, other) if order else (other, project)))
    return Case(
        f"two paths in one span / {'project path first' if inside and order else 'other'}",
        f"read {quote}{span}{quote} then",
        (*(() if inside else first), *second),
        False,
    )


def _failure(case: Case) -> str | None:
    said = host_paths_masked(case.text, ROOT)
    left = [marker for marker in case.outside if marker in said]
    if left:
        return f"{left} left in {said!r}"
    if ROOT_NAME in said:
        return f"the project root left in {said!r}"
    if case.is_json:
        try:
            json.loads(said)
        except ValueError:
            return f"no longer JSON: {said!r}"
    return None


def test_no_generated_windows_path_leaves_a_name_behind() -> None:
    rng = random.Random(SEED)
    failed: Counter[str] = Counter()
    examples: list[str] = []
    for number in range(CASES):
        case = _case(rng, number)
        failure = _failure(case)
        if failure:
            failed[case.category] += 1
            if len(examples) < 10:
                examples.append(f"{case.text!r}: {failure}")
    assert not failed, (
        f"{sum(failed.values())} of {CASES} cases leak; by category {dict(failed.most_common())};"
        f" first: {examples}"
    )


def test_the_grammar_writes_every_head_style_and_context() -> None:
    rng = random.Random(SEED)
    cases = [_case(rng, number) for number in range(CASES)]
    seen = {case.category for case in cases}
    for head in HEADS:
        assert any(category.startswith(head.name + " /") for category in seen), head.name
    for context in CONTEXTS:
        assert any(category.endswith("/ " + context.name) for category in seen), context.name
    assert any(category.endswith("project path first") for category in seen)
    texts = " ".join(case.text for case in cases)
    for mark in _MARKS:
        assert mark in texts
    assert "\\\\\\\\" in texts and " " in texts


# Text with no Windows-form path, and its masked form, as it has always read:
# a POSIX project at /home/op/proj.
POSIX_ROOT = PurePosixPath("/home/op/proj")
UNCHANGED = (
    ("read /home/op/proj/data/rules/a.yml", "read data/rules/a.yml"),
    ("read /home/op/other/x", f"read {OUTSIDE_PROJECT}"),
    ("open '/home/a b/c'", f"open '{OUTSIDE_PROJECT} b/c'"),
    ('open "/tmp/x.yml" failed', f'open "{OUTSIDE_PROJECT}" failed'),
    ("GET /api/v1/jobs failed", "GET /api/v1/jobs failed"),
    ("see https://example.com/home/x", "see https://example.com/home/x"),
    ("file:///etc/passwd and file://localhost/opt/r", f"{OUTSIDE_PROJECT} and {OUTSIDE_PROJECT}"),
    ("file:///home/op/proj/data/x", "data/x"),
    ("file:///srv/a(1)/b", f"{OUTSIDE_PROJECT}(1)/b"),
    ("a/b/c and ./x/y", "a/b/c and ./x/y"),
    ("PATH=/usr/bin:/home/x", f"PATH={OUTSIDE_PROJECT}:/home/x"),
    ("ab:/home/y", "ab:/home/y"),
    ("[Errno 2] No such file: '/var/lib/x'", f"[Errno 2] No such file: '{OUTSIDE_PROJECT}'"),
    ('{"path": "/home/op/x", "n": 1}', f'{{"path": "{OUTSIDE_PROJECT}", "n": 1}}'),
    ("/home/op/proj", OUTSIDE_PROJECT),
    ("/home/op/proj/", OUTSIDE_PROJECT),
    ("/home/op/proj/../other/x", f"{OUTSIDE_PROJECT}"),
    ("ratio 3/4 and a\\b and C: drive", "ratio 3/4 and a\\b and C: drive"),
    ("error:\\nline two", "error:\\nline two"),
    ("see https://x.org/a/b?c=/home/d", f"see https://x.org/a/b?c={OUTSIDE_PROJECT}"),
    ("/Users/alice/Library/x", OUTSIDE_PROJECT),
    ("/proc/self/maps", "/proc/self/maps"),
    ("rules in /home/op/proj/data/sigma rules", "rules in data/sigma rules"),
)


@pytest.mark.parametrize(("text", "said"), UNCHANGED)
def test_text_without_a_windows_path_reads_as_it_always_has(text: str, said: str) -> None:
    assert host_paths_masked(text, POSIX_ROOT) == said  # type: ignore[arg-type]
