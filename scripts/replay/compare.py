"""The same stored runs replayed under two git refs, and every difference between the records.

Each ref is replayed with its own harness over its own rules. Its tree is
written out of the repository's object store into a directory of the replay's
own (``git archive``, :func:`materialise`): ``pyproject.toml`` (the project
root the rules' data readers look for), the ``src`` tree, the ``data`` tables
without ``data/samples``, ``scripts/replay``, and the API and the surface audit
(``apps/api``, ``scripts/audit``) where the ref holds them. That tree's own
``scripts/replay/run.py`` then replays the runs in a process of its own, with
that tree first on the import path and the same read-only and cache guards
(:func:`replay_under`), and the record says which tree it imported its rules
from, which is checked. No working tree is read for the rules, and none is
written. A ref from before the replay tool has no harness to replay with: it
cannot be compared (:class:`PredatesTheReplay`). A ref's replay can be given a
time limit; one stopped at it is named (:class:`RefTimedOut`).

:func:`diff_records` names every difference between two records of one run:
the codes each producer gained or lost, per claim (the flag's path and
subject); the claims each answer parsed into and the notes the claims in force
carry; the published techniques and the reasons for the unpublished ones; each
indicator's publish answer; the report's values; the judge's drops; the
settings and guards each tree refused or lacked; corroboration per technique;
and the parts one side could replay and the other could not. The values are
compared value-free (``scripts.replay.record``), so a record made with the
text compares with one made without it.

A finding is keyed by its producer, answer, claim and code, a digest of its
words and every value-free field beside them (``advisory``, ``asked``, the
linter's ``severity``, the entries it names, ...), and the findings of one key
are compared as a multiset; the fields a finding holds only as words, and its
place in the checked text, are never compared
(``scripts.replay.record.NOT_COMPARED_IN_A_FINDING``), and the rendered comparison
says so in the one list of every part it never compares
(``scripts.replay.record.NEVER_COMPARED``). A detection draft is compared by its kind,
the digests of its name, its body, its compile error, the evidence entries it
was drafted from and the values its selection left out, dated by the stored
run's clock; what else a draft holds the record never holds, and the
comparison lists it as never compared.

Two records of different schemas are compared on what both define, and every
part only one of them defines is listed under ``not_compared``, a field inside
a finding as well: the comparison is then partial. A part that raised in either
tree is listed under ``errors``. Either way the comparison is not a decision,
and the command ends with status 2.

:func:`difference_lines` writes every difference of one run as canonical lines,
each built from both records' values and naming the run by its path under the
stored runs' root, so two different differences never give one line; an
expected-difference file (:func:`read_expected`) is compared with them as a
multiset, exactly.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess  # nosec B404 — git and the replay itself, argument lists only
import sys
import tarfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts.replay.guard import ATTCK_CACHE_VARIABLE
from scripts.replay.record import (
    BOOKKEEPING_KEYS,
    NOT_COMPARED_IN_A_FINDING,
    answer_head,
    digest,
    errors,
    schema_of,
    value_free_path,
    value_free_subject,
)

from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME

# What a ref's replay is made of: the project root marker, the rules, the
# tables they read, and the harness that replays them. ``data/samples`` is
# left out: a sample is never copied.
ARCHIVED_PATHS: tuple[str, ...] = (
    "pyproject.toml",
    "src",
    "data",
    ":(exclude)data/samples",
    "scripts/replay",
    # The API writes /mitre, /iocs and the unpublished bundle's notice, which the
    # surface render (``render_surfaces.py``) reads; the audit sits beside it.
    "apps/api",
    "scripts/audit",
)
# The harness a ref replays with; a ref without it predates the replay tool.
HARNESS = "scripts/replay/run.py"
# The schema from which a record's subjects and values are value-free, and the one
# from which the object labels in its paths are too.
VALUE_FREE_SCHEMA = 3
LABEL_FREE_SCHEMA = 4
# The schema from which every finding carries a digest of its words (``words``), the report
# lists each detection draft (``detection_drafts``), and the reason beside an unpublished
# technique is a digest.
WORDS_SCHEMA = 5

# What a finding's key names besides its producer and answer.
_KEY_FIELDS = ("code", "path", "subject")
# The fields a finding holds only with the text: its words (compared by their digest), the
# text forms of its subject and path (compared value-free), its claim's sentence and the
# values of a self-named argument.
_TEXT_FIELDS = frozenset({"message", "subject_text", "path_text", "claim", "values"})
_OUTSIDE_THE_KEY = frozenset(
    {*_KEY_FIELDS, *_TEXT_FIELDS, "words", *(name for name, _why in NOT_COMPARED_IN_A_FINDING)}
)
# The parts a record of the words schema defines inside its findings.
_FINDING_PARTS = ("findings: words", "findings: the fields beside code, path and subject")


class CompareError(RuntimeError):
    """A ref could not be written out or replayed."""


class PredatesTheReplay(CompareError):
    """A ref from before the replay tool: it has no harness to replay its rules with."""


class RefTimedOut(CompareError):
    """A ref's replay did not finish within the time it was given, and was stopped."""


def _git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )
    if done.returncode != 0:
        said = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise CompareError(f"git {args[0]} failed: {said[-1] if said else done.returncode}")
    return done.stdout


def resolve(repo: Path, ref: str) -> str:
    """The commit ``ref`` names, as a full hash."""
    return _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()


def _held(repo: Path, commit: str, path: str) -> bool:
    done = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        ["git", "-C", str(repo), "cat-file", "-e", f"{commit}:{path}"],
        capture_output=True,
        check=False,
    )
    return done.returncode == 0


def has_harness(repo: Path, commit: str) -> bool:
    """Whether ``commit`` carries the replay harness."""
    return _held(repo, commit, HARNESS)


def materialise(repo: Path, ref: str, into: Path, *, harness: str | None = HARNESS) -> Path:
    """Write ``ref``'s replay into ``into`` from the object store; return the tree's root.

    A path of :data:`ARCHIVED_PATHS` the commit does not hold is left out. A
    caller that brings its own driver (``harness=None``) takes a ref from before
    the replay tool too.
    """
    commit = resolve(repo, ref)
    if harness is not None and not _held(repo, commit, harness):
        raise PredatesTheReplay(
            f"{ref} predates the replay tool (it has no {harness}): it cannot be compared"
        )
    # An exclusion stands only where what it excludes is there: alone, it
    # would archive everything else.
    paths = [
        path for path in ARCHIVED_PATHS if _held(repo, commit, path.removeprefix(":(exclude)"))
    ]
    archive = _git(repo, "archive", "--format=tar", commit, "--", *paths)
    if into.exists():
        # A tree an earlier comparison left: a module this ref does not have
        # must not stay importable beside the ones it does.
        shutil.rmtree(into)
    into.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(into, filter="data")  # nosec B202 — our own archive, the data filter
    # A ref from before the product's rename (T-576) holds its package under
    # the previous name; its own harness imports it by that name.
    packages = (CURRENT_NAME, PREVIOUS_NAME)
    if (
        not any((into / "src" / p).is_dir() for p in packages)
        or not (into / "pyproject.toml").is_file()
    ):
        raise CompareError(f"{ref} has no src/{CURRENT_NAME} tree or no pyproject.toml")
    return into


def replay_under(
    tree: Path,
    runs: Sequence[Path],
    out: Path,
    *,
    show_text: bool = False,
    timeout: float | None = None,
) -> list[dict[str, Any]]:
    """The replay of each of ``runs`` by ``tree``'s own harness over its own rules.

    The harness ends with status 2 when a part raised and still writes its
    record, which says which part; no record at all is a harness that failed.
    ``timeout`` is how many seconds the harness is given (none by default); one
    that is still running then is stopped (:class:`RefTimedOut`). The ATT&CK
    cache variable points at a directory of the comparison's own before the
    harness starts, whatever the harness does with it.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(tree / "src"), str(tree)])
    cache = out.with_name(f"{out.stem}-attck")
    cache.mkdir(parents=True, exist_ok=True)
    env[ATTCK_CACHE_VARIABLE] = str(cache.resolve())
    # The same variable under the previous name, for a ref from before the
    # rename, so its harness reads the comparison's cache as well.
    previous = PREVIOUS_NAME.upper() + ATTCK_CACHE_VARIABLE.removeprefix(CURRENT_NAME.upper())
    env[previous] = str(cache.resolve())
    if out.exists():
        out.unlink()
    command = [
        sys.executable,
        str(tree / HARNESS),
        *(str(Path(run).resolve()) for run in runs),
        "--json",
        str(out.resolve()),
        "--quiet",
    ]
    if show_text:
        command.append("--show-text")
    try:
        done = subprocess.run(  # nosec B603 — the replay itself, an argument list
            command, env=env, cwd=tree, capture_output=True, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise RefTimedOut(
            f"the replay under {tree} did not finish within {timeout:g} s and was stopped"
        ) from exc
    if done.returncode not in (0, 2) or not out.is_file():
        # The harness's own error output can quote a value from the run: it is
        # kept beside the record, and only the failure's name is said.
        kept = out.with_name(f"{out.stem}-stderr.txt")
        kept.write_bytes(done.stderr)
        named = _failure_named(done.stderr, done.returncode)
        raise CompareError(
            f"the replay under {tree} wrote no record: {named} (its error output is kept in {kept})"
        )
    records = json.loads(out.read_text(encoding="utf-8"))
    records = records if isinstance(records, list) else [records]
    expected = str((tree / "src").resolve().parent)
    for record in records:
        imported = str((record.get("rules") or {}).get("tree") or "")
        if Path(imported).resolve() != Path(expected):
            raise CompareError(
                f"the replay under {tree} imported its rules from {imported or 'nowhere'}"
            )
    return records


# How a harness names the failure it ended on: the exception's class and where
# it was raised, never its message.
_FAILURE_RE = re.compile(r"^replay failed: (\w+)(?: at [\w.-]+\.py:\d+ \([\w<>.]+\))?")


def _failure_named(stderr: bytes, status: int) -> str:
    """The failure a harness ended on, by name and place only, or its exit status."""
    for line in reversed(stderr.decode("utf-8", "replace").splitlines()):
        found = _FAILURE_RE.match(line.strip())
        if found:
            return found.group(0)
    return f"exit status {status}"


# ---------------------------------------------------------------------------
# The differences
# ---------------------------------------------------------------------------


def _is_item() -> Any:
    """The platform's reader of a sandbox item id, or ``None`` where it cannot be imported."""
    try:
        from malspark.analysis.sandbox_sections import is_item_id
    except Exception:  # noqa: BLE001 — then an item id is digested like any value
        return None
    return is_item_id


def _flag_key(
    part: str, owner: str, flag: Mapping[str, Any], schema: int, *, words: bool = False
) -> tuple[str, ...]:
    """A finding's key. A record from before the value-free schemas wrote its subject
    (before 3) or the object labels in its paths (before 4) with the values in them: they
    are made value-free here as a later record writes them, so the two compare. With
    ``words`` the key adds the digest of the finding's words and every value-free field
    beside the code, path and subject, as canonical JSON."""
    subject = str(flag.get("subject") or "")
    path = str(flag.get("path") or "")
    if schema < VALUE_FREE_SCHEMA:
        is_item = _is_item()
        path = value_free_path(path, subject, is_item)
        subject = value_free_subject(subject, is_item)
    elif schema < LABEL_FREE_SCHEMA:
        path = value_free_path(path)
    said, fields = "", ""
    if words:
        said = str(flag.get("words") or "")
        beside = {k: v for k, v in flag.items() if k not in _OUTSIDE_THE_KEY}
        fields = _canonical(beside) if beside else ""
    return (part, owner, path, subject, str(flag.get("code") or ""), said, fields)


def _canonical(value: Any) -> str:
    """``value`` as one line of JSON that the same value always writes the same way."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _findings(
    record: Mapping[str, Any], words: bool
) -> Iterable[tuple[tuple[str, ...], Mapping[str, Any]]]:
    """Every finding of a record with its key (:func:`_flag_key`)."""
    schema = schema_of(record)
    for agent, entry in (record.get("analysts") or {}).items():
        for answer in entry.get("answers") or []:
            owner = f"{agent} {answer.get('answer', '')}"
            for flag in answer.get("flags") or []:
                yield _flag_key("analyst answer", owner, flag, schema, words=words), flag
        for flag in (entry.get("in_force") or {}).get("flags") or []:
            yield _flag_key("claims in force", agent, flag, schema, words=words), flag
    for part in ("judge", "narrative", "tool", "fp_linter"):
        for flag in (record.get(part) or {}).get("flags") or []:
            owner = ",".join(flag.get("entries") or []) if part == "tool" else ""
            yield _flag_key(part, owner, flag, schema, words=words), flag
    for section, entry in ((record.get("composer") or {}).get("sections") or {}).items():
        for flag in entry.get("flags") or []:
            yield _flag_key("composer", section, flag, schema, words=words), flag


def flag_keys(record: Mapping[str, Any], *, words: bool | None = None) -> Counter[tuple[str, ...]]:
    """Every finding of a record, keyed by producer, answer, claim and code, counted.

    ``words`` (by default: the record is of the words schema) adds each finding's words
    digest and its other value-free fields to its key."""
    if words is None:
        words = schema_of(record) >= WORDS_SCHEMA
    return Counter(key for key, _flag in _findings(record, words))


def _keyed(
    rows: Iterable[tuple[tuple[str, ...], int]],
    counts_a: Counter[tuple[str, ...]],
    counts_b: Counter[tuple[str, ...]],
    said: Mapping[tuple[str, ...], str],
) -> list[dict[str, Any]]:
    names = ("part", "owner", "path", "subject", "code", "words")
    out: list[dict[str, Any]] = []
    for key, count in sorted(rows):
        row: dict[str, Any] = {n: v for n, v in zip(names, key, strict=False) if v}
        if key[6]:
            row["fields"] = json.loads(key[6])
        row.update(count=count, in_a=counts_a[key], in_b=counts_b[key])
        if key in said:
            row["message"] = said[key]
        out.append(row)
    return out


def _changed(a: Any, b: Any) -> dict[str, Any] | None:
    return None if a == b else {"a": a, "b": b}


def _mapping_diff(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    """Keys only in ``a``, only in ``b``, and changed values, of two flat mappings."""
    out: dict[str, Any] = {}
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    changed = {k: {"a": a[k], "b": b[k]} for k in sorted(set(a) & set(b)) if a[k] != b[k]}
    if only_a:
        out["only_a"] = {k: a[k] for k in only_a}
    if only_b:
        out["only_b"] = {k: b[k] for k in only_b}
    if changed:
        out["changed"] = changed
    return out


# What an answer's shape and the notes on the claims in force are, by the
# schema that first records each.
_SHAPE_KEYS: tuple[tuple[str, int], ...] = (("claims", 1), ("findings", 1))
_NOTE_KEYS: tuple[tuple[str, int], ...] = (
    ("claims", 1),
    ("findings", 1),
    ("not_valid", 2),
    ("kept_after_absence_question", 2),
)


def _answer_shapes(record: Mapping[str, Any], schema: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for agent, entry in (record.get("analysts") or {}).items():
        for answer in entry.get("answers") or []:
            key = f"{agent} {answer.get('answer', '')} ({answer.get('source', '')})"
            out[key] = (
                {k: answer.get(k) for k, since in _SHAPE_KEYS if since <= schema}
                if answer.get("replayed")
                else {"replayed": False}
            )
        in_force = entry.get("in_force") or {}
        if in_force:
            out[f"{agent} claims in force"] = {
                k: in_force.get(k) for k, since in _NOTE_KEYS if since <= schema
            }
    return out


def _defined(record: Mapping[str, Any], schema: int) -> set[str]:
    """The parts a record defines, by name: its parts, its report's values and its notes.

    The record's own bookkeeping and the text fields (``*_text``) are never
    compared, so they are not among them.
    """
    names = {key for key in record if key not in BOOKKEEPING_KEYS}
    report = record.get("report")
    if isinstance(report, dict):
        names.update(f"report.{key}" for key in report if not key.endswith("_text"))
    for key, since in _NOTE_KEYS:
        if since <= schema and any(
            key in (entry.get("in_force") or {})
            for entry in (record.get("analysts") or {}).values()
        ):
            names.add(f"claims in force: {key}")
    composer = record.get("composer")
    if isinstance(composer, dict):
        names.update(f"composer section: {name}" for name in composer.get("sections") or {})
    if schema >= WORDS_SCHEMA:
        names.update(_FINDING_PARTS)
    return names


def _has_reasons(record: Mapping[str, Any]) -> bool:
    techniques = (record.get("report") or {}).get("techniques") or {}
    return any(isinstance(row, dict) and "why" in row for row in techniques.values())


def _reasons_compare(schema_a: int, schema_b: int) -> bool:
    """Whether two records write the reason beside an unpublished technique in one form."""

    def form(schema: int) -> int:
        return 0 if schema < VALUE_FREE_SCHEMA else 1 if schema < WORDS_SCHEMA else 2

    return form(schema_a) == form(schema_b) != 0


def _common(
    a: Mapping[str, Any], b: Mapping[str, Any], schema_a: int, schema_b: int
) -> tuple[dict[str, Any], dict[str, Any], dict[str, list[str]]]:
    """The two records cut to what both define, and the parts left uncompared.

    ``a`` and ``b`` list the parts only that record defines. ``differently``
    lists the parts both define in forms that cannot be compared: the reason
    beside an unpublished technique was, before the value-free schema, the
    judge's words when the record was made with the text (and the record does
    not say whether it was), then the reason or the judge's marker, and from
    the words schema a digest of the whole reason.
    """
    keys = set(a) & set(b)
    a2 = {k: a[k] for k in keys}
    b2 = {k: b[k] for k in keys}
    report_a, report_b = a2.get("report"), b2.get("report")
    if isinstance(report_a, dict) and isinstance(report_b, dict):
        both = set(report_a) & set(report_b)
        a2["report"] = {k: report_a[k] for k in both}
        b2["report"] = {k: report_b[k] for k in both}
    defined_a, defined_b = _defined(a, schema_a), _defined(b, schema_b)
    not_compared = {
        "a": sorted(defined_a - defined_b),
        "b": sorted(defined_b - defined_a),
        "differently": [],
    }
    if not _reasons_compare(schema_a, schema_b) and (_has_reasons(a) or _has_reasons(b)):
        not_compared["differently"].append("report.techniques: why")
    return a2, b2, not_compared


def _free_indicators(indicators: Mapping[str, Any]) -> dict[str, Any]:
    """The IOC rows' value-free answers: the head and a digest of the whole answer."""
    out: dict[str, Any] = {}
    for key, row in indicators.items():
        if not isinstance(row, dict):
            continue
        said = str(row.get("published") or "")
        head = answer_head(said) or said
        answer = row.get("answer")
        if answer is None and said and said != head:
            # A record from before the value-free schema kept the whole answer.
            answer = digest(said)
        out[str(key)] = {"kind": row.get("kind"), "published": head or None, "answer": answer}
    return out


def _free_category(category: Any) -> str | None:
    said = str(category or "")
    if not said:
        return None
    return said if said.startswith("sha256:") else f"sha256:{digest(said)}"


def _free_techniques(techniques: Mapping[str, Any], with_why: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for tid, row in techniques.items():
        if not isinstance(row, dict):
            continue
        out[str(tid)] = {
            k: row[k] for k in ("published", "why") if k in row and (with_why or k != "why")
        }
    return out


def diff_records(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    """Every difference between two replay records of one stored run."""
    out: dict[str, Any] = {"run": a.get("run")}
    errors_a, errors_b = errors(a), errors(b)
    if errors_a or errors_b:
        out["errors"] = {"a": errors_a, "b": errors_b}
    schema_a, schema_b = schema_of(a), schema_of(b)
    schema = min(schema_a, schema_b)
    if schema_a != schema_b:
        out["schema"] = {"a": schema_a, "b": schema_b}
    # On every comparison, not only across schemas: two harnesses of one schema
    # may still define different parts (a composer section one tree no longer
    # writes), and a part only one side defines is not compared.
    a, b, not_compared = _common(a, b, schema_a, schema_b)
    if any(not_compared.values()):
        out["not_compared"] = {key: rows for key, rows in not_compared.items() if rows}
    words = schema >= WORDS_SCHEMA
    keys_a, keys_b = flag_keys(a, words=words), flag_keys(b, words=words)
    # The words a record made with the text holds, shown beside their digest.
    said = {
        key: str(flag["message"])
        for record in (a, b)
        for key, flag in _findings(record, words)
        if "message" in flag
    }
    gained = _keyed(((k, c) for k, c in (keys_b - keys_a).items()), keys_a, keys_b, said)
    lost = _keyed(((k, c) for k, c in (keys_a - keys_b).items()), keys_a, keys_b, said)
    if gained:
        out["codes_gained"] = gained
    if lost:
        out["codes_lost"] = lost
    totals = _mapping_diff(
        {
            f"{part} {code}": count
            for part, codes in (a.get("totals") or {}).items()
            for code, count in codes.items()
        },
        {
            f"{part} {code}": count
            for part, codes in (b.get("totals") or {}).items()
            for code, count in codes.items()
        },
    )
    if totals:
        out["totals"] = totals
    shapes = _mapping_diff(_answer_shapes(a, schema), _answer_shapes(b, schema))
    if shapes:
        out["answers"] = shapes
    report_a, report_b = a.get("report") or {}, b.get("report") or {}
    report: dict[str, Any] = {}
    for key in (
        "replayed",
        "verdict",
        "severity",
        "category",
        "confidence",
        "degraded",
        "degradation",
        "persistence",
        "claims_not_discussed",
        "detection_rules",
        "detection_rules_not_compiled",
    ):
        if key in report_a or key in report_b:
            value_a, value_b = report_a.get(key), report_b.get(key)
            if key == "category":
                value_a, value_b = _free_category(value_a), _free_category(value_b)
            changed = _changed(value_a, value_b)
            if changed:
                report[key] = changed
    sections_a, sections_b = report_a.get("sections") or [], report_b.get("sections") or []
    if sections_a != sections_b:
        held_a, held_b = set(sections_a), set(sections_b)
        report["sections"] = {
            "only_a": [s for s in sections_a if s not in held_b],
            "only_b": [s for s in sections_b if s not in held_a],
            "order_changed": [s for s in sections_a if s in held_b]
            != [s for s in sections_b if s in held_a],
            # Both orders, so two different moves never read as one difference.
            "a": list(sections_a),
            "b": list(sections_b),
        }
    drafts = _draft_diff(report_a, report_b)
    if drafts:
        report["detection_drafts"] = drafts
    with_why = _reasons_compare(schema_a, schema_b)
    techniques = _mapping_diff(
        _free_techniques(report_a.get("techniques") or {}, with_why),
        _free_techniques(report_b.get("techniques") or {}, with_why),
    )
    if techniques:
        report["techniques"] = techniques
    indicators = _mapping_diff(
        _free_indicators(report_a.get("indicators") or {}),
        _free_indicators(report_b.get("indicators") or {}),
    )
    if indicators:
        report["indicators"] = indicators
    export_a, export_b = report_a.get("export") or {}, report_b.get("export") or {}
    patterns_a = set(export_a.get("attack_patterns") or [])
    patterns_b = set(export_b.get("attack_patterns") or [])
    if patterns_a != patterns_b:
        report["exported_techniques"] = {
            "only_a": sorted(patterns_a - patterns_b),
            "only_b": sorted(patterns_b - patterns_a),
        }
    objects = _mapping_diff(export_a.get("objects") or {}, export_b.get("objects") or {})
    if objects:
        report["exported_objects"] = objects
    if report:
        out["report"] = report
    judge: dict[str, Any] = {}
    for key in ("objects", "indicators_dropped"):
        changed = _changed((a.get("judge") or {}).get(key), (b.get("judge") or {}).get(key))
        if changed and ("judge" in a or "judge" in b):
            judge[key] = changed
    if judge:
        out["judge"] = judge
    written_a = set((a.get("composer") or {}).get("not_written") or [])
    written_b = set((b.get("composer") or {}).get("not_written") or [])
    if written_a != written_b:
        out["composer"] = {
            "not_written": {
                "only_a": sorted(written_a - written_b),
                "only_b": sorted(written_b - written_a),
            }
        }
    calls = _changed((a.get("tool") or {}).get("calls"), (b.get("tool") or {}).get("calls"))
    if calls and ("tool" in a or "tool" in b):
        out["tool"] = {"calls": calls}
    environment: dict[str, Any] = {}
    env_a, env_b = a.get("environment") or {}, b.get("environment") or {}
    refused = _mapping_diff(
        env_a.get("settings_refused") or {}, env_b.get("settings_refused") or {}
    )
    if refused:
        environment["settings_refused"] = refused
    lacking_a = set(env_a.get("doors_this_tree_lacks") or [])
    lacking_b = set(env_b.get("doors_this_tree_lacks") or [])
    if lacking_a != lacking_b:
        environment["doors_this_tree_lacks"] = {
            "only_a": sorted(lacking_a - lacking_b),
            "only_b": sorted(lacking_b - lacking_a),
        }
    applied_a = set(env_a.get("settings_from_run") or [])
    applied_b = set(env_b.get("settings_from_run") or [])
    if applied_a != applied_b:
        environment["settings_from_run"] = {
            "only_a": sorted(applied_a - applied_b),
            "only_b": sorted(applied_b - applied_a),
        }
    if environment:
        out["environment"] = environment
    corroboration = _mapping_diff(
        (a.get("corroboration") or {}).get("techniques") or {},
        (b.get("corroboration") or {}).get("techniques") or {},
    )
    if corroboration:
        out["corroboration"] = corroboration
    parts_a = {(row["part"], row["why"]) for row in a.get("not_replayed") or []}
    parts_b = {(row["part"], row["why"]) for row in b.get("not_replayed") or []}
    if parts_a != parts_b:
        out["not_replayed"] = {
            "only_a": [{"part": p, "why": w} for p, w in sorted(parts_a - parts_b)],
            "only_b": [{"part": p, "why": w} for p, w in sorted(parts_b - parts_a)],
        }
    for part in ("judge", "narrative", "composer", "tool", "fp_linter", "corroboration"):
        if part in a or part in b:
            replayed = _changed(
                (a.get(part) or {}).get("replayed"), (b.get(part) or {}).get("replayed")
            )
            if replayed:
                out.setdefault("replayed", {})[part] = replayed
    return out


def _draft_key(row: Mapping[str, Any]) -> tuple[str, str, str, bool, str, str, str]:
    return (
        str(row.get("kind") or ""),
        str(row.get("name") or ""),
        str(row.get("body") or ""),
        bool(row.get("not_compiled")),
        str(row.get("compile_error") or ""),
        str(row.get("evidence") or ""),
        str(row.get("left_out") or ""),
    )


def _draft_diff(report_a: Mapping[str, Any], report_b: Mapping[str, Any]) -> dict[str, Any]:
    """The detection drafts one report holds more often than the other, by kind and the digests
    of its name, body, compile error, evidence entries and values left out; the words beside
    them when a record holds them."""
    if "detection_drafts" not in report_a or "detection_drafts" not in report_b:
        return {}
    rows_a = [r for r in report_a.get("detection_drafts") or [] if isinstance(r, Mapping)]
    rows_b = [r for r in report_b.get("detection_drafts") or [] if isinstance(r, Mapping)]
    counts_a = Counter(_draft_key(r) for r in rows_a)
    counts_b = Counter(_draft_key(r) for r in rows_b)
    texts = {
        _draft_key(r): {
            k: str(r[k]) for k in ("name_text", "body_text", "compile_error_text") if k in r
        }
        for r in (*rows_a, *rows_b)
    }
    out: dict[str, Any] = {}
    for side, rows in (("lost", counts_a - counts_b), ("gained", counts_b - counts_a)):
        listed = []
        for key, count in sorted(rows.items()):
            kind, name, body, not_compiled, compile_error, evidence, left_out = key
            row: dict[str, Any] = {"kind": kind, "name": name, "body": body}
            if not_compiled:
                row["not_compiled"] = True
            for field, held in (
                ("compile_error", compile_error),
                ("evidence", evidence),
                ("left_out", left_out),
            ):
                if held:
                    row[field] = held
            row.update(count=count, in_a=counts_a[key], in_b=counts_b[key], **texts.get(key, {}))
            listed.append(row)
        if listed:
            out[side] = listed
    return out


# The keys of a diff that say how the comparison went rather than what differs.
_NOT_A_DIFFERENCE = frozenset({"run", "errors", "schema", "not_compared"})


def differs(diff: Mapping[str, Any]) -> bool:
    """Whether a diff names any difference between what the two refs decide."""
    return any(key not in _NOT_A_DIFFERENCE for key in diff)


def has_errors(diff: Mapping[str, Any]) -> bool:
    """Whether a part raised in either tree: the comparison is then not a decision."""
    found = diff.get("errors") or {}
    return bool(found.get("a") or found.get("b"))


def is_partial(diff: Mapping[str, Any]) -> bool:
    """Whether a part was left uncompared: a part not compared is not a decision either."""
    return any((diff.get("not_compared") or {}).values())


# ---------------------------------------------------------------------------
# The canonical lines, and the expected-difference file
# ---------------------------------------------------------------------------

# The parts of a diff that are never a line: how the comparison went, never what differs.
# A line in an expected file that names one of them is refused.
NEVER_EXPECTED = _NOT_A_DIFFERENCE
# The fields of a finding's or a draft's row that make its unit; the rest are its counts
# and the words beside them.
_FINDING_UNIT = ("part", "owner", "path", "subject", "code", "words", "fields")
_DRAFT_UNIT = ("kind", "name", "body", "not_compiled", "compile_error", "evidence", "left_out")


class ExpectedFileError(CompareError):
    """An expected-difference file that cannot be read, or that may not be used as given."""


def run_label(run: Path, root: Path) -> str:
    """A stored run named by its path under the stored runs' root, written with ``/``."""
    resolved, base = run.resolve(), root.resolve()
    if resolved == base or base not in resolved.parents:
        raise CompareError(f"the stored run {run} is not inside the stored runs' root {root}")
    return resolved.relative_to(base).as_posix()


def _units(part: str, value: Any) -> Iterable[tuple[str, Any, Any, Any]]:
    """Each unit of one part of a diff: its name, and its value under A and under B."""
    if not isinstance(value, Mapping):
        raise TypeError(f"the diff's part {part} is not a mapping")
    if part == "report.detection_drafts":
        for side in ("lost", "gained"):
            for row in value.get(side) or []:
                unit = {k: row[k] for k in _DRAFT_UNIT if k in row}
                yield part, unit, row["in_a"], row["in_b"]
        return
    if "a" in value and "b" in value:
        yield part, None, value["a"], value["b"]
        return
    if value and set(value) <= {"only_a", "only_b", "changed"}:
        only_a, only_b = value.get("only_a"), value.get("only_b")
        if "changed" in value or isinstance(only_a, Mapping) or isinstance(only_b, Mapping):
            for key, held in (only_a or {}).items():
                yield part, key, held, None
            for key, held in (only_b or {}).items():
                yield part, key, None, held
            for key, row in (value.get("changed") or {}).items():
                yield part, key, row["a"], row["b"]
        else:
            for held in only_a or []:
                yield part, held, True, False
            for held in only_b or []:
                yield part, held, False, True
        return
    for key, inner in value.items():
        yield from _units(f"{part}.{key}", inner)


def difference_lines(diff: Mapping[str, Any], run: str) -> list[str]:
    """Every difference of one run's diff as canonical lines, sorted.

    A line is one JSON array, ASCII only: the run (its path under the stored runs'
    root), the part, the unit, and the unit's value under A and under B (``null`` where
    a side does not hold it). A finding's or a draft's unit is its whole key and its
    values the times each record holds it. The words a record made with the text holds
    are never in a line, so a comparison writes the same lines with the text or without
    it. How the comparison went (an error, a schema, a part not compared) is never a
    line.
    """
    raised = {
        _canonical({"part": row.get("part"), "why": row.get("why")})
        for side in ("a", "b")
        for row in (diff.get("errors") or {}).get(side) or []
    }
    lines: list[str] = []
    for key, value in diff.items():
        if key in _NOT_A_DIFFERENCE:
            continue
        if key in ("codes_gained", "codes_lost"):
            for row in value:
                unit = {k: row[k] for k in _FINDING_UNIT if k in row}
                lines.append(_canonical([run, "findings", unit, row["in_a"], row["in_b"]]))
            continue
        for part, unit, held_a, held_b in _units(key, value):
            if part == "not_replayed" and _canonical(unit) in raised:
                continue  # a part that raised is an error, never a line
            lines.append(_canonical([run, part, unit, held_a, held_b]))
    return sorted(lines)


def _never_expected(line: str) -> bool:
    """Whether a line of an expected file names how a comparison went rather than a difference."""
    try:
        parsed = json.loads(line)
    except ValueError:
        return False
    if not isinstance(parsed, list) or len(parsed) < 2:
        return False
    part = str(parsed[1])
    return any(part == name or part.startswith(f"{name}.") for name in NEVER_EXPECTED)


def read_expected(path: Path, sha256: str | None = None) -> tuple[Counter[str], str]:
    """The lines an expected-difference file approves, counted, and the file's SHA-256.

    Lines are split at a line feed and nothing else is removed, so a carriage return
    stays part of its line; a line starting with ``#`` is a comment, which no canonical
    line can be. Given ``sha256``, a file whose digest differs is refused. A file that
    cannot be read, does not read as UTF-8 or names how a comparison went (an error, a
    schema, a part not compared) is refused (:class:`ExpectedFileError`).
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ExpectedFileError(
            f"the expected-difference file {path} cannot be read ({type(exc).__name__})"
        ) from exc
    found = hashlib.sha256(data).hexdigest()
    if sha256 is not None and found != sha256.lower():
        raise ExpectedFileError(
            f"the expected-difference file {path} has sha256 {found}, not the approved {sha256}"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExpectedFileError(f"the expected-difference file {path} is not UTF-8") from exc
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    body = [line for line in lines if not line.startswith("#")]
    refused = [line for line in body if _never_expected(line)]
    if refused:
        raise ExpectedFileError(
            f"the expected-difference file {path} expects how a comparison went, which is never "
            f"expected: {refused[0]}"
        )
    return Counter(body), found
