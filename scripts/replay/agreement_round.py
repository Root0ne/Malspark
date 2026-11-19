"""Re-run a stored run's agreement round on the model's stored answers, at zero cost.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/agreement_round.py <run dir> [<run dir> ...] [--out DIR]

recovers, per run, what the agreement round (``reporting.section_agreement``) was given and
answered, and puts the answers through the round's own code under this tree, with a stub in
place of the model:

- the round's first request and its retry request, read line by line from ``worker.log``
  and chosen by the round's system text; the passages as the first request showed them;
- the model's first answer: the assistant turn the retry request repeats; and, where the
  run's record keeps them (``run_summary.section_agreement.answers`` of ``report.json``,
  each left unchanged by the record's mask), the answers of both turns;
- the report as the round was given it: the stored report is the one after the round, so
  each passage's text is put back to what the first request showed (with the ids a rewrite
  added to its record's list taken out again, and the round's own flagged statements left
  out), and the round's own ``passages_of`` builds its passages, with their cites,
  addresses, values, checks and writers, from it. The debate's mediations are read off the
  request. The reconstruction is checked: the prompt the round's code builds from it must
  equal the logged one, and where it does not the first differing position is said.

The replay hands the stub the first answer for the first turn and, for the retry, the
retry's stored answer; where none is stored the run is marked "first turn only" and the
retry is answered with no rows, as the round's own re-applier answers a turn it holds no
answer for (``section_agreement.StoredAnswers``). It records every passage's text before
and after, every outcome record of the round (``agreement.*``), its counts and flagged
statements, and every row of the answers with what became of it: applied, kept, left out,
or replaced by the retry's row, with the records that name it.

``--check-stored`` also compares, for a run whose record keeps the round's answers, the
replay's passages and records with the stored ones, and names every difference.

``--compare REF_A REF_B`` replays the same recovered input under two git refs, in the manner
of ``scripts/replay/compare.py``: each ref's ``src`` and ``data`` are written out of the
object store, and this harness runs over that tree in a process of its own. Per run it
lists the sentences whose final text differs, the sentences left out under one ref only,
and the outcome codes gained and lost. ``--expect FILE`` (a JSON list of expected
differences, kept outside git, each matching every difference whose fields it gives)
excuses differences; the command ends with status 1 on any difference no entry matches,
0 otherwise.

``--labels FILE`` (a JSON list of labelled sentences kept outside git, each with ``run``,
``text``, ``label`` ``false`` or ``true``, and ``passage`` where it is known) states, per
label, whether that exact text is printed in the final text of its passage (of any passage
where none is given) under each ref, and as stored before the round. Results are judged by
these labels, never by the code's own reading of a contradiction.

Limits: the answers after the retry are stored for two runs only (the record keeps the
round's answers since T-736); a first answer is recovered only where the retry request
repeats it (a first answer the retry left out, and a round that needed no retry, give
none); the passages are put back from the prompt, so a text the prompt does not show is the
stored one; the ledger is the stored one, after its byte budget, and no sandbox report nor
evidence corpus is stored, so an item's or an entry's text is read as stored. The harness
shows what the code does with a given answer, not what a model would answer to a changed
question.

Read-only over the runs: nothing is written beside them, no network is reached, no
credential is read; every file of a run is digested before and after.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import copy
import json
import os
import re
import subprocess  # nosec B404 — the harness itself over a ref's tree, an argument list
import sys
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# What selects the round's requests in a worker log: its system text (``SYSTEM_PROMPT``).
SYSTEM_MARK = "reading one analysis report for agreement between its parts"
_OPTIONS = "Request options: "
# The kinds of passage the round may rewrite, and the one shown for reading only.
_WRITTEN = ("claim-led", "section 5")
_CITES = re.compile(r" \(cites ([^)]*)\)")
# What an empty field is filled with while the round's own writers are looked up, and
# emptied again after: a passage the round left with no text shows no writer otherwise.
_SENTINEL = "⁣t768-empty⁣"
# The codes of the round's own records, and the keys of its counts no replay compares.
_CODE_PREFIX = "agreement."
_SUMMARY_SKIP = ("answers", "answers_masked", "verbatim_unseen")
_NO_ROWS = '{"sentences": []}'

LIMITS = (
    "Limits: the answers after the retry are stored for two runs only; a first answer is "
    "recovered only where the retry request repeats it; a text the prompt does not show is "
    "the stored one; the ledger is the stored one and no sandbox report or evidence corpus "
    "is stored; the harness shows what the code does with a given answer, not what a model "
    "would answer to a changed question."
)


# ---------------------------------------------------------------------------
# The worker log
# ---------------------------------------------------------------------------


def _text(content: Any) -> str:
    """The text of a message's content: a string, or its text blocks joined."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(part.get("text") or "")
            for part in content
            if isinstance(part, dict) and part.get("type", "text") == "text"
        )
    return ""


def _tool_turn(content: Any) -> bool:
    """Whether a message's content carries a tool call or a tool's reply."""
    return isinstance(content, list) and any(
        isinstance(part, dict) and part.get("type") in ("tool_use", "tool_result")
        for part in content
    )


def _system_text(data: Mapping[str, Any]) -> str:
    said = _text(data.get("system"))
    for message in data.get("messages") or []:
        if isinstance(message, dict) and message.get("role") == "system":
            said += _text(message.get("content"))
    return said


@dataclass
class Requests:
    """The round's requests in one worker log: the first, the retry, and how many there were."""

    first: list[dict[str, Any]] | None = None
    retry: list[dict[str, Any]] | None = None
    count: int = 0


def _turns(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    """A request's turns past the system one: role, text, and whether it is a tool turn."""
    return [
        {
            "role": str(message.get("role") or ""),
            "text": _text(message.get("content")),
            "tool": _tool_turn(message.get("content")),
        }
        for message in data.get("messages") or []
        if isinstance(message, dict) and message.get("role") != "system"
    ]


def _feedback_at(turns: Sequence[Mapping[str, Any]]) -> int | None:
    """Where the first correction turn stands: a user turn after an answer, no tool reply."""
    for at, turn in enumerate(turns):
        if at and turn["role"] == "user" and not turn["tool"]:
            return at
    return None


def agreement_requests(log: Path) -> Requests:
    """The round's first request and its retry request in ``log``, read one line at a time.

    A request is a ``Request options:`` line whose system text is the round's. The first is
    the first such request; the retry, the first holding a correction turn after an answer.
    No whole log is ever held: only the two requests' turns are kept."""
    found = Requests()
    with log.open(encoding="utf-8", errors="replace", newline="\n") as lines:
        for line in lines:
            if _OPTIONS not in line or SYSTEM_MARK not in line:
                continue
            try:
                options = ast.literal_eval(line.split(_OPTIONS, 1)[1].strip())
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                continue
            data = options.get("json_data") if isinstance(options, dict) else None
            if not isinstance(data, dict) or SYSTEM_MARK not in _system_text(data):
                continue
            found.count += 1
            turns = _turns(data)
            if found.first is None:
                found.first = turns
            if found.retry is None and _feedback_at(turns) is not None:
                found.retry = turns
    return found


def prompt_of(turns: Sequence[Mapping[str, Any]]) -> str:
    """The round's human turn: the first user turn of its first request."""
    return next((str(t["text"]) for t in turns if t["role"] == "user"), "")


def first_answer(turns: Sequence[Mapping[str, Any]] | None) -> str | None:
    """The model's first answer as the retry request repeats it: the assistant turn just
    before the first correction, its text blocks; ``None`` where the retry left it out."""
    if not turns:
        return None
    at = _feedback_at(turns)
    if at is None or turns[at - 1]["role"] != "assistant":
        return None
    said = str(turns[at - 1]["text"])
    return said if said.strip() else None


# ---------------------------------------------------------------------------
# The report the round was given
# ---------------------------------------------------------------------------


@dataclass
class Shown:
    """One passage as the first request showed it."""

    kind: str
    text: str
    cites: frozenset[str]
    marked: bool


def shown_of(prompt: str) -> dict[str, Shown]:
    """Every passage the prompt shows, by id: its kind, its text as the round held it (a
    quoted text read back), the ids it cites, and whether it is marked read only or
    verbatim."""
    from scripts.replay.agreement_names import _KINDS, _PASSAGE, _unquoted

    kind = ""
    out: dict[str, Shown] = {}
    for line in prompt.splitlines():
        if line.strip() in _KINDS:
            kind = _KINDS[line.strip()]
            continue
        found = _PASSAGE.match(line)
        if not found or not kind:
            continue
        pid, _label, text = found.groups()
        head = line.split(": ", 1)[0]
        cited = _CITES.search(line[: len(line) - len(text)])
        out[pid] = Shown(
            kind=kind,
            text=text if kind in ("fact", "judge") else _unquoted(text),
            cites=frozenset(c.strip() for c in cited.group(1).split(",")) if cited else frozenset(),
            marked="(read only)" in head or "(verbatim" in head,
        )
    return out


def discussion_of(shown: Mapping[str, Shown]) -> list[dict[str, str]]:
    """The debate's mediations as the prompt showed them, in round order, as the mediator's."""
    from malspark.reporting.section_agreement import _mediator_name

    rounds = sorted(
        ((pid, s) for pid, s in shown.items() if s.kind == "debate"),
        key=lambda item: int(item[0].rsplit(".", 1)[-1]) if item[0][-1:].isdigit() else 0,
    )
    return [{"agent_name": _mediator_name(), "finding": s.text} for _pid, s in rounds]


def _empty_fields(model: Any, seen: set[int]) -> Iterator[tuple[Any, str]]:
    """Every empty string field of every model under ``model``, once each."""
    from pydantic import BaseModel

    if id(model) in seen:
        return
    seen.add(id(model))
    if isinstance(model, BaseModel):
        for name in type(model).model_fields:
            value = getattr(model, name, None)
            if isinstance(value, str) and not value.strip():
                yield model, name
            else:
                yield from _empty_fields(value, seen)
    elif isinstance(model, list | tuple):
        for item in model:
            yield from _empty_fields(item, seen)
    elif isinstance(model, dict):
        for item in model.values():
            yield from _empty_fields(item, seen)


def _owner(write: Any) -> Any:
    """The record a passage's writer writes on (``section_agreement._setter``), or ``None``."""
    import inspect

    try:
        held = inspect.getclosurevars(write).nonlocals
    except (TypeError, ValueError):
        return None
    return held.get("obj")


def _without_ids(owner: Any, extra: frozenset[str]) -> bool:
    """Take each id of ``extra`` out of the record's own lists; whether one was taken out."""
    from malspark.reporting.section_agreement import _ids

    taken = False
    for listing in ("evidence_ids", "evidence_refs"):
        held = getattr(owner, listing, None)
        if not isinstance(held, list):
            continue
        kept = [value for value in held if not (_ids([value]) and _ids([value]) <= extra)]
        if len(kept) != len(held):
            held[:] = kept
            taken = True
    return taken


@dataclass
class PreRound:
    """The report as the round was given it, rebuilt, and what could not be put back."""

    report: Any
    narrative_written: bool
    discussion: list[dict[str, str]]
    not_found: list[str] = field(default_factory=list)
    not_writable: list[str] = field(default_factory=list)
    ids_taken_out: list[str] = field(default_factory=list)
    flagged_left_out: int = 0


def _passages(report: Any, narrative_written: bool, discussion: Any) -> list[Any]:
    from malspark.reporting.section_agreement import passages_of

    built: list[Any] = passages_of(
        report, narrative_written=narrative_written, discussion=discussion
    )
    return built


def pre_round_report(stored: Mapping[str, Any], prompt: str) -> PreRound:
    """The stored report with each passage's text put back to what ``prompt`` showed.

    Every passage the round may rewrite is put back through the round's own writer; one the
    round left with no text is found by filling every empty field for the lookup and emptying
    again each one no text was put in. The ids a rewrite added to its record's list are taken
    out where the prompt shows the passage citing none of them, and the round's own flagged
    statements (``agreement.*``) are left out."""
    from malspark.reporting.models import MalwareReport

    report = MalwareReport.model_validate(copy.deepcopy(dict(stored)))
    flagged = list(report.flagged_statements or [])
    report.flagged_statements = [
        f for f in flagged if not str(getattr(f, "code", "")).startswith(_CODE_PREFIX)
    ]
    shown = shown_of(prompt)
    narrative = any(p == "executive_summary" or p.startswith("key_findings.") for p in shown)
    discussion = discussion_of(shown)
    pre = PreRound(
        report=report,
        narrative_written=narrative,
        discussion=discussion,
        flagged_left_out=len(flagged) - len(report.flagged_statements),
    )
    wanted = {pid: s for pid, s in shown.items() if s.kind in _WRITTEN and not s.marked}
    live = {p.id: p for p in _passages(report, narrative, discussion)}
    filled: list[tuple[Any, str]] = []
    if any(pid not in live for pid in wanted):
        for owner, name in _empty_fields(report, set()):
            if owner.model_config.get("frozen"):
                # A frozen record is no field a passage writes.
                continue
            setattr(owner, name, _SENTINEL)
            filled.append((owner, name))
        live = {p.id: p for p in _passages(report, narrative, discussion)}
    for pid, said in wanted.items():
        passage = live.get(pid)
        if passage is None:
            pre.not_found.append(pid)
        elif passage.text != said.text:
            if passage.write is None:
                pre.not_writable.append(pid)
            else:
                passage.write(said.text)
    for owner, name in filled:
        if getattr(owner, name) == _SENTINEL:
            setattr(owner, name, "")
    for passage in _passages(report, narrative, discussion):
        shown_as = wanted.get(passage.id)
        extra = frozenset(passage.cites - shown_as.cites) if shown_as is not None else frozenset()
        owner = _owner(passage.write) if passage.write is not None else None
        if extra and owner is not None and _without_ids(owner, extra):
            pre.ids_taken_out.append(passage.id)
    return pre


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


@dataclass
class Recovery:
    """What one stored run gives the replay, and what it does not."""

    run: str
    path: str
    requests: int = 0
    request_found: bool = False
    retry_found: bool = False
    first_answer_found: bool = False
    final_answers_stored: bool = False
    first_answer_matches_record: bool | None = None
    prompt_reproduced: bool | None = None
    first_difference: int | None = None
    difference_context: tuple[str, str] = ("", "")
    passages_differing: list[str] = field(default_factory=list)
    not_found: list[str] = field(default_factory=list)
    not_writable: list[str] = field(default_factory=list)
    ids_taken_out: list[str] = field(default_factory=list)
    why: list[str] = field(default_factory=list)
    # What the replay is given: absent where the run gives it nothing to replay.
    case: dict[str, Any] | None = None

    def row(self) -> dict[str, Any]:
        out = asdict(self)
        out.pop("case")
        return out


def _stored_answers(report: Mapping[str, Any]) -> tuple[list[Any] | None, str]:
    """The round's answers the run's record keeps, each unchanged by its mask, and why none."""
    summary = report.get("run_summary") if isinstance(report.get("run_summary"), dict) else {}
    record = (summary or {}).get("section_agreement")
    if not isinstance(record, dict) or "answers" not in record:
        return None, "the run's record keeps no answer of the round"
    answers = record.get("answers") or []
    masked = record.get("answers_masked") or []
    if len(masked) < len(answers) or any(masked):
        return None, "the record's mask changed a stored answer, or one carries no flag"
    return list(answers), ""


def _ledger_inputs(run: Path) -> tuple[list[Any], Any, Any]:
    """The stored ledger, its entries' texts and the sandbox items, as the report rounds read
    them (``scripts.replay.rules._report_inputs``): no sandbox report and no corpus."""
    from scripts.replay.stored import evidence_rows

    from malspark.analysis.sandbox_sections import ItemCitations, item_index_of
    from malspark.pipeline.triage_pack import pack_entries
    from malspark.pipeline.validation import EntryTexts
    from malspark.reporting.follow_up import stored_ledger

    path = run / "evidence.json"
    rows = evidence_rows(json.loads(path.read_bytes()))[0] if path.is_file() else []
    ledger: list[Any] = stored_ledger(rows)[0]
    index = item_index_of(pack_entries(ledger))
    items = ItemCitations(index, None) if index is not None else None
    entries = EntryTexts.from_ledger(list(ledger), None)
    if items is not None:
        from malspark.pipeline.nodes import with_item_texts

        entries = with_item_texts(entries, items)
    return ledger, entries, items


def rebuilt_prompt(pre: PreRound, run: Path) -> str:
    """The prompt the round's own code builds from the rebuilt report and the stored ledger."""
    from malspark.reporting.section_agreement import passages_of, prompt_text

    _ledger, entries, _items = _ledger_inputs(run)
    passages = passages_of(
        copy.deepcopy(pre.report),
        narrative_written=pre.narrative_written,
        discussion=pre.discussion,
        entries=entries.entries.values() if entries is not None else (),
        degradations=[],
    )
    built: str = prompt_text(passages)
    return built


def _first_difference(a: str, b: str) -> int | None:
    if a == b:
        return None
    for at, (one, two) in enumerate(zip(a, b, strict=False)):
        if one != two:
            return at
    return min(len(a), len(b))


def recover(run: Path, name: str | None = None) -> Recovery:
    """What one stored run gives the replay: its requests, its answers, and the report as the
    round was given it, checked against the logged prompt."""
    from scripts.replay.stored import read_run

    found = Recovery(run=name or _name(run), path=str(run))
    log = run / "worker.log"
    if not log.is_file():
        found.why.append("no worker.log is stored")
        return found
    requests = agreement_requests(log)
    found.requests = requests.count
    found.request_found = requests.first is not None
    found.retry_found = requests.retry is not None
    if requests.first is None:
        found.why.append("the worker log holds no agreement request")
        return found
    answer = first_answer(requests.retry)
    found.first_answer_found = answer is not None
    if answer is None:
        found.why.append(
            "no retry request repeats the first answer"
            if requests.retry is not None
            else "the worker log holds no retry request"
        )
    stored = read_run(run)
    if stored.report is None:
        found.why.append("no report.json is stored")
        return found
    answers, why = _stored_answers(stored.report)
    found.final_answers_stored = answers is not None
    if answers is None:
        found.why.append(why)
    if answer is not None and answers:
        # Masked as the worker masked the record's copy (:func:`_rows_as_the_worker_keeps_them`).
        with _rows_as_the_worker_keeps_them():
            found.first_answer_matches_record = _parsed(answer) == answers[0]
    prompt = prompt_of(requests.first)
    pre = pre_round_report(stored.report, prompt)
    found.not_found, found.not_writable = pre.not_found, pre.not_writable
    found.ids_taken_out = pre.ids_taken_out
    rebuilt = rebuilt_prompt(pre, run)
    # The passages the round may answer, each as shown in the two prompts: a prompt an older
    # build wrote differs in its facts wherever the facts' code changed since.
    logged, again = shown_of(prompt), shown_of(rebuilt)
    found.passages_differing = sorted(
        pid
        for pid in set(logged) | set(again)
        if (logged.get(pid) or again.get(pid)).kind in _WRITTEN  # type: ignore[union-attr]
        and logged.get(pid) != again.get(pid)
    )
    at = _first_difference(rebuilt, prompt)
    found.prompt_reproduced = at is None
    found.first_difference = at
    if at is not None:
        found.difference_context = (
            prompt[max(0, at - 60) : at + 60],
            rebuilt[max(0, at - 60) : at + 60],
        )
    turns: list[Any] = []
    source = ""
    if answer is not None:
        turns.append(answer)
        source = "first answer from the retry request"
    elif answers:
        turns.append(answers[0])
        source = "first answer from the run's record"
    if turns and answers and len(answers) > 1:
        turns.extend(answers[1:])
        source += "; retry answer from the run's record"
    if not turns:
        return found
    found.case = {
        "run": found.run,
        "path": str(run),
        "report": pre.report.model_dump(mode="json"),
        "narrative_written": pre.narrative_written,
        "discussion": pre.discussion,
        "answers": turns,
        "answer_source": source,
        "first_turn_only": len(turns) < 2,
        "settings": stored.settings,
    }
    return found


def _name(run: Path) -> str:
    """A run's name as the benchmark keeps it: ``family/1`` for a numbered job directory."""
    return f"{run.parent.name}/{run.name}" if run.name.isdigit() else run.name


def _parsed(answer: Any) -> Any:
    """An answer as the round keeps it in its record: parsed, masked (``_parse``)."""
    from langchain_core.messages import AIMessage

    from malspark.llm.answer_text import structured_answer_text
    from malspark.reporting.narrative_agent import _message_text
    from malspark.reporting.section_agreement import _masked_answer
    from malspark.utils.json_cleaner import safe_parse_json

    if not isinstance(answer, str):
        return answer
    read = structured_answer_text(AIMessage(content=answer), _message_text)
    parsed = safe_parse_json(read)
    return _masked_answer(parsed if isinstance(parsed, dict | list) else read)


# ---------------------------------------------------------------------------
# The replay
# ---------------------------------------------------------------------------


class _Stub:
    """The model's place in the round: each turn answered with the stored answer for it, a
    turn none is stored for with no rows."""

    def __init__(self, answers: Sequence[Any]) -> None:
        self.answers = [a if isinstance(a, str) else json.dumps(a) for a in answers]
        self.asked = 0
        self.unanswered = 0
        self.degradations: list[str] = []

    async def ask(self, turns: list[Any], *_args: Any, **_kwargs: Any) -> Any:
        from langchain_core.messages import AIMessage

        place = self.asked
        self.asked += 1
        if place >= len(self.answers):
            self.unanswered += 1
            return AIMessage(content=_NO_ROWS)
        return AIMessage(content=self.answers[place])


def texts_of(report: Any, narrative_written: bool, discussion: Any) -> dict[str, dict[str, Any]]:
    """Each passage the round may answer, by id: its kind and its text as the report prints
    it, a text printed in its writer's own words without the sentences the round left out."""
    from malspark.reporting.section_agreement import passages_of

    try:
        from malspark.reporting.section_agreement import left_out_of
    except ImportError:  # a tree from before verbatim passages were asked (T-613)
        left_out_of = None
    dropped: dict[str, list[str]] = {}
    for row in getattr(report, "flagged_statements", None) or []:
        if str(getattr(row, "code", "")) == "agreement.dropped":
            dropped.setdefault(str(getattr(row, "label", "")), []).append(str(row.sentence))
    out: dict[str, dict[str, Any]] = {}
    for passage in passages_of(report, narrative_written=narrative_written, discussion=discussion):
        if passage.kind not in _WRITTEN or getattr(passage, "source_only", False):
            continue
        text = passage.text
        if getattr(passage, "verbatim", "") and left_out_of is not None:
            text = left_out_of(text, dropped.get(passage.id, []))[0]
        out[passage.id] = {
            "kind": passage.kind,
            "text": text,
            "verbatim": bool(getattr(passage, "verbatim", "")),
        }
    return out


def _flagged(report: Any) -> list[dict[str, Any]]:
    return [
        row.model_dump(mode="json")
        for row in getattr(report, "flagged_statements", None) or []
        if str(getattr(row, "code", "")).startswith(_CODE_PREFIX)
    ]


def _rows_of(answer: Any) -> list[dict[str, Any]]:
    parsed = _parsed(answer) if isinstance(answer, str) else answer
    raw = parsed.get("sentences") if isinstance(parsed, dict) else parsed
    return [row for row in raw if isinstance(row, dict)] if isinstance(raw, list) else []


def _plain(text: Any) -> str:
    return " ".join(str(text or "").split())


def _row_ends(
    answers: Sequence[Any],
    before: Mapping[str, Mapping[str, Any]],
    after: Mapping[str, Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Every row of every answer with what became of its sentence: replaced by the retry's
    row for it, or, read off the passage after the round, rewritten, kept or left out; and
    the codes of the round's records that quote it."""
    turns = [_rows_of(answer) for answer in answers]
    later = {
        (str(row.get("passage") or ""), _plain(row.get("sentence")))
        for rows in turns[1:]
        for row in rows
    }
    out: list[dict[str, Any]] = []
    for turn, rows in enumerate(turns, 1):
        for index, row in enumerate(rows, 1):
            pid = str(row.get("passage") or "")
            sentence = _plain(row.get("sentence"))
            rewrite = _plain(row.get("rewrite"))
            was = _plain((before.get(pid) or {}).get("text"))
            now = _plain((after.get(pid) or {}).get("text"))
            if turn < len(turns) and (pid, sentence) in later:
                end = "replaced by the retry's row"
            elif not sentence or sentence not in was:
                end = "its sentence does not stand in the passage as given"
            elif sentence in now:
                end = "stands as written"
            elif rewrite and rewrite in now:
                end = "rewritten as answered"
            elif pid not in after:
                end = "left out with its passage"
            else:
                end = "left out or changed by the platform"
            head = sentence[:60]
            codes = sorted(
                {
                    str(r.get("code"))
                    for r in records
                    if head and head in _plain(r.get("message")) + " " + _plain(r.get("stood"))
                }
            )
            out.append(
                {
                    "turn": turn,
                    "row": index,
                    "passage": pid,
                    "sentence": sentence,
                    "decision": str(row.get("decision") or ""),
                    "rewrite": rewrite,
                    "end": end,
                    "codes": codes,
                }
            )
    return out


@contextmanager
def _rows_as_the_worker_keeps_them() -> Iterator[None]:
    """The finding rows' masking as in the worker that ran the round.

    The worker registers the job's configured values, and a finding row then keeps its words,
    only a configured value masked (``events.safe_finding_value``); a process with none
    registered holds a row to the whole event scrub, which shortens a URL and masks a long
    name. One value of the harness's own, made at random and held by no text, is registered
    for the block, and the registry is put back as it was after it. A tree without the
    registry is left as it is."""
    import secrets

    try:
        from malspark.pipeline import events
    except ImportError:
        yield
        return
    names = ("_SECRET_SCOPES", "_SHORT_SECRETS", "_FAILED_SCOPES", "_CONFIGURED_PATTERN")
    remember = getattr(events, "remember_secret_values", None)
    if remember is None or not all(hasattr(events, n) for n in names):
        yield
        return
    saved = {n: copy.copy(getattr(events, n)) for n in names}
    try:
        remember([f"replay-{secrets.token_hex(16)}"], scope="agreement-replay")
        yield
    finally:
        for name, value in saved.items():
            setattr(events, name, value)


def replay_case(case: Mapping[str, Any]) -> dict[str, Any]:
    """The round re-run over one recovered case under the tree this process imports."""
    from scripts.replay.guard import replay_environment
    from scripts.replay.stored import check_unchanged, digests

    import malspark
    from malspark.reporting.models import MalwareReport
    from malspark.reporting.section_agreement import ask_section_agreement

    run = Path(str(case["path"]))
    before_files = digests(run)
    with replay_environment(case.get("settings") or {}) as env, _rows_as_the_worker_keeps_them():
        ledger, entries, items = _ledger_inputs(run)
        report = MalwareReport.model_validate(copy.deepcopy(case["report"]))
        narrative = bool(case.get("narrative_written", True))
        discussion = list(case.get("discussion") or [])
        before = texts_of(report, narrative, discussion)
        stub = _Stub(case.get("answers") or [])
        done = asyncio.run(
            ask_section_agreement(
                stub,
                report,
                narrative_written=narrative,
                discussion=discussion,
                citable_ids=[str(entry.id) for entry in ledger],
                items=items,
                evidence_texts=entries,
            )
        )
        after = texts_of(report, narrative, discussion)
        tally = done.tally.to_dict()
        settings = {"applied": env.settings_applied, "refused": env.settings_refused}
    check_unchanged(before_files, digests(run))
    records = [dict(row) for row in tally.get("unresolved") or []]
    return {
        "run": case.get("run"),
        "tree": str(Path(malspark.__file__).resolve().parents[1]),
        "answer_source": case.get("answer_source"),
        "first_turn_only": bool(case.get("first_turn_only")),
        "turns_asked": stub.asked,
        "turns_unanswered": stub.unanswered,
        "before": before,
        "after": after,
        "records": records,
        "by_code": {
            code: count
            for code, count in (tally.get("by_code") or {}).items()
            if str(code).startswith(_CODE_PREFIX)
        },
        "summary": {k: v for k, v in done.summary.items() if k not in _SUMMARY_SKIP},
        "flagged": _flagged(report),
        "degradations": list(done.degradations),
        "settings": settings,
        "rows": _row_ends(case.get("answers") or [], before, after, records),
    }


# ---------------------------------------------------------------------------
# Against the stored round
# ---------------------------------------------------------------------------


def _cut(text: str, at: int) -> str:
    return text[max(0, at - 40) : at + 40]


def against_stored(run: Path, case: Mapping[str, Any], record: Mapping[str, Any]) -> list[str]:
    """Every difference between the replay and the round as the run stored it: each passage's
    final text, each outcome record in order, the codes counted, the counts and the flagged
    statements. Empty where the replay reproduces the stored round exactly."""
    from malspark.reporting.models import MalwareReport

    stored = json.loads((run / "report.json").read_bytes())
    report = MalwareReport.model_validate(stored)
    texts = texts_of(report, bool(case.get("narrative_written", True)), case.get("discussion"))
    out: list[str] = []
    after = record["after"]
    for pid in sorted(set(texts) | set(after)):
        a, b = (after.get(pid) or {}).get("text"), (texts.get(pid) or {}).get("text")
        if a == b:
            continue
        if a is None or b is None:
            out.append(f"passage {pid}: {'only stored' if a is None else 'only replayed'}")
            continue
        at = _first_difference(a, b) or 0
        out.append(
            f"passage {pid}: final text differs at {at}: replay {_cut(a, at)!r}, "
            f"stored {_cut(b, at)!r}"
        )
    summary = stored.get("run_summary") or {}
    rows = [
        r
        for r in ((summary.get("validation") or {}).get("unresolved") or [])
        if isinstance(r, dict) and str(r.get("agent")) == "agreement"
    ]
    replayed = list(record["records"])
    if len(rows) != len(replayed):
        out.append(f"records: {len(replayed)} replayed, {len(rows)} stored")
    for index, (one, two) in enumerate(zip(replayed, rows, strict=False), 1):
        if one != two:
            keys = sorted(k for k in set(one) | set(two) if one.get(k) != two.get(k))
            out.append(
                f"record {index} ({one.get('code')} / {two.get('code')}): differs in "
                + ", ".join(keys)
            )
    for code, count in sorted(
        (Counter(r.get("code") for r in replayed) - Counter(r.get("code") for r in rows)).items()
    ):
        out.append(f"records: {count} more {code} replayed than stored")
    for code, count in sorted(
        (Counter(r.get("code") for r in rows) - Counter(r.get("code") for r in replayed)).items()
    ):
        out.append(f"records: {count} more {code} stored than replayed")
    counted = {
        k: v
        for k, v in ((summary.get("validation") or {}).get("by_code") or {}).items()
        if str(k).startswith(_CODE_PREFIX)
    }
    if counted != record["by_code"]:
        out.append(f"codes counted: replay {record['by_code']}, stored {counted}")
    kept = {
        k: v for k, v in (summary.get("section_agreement") or {}).items() if k not in _SUMMARY_SKIP
    }
    for key in sorted(set(kept) | set(record["summary"])):
        if kept.get(key) != record["summary"].get(key):
            out.append(
                f"count {key}: replay {record['summary'].get(key)!r}, stored {kept.get(key)!r}"
            )
    flagged = [
        r
        for r in report.model_dump(mode="json").get("flagged_statements") or []
        if str(r.get("code", "")).startswith(_CODE_PREFIX)
    ]
    if flagged != record["flagged"]:
        out.append(
            f"flagged statements: {len(record['flagged'])} replayed, {len(flagged)} stored, "
            "not the same"
        )
    return out


# ---------------------------------------------------------------------------
# Two refs
# ---------------------------------------------------------------------------


def _sentences(text: str) -> list[str]:
    from malspark.reporting.section_agreement import _sentences_of

    return [_plain(s) for s in _sentences_of(text) if s.strip()]


def diff_records(a: Mapping[str, Any], b: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every difference between two replays of one run: each sentence whose final text
    differs (printed under one ref only), each sentence of the passage as given left out
    under one ref only, and each outcome code gained or lost (B against A)."""
    run = str(a.get("run") or b.get("run") or "")
    out: list[dict[str, Any]] = []
    given = {**b.get("before", {}), **a.get("before", {})}
    for pid in sorted(set(a.get("after", {})) | set(b.get("after", {})) | set(given)):
        one = (a.get("after", {}).get(pid) or {}).get("text") or ""
        two = (b.get("after", {}).get(pid) or {}).get("text") or ""
        if one == two:
            continue
        first, second = _sentences(one), _sentences(two)
        for sentence in first:
            if sentence not in second:
                out.append(
                    {"run": run, "kind": "text", "passage": pid, "only": "A", "sentence": sentence}
                )
        for sentence in second:
            if sentence not in first:
                out.append(
                    {"run": run, "kind": "text", "passage": pid, "only": "B", "sentence": sentence}
                )
        for sentence in _sentences((given.get(pid) or {}).get("text") or ""):
            in_one, in_two = sentence in _plain(one), sentence in _plain(two)
            if in_one != in_two:
                out.append(
                    {
                        "run": run,
                        "kind": "left_out",
                        "passage": pid,
                        "only": "B" if in_one else "A",
                        "sentence": sentence,
                    }
                )
    codes_a = Counter(str(r.get("code")) for r in a.get("records") or [])
    codes_b = Counter(str(r.get("code")) for r in b.get("records") or [])
    for code in sorted(set(codes_a) | set(codes_b)):
        if codes_a[code] != codes_b[code]:
            out.append(
                {
                    "run": run,
                    "kind": "code",
                    "code": code,
                    "change": "gained" if codes_b[code] > codes_a[code] else "lost",
                    "A": codes_a[code],
                    "B": codes_b[code],
                }
            )
    return out


def unexpected(
    differences: Iterable[Mapping[str, Any]], expect: Sequence[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    """The differences no entry of ``expect`` matches; an entry matches a difference whose
    every field it names holds the value it gives."""
    return [
        d for d in differences if not any(all(d.get(k) == v for k, v in e.items()) for e in expect)
    ]


def _printed(label: Mapping[str, Any], texts: Mapping[str, Mapping[str, Any]]) -> bool | None:
    """Whether a labelled text is printed in the final text of its passage (of any, where the
    label names none); ``None`` where the passage is not there at all."""
    said = _plain(label.get("text"))
    pid = label.get("passage")
    if pid:
        if pid not in texts:
            return False
        return said in _plain(texts[pid].get("text"))
    return any(said in _plain(t.get("text")) for t in texts.values())


def label_lines(
    labels: Sequence[Mapping[str, Any]], records: Mapping[str, Mapping[str, Mapping[str, Any]]]
) -> list[dict[str, Any]]:
    """Per label, whether its text is printed as stored before the round and under each ref
    (``records``: ref name to the replays of each run by name)."""
    out: list[dict[str, Any]] = []
    for label in labels:
        run = str(label.get("run") or "")
        row: dict[str, Any] = {
            "run": run,
            "passage": label.get("passage"),
            "label": str(label.get("label") or ""),
            "text": str(label.get("text") or ""),
            "printed": {},
        }
        for ref, by_run in records.items():
            record = by_run.get(run)
            if record is None:
                row["printed"][ref] = None
                continue
            if "before" not in row["printed"]:
                row["printed"]["before"] = _printed(label, record.get("before") or {})
            row["printed"][ref] = _printed(label, record.get("after") or {})
        out.append(row)
    return out


def _replay_under(
    tree: Path, cases: Sequence[Path], out: Path, timeout: float
) -> list[dict[str, Any]]:
    """Each case replayed by this harness over ``tree``'s rules, in a process of its own."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(tree / "src"), str(_ROOT)])
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--replay-cases",
        *(str(c) for c in cases),
        "--json",
        str(out),
    ]
    done = subprocess.run(  # nosec B603 — the harness itself, an argument list
        command, env=env, cwd=out.parent, capture_output=True, check=False, timeout=timeout
    )
    if done.returncode != 0 or not out.is_file():
        kept = out.with_name(f"{out.stem}-stderr.txt")
        kept.write_bytes(done.stderr)
        raise RuntimeError(f"the replay under {tree} wrote no record (its error output: {kept})")
    records: list[dict[str, Any]] = json.loads(out.read_text(encoding="utf-8"))
    for record in records:
        if not str(record.get("tree", "")).startswith(str(tree.resolve())):
            raise RuntimeError(
                f"the replay under {tree} imported its rules from {record.get('tree')}"
            )
    return records


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def _safe(value: object) -> str:
    from scripts.replay.output import terminal_safe

    return terminal_safe(value)


def _yes(value: bool | None) -> str:
    return "-" if value is None else "yes" if value else "no"


def _print_recovery(rows: Sequence[Recovery]) -> None:
    print(
        "run | requests | request | first answer | final answers | prompt reproduced | "
        "written passages differing"
    )
    for row in rows:
        where = "" if row.first_difference is None else f" (differs at {row.first_difference})"
        print(
            f"{_safe(row.run)} | {row.requests} | {_yes(row.request_found)} | "
            f"{_yes(row.first_answer_found)} | {_yes(row.final_answers_stored)} | "
            f"{_yes(row.prompt_reproduced)}{where} | "
            f"{len(row.passages_differing) if row.request_found else '-'}"
        )


def _print_record(record: Mapping[str, Any]) -> None:
    changed = [p for p in record["after"] if record["after"][p] != record["before"].get(p)]
    gone = [p for p in record["before"] if p not in record["after"]]
    print(
        f"== {_safe(record['run'])}: {record['turns_asked']} turn(s) asked"
        + (" (first turn only)" if record["first_turn_only"] else "")
        + f"; {len(changed)} passage(s) changed, {len(gone)} left out; "
        + ", ".join(
            f"{_safe(c)} x{n}"
            for c, n in sorted(Counter(r["code"] for r in record["records"]).items())
        )
    )
    for row in record["rows"]:
        print(
            f"   turn {row['turn']} row {row['row']} [{_safe(row['passage'])}] "
            f"{_safe(row['decision'])}: {_safe(row['end'])}"
            + (f" ({', '.join(_safe(c) for c in row['codes'])})" if row["codes"] else "")
        )


def _read_list(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _write(path: Path, value: Any) -> None:
    from scripts.replay.output import write_json

    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, value, indent=2)


def _print_labels(lines: Sequence[Mapping[str, Any]]) -> None:
    for line in lines:
        printed = ", ".join(f"{_safe(ref)}: {_yes(said)}" for ref, said in line["printed"].items())
        print(
            f" - label {_safe(line['label'])} [{_safe(line['run'])}"
            f"{' ' + _safe(line['passage']) if line['passage'] else ''}] printed: {printed}"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python scripts/replay/agreement_round.py",
        description=(__doc__ or "").split("\n", 1)[0],
        epilog=LIMITS,
    )
    parser.add_argument("runs", nargs="*", type=Path, help="stored run directories")
    parser.add_argument("--out", type=Path, default=None, help="write each record here")
    parser.add_argument("--recover-only", action="store_true", help="recover, replay nothing")
    parser.add_argument(
        "--check-stored",
        action="store_true",
        help="compare the replay with the stored round where its answers are stored",
    )
    parser.add_argument("--compare", nargs=2, metavar=("REF_A", "REF_B"), default=None)
    parser.add_argument("--expect", type=Path, default=None, help="expected differences (JSON)")
    parser.add_argument("--labels", type=Path, default=None, help="labelled sentences (JSON)")
    parser.add_argument("--repo", type=Path, default=_ROOT, help="the repository of the refs")
    parser.add_argument("--timeout", type=float, default=900.0, help="seconds per ref")
    parser.add_argument(
        "--replay-cases", nargs="+", type=Path, default=None, help=argparse.SUPPRESS
    )
    parser.add_argument("--json", type=Path, default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.replay_cases is not None:
        # One ref's process: each recovered case replayed under the tree it imports.
        cases = [json.loads(p.read_text(encoding="utf-8")) for p in args.replay_cases]
        _write(args.json, [replay_case(case) for case in cases])
        return 0
    if not args.runs:
        _parser().error("name at least one stored run")
    out: Path | None = args.out
    recovered = [recover(run) for run in args.runs]
    _print_recovery(recovered)
    for row in recovered:
        if row.not_found or row.not_writable:
            print(
                f"   {_safe(row.run)}: not found {row.not_found}, not writable {row.not_writable}"
            )
    if out is not None:
        _write(out / "recovery.json", [row.row() for row in recovered])
    if args.recover_only:
        return 0
    cases = [row for row in recovered if row.case is not None]
    labels = _read_list(args.labels)
    if args.compare is None:
        records: dict[str, dict[str, Any]] = {}
        status = 0
        for row in cases:
            assert row.case is not None
            record = replay_case(row.case)
            records[row.run] = record
            _print_record(record)
            if args.check_stored and row.final_answers_stored:
                found = against_stored(Path(row.path), row.case, record)
                record["against_stored"] = found
                print(f"   against the stored round: {len(found)} difference(s)")
                for line in found:
                    print(f"     {_safe(line)}")
                status = status or (1 if found else 0)
            if out is not None:
                _write(out / f"{row.run.replace('/', '-')}.json", record)
        if labels:
            lines = label_lines(labels, {"HEAD": records})
            _print_labels(lines)
            if out is not None:
                _write(out / "labels.json", lines)
        return status
    if out is None:
        _parser().error("--compare needs --out, where each ref's tree and records are written")
    from scripts.replay.compare import materialise

    paths = []
    for row in cases:
        assert row.case is not None
        path = out / "cases" / f"{row.run.replace('/', '-')}.json"
        _write(path, row.case)
        paths.append(path.resolve())
    by_ref: dict[str, dict[str, dict[str, Any]]] = {}
    for side, ref in zip(("A", "B"), args.compare, strict=True):
        tree = materialise(args.repo, ref, out / f"tree-{side}")
        replays = _replay_under(tree, paths, (out / f"records-{side}.json").resolve(), args.timeout)
        by_ref[side] = {str(r["run"]): r for r in replays}
    differences = [
        d
        for run in by_ref["A"]
        if run in by_ref["B"]
        for d in diff_records(by_ref["A"][run], by_ref["B"][run])
    ]
    left = unexpected(differences, _read_list(args.expect))
    _write(out / "differences.json", differences)
    if args.check_stored:
        # Each ref's replay against the round as stored, where its answers are stored.
        for row in cases:
            if not row.final_answers_stored or row.case is None:
                continue
            for side, ref in zip(("A", "B"), args.compare, strict=True):
                replayed = by_ref[side].get(row.run)
                if replayed is None:
                    continue
                found = against_stored(Path(row.path), row.case, replayed)
                print(
                    f"{_safe(row.run)} under {_safe(ref)} against the stored round: "
                    f"{len(found)} difference(s)"
                )
                for line in found:
                    print(f"   {_safe(line)}")
    print(f"== {args.compare[0]} (A) against {args.compare[1]} (B)")
    for d in differences:
        mark = "  " if d not in left else "! "
        if d["kind"] == "code":
            print(
                f"{mark}{_safe(d['run'])}: {_safe(d['code'])} {d['change']} ({d['A']} -> {d['B']})"
            )
        else:
            print(
                f"{mark}{_safe(d['run'])} [{_safe(d['passage'])}] {d['kind']} under "
                f"{d['only']} only: {_safe(d['sentence'][:160])}"
            )
    if labels:
        lines = label_lines(labels, by_ref)
        _print_labels(lines)
        _write(out / "labels.json", lines)
    print(f"{len(differences)} difference(s), {len(left)} not expected")
    return 1 if left else 0


if __name__ == "__main__":
    raise SystemExit(main())
