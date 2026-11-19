"""Re-run a stored run's agreement round on the model's stored answers, at zero cost.

As the stored runs stand, none replays without ``--allow-differing``: the retry turn the
round sends differs from the logged one in every run that has an agreement request, so the
tool is a comparison instrument on rebuilt inputs only, not a reproduction of what a run did.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/agreement_round.py <run dir> [<run dir> ...] [--out DIR]

recovers, per run, what the agreement round (``reporting.section_agreement``) was given and
answered, and puts the answers through the round's own code under this tree, with a stub in
place of the model:

- the round's first request and its retry request, read line by line from ``worker.log``
  and chosen by the round's system text; the passages as the first request showed them;
- the model's first answer: the assistant turn the retry request repeats, its raw text; and,
  where the run's record keeps them (``run_summary.section_agreement.answers`` of
  ``report.json``, each left unchanged by the record's mask), the answers of both turns, as
  parsed (a parsed answer is fed re-serialised, and marked ``answer_reserialised``);
- the report as the round was given it: the stored report is the one after the round, so
  each passage's text is put back to what the first request showed (with the ids a rewrite
  added to its record's list taken out again, and the round's own flagged statements left
  out), and the round's own ``passages_of`` builds its passages, with their cites,
  addresses, values, checks and writers, from it. The debate's mediations are read off the
  request. The reconstruction is checked: the prompt the round's code builds from it must
  equal the logged one, and where it does not the first differing position is said.

The replay hands the stub the first answer for the first turn (the log's raw text where the
log holds it, the record's copy otherwise) and, for the retry, the retry's stored answer;
where none is stored the run is marked "first turn only" and the
retry is answered with no rows, as the round's own re-applier answers a turn it holds no
answer for (``section_agreement.StoredAnswers``); the round then acts on an empty retry the
run did not have, and every record, difference and label line of such a run says
``first_turn_only``. A first answer the log repeats otherwise than the record keeps it is
said (``first_answer_matches_record``). It records every passage's text before
and after, every outcome record of the round (``agreement.*``), its counts and flagged
statements, and every row of the answers with what became of it: applied, kept, left out,
or replaced by the retry's row, with the records that name it.

The two prompts are compared block by block and by kind: the written passages, the facts
(which the round reads as sources), the judge's decision and the debate's mediations, each
block with the lines asked under it, and the text outside them; per kind, the blocks shown
in the logged prompt only, in the rebuilt one only, and in both with another text are named
(``blocks_differing``, with ``passages_differing`` and ``facts_differing``). Where the
rebuilt prompt is not the logged one, the round is given an input the model was not shown:
every record, difference and label line carries ``prompt_reproduced``,
``first_difference`` and the differing blocks, and says which kinds differ and how many. A
block shown in both at another place is named under ``order``. Every human turn the round
sends is also checked, inside the stub, against the logged turn of the same position by
the same comparison: the first turn as sent (``first_turn_sent_reproduced``) and the retry's
correction turn (``retry_reproduced``, ``retry_first_difference``,
``retry_blocks_differing``). A run whose prompt differs in any block, in their order or
outside them, or whose retry turn differs, is replayed only under ``--allow-differing``, and
such a replay is a replay on a rebuilt input, not a reproduction of what the run did (under
``--compare``, a comparison of refs on a rebuilt input), said once per run and in the summary
line; without the flag the run is refused, and so is a log holding more requests than the
round's two (more than one job's round). A label of a refused run says why, and one of a run
not replayed says so. The command ends with status 3 where a run is refused, and 5 where a
run is refused and a difference no expectation excuses is found as well, printed under the
refusals. The command refuses to start, with status 4, where the round's code is imported
from another tree than this one.

``--check-stored`` also compares, for a run whose record keeps the round's answers, the
replay's passages, records and whole report with the stored ones, and names every
difference.

``--compare REF_A REF_B`` replays the same recovered input under two git refs, in the manner
of ``scripts/replay/compare.py``: each ref's ``src`` and ``data`` are written out of the
object store, and this harness runs over that tree in a process of its own. Per run it
lists the sentences whose final text differs, the sentences left out under one ref only,
and the outcome codes gained and lost. ``--expect FILE`` (a JSON list of expected
differences, kept outside git, each matching every difference whose fields it gives)
excuses differences; the command ends with status 1 on any difference no entry matches,
0 otherwise. Each ref's round checks every human turn it sends against the logged one,
printed per ref; the pre-round report is rebuilt, and a run refused, by the code this
command runs from. With ``--check-stored``, ref A's differences from the stored round on a
run whose first turn is reproduced count toward the status (the harness testing itself),
whatever its retry and re-serialised answers, whose marks are printed beside them; ref B's,
the change measured, are printed only.

``--labels FILE`` (a JSON list of labelled sentences kept outside git, each with ``run``,
``text``, ``label`` ``false`` or ``true``, and ``passage`` where it is known) states, per
label, whether that exact text is printed in the final text of its passage (of any passage
where none is given) under each ref, and as stored before the round. Results are judged by
these labels, never by the code's own reading of a contradiction.

Limits: final answers are replayed only where the run's record stores them (the record keeps
the round's answers since T-736); a first answer is recovered only where the retry request
repeats it (a first answer the retry left out, and a round that needed no retry, give
none); an answer only the record keeps is fed re-serialised from its parsed form, not as the
text the round read; the passages are put back from the prompt, so a text the prompt does
not show is the stored one; the facts are rebuilt from the shortened stored ledger, the one
after its byte budget, and no sandbox report nor evidence corpus is stored, so an item's or
an entry's text is read as stored. Where the retry is the harness's own empty answer, any
difference in how a retry is handled is measured on a turn the run never had. The harness
shows what the code does with a given answer, not what a model would answer to a changed
question; results are judged by the labels, not by the code's own reading.

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
# The tree whose ``src`` the round's code is imported from: this checkout's, or, in a ref's
# own process under ``--compare``, that ref's tree as written out of the object store. Its
# ``src`` stands first, ahead of any installed copy of the package elsewhere.
TREE_VARIABLE = "AGREEMENT_REPLAY_TREE"
_TREE = Path(os.environ.get(TREE_VARIABLE) or _ROOT).resolve()


def _put_tree_first() -> None:
    """Put this checkout and the measured tree's ``src`` first on the path: done when the
    harness runs as a program, never on import, so an importing process keeps its own."""
    for path in (str(_ROOT), str(_ROOT / "apps" / "api"), str(_TREE / "src")):
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)


# The command's statuses: a difference no expectation excuses, a run refused, the round's
# code another tree's, and a difference no expectation excuses with a run refused.
DIFFERENCES = 1
REFUSED = 3
WRONG_TREE = 4
REFUSED_AND_DIFFERING = 5
STATUSES = (
    "Exit status: 0 where every replayed run ends as expected; 1 where a difference no "
    "expectation excuses is found (under --check-stored, any difference from the stored "
    "round; under --compare with --check-stored, also any difference of ref A's replay from "
    "the stored round on a run whose first turn is reproduced, whatever its retry and "
    "re-serialised answers, ref B's being printed and never counted); 2 on "
    "a usage error; 3 where a run is refused and no such difference is found; "
    "4 where the round's code is imported from another tree than this one; 5 where a run is "
    "refused and such a difference is found as well."
)

# Said once in the output of two refs: what each ref checks of its own input.
COMPARE_NOTE = (
    "note: each ref checks every human turn its own round sends against the logged turn of "
    "the same position (printed per ref); the pre-round report is rebuilt, and a run refused, "
    "by the code this command runs from"
)
# What a replay of a rebuilt input is, of one tree and under two refs, and what a retry the
# run never had measures: said once per such run and in the summary line.
REPLAY_NOTE = "a replay on a rebuilt input, not a reproduction of what the run did"
REBUILT_NOTE = "a comparison of refs on a rebuilt input, not a reproduction of what the run did"
EMPTY_RETRY_NOTE = (
    "any difference in how a retry is handled is measured on a turn the run never had"
)

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
    "Limits: final answers are replayed only where the run's record stores them; where the "
    "retry's answer is not stored the retry is answered with no rows, an empty retry the run "
    "did not have, the run is marked first_turn_only, and " + EMPTY_RETRY_NOTE + "; a first "
    "answer is recovered only where the retry request repeats it, and the model's raw answer "
    "text is fed only where the log holds it: an answer only the record keeps is fed "
    "re-serialised from its parsed form, which need not be the text the round read, and the "
    "run is marked answer_reserialised; a text the prompt does not show is the stored one; "
    "the facts are rebuilt from the shortened stored ledger (the ledger after its byte "
    "budget), and no sandbox report or evidence corpus is stored; where the rebuilt prompt "
    "or the retry turn the round sends is not the logged one the round acts on an input the "
    "model was not shown, and a run whose first turn differs in any block (a written passage, "
    "a fact, the judge's decision, a debate mediation), in the blocks' order or outside them, "
    "or whose retry turn differs, is replayed only under --allow-differing, every line of it "
    "marked with the kinds that differ and how many, and said to be " + REPLAY_NOTE + " "
    "(under --compare, " + REBUILT_NOTE + "); "
    "under --compare the pre-round report is rebuilt and a run refused by the code this "
    "command runs from, while each ref checks the turns its own round sends; the harness "
    "shows what the code does with a given answer, not what a model would answer to a "
    "changed question; results are judged by the labels, not by the code's own reading."
)
# What a replay's input is, carried by every record, difference and label line of its run.
MARKS = (
    "prompt_reproduced",
    "first_difference",
    "passages_differing",
    "facts_differing",
    "blocks_differing",
    "first_turn_sent_reproduced",
    "retry_reproduced",
    "retry_first_difference",
    "retry_blocks_differing",
    "first_turn_only",
    "first_answer_matches_record",
    "answer_reserialised",
)
# The kinds of block a prompt is compared by, as ``blocks_differing`` names them, and what
# each block's difference is: present in the logged prompt only, in the rebuilt one only, or
# in both with another text. ``order`` names the blocks shown in both whose order differs;
# ``outside`` is the prompt's text outside every block.
BLOCK_KINDS = ("written", "fact", "judge", "debate", "order", "outside")
_COUNTED = BLOCK_KINDS[:4]
_WHERE = ("only_logged", "only_rebuilt", "text")
_KIND_NAMES = {
    "written": "written passage(s)",
    "fact": "fact block(s)",
    "judge": "judge block(s)",
    "debate": "debate block(s)",
}


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
            if found.count > 2:
                # A second job's round: counted, its turns not kept.
                continue
            turns = _turns(data)
            if found.first is None:
                found.first = turns
            if found.retry is None and _feedback_at(turns) is not None:
                found.retry = turns
    return found


def human_turns(turns: Sequence[Mapping[str, Any]] | None) -> list[str]:
    """A request's human turns in order, its tool replies left out: the retry request repeats
    the first turn and adds its correction after the answer."""
    return [str(t["text"]) for t in turns or () if t["role"] == "user" and not t["tool"]]


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


def blocks_of(prompt: str) -> tuple[dict[str, tuple[str, str]], str]:
    """Every block the prompt shows, by id: its kind and its whole text, the passage's line
    with the lines asked under it up to the next passage, heading or empty line; and the
    prompt's text outside every block."""
    from scripts.replay.agreement_names import _KINDS, _PASSAGE

    kind = ""
    blocks: dict[str, tuple[str, str]] = {}
    outside: list[str] = []
    current: str | None = None
    for line in prompt.split("\n"):
        if line.strip() in _KINDS:
            kind, current = _KINDS[line.strip()], None
            outside.append(line)
            continue
        found = _PASSAGE.match(line) if kind else None
        if found:
            current = found.group(1)
            while current in blocks:
                # The same id shown twice: each block is compared on its own.
                current += "#"
            blocks[current] = (kind, line)
            continue
        if current is not None and line.strip():
            held, text = blocks[current]
            blocks[current] = (held, f"{text}\n{line}")
            continue
        current = None
        outside.append(line)
    return blocks, "\n".join(outside)


def block_differences(logged: str, rebuilt: str) -> dict[str, dict[str, list[str]]]:
    """Where two prompts differ, block by block and by kind (``BLOCK_KINDS``): per kind, the
    ids of the blocks shown in the logged prompt only, in the rebuilt one only, and in both
    with another text; the blocks shown in both at another place in their order (``order``,
    as the logged prompt orders them); and the text outside them. Empty where the two are the
    same."""
    one, outside_one = blocks_of(logged)
    two, outside_two = blocks_of(rebuilt)
    out: dict[str, dict[str, list[str]]] = {}
    for pid in sorted(set(one) | set(two)):
        if one.get(pid) == two.get(pid):
            continue
        held = (one.get(pid) or two.get(pid) or ("", ""))[0]
        kind = "written" if held in _WRITTEN else held
        where = "only_rebuilt" if pid not in one else "only_logged" if pid not in two else "text"
        out.setdefault(kind, {w: [] for w in _WHERE})[where].append(pid)
    order_one = [pid for pid in one if pid in two]
    order_two = [pid for pid in two if pid in one]
    moved = [a for a, b in zip(order_one, order_two, strict=True) if a != b]
    if moved:
        out["order"] = {"only_logged": [], "only_rebuilt": [], "text": moved}
    if outside_one != outside_two or (logged != rebuilt and not out):
        out["outside"] = {"only_logged": [], "only_rebuilt": [], "text": ["outside"]}
    return out


def _differing_text(blocks: Mapping[str, Mapping[str, Sequence[str]]]) -> list[str]:
    """Per kind that differs, how many blocks and where, as a printed line says it."""
    said = []
    for kind in BLOCK_KINDS:
        held = blocks.get(kind)
        if not held:
            continue
        if kind == "outside":
            said.append("the text outside the passages differs")
            continue
        if kind == "order":
            said.append(f"order differs ({', '.join(held.get('text') or [])})")
            continue
        counts = [len(held.get(w) or []) for w in _WHERE]
        said.append(
            f"{sum(counts)} {_KIND_NAMES[kind]} differ ({counts[0]} only logged, "
            f"{counts[1]} only rebuilt, {counts[2]} in text)"
        )
    return said


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
    # The fact, judge and debate blocks that differ, and every differing block by kind.
    facts_differing: list[str] = field(default_factory=list)
    blocks_differing: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    not_found: list[str] = field(default_factory=list)
    not_writable: list[str] = field(default_factory=list)
    ids_taken_out: list[str] = field(default_factory=list)
    # Each human turn this tree's round sends, checked against the logged turn of the same
    # position: the first turn as sent, and the retry turn (``None`` where neither the log nor
    # the replay holds one).
    first_turn_sent_reproduced: bool | None = None
    retry_reproduced: bool | None = None
    retry_first_difference: int | None = None
    retry_blocks_differing: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    first_turn_only: bool | None = None
    # The turns whose answer is fed re-serialised from the record's parsed copy.
    answer_reserialised: list[int] = field(default_factory=list)
    why: list[str] = field(default_factory=list)
    # Why the run is not replayed although it gives a case; empty where it is.
    refused: str = ""
    # The ``src`` the recovery's code was imported from.
    tree: str = ""
    # What the replay is given: absent where the run gives it nothing to replay.
    case: dict[str, Any] | None = None
    # The replay the turns were checked by, kept for the command to print.
    record: dict[str, Any] | None = None

    def row(self) -> dict[str, Any]:
        out = asdict(self)
        out.pop("case")
        out.pop("record")
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


def _tree_of() -> str:
    """The ``src`` the round's code is imported from in this process."""
    import malspark

    return str(Path(malspark.__file__).resolve().parents[1])


def recover(run: Path, name: str | None = None, *, allow_differing: bool = False) -> Recovery:
    """What one stored run gives the replay: its requests, its answers, and the report as the
    round was given it, checked against the logged prompt.

    A log holding more requests than the round's two is refused, and so, unless
    ``allow_differing``, is a run whose written passages differ from the logged ones."""
    from scripts.replay.stored import read_run

    found = Recovery(run=name or _name(run), path=str(run), tree=_tree_of())
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
    if requests.count > 2:
        found.refused = (
            f"the worker log holds {requests.count} agreement requests, more than the round's "
            "two (a first request and one retry): it holds more than one job's round, and "
            "which answer belongs to which is not known"
        )
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
            found.first_answer_matches_record = _parsed(answer) == _parsed(answers[0])
    prompt = prompt_of(requests.first)
    pre = pre_round_report(stored.report, prompt)
    found.not_found, found.not_writable = pre.not_found, pre.not_writable
    found.ids_taken_out = pre.ids_taken_out
    rebuilt = rebuilt_prompt(pre, run)
    # Every block as shown in the two prompts, by kind: a prompt an older build wrote
    # differs in its facts wherever the facts' code changed since, and the round reads its
    # facts as sources.
    found.blocks_differing = block_differences(prompt, rebuilt)
    found.passages_differing = sorted(
        pid for w in _WHERE for pid in found.blocks_differing.get("written", {}).get(w, [])
    )
    found.facts_differing = sorted(
        pid
        for kind in ("fact", "judge", "debate")
        for w in _WHERE
        for pid in found.blocks_differing.get(kind, {}).get(w, [])
    )
    at = _first_difference(rebuilt, prompt)
    found.prompt_reproduced = at is None
    found.first_difference = at
    if at is not None:
        found.difference_context = (
            prompt[max(0, at - 60) : at + 60],
            rebuilt[max(0, at - 60) : at + 60],
        )
    turns, source = _answers_fed(answer, answers)
    if not turns:
        return found
    found.first_turn_only = len(turns) < 2
    found.answer_reserialised = [n for n, a in enumerate(turns, 1) if not isinstance(a, str)]
    case: dict[str, Any] = {
        "run": found.run,
        "path": str(run),
        "report": pre.report.model_dump(mode="json"),
        "narrative_written": pre.narrative_written,
        "discussion": pre.discussion,
        "answers": turns,
        "answer_source": source,
        # Every human turn of the round as logged, by position: the first and the retry's.
        "logged_turns": human_turns(requests.retry or requests.first),
        "settings": stored.settings,
        **{mark: getattr(found, mark) for mark in MARKS},
    }
    # This tree's round over the case: each human turn it sends is checked against the logged
    # turn of the same position, the retry's among them.
    record = replay_case(case)
    for mark in _OWN_MARKS:
        setattr(found, mark, copy.deepcopy(record[mark]))
        case[mark] = copy.deepcopy(record[mark])
    reasons = _refusals(found, record)
    if reasons and not allow_differing:
        found.refused = (
            "; ".join(reasons) + ", so the round would act on an input the model was not "
            "shown; replay it with --allow-differing to have every line of it marked"
        )
        return found
    found.case = case
    found.record = record
    return found


def _answers_fed(answer: str | None, answers: Sequence[Any] | None) -> tuple[list[Any], str]:
    """The answers the stub feeds, in turn order, and where they come from: the model's raw
    first answer where the retry request repeats it, the record's copy of it otherwise, and
    each later answer from the record (a parsed copy there, unless the record kept the text)."""
    turns: list[Any] = []
    if answer is not None:
        turns.append(answer)
    elif answers:
        turns.append(answers[0])
    turns.extend(list(answers or [])[1:])
    if answer is None:
        source = "answers from the run's record" if turns else ""
    elif len(turns) > 1:
        source = "first answer from the retry request, the retry's from the run's record"
    else:
        source = "first answer from the retry request"
    return turns, source


def _refusals(found: Recovery, record: Mapping[str, Any]) -> list[str]:
    """Why the round would act on an input the model was not shown: its first turn as rebuilt
    or as sent, or its retry turn, not the logged one."""
    out: list[str] = []
    if found.blocks_differing:
        named = "; ".join(
            f"{kind}: " + ", ".join(pid for w in _WHERE for pid in held.get(w, []))
            for kind, held in found.blocks_differing.items()
            if kind != "outside"
        )
        out.append(
            "the prompt the round's code builds here is not the logged one: "
            + "; ".join(_differing_text(found.blocks_differing))
            + (f" ({named})" if named else "")
        )
    checks = {int(c["turn"]): c for c in record.get("turns_checked") or []}
    if found.first_turn_sent_reproduced is False:
        out.append(
            "the first turn this tree's round sends is not the logged one: "
            + "; ".join(_differing_text(checks[1]["blocks_differing"]))
        )
    if found.retry_reproduced is False:
        retry = checks[2]
        if not retry["sent"]:
            said = "the log holds a retry turn the replay's round does not send"
        elif not retry["logged"]:
            said = "the replay's round sends a retry turn the log does not hold"
        else:
            said = (
                f"the retry turn the round sends is not the logged one (differs at "
                f"{retry['first_difference']}: logged {retry['context'][0]!r}, sent "
                f"{retry['context'][1]!r}): "
                + "; ".join(_differing_text(retry["blocks_differing"]))
            )
        out.append(said)
    return out


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


def turn_check(turn: int, logged: str | None, sent: str | None) -> dict[str, Any]:
    """One human turn of the round against the logged turn of the same position, by the
    block comparison of the first turn: whether each side holds it, whether the two are the
    same, where they first differ and the blocks that differ."""
    at = _first_difference(sent or "", logged or "")
    return {
        "turn": turn,
        "logged": logged is not None,
        "sent": sent is not None,
        "reproduced": logged is not None and sent is not None and at is None,
        "first_difference": at,
        "context": (
            ((logged or "")[max(0, at - 60) : at + 60], (sent or "")[max(0, at - 60) : at + 60])
            if at is not None
            else ("", "")
        ),
        "blocks_differing": block_differences(logged or "", sent or "") if at is not None else {},
    }


# The marks a replay sets from its own round's turns rather than from the recovery.
_OWN_MARKS = (
    "first_turn_sent_reproduced",
    "retry_reproduced",
    "retry_first_difference",
    "retry_blocks_differing",
)


def own_marks(checks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The marks of the turns a round sent (``_OWN_MARKS``): the first turn as sent, and the
    retry turn, ``None`` where neither the log nor the round holds one."""
    by_turn = {int(c["turn"]): c for c in checks}
    first, retry = by_turn.get(1), by_turn.get(2)
    return {
        "first_turn_sent_reproduced": first["reproduced"] if first and first["logged"] else None,
        "retry_reproduced": retry["reproduced"] if retry else None,
        "retry_first_difference": retry["first_difference"] if retry else None,
        "retry_blocks_differing": copy.deepcopy(retry["blocks_differing"]) if retry else {},
    }


class _Stub:
    """The model's place in the round: each turn answered with the stored answer for it, a
    turn none is stored for with no rows; and each human turn the round sends checked
    against the logged turn of the same position (``checks``)."""

    def __init__(self, answers: Sequence[Any], logged: Sequence[str] = ()) -> None:
        # A parsed answer is fed re-serialised: the case marks it (``answer_reserialised``).
        self.answers = [a if isinstance(a, str) else json.dumps(a) for a in answers]
        self.logged = [str(t) for t in logged]
        self.sent: list[str] = []
        self.checks: list[dict[str, Any]] = []
        self.asked = 0
        self.unanswered = 0
        self.degradations: list[str] = []

    def _check(self, said: str | None) -> None:
        place = len(self.checks)
        logged = self.logged[place] if place < len(self.logged) else None
        self.checks.append(turn_check(place + 1, logged, said))

    def finished(self) -> list[dict[str, Any]]:
        """Every turn's check, with one for each logged turn the round never sent; none where
        no turn is logged."""
        if not self.logged:
            return []
        while len(self.checks) < len(self.logged):
            self._check(None)
        return self.checks

    async def ask(self, turns: list[Any], *_args: Any, **_kwargs: Any) -> Any:
        from langchain_core.messages import AIMessage, HumanMessage

        said = [_text(t.content) for t in turns if isinstance(t, HumanMessage)]
        for text in said[len(self.sent) :]:
            self.sent.append(text)
            self._check(text)
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
        left_out_of = None  # type: ignore[assignment]
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
        stub = _Stub(case.get("answers") or [], case.get("logged_turns") or [])
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
        "tree": _tree_of(),
        "answer_source": case.get("answer_source"),
        **marks_of(case),
        **(own_marks(stub.finished()) if stub.logged else {}),
        "turns_checked": stub.finished(),
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
        "report": report.model_dump(mode="json"),
    }


def marks_of(record: Mapping[str, Any]) -> dict[str, Any]:
    """What a replay's input is (``MARKS``), as a case or a record carries it."""
    return {mark: copy.deepcopy(record.get(mark)) for mark in MARKS}


def mark_text(record: Mapping[str, Any]) -> str:
    """The marks a printed line of a run carries: empty for a replay of the logged turns with
    both turns' raw answers, the logged first answer the record's."""
    said = []
    if record.get("prompt_reproduced") is False:
        said.append(f"prompt not reproduced (differs at {record.get('first_difference')})")
    if record.get("blocks_differing"):
        said.extend(_differing_text(record["blocks_differing"]))
    else:
        if record.get("passages_differing"):
            said.append(f"{len(record['passages_differing'])} written passage(s) differ")
        if record.get("facts_differing"):
            said.append(f"{len(record['facts_differing'])} fact, judge or debate block(s) differ")
    if record.get("first_turn_sent_reproduced") is False:
        said.append("the first turn this tree's round sends is not the logged one")
    if record.get("retry_reproduced") is False:
        said.append(
            f"retry turn not reproduced (differs at {record.get('retry_first_difference')})"
        )
        said.extend(
            f"retry: {t}" for t in _differing_text(record.get("retry_blocks_differing") or {})
        )
    if record.get("first_turn_only"):
        said.append("first turn only")
    if record.get("first_answer_matches_record") is False:
        said.append("the log's first answer is not the record's")
    if record.get("answer_reserialised"):
        said.append(
            "answer(s) "
            + ", ".join(str(n) for n in record["answer_reserialised"])
            + " re-serialised from the record"
        )
    return f" [{'; '.join(said)}]" if said else ""


def rebuilt_input(record: Mapping[str, Any]) -> bool:
    """Whether a run's replay rests on a turn that is not the logged one: replayed only under
    ``--allow-differing``."""
    return bool(
        record.get("prompt_reproduced") is False
        or record.get("blocks_differing")
        or record.get("first_turn_sent_reproduced") is False
        or record.get("retry_reproduced") is False
    )


def first_turn_reproduced(record: Mapping[str, Any]) -> bool:
    """Whether a replay's first turn, as rebuilt and as sent, is the logged one, whatever its
    retry and re-serialised answers."""
    return bool(record.get("prompt_reproduced") and record.get("first_turn_sent_reproduced"))


def empty_retry(record: Mapping[str, Any]) -> bool:
    """Whether the replay's retry was answered by the harness's own empty answer."""
    return bool(record.get("first_turn_only") and record.get("turns_unanswered"))


def run_notes(record: Mapping[str, Any], compared: bool = False) -> list[str]:
    """What a run's replay is, said once per run: a replay on a rebuilt input (a comparison
    of refs on one where ``compared``), and a retry the run never had."""
    return [
        note
        for note, holds in (
            (REBUILT_NOTE if compared else REPLAY_NOTE, rebuilt_input(record)),
            (EMPTY_RETRY_NOTE, empty_retry(record)),
        )
        if holds
    ]


def checks_text(record: Mapping[str, Any]) -> str:
    """Each human turn a replay's round sent, against the logged one, as a line says it."""
    said = []
    for check in record.get("turns_checked") or []:
        if check["reproduced"]:
            what = "as logged"
        elif not check["sent"]:
            what = "logged, not sent"
        elif not check["logged"]:
            what = "sent, not logged"
        else:
            what = (
                f"differs at {check['first_difference']} ("
                + "; ".join(_differing_text(check["blocks_differing"]))
                + ")"
            )
        said.append(f"turn {check['turn']} {what}")
    return "; ".join(said) or "no logged turn to check"


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
    if "report" not in record:
        out.append("report: the replay kept no report to compare")
    else:
        out.extend(
            f"report {where}: {what}"
            for where, what in _dump_differences(record["report"], report.model_dump(mode="json"))
        )
    return out


def _dump_differences(a: Any, b: Any, where: str = "", limit: int = 20) -> list[tuple[str, str]]:
    """Where two dumps differ, by path, the first ``limit`` of them (replay ``a``, stored
    ``b``)."""
    out: list[tuple[str, str]] = []

    def walk(one: Any, two: Any, at: str) -> None:
        if len(out) >= limit or one == two:
            return
        if isinstance(one, dict) and isinstance(two, dict):
            for key in sorted(set(one) | set(two), key=str):
                if key not in one or key not in two:
                    out.append(
                        (f"{at}.{key}", "only stored" if key not in one else "only replayed")
                    )
                else:
                    walk(one[key], two[key], f"{at}.{key}")
            return
        if isinstance(one, list) and isinstance(two, list):
            if len(one) != len(two):
                out.append((at or ".", f"{len(one)} item(s) replayed, {len(two)} stored"))
                return
            for index, (x, y) in enumerate(zip(one, two, strict=True)):
                walk(x, y, f"{at}[{index}]")
            return
        out.append((at or ".", f"replay {_cut(repr(one), 0)!r}, stored {_cut(repr(two), 0)!r}"))

    walk(a, b, where)
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
    marks = marks_of(a)
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
    # Both replays are given the one recovered case: its marks are each difference's.
    return [{**d, **copy.deepcopy(marks)} for d in out]


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


# Why a label's run has no replay where it was not refused: it was not on the command line,
# or gave nothing to replay.
NOT_REPLAYED = "run not replayed"


def _label_value(value: Any) -> str:
    """A label as printed and kept: a JSON boolean as ``true`` or ``false``, any other value
    as its text."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value or "")


def label_lines(
    labels: Sequence[Mapping[str, Any]],
    records: Mapping[str, Mapping[str, Mapping[str, Any]]],
    refused: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Per label, whether its text is printed as stored before the round and under each ref
    (``records``: ref name to the replays of each run by name), and why its run was not
    replayed where it was refused (``refused``: run name to the refusal), or that it was not
    replayed where no ref holds it otherwise."""
    out: list[dict[str, Any]] = []
    for label in labels:
        run = str(label.get("run") or "")
        row: dict[str, Any] = {
            "run": run,
            "passage": label.get("passage"),
            "label": _label_value(label.get("label")),
            "text": str(label.get("text") or ""),
            "printed": {},
            "refused": (refused or {}).get(run, ""),
        }
        if not row["refused"] and not any(run in by_run for by_run in records.values()):
            row["not_replayed"] = NOT_REPLAYED
        given = next((by_run[run] for by_run in records.values() if run in by_run), {})
        row.update(marks_of(given))
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
    env[TREE_VARIABLE] = str(tree.resolve())
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


def _block_counts(blocks: Mapping[str, Mapping[str, Sequence[str]]], checked: bool) -> str:
    """Per kind of block, how many differ: only logged / only rebuilt / in text."""
    if not checked:
        return "-"
    return (
        ", ".join(
            f"{kind} " + "/".join(str(len(blocks.get(kind, {}).get(w, []))) for w in _WHERE)
            for kind in _COUNTED
        )
        + (", order" if "order" in blocks else "")
        + (", outside" if "outside" in blocks else "")
    )


def _print_recovery(rows: Sequence[Recovery]) -> None:
    print(
        "run | requests | request | first answer | final answers | prompt reproduced | "
        "blocks differing per kind (only logged/only rebuilt/in text) | first turn as sent | "
        "retry reproduced | retry blocks differing per kind | first turn only | "
        "answers re-serialised | replay"
    )
    for row in rows:
        where = "" if row.first_difference is None else f" (differs at {row.first_difference})"
        again = (
            ""
            if row.retry_first_difference is None
            else f" (differs at {row.retry_first_difference})"
        )
        replay = "refused" if row.refused else "yes" if row.case is not None else "-"
        print(
            f"{_safe(row.run)} | {row.requests} | {_yes(row.request_found)} | "
            f"{_yes(row.first_answer_found)} | {_yes(row.final_answers_stored)} | "
            f"{_yes(row.prompt_reproduced)}{where} | "
            f"{_block_counts(row.blocks_differing, row.prompt_reproduced is not None)} | "
            f"{_yes(row.first_turn_sent_reproduced)} | {_yes(row.retry_reproduced)}{again} | "
            f"{_block_counts(row.retry_blocks_differing, row.retry_reproduced is not None)} | "
            f"{_yes(row.first_turn_only)} | "
            f"{', '.join(str(n) for n in row.answer_reserialised) or '-'} | {replay}"
        )


def against_line(found: Sequence[str], record: Mapping[str, Any]) -> str:
    """The line heading a run's differences from the stored round, with the run's marks and
    how many of the differences rest on marked input."""
    marked = mark_text(record)
    return (
        f"against the stored round: {len(found)} difference(s), "
        f"{len(found) if marked else 0} of them on marked input{marked}"
    )


def summary_line(
    differences: Sequence[Mapping[str, Any]],
    left: Sequence[Mapping[str, Any]],
    records: Sequence[Mapping[str, Any]] = (),
) -> str:
    """The closing line of two refs' differences: how many, how many not expected, how many
    rest on marked input, each marked run's marks, and what the replay of each run on a
    rebuilt input or with a retry the run never had is."""
    marked = [d for d in differences if mark_text(d)]
    runs = {str(d.get("run")): mark_text(d) for d in marked}
    rebuilt = sorted({str(r.get("run")) for r in (*differences, *records) if rebuilt_input(r)})
    empty = sorted({str(r.get("run")) for r in records if empty_retry(r)})
    return (
        f"{len(differences)} difference(s), {len(left)} not expected, {len(marked)} on marked "
        "input"
        + "".join(f"; {_safe(run)}{said}" for run, said in sorted(runs.items()))
        + (f"; {REBUILT_NOTE}: {', '.join(_safe(r) for r in rebuilt)}" if rebuilt else "")
        + (f"; {EMPTY_RETRY_NOTE}: {', '.join(_safe(r) for r in empty)}" if empty else "")
    )


def _closing(refused: Sequence[Recovery], left: Sequence[str]) -> None:
    """Under the refusals, the differences no expectation excuses, so neither hides the
    other."""
    if not refused:
        return
    print(f"{len(refused)} run(s) refused:")
    for row in refused:
        print(f"   {_safe(row.run)}: {_safe(row.refused)}")
    print(f"{len(left)} difference(s) not expected in the runs replayed" + (":" if left else ""))
    for line in left:
        print(f"   {_safe(line)}")


def _status(refused: Sequence[Recovery], differing: bool) -> int:
    if refused:
        return REFUSED_AND_DIFFERING if differing else REFUSED
    return DIFFERENCES if differing else 0


def _print_record(record: Mapping[str, Any]) -> None:
    changed = [p for p in record["after"] if record["after"][p] != record["before"].get(p)]
    gone = [p for p in record["before"] if p not in record["after"]]
    marked = mark_text(record)
    print(
        f"== {_safe(record['run'])}: {record['turns_asked']} turn(s) asked"
        + f"; {len(changed)} passage(s) changed, {len(gone)} left out; "
        + ", ".join(
            f"{_safe(c)} x{n}"
            for c, n in sorted(Counter(r["code"] for r in record["records"]).items())
        )
        + marked
    )
    for note in run_notes(record):
        print(f"   note: {note}")
    for row in record["rows"]:
        print(
            f"   turn {row['turn']} row {row['row']} [{_safe(row['passage'])}] "
            f"{_safe(row['decision'])}: {_safe(row['end'])}"
            + (f" ({', '.join(_safe(c) for c in row['codes'])})" if row["codes"] else "")
            + marked
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
            + mark_text(line)
            + (f" (refused: {_safe(line['refused'])})" if line.get("refused") else "")
            + (f" ({_safe(line['not_replayed'])})" if line.get("not_replayed") else "")
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python scripts/replay/agreement_round.py",
        # The summary line and what the tool is on the stored runs as they stand.
        description=" ".join(" ".join((__doc__ or "").split("\n\n")[:2]).split()),
        epilog=f"{LIMITS} {STATUSES}",
    )
    parser.add_argument("runs", nargs="*", type=Path, help="stored run directories")
    parser.add_argument("--out", type=Path, default=None, help="write each record here")
    parser.add_argument("--recover-only", action="store_true", help="recover, replay nothing")
    parser.add_argument(
        "--check-stored",
        action="store_true",
        help="compare the replay with the stored round where its answers are stored",
    )
    parser.add_argument(
        "--allow-differing",
        action="store_true",
        help="replay a run whose prompt differs from the logged one, every line marked",
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


def tree_refusal(module_file: str, tree: Path) -> str:
    """Why the round's code imported from ``module_file`` is not ``tree``'s; empty where it
    is."""
    where = Path(module_file).resolve()
    if where.is_relative_to(tree.resolve()):
        return ""
    return (
        f"the round's code is imported from {where.parent}, not from this tree {tree}: put "
        f"{tree / 'src'} first on the path, or run the harness of the tree to be measured"
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    import malspark

    refusal = tree_refusal(str(malspark.__file__), _TREE)
    if refusal:
        print(f"agreement_round: {refusal}", file=sys.stderr)
        return WRONG_TREE
    if args.replay_cases is not None:
        # One ref's process: each recovered case replayed under the tree it imports.
        cases = [json.loads(p.read_text(encoding="utf-8")) for p in args.replay_cases]
        _write(args.json, [replay_case(case) for case in cases])
        return 0
    if not args.runs:
        _parser().error("name at least one stored run")
    out: Path | None = args.out
    recovered = [recover(run, allow_differing=args.allow_differing) for run in args.runs]
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
    refused = [row for row in recovered if row.refused]
    for row in refused:
        print(f"refused {_safe(row.run)}: {_safe(row.refused)}")
    cases = [row for row in recovered if row.case is not None]
    labels = _read_list(args.labels)
    why_refused = {row.run: row.refused for row in refused}
    if args.compare is None:
        records: dict[str, dict[str, Any]] = {}
        left_lines: list[str] = []
        for row in cases:
            assert row.case is not None
            record = row.record if row.record is not None else replay_case(row.case)
            records[row.run] = record
            _print_record(record)
            if args.check_stored and row.final_answers_stored:
                found = against_stored(Path(row.path), row.case, record)
                record["against_stored"] = found
                print(f"   {against_line(found, record)}")
                for line in found:
                    print(f"     {_safe(line)}{mark_text(record)}")
                left_lines.extend(f"{row.run}: {line}{mark_text(record)}" for line in found)
            if out is not None:
                _write(out / f"{row.run.replace('/', '-')}.json", record)
        if labels:
            lines = label_lines(labels, {"HEAD": records}, why_refused)
            _print_labels(lines)
            if out is not None:
                _write(out / "labels.json", lines)
        _closing(refused, left_lines)
        return _status(refused, bool(left_lines))
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
    for run, under_a in by_ref["A"].items():
        # Each ref's own turns against the logged ones, and what the run's replay is.
        for side, ref in zip(("A", "B"), args.compare, strict=True):
            mine = by_ref[side].get(run)
            if mine is not None:
                print(f"{_safe(run)} under {_safe(ref)}: {_safe(checks_text(mine))}")
        for note in run_notes(under_a, compared=True):
            print(f"{_safe(run)}: note: {note}")
    stored_left: list[str] = []
    if args.check_stored:
        # Each ref's replay against the round as stored, where its answers are stored. Ref A's
        # differences on a run whose first turn is reproduced are the harness testing itself
        # and are counted, whatever its retry and re-serialised answers, with its marks beside
        # them; ref B's are the change measured and are printed only.
        for row in cases:
            if not row.final_answers_stored or row.case is None:
                continue
            for side, ref in zip(("A", "B"), args.compare, strict=True):
                replayed = by_ref[side].get(row.run)
                if replayed is None:
                    continue
                found = against_stored(Path(row.path), row.case, replayed)
                print(f"{_safe(row.run)} under {_safe(ref)} {against_line(found, replayed)}")
                for line in found:
                    print(f"   {_safe(line)}{mark_text(replayed)}")
                if side == "A" and first_turn_reproduced(replayed):
                    stored_left.extend(
                        f"{row.run} under {ref}: {line}{mark_text(replayed)}" for line in found
                    )
    print(f"== {args.compare[0]} (A) against {args.compare[1]} (B)")
    print(COMPARE_NOTE)
    for d in differences:
        print(f"{'  ' if d not in left else '! '}{_safe(_difference_text(d))}")
    if labels:
        lines = label_lines(labels, by_ref, why_refused)
        _print_labels(lines)
        _write(out / "labels.json", lines)
    print(summary_line(differences, left, list(by_ref["A"].values())))
    _closing(refused, [_difference_text(d) for d in left] + stored_left)
    return _status(refused, bool(left) or bool(stored_left))


def _difference_text(d: Mapping[str, Any]) -> str:
    """One difference between two refs as a line, its run's marks after it."""
    if d["kind"] == "code":
        said = f"{d['run']}: {d['code']} {d['change']} ({d['A']} -> {d['B']})"
    else:
        said = (
            f"{d['run']} [{d['passage']}] {d['kind']} under {d['only']} only: {d['sentence'][:160]}"
        )
    return said + mark_text(d)


if __name__ == "__main__":
    _put_tree_first()
    raise SystemExit(main())
