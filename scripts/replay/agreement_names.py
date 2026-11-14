"""Read a stored run's agreement question against the ledger's names, at zero cost.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/agreement_names.py <run dir> [<run dir> ...]

rebuilds the agreement round's inputs from what the run stored: the passages
as the round was first shown them (the first agreement request in
``worker.log``), the ledger (``evidence.json``) and the run's recorded
limitations and open questions (``report.json``). It then reads, with the
platform's own code and no model call, each held sentence that denies
something of a name the run holds (``section_agreement.name_readings``) and
each limitations sentence held to the failed calls a later call redid
(``section_agreement.held_limitation_sentences``), and prints per sentence:
the name, the fact the round would be shown for it, how its answer is held,
and the characters of the facts the round was shown before and would be
shown now. Code decides none of these sentences: each is the model's to answer.

Read-only over the runs: nothing is written beside them, no network is reached,
no credential is read. ``--json PATH`` also writes the readings to ``PATH``.
The agreement round itself is not replayable (``scripts/replay/rules.py``):
this reads its inputs, not its answer.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# The headings the round's prompt groups its passages under (``section_agreement``).
_KINDS = {
    "FACTS THE PLATFORM STATES": "fact",
    "SECTION 5, WRITTEN FROM THE CODE AND THE TOOL ANSWERS": "section 5",
    "THE DEBATE'S MEDIATIONS, IN ROUND ORDER": "debate",
    "PASSAGES WRITTEN WITHOUT THE CODE": "claim-led",
}
_PASSAGE = re.compile(
    r"^- \[([^\]]+)\] (.*?)(?: \((?:read only|verbatim|verbatim, a source only)\))?"
    r"(?: \(cites [^)]*\))?: (.*)$"
)
_CLOSING = ("conclusion", "limitations")
# Who wrote a passage the prompt marks (verbatim), as far as the prompt says (T-613).
_VERBATIM = "its writer's own words, printed as written"
# The ids the limitations paragraph's facts were shown under before the inventory's rows.
_LIMITATION_FACTS = ("failed", "not_run", "recorded", "open", "inv")


def _request_text(log: Path) -> str:
    """The human turn of the first agreement request the worker logged, or ``""``."""
    with log.open(encoding="utf-8", errors="replace", newline="\n") as lines:
        for line in lines:
            if "Request options: " not in line or "FACTS THE PLATFORM STATES" not in line:
                continue
            if "PASSAGES WRITTEN WITHOUT THE CODE" not in line:
                continue
            options = ast.literal_eval(line.split("Request options: ", 1)[1].strip())
            data = options.get("json_data") or {}
            for message in data.get("messages") or []:
                content = message.get("content")
                if isinstance(content, list):
                    content = "\n".join(str(part.get("text") or "") for part in content)
                if isinstance(content, str) and "FACTS THE PLATFORM STATES" in content:
                    return content
    return ""


def _unquoted(text: str) -> str:
    from malspark.utils.written_forms import pack_reads

    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    read = pack_reads(text)
    return read[0] if read else text


def _passages(prompt: str, labels: Mapping[str, Any] | None = None) -> list[Any]:
    """The passages the prompt shows, each as the round built it: its id, label, text,
    kind, and whether it may be rewritten (a writable one carries a no-op writer). The
    prompt shows no place label: each is rebuilt from the passage's identity, its id in the
    stored report (``labels``, ``section_agreement.place_labels``, T-613)."""
    from malspark.reporting.section_agreement import Passage

    kind = ""
    out: list[Any] = []
    for line in prompt.splitlines():
        if line.strip() in _KINDS:
            kind = _KINDS[line.strip()]
            continue
        found = _PASSAGE.match(line)
        if not found or not kind:
            continue
        pid, label, text = found.groups()
        head = line.split(": ", 1)[0]
        read_only = "(read only)" in head
        # A text printed in its writer's own words is listed, never rewritten (T-613).
        verbatim = _VERBATIM if "(verbatim" in head else ""
        # An agent's words the analyst report does not print: a source only (T-613).
        source_only = "(verbatim, a source only)" in head
        writable = kind in ("claim-led", "section 5") and not read_only and not verbatim
        out.append(
            Passage(
                id=pid,
                label=label,
                text=text if kind == "fact" else _unquoted(text),
                kind=kind,
                write=(lambda _text: None) if writable else None,
                closing=pid in _CLOSING,
                verbatim=verbatim,
                place_label=(labels or {}).get(pid),
                source_only=source_only,
            )
        )
    return out


def _ledger(run: Path) -> list[Any]:
    from scripts.replay.stored import evidence_rows

    from malspark.reporting.follow_up import stored_ledger

    rows, _why = evidence_rows(json.loads((run / "evidence.json").read_bytes()))
    ledger: list[Any] = stored_ledger(rows)[0]
    return ledger


def _report(run: Path, limitations: str) -> Any:
    """The stored report, its limitations paragraph as the round was shown it."""
    from malspark.reporting.models import MalwareReport

    report = MalwareReport.model_validate(json.loads((run / "report.json").read_bytes()))
    ta = report.technical_analysis
    if ta is not None and ta.analyst_limitations is not None and limitations:
        ta.analyst_limitations.body = limitations
    return report


def _cut(text: str, limit: int = 160) -> str:
    line = " ".join(text.split())
    return line if len(line) <= limit else line[: limit - 1] + "…"


def read_run(run: Path) -> dict[str, Any]:
    """Each held name in one stored run with the fact shown for it, and the facts' sizes."""
    from malspark.reporting.agreement_facts import ledger_facts
    from malspark.reporting.ledger_entities import run_names
    from malspark.reporting.limitation_facts import failed_calls
    from malspark.reporting.section_agreement import (
        _SAYS_FAILED,
        FACT,
        SECTION_5,
        _count_fact,
        _failure_counts,
        _ledger_passages,
        _limitation_passages,
        _name_passages,
        _named_addresses,
        _redo_choices,
        _stale_calls,
        generic_words,
        held_limitation_sentences,
        place_labels,
        redone_calls_named,
    )

    prompt = _request_text(run / "worker.log")
    shown = _passages(prompt, place_labels(_report(run, "")))
    ledger = _ledger(run)
    found = ledger_facts(ledger)
    names = run_names(ledger, found.image_bases)
    by_id = {p.id: p for p in shown}
    generic = generic_words({p.id: p for p in shown if p.kind == SECTION_5})
    facts_before = sum(len(p.text) for p in shown if p.kind == FACT)
    name_facts, readings = _name_passages(
        shown, names, found, {str(getattr(e, "id", "")): e for e in ledger}, generic
    )
    by_fact = {f.id: f for f in name_facts}
    rows: list[dict[str, Any]] = []
    for passage in shown:
        named = dict(passage.ledger_named)
        for reading in (r for r in readings if r.sentence in named):
            if reading.sentence not in passage.text:
                continue
            ids = named.get(reading.sentence, ())
            rows.append(
                {
                    "passage": passage.id,
                    "closing": passage.closing,
                    "sentence": reading.sentence,
                    "name": f"{reading.kind} {reading.shown}"
                    + (" (sentence before)" if reading.back else ""),
                    "facts": [
                        {"id": fid, "cites": sorted(by_fact[fid].cites), "text": by_fact[fid].text}
                        for fid in ids
                        if fid in by_fact
                    ],
                    "outcome": (
                        "held; a keep as written is refused: rewritten on the lines or left out"
                        if passage.closing
                        else "held; a keep is recorded unless quoted"
                    ),
                }
            )
    # The limitations paragraph held to the failed calls a later call redid.
    failed = failed_calls(ledger, found.answered, found.image_bases, found.redone)
    limitations = by_id.get("limitations")
    held_failed: list[dict[str, Any]] = []
    added_limitation = 0
    if limitations is not None:
        listed = [routine.address for routine in found.listed]
        for sentence in held_limitation_sentences(
            limitations.text, failed, listed, found.image_bases
        ):
            named = redone_calls_named(sentence, failed, found.image_bases)
            # The calls a keep of it is refused for, as the failure check reads them: the
            # ones it names or cites, unless it says a call failed.
            stale = (
                _stale_calls(sentence, failed, found.image_bases, broad=True)
                if _SAYS_FAILED.search(sentence)
                else named
            )
            refused = "a keep is refused (agreement.failure_redone): left out unless rewritten"
            held_failed.append(
                {
                    "sentence": sentence,
                    "redone": [f"{c.entry} by {', '.join(c.redone_by)}" for c in stale],
                    "outcome": refused if stale else "held; read against the inv.N facts",
                    # Held by the calls it names or cites: the entries a keep must cite.
                    "cite": list(_redo_choices(named)),
                    # Held before too: the sentence says a call failed in words read so.
                    "held_before": bool(_SAYS_FAILED.search(sentence)),
                }
            )
        # The limitations inventory's rows (``inv.N``) are shown wherever the paragraph
        # stands (T-601), in place of the failure facts the stored prompt held, if any.
        _para, limit_facts, _failed = _limitation_passages(
            _report(run, limitations.text), ledger, found, ()
        )
        added_limitation = sum(len(p.text) for p in limit_facts) - sum(
            len(p.text) for p in shown if p.id.split(".", 1)[0] in _LIMITATION_FACTS
        )
        counts = _failure_counts(failed)
        if limit_facts and counts is not None and "calls.1" not in by_id:
            # The ledger's count of failed calls is shown beside them.
            added_limitation += len(_count_fact(counts, failed).text)
    # The answered facts as the round is shown them now: the call that redid each failure.
    answered_before = sum(len(p.text) for p in shown if p.id.startswith("answered."))
    closing = [p for p in shown if p.closing]
    answered_after = sum(
        len(p.text)
        for p in _ledger_passages(ledger, shown, found, also=_named_addresses(closing))
        if p.id.startswith("answered.")
    )
    names_size = sum(len(f.text) for f in name_facts)
    return {
        "run": run.name,
        "passages": len(shown),
        "names": rows,
        "failed": held_failed,
        "answered": [(a.failed, a.answered, a.redone) for a in found.answered],
        "facts_before": facts_before,
        "facts_after": facts_before
        + names_size
        + added_limitation
        + answered_after
        - answered_before,
        "names_chars": names_size,
        "limitation_chars": added_limitation,
    }


def _print(read: dict[str, Any]) -> None:
    from scripts.replay.output import terminal_safe as safe

    print(f"== {safe(read['run'])}: {read['passages']} passages shown")
    print(
        f"   facts shown: {read['facts_before']} characters before, {read['facts_after']} after "
        f"(ledger.N {read['names_chars']}, limitation facts {read['limitation_chars']})"
    )
    print(
        "   answered: "
        + ", ".join(f"{safe(f)}->{safe(a)}{' (redo)' if r else ''}" for f, a, r in read["answered"])
    )
    for row in read["names"]:
        print(f" - [{safe(row['passage'])}] {safe(row['name'])}: {safe(row['outcome'])}")
        print(f"     sentence: {safe(_cut(row['sentence'], 220))}")
        for fact in row["facts"]:
            print(
                f"     {safe(fact['id'])} (cites {', '.join(safe(c) for c in fact['cites'])}): "
                f"{safe(_cut(fact['text'], 400))}"
            )
    for row in read["failed"]:
        before = "held before too" if row["held_before"] else "not held before"
        # The redone calls it is held to, each with the calls that redid it; none where
        # it is held by a failure no later call redid.
        redone = "; ".join(safe(r) for r in row["redone"])
        print(
            f" - [limitations] failed call ({before}): {safe(row['outcome'])}"
            + (f" ({redone})" if redone else "")
            + (f"; cite {' and '.join(safe(c) for c in row['cite'])}" if row["cite"] else "")
        )
        print(f"     sentence: {safe(_cut(row['sentence'], 220))}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("runs", nargs="+", type=Path, help="stored run directories")
    parser.add_argument("--json", type=Path, default=None, help="write the readings here too")
    args = parser.parse_args(argv)
    found = []
    for run in args.runs:
        read = read_run(run)
        _print(read)
        found.append(read)
    if args.json is not None:
        from scripts.replay.output import write_json

        write_json(args.json, found, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
