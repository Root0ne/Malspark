"""Merge a stored run's debate revisions again, under the earlier rule and this tree's.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/remerge_revisions.py <run dir> [<run dir> ...]

reads the answers in force each mediation was given from the run's
``worker.log`` (the requests the model client logged), and for each analyst a
revision round revised merges its revision into the answer in force again
(``pipeline.revision_merge.merge_revision``) twice: under the rule this tree
holds, and under the earlier one, which pooled a claim's values over the
revision's blocks and asked no block for the claim's subject. It prints, per
round and analyst, the claims each rule restated, carried (and, of those,
carried beside a block that states the claim again without an address of it),
withdrew (by a line or by rule) and left with values the merged answer states
nowhere (``claim_drops.dropped_values``), the claims this tree's rule keeps in force
that the earlier one replaced, and, for each, the revision block nearest to
it, so a near duplicate is seen. ``--json OUT`` writes the record.

What a log holds, and what is read from it:

- the answer in force of each analyst, as the round's mediation was shown it:
  the summary of its claims (``AgentISR.to_text_summary``), its disputes and
  what it wrote besides its claims;
- the revision's own blocks: the claims of the next answer in force that no
  carried-forward note marks; a revision placed by its written numbers is
  replayed by what it states, since a summary shows the merged numbers only;
- the lines of the round's mediation, from the next mediation's account of
  them (``(standing: ...)``), read as the merge reads them
  (``debate_facts.claims_named_by_lines``).

The earlier rule's merge, as the run's log said it, is printed beside each
replay so a reading that differs from what the run did is seen. The stored
runs are read and never written; no model is called.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[2]
for _path in (str(_ROOT / "src"), str(_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from malspark.pipeline import revision_merge  # noqa: E402
from malspark.pipeline.claim_drops import content_words, dropped_values  # noqa: E402
from malspark.pipeline.debate_facts import claims_named_by_lines  # noqa: E402
from malspark.schemas.isr_models import AgentISR, ClaimEvidence  # noqa: E402

_REQUEST = b"Request options: "
_SECTION = re.compile(r"(?m)^--- (.+?) ANALYST ---\n")
_HEADER = re.compile(r"^\[([A-Z0-9_]+) ANALYST — round (\d+)\]\n")
_CLAIM = re.compile(r"(?m)^  Claim (\d+)((?: \([^\n:]*?\))?): ")
_ENDS = (
    "\n  Open questions (unknowns, not absences):",
    "\n  Disputes:",
    "\n  [CONVERGENCE SIGNAL",
    "\n  Findings:",
    "\nWritten in this answer besides its claims:",
)
_BESIDES = "\nWritten in this answer besides its claims:\n"
_TECHNIQUES = re.compile(r" \(((?:T\d{4}(?:\.\d{3})?(?: — [^,()]*)?(?:, )?)+)\)$")
_MARKER = re.compile(
    r" \((?:the claim cites only tool calls that failed"
    r"|added by a tool-less retry, round \d+"
    r"|carried forward[: ][^\n]*?)\)$"
)
_STANDING = re.compile(r"(?m)^- \(standing: [^)]*\) (.+)$")
_MERGE_SAID = re.compile(
    r"The (\S+) analyst's round-(\d+) revision wrote (\d+) claim\(s\) against (\d+) in force: "
    r"by (their numbers|what they state), they restate (\d+) of those and add (\d+); it withdrew "
    r"(\d+)(?: and (\d+) were withdrawn by rule)?, and the other (\d+) stand carried"
)
_REPLACED_SAID = re.compile(
    r"The (\S+) analyst's round-(\d+) revision replaced (\d+) claim\(s\) with (\d+)\."
)


@dataclass
class _Answer:
    """One analyst's answer in force as a mediation was shown it."""

    name: str
    revision_round: int | None
    text: str
    claims: list[ClaimEvidence] = field(default_factory=list)
    carried: list[bool] = field(default_factory=list)
    disputes: list[str] = field(default_factory=list)
    besides: str = ""


@dataclass
class _Mediation:
    """What one mediation was given: each analyst's answer, and the earlier mediation's lines."""

    line: int
    answers: dict[str, _Answer]
    earlier_lines: list[str]


def _text_of_request(raw: bytes) -> tuple[str, str] | None:
    """``(system, first user message)`` of one logged request, or ``None``."""
    line = raw.decode("utf-8", "replace")
    try:
        options = ast.literal_eval(line[line.index("Request options: ") + 17 :].strip())
    except (ValueError, SyntaxError, MemoryError):
        return None
    data = options.get("json_data") or {}
    system = data.get("system")
    if isinstance(system, list):
        system = " ".join(str(part.get("text", "")) for part in system)
    messages = data.get("messages") or []
    if not messages:
        return None
    content = messages[0].get("content")
    if isinstance(content, list):
        content = "\n".join(str(part.get("text") or "") for part in content)
    return str(system or ""), str(content or "")


def _claims_of(body: str) -> tuple[list[ClaimEvidence], list[bool]]:
    """The claims a summary shows, one per technique id, and whether each is carried."""
    end = min((at for marker in _ENDS if (at := body.find(marker)) >= 0), default=len(body))
    region = body[:end]
    starts = list(_CLAIM.finditer(region))
    claims: list[ClaimEvidence] = []
    carried: list[bool] = []
    for index, match in enumerate(starts):
        stop = starts[index + 1].start() if index + 1 < len(starts) else len(region)
        chunk = region[match.end() : stop].rstrip("\n")
        head, _sep, confidence = chunk.rpartition(" | Confidence: ")
        said, _sep, evidence = head.rpartition(" | Evidence: ")
        is_carried = False
        while (marker := _MARKER.search(evidence)) is not None:
            is_carried = is_carried or "carried forward" in marker.group(0)
            evidence = evidence[: marker.start()]
        techniques: list[str] = []
        if (written := _TECHNIQUES.search(said)) is not None:
            techniques = [t.split(" — ")[0].strip() for t in written.group(1).split(", ")]
            said = said[: written.start()]
        try:
            value = float(confidence.strip())
        except ValueError:
            value = 0.5
        note = match.group(2).strip() or None
        written_ids: list[str | None] = list(techniques) or [None]
        for technique in written_ids:
            claims.append(
                ClaimEvidence(
                    claim=said,
                    evidence_ref=evidence,
                    confidence=value,
                    technique_id=technique,
                    technique_line=", ".join(techniques) or None,
                    heading_note=note,
                )
            )
            carried.append(is_carried)
    return claims, carried


def _answer(name: str, section: str) -> _Answer:
    header = _HEADER.match(section)
    answer = _Answer(
        name=name, revision_round=int(header.group(2)) if header else None, text=section
    )
    if header is None:
        return answer
    answer.claims, answer.carried = _claims_of(section)
    disputes = section.find("\n  Disputes:\n")
    if disputes >= 0:
        for item in section[disputes + 13 :].split("\n"):
            if not item.startswith("    - "):
                break
            answer.disputes.append(item[6:])
    at = section.find(_BESIDES)
    if at >= 0:
        answer.besides = section[at + len(_BESIDES) :]
    return answer


def _mediations(log: Path) -> Iterator[_Mediation]:
    """Each distinct mediation (and the judge's) prompt of a run's log, in order."""
    seen: set[str] = set()
    with log.open("rb") as handle:
        for number, raw in enumerate(handle, 1):
            if _REQUEST not in raw:
                continue
            read = _text_of_request(raw)
            if read is None:
                continue
            system, text = read
            if not system.startswith(
                (
                    "You are the Lead Cyber Security Mediator",
                    "You are the Chief Malware Judge. Based",
                )
            ):
                continue
            parts = _SECTION.split(text)
            answers: dict[str, _Answer] = {}
            for at in range(1, len(parts) - 1, 2):
                name = parts[at].strip().lower()
                answers[name] = _answer(name, parts[at + 1].split("\n=== ")[0])
            key = repr(sorted((n, a.revision_round, len(a.text)) for n, a in answers.items()))
            if not answers or key in seen:
                continue
            seen.add(key)
            yield _Mediation(line=number, answers=answers, earlier_lines=_STANDING.findall(text))


def _isr(answer: _Answer, claims: list[ClaimEvidence], disputes: list[str]) -> AgentISR:
    return AgentISR(
        agent_id=answer.name,
        domain=answer.name,
        claims=[c.model_copy() for c in claims],
        dissent_items=list(disputes),
        revision_round=int(answer.revision_round or 0),
    )


@contextmanager
def _earlier_rule() -> Iterator[None]:
    """The rule before this tree's: values pooled over blocks, no block asked for the subject."""
    rm = revision_merge

    def restated(earlier: Any, readings: Any) -> tuple[bool, int | None]:
        for index, reading in enumerate(readings):
            if rm._block_restates(earlier, reading):
                return True, index
        values = rm._counted_values(earlier)
        if not values:
            return False, None
        pooled: set[str] = set()
        for reading in readings:
            pooled |= rm._stated(values, reading)
        if any(rm._strong(v) for v in pooled) and len(pooled) / len(values) >= rm.RESTATED_SHARE:
            return True, None
        return False, None

    def by_statement(first: Any, readings: Any, _stated: Any = None) -> Any:
        found: set[int] = set()
        target: dict[int, int] = {}
        for earlier in first:
            ok, index = restated(earlier, readings)
            if not ok:
                continue
            found.add(earlier.number)
            if index is not None and index not in target:
                target[index] = earlier.number
        return found, target, {}

    with patch.object(rm, "_by_statement", by_statement):
        yield


def _nearest(claim: str, blocks: list[str]) -> tuple[float, str]:
    """The revision block whose content words are nearest ``claim``'s (Jaccard), with the share."""
    words = content_words(claim)
    best, text = 0.0, ""
    for block in blocks:
        other = content_words(block)
        if words or other:
            share = len(words & other) / len(words | other)
            if share > best:
                best, text = share, block
    return best, text


def _merge_row(merge: Any, in_force: AgentISR, revision: AgentISR, besides: str) -> dict[str, Any]:
    stands = merge.merged if merge.merged is not None else revision
    report = "\n".join([stands.to_text_summary(), besides])
    dropped = dropped_values(in_force, stands, report, revision_round=None)
    return {
        "restated": list(merge.replaced),
        "added": merge.added,
        "withdrawn": [n for n, _s, _r in merge.withdrawn],
        "withdrawn_by_rule": [n for n, _s, _r in merge.withdrawn_by_rule],
        "carried": [n for n, _s in merge.carried],
        "beside": [[n, now, list(addresses)] for n, _s, now, addresses in merge.beside],
        "dropped_claims": len(dropped),
        "dropped_values": sum(len(d.missing) for d in dropped),
    }


def _said(log: Path) -> dict[tuple[str, int], str]:
    """The merge each revision's log sentence states, by ``(analyst, round)``."""
    out: dict[tuple[str, int], str] = {}
    with log.open("rb") as handle:
        for raw in handle:
            if b"revision wrote" not in raw and b"revision replaced" not in raw:
                continue
            line = raw.decode("utf-8", "replace")
            if (m := _MERGE_SAID.search(line)) is not None:
                out[(m.group(1), int(m.group(2)))] = (
                    f"restated {m.group(6)}, added {m.group(7)}, withdrew {m.group(8)}, "
                    f"by rule {m.group(9) or 0}, carried {m.group(10)} (by {m.group(5)})"
                )
            elif (m := _REPLACED_SAID.search(line)) is not None:
                out[(m.group(1), int(m.group(2)))] = (
                    f"stood as written ({m.group(3)} claim(s) replaced with {m.group(4)})"
                )
    return out


def remerge(run: Path) -> dict[str, Any]:
    """Every revision of ``run`` merged again under both rules."""
    log = run / "worker.log"
    mediations = list(_mediations(log))
    said = _said(log)
    rows: list[dict[str, Any]] = []
    for before, after in zip(mediations, mediations[1:], strict=False):
        names = list(before.answers)
        kept = {n: _isr(a, a.claims, a.disputes) for n, a in before.answers.items()}
        try:
            named = claims_named_by_lines(
                after.earlier_lines,
                names,
                {n: revision_merge.claim_tokens_by_number(isr) for n, isr in kept.items()},
            )
        except Exception as exc:  # noqa: BLE001 — a line not read names no claim
            print(_not_read(run.name, exc), file=sys.stderr)
            named = {}
        for name, now in after.answers.items():
            was = before.answers.get(name)
            if was is None or now.revision_round is None or was.revision_round is None:
                continue
            if now.revision_round <= was.revision_round or not was.claims:
                continue
            own = [c for c, carried in zip(now.claims, now.carried, strict=True) if not carried]
            revision = _isr(now, own, now.disputes)
            in_force = kept[name]
            round_number = int(now.revision_round)
            merged_new = revision_merge.merge_revision(
                in_force, revision, now.besides, round_number, named.get(name)
            )
            with _earlier_rule():
                merged_old = revision_merge.merge_revision(
                    in_force, revision, now.besides, round_number, named.get(name)
                )
            new_row = _merge_row(merged_new, in_force, revision, now.besides)
            old_row = _merge_row(merged_old, in_force, revision, now.besides)
            sentences = {
                n: s
                for n, s in [
                    *merged_new.carried,
                    *[(n, s) for n, s, _r in merged_new.withdrawn_by_rule],
                ]
            }
            blocks = [" ".join(c.claim.split()) for c in revision.claims]
            kept_now = []
            for number in sorted(set(old_row["restated"]) - set(new_row["restated"])):
                sentence = sentences.get(number, "")
                share, nearest = _nearest(sentence, list(dict.fromkeys(blocks)))
                kept_now.append(
                    {
                        "claim": number,
                        "now": "carried"
                        if number in new_row["carried"]
                        else "withdrawn by rule"
                        if number in new_row["withdrawn_by_rule"]
                        else "withdrawn",
                        "sentence": sentence,
                        "nearest_share": round(share, 2),
                        "nearest": nearest,
                    }
                )
            rows.append(
                {
                    "round": round_number,
                    "analyst": name,
                    "in_force": len(revision_merge._blocks(in_force.claims)),
                    "revision_blocks": len(revision_merge._blocks(revision.claims)),
                    "logged": said.get((name, round_number), "(no merge sentence logged)"),
                    "earlier_rule": old_row,
                    "this_rule": new_row,
                    "kept_in_force_now": kept_now,
                }
            )
    return {"run": run.name, "mediations": [m.line for m in mediations], "revisions": rows}


def _not_read(name: str, exc: Exception) -> str:
    """The line said when the lines could not be read; the message can quote a stored line."""
    from scripts.replay.output import terminal_safe as safe

    return f"{safe(name)}: the lines were not read ({type(exc).__name__}: {safe(exc)})"


def _print(record: dict[str, Any]) -> None:
    from scripts.replay.output import terminal_safe as safe

    print(f"== {safe(record['run'])} (mediation prompts at log lines {safe(record['mediations'])})")
    for row in record["revisions"]:
        old, new = row["earlier_rule"], row["this_rule"]
        print(
            f"  round {safe(row['round'])} {safe(row['analyst'])}: "
            f"{safe(row['in_force'])} in force, "
            f"{safe(row['revision_blocks'])} revision block(s); logged: {safe(row['logged'])}"
        )
        for label, said in (("earlier", old), ("this   ", new)):
            print(
                f"    {label} rule: restated {len(said['restated'])}, added {safe(said['added'])}, "
                f"carried {len(said['carried'])} ({len(said['beside'])} beside a "
                f"restatement), withdrawn {len(said['withdrawn'])}, by rule "
                f"{len(said['withdrawn_by_rule'])}, claims with dropped values "
                f"{safe(said['dropped_claims'])} ({safe(said['dropped_values'])} value(s))"
            )
        for kept in row["kept_in_force_now"]:
            print(
                f"    kept now (claim {safe(kept['claim'])}, {safe(kept['now'])}; nearest block "
                f"{kept['nearest_share']:.2f}): {safe(kept['sentence'][:110])}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scripts/replay/remerge_revisions.py",
        description="Merge a stored run's debate revisions again under the earlier and this rule.",
    )
    parser.add_argument("runs", nargs="+", type=Path, help="stored run directories")
    parser.add_argument("--json", type=Path, help="write the record here")
    args = parser.parse_args(argv)
    records = []
    for run in args.runs:
        if not (run / "worker.log").is_file():
            from scripts.replay.output import terminal_safe

            print(f"{terminal_safe(run)}: no worker.log", file=sys.stderr)
            continue
        record = remerge(run)
        records.append(record)
        _print(record)
    if args.json is not None:
        from scripts.replay.output import write_json

        write_json(args.json, records, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
