"""A debate revision merged into the answer in force, claim by claim.

A revision used to stand as the analyst's whole answer: a claim it did not
write again was gone, and the platform only said how many claims it had
before and after. Here a revision changes only what it states:

- a claim it writes again replaces its predecessor;
- a claim it withdraws is removed, with the reason it gives: a
  ``WITHDRAW CLAIM <n>: <reason>`` line (``retry_merge.read_withdrawals``),
  or a claim block under the number of a claim in force whose heading or
  sentence declares the withdrawal ("CLAIM 5 (withdrawn): ..."). No reading
  of free prose withdraws a claim: a dispute in which the analyst rejects a
  claim of its own answer in force ("my own earlier claim 17 ... I reject
  this", ``retry_merge.read_own_withdrawals``) withdraws nothing (below);
- a claim in force that a blocking line of the round's mediation named, and
  that the revision neither wrote again nor withdrew, is withdrawn by rule,
  with the line as its reason: a challenged claim left unanswered never
  reaches the report as if it stood. A line names a claim by its number, in
  a list or inside a bounded range ("claims 32-34",
  ``debate_facts.read_claim_numbers``); a reference that names no claim (a
  longer range, or a number no analyst is read for) withdraws nothing and
  is stated, one sentence per reference (``unplaced_sentence``). A number
  written for no analyst names the claim of its owner where exactly one
  analyst the line may mean has a claim of that number sharing with the
  reference's clause a ledger id or an address no other claim of its answer
  writes; it is carried with the line, never withdrawn by rule, and that is
  stated (``owned_sentence``). A blocking line withdraws by rule only a
  claim it speaks to. Where a claim the line names, of any analyst, shares
  a ledger id or a value with the whole line, or has a run of four
  consecutive words of its sentence written on it, the line speaks only to
  those claims, and to each of them itself (:func:`anchored_lines`); where
  none does, it speaks to no claim itself, and its rule reaches every claim
  it names, except one it reaches only through a range or a list that
  shares no ledger id or address with the reference's clause. A claim a
  block restates is never withdrawn by rule, carried beside that block or
  not. A claim a line names without speaking to it is never withdrawn by
  rule by that line, keeps the address test and the line's mark, and the
  reference is stated (``not_spoken_sentence``);
- a claim it writes under a new number, or one that writes again no claim in
  force, is added;
- every other claim in force stays as the answer in force wrote it, marked
  as carried forward from that round (``ClaimEvidence.carried_since_round``),
  and, where a line named it and did not withdraw it, with that line
  (``ClaimEvidence.carried_contested_by``).

The identity is the claim block's place in the answer in force, counted from
1: the number the mediator, the questions and every summary name a claim by.
A revision whose every block writes a number, each of which either names a
claim in force the block restates (below) or lies after the last one, is
placed by those numbers. Any other revision is placed by what it states.

A revision block restates a claim in force when it states four fifths of the
claim's content words, or at least half of the claim's values that are no
mere small number (a value of three characters or more, or a technique id)
with at least one of them strong (four characters or more, or a technique
id), or a third of them with the claim's technique id; and when it states
every address the claim's sentence names (``0x…`` of at least
:data:`LEAST_ADDRESS`, or in a decompiler's name) that no other block of the
revision states: the claim's subject. An address another block states is
still in the answer; one no block states left it, and a block without it
writes another claim, not this one. An address is stated by a ``0x…`` or a
decompiler's name of at least :data:`LEAST_ADDRESS` (never a decimal) that
equals it or differs from it by a multiple of 64 KiB, either way: a whole
address and its offset under an image base are one address. A claim a block
restates while an address of it is stated nowhere is carried beside that
block, and the merge says so, naming the addresses
(``ClaimEvidence.carried_beside``, :func:`beside_sentence`). One block
restates a claim, or none does: values and words are never pooled over
blocks, since a claim's helpers recurring across other claims of the
revision say nothing of the claim itself. A claim that names no address is
restated by one block on its words or values alone. A claim a blocking line
of the round's mediation speaks to itself is asked no address either, unless
an own reference of the revision's disputes speaks for it: the revision
answers the line, so the block that restates it best replaces it
(:func:`_answered_by_a_block`). Every other claim a line names keeps the
address and subject tests above. A dispute item read as the author's
withdrawal of that claim leaves it so answered; it has no other effect, and
with no block restating the claim the claim stays in force. A revision
placed by its numbers asks no block for the subject: the number names the
claim.
A revision that writes again or withdraws every claim in force merges
nothing: it stands as written, as it always did.

The rule reads only the lines of the mediation right before the round: a
claim a line of an earlier mediation contested, and that the mediator no
longer listed, is carried with its mark like any other. A claim a blocking
line named that the revision's disputes refer to in any way (its number, as
an own reference however the item reads, or a statement restating it,
:func:`_disputes_read`) is never withdrawn by rule: it is carried with that line.

Nothing here edits a claim's words; the merge only chooses which claims
stand, and :class:`RevisionMerge` records every choice.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from malspark.analysis.technique_ids import is_technique_id
from malspark.pipeline.claim_drops import (
    _DECOMPILER_NAME,
    _HEX,
    _IMAGE_BASE_ALIGNMENT,
    _is_stated,
    _refanged,
    _searched,
    claim_values,
    content_words,
    defanged,
)
from malspark.pipeline.debate_facts import (
    RANGE_NOT_READ,
    ExpandedNaming,
    NamingClause,
    OwnedClaim,
    UnplacedClaims,
    claims_named_by_lines,
    line_tokens,
    read_claim_numbers,
    without_line_mark,
)
from malspark.pipeline.retry_merge import (
    _WITHDRAW_OR_RETRACT_RE,
    _WITHDRAW_WORD_RE,
    _WITHDRAWING_OPENER_RE,
    OwnWithdrawals,
    read_own_withdrawals,
    read_withdrawals,
)
from malspark.schemas.isr_models import carried_beside_marker

# The share of a claim's values the revision must state to write it again.
RESTATED_SHARE = 0.5
# The share of a claim's content words one revision block must state to write
# it again, whatever values it states.
WORDED_SHARE = 0.8
# The share of a claim's values one block must state, beside its technique
# id, to write it again.
CORRECTED_SHARE = 0.34
# A value shorter than this is a small number that many claims state ("0",
# "17"): it is never counted.
TRIVIAL_LENGTH = 3
# A value this long, or a technique id, is one a match must include.
STRONG_LENGTH = 4
# The share of a claim's values one block of a validation retry must state
# for the claim to be read as written again in other words, not left out.
REWRITTEN_SHARE = 2 / 3
# A hex value this large or larger is an address a claim names, the floor the
# validation reads a routine's address by; below it, a key, a flag or a count.
LEAST_ADDRESS = 0x100

# One line of the round's mediation that named a claim: its number (from 1)
# and whether it blocks.
NamingLine = tuple[int, bool]


@dataclass
class _Block:
    """One claim block: its place (from 1) and every claim read from it."""

    number: int
    claims: list[Any] = field(default_factory=list)

    @property
    def sentence(self) -> str:
        return " ".join(str(getattr(self.claims[0], "claim", "") or "").split())


def _blocks(claims: Sequence[Any]) -> list[_Block]:
    """``claims`` by claim block, numbered by place (``validation.claim_block_indexes``)."""
    from malspark.pipeline.validation import claim_block_indexes

    blocks: list[_Block] = []
    for claim, index in zip(claims, claim_block_indexes(list(claims)), strict=True):
        if index == len(blocks):
            blocks.append(_Block(number=index + 1))
        blocks[index].claims.append(claim)
    return blocks


def _text_of(block: _Block) -> str:
    """Everything a revision block states: sentence, evidence and techniques."""
    parts: list[str] = [str(getattr(block.claims[0], "claim", "") or "")]
    parts.append(str(getattr(block.claims[0], "evidence_ref", "") or ""))
    parts.extend(str(getattr(c, "technique_id", "") or "") for c in block.claims)
    return "\n".join(parts)


def _techniques(block: _Block) -> frozenset[str]:
    return frozenset(
        str(getattr(c, "technique_id", "") or "").strip().upper()
        for c in block.claims
        if getattr(c, "technique_id", None)
    )


def _counted_values(block: _Block) -> frozenset[str]:
    """The values a claim states that a restatement is measured by: no small numbers."""
    values: set[str] = set()
    for claim in block.claims:
        values |= claim_values(
            str(getattr(claim, "claim", "") or ""), getattr(claim, "technique_id", None) or ""
        )
    return frozenset(v for v in values if is_technique_id(v) or len(v) >= TRIVIAL_LENGTH)


def _strong(value: str) -> bool:
    return is_technique_id(value) or len(value) >= STRONG_LENGTH


@dataclass(frozen=True)
class _Reading:
    """What a revision block states, read once.

    ``highest`` is, per offset in 64 KiB, the highest address a decompiler's
    name in the block holds there: a number is stated by a name that holds
    it under an image base when that name is higher, so one lookup answers
    what ``claim_drops._is_stated`` asks of every name.
    """

    searched: Any
    words: frozenset[str]
    techniques: frozenset[str]
    highest: Mapping[int, int] = field(default_factory=dict)


def _reading(searched: Any, words: frozenset[str], techniques: frozenset[str]) -> _Reading:
    highest: dict[int, int] = {}
    for name in searched.names:
        offset = name % _IMAGE_BASE_ALIGNMENT
        if name > highest.get(offset, -1):
            highest[offset] = name
    return _Reading(searched=searched, words=words, techniques=techniques, highest=highest)


def _read(block: _Block) -> _Reading:
    text = _text_of(block)
    return _reading(_searched(text), content_words(text), _techniques(block))


def _is_stated_in(value: str, reading: _Reading) -> bool:
    """``claim_drops._is_stated`` of ``value`` in ``reading``, a number in one lookup."""
    if re.fullmatch(r"0x[0-9a-f]+", value) or value.isdecimal():
        number = int(value, 16) if value.startswith("0x") else int(value)
        if number in reading.searched.numbers:
            return True
        return reading.highest.get(number % _IMAGE_BASE_ALIGNMENT, -1) > number
    return _is_stated(value, reading.searched)


def _stated(values: frozenset[str], reading: _Reading) -> set[str]:
    return {v for v in values if _is_stated_in(v, reading)}


def _block_restates(earlier: _Block, reading: _Reading) -> bool:
    """Whether one revision block, read as ``reading``, writes ``earlier`` again."""
    words = content_words(earlier.sentence)
    if words and len(words & reading.words) / len(words) >= WORDED_SHARE:
        return True
    values = _counted_values(earlier)
    if not values:
        return False
    got = _stated(values, reading)
    if not any(_strong(v) for v in got):
        return False
    share = len(got) / len(values)
    if share >= RESTATED_SHARE:
        return True
    return share >= CORRECTED_SHARE and bool(_techniques(earlier) & reading.techniques)


def rewritten_in(claim: Any, retried: Any, others: Sequence[Any] = ()) -> int | None:
    """The block of ``retried`` that writes ``claim`` again and nothing else, or ``None``.

    The block, counted from 1, that writes the claim's sentence as it is, or
    the one block that states four fifths of the claim's content words, or
    two thirds of its values that are no mere small number with at least one
    of them strong. It must also add nothing: every value and every ledger
    id it writes is one of the claim's. And it must write again none of
    ``others`` (the first answer's claims the retry still states): a block
    that holds another claim is that claim's. Two blocks that both qualify
    are no answer.
    """
    earlier = _Block(number=0, claims=[claim])
    words = content_words(earlier.sentence)
    values = _counted_values(earlier)
    ids = _entry_ids(_text_of(earlier))
    held = [_Block(number=0, claims=[other]) for other in others]
    found: list[int] = []
    for block in _blocks(list(getattr(retried, "claims", None) or [])):
        reading = _read(block)
        got = _stated(values, reading) if values else set()
        if not (
            block.sentence == earlier.sentence
            or (words and len(words & reading.words) / len(words) >= WORDED_SHARE)
            or (any(_strong(v) for v in got) and len(got) / len(values) >= REWRITTEN_SHARE)
        ):
            continue
        if not _counted_values(block) <= values or not _entry_ids(_text_of(block)) <= ids:
            continue
        if any(_block_restates(other, reading) for other in held):
            continue
        found.append(block.number)
    return found[0] if len(found) == 1 else None


def _entry_ids(text: str) -> frozenset[str]:
    """The ledger ids ``text`` writes, lower-cased."""
    return frozenset(m.group(0).lower() for m in re.finditer(r"\bev_\d++\b", text, re.I))


def _hex_addresses(text: str) -> set[int]:
    """The addresses ``text`` writes: ``0x…`` or in a decompiler's name, none small, no decimal."""
    plain = _refanged(text)
    found = {int(m.group(1), 16) for m in _HEX.finditer(plain)}
    found |= {int(m.group(1), 16) for m in _DECOMPILER_NAME.finditer(plain)}
    return {a for a in found if a >= LEAST_ADDRESS}


def _stated_addresses(revision: Sequence[_Block]) -> frozenset[int]:
    """Each address the revision's blocks state, headings with them, as its offset in 64 KiB.

    Two addresses are one where they differ by a multiple of the image base
    alignment, either way: a whole address and its offset, or one address
    under two bases. Reduced to that offset, an address is stated when its
    own offset is in this set. The blocks only: an address the revision
    writes only in its prose or its disputes is in none of its claims, and
    no claim of it stands for the claim in force.
    """
    text = "\n".join(
        f"{getattr(block.claims[0], 'heading_note', '') or ''}\n{_text_of(block)}"
        for block in revision
    )
    return frozenset(a % _IMAGE_BASE_ALIGNMENT for a in _hex_addresses(text))


def _subject_left_out(earlier: _Block, stated: frozenset[int]) -> tuple[int, ...]:
    """Each address ``earlier`` names that no block of the revision states, in order.

    ``stated`` is :func:`_stated_addresses` of the revision. The one block
    that restates the claim must state each address no other block states;
    one that no block states is in none, so no block restates the claim.
    """
    return tuple(
        a
        for a in sorted(_hex_addresses(earlier.sentence))
        if a % _IMAGE_BASE_ALIGNMENT not in stated
    )


def _restated(earlier: _Block, readings: Sequence[_Reading]) -> int | None:
    """The first revision block that restates ``earlier`` by itself, or ``None``.

    Never values pooled over blocks.
    """
    for index, reading in enumerate(readings):
        if _block_restates(earlier, reading):
            return index
    return None


def _share(earlier: _Block, reading: _Reading) -> float:
    """How much of ``earlier`` one block states, the larger of two shares.

    The share of its content words and the share of its values, the two
    measures :func:`_block_restates` reads, values as it counts them.
    """
    words = content_words(earlier.sentence)
    worded = len(words & reading.words) / len(words) if words else 0.0
    values = _counted_values(earlier)
    valued = len(_stated(values, reading)) / len(values) if values else 0.0
    return max(worded, valued)


def _restated_best(earlier: _Block, readings: Sequence[_Reading]) -> int | None:
    """The revision block that restates ``earlier`` best (:func:`_share`), or ``None``.

    The first such block on a tie.
    """
    best: tuple[float, int] | None = None
    for index, reading in enumerate(readings):
        if not _block_restates(earlier, reading):
            continue
        share = _share(earlier, reading)
        if best is None or share > best[0]:
            best = (share, index)
    return None if best is None else best[1]


_OWN_CLAIM_NUMBERS = re.compile(
    r"\bclaims?\s*+#?\s*+(\d++(?:\s*+(?:/|,|&|and|\+)\s*+#?\d++)*+)", re.IGNORECASE
)


def _numbers_written(item: str) -> set[int]:
    """The claim numbers an item writes, each claim of a bounded range among them."""
    out: set[int] = set()
    for match in _OWN_CLAIM_NUMBERS.finditer(item):
        read = read_claim_numbers(item, match.start(1))
        out.update(
            int(n) for n in (read.numbers if read is not None else ()) if len(n.lstrip("0")) <= 6
        )
    return out


# A range written backwards in a dispute ("my claims 9-2", "claims 6 to 4"):
# it names no claim, but both its ends are referred to.
_REVERSED_RANGE_RE = re.compile(
    r"\bclaims?\s*+#?\s*+(\d{1,6})\s*+(?:-|–|—|\bto\b)\s*+#?(\d{1,6})\b", re.IGNORECASE
)


@dataclass(frozen=True)
class _DisputesRead:
    """The revision's dispute items, each read once per merge.

    ``numbers`` are the claims in force they refer to by number: every
    "claim N" an item writes, each claim of a bounded range
    (``debate_facts.read_claim_numbers``), both ends of a range written
    backwards, and every own reference however it reads (``own``); and
    ``readings`` each item as a block's statement is read
    (:func:`_block_restates`).
    """

    numbers: frozenset[int]
    readings: tuple[_Reading, ...]

    def refer_to(self, block: _Block) -> bool:
        """Whether an item writes the claim's number or restates it."""
        return block.number in self.numbers or any(
            _block_restates(block, reading) for reading in self.readings
        )


def _disputes_read(
    disputes: Sequence[str], own: OwnWithdrawals, ordered: Sequence[int]
) -> _DisputesRead:
    """The disputes read once (:class:`_DisputesRead`), each item in one pass of its own.

    The line rule never withdraws a claim they refer to: a misread item can
    keep a claim, never remove one. Only a claim a blocking line names is
    asked, so a merge no line names anything in costs the items' length.
    """
    numbers: set[int] = set()
    for item in disputes:
        numbers |= _numbers_written(item)
        for match in _REVERSED_RANGE_RE.finditer(item):
            start, end = int(match.group(1)), int(match.group(2))
            if end < start:
                numbers.update((start, end))
    for low, high, _item in own.claims:
        numbers.update(_known_in(low, high, ordered))
    for low, high in own.spoken:
        numbers.update(_known_in(low, high, ordered))
    readings = tuple(
        _reading(_searched(item), content_words(item), frozenset()) for item in disputes
    )
    return _DisputesRead(frozenset(numbers), readings)


def _answered_by_a_block(
    itself: Mapping[int, Sequence[int]], own: OwnWithdrawals, ordered: Sequence[int]
) -> frozenset[int]:
    """The claims in force a block of the revision may replace without the address test.

    ``itself`` is, per claim in force, the blocking lines that speak to it
    itself (:func:`_speaking_lines`). Such a claim is answered by the block
    that restates it best, unless an own reference of the disputes speaks
    for it (``own.spoken``): then it keeps the address test. This is the
    one use of the own-withdrawal reading
    (``retry_merge.read_own_withdrawals``): an item read as the author's
    withdrawal of its claim only leaves the claim open to that block. It
    never withdraws the claim, which with no block restating it stays in
    force.
    """
    spoken_for: set[int] = set()
    for low, high in own.spoken:
        spoken_for.update(_known_in(low, high, ordered))
    return frozenset(number for number, lines in itself.items() if lines) - spoken_for


def _declares_withdrawal(claim: Any) -> bool:
    """Whether a claim block's heading note or sentence withdraws its own claim."""
    note = str(getattr(claim, "heading_note", "") or "")
    sentence = str(getattr(claim, "claim", "") or "")
    return bool(
        _WITHDRAW_WORD_RE.search(note)
        or _WITHDRAW_OR_RETRACT_RE.search(sentence)
        or _WITHDRAWING_OPENER_RE.match(sentence)
    )


def _written_number(block: _Block) -> int | None:
    written = getattr(block.claims[0], "number", None)
    text = str(written or "").strip()
    return int(text) if text.isdecimal() else None


def _spans(numbers: Sequence[int]) -> str:
    """``1, 3-5, 9`` for ``[1, 3, 4, 5, 9]``."""
    out: list[str] = []
    ordered = sorted(numbers)
    start = previous = None
    for number in [*ordered, None]:
        if previous is not None and number == previous + 1:
            previous = number
            continue
        if start is not None:
            out.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = number
    return ", ".join(out)


def _lines(numbers: Sequence[int]) -> str:
    return ", ".join(f"L{n}" for n in numbers)


@dataclass(frozen=True)
class RevisionMerge:
    """What merging a revision into the answer in force made.

    ``merged`` is the answer that stands, ``None`` when the revision stands as
    written (it wrote again or withdrew every claim in force). ``placed_by``
    is ``"number"`` or ``"statement"``. ``replaced`` are the numbers of the
    claims in force a revision claim wrote again, ``added`` how many revision
    blocks wrote again none, ``withdrawn`` ``(number, sentence, reason)`` per
    claim in force the revision withdrew, ``withdrawn_by_rule`` the same for
    each a blocking line named and the revision left unanswered (with its
    claims, ``ruled_claims``), ``carried`` ``(number, sentence)`` per claim in
    force carried forward, ``unread`` how many withdrawing lines were not read
    exactly (the claims they may name are carried), ``unplaced`` the round's
    claim references that name no claim and may mean this analyst's
    (``debate_facts.UnplacedClaims``): no claim is withdrawn by rule on them;
    ``not_spoken_to`` ``(number, sentence, line, reference)`` per claim
    the merge neither replaced nor withdrew that a blocking line named
    without speaking to it: the line withdraws nothing of it by rule, and
    its mark stays on it; ``owned`` the round's claim
    numbers written for no analyst that are read as this analyst's
    (``debate_facts.OwnedClaim``); ``numbering`` ``(a number the revision's
    text may name a claim by, its number in the merged answer)``
    (:func:`_numbering`, :func:`numbering_key`); ``beside`` ``(number,
    sentence, its number in the merged answer of the block that states it
    again, the addresses that block leaves out)`` per claim carried only
    because the one block that restates it states an address of it nowhere;
    ``restated_by`` ``(number, its number in the answer that stands of the
    block that replaces it)`` per claim in ``replaced``, also where that
    block stands at another claim's place (:func:`_restated_best`);
    ``held_unread`` ``(number, sentence, blocking lines, why)`` per claim the
    line rule would have withdrawn, carried with its lines because the
    revision began a claim the platform did not read (:func:`claims_left_unread`).
    """

    merged: Any | None = None
    placed_by: str = ""
    replaced: tuple[int, ...] = ()
    added: int = 0
    withdrawn: tuple[tuple[int, str, str], ...] = ()
    withdrawn_by_rule: tuple[tuple[int, str, str], ...] = ()
    ruled_claims: tuple[Any, ...] = ()
    carried: tuple[tuple[int, str], ...] = ()
    unread: int = 0
    before: int = 0
    after: int = 0
    unplaced: tuple[UnplacedClaims, ...] = ()
    not_spoken_to: tuple[tuple[int, str, int, str], ...] = ()
    owned: tuple[OwnedClaim, ...] = ()
    numbering: tuple[tuple[int, int], ...] = ()
    beside: tuple[tuple[int, str, int, tuple[str, ...]], ...] = ()
    restated_by: tuple[tuple[int, int], ...] = ()
    held_unread: tuple[tuple[int, str, tuple[int, ...], str], ...] = ()

    def sentences(self, name: str, revision_round: int) -> list[str]:
        """The run summary's sentences: the merge, each withdrawal, each unplaced reference."""
        out: list[str] = []
        r = int(revision_round)
        if self.carried:
            how = "their numbers" if self.placed_by == "number" else "what they state"
            ruled = (
                f" and {len(self.withdrawn_by_rule)} were withdrawn by rule"
                if self.withdrawn_by_rule
                else ""
            )
            out.append(
                f"The {name} analyst's round-{r} revision wrote {self.after - len(self.carried)} "
                f"claim(s) against {self.before} in force: by {how}, they restate "
                f"{len(self.replaced)} of those and add {self.added}; it withdrew "
                f"{len(self.withdrawn)}{ruled}, and the other {len(self.carried)} stand carried "
                f"forward unchanged (claims {_spans([n for n, _s in self.carried])} of its "
                "answer in force)."
                + (
                    f" {self.unread} line(s) that withdraw were not read exactly."
                    if self.unread
                    else ""
                )
            )
        for number, sentence, reason in self.withdrawn:
            out.append(
                defanged(
                    f"The {name} analyst's round-{r} revision withdrew claim {number} "
                    f'("{sentence}")'
                    + (f": {reason.rstrip('.')}" if reason else " and gave no reason")
                    + "."
                )
            )
        for number, sentence, reason in self.withdrawn_by_rule:
            out.append(rule_sentence(name, r, number, sentence, reason))
        for number, sentence, lines, why in self.held_unread:
            out.append(held_unread_sentence(name, r, number, sentence, lines, why))
        for number, sentence, line, reference in self.not_spoken_to:
            out.append(not_spoken_sentence(name, r, number, sentence, line, reference))
        for number, sentence, now, addresses in self.beside:
            out.append(beside_sentence(name, r, number, sentence, now, addresses))
        for owned_claim in self.owned:
            out.append(owned_sentence(name, r, owned_claim))
        for unread_reference in self.unplaced:
            out.append(unplaced_sentence(name, r, unread_reference))
        return out


def held_unread_sentence(
    name: str, revision_round: int, number: int, sentence: str, lines: Sequence[int], why: str
) -> str:
    """The sentence for a claim kept from the line rule by a claim the revision left unread."""
    return defanged(
        f'Claim {int(number)} of the {name} analyst\'s answer in force ("{sentence}") is carried '
        f"with blocking line {_lines(lines)}: the round-{int(revision_round)} revision began a "
        f"claim the platform did not read ({why}), so nothing is withdrawn by rule."
    )


def not_spoken_sentence(
    name: str, revision_round: int, number: int, sentence: str, line: int, reference: str
) -> str:
    """The sentence for a claim a blocking line names without speaking to it."""
    return defanged(
        f"Blocking line L{int(line)} of the round-{int(revision_round)} mediation names "
        f"{reference} of the {name} analyst; claim {number} of its answer in force "
        f'("{sentence}") shares no ledger id or address with it, so the line withdraws '
        "nothing of it by rule, and the claim is carried with the line's mark."
    )


def beside_sentence(
    name: str, revision_round: int, number: int, sentence: str, now: int, addresses: Sequence[str]
) -> str:
    """The sentence for a claim carried beside a block that states it without an address of it."""
    return defanged(
        f'Claim {int(number)} of the {name} analyst\'s answer in force ("{sentence}") is '
        f"carried beside {carried_beside_marker(revision_round, now, addresses)}."
    )


def _tokens_of(block: _Block) -> frozenset[str]:
    """The ledger ids and addresses a claim block writes (``debate_facts.line_tokens``)."""
    return line_tokens(
        "\n".join(
            f"{getattr(c, 'claim', '') or ''}\n{getattr(c, 'evidence_ref', '') or ''}"
            for c in block.claims
        )
    )


def unplaced_sentence(name: str, revision_round: int, reference: UnplacedClaims) -> str:
    """The sentence for a claim reference that names no claim: never acted on in silence.

    Said in the merge of each analyst it may mean
    (``ClaimReferences.unplaced_for``), in the same words where no analyst is
    read for it, and kept once by the run summary; "Blocking line" only for a
    line whose blocking mark was read.
    """
    head = (
        f"{'Blocking line' if reference.marked else 'Line'} L{int(reference.line)} of the "
        f"round-{int(revision_round)} mediation writes {reference.claims}"
    )
    if reference.why == RANGE_NOT_READ:
        return (
            f"{head} of the {name} analyst, {reference.why}: no claim of it is withdrawn by rule "
            "on that reference."
        )
    return f"{head} and {reference.why}: no claim is withdrawn by rule on that reference."


def _own_numbers(revised: Sequence[_Block]) -> list[int] | None:
    """The numbers the revision's headings gave its claim blocks, or ``None``.

    Read only where every block wrote one: a revision that wrote none, or
    some only, has no numbers read, and no key is written for it. A number
    written on two blocks is read for the first only (:func:`_numbering`).
    """
    written = [_written_number(block) for block in revised]
    if any(n is None for n in written):
        return None
    return [int(n or 0) for n in written]


def _numbering(
    placed_by: str,
    revised: Sequence[_Block],
    kept: Sequence[int],
    merged: Sequence[Any],
    carried_ids: Mapping[int, int],
) -> tuple[tuple[int, int], ...]:
    """``(a number the revision's text may name a claim by, its number in the merged answer)``.

    Placed by number, the revision numbers claims as the answer in force
    does: every claim carried keeps its number there, and every block its
    written one. Placed by statement, only the revision's blocks have
    numbers of the revision's own (:func:`_own_numbers`). One mapping per
    number, either way: a number written on two blocks maps the first, in
    the revision's order, which is the text's own block (a claim kept from a
    first answer is put back after the retry's blocks); the revision's
    blocks come before the claims carried. Sorted.
    """
    at = {id(block.claims[0]): block.number for block in _blocks(merged)}
    if placed_by == "number":
        own: list[int | None] = [_written_number(block) for block in revised]
    else:
        own = list(_own_numbers(revised) or [])
        if not own:
            return ()
    found: list[tuple[int, int]] = [
        (int(own[index] or 0), at[id(revised[index].claims[0])])
        for index in sorted(kept)
        if own[index] is not None and id(revised[index].claims[0]) in at
    ]
    if placed_by == "number":
        found += [(n, at[i]) for n, i in carried_ids.items() if i in at]
    first: dict[int, int] = {}
    for number, now in found:
        first.setdefault(number, now)
    return tuple(sorted(first.items()))


def numbering_key(merge: RevisionMerge) -> str:
    """The sentence that maps the numbers the revision text uses onto the merged ones, or ``""``.

    Said only where some number differs. Placed by number, the revision
    names claims by the numbers of the answer it revised: every one that
    moved is listed, carried claims included, and every claim withdrawn is
    named. Placed by statement, it names them by its own numbers: every
    pair is listed, and a number not listed names no claim the platform
    read from the revision.
    """
    moved = [(own, now) for own, now in merge.numbering if own != now]
    if not moved:
        return ""
    if merge.placed_by == "number":
        pairs = "; ".join(f"its claim {own} is claim {now}" for own, now in moved)
        gone = sorted({n for n, _s, _r in (*merge.withdrawn, *merge.withdrawn_by_rule)})
        withdrawn = (
            f" Claim{'s' if len(gone) != 1 else ''} {_spans(gone)} of that answer "
            f"{'were' if len(gone) != 1 else 'was'} withdrawn."
            if gone
            else ""
        )
        return (
            "(The text below names this analyst's claims by their numbers in the answer it "
            f"revised. In the numbering above, {pairs}; every other number is the same."
            f"{withdrawn})"
        )
    pairs = "; ".join(f"its claim {own} is claim {now}" for own, now in merge.numbering)
    return (
        "(The text below names this analyst's claims by the numbers its revision gave them. "
        f"In the numbering above, {pairs}. A number not listed names no claim the platform read "
        "from the revision.)"
    )


def with_numbering_key(text: str, merge: RevisionMerge) -> str:
    """``text`` with :func:`numbering_key` right after the line that opens what it wrote besides.

    A text without that line, or a merge whose numbers all agree, is
    returned as it is.
    """
    from malspark.agents.base_agent import WRITTEN_BESIDES_CLAIMS

    key = numbering_key(merge)
    head = f"\n{WRITTEN_BESIDES_CLAIMS}\n"
    if not key or head not in text:
        return text
    at = text.index(head) + len(head)
    return f"{text[:at]}{key}\n{text[at:]}"


def owned_sentence(name: str, revision_round: int, owned: OwnedClaim) -> str:
    """The sentence for a claim number written for no analyst and read for its owner."""
    shared = int(owned.shared)
    return (
        f"{'Blocking line' if owned.marked else 'Line'} L{int(owned.line)} of the "
        f"round-{int(revision_round)} mediation writes claim {int(owned.claim)} with no analyst "
        f"named for it; it is read as claim {int(owned.claim)} of the {name} analyst, the one "
        f"analyst the line may mean whose claim {int(owned.claim)} alone shares {shared} ledger "
        f"id{'s' if shared != 1 else ''} or address{'es' if shared != 1 else ''} with the line. "
        "Read so, it is carried with the line and never withdrawn by rule."
    )


def claim_tokens_by_number(isr: Any) -> dict[int, frozenset[str]]:
    """``{claim number: the ledger ids and addresses its block writes}`` of an answer in force.

    Numbered by claim block, as the merge and the mediator number them
    (``validation.claim_block_indexes``); an answer with no claims has none.
    """
    claims = list(getattr(isr, "claims", None) or [])
    return {block.number: _tokens_of(block) for block in _blocks(claims)} if claims else {}


def rule_sentence(name: str, revision_round: int, number: int, sentence: str, reason: str) -> str:
    """The sentence for a claim withdrawn by rule, its network values defanged."""
    return defanged(
        f'Claim {number} of the {name} analyst\'s answer in force ("{sentence}") is withdrawn '
        f"by rule after the round-{int(revision_round)} revision: {reason}."
    )


def _by_number(
    first: list[_Block], revision: list[_Block], readings: list[_Reading]
) -> dict[int, int] | None:
    """``{revision block index: claim in force number}`` from written numbers, or ``None``.

    ``None`` when a block wrote no number or one twice, or a number naming a
    claim in force it does not restate: then its numbers may not name the
    claims in force. A block under the number of a claim it restates writes
    that claim again, its addresses or not: the number names it.
    """
    if not revision:
        return None
    by_number = {block.number: block for block in first}
    placed: dict[int, int] = {}
    seen: set[int] = set()
    sentences = {block.sentence: block.number for block in first}
    for index, block in enumerate(revision):
        number = _written_number(block)
        if number is None or number in seen or number < 1:
            return None
        seen.add(number)
        moved = sentences.get(block.sentence)
        if moved is not None and moved != number:
            return None
        earlier = by_number.get(number)
        if earlier is None:
            continue
        if (
            earlier.sentence != block.sentence
            and not _declares_withdrawal(block.claims[0])
            and not _block_restates(earlier, readings[index])
        ):
            return None
        placed[index] = number
    return placed


def _by_statement(
    first: list[_Block],
    readings: list[_Reading],
    stated: frozenset[int],
    answered: frozenset[int] = frozenset(),
) -> tuple[set[int], dict[int, int], dict[int, tuple[int, tuple[int, ...]]], dict[int, int]]:
    """``(numbers restated, {revision block index: claim in force number}, beside, by)``.

    Each revision block stands at the first claim in force it restates by
    itself (:func:`_restated`) with every address of the claim stated by
    some block (:func:`_subject_left_out`). ``beside`` is ``{claim in force
    number: (the first block that restates it, the addresses no block
    states)}`` for each claim a block restates while an address of it is
    stated nowhere: it is carried, beside that block. A claim of
    ``answered`` (one a blocking line of the round's mediation speaks to
    itself, :func:`_answered_by_a_block`) is asked no address: the block
    that restates it best (:func:`_restated_best`) is the revision's answer
    to the line, and replaces it. ``by`` is ``{claim in force number
    restated: the index of the block that replaces it}``, also where that
    block stands at another claim's place.
    """
    restated: set[int] = set()
    target: dict[int, int] = {}
    beside: dict[int, tuple[int, tuple[int, ...]]] = {}
    by: dict[int, int] = {}
    for earlier in first:
        if earlier.number in answered:
            index = _restated_best(earlier, readings)
            left_out: tuple[int, ...] = ()
        else:
            index = _restated(earlier, readings)
            left_out = () if index is None else _subject_left_out(earlier, stated)
        if index is None:
            continue
        if left_out:
            beside[earlier.number] = (index, left_out)
            continue
        restated.add(earlier.number)
        by[earlier.number] = index
        target.setdefault(index, earlier.number)
    return restated, target, beside, by


# Digits past this many name no claim of any answer: the number is read as
# lying past the last claim, never converted.
_CLAIM_NUMBER_DIGITS = 6


def _known_in(low: str, high: str, ordered: Sequence[int]) -> Sequence[int]:
    """The claim numbers of ``ordered`` (sorted) a withdrawn range ``low``-``high`` holds.

    A range is read against the claims there are, so its cost is theirs, never
    its width; a reversed range holds none, and an end too long to be a claim
    number lies past the last claim.
    """

    def bound(digits: str) -> int:
        kept = digits.lstrip("0") or "0"
        return int(kept) if len(kept) <= _CLAIM_NUMBER_DIGITS else 10**_CLAIM_NUMBER_DIGITS

    a, b = bound(low), bound(high)
    if a > b:
        return ()
    return ordered[bisect.bisect_left(ordered, a) : bisect.bisect_right(ordered, b)]


@dataclass(frozen=True)
class _Speaking:
    """What the blocking lines of the round's mediation that name one claim say to it.

    ``rows`` are the lines that name the claim, its contest mark,
    ``unspoken`` ``(line, reference)`` per blocking line that names it
    without speaking to it,
    ``ruling`` the blocking lines whose rule reaches it, and ``itself`` those
    of them that speak to the claim itself (:func:`_speaking_lines`).
    """

    rows: list[NamingLine]
    unspoken: list[tuple[int, str]]
    ruling: list[int]
    itself: list[int]


def _speaking_lines(
    block: _Block,
    named: Mapping[int, Sequence[NamingLine]],
    expanded: Mapping[int, Sequence[ExpandedNaming]],
    clauses: Mapping[int, Sequence[NamingClause]],
    anchored: Mapping[int, frozenset[int]],
) -> _Speaking:
    """What each blocking line that names the claim says to it (:class:`_Speaking`).

    A blocking line anchored by a claim it names (``anchored``,
    :func:`anchored_lines`) speaks only to the claims that anchor it, and to
    each of them itself: the claim shares a ledger id or a value with the
    whole line, or the line quotes its sentence. A line no claim anchors
    speaks to no claim itself; its rule reaches every claim it names, except
    one it reaches only through a range or a list (``expanded``) that shares
    no ledger id or address with the reference's clause. A line whose rule
    does not reach the claim never withdraws it by rule and asks no block to
    answer it; the claim keeps the line's mark.
    """
    rows = list(named.get(block.number, ()))
    blocking = sorted({line for line, blocks in rows if blocks})
    references = {c.line: c.reference for c in clauses.get(block.number, ())}
    reaching = {e.line: e for e in expanded.get(block.number, ())}
    unspoken: list[tuple[int, str]] = []
    for n in blocking:
        if n in anchored:
            if block.number not in anchored[n]:
                unspoken.append((n, references.get(n, f"claim {block.number}")))
        elif n in reaching and not reaching[n].tokens & _tokens_of(block):
            unspoken.append((n, reaching[n].reference))
    silent = {n for n, _r in unspoken}
    ruling = [n for n in blocking if n not in silent]
    return _Speaking(
        rows=rows,
        unspoken=unspoken,
        ruling=ruling,
        itself=[n for n in ruling if n in anchored],
    )


# The consecutive words of a claim's sentence a line must write to speak to
# a claim that shares no ledger id or value with it: a quotation of the
# claim, not words any two claims share.
SPEAKING_RUN_WORDS = 4
# A word, for the runs of words a line and a claim's sentence share.
_RUN_WORD_RE = re.compile(r"[\w'’]++")


def _runs(text: str) -> set[tuple[str, ...]]:
    """Every run of :data:`SPEAKING_RUN_WORDS` consecutive words of ``text``, folded."""
    words = [w.lower() for w in _RUN_WORD_RE.findall(text)]
    return {
        tuple(words[i : i + SPEAKING_RUN_WORDS]) for i in range(len(words) - SPEAKING_RUN_WORDS + 1)
    }


# A line's ``[analysts: ...]`` field: names, never what the line says.
_ANALYSTS_FIELD_RE = re.compile(r"\[\s*+analysts?\s*+:[^\[\]]*+\]", re.IGNORECASE)


def anchored_lines(
    lines: Sequence[str],
    named: Mapping[str, Mapping[int, Sequence[NamingLine]]],
    in_force: Mapping[str, Any],
) -> dict[str, dict[int, frozenset[int]]]:
    """Per analyst, per line a claim anchors, the claims of that analyst that anchor it.

    ``named`` is ``{analyst: {claim number: [(line, blocking), ...]}}``
    (``debate_facts.claims_named_by_lines``) and ``in_force`` each analyst's
    answer in force. A claim anchors a line it is named by when it shares
    with the whole line, its field left out, a ledger id or a value
    (:func:`_counted_values`, stated as :func:`_restated` reads values: an
    address, a number), or when the line writes a run of
    :data:`SPEAKING_RUN_WORDS` consecutive words of its sentence: the line
    quotes it. Content words take no part otherwise. A line is listed for
    every analyst it names a claim of, as soon as one claim of any analyst
    anchors it; a line no claim anchors is listed for none. Each line is read once and
    each claim's values and runs once, so the cost is the lines' and the
    references' length.
    """
    blocks: dict[str, dict[int, _Block]] = {}
    for name, isr in in_force.items():
        claims = list(getattr(isr, "claims", None) or [])
        if claims:
            blocks[name] = {block.number: block for block in _blocks(claims)}
    by_line: dict[int, list[tuple[str, int]]] = {}
    for name, rows in named.items():
        for number, naming in rows.items():
            for line, _blocks_it in naming:
                by_line.setdefault(int(line), []).append((name, int(number)))
    values: dict[tuple[str, int], tuple[frozenset[str], frozenset[str]]] = {}
    runs: dict[tuple[str, int], set[tuple[str, ...]]] = {}
    out: dict[str, dict[int, frozenset[int]]] = {}
    for line, refs in by_line.items():
        if not 0 < line <= len(lines):
            continue
        text = _ANALYSTS_FIELD_RE.sub(" ", without_line_mark(str(lines[line - 1])))
        reading = _reading(_searched(text), frozenset(), frozenset())
        ids = _entry_ids(text)
        anchors: set[tuple[str, int]] = set()
        for ref in dict.fromkeys(refs):
            block = blocks.get(ref[0], {}).get(ref[1])
            if block is None:
                continue
            if ref not in values:
                values[ref] = (_entry_ids(_text_of(block)), _counted_values(block))
            own_ids, own_values = values[ref]
            if own_ids & ids or _stated(own_values, reading):
                anchors.add(ref)
        written = _runs(text)
        for ref in dict.fromkeys(refs):
            block = blocks.get(ref[0], {}).get(ref[1])
            if block is None or ref in anchors:
                continue
            if ref not in runs:
                runs[ref] = _runs(block.sentence)
            if not written.isdisjoint(runs[ref]):
                anchors.add(ref)
        if not anchors:
            continue
        for name in {name for name, _n in refs}:
            out.setdefault(name, {})[line] = frozenset(n for who, n in anchors if who == name)
    return out


def claims_named_in_force(
    lines: Sequence[str], participants: Sequence[str], in_force: Mapping[str, Any]
) -> Any:
    """``debate_facts.claims_named_by_lines`` read against the answers in force, with its anchors.

    The claim numbers each line names per analyst (the owners read from
    ``in_force``), each analyst's rows carrying the lines its claims anchor
    or leave silent (``NamedClaims.anchored``, :func:`anchored_lines`).
    """
    named = claims_named_by_lines(
        lines,
        participants,
        {name: claim_tokens_by_number(isr) for name, isr in in_force.items()},
    )
    for name, lines_of in anchored_lines(lines, named, in_force).items():
        rows = named.get(name)
        if rows is not None and hasattr(rows, "anchored"):
            rows.anchored = lines_of
    return named


def claims_left_unread(answer: str) -> int:
    """How many claims ``answer`` began that its reading did not read.

    The revision's own reading of its claim blocks
    (``base_agent.read_claim_blocks``): the claims begun and not read
    (``ClaimRead.unread``, a block whose confidence cannot be read among
    them) and the blocks that state no confidence. A note that parts of the
    input were not analysed is no claim begun, and counts nothing.
    """
    from malspark.agents.base_agent import read_claim_blocks

    reading = read_claim_blocks(str(answer or ""))
    return int(reading.unread) + int(reading.without_confidence)


def claims_left_unread_of(isr: Any) -> int:
    """How many claims a revision began that its own reading left unread, as its answer holds it.

    What the answer holds after its validation turn: one where it carries a
    reason that claims it began were not read (``AgentISR.claims_unread_reason``,
    set from the reader's own count, ``ClaimRead.unread``, which counts a claim
    begun under a heading the reader does not read; a note that parts of the
    input were not analysed among them), and each
    block that stated no confidence (``AgentISR.blocks_without_confidence``).
    The text is not read again: this is the count the revision node gives
    :func:`merge_revision`.
    """
    reason = 1 if str(getattr(isr, "claims_unread_reason", "") or "").strip() else 0
    return reason + max(0, int(getattr(isr, "blocks_without_confidence", 0) or 0))


def merge_revision(
    in_force: Any,
    revision: Any,
    answer: str,
    revision_round: int,
    named: Mapping[int, Sequence[NamingLine]] | None = None,
    unplaced: Sequence[UnplacedClaims] | None = None,
    expanded: Mapping[int, Sequence[ExpandedNaming]] | None = None,
    owned: Sequence[OwnedClaim] | None = None,
    claims_unread: int | None = None,
) -> RevisionMerge:
    """``revision`` merged into ``in_force`` by claim (:class:`RevisionMerge`).

    ``answer`` is the revision as written, its ``WITHDRAW`` lines included.
    ``named`` is, per claim number of the answer in force, each line of the
    round's mediation that named it (``debate_facts.claims_named_by_lines``),
    and ``unplaced`` each reference of those lines that names no claim and
    that this merge states (``ClaimReferences.unplaced_for``): it withdraws
    nothing. A blocking line that a claim it names anchors
    (``NamedClaims.anchored``, :func:`claims_named_in_force`) speaks only to
    the claims that anchor it; one no claim anchors speaks to every claim it
    names, except one it reaches only by the newer reading, a range or a
    list going on (``expanded``, ``ClaimReferences.expanded_for``), that
    shares no ledger id or address with the reference's clause. A blocking
    line that does not speak to a claim withdraws nothing of it, leaves no
    mark on it, and that is stated. ``owned`` is each claim number written for no
    analyst that the lines' reading read as this analyst's: it is stated.
    Where ``unplaced``, ``expanded`` or ``owned`` is not given, it is read
    from ``named`` (``debate_facts.NamedClaims``). ``claims_unread`` is how
    many claims the revision began and its reading did not read, as the
    caller holds it (:func:`claims_left_unread_of`); given, the text is not
    read again. Not given, by a caller that holds no reading of its own, it
    is read once from ``answer`` (:func:`claims_left_unread`). With one or
    more, nothing is withdrawn by rule. ``in_force`` is not changed.
    """
    if unplaced is None:
        unplaced = tuple(getattr(named, "unplaced", ()) or ())
    owned = tuple(getattr(named, "owned", ()) or ()) if owned is None else tuple(owned)
    if expanded is None:
        expanded = dict(getattr(named, "expanded", {}) or {})
    clauses = dict(getattr(named, "clauses", {}) or {})
    anchored = dict(getattr(named, "anchored", {}) or {})
    first_claims = list(getattr(in_force, "claims", None) or [])
    revision_claims = list(getattr(revision, "claims", None) or [])
    first = _blocks(first_claims)
    # A range whose every claim lies past the answer in force names none of
    # its claims, and is no question about this merge.
    unplaced = tuple(u for u in unplaced if u.why != RANGE_NOT_READ or int(u.lowest) <= len(first))
    if not first_claims or not revision_claims:
        return RevisionMerge(unplaced=unplaced, owned=owned)
    named = named or {}
    expanded = expanded or {}
    revised = _blocks(revision_claims)
    known = {block.number for block in first}
    read = read_withdrawals(answer)
    withdrawn: dict[int, str] = {}
    ordered = sorted(known)
    for low, high, reason in read.claims:
        for number in _known_in(low, high, ordered):
            withdrawn.setdefault(number, reason)
    unread = read.unread
    disputes = [str(item) for item in getattr(revision, "dissent_items", None) or [] if item]
    # The analyst's own references in its disputes, read under the numbering
    # of the answer in force (``retry_merge.read_own_withdrawals``).
    own = read_own_withdrawals(
        disputes,
        getattr(in_force, "revision_round", None),
        tuple(getattr(named, "participants", ()) or ()),
    )
    # Per claim in force, the lines of the round's mediation that named it and
    # the blocking ones that speak to it (:func:`_speaking_lines`).
    speaking = {
        block.number: _speaking_lines(block, named, expanded, clauses, anchored) for block in first
    }
    # The one place the own-withdrawal reading counts (:func:`_answered_by_a_block`).
    answered = _answered_by_a_block(
        {number: lines.itself for number, lines in speaking.items()}, own, ordered
    )
    # The disputes, read once: the line rule never withdraws a claim they
    # refer to, however the item reads (:func:`_disputes_read`).
    referred = _disputes_read(disputes, own, ordered)

    readings = [_read(block) for block in revised]
    numbered = _by_number(first, revised, readings)
    kept_blocks: list[int] = list(range(len(revised)))
    # Where each revision block stands in the merged answer: the number of
    # the claim in force it writes again; a block with none is added.
    target: dict[int, int] = {}
    written_again: set[int] = set()
    beside: dict[int, tuple[int, tuple[int, ...]]] = {}
    # Per claim in force written again, the index of the block that does.
    replaced_by: dict[int, int] = {}
    if numbered is not None:
        placed_by = "number"
        declared = 0
        for index, block in enumerate(revised):
            written = _written_number(block)
            if written in known and _declares_withdrawal(block.claims[0]):
                # A block under a claim's number that withdraws it: the
                # claim goes, with the block's sentence as the reason. The
                # reader counted its line as a withdrawal not read exactly.
                withdrawn.setdefault(int(written or 0), block.sentence)
                kept_blocks.remove(index)
                declared += 1
            elif index in numbered:
                target[index] = numbered[index]
        unread = max(0, unread - declared)
        written_again = set(target.values())
        replaced_by = {number: index for index, number in target.items()}
    else:
        placed_by = "statement"
        written_again, target, beside, replaced_by = _by_statement(
            first, readings, _stated_addresses(revised), answered
        )
    # A claim written again stands as written, whatever a line withdrew.
    for number in written_again:
        withdrawn.pop(number, None)

    # What the revision left unanswered: withdrawn by rule where a blocking
    # line named it and the revision's disputes do not argue it, carried
    # forward otherwise.
    ruled: dict[int, str] = {}
    contested: dict[int, list[int]] = {}
    not_spoken_to: list[tuple[int, str, int, str]] = []
    # Why the revision's reading left a claim it began unread, or "": then
    # nothing is withdrawn by rule (``held_unread``).
    left = claims_left_unread(answer) if claims_unread is None else int(claims_unread)
    begun_unread = f"{left} claim block(s) it began were not read" if left > 0 else ""
    held_unread: list[tuple[int, str, tuple[int, ...], str]] = []
    for block in first:
        if block.number in written_again or block.number in withdrawn:
            continue
        on = speaking[block.number]
        lines, spoken = on.rows, on.ruling
        # A blocking line that does not speak to the claim withdraws nothing
        # of it and keeps its mark on it; the reference is stated.
        not_spoken_to.extend((block.number, block.sentence, n, ref) for n, ref in on.unspoken)
        if spoken and block.number in beside:
            # A block restates it without an address of it: the revision
            # wrote it again, so the line rule withdraws nothing; it is
            # carried beside that block, with the line that contested it.
            contested[block.number] = sorted({line for line, _b in lines})
        elif spoken and referred.refer_to(block):
            # The revision did not restate it but its disputes refer to it:
            # an answer, carried with the line that contested it.
            contested[block.number] = sorted({line for line, _b in lines})
        elif spoken and begun_unread:
            # The revision began a claim the platform did not read: it may be
            # this one restated, so the line rule withdraws nothing.
            contested[block.number] = sorted({line for line, _b in lines})
            held_unread.append((block.number, block.sentence, tuple(spoken), begun_unread))
        elif spoken:
            ruled[block.number] = (
                f"named by blocking line {_lines(spoken)} of the round-{int(revision_round)} "
                "mediation; the revision did not restate it"
            )
        elif lines:
            contested[block.number] = sorted({line for line, _b in lines})
    carried_blocks = [
        block
        for block in first
        if block.number not in written_again
        and block.number not in withdrawn
        and block.number not in ruled
    ]
    replaced = tuple(sorted(written_again))
    added = sum(1 for index in kept_blocks if index not in target)
    withdrawn_rows = tuple(
        (block.number, block.sentence, withdrawn[block.number])
        for block in first
        if block.number in withdrawn
    )
    ruled_blocks = [block for block in first if block.number in ruled]
    ruled_rows = tuple(
        (block.number, block.sentence, ruled[block.number]) for block in ruled_blocks
    )
    ruled_claims = tuple(claim for block in ruled_blocks for claim in block.claims)
    if not carried_blocks:
        return RevisionMerge(
            placed_by=placed_by,
            replaced=replaced,
            added=added,
            withdrawn=withdrawn_rows,
            withdrawn_by_rule=ruled_rows,
            ruled_claims=ruled_claims,
            unread=unread,
            before=len(first),
            after=len(kept_blocks),
            unplaced=unplaced,
            not_spoken_to=tuple(not_spoken_to),
            held_unread=tuple(held_unread),
            owned=owned,
            restated_by=tuple(sorted((n, revised[i].number) for n, i in replaced_by.items())),
        )

    # In the order of the answer in force: each claim carried where it stood,
    # each revision block at the first claim it writes again, and the blocks
    # that write none again after them, in the revision's order.
    at: dict[int, list[int]] = {}
    for index in kept_blocks:
        if index in target:
            at.setdefault(target[index], []).append(index)
    claims: list[Any] = []
    carried_numbers = {block.number for block in carried_blocks}
    # The first claim each carried block stands with, for the numbering key.
    carried_ids: dict[int, int] = {}
    copies: dict[int, list[Any]] = {}
    for block in first:
        if block.number in carried_numbers:
            for claim in block.claims:
                copy = claim.model_copy()
                # The earliest round that carried it is kept.
                if getattr(copy, "carried_since_round", None) is None:
                    copy.carried_since_round = int(revision_round)
                if block.number in contested:
                    copy.carried_contested_by = [
                        f"L{n} (round {int(revision_round)})" for n in contested[block.number]
                    ]
                # Set below where this merge carries it beside a block; a mark
                # of an earlier merge names a number of an earlier answer.
                copy.carried_beside = ""
                carried_ids.setdefault(block.number, id(copy))
                copies.setdefault(block.number, []).append(copy)
                claims.append(copy)
        for index in at.get(block.number, ()):
            claims.extend(revised[index].claims)
    for index in kept_blocks:
        if index not in target:
            claims.extend(revised[index].claims)
    # Each claim carried beside the block that states it again without an
    # address of it says so, naming that block by its number in this answer.
    # Every claim of a block is indexed: two added blocks that end up neighbours
    # may read as one block, so a block's first claim need not head one here.
    now = {id(claim): block.number for block in _blocks(claims) for claim in block.claims}
    beside_rows: list[tuple[int, str, int, tuple[str, ...]]] = []
    for block in carried_blocks:
        if block.number not in beside:
            continue
        index, left_out = beside[block.number]
        addresses = tuple(f"0x{a:x}" for a in left_out)
        number = now[id(revised[index].claims[0])]
        beside_rows.append((block.number, block.sentence, number, addresses))
        for copy in copies[block.number]:
            copy.carried_beside = carried_beside_marker(revision_round, number, addresses)
    merged = revision.model_copy(update={"claims": claims})
    return RevisionMerge(
        restated_by=tuple(
            sorted(
                (n, now[id(revised[i].claims[0])])
                for n, i in replaced_by.items()
                if id(revised[i].claims[0]) in now
            )
        ),
        beside=tuple(beside_rows),
        numbering=_numbering(placed_by, revised, kept_blocks, claims, carried_ids),
        merged=merged,
        placed_by=placed_by,
        replaced=replaced,
        added=added,
        withdrawn=withdrawn_rows,
        withdrawn_by_rule=ruled_rows,
        ruled_claims=ruled_claims,
        carried=tuple((block.number, block.sentence) for block in carried_blocks),
        unread=unread,
        before=len(first),
        after=len(kept_blocks) + len(carried_blocks),
        unplaced=unplaced,
        not_spoken_to=tuple(not_spoken_to),
        held_unread=tuple(held_unread),
        owned=owned,
    )
