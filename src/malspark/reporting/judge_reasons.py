"""A judge's reason as the report's ATT&CK table prints it, under one rule.

The judge answers each technique question with a reason, and the record keeps
it whole. The table prints whole sentences of it, up to the first that opens
the model's own working ("Wait, …") and as many as fit one width, marked where
anything is left out.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from malspark.utils.marked_cut import CUT_MARK

# The words a judge's reason is printed after in the ATT&CK table, and the
# width its printed reason keeps to.
_JUDGE_REASON_OPENERS = ("the judge dropped it (", "kept by the judge when asked (")
JUDGE_REASON_WIDTH = 200
# Where one sentence ends and the next begins.
_SENTENCE_BREAK_RE = re.compile(r"(?<=[.!?])[\"')\]]?\s+(?=[A-Z\"'(\[])")
# A sentence that is the model's own working rather than its reason: one that
# opens with words only working opens with. "Actually", "okay" and "oh" open
# reasons as often, and are not among them.
_SELF_TALK_RE = re.compile(
    r"^\W*(?:wait\b|hmm+\b|hold on\b|let me\b|let's\b|but wait\b|on second thought\b"
    r"|re-?reading\b|looking again\b)",
    re.IGNORECASE,
)


# A sentence that takes back the one before it.
_RETRACTION_RE = re.compile(
    r"^\W*(?:wait,?\s+no\b|no\b\s*[,.!]|actually,?\s+no\b|on second thought\b)",
    re.IGNORECASE,
)


def judge_reason_shown(reason: str, width: int = JUDGE_REASON_WIDTH) -> str:
    """A judge's reason as the ATT&CK table prints it, under one rule.

    The sentences that are the model's own working ("Wait, …", "Let me …")
    are left out wherever they stand, and a sentence a retraction takes back
    ("Wait, no.", "No, …") with them; the others are printed in order, as
    many as fit ``width``, so a conclusion written after the working is
    printed. A reason that is all working prints its last sentence, its
    conclusion. A first sentence longer than the width is cut at a word.
    Anything left out is marked with the cut mark. The record keeps the
    reason whole.
    """
    text = " ".join(str(reason or "").split())
    if not text:
        return ""
    sentences = _SENTENCE_BREAK_RE.split(text)
    kept: list[str] = []
    for sentence in sentences:
        # A retraction ("Wait, no.", "No, …", "Actually no, …") takes back the
        # sentence written just before it: that sentence is not the reason.
        if _RETRACTION_RE.match(sentence) and kept:
            kept.pop()
        if not _SELF_TALK_RE.match(sentence):
            kept.append(sentence)
    if not kept:
        kept = sentences[-1:]
    shown: list[str] = []
    for sentence in kept:
        if len(" ".join([*shown, sentence])) > width:
            break
        shown.append(sentence)
    if not shown:
        return word_cut(kept[0], width)
    said = " ".join(shown)
    return said if len(shown) == len(sentences) else f"{said} {CUT_MARK}"


def status_shown(text: str, width: int, plain: Callable[[str], str] = str) -> str:
    """A status that may carry a judge's reason, as the report prints it in ``width``.

    Each judge's reason is printed by :func:`judge_reason_shown` and never cut
    into; what follows the last reason is cut at a word to what the width
    leaves. A status with no judge's reason is cut to the width at a word. Every bracket a
    cut leaves open is closed after the cut mark, within the width
    (:func:`closed_cut`). ``plain`` is the report's defanger, applied before anything is
    cut.
    """
    return "".join(
        piece for piece, _set in status_parts(text, width, lambda t: [(plain(t), False)])
    )


# A text in pieces, each with whether the platform set it: a mark it prints
# after a sentence, the cut mark and the brackets a cut closes.
Parts = list[tuple[str, bool]]


def status_parts(text: str, width: int, parts: Callable[[str], Parts]) -> Parts:
    """The status :func:`status_shown` prints, in its pieces: ``parts`` gives the pieces of a
    text before any cut (the marks the platform sets in it among them), and the cut is made on
    their characters as :func:`status_shown` makes it, the cut mark and the brackets it closes
    one piece the platform set. A piece is cut where the cut falls in it, never written again."""
    said, through = judge_reasons_shown(str(text or ""))
    if not through:
        return closed_cut_parts(parts(said), width)
    head, tail = parts(said[:through]), parts(said[through:])
    used = sum(len(piece) for piece, _set in head)
    if not "".join(piece for piece, _set in tail):
        return head
    return [*head, *closed_cut_parts(tail, max(0, width - used))]


def closed_cut(text: str, width: int) -> str:
    """``text`` cut at a word to ``width`` (:func:`word_cut`), each bracket the cut leaves open
    closed after the cut mark, the closing brackets within the width too."""
    if len(text) <= width:
        return text
    kept, marks = _closed_cut_at(text, width)
    return text[:kept] + marks


def closed_cut_parts(pieces: Parts, width: int) -> Parts:
    """``pieces`` cut as :func:`closed_cut` cuts the text they make, the cut mark and the
    brackets it closes one piece the platform set."""
    text = "".join(piece for piece, _set in pieces)
    if len(text) <= width:
        return pieces
    kept, marks = _closed_cut_at(text, width)
    out: Parts = []
    at = 0
    for piece, platform in pieces:
        if at >= kept:
            break
        out.append((piece[: kept - at], platform))
        at += len(piece)
    return [*out, (marks, True)]


def _closed_cut_at(text: str, width: int) -> tuple[int, str]:
    """How much of ``text``, longer than ``width``, :func:`closed_cut` keeps, and what it sets
    after: the cut mark and the brackets that close every bracket the kept text leaves open."""
    room = width
    while room > len(CUT_MARK):
        kept = _word_kept(text, room)
        closing = _closing(text[:kept])
        over = kept + len(CUT_MARK) + len(closing) - width
        if over <= 0:
            return kept, CUT_MARK + closing
        room -= over
    return 0, CUT_MARK


# Each opening bracket and the one that closes it.
_CLOSERS = {"(": ")", "[": "]"}


def _closing(text: str) -> str:
    """The brackets that close, innermost first, every bracket ``text`` leaves open."""
    held: list[str] = []
    for character in text:
        if character in _CLOSERS:
            held.append(_CLOSERS[character])
        elif held and character == held[-1]:
            held.pop()
    return "".join(reversed(held))


def word_cut(text: str, width: int) -> str:
    """``text`` whole when it fits ``width``, else cut at the last word that fits and marked."""
    if len(text) <= width:
        return text
    return text[: _word_kept(text, width)] + CUT_MARK


def _word_kept(text: str, width: int) -> int:
    """How much of ``text``, longer than ``width``, :func:`word_cut` keeps before its mark."""
    cut = text[: max(0, width - len(CUT_MARK))]
    if " " in cut:
        cut = cut[: cut.rfind(" ")]
    return len(cut.rstrip(" ,;:"))


def judge_reason_spans(text: str) -> list[tuple[int, int, int]]:
    """Where each judge's reason stands in ``text``, a status or a note as
    :func:`judge_reasons_shown` prints it: for each, where the judge's words start and end
    (the bracket after "the judge dropped it" or "kept by the judge when asked", up to the cut
    mark a reason cut to its width ends in, wherever it stands: at the bracket's end, or
    before the closing bracket of one the judge opened that the cut fell inside) and where its
    bracket closes (the end of ``text`` where it never does). Every word around them, the cut
    mark among them, is the platform's."""
    out: list[tuple[int, int, int]] = []
    at = 0
    lowered = text.lower()
    while True:
        starts = [
            found for opener in _JUDGE_REASON_OPENERS if (found := lowered.find(opener, at)) >= 0
        ]
        if not starts:
            return out
        start = min(starts)
        open_at = start + next(
            len(opener) for opener in _JUDGE_REASON_OPENERS if lowered.startswith(opener, start)
        )
        depth, end = 1, open_at
        while end < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[end], 0)
            end += 1
        inner = end - 1 if depth == 0 else len(text)
        words = text[open_at:inner].rstrip()
        # The cut mark ends the reason as printed: only closing brackets follow it.
        cut = words.rfind(CUT_MARK)
        if cut >= 0 and not words[cut + len(CUT_MARK) :].strip(") "):
            words = words[:cut].rstrip()
        lead = len(words) - len(words.lstrip())
        if words.strip():
            out.append((open_at + lead, open_at + len(words), end))
        at = end


def judge_reasons_shown(text: str) -> tuple[str, int]:
    """``text`` with each judge's reason in it printed by :func:`judge_reason_shown`.

    The reason is the bracket after "the judge dropped it" or "kept by the
    judge when asked", to its matching close (to the end, where the bracket is
    never closed). The second value is where the last reason printed ends in
    the returned text, ``0`` when there is none.
    """
    out: list[str] = []
    at = 0
    through = 0
    lowered = text.lower()
    while True:
        starts = [
            (lowered.find(opener, at), opener)
            for opener in _JUDGE_REASON_OPENERS
            if lowered.find(opener, at) >= 0
        ]
        if not starts:
            break
        start, opener = min(starts)
        open_at = start + len(opener)
        depth = 1
        end = open_at
        while end < len(text) and depth:
            if text[end] == "(":
                depth += 1
            elif text[end] == ")":
                depth -= 1
            end += 1
        closed = depth == 0
        inner = text[open_at : end - 1] if closed else text[open_at:]
        out.append(text[at:open_at] + judge_reason_shown(inner) + (")" if closed else ""))
        at = end
        through = len("".join(out))
    out.append(text[at:])
    return "".join(out), through
