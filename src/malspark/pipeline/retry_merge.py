"""A validation retry merged into the answer it fixes, claim by claim, by the claim's block number.

The validation turn asks an analyst to fix the claims a check flagged. Its
retry used to be taken as the analyst's whole answer, so every claim it did
not write again was lost and then had to be asked back. Here the retry changes
only what it writes:

- a claim it writes again under the number of a claim block of the answer it
  fixes replaces that block, every claim the block reads (one per technique
  id) at once;
- a claim it takes out with a ``WITHDRAW CLAIM <n>`` line is withdrawn, with
  the reason the line gives;
- a claim under a number the answer it fixes did not use is added;
- every other claim stays as the answer it fixes wrote it.

Findings are merged the same way by their title: a finding the retry writes
again under the same title replaces it, a ``WITHDRAW FINDING`` line takes one
out and a finding with a new title is added. A finding the retry left
unwritten while it added a new title may be the one it renamed, so it is put
to the analyst (``unplaced``) rather than kept beside the new one in silence.

The merged answer is the first answer with those changes and nothing else: its
disputes, its notes and every field the retry does not write stay its own.

The identity is the claim block's number: its place among the answer's claim
blocks, counted from 1 (``validation.claim_block_indexes``). It is the one
number the platform names claims by everywhere: a flag's path
(``claims[<block>]``), a question's "claim N", and the question that asks
for the retry. The answer being fixed has it when it was read from one
written answer, with every block it began read, none set aside, and the
numbers its headings wrote, if any, equal to their places. Every retry block
must write its number.

Nothing here edits a claim's words: the merge only chooses which version of
each claim stands. Where the numbers do not place the retry beyond doubt it
merges nothing and says why (:attr:`RetryMerge.why`); the caller then asks the
analyst once for its whole corrected answer. The doubts are a block written
without its number or twice, a block left unread, a ``WITHDRAW`` line not
read exactly or naming what the answer has not, a number both written and
withdrawn, a sentence written as written under another number, a claim no
question was about written again with no value in common with the claim it
replaces (or with no value on either side to compare), and a retry that wrote
again a claim no question was about while it left a claim a question was
about neither written nor withdrawn.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from malspark.agents.claim_headings import CLAIM_HEAD_RE, LINE_PREFIX, heading_sentence
from malspark.pipeline.claim_drops import claim_values, dropped_claims

_MARKS = r"[ \t*_`]"
# One claim number or a range of them: ``7``, ``#7``, ``3-5``, ``3 to 5``.
_NUMBER_OR_RANGE = rf"#?\d++(?:{_MARKS}*+(?:-|–|—|\bto\b){_MARKS}*+#?\d++)?+"
# ``WITHDRAW CLAIM 7: reason``, ``WITHDRAW CLAIMS 3, 5 and 9 - reason``,
# ``withdraw claims 1-3``: any case, marks and a list marker before it, its
# reason after a mark or ``because``, or nothing after it.
_WITHDRAW_CLAIM_RE = re.compile(
    r"^" + LINE_PREFIX + rf"withdraw{_MARKS}++claims?+{_MARKS}*+"
    rf"(?P<numbers>{_NUMBER_OR_RANGE}(?:{_MARKS}*+(?:,|&|\band\b){_MARKS}*+{_NUMBER_OR_RANGE})*+)"
    rf"{_MARKS}*+(?:$|(?:[:.\-–—)]|\bbecause\b){_MARKS}*+(?P<reason>.*)$)",
    re.IGNORECASE,
)
# ``WITHDRAW FINDING "<title>": <reason>``, or ``WITHDRAW FINDING: <title>``.
_WITHDRAW_FINDING_RE = re.compile(
    r"^" + LINE_PREFIX + rf"withdraw{_MARKS}++finding{_MARKS}*+"
    rf"(?:\"(?P<quoted>[^\"\n]+)\"{_MARKS}*+(?:[:.\-–—]{_MARKS}*+(?P<reason>.*))?+"
    r"|:(?P<title>.*))$",
    re.IGNORECASE,
)
# Any line that begins with the word: one the two forms above do not read
# exactly is a doubt, never a line passed over.
_WITHDRAW_LINE_RE = re.compile(r"^" + LINE_PREFIX + r"withdraw\b", re.IGNORECASE)
# A withdrawal of a claim written in other words anywhere on a line ("I
# withdraw claim 2", "Claim 5 is withdrawn", "Retract claim 2", "Drop claim
# 2"): a line that holds both a claim number and a withdrawing word, in either
# order, is a doubt unless it is one of the forms above. A claim heading's own
# "CLAIM <n>", on a line the reader reads as a heading, is not that number: the
# rest of the line is what is read. Any other line is read whole, so
# "CLAIM 2 is withdrawn." is a doubt. Two searches per line, so a line costs
# its length.
_WITHDRAW_WORD_RE = re.compile(r"\b(?:withdraw|retract|remov|drop|delet)\w*+", re.IGNORECASE)
_CLAIM_NUMBER_RE = re.compile(r"\bclaims?+\s*+#?\d", re.IGNORECASE)
# A heading that withdraws its own claim: a withdrawing word in its note
# ("CLAIM 2 (withdrawn):"), "withdraw" or "retract" in any form anywhere in
# its sentence ("CLAIM 2: This claim is withdrawn because ..."), which never
# describe what code does, or a bare "removed", "dropped" or "deleted" opening
# its sentence before a mark, the line's end or a reason ("CLAIM 2: [Removed]
# as unsupported"). A sentence that opens with what the code does ("Drops a.exe
# to %TEMP%", "Deletes its own file", "Dropped payload a.exe runs") describes a
# claim.
_WITHDRAW_OR_RETRACT_RE = re.compile(r"\b(?:withdraw|retract)", re.IGNORECASE)
_WITHDRAWING_OPENER_RE = re.compile(
    r"[ \t*_`\"'\[(~>]*+(?:removed|dropped|deleted)\b(?=[ \t*_`\"'~]*+"
    r"(?:$|[:.,;!()\[\]\-–—]|(?:because|since|due|as|from|for[ \t]++lack)\b))",
    re.IGNORECASE,
)
_NUMBER_RE = re.compile(r"\d++")
_RANGE_SPLIT_RE = re.compile(r"(?:,|&|\band\b)", re.IGNORECASE)

# A debate revision's dispute that rejects a claim of the analyst's own answer
# in force is read as the author's withdrawal of it (``read_own_withdrawals``).
# The reading withdraws nothing: it only leaves the claim open to the block of
# the same revision that restates it (``revision_merge``). The wordings, as
# data:
#
# - the reference to its own claim: a first-person word, any of the words of
#   an earlier answer, an optional "round-<n>" (read only for the round of the
#   answer in force: another round's numbers index another answer), then
#   "claim(s)" and its numbers ("my own earlier claim 17", "my claims 3 and 4");
OWN_CLAIM_OPENERS = ("my", "our")
OWN_CLAIM_EARLIER_WORDS = ("own", "earlier", "previous", "prior", "original", "former")
# - the first-person verbs that withdraw it, followed by the reference ("I
#   retract my earlier claim 2: ...") or, after it, by one of the pronouns
#   ("... my own earlier claim 17). I reject this.");
OWN_WITHDRAWING_VERBS = ("withdraw", "retract", "reject")
OWN_WITHDRAWN_PRONOUNS = ("it", "this", "that", "them", "these", "those", "both")
# - the words that say it withdrawn, after the reference ("My claims 1 and 2
#   are superseded by ...", "My claim 2 (...). Withdrawn as stated.");
OWN_WITHDRAWN_WORDS = ("withdrawn", "retracted", "rejected", "superseded", "replaced")
# - the words that keep it, and the words that contrast with a withdrawal:
#   one anywhere in the item after the reference makes a withdrawal by a
#   withdrawn word, or by a verb before the reference, a doubt, and a doubt
#   withdraws nothing ("I withdraw my claim 4 — no, I keep it", "My claims
#   3-5: TRIAGE says they are superseded; I disagree"). A word of evidence or
#   of judgement on the claim ("right", "confirms") is neither;
OWN_KEEPING_WORDS = (
    "stand", "stands", "keep", "kept", "hold", "holds", "maintain", "maintained", "remains",
    "uphold", "upholds", "defend", "defends", "retain", "retains",
)  # fmt: skip
OWN_CONTRASTING_WORDS = (
    "but", "however", "though", "although", "yet", "nevertheless", "disagree", "disagrees",
    "contrary",
)  # fmt: skip
# - the words of reported speech: one between the reference and a withdrawn
#   word makes the word another's report ("TRIAGE says they are superseded").
#   A word that also names a thing of the code ("call", "state", "write",
#   "report") is not one;
OWN_REPORTING_WORDS = (
    "say", "says", "said", "argue", "argues", "argued", "wrote", "stated", "assert", "asserts",
    "asserted", "according",
)  # fmt: skip
# - the words that negate: one among the few words right before the
#   withdrawing word, in its sentence and outside brackets and quotations,
#   governs it and makes the item a doubt ("My claim 4 is not withdrawn",
#   "No, I reject this"), and so does a word ending in one of the endings
#   ("isn't"); a negation inside a bracketed description of the claim
#   ("My claim 2 (the name is not recovered). Withdrawn as stated.") governs
#   nothing;
OWN_NEGATING_WORDS = ("not", "never", "no", "nothing", "none", "neither", "nor", "cannot")
OWN_NEGATING_ENDINGS = ("n't", "n’t")
OWN_NEGATION_REACH = 3
# - the marks that end a clause: a negation before one governs nothing after
#   it ("... was not shown, and I withdraw it");
OWN_CLAUSE_MARKS = (",", ";", ":")
OWN_BRACKETS = (("(", ")"), ("[", "]"))
# - the words of another's act, which give a sentence another subject (below),
#   and the words that name the author as an agent ("rejected by me");
OWN_OTHERS_ACT_WORDS = ("rejected", "disputed", "contested", "challenged", "questioned")
OWN_AUTHOR_AGENTS = ("me", "us", "myself", "ourselves")
# - what may stand right before a word that says it withdrawn: a word of the
#   passive or an adverb, a mark or the item's start ("is withdrawn", "...).
#   Withdrawn as stated"). After any other word ("Peers rejected it") the
#   word is another's act, and the item a doubt;
OWN_PASSIVE_WORDS = (
    "is", "are", "was", "be", "been", "being", "now", "hereby", "both", "all", "also", "thus",
    "therefore", "fully", "entirely",
)  # fmt: skip
# - the words that make a sentence conditional: one in the sentences that hold
#   the reference and the withdrawing word makes the item a doubt ("If
#   ev_0012 is wrong, I withdraw my claim 4"), and so does a question mark
#   there; for a first-person verb on a pronoun in a later sentence than the
#   reference ("... my claim 17). I reject this."), only that verb's own
#   sentence is read;
OWN_CONDITIONAL_WORDS = ("if", "unless", "would", "should", "were", "whether", "could", "might")
OWN_QUESTION_MARKS = ("?",)
# - the quotation marks, opening and closing: a reference or a withdrawing
#   word inside a quotation is another's text ("STATIC wrote: \"my claim 3 is
#   wrong. I reject this.\""). A mark between two letters is an apostrophe,
#   an opening mark never follows a letter and a closing mark never precedes
#   one; a quotation left open runs to the item's end;
OWN_QUOTE_MARKS = (
    ('"', '"'), ("“", "”"), ("‘", "’"), ("«", "»"), ("`", "`"), ("'", "'"),
)  # fmt: skip
# - the endings that make the reference a possessive: what follows is about
#   something of the claim, not the claim ("I reject my claim 4's critics");
OWN_POSSESSIVE_ENDINGS = ("'s", "’s")
# - what may follow the reference right after a verb that names it, or a
#   pronoun: a mark, or one of these words. Anything else ("I reject that
#   wording") withdraws a part of the claim, not the claim;
OWN_CLAIM_ENDS = ("as", "because", "since", "outright", "entirely", "in", "too", "also")
# - what may follow a word that says it withdrawn: the item's end, a mark
#   that ends a sentence or a clause, one of these words ("withdrawn as
#   stated", "withdrawn and replaced"), or "by" with the author
#   (:data:`OWN_AUTHOR_AGENTS`) or a claim ("superseded by claim 7", "by my
#   claim 6"). Anything else makes the item a doubt: a place or a part
#   ("rejected in L2", "superseded in part"), a colon ("Rejected: STATIC's
#   idea"), another agent ("withdrawn by CloseHandle") or a noun the word
#   stands before ("Rejected readings");
OWN_WITHDRAWN_ENDS = ("as", "and")
OWN_WITHDRAWN_END_MARKS = (".", "!", "?", ";")
# - the words that may stand between the reference and a word that says it
#   withdrawn, brackets and quotations aside: any other word gives the word
#   another subject ("My claim 4 refined: the earlier path is superseded");
OWN_SUBJECT_GAP_WORDS = (*OWN_PASSIVE_WORDS, "were", "has", "have", "had")
# - for a verb on a pronoun in a later sentence than the reference, what gives
#   a sentence between them another subject, whose act the pronoun may stand
#   for ("My claim 4. L2 says it is unsupported. I reject this."): a word of
#   :data:`OWN_REPORTING_WORDS` or :data:`OWN_OTHERS_ACT_WORDS`, one of these
#   words of another's act or of a role, a line of the mediation ("L2"), or a
#   word of a participant's name (the participants the caller gives). One of
#   them between the reference and the verb makes the item a doubt, and so
#   does a word of :data:`OWN_KEEPING_WORDS` ("My claim 4 stands. I reject
#   it.") and one of these plural pronouns for a single claim ("My claim 4. I
#   reject them.");
OWN_OTHERS_ACT_VERBS = (
    "disputes", "contradicts", "contradicted", "calls", "called", "rejects", "challenges",
    "questions", "contests", "doubts", "doubted", "objects", "objected",
)  # fmt: skip
OWN_ROLE_WORDS = ("mediator", "mediators", "peer", "peers", "reviewer", "reviewers")
OWN_LINE_REFERENCE = r"\bL\d++\b"
OWN_PLURAL_PRONOUNS = ("them", "these", "those", "both")
# - the words that affirm the claim, and the copulas that may stand between
#   one and the reference: one right after the reference, with nothing else
#   between, makes the item a defence, and a defence withdraws nothing ("my
#   claim 4 is correct"). A reference right after one ("ev_0012 supports my
#   claim 4") is no subject of a withdrawal and reads as nothing already.
#   The same word said of something else ("TRIAGE is right") blocks
#   nothing;
OWN_AFFIRMING_WORDS = (
    "correct", "right", "valid", "accurate", "sound", "true", "confirmed", "supported", "upheld",
    "confirms", "supports", "upholds", "confirm", "support", "uphold",
)  # fmt: skip
OWN_COPULAS = ("is", "are", "was", "were", "be", "been", "remains", "stays", "still")
# - the words that, right after the reference, name a part of the claim ("my
#   earlier claim 3 confidence of 0.60", "my claim 6 detail that ..."): a
#   doubt.
OWN_CLAIM_PARTS = (
    "attribution", "characterisation", "characterization", "confidence", "detail", "details",
    "figure", "framing", "label", "part", "parts", "score", "tag", "tags", "technique",
    "techniques", "wording",
)  # fmt: skip

# How far before a reference the words that withdraw it or make it a subject
# are read, in characters: a first-person verb with an adverb ("I hereby
# withdraw ") or the marks after a sentence's end stand within a few words of
# it. A bound, so an item of many references costs its length.
OWN_CLAIM_BEFORE_WINDOW = 80
# How far after a reference the other claims of its list are read: a list
# longer than this is no list of the reference's, and the item a doubt.
OWN_LIST_WINDOW = 400

_OWN_WORDS = "|".join(OWN_CLAIM_EARLIER_WORDS)
_OWN_CLAIM_RE = re.compile(
    rf"\b(?:{'|'.join(OWN_CLAIM_OPENERS)})(?:\s++(?:{_OWN_WORDS}))*+"
    r"(?:\s++round[-\s]*+(?P<round>\d++))?+\s++claims?+\s*+"
    rf"(?P<numbers>{_NUMBER_OR_RANGE}(?:\s*+(?:,|&|\band\b)\s*+{_NUMBER_OR_RANGE})*+)",
    re.IGNORECASE,
)
_OWN_VERB = rf"\b(?:I|we)\s++(?:now\s++|also\s++|hereby\s++)?(?:{'|'.join(OWN_WITHDRAWING_VERBS)})"
# A verb right before the reference.
_OWN_VERB_BEFORE_RE = re.compile(rf"{_OWN_VERB}\s*+$", re.IGNORECASE)
_OWN_END = rf"[\s*_`]*+(?:$|[.,;:()\[\]\"'“”—–-]|(?:{'|'.join(OWN_CLAIM_ENDS)})\b)"
_OWN_CLAIM_END_RE = re.compile(_OWN_END, re.IGNORECASE)
_OWN_BY_AUTHOR_OR_CLAIM = (
    rf"by\s++(?:(?:{'|'.join(OWN_AUTHOR_AGENTS)})\b"
    rf"|(?:(?:{'|'.join(OWN_CLAIM_OPENERS)})\s++(?:(?:{'|'.join(OWN_CLAIM_EARLIER_WORDS)})\s++)*+)?"
    r"claims?+\s*+#?\d)"
)
_OWN_WITHDRAWN_END_RE = re.compile(
    rf"[\s*_`]*+(?:$|[{re.escape(''.join(OWN_WITHDRAWN_END_MARKS))}]"
    rf"|(?:{'|'.join(OWN_WITHDRAWN_ENDS)})\b|{_OWN_BY_AUTHOR_OR_CLAIM})",
    re.IGNORECASE,
)
_OWN_GAP_WORDS = frozenset(w.lower() for w in OWN_SUBJECT_GAP_WORDS)
_OWN_ANOTHER_SUBJECT_RE = re.compile(
    rf"\b(?:{'|'.join((*OWN_REPORTING_WORDS, *OWN_OTHERS_ACT_WORDS, *OWN_OTHERS_ACT_VERBS))})\b"
    rf"|\b(?:{'|'.join(OWN_ROLE_WORDS)})\b|{OWN_LINE_REFERENCE}",
    re.IGNORECASE,
)
_OWN_KEEPING_ONLY_RE = re.compile(rf"\b(?:{'|'.join(OWN_KEEPING_WORDS)})\b", re.IGNORECASE)
_OWN_COPULA = rf"(?:(?:{'|'.join(OWN_COPULAS)})[\s*_`]++)*+"
_OWN_AFFIRMING = rf"(?:{'|'.join(OWN_AFFIRMING_WORDS)})\b"
# An affirming word right after the reference, a bracket and copulas between.
_OWN_AFFIRMED_AFTER_RE = re.compile(
    rf"[\s*_`]*+(?:\([^()]{{0,{OWN_LIST_WINDOW}}}+\)[\s*_`]*+)?{_OWN_COPULA}{_OWN_AFFIRMING}",
    re.IGNORECASE,
)
_OWN_CLAIM_PART_RE = re.compile(rf"[\s*_`]*+(?:{'|'.join(OWN_CLAIM_PARTS)})\b", re.IGNORECASE)
# A verb with a pronoun after the reference, or a word that says it withdrawn.
_OWN_WITHDRAWN_AFTER_RE = re.compile(
    rf"{_OWN_VERB}\s++(?P<pronoun>{'|'.join(OWN_WITHDRAWN_PRONOUNS)})(?={_OWN_END})"
    rf"|(?P<word>\b(?:{'|'.join(OWN_WITHDRAWN_WORDS)})\b)",
    re.IGNORECASE,
)
# Other claims of the list the reference stands in, right after it ("my claim
# 20, PEER claim 36 and DYNAMIC claim 42"): one list, not another claim.
_OWN_LIST_GOES_ON_RE = re.compile(
    r"(?:\s*+(?:\([^()]*+\))?[\s*_`]*+(?:,|;|&|\band\b)\s*+(?:and\s++)?"
    r"(?:[A-Za-z0-9_'’-]++\s++){0,4}claims?+\s*+#?\d++"
    r"(?:\s*+(?:,|&|\band\b|/|-|–|\bto\b)\s*+#?\d++)*+)*+",
    re.IGNORECASE,
)
_OWN_KEEPING_RE = re.compile(
    rf"\b(?:{'|'.join((*OWN_KEEPING_WORDS, *OWN_CONTRASTING_WORDS))})\b", re.IGNORECASE
)
_OWN_REPORTING_RE = re.compile(rf"\b(?:{'|'.join(OWN_REPORTING_WORDS)})\b", re.IGNORECASE)
_OWN_NEGATING_WORD_RE = re.compile(
    rf"(?:{'|'.join(OWN_NEGATING_WORDS)})"
    rf"|[\w'’]*(?:{'|'.join(map(re.escape, OWN_NEGATING_ENDINGS))})",
    re.IGNORECASE,
)
# A reporting word right after the reference or its list: its subject is the claim.
_OWN_SELF_REPORT_RE = re.compile(
    rf"[\s*_`]*+(?:\([^()]{{0,{OWN_LIST_WINDOW}}}+\)[\s*_`]*+)?"
    rf"(?:{'|'.join(OWN_REPORTING_WORDS)})\b",
    re.IGNORECASE,
)
# A word, for the few words before the withdrawing word a negation is read in.
_WORD_RE = re.compile(r"[\w'’]++")
# How far before the withdrawing word those words are read, in characters.
_OWN_NEGATION_WINDOW = 80
_OWN_PASSIVE_BEFORE_RE = re.compile(
    rf"(?:^|[.!?:;,()\[\]\"'“”—–-]|\b(?:{'|'.join(OWN_PASSIVE_WORDS)})\b)[\s*_`]*+$",
    re.IGNORECASE,
)
_OWN_CONDITIONAL_RE = re.compile(
    rf"\b(?:{'|'.join(OWN_CONDITIONAL_WORDS)})\b"
    rf"|(?:{'|'.join(map(re.escape, OWN_QUESTION_MARKS))})",
    re.IGNORECASE,
)
_OWN_POSSESSIVE_RE = re.compile(
    rf"(?:{'|'.join(map(re.escape, OWN_POSSESSIVE_ENDINGS))})\b", re.IGNORECASE
)
_QUOTE_MARK_RE = re.compile(
    "[" + re.escape("".join(dict.fromkeys(c for pair in OWN_QUOTE_MARKS for c in pair))) + "]"
)
_BRACKET_MARK_RE = re.compile(
    "[" + re.escape("".join(c for pair in OWN_BRACKETS for c in pair)) + "]"
)
# Where a sentence ends: a mark of its end before a space or the item's end.
_SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)")
# What the reference may stand after to be the subject of what follows: the
# item's or a sentence's start, or a list it closes ("(STATIC claim 23, my own
# earlier claim 17)").
_OWN_SUBJECT_BEFORE_RE = re.compile(
    r"(?:^|[.!?:;]|\(|,|&|\band\b)[\s*_`\"'“”(\[]*+$", re.IGNORECASE
)
_ANY_CLAIM_RE = re.compile(r"\bclaims?+\s*+#?\d", re.IGNORECASE)


def _inside(spans: Sequence[tuple[int, int]], at: int) -> bool:
    """Whether ``at`` lies inside one of ``spans`` (sorted, apart)."""
    index = bisect.bisect_left(spans, (at + 1,)) - 1
    return index >= 0 and spans[index][0] <= at < spans[index][1]


def _any_between(positions: Sequence[int], low: int, high: int) -> bool:
    """Whether a position of ``positions`` (sorted) lies in ``[low, high)``."""
    at = bisect.bisect_left(positions, low)
    return at < len(positions) and positions[at] < high


def _quoted_spans(item: str) -> list[tuple[int, int]]:
    """The quotations of ``item`` (:data:`OWN_QUOTE_MARKS`), sorted and apart, in one pass.

    A mark between two word characters is an apostrophe; an opening mark
    never follows a word character, a closing one never precedes one; a
    quotation left open runs to the item's end.
    """
    closing_of = dict(OWN_QUOTE_MARKS)
    found: list[tuple[int, int]] = []
    opened: str | None = None
    start = 0
    for match in _QUOTE_MARK_RE.finditer(item):
        at = match.start()
        mark = item[at]
        before = item[at - 1] if at else " "
        after = item[at + 1] if at + 1 < len(item) else " "
        word_before = before.isalnum() or before == "_"
        word_after = after.isalnum() or after == "_"
        if opened is not None:
            if mark == closing_of[opened] and not word_after:
                found.append((start, at + 1))
                opened = None
            continue
        if mark in closing_of and not word_before:
            opened, start = mark, at
    if opened is not None:
        found.append((start, len(item)))
    return found


def _bracketed_spans(item: str) -> list[tuple[int, int]]:
    """The bracketed spans of ``item`` (:data:`OWN_BRACKETS`), outermost, sorted, in one pass.

    A bracket left open runs to the item's end.
    """
    closing_of = dict(OWN_BRACKETS)
    found: list[tuple[int, int]] = []
    opened: list[str] = []
    start = 0
    for match in _BRACKET_MARK_RE.finditer(item):
        at, mark = match.start(), match.group()
        if mark in closing_of:
            if not opened:
                start = at
            opened.append(closing_of[mark])
        elif opened and mark == opened[-1]:
            opened.pop()
            if not opened:
                found.append((start, at + 1))
    if opened:
        found.append((start, len(item)))
    return found


def _merged(spans: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """``spans`` sorted, overlapping ones joined."""
    out: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if out and start < out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def _negation_governs(
    item: str, at: int, sentence_start: int, aside: Sequence[tuple[int, int]]
) -> bool:
    """Whether a negation stands among the few words right before ``at``.

    Within :data:`OWN_NEGATION_REACH` words, in the clause that holds ``at``
    (the sentence that starts at ``sentence_start``, cut at the last mark of
    :data:`OWN_CLAUSE_MARKS` before ``at``), and outside ``aside`` (brackets
    and quotations).
    """
    low = max(sentence_start, at - _OWN_NEGATION_WINDOW)
    low = max(low, *(item.rfind(mark, low, at) + 1 for mark in OWN_CLAUSE_MARKS))
    words = list(_WORD_RE.finditer(item, low, at))[-OWN_NEGATION_REACH:]
    return any(
        _OWN_NEGATING_WORD_RE.fullmatch(word.group()) and not _inside(aside, word.start())
        for word in words
    )


def _sentence_of(ends: Sequence[int], low: int, high: int, size: int) -> tuple[int, int]:
    """``[start, end]`` of the sentences that hold ``low`` to ``high``, its end mark included."""
    before = bisect.bisect_left(ends, low)
    start = ends[before - 1] + 1 if before else 0
    after = bisect.bisect_left(ends, high)
    return start, ends[after] + 1 if after < len(ends) else size


@dataclass(frozen=True)
class OwnWithdrawals:
    """How a revision's disputes read of its own claims.

    ``claims`` is ``(first, last, item)`` per number or range read as the
    author's withdrawal, as digits, with the dispute item; ``spoken``
    ``(first, last)`` per number or range of every other reference of its
    own an item writes: the item speaks for that claim.
    """

    claims: tuple[tuple[str, str, str], ...] = ()
    spoken: tuple[tuple[str, str], ...] = ()


# "to" between two numbers of a reference.
_TO_RE = re.compile(r"\bto\b", re.IGNORECASE)
# A decimal's mark and fraction, right after a number.
_DECIMAL_AFTER_RE = re.compile(r"\.\d")


def _ranges(numbers: str, decimal_after: bool = False) -> list[tuple[str, str]]:
    """``(first, last)`` per number or range of a reference's numbers, as digits.

    "to" makes a range only when its second end is not below its first and
    is no decimal (``decimal_after``: a fraction follows the numbers): "my
    claim 1 to 0.6" names claim 1.
    """
    out: list[tuple[str, str]] = []
    parts = _RANGE_SPLIT_RE.split(numbers)
    for index, part in enumerate(parts):
        ends = _NUMBER_RE.findall(part)
        if not ends:
            continue
        first, last = _number(ends[0]), _number(ends[-1])
        if _TO_RE.search(part) and (
            (len(last), last) < (len(first), first) or (decimal_after and index == len(parts) - 1)
        ):
            last = first
        out.append((first, last))
    return out


def _participant_words(participants: Sequence[str]) -> re.Pattern[str] | None:
    """The words of the participants' names, as one pattern, or ``None`` for none.

    Each part of a name (split at ``_``, ``-`` and spaces) of at least three
    letters that is no filler word of a short form (``debate_facts``).
    """
    from malspark.pipeline.debate_facts import _FILLER_WORDS, _SHORT_WORD_LENGTH

    words = {
        part
        for name in participants
        for part in re.split(r"[_\-\s]+", str(name or "").lower())
        if len(part) >= _SHORT_WORD_LENGTH and part not in _FILLER_WORDS
    }
    if not words:
        return None
    return re.compile(rf"\b(?:{'|'.join(map(re.escape, sorted(words)))})\b", re.IGNORECASE)


def read_own_withdrawals(
    items: Sequence[str], round_in_force: int | None, participants: Sequence[str] = ()
) -> OwnWithdrawals:
    """The claims of its own answer in force the dispute ``items`` read as rejected, in order.

    What is read here withdraws no claim: the merge only lets a block of the
    same revision that restates such a claim replace it
    (``revision_merge``), so where the item is unsure it reads nothing. An
    item reads as a withdrawal of a claim where it names it as its own
    (:data:`OWN_CLAIM_OPENERS`, :data:`OWN_CLAIM_EARLIER_WORDS`) and either a
    first-person verb of :data:`OWN_WITHDRAWING_VERBS` stands right before
    that reference, nothing but a mark or one of :data:`OWN_CLAIM_ENDS` after
    it; or the reference opens the item or a sentence, or closes a list of
    claims, and later in the item, with no other claim named in between,
    such a verb takes one of :data:`OWN_WITHDRAWN_PRONOUNS`, or a word of
    :data:`OWN_WITHDRAWN_WORDS` follows it with nothing but words of
    :data:`OWN_SUBJECT_GAP_WORDS` between them (brackets and quotations
    aside), after a word of :data:`OWN_PASSIVE_WORDS`, a mark or the item's
    start, and with the item's end, a mark of :data:`OWN_WITHDRAWN_END_MARKS`,
    a word of :data:`OWN_WITHDRAWN_ENDS`, or "by" with the author or a claim
    after it. A "round-<n>" reference is read only where ``n`` is
    ``round_in_force``; any other names no claim of the answer in force,
    neither withdrawn nor ``spoken``. "to" between two numbers makes a range
    only when the second is not below the first and is no decimal.

    Read whole, the item must say nothing against the withdrawal, so it reads
    as nothing where a word of :data:`OWN_NEGATING_WORDS` governs the
    withdrawing word (within :data:`OWN_NEGATION_REACH` words before it, in its
    sentence, outside brackets and quotations); another agent than the
    author follows a withdrawn word ("rejected by the mediator", above); a
    word of :data:`OWN_REPORTING_WORDS` stands between the reference and a withdrawn
    word; a word of :data:`OWN_KEEPING_WORDS` or :data:`OWN_CONTRASTING_WORDS`
    stands anywhere after the reference, unless the withdrawal is the
    author's verb on a pronoun in a later sentence; for a verb on a pronoun,
    another subject (a reporting word, a word of another's act or of a role,
    :data:`OWN_OTHERS_ACT_VERBS`, :data:`OWN_ROLE_WORDS`, a line of the
    mediation, or a word of the name of one of ``participants``) stands
    between the reference and the end of the verb's sentence, a word of
    :data:`OWN_KEEPING_WORDS` stands between the reference and the verb, or
    a pronoun of :data:`OWN_PLURAL_PRONOUNS` stands for one claim; a word of
    :data:`OWN_CONDITIONAL_WORDS` or a question mark stands in the sentences
    that hold the reference and the withdrawing word (for that verb on a
    pronoun, in its own sentence only); the reference or the withdrawing word
    stands inside a quotation (:data:`OWN_QUOTE_MARKS`); the reference is a
    possessive (:data:`OWN_POSSESSIVE_ENDINGS`) or is followed by a part of
    the claim (:data:`OWN_CLAIM_PARTS`). A rejection of another analyst's
    claim names no claim of its own, and is a dispute; anything else is a
    doubt and withdraws nothing, and every reference of its own read so is
    ``spoken``.
    What stands before a reference is read within
    :data:`OWN_CLAIM_BEFORE_WINDOW` characters and its list within
    :data:`OWN_LIST_WINDOW`; every other word is found in one pass over the
    item, so an item costs its length whatever the number of its references.
    """
    claims: list[tuple[str, str, str]] = []
    spoken: list[tuple[str, str]] = []
    in_force = None if round_in_force is None else str(int(round_in_force))
    named_re = _participant_words(participants)
    for raw in items:
        item = " ".join(str(raw or "").split())
        size = len(item)
        # Read once per item: every reference of its own, every other claim
        # named, every word that withdraws, keeps, reports, makes a condition
        # or names another's act, every quotation, bracket and sentence's end.
        own = list(_OWN_CLAIM_RE.finditer(item))
        spans = [(m.start(), m.end()) for m in own]
        others = [m.start() for m in _ANY_CLAIM_RE.finditer(item) if not _inside(spans, m.start())]
        said = [
            (m.start(), m.end(), m.group("word") is not None, (m.group("pronoun") or "").lower())
            for m in _OWN_WITHDRAWN_AFTER_RE.finditer(item)
        ]
        said_at = [at for at, *_rest in said]
        kept_at = [m.start() for m in _OWN_KEEPING_RE.finditer(item)]
        keeping_at = [m.start() for m in _OWN_KEEPING_ONLY_RE.finditer(item)]
        subject_at = sorted(
            [m.start() for m in _OWN_ANOTHER_SUBJECT_RE.finditer(item)]
            + ([m.start() for m in named_re.finditer(item)] if named_re is not None else [])
        )
        reported_at = [m.start() for m in _OWN_REPORTING_RE.finditer(item)]
        conditional_at = [m.start() for m in _OWN_CONDITIONAL_RE.finditer(item)]
        quoted = _quoted_spans(item)
        aside = _merged([*quoted, *_bracketed_spans(item)])
        ends = [m.start() for m in _SENTENCE_END_RE.finditer(item)]
        # Every word, brackets and quotations aside, that may not stand
        # between the reference and a word that says it withdrawn.
        foreign_at = [
            m.start()
            for m in _WORD_RE.finditer(item)
            if m.group().lower() not in _OWN_GAP_WORDS and not _inside(aside, m.start())
        ]
        for match in own:
            ranges = _ranges(
                match.group("numbers"), bool(_DECIMAL_AFTER_RE.match(item, match.end()))
            )
            written_round = match.group("round")
            if written_round is not None and (written_round.lstrip("0") or "0") != in_force:
                # Another answer's numbers: no claim of the answer in force.
                continue
            start, end = match.span()
            window = max(0, start - OWN_CLAIM_BEFORE_WINDOW)
            # Where the withdrawing word stands, where it ends, and its form:
            # a verb before the reference, a withdrawn word, or a verb on a
            # pronoun.
            word: tuple[int, int] | None = None
            form = ""
            if (
                _OWN_POSSESSIVE_RE.match(item, end)
                or _OWN_CLAIM_PART_RE.match(item, end)
                or _inside(quoted, start)
                or _OWN_AFFIRMED_AFTER_RE.match(item, end)
            ):
                word = None
            elif verb := _OWN_VERB_BEFORE_RE.search(item, window, start):
                if _OWN_CLAIM_END_RE.match(item, end):
                    word, form = (verb.start(), verb.end()), "verb"
            elif _OWN_SUBJECT_BEFORE_RE.search(item, window, start):
                at = bisect.bisect_left(said_at, end)
                listed = _OWN_LIST_GOES_ON_RE.match(item, end, min(size, end + OWN_LIST_WINDOW))
                list_end = listed.end() if listed is not None else end
                # A reporting word whose subject is the reference itself, or
                # the list it ends ("my claim 16 say ..."), describes the
                # claim: reported speech is read after it.
                described = _OWN_SELF_REPORT_RE.match(item, list_end)
                reported_from = described.end() if described is not None else end
                if at < len(said):
                    word_at, word_end, passive, pronoun = said[at]
                    one_claim = (
                        list_end == end and len(ranges) == 1 and ranges[0][0] == ranges[0][1]
                    )
                    if not _any_between(others, list_end, word_at) and not (
                        (
                            passive
                            and (
                                _any_between(reported_at, reported_from, word_at)
                                or _any_between(foreign_at, list_end, word_at)
                                or not _OWN_WITHDRAWN_END_RE.match(item, word_end)
                                or not _OWN_PASSIVE_BEFORE_RE.search(
                                    item, max(0, word_at - OWN_CLAIM_BEFORE_WINDOW), word_at
                                )
                            )
                        )
                        or (
                            not passive
                            and (
                                _any_between(
                                    subject_at,
                                    reported_from,
                                    _sentence_of(ends, word_at, word_at, size)[1],
                                )
                                or _any_between(keeping_at, end, word_at)
                                or (one_claim and pronoun in OWN_PLURAL_PRONOUNS)
                            )
                        )
                    ):
                        word, form = (word_at, word_end), "passive" if passive else "pronoun"
            if word is not None:
                # A verb on a pronoun in a later sentence than the reference
                # is the author's own act: only its own sentence is read for
                # a condition, and no keeping or contrasting word blocks it.
                later = form == "pronoun" and bisect.bisect_left(ends, end) < bisect.bisect_left(
                    ends, word[0]
                )
                low, high = _sentence_of(
                    ends, word[0] if later else min(start, word[0]), max(end, word[1]), size
                )
                sentence_start, _high = _sentence_of(ends, word[0], word[0], size)
                if (
                    _inside(quoted, word[0])
                    or _negation_governs(item, word[0], sentence_start, aside)
                    or (not later and _any_between(kept_at, end, size + 1))
                    or _any_between(conditional_at, low, high)
                ):
                    word = None
            if word is None:
                spoken.extend(ranges)
                continue
            claims.extend((first, last, item) for first, last in ranges)
    return OwnWithdrawals(claims=tuple(claims), spoken=tuple(spoken))


# Where a flag names the claim block it is about: ``static.claims[5].T1041``.
_CLAIM_PATH_RE = re.compile(r"claims\[(\d++)\]")


def flagged_blocks(violations: Iterable[Any]) -> list[int]:
    """The claim blocks the flags in ``violations`` name by their paths, each once, in order."""
    found: dict[int, None] = {}
    for violation in violations:
        match = _CLAIM_PATH_RE.search(str(getattr(violation, "path", "") or ""))
        if match is not None:
            found.setdefault(int(match.group(1)))
    return list(found)


def folded_title(value: Any) -> str:
    """A finding's title as two titles are compared: case, marks and spacing aside."""
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).split())


def _number(digits: str) -> str:
    return digits.lstrip("0") or "0"


def _said(reason: str | None) -> str:
    return str(reason or "").strip().strip("*_`").strip()


@dataclass(frozen=True)
class Withdrawals:
    """What a retry's ``WITHDRAW`` lines read.

    ``claims`` is ``(first, last, reason)`` per number or range, as digits;
    ``findings`` is ``(folded title, title as written, reason)``; ``unread``
    counts the lines that begin with the word and were not read exactly.
    """

    claims: tuple[tuple[str, str, str], ...] = ()
    findings: tuple[tuple[str, str, str], ...] = ()
    unread: int = 0

    def __bool__(self) -> bool:
        return bool(self.claims or self.findings)


def read_withdrawals(text: str) -> Withdrawals:
    """The ``WITHDRAW`` lines of ``text``, in order, each read once from its start."""
    claims: list[tuple[str, str, str]] = []
    findings: list[tuple[str, str, str]] = []
    unread = 0
    for line in str(text or "").splitlines():
        if _WITHDRAW_LINE_RE.match(line) is None:
            heading = CLAIM_HEAD_RE.match(line)
            rest = line
            if heading is not None:
                rest = line[heading.end() :]
                sentence = heading_sentence(line, heading)
                if (
                    _WITHDRAW_WORD_RE.search(heading.group("note") or "")
                    or _WITHDRAW_OR_RETRACT_RE.search(sentence)
                    or _WITHDRAWING_OPENER_RE.match(sentence)
                ):
                    unread += 1
                    continue
            if _WITHDRAW_WORD_RE.search(rest) and _CLAIM_NUMBER_RE.search(rest):
                unread += 1
            continue
        found = _WITHDRAW_CLAIM_RE.match(line)
        if found is not None:
            reason = _said(found.group("reason"))
            for part in _RANGE_SPLIT_RE.split(found.group("numbers")):
                ends = _NUMBER_RE.findall(part)
                if ends:
                    claims.append((_number(ends[0]), _number(ends[-1]), reason))
            continue
        titled = _WITHDRAW_FINDING_RE.match(line)
        written = ""
        if titled is not None:
            written = _said(titled.group("quoted") or titled.group("title"))
        if titled is None or not folded_title(written):
            unread += 1
            continue
        findings.append((folded_title(written), written, _said(titled.group("reason"))))
    return Withdrawals(claims=tuple(claims), findings=tuple(findings), unread=unread)


@dataclass
class _Block:
    number: str
    claims: list[Any] = field(default_factory=list)


def _parse_left_unread(isr: Any) -> str:
    """Why the parse of ``isr`` left a claim block it began unread, or ``""``."""
    if int(getattr(isr, "blocks_without_confidence", 0) or 0):
        return "a claim block stated no confidence"
    if list(getattr(isr, "confidence_unreadable", None) or []):
        return "a claim block's confidence could not be read"
    if str(getattr(isr, "claims_unread_reason", "") or ""):
        return "a claim block it began was not read"
    return ""


def _first_blocks(first: Any) -> tuple[list[_Block], str]:
    """The answer being fixed by claim block, numbered by place, or why it cannot be."""
    from malspark.pipeline.validation import claim_block_indexes

    claims = list(getattr(first, "claims", None) or [])
    places = claim_block_indexes(claims)
    blocks: list[_Block] = []
    for claim, place in zip(claims, places, strict=True):
        ordinal = getattr(claim, "block", None)
        if ordinal is None:
            return [], "a claim was not read from a claim block"
        if int(ordinal) != place:
            # The reader's own count and the platform's disagree: claims of
            # answers read apart and put together, or set aside after reading.
            return [], "the answer's claim blocks are not one answer's blocks in order"
        number = str(place + 1)
        written = getattr(claim, "number", None)
        if written is not None and written != number:
            return [], (
                f"the answer being fixed numbered a claim {written} where it is claim {number}"
            )
        if blocks and blocks[-1].number == number:
            blocks[-1].claims.append(claim)
        else:
            blocks.append(_Block(number=number, claims=[claim]))
    return blocks, ""


def numbering_unsettled(first: Any) -> str:
    """Why a retry of ``first`` cannot be merged by claim number, or ``""`` when it can.

    Decided before the retry is asked, so the question names claims by number
    only when they can be named so.
    """
    if not list(getattr(first, "claims", None) or []):
        return "the answer being fixed has no claim"
    if not str(getattr(first, "answer_text", "") or "").strip():
        return "the answer being fixed was not written as one answer"
    if list(getattr(first, "gate_removed", None) or []):
        return "claims of the answer being fixed were set aside before it was checked"
    unread = _parse_left_unread(first)
    if unread:
        return f"in the answer being fixed, {unread}"
    return _first_blocks(first)[1]


def _retry_blocks(claims: Sequence[Any]) -> tuple[list[_Block], str]:
    """The retry's claim blocks, each by the number it wrote, or why they cannot be placed."""
    blocks: list[_Block] = []
    last: int | None = None
    seen: set[str] = set()
    for claim in claims:
        ordinal = getattr(claim, "block", None)
        if ordinal is None:
            return [], "a claim was not read from a claim block"
        written = getattr(claim, "number", None)
        if blocks and ordinal == last:
            blocks[-1].claims.append(claim)
            continue
        last = ordinal
        if written is None:
            return [], "the retry wrote a claim block without its number"
        if written in seen:
            return [], f"the retry wrote claim {written} twice"
        seen.add(written)
        blocks.append(_Block(number=written, claims=[claim]))
    return blocks, ""


def _sentence(block: _Block) -> str:
    """A block's sentence as two are compared: spacing aside."""
    return " ".join(str(getattr(block.claims[0], "claim", "") or "").split())


def _sentence_values(block: _Block) -> frozenset[str]:
    """The values a block's sentence states; its technique ids aside, which a fix may change."""
    return claim_values(str(getattr(block.claims[0], "claim", "") or ""), "")


def _digits_key(number: str) -> tuple[int, str]:
    return (len(number), number)


@dataclass(frozen=True)
class RetryMerge:
    """What merging a retry into the answer it fixes made, or why it merged nothing.

    ``merged`` is the answer that stands, ``None`` when the numbers did not
    place the retry (``why``). ``withdrawn`` is ``(kind, item, reason)`` for
    each claim block and finding of the answer being fixed that a
    ``WITHDRAW`` line read exactly names, whether or not the rest merged:
    the item is the first answer's own object (each claim of a block). The
    caller applies and records them on every path. ``unplaced`` is
    ``(kind, item, missing values)`` for each claim a question was about that
    the retry neither wrote again nor withdrew, and each finding it left
    unwritten while it added a new title: each stays in ``merged`` as
    written, and they are the items left to ask about.
    """

    merged: Any | None = None
    why: str = ""
    replaced: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    unchanged: int = 0
    findings_replaced: int = 0
    findings_added: int = 0
    withdrawn: tuple[tuple[str, Any, str], ...] = ()
    unplaced: tuple[tuple[str, Any, tuple[str, ...]], ...] = ()

    def record(self) -> dict[str, Any]:
        """The merge on the loop's record: what it did, or why it did nothing."""
        claims_out = sorted({id(item) for kind, item, _r in self.withdrawn if kind == "claim"})
        findings_out = sum(1 for kind, _item, _r in self.withdrawn if kind == "finding")
        if self.merged is None:
            return {
                "merged": False,
                "why": self.why,
                "withdrawn_claims": len(claims_out),
                "withdrawn_findings": findings_out,
            }
        return {
            "merged": True,
            "replaced": list(self.replaced),
            "added": list(self.added),
            "unchanged_blocks": self.unchanged,
            "withdrawn_claims": len(claims_out),
            "findings_replaced": self.findings_replaced,
            "withdrawn_findings": findings_out,
            "findings_added": self.findings_added,
            "unplaced": len(self.unplaced),
        }


def _withdrawn_items(
    first_blocks: Sequence[_Block], first_findings: Sequence[Any], read: Withdrawals
) -> tuple[list[tuple[str, Any, str]], dict[str, str], set[str], str]:
    """``(items, number → reason, titles withdrawn, doubt)`` for what the lines read exactly name.

    A range names every number from its first to its last; both ends must be
    numbers of the answer. Linear in the answer and the lines: the ranges
    are laid over the answer's numbers once.
    """
    by_number = {block.number: index for index, block in enumerate(first_blocks)}
    doubt = ""
    # Each range as the blocks it covers, in the order the lines wrote them.
    spans: list[tuple[int, int, str]] = []
    for low, high, reason in read.claims:
        if low not in by_number or high not in by_number:
            missing = low if low not in by_number else high
            doubt = doubt or f"the retry withdrew claim {missing}, which the answer has not"
            continue
        start, stop = by_number[low], by_number[high]
        if start > stop:
            doubt = doubt or f"the retry withdrew claims {low} to {high}, which run backwards"
            continue
        spans.append((start, stop, reason))
    # Which blocks any range covers: one pass over a difference count.
    count = len(first_blocks)
    depth = [0] * (count + 1)
    for start, stop, _reason in spans:
        depth[start] += 1
        depth[stop + 1] -= 1
    # A block's reason is the first written reason of a range that covers it,
    # and no other: each block is given one once, the next block not yet given
    # one found by a pointer that only moves forward (path halving).
    reason_of: list[str | None] = [None] * count
    following = list(range(count + 1))

    def _next_open(index: int) -> int:
        while following[index] != index:
            following[index] = following[following[index]]
            index = following[index]
        return index

    for start, stop, reason in spans:
        if not reason:
            continue
        index = _next_open(start)
        while index <= stop:
            reason_of[index] = reason
            following[index] = index + 1
            index = _next_open(index + 1)
    numbers: dict[str, str] = {}
    covering = 0
    for index, block in enumerate(first_blocks):
        covering += depth[index]
        if covering > 0:
            numbers[block.number] = reason_of[index] or ""
    items: list[tuple[str, Any, str]] = [
        ("claim", claim, numbers[block.number])
        for block in first_blocks
        if block.number in numbers
        for claim in block.claims
    ]
    titles = {title for title, _written, _reason in read.findings}
    reasons = {title: reason for title, _written, reason in read.findings}
    have = {folded_title(getattr(f, "title", "")) for f in first_findings}
    for title in titles:
        if title not in have:
            doubt = doubt or "the retry withdrew a finding the answer has not"
    items += [
        ("finding", finding, reasons[folded_title(getattr(finding, "title", ""))])
        for finding in first_findings
        if folded_title(getattr(finding, "title", "")) in titles
    ]
    return items, numbers, titles, doubt


def merge_retry(
    first: Any,
    retried: Any,
    answer: str,
    asked: Iterable[int] = (),
    asked_about: Iterable[str] = (),
) -> RetryMerge:
    """``retried`` merged into ``first`` by claim block number (:class:`RetryMerge`).

    ``answer`` is the retry as written, its ``WITHDRAW`` lines included.
    ``asked`` are the claim blocks of ``first`` (by index, as a flag's path
    names them) the question was about; ``asked_about`` the technique ids it
    asked about, which a claim the retry left as it was does not count as
    values the retry dropped. Linear in the size of both answers.
    """
    why = numbering_unsettled(first)
    if why:
        return RetryMerge(why=why)
    first_blocks, _ = _first_blocks(first)
    first_findings = list(getattr(first, "findings", None) or [])
    read = read_withdrawals(answer)
    withdrawn, withdrawn_numbers, withdrawn_titles, doubt = _withdrawn_items(
        first_blocks, first_findings, read
    )

    def _not_merged(reason: str) -> RetryMerge:
        return RetryMerge(why=reason, withdrawn=tuple(withdrawn))

    if read.unread:
        return _not_merged("a line of the retry that withdraws could not be read exactly")
    if doubt:
        return _not_merged(doubt)
    unread = _parse_left_unread(retried)
    if unread:
        return _not_merged(f"in the retry, {unread}")
    retry_blocks, why = _retry_blocks(list(getattr(retried, "claims", None) or []))
    if why:
        return _not_merged(why)
    retry_findings = list(getattr(retried, "findings", None) or [])
    if not retry_blocks and not read and not retry_findings:
        return _not_merged("the retry wrote no claim block, finding or withdrawal")

    by_number = {block.number: block for block in first_blocks}
    written_again = {block.number: block for block in retry_blocks}
    asked_numbers = {str(int(index) + 1) for index in asked if 0 <= int(index) < len(first_blocks)}
    for number in withdrawn_numbers:
        if number in written_again:
            return _not_merged(f"the retry both wrote claim {number} again and withdrew it")
    numbered_sentence: dict[str, dict[str, None]] = {}
    for block in first_blocks:
        numbered_sentence.setdefault(_sentence(block), {})[block.number] = None
    for block in retry_blocks:
        moved = numbered_sentence.get(_sentence(block)) or {}
        if moved and block.number not in moved:
            return _not_merged(
                f"the retry wrote claim {next(iter(moved))}'s sentence as claim "
                f"{block.number}, so its numbers do not name the claims of the answer being fixed"
            )
    unasked_written = [
        block
        for block in retry_blocks
        if block.number in by_number and block.number not in asked_numbers
    ]
    for block in unasked_written:
        earlier = by_number[block.number]
        if _sentence(earlier) == _sentence(block):
            continue
        before, after = _sentence_values(earlier), _sentence_values(block)
        if not before or not after or not before & after:
            return _not_merged(
                f"the retry wrote again claim {block.number}, which no question was about, "
                "with no value in common with it, so its number may not name that claim"
            )
    left = [
        number
        for number in sorted(asked_numbers, key=_digits_key)
        if number not in written_again and number not in withdrawn_numbers
    ]
    if left and any(_sentence(by_number[b.number]) != _sentence(b) for b in unasked_written):
        return _not_merged(
            f"the retry wrote again a claim no question was about and left claim {left[0]}, "
            "which a question was about, neither written again nor withdrawn"
        )

    retry_titles: dict[str, Any] = {}
    for finding in retry_findings:
        title = folded_title(getattr(finding, "title", ""))
        if title in retry_titles:
            return _not_merged("the retry wrote one finding title twice")
        if title in withdrawn_titles:
            return _not_merged("the retry both wrote a finding again and withdrew it")
        retry_titles[title] = finding

    claims: list[Any] = []
    replaced: list[str] = []
    unchanged = 0
    for block in first_blocks:
        if block.number in withdrawn_numbers:
            continue
        again = written_again.get(block.number)
        if again is not None:
            claims.extend(again.claims)
            replaced.append(block.number)
        else:
            claims.extend(block.claims)
            unchanged += 1
    added = [block.number for block in retry_blocks if block.number not in by_number]
    for block in retry_blocks:
        if block.number not in by_number:
            claims.extend(block.claims)

    findings: list[Any] = []
    findings_replaced = 0
    unwritten: list[Any] = []
    for finding in first_findings:
        title = folded_title(getattr(finding, "title", ""))
        if title in withdrawn_titles:
            continue
        again = retry_titles.pop(title, None)
        if again is not None:
            findings.append(again)
            findings_replaced += 1
        else:
            findings.append(finding)
            unwritten.append(finding)
    # What is left of the retry's findings has titles the answer had not.
    new_findings = list(retry_titles.values())
    findings.extend(new_findings)

    artifacts = list(getattr(first, "artifacts", None) or [])
    artifacts.extend(a for a in getattr(retried, "artifacts", None) or [] if a not in artifacts)
    # An open question is kept the way an artifact is: the answer's, then
    # each the retry wrote that the answer had not.
    questions = list(getattr(first, "open_questions", None) or [])
    questions.extend(
        q for q in getattr(retried, "open_questions", None) or [] if q not in questions
    )

    unplaced: list[tuple[str, Any, tuple[str, ...]]] = [
        ("claim", claim, missing)
        for claim, missing in _unplaced(retried, answer, [by_number[n] for n in left], asked_about)
    ]
    # A finding left unwritten beside a new title may be the one renamed.
    if new_findings:
        unplaced += [("finding", finding, ()) for finding in unwritten]

    merged = first.model_copy(
        update={
            "claims": claims,
            "findings": findings,
            "artifacts": artifacts,
            "open_questions": questions,
        }
    )
    # Claim headings the answer wrote under its DISPUTES section that the
    # retry writes as claims of its own come in under new numbers: then where
    # its headings stand is as the retry wrote them.
    if added and hasattr(merged, "note_claims_under_disputes"):
        merged.note_claims_under_disputes(int(getattr(retried, "claims_under_disputes", 0) or 0))
    return RetryMerge(
        merged=merged,
        replaced=tuple(replaced),
        added=tuple(added),
        unchanged=unchanged,
        findings_replaced=findings_replaced,
        findings_added=len(new_findings),
        withdrawn=tuple(withdrawn),
        unplaced=tuple(unplaced),
    )


def _unplaced(
    retried: Any,
    answer: str,
    blocks: Sequence[_Block],
    asked_about: Iterable[str],
) -> list[tuple[Any, tuple[str, ...]]]:
    """Each claim of ``blocks`` with the values the retry states nowhere, asked ids aside."""
    if not blocks:
        return []
    asked = {str(value).strip().upper() for value in asked_about if str(value).strip()}
    wanted = [claim for block in blocks for claim in block.claims]
    missing = {
        id(claim): values
        for claim, values in dropped_claims(SimpleNamespace(claims=wanted), retried, answer)
    }
    return [
        (claim, tuple(v for v in missing.get(id(claim), ()) if v.upper() not in asked))
        for claim in wanted
    ]
