"""Where a sentence ends: one rule for the agreement round's units and the analyst report.

The agreement round cuts each passage into the sentences a row answers
(``section_agreement._sentence_units``); the analyst report reads whether a flagged text
stands whole in its sentence (``renderers.analyst._stands_whole``). Both ask this module,
so a text the round answers as one sentence is one sentence where the report prints it
(T-719).

A sentence ends at a ``.``, ``!`` or ``?`` that white space or the end of the text
follows, any closing quote or bracket after it read past (:func:`close_end`), and a mark of
emphasis (``*``, ``_``) only where it closes emphasis opened earlier on the same line: a
wildcard's ``*.*`` closes nothing. A period ends no sentence when

* it closes a run of two or more single letters each followed by a period ("e.g.",
  "i.e.", "U.S."), or
* it sits inside a number ("1.2": no white space follows it).

Nothing else joins. The rule names no abbreviation and reads no word after the period:
where it cannot tell ("approx. half", "Fig. 3", a sentence opening on a lower-case name),
the period ends the sentence, as the cut always read it. The end of the text, or a line
break, after the mark ends the sentence whatever the word before it.
"""

from __future__ import annotations

import re

# What may close a sentence after its end mark: any closing quote, bracket or emphasis markup.
SENTENCE_CLOSE = "\"'\u2019\u201d)]*_"
# The marks of emphasis among them: each closes a sentence only where it closes emphasis.
_EMPHASIS = "*_"
# What a mark of emphasis never follows where it opens or closes emphasis: a wildcard, a
# path, or another mark of the same run.
_NO_EMPHASIS_AFTER = "*\\/"
# What may open a word before its letters: an opening quote, bracket, emphasis or code mark.
_WORD_OPEN = "\"'\u2018\u201c([*_`"
# A run of single letters each followed by a period ("e.g.", "U.S."): its last period ends
# no sentence.
_SINGLE_LETTERS = re.compile(r"(?:[^\W\d_]\.){2,}")


def _opens_emphasis(text: str, at: int, mark: str) -> bool:
    """Whether emphasis by ``mark`` stands open over words on the line before ``text[at]``:
    an odd count of marks there, each the first of its run and following no ``*``, ``\\`` or
    ``/``, the last of them followed by a letter or a digit before ``at``."""
    line = text.rfind("\n", 0, at) + 1
    opened = []
    for i in range(line, at):
        before = text[i - 1] if i > line else ""
        if text[i] == mark and before != mark and not (before and before in _NO_EMPHASIS_AFTER):
            opened.append(i)
    return len(opened) % 2 == 1 and any(c.isalnum() for c in text[opened[-1] : at])


def close_end(text: str, at: int) -> int:
    """Where the closing marks after the end mark at ``text[at]`` end: each closing quote or
    bracket, and a run of a mark of emphasis where it closes emphasis opened earlier on the
    line (T-719); else right after the mark."""
    after = at + 1
    while after < len(text) and text[after] in SENTENCE_CLOSE:
        mark = text[after]
        if mark in _EMPHASIS:
            if text[after - 1] in _NO_EMPHASIS_AFTER or not _opens_emphasis(text, at, mark):
                break
            while after < len(text) and text[after] == mark:
                after += 1
            continue
        after += 1
    return after


def ends_sentence(text: str, at: int) -> bool:
    """Whether the mark at ``text[at]`` ends a sentence, as the module's rule reads it."""
    if text[at : at + 1] not in (".", "!", "?"):
        return False
    after = close_end(text, at)
    if after < len(text) and not text[after].isspace():
        return False
    if text[at] != ".":
        return True
    begin = at
    while begin > 0 and not text[begin - 1].isspace():
        begin -= 1
    word = text[begin : at + 1].lstrip(_WORD_OPEN)
    following = after
    while following < len(text) and text[following].isspace():
        if text[following] in "\n\r":
            return True
        following += 1
    if following == len(text):
        return True
    return not _SINGLE_LETTERS.fullmatch(word)


def pieces(sentence: str) -> list[str]:
    """``sentence`` cut at each mark of a sentence's end that the rule reads as none (a
    period white space follows, which :func:`ends_sentence` declines): the shorter
    sentences a reading may need where the rule joined them. ``[sentence]`` where it
    joined none. A reading that holds a sentence for what one of its parts says reads
    each piece, so no part escapes it by standing in a longer sentence (T-719)."""
    out: list[str] = []
    begin = 0
    for at, char in enumerate(sentence):
        if char not in ".!?" or ends_sentence(sentence, at):
            continue
        after = close_end(sentence, at)
        if after < len(sentence) and sentence[after].isspace():
            out.append(sentence[begin:after].strip())
            begin = after
    out.append(sentence[begin:].strip())
    return [piece for piece in out if piece] or [sentence]
