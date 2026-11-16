"""Where a sentence ends: one rule for the agreement round's units and the analyst report.

The agreement round cuts each passage into the sentences a row answers
(``section_agreement._sentence_units``); the analyst report reads whether a flagged text
stands whole in its sentence (``renderers.analyst._stands_whole``). Both ask this module,
so a text the round answers as one sentence is one sentence where the report prints it
(T-719).

A sentence ends at a ``.``, ``!`` or ``?`` that white space or the end of the text
follows, any closing quote, bracket or emphasis after it read past. A period ends no
sentence when

* it closes a run of single letters each followed by a period ("e.g.", "i.e."),
* it sits inside a number ("1.2": no white space follows it),
* the next word is a lower-case word, of letters alone ("approx. half", "etc. were"), or
* the next word is a number and the word the period closes is one of one to five letters
  ("Fig. 3", "v. 7").

A word holding a digit or an underscore ("ev_0060") is no lower-case word, and a hexadecimal
value ("0x5030") is no number: a sentence opening on one still follows a sentence's end.

The rule names no abbreviation: it reads only the shape of the words on either side.
Where it cannot tell, the period ends nothing, and the sentence is the longer one. The end
of the text, or a line break, after the mark ends the sentence whatever the word before it.
"""

from __future__ import annotations

import re

# What may close a sentence after its end mark: any closing quote, bracket or emphasis markup.
SENTENCE_CLOSE = "\"'\u2019\u201d)]*_"
# What may open a word before its letters: an opening quote, bracket, emphasis or code mark.
_WORD_OPEN = "\"'\u2018\u201c([*_`"
# A run of single letters each followed by a period ("e.g.", "U.S."): its last period ends
# no sentence.
_SINGLE_LETTERS = re.compile(r"(?:[^\W\d_]\.){2,}")
# A word of one to five letters before a period: one a number follows ends no sentence.
_SHORT_WORD = re.compile(r"[^\W\d_]{1,5}\.")
# A word of letters alone, no digit or underscore in it ("half", "were"; never "ev_0060").
_LOWER_WORD = re.compile(r"[^\W\d_]+(?![\w])")
# A number: digits, any group or decimal marks between them, and no letter after it ("3",
# "1,500", "2.5"; never "0x5030" or "3rd").
_NUMBER = re.compile(r"\d+(?:[.,]\d+)*(?![\w])")


def ends_sentence(text: str, at: int) -> bool:
    """Whether the mark at ``text[at]`` ends a sentence, as the module's rule reads it."""
    if text[at : at + 1] not in (".", "!", "?"):
        return False
    after = at + 1
    while after < len(text) and text[after] in SENTENCE_CLOSE:
        after += 1
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
    if _SINGLE_LETTERS.fullmatch(word):
        return False
    lower = _LOWER_WORD.match(text, following)
    if lower is not None and lower.group().islower():
        return False
    return not (_NUMBER.match(text, following) and _SHORT_WORD.fullmatch(word))


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
        after = at + 1
        while after < len(sentence) and sentence[after] in SENTENCE_CLOSE:
            after += 1
        if after < len(sentence) and sentence[after].isspace():
            out.append(sentence[begin:after].strip())
            begin = after
    out.append(sentence[begin:].strip())
    return [piece for piece in out if piece] or [sentence]
