"""What one ledger entry holds of its call's answer, and what each member of it holds.

One reading, from the entry alone: its own fields, never its tool's name, its
provider, the sample or a family. A tool nobody declared is read by exactly the
same fields as a declared one. :func:`entry_reading` gives every state that
holds for an entry, the one that governs, and the state of each member (one
routine of a batch, one row of a list). It decides nothing about wording: the
readers that build sentences on it keep their own words.

**Entry states.** Read in this order; the first that holds is the entry's
:attr:`EntryReading.state`, and every one that holds is in
:attr:`EntryReading.states`, so the states are a reading, not a partition.

=====  ========================  ===============================================
id     state                     decided by
=====  ========================  ===============================================
E7     :data:`REPEAT`            ``repeated_of``; read through the entry that
                                 holds its answer when the caller gives it
E8     :data:`ABSENT`            no entry (``None``)
E6     :data:`FAILED`            ``ok`` false, or an answer that is only an
                                 error envelope or an error line
                                 (``pipeline.validation._answer_failed``)
E4     :data:`NOT_SHOWN`         the conversation had no room: the output is the
                                 record of the cut (``evidence.answer_not_shown``)
E5a    :data:`BLANKED_UNREAD`    output empty and ``truncated``, blanked by the
                                 pack's budget: ``blanked_by`` "pack" where the
                                 entry records it, else stage ``triage_pack`` or
                                 agent ``pipeline``
E5b    :data:`BLANKED_READ`      the same, blanked by an agent's budget after its
                                 model read the answer
E3     :data:`CUT_AS_TEXT`       ``truncated`` or ``chars_dropped`` above 0, and
                                 no map: a prefix of the text is kept
E2     :data:`SHORTENED`         the shortener's map in the answer
                                 (``output_shortening.our_key_in``)
E9     :data:`ONE_PAGE`          the answer's own paging markers
                                 (``answer_completeness.read_answer``): a flag,
                                 a next field, a bound count, a page number, or
                                 a start field above 0 that the mapping holding
                                 the rows holds itself (``AnswerReading.starts``)
                                 or in its paging block, a list-free block that
                                 also holds a paging word
                                 (``AnswerReading.block_starts``), whether or
                                 not a next field is given or the page is the
                                 last
E10    :data:`WHOLE_WITH_GAPS`   a coverage count of the entry's declared kind
                                 the answer reports something in
E5c    :data:`STRUCTURE_DROPPED` the text kept, the structure beside it dropped
                                 (a ``spilled`` reference of part ``structured``)
E11    :data:`SHOWN_IN_PART`     the reader shows fewer characters than the
                                 ledger holds (``shown_chars``)
E1     :data:`WHOLE`             none of the above (also beside E11 alone)
=====  ========================  ===============================================

The order is the precedence: E7 is resolved to its holder first, then the
state first in the order is :attr:`EntryReading.state`. The order is no ranking
of what may be said: a sentence takes, per column of what it asserts, the most
restrictive cell over ALL of :attr:`EntryReading.states`, never the governing
state alone. E6, E4, E5a, E5b, E3 and E2 say how much of the text the entry
keeps and exclude one another; E9, E10, E5c and E11 stand beside any of them
that keeps text (E2 with E9, E3 with E9, E9 with E10, ...).

**Unknown, never whole.** Where the entry cannot tell whether it holds all,
the reading says so instead of whole. Paging is unknown
(:attr:`EntryReading.paging_unknown`) on E2 with a top-level ``truncated:
true``, which may be the tool's own or the shortener's (it writes one only
where the tool's is not true; the map's count of what it took stays); where
only the call's own ``offset`` argument places the answer after the first row
and no start field of the answer's own or of its paging block does (it may be
a place in a file, so it makes no page); and on a full page under a bounding
argument: an argument the one definition of a bounding argument names
(``output_shortening.bounding_arguments``, read off the entry's own
arguments) equal to the length of the answer's primary list, with no marker
(the outcome is unknown, never a page). On these, as on E9, the members not
kept are unknown (:attr:`EntryReading.members_not_kept` is ``None``). A start
field in a list-free block that holds no paging word is a place of its own
(a position in a file) and no signal at all.
Gaps are unknown (:attr:`EntryReading.gaps_unknown`) for an entry whose
declared kind states no coverage counts, and for a count its kind states that
the answer leaves out: the counts of a kind are read from the one definition
its own reader reads them by (:func:`_coverage_counts`), so an answer of any
other kind, or of a tool nobody declared, reports no gap and is never read as
reporting none. A structure dropped where the run had no store leaves no
reference and is not seen.

**Member states.** There are five. The members are found by shape
(:func:`_container`): an object whose every value is a text is one member per
key; a list, or an object's one list beside nothing but single values, is one
member per row. Any other answer has no members.

=====  ========================  ===============================================
id     member state              decided by
=====  ========================  ===============================================
M1     :data:`MEMBER_WHOLE`      a member of an entry that keeps its text whole;
                                 on E2 a member with no row and no ``others``
                                 row; on E3 a member closed before the cut
M2     :data:`MEMBER_IN_PART`    on E2 its own row keeps ``k`` of ``t`` above 0
M3     :data:`MEMBER_EMPTY`      its kept text is empty where it was cut: its row
                                 keeps 0, or it has none beside an ``others``
                                 row, or the cut of E3 fell in it before any of
                                 its text
M4     :data:`MEMBER_UNMEASURED` text kept and its extent not recorded: on E2
                                 beside an ``others`` row or rows only under it;
                                 on E3 the member the cut fell in
M5     :data:`MEMBER_NOT_KEPT`   not in the kept answer: rows the shortener took
                                 off a list (counted, unnamed), members after an
                                 E3 cut, later pages, every member of an entry
                                 that keeps no text
=====  ========================  ===============================================

A member whose kept text is empty is never M1, M2 or M4 on an entry that was
cut: the shortener empties members largest first, so an empty member is the
common case of a cut, not a sign of a whole one. M5 members are not
enumerated; :attr:`EntryReading.members_not_kept` counts them where the map
does and is ``None`` where some may be missing uncounted, and
:meth:`EntryReading.member` answers M5 for a key the kept answer lacks
whenever it may be among them.

**The readings it stands for.** No reader calls it yet. Each reading of an
entry's state a reader keeps of its own today, and the states it answers for:

* ``agents/function_callees._shown``: shown is not E7, not E4, not E6 by
  ``ok``; an E5 entry and an E6 entry by its answer's form count as shown.
* ``pipeline/validation._batch_members`` and ``_cut_batch_items``: the members
  of a code batch; an E2 batch is no batch, and an E3 member open at "" (M3)
  is listed.
* ``core/undeclared_tools.code_parts``: ``cut`` is M3 or M4 on E3,
  ``answer_cut`` is M5 after it; an E2 batch has no parts.
* ``reporting/redone_calls._cut``: E2, E3, E4, E5a, E5b, and any entry whose
  output is empty (an E1 that answered nothing included).
* ``reporting/ledger_entities`` ``index_whole``, ``agents/function_map``
  ``index_cut``, ``pipeline/function_claims`` ``INDEX_CUT`` and
  ``pipeline/run_state`` ``dropped``: ``truncated``, which is E2, E3, E4,
  E5a and E5b.
* E10, by each kind's own reader of its coverage fields:
  ``tools/artefact_index.head_text`` and ``pipeline/function_claims``
  ``function_facts`` (the function index), ``analysis/behaviour_code``
  ``unread_words`` and the behaviour lines of ``reporting/ledger_report`` and
  ``pipeline/triage_pack`` (the behaviour links), and the pack's directed-text
  and unpacked-program lines.
* ``pipeline/validation.EntryTexts`` ``partial`` and ``failed``,
  ``agents/judge_agent`` ``partial``: ``truncated`` (E2, E3, E4, E5a, E5b) and
  E6; a repeat as its holder.
* ``pipeline/nodes._tools_that_were_shortened``: E2, E3 by ``chars_dropped``,
  E4, and E9 by a top-level ``truncated`` only.
* ``pipeline/nodes._what_the_run_saw``: E5a and E5b, not told apart.
* ``reporting/ledger_report.shortened_sentence``: E2, by the map's first rows.
* ``reporting/renderers/stix_renderer._whole_listing``: not E9 by
  ``truncated``, ``page_offset``, ``total_matched`` or ``total``, and not
  filtered.
* ``agents/ledger_reads`` (stored copy, stored answer) and ``agents/base_agent``
  (stored copy): :attr:`EntryReading.stored`, ``answer`` or ``output`` and
  ``answer`` alone.
* The pack's ``apply_budget`` (``pipeline/triage_pack``, ``pipeline/nodes``)
  writes E5a; ``base_agent._finish_evidence`` writes E5b.

The sentences built on these (the listed and unread routines, the count line,
the index facts, the value checks) read an entry's state only through them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ABSENT",
    "BLANKED_READ",
    "BLANKED_UNREAD",
    "CUT_AS_TEXT",
    "ENTRY_STATES",
    "EntryReading",
    "FAILED",
    "MEMBER_EMPTY",
    "MEMBER_IN_PART",
    "MEMBER_NOT_KEPT",
    "MEMBER_STATES",
    "MEMBER_UNMEASURED",
    "MEMBER_WHOLE",
    "MemberReading",
    "NOT_SHOWN",
    "ONE_PAGE",
    "REPEAT",
    "SHORTENED",
    "SHOWN_IN_PART",
    "STRUCTURE_DROPPED",
    "WHOLE",
    "WHOLE_WITH_GAPS",
    "entry_reading",
]

REPEAT = "repeat"
ABSENT = "absent"
FAILED = "failed"
NOT_SHOWN = "not_shown"
BLANKED_UNREAD = "blanked_before_any_model_read_it"
BLANKED_READ = "blanked_after_a_model_read_it"
CUT_AS_TEXT = "cut_as_text"
SHORTENED = "shortened"
STRUCTURE_DROPPED = "structure_dropped"
ONE_PAGE = "one_page"
WHOLE_WITH_GAPS = "whole_with_gaps"
SHOWN_IN_PART = "shown_in_part"
WHOLE = "whole"

# The precedence, most restrictive first.
ENTRY_STATES = (
    REPEAT,
    ABSENT,
    FAILED,
    NOT_SHOWN,
    BLANKED_UNREAD,
    BLANKED_READ,
    CUT_AS_TEXT,
    SHORTENED,
    ONE_PAGE,
    WHOLE_WITH_GAPS,
    STRUCTURE_DROPPED,
    SHOWN_IN_PART,
    WHOLE,
)

MEMBER_WHOLE = "whole"
MEMBER_IN_PART = "in_part"
MEMBER_EMPTY = "empty"
MEMBER_UNMEASURED = "text_kept_extent_not_recorded"
MEMBER_NOT_KEPT = "not_in_the_kept_answer"
MEMBER_STATES = (MEMBER_WHOLE, MEMBER_IN_PART, MEMBER_EMPTY, MEMBER_UNMEASURED, MEMBER_NOT_KEPT)

# The stage and the agent an entry the pack's budget blanked was filed under,
# for an entry stored before ``blanked_by`` was recorded.
_PACK_STAGE = "triage_pack"
_PACK_AGENT = "pipeline"
_BLANKED_BY_PACK = "pack"
_BLANKED_BY_AGENT = "agent"

# The part of a ``spilled`` reference a structure the eviction dropped is kept as.
_STRUCTURED_PART = "structured"

# The shortener's row for everything past its named rows.
_OTHERS = "others"
_TRUNCATED = "truncated"
_CHARACTERS = "characters"
_ELEMENTS = "elements"


@dataclass(frozen=True)
class MemberReading:
    """One member's state. ``kept`` of ``total`` in ``unit`` only for :data:`MEMBER_IN_PART`."""

    key: str
    path: str
    state: str
    kept: int | None = None
    total: int | None = None
    unit: str = ""


@dataclass(frozen=True)
class EntryReading:
    """Every state one entry is in, the one that governs, and its members.

    ``stored`` names the parts of the answer the job's store keeps whole (a
    ``spilled`` reference with a key and a digest): ``answer`` for an answer cut
    or not shown, ``output`` for one the budget blanked, ``structured`` and
    ``structured_content`` for structures. ``holder`` is the id a repeat names
    and ``holder_reading`` the reading of the entry the caller gave for it.
    ``gap_fields`` are the coverage counts the entry's declared kind states
    (none for any other entry), ``gaps`` those the answer reports something
    in, ``gaps_zero`` those it gives at zero.
    """

    entry_id: str
    state: str
    states: tuple[str, ...]
    members: tuple[MemberReading, ...] = ()
    members_not_kept: int | None = 0
    paging_unknown: bool = False
    gaps: Mapping[str, Any] = field(default_factory=dict)
    gaps_zero: frozenset[str] = frozenset()
    gap_fields: tuple[str, ...] = ()
    stored: tuple[str, ...] = ()
    holder: str = ""
    holder_reading: EntryReading | None = None

    def member(self, key: Any) -> MemberReading | None:
        """The state of the member ``key`` (its key, or its row's index), or ``None``.

        A key the kept answer lacks is :data:`MEMBER_NOT_KEPT` wherever members
        may be missing from it, and ``None`` where the answer is known to hold
        every member it has.
        """
        said = str(key)
        for held in self.members:
            if held.key == said:
                return held
        if self.members_not_kept == 0:
            return None
        return MemberReading(said, "", MEMBER_NOT_KEPT)

    def gap_unknown(self, name: str) -> bool:
        """Whether the answer leaves the gap ``name`` unstated; any name its kind counts not."""
        return name not in self.gaps and name not in self.gaps_zero

    @property
    def gaps_unknown(self) -> bool:
        """Whether what the answer left unread is unknown: its kind counts none, or it omits one."""
        return not self.gap_fields or any(self.gap_unknown(name) for name in self.gap_fields)


def _field(entry: Any, name: str) -> Any:
    return entry.get(name) if isinstance(entry, Mapping) else getattr(entry, name, None)


class _Fields:
    """An entry's dump read by attribute, for the readers that take a ledger entry."""

    def __init__(self, entry: Mapping[str, Any]) -> None:
        self._entry = entry

    def __getattr__(self, name: str) -> Any:
        if name not in self._entry:
            raise AttributeError(name)
        return self._entry[name]


def _escaped(name: str) -> str:
    return name.replace("~", "~0").replace("/", "~1")


def _parsed(text: str) -> Any:
    from malspark.schemas.evidence import parse_structured

    return parse_structured(text)


def _stored(entry: Any) -> tuple[str, ...]:
    parts: list[str] = []
    for ref in _field(entry, "spilled") or ():
        if not isinstance(ref, Mapping):
            continue
        part = str(ref.get("part") or "")
        if part and ref.get("key") and ref.get("sha256") and part not in parts:
            parts.append(part)
    return tuple(parts)


def _structure_dropped(entry: Any) -> bool:
    return any(
        isinstance(ref, Mapping) and ref.get("part") == _STRUCTURED_PART
        for ref in _field(entry, "spilled") or ()
    )


def _blanked_by_pack(entry: Any) -> bool:
    said = str(_field(entry, "blanked_by") or "").strip().lower()
    if said in (_BLANKED_BY_PACK, _BLANKED_BY_AGENT):
        return said == _BLANKED_BY_PACK
    return (
        str(_field(entry, "stage") or "") == _PACK_STAGE
        or str(_field(entry, "agent") or "") == _PACK_AGENT
    )


def _whole_number(value: Any) -> int:
    """``value`` as a count of 0 or more; anything that is no count reads as 0."""
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _dropped(entry: Any) -> int:
    return _whole_number(_field(entry, "chars_dropped"))


def _text_state(entry: Any, output: str, document: Any) -> str:
    """How much of its text the entry keeps: one of E6, E4, E5a, E5b, E3, E2, or ``""``."""
    from malspark.agents.output_shortening import our_key_in
    from malspark.pipeline.validation import _answer_failed
    from malspark.schemas.evidence import answer_not_shown

    truncated = bool(_field(entry, "truncated"))
    held = _Fields(entry) if isinstance(entry, Mapping) else entry
    if _answer_failed(held):
        return FAILED
    if answer_not_shown(held):
        return NOT_SHOWN
    if truncated and not output:
        return BLANKED_UNREAD if _blanked_by_pack(entry) else BLANKED_READ
    if our_key_in(document):
        return SHORTENED
    if truncated or _dropped(entry):
        return CUT_AS_TEXT
    return ""


def _pages(entry: Any, document: Any, shortened: bool) -> tuple[bool, bool]:
    """``(page, unknown)``: whether the answer's own fields make it one page of more
    (E9), and, where they do not, whether its paging is unknown.

    A page by a flag, a next field, a bound count, a page number, or a start
    above 0 that a paged mapping holds itself or in its paging block. Unknown
    where only the call's own ``offset`` argument places the answer after the
    first row, or a bounding argument equals the length of the answer's
    primary list and no marker stands beside it.
    """
    from malspark.agents.output_shortening import bounding_arguments
    from malspark.schemas.answer_completeness import _OFFSET_ARGUMENT, _bounded, read_answer

    raw = _field(entry, "args")
    args = raw if isinstance(raw, Mapping) else None
    held = _field(entry, "structured") is not None
    reading = read_answer(
        document,
        args=args,
        text_chars=None if held else len(str(_field(entry, "output") or "")),
        platform_shortened=shortened,
    )
    if reading.malformed:
        return False, False
    if shortened:
        # Beside the map, the top-level flag and the counts may be the shortener's.
        flags = [name for name, top in reading.flags if not (top and name == _TRUNCATED)]
        page = bool(flags or reading.nexts or reading.pages or reading.page_unknown is not None)
    else:
        page = reading.partial or reading.page_unknown is not None
    if page or reading.starts_after_first or any(start > 0 for start, _ in reading.block_starts):
        return True, False
    if not args:
        return False, False
    offset = args.get(_OFFSET_ARGUMENT)
    placed = isinstance(offset, int) and not isinstance(offset, bool) and offset > 0
    full = _bounded(
        reading, args, bounding_arguments([name for name in args if isinstance(name, str)])
    )
    return False, (placed and not reading.starts and not reading.block_starts) or full is not None


def _coverage_counts(entry: Any) -> tuple[str, ...]:
    """The coverage counts the entry's declared kind states, or ``()``.

    Each kind's are imported from the one definition that kind's own reader
    reads them by; a kind whose gaps no reader counts states none.
    """
    from malspark.agents.function_map import _INDEX_KIND
    from malspark.analysis import behaviour_code, directed_text
    from malspark.core.declared_reading import kind_of
    from malspark.tools import artefact_index, upx

    counted = {
        _INDEX_KIND: artefact_index.COVERAGE_FIELDS,
        behaviour_code.KIND: behaviour_code.COVERAGE_FIELDS,
        directed_text.KIND: directed_text.COVERAGE_FIELDS,
        upx.KIND: upx.COVERAGE_FIELDS,
    }
    return counted.get(kind_of(entry), ())


def _gaps(document: Any, counts: tuple[str, ...]) -> tuple[dict[str, Any], frozenset[str]]:
    if not isinstance(document, Mapping):
        return {}, frozenset()
    reported: dict[str, Any] = {}
    zero: set[str] = set()
    for name in counts:
        if name not in document or document[name] is None:
            continue
        if document[name]:
            reported[name] = document[name]
        else:
            zero.add(name)
    return reported, frozenset(zero)


def _container(document: Any, ours: str = "") -> tuple[str, list[tuple[str, Any]]] | None:
    """The path of the answer's members and the members, by shape, or ``None``.

    A list is one member per row. An object whose every value is a text is one
    member per key; an object with one list beside nothing but single values
    is one member per row of that list. The shortener's map and the top-level
    flag beside it are no members.
    """
    if isinstance(document, list):
        return "", [(str(at), value) for at, value in enumerate(document)]
    if not isinstance(document, Mapping):
        return None
    own = {
        str(key): value
        for key, value in document.items()
        if key != ours and not (ours and key == _TRUNCATED and isinstance(value, bool))
    }
    if not own:
        return None
    lists = [key for key, value in own.items() if isinstance(value, list)]
    if len(lists) == 1 and all(
        not isinstance(value, Mapping | list) for key, value in own.items() if key != lists[0]
    ):
        rows = own[lists[0]]
        return f"/{_escaped(lists[0])}", [(str(at), value) for at, value in enumerate(rows)]
    if all(isinstance(value, str) for value in own.values()):
        return "", list(own.items())
    return None


def _holds_text(value: Any) -> bool:
    """Whether a kept member holds anything: a text that is not empty, or any other value."""
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, Mapping):
        return any(_holds_text(item) for item in value.values())
    if isinstance(value, list):
        return any(_holds_text(item) for item in value)
    return value is not None


def _shortened_members(
    document: Mapping[str, Any], ours: str
) -> tuple[tuple[MemberReading, ...], int | None]:
    """The members of an E2 answer, read against the shortener's map."""
    book = document.get(ours)
    rows = book if isinstance(book, Mapping) else {}
    others = rows.get(_OTHERS)
    found = _container(document, ours)
    if found is None:
        # No container found by shape: whether every member is kept is not known.
        return (), None
    at, items = found
    members: list[MemberReading] = []
    for key, value in items:
        path = f"{at}/{_escaped(key)}"
        own = rows.get(path)
        under = [p for p in rows if isinstance(p, str) and p.startswith(path + "/")]
        if isinstance(own, Mapping) and ("kept_chars" in own or "kept" in own):
            chars = "kept_chars" in own
            kept = _whole_number(own.get("kept_chars" if chars else "kept"))
            left = _whole_number(own.get("omitted_chars" if chars else "omitted"))
            if kept <= 0 or not _holds_text(value):
                members.append(MemberReading(key, path, MEMBER_EMPTY))
            else:
                unit = _CHARACTERS if chars else _ELEMENTS
                members.append(MemberReading(key, path, MEMBER_IN_PART, kept, kept + left, unit))
        elif under or others is not None:
            state = MEMBER_UNMEASURED if _holds_text(value) else MEMBER_EMPTY
            members.append(MemberReading(key, path, state))
        else:
            members.append(MemberReading(key, path, MEMBER_WHOLE))
    # Keys are never removed; rows of a list are, from its end.
    missing: int | None = 0
    if at:
        own_row = rows.get(at)
        if isinstance(own_row, Mapping) and "omitted" in own_row:
            missing = _whole_number(own_row.get("omitted"))
        elif isinstance(others, Mapping) and _whole_number(others.get("omitted")):
            missing = None
    return tuple(members), missing


def _read_prefix(text: str, at: int, depth: int) -> tuple[Any, int, list[Any] | None]:
    """``(value, end, cut)`` of the JSON value at ``at`` of a text cut short.

    ``cut`` is ``None`` for a value read whole, else the keys from this value
    down to the member the cut fell in (``[]`` when it fell in this value
    itself, between members or in a key). A member whose value the cut left
    nothing of is kept as an empty text, so its key is still read.
    """
    from json import decoder

    from malspark.core.undeclared_tools import _read_to_cut

    try:
        value, end = json.JSONDecoder().raw_decode(text, at)
        return value, end, None
    except ValueError:
        pass
    except RecursionError:
        return None, len(text), []
    if at >= len(text):
        return None, at, []
    opening = text[at]
    if opening == '"':
        return _read_to_cut(text[at + 1 :]), len(text), []
    if opening not in "{[" or depth <= 0:
        return None, len(text), []
    keyed = opening == "{"
    closing = "}" if keyed else "]"
    container: Any = {} if keyed else []
    pos = at + 1

    def space(pos: int) -> int:
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        return pos

    while True:
        pos = space(pos)
        if pos < len(text) and text[pos] == closing:
            return container, pos + 1, None
        key: Any = len(container)
        if keyed:
            if pos >= len(text) or text[pos] != '"':
                return container, len(text), []
            try:
                key, pos = decoder.scanstring(text, pos + 1, False)  # type: ignore[attr-defined]
            except ValueError:
                return container, len(text), []
            pos = space(pos)
            if pos >= len(text) or text[pos] != ":":
                return container, len(text), []
            pos = space(pos + 1)
        if pos >= len(text):
            if keyed:
                container[key] = ""
            else:
                container.append("")
            return container, len(text), [key]
        value, pos, inner = _read_prefix(text, pos, depth - 1)
        if keyed:
            container[key] = value
        else:
            container.append(value)
        if inner is not None:
            return container, len(text), [key, *inner]
        pos = space(pos)
        if pos < len(text) and text[pos] == ",":
            pos += 1
            continue
        if pos < len(text) and text[pos] == closing:
            return container, pos + 1, None
        return container, len(text), []


def _cut_members(output: str) -> tuple[tuple[MemberReading, ...], int | None]:
    """The members an E3 text still shows, read from its opening to the cut.

    The platform's mark of the cut at the end is no part of the answer.
    """
    from malspark.core.undeclared_tools import _STORAGE_CUT_MARKS

    stripped = output.strip()
    trimmed = True
    while trimmed:
        trimmed = False
        for mark in _STORAGE_CUT_MARKS:
            if stripped.endswith(mark):
                stripped = stripped[: -len(mark)].rstrip()
                trimmed = True
    if not stripped or stripped[0] not in "{[":
        return (), None
    document, _end, cut = _read_prefix(stripped, 0, 3)
    found = _container(document)
    if found is None:
        return (), None
    at, items = found
    inside: list[Any] | None = None
    if cut is not None:
        if not at:
            inside = cut
        elif cut and str(cut[0]) == at[1:].replace("~1", "/").replace("~0", "~"):
            inside = cut[1:]
    members: list[MemberReading] = []
    for key, value in items:
        path = f"{at}/{_escaped(key)}"
        if inside and str(inside[0]) == key:
            state = MEMBER_UNMEASURED if _holds_text(value) else MEMBER_EMPTY
            members.append(MemberReading(key, path, state))
        else:
            members.append(MemberReading(key, path, MEMBER_WHOLE))
    if cut is None or (at and inside is None):
        # The members' container closed before the cut.
        return tuple(members), 0
    return tuple(members), None


def _whole_members(document: Any) -> tuple[MemberReading, ...]:
    found = _container(document)
    if found is None:
        return ()
    at, items = found
    return tuple(MemberReading(key, f"{at}/{_escaped(key)}", MEMBER_WHOLE) for key, _ in items)


def entry_reading(
    entry: Any, *, holder: Any = None, shown_chars: int | None = None
) -> EntryReading:
    """The states of ``entry`` (a ledger entry or its dump) and of each of its members.

    ``holder`` is the entry a repeat's chain ends at, where the caller holds
    it (``evidence.repeat_holders``): the repeat is then read through it.
    ``shown_chars`` is how many characters of the entry's text the caller shows
    a reader, for :data:`SHOWN_IN_PART`. ``None`` reads as :data:`ABSENT`.
    """
    if entry is None:
        return EntryReading("", ABSENT, (ABSENT,), members_not_kept=None)
    entry_id = str(_field(entry, "id") or "")
    stored = _stored(entry)
    named = str(_field(entry, "repeated_of") or "").strip()
    if named:
        own = entry_id.strip().lower()
        first = "" if named.lower() == own else named
        if holder is None:
            return EntryReading(
                entry_id, REPEAT, (REPEAT,), members_not_kept=None, stored=stored, holder=first
            )
        held = entry_reading(holder)
        return EntryReading(
            entry_id,
            REPEAT,
            # A holder that is itself a repeat gives each state once.
            tuple(dict.fromkeys((REPEAT, *held.states))),
            members=held.members,
            members_not_kept=held.members_not_kept,
            paging_unknown=held.paging_unknown,
            gaps=held.gaps,
            gaps_zero=held.gaps_zero,
            gap_fields=held.gap_fields,
            stored=stored,
            holder=first,
            holder_reading=held,
        )

    output = str(_field(entry, "output") or "")
    structured = _field(entry, "structured")
    document = structured if structured is not None else _parsed(output)
    text = _text_state(entry, output, document)
    if text in (FAILED, NOT_SHOWN, BLANKED_UNREAD, BLANKED_READ):
        return EntryReading(
            entry_id,
            text,
            (text,),
            members_not_kept=0 if text == FAILED else None,
            stored=stored,
        )

    from malspark.agents.output_shortening import our_key_in

    states: list[str] = [text] if text else []
    ours = our_key_in(document)
    members: tuple[MemberReading, ...]
    missing: int | None
    paging_unknown = False
    if text == SHORTENED:
        members, missing = _shortened_members(document, ours)
        paging_unknown = document.get(_TRUNCATED) is True
    elif text == CUT_AS_TEXT:
        if document is None:
            members, missing = _cut_members(output)
        else:
            # Cut, and still a document: what it holds is read as it stands, and
            # members past its end are not known to be all.
            members, missing = _whole_members(document), None
    else:
        members, missing = _whole_members(document), 0
    if output and _structure_dropped(entry):
        states.append(STRUCTURE_DROPPED)
    # Read on an entry cut as text too: what still parses says what it says.
    page, unknown = _pages(entry, document, text == SHORTENED)
    if page or unknown:
        # The rows held are whole; rows of other pages, if any, are not in it.
        missing = None
        if page:
            states.append(ONE_PAGE)
        else:
            paging_unknown = True
    counts = _coverage_counts(entry)
    gaps, gaps_zero = _gaps(document, counts)
    if gaps:
        states.append(WHOLE_WITH_GAPS)
    if shown_chars is not None and output and 0 <= int(shown_chars) < len(output):
        states.append(SHOWN_IN_PART)
    if not states or states == [SHOWN_IN_PART]:
        states.append(WHOLE)
    ordered = tuple(state for state in ENTRY_STATES if state in states)
    return EntryReading(
        entry_id,
        ordered[0],
        ordered,
        members=members,
        members_not_kept=missing,
        paging_unknown=paging_unknown,
        gaps=gaps,
        gaps_zero=gaps_zero,
        gap_fields=counts,
        stored=stored,
    )
