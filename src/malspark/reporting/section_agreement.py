"""One question once the report body is written: does a passage say otherwise than section 5?

The key findings, the summary, the execution flow, the host identifiers, the
background, the ATT&CK table's procedures and the composed sections shown no
function's code (the cipher table, the channel table, the packing prose) are
written from the analysts' claims, at the same time as section 5 is written
from the code and the tool answers; none of them is shown section 5. A claim
that calls a routine's body "not read", a key's use "not established" or a
mutex name "open" is that analyst's view, and a writer shown only the claim
repeats it beside a section 5 that states the thing (T-390). The absence
check (``validation.ledger_absence_contradictions``) decides such a sentence
only where it names an address, an entry or a value; "the sleep constants"
names none.

So, after every section is written, the reporter's model is shown, once:

- the facts the platform states: each decoded text the code passes to an API
  argument (``report.bound_values``), in the words every surface that
  publishes it uses (``call_bindings.binding_words``); each routine a read
  routine calls whose code no entry lists, a fact of its own where a passage
  names it (the rest counted), each routine whose code an entry lists where a
  passage calls code it names not read (``_said_unread``), and each failed
  call for an address with the later call that answered for it
  (``reporting.agreement_facts``), read off the ledger;
- section 5's passages written from the code: each prose subsection and each
  row of the configuration, command and flag tables, with the ids it cites;
- the debate's mediations, in round order, as the mediator wrote them;
- every passage written without the code, under an id naming where it stands;
  the composed conclusion and limitations paragraph among them, which sum up
  what sections 4 to 6 state (T-554); the limitations paragraph, held to the
  failed calls where a sentence of it says a call failed or a reading could not
  be made and the ledger says otherwise (a later call redid the call, or an
  entry lists the code, T-526); and, wherever the paragraph stands, the rows of
  the limitations inventory as facts (``inv.N``): the failed calls and the
  later calls that answered them, the code read, the tools not run, the
  recorded limitations, the sandbox's sections, the capture and the open
  questions (``reporting.limitation_inventory``, T-601), which speak of a
  sentence only where the paragraph is held.

It lists each sentence of a passage written without the code that calls
absent, unknown or open, or states the opposite of, what a section 5 passage,
a fact or a closed debate line states, and each sentence of a section 5
passage a fact contradicts; names the sources; and keeps the sentence or
rewrites it. Nothing here reads a sentence's words to decide: which
sentences, and on which subject, is the model's call (the words that call
code not read only choose which listed routines are shown). A sentence of a
passage written without the code may be rewritten on any source; a sentence of
a section 5 prose passage only on the platform's facts, never on another
model's words (a section 5 sentence was pulled toward an analyst's wrong claim
when it could be), and kept, it is listed, the listing recorded as the model's answer; a
passage marked read only (a row of the configuration, command or flag tables) is
shown for reading, and a sentence of one is listed and kept. Code checks the
answer's structure: the passage is one it was shown, the copied text is one
whole sentence of it standing there once, a section 5 passage is answered by a
fact alone, about an address or a value the sentence or its rewrite names, and
a rewrite keeps every id
its sentence cites, cites at least one id its sources cite (sources citing no
id ground no rewrite) and no id that neither they nor the passage cite;
and it reads each rewrite as the report rounds read their prose (its
citations, a value beside an entry that does not hold it, an entry said to
hold nothing, an absence the ledger contradicts); a rewrite of a limitations
sentence that still says a call failed that a later call redid is not one. The
model is told what is wrong and asked once more. A rewrite that passes takes
its sentence's place, read against the passage as it was written, its new ids
added to the record's own list, and what it replaced is recorded as the model's
answer; a sentence kept, or a rewrite that still fails, stays as written, and
the finding is recorded. A sentence of the conclusion or the limitations a row
lists against sources it may rest on, whose rewrite still fails, is left out
instead, and
recorded with what stood: neither states what section 5 says otherwise of.
A sentence of either that calls open an address or a value a section 5
passage or a fact states, or says the run's own reading left something open,
is held (:func:`held_closing_sentences`): the prompt names it, and an answer
listing no row for it is asked once more; what becomes of it is the model's
answer, never this read's.

A sentence of any passage that may be rewritten, section 5 and the body
included, that calls code not read which an entry lists is held the same way
(:func:`unread_listed_sentences`): haiku11 rewrote the limitations' "the body
of 0x3728 was not read" and left section 5's twin standing, so the two sections
then said opposite things (T-562). Where the statement's own clause names the
routine (not a noun it modifies, not a clause about it), the ledger itself
contradicts the sentence: it is answered in the model's words, even in section
5, and a retry names the listing (``UNREAD_STANDING_CODE``); one the answer
still leaves standing gets the ledger's fact appended ("; the ledger lists the
code of the routine at offset 0x2800 (decompiled or disassembled) [ev_0003]"),
never an inference about the sentence, recorded (``QUALIFIED_CODE``), and is
never left out. A sentence
that reports or refutes another's claim ("They say ... was not read",
"according to", "... is also wrong") is held only: what it calls not read is
that claim's, and the model answers it. A "not read as" or "not read at
runtime" says nothing of a listing and is not read.

A retry that answers only what it was asked keeps the first answer's rows
that passed every check, the retry's row winning for the same sentence.

Two more shapes are held, read by shape alone: a sentence of any writable
passage that calls something absent from the whole code read, naming no
address ("No X read appears in the analysed code", :func:`whole_code_absences`),
which names nothing a fact is about, so one of section 5 may be rewritten in
the model's words on a fact or another section 5 passage, its citations read as
any rewrite's; and every negation of the conclusion and the limitations
(:func:`closing_negations`), which the body may state otherwise of (haiku11's
limitations said no command identifiers were known beside section 6's table).
A held closing sentence the answer keeps is counted, and recorded
(``HELD_KEPT_CODE``) where no fact or section 5 passage backs it. A section 5
sentence answered in the model's words never rests on its own passage.

Three runs in a row held new shapes and slipped new contradictions into the
limitations (T-568), so the platform no longer chooses which closing sentences
are asked: every sentence of the conclusion and the limitations is held, and
each routine a closing passage names is shown with its listing where an entry
lists it. The answer keeps a closing sentence naming the sources it read and
quoting ("quote") the words of one that state the same (two or more of the
sentence's own words, an absence on words stating one), or naming none with its
reason where no fact about a routine it names, and no section 5 passage or fact
holding what it denies something of, is shown; rewrites it; or leaves it out
("drop") with its reason. A keep on a quote that passes is counted; a keep on no
source with its reason, and every drop, is recorded. A kept closing sentence
the ledger itself says otherwise of (a failed call a later call redid), or kept
on no source or a quote a check refused, is left out after the retry, and
recorded (a section 5 keep a check refuses stands, as before); a number of
failed calls the ledger's count does not hold is recorded, never a reason to
leave a sentence out. A rewrite
resting on a fact that states again the
absence the fact contradicts, the same words on the same addresses
(``absence_answers.kept_absence``), or calling unread a routine a closing
passage's listing shows read, is refused. A section 5 sentence denying what a
decoded value's fact states is answered in the model's words, never with the
fact's clause appended beside the denial; only where no rewrite passes is the
clause added, as before, and recorded. A section 5 sentence calling something
not established, naming no address, is a whole-code absence. A sentence of any
section giving failed calls a number is held to the ledger's count
(``calls.1``).

haiku13's section 5 then said the sample was "not shown to use anti-debug or
environment checks" beside the gates section 4 and the ATT&CK table describe,
and its limitations kept the parents of two processes "not established" on no
source while the entry the sentence cites records them (T-580). A whole-code
absence of any section, section 5's and every passage's written without the
code alike, "not shown to", "not confirmed" and "no evidence of" among the
shapes, is held (:func:`body_absences`), and a keep of one is held as a closing
keep is: on the words of a source stating the same (any passage but its own),
or on the reason where no source, another passage of the body included, speaks
of it. It is never left out, unless the ledger's own lines hold it (below): a
keep a check still refuses after the retry stands, and every keep not tied to a
source's words is recorded. A closing
sentence or a held absence citing an entry whose rows record a value it names
is shown those rows as a fact that speaks of it (``entry.N``,
``reporting.entry_fields``), so a keep on no source is asked again with them; a
keep quoting them is recorded.

A held absence of section 5 may be rewritten in the model's words on any source that
speaks of it, a passage written without the code included where it names an address
the sentence's passage names and a fact holds: the passage stating the checks the
absence denies is the one that says otherwise of it, and a claim sharing only words or
a constant with it (another file's, another family's) neither speaks of it nor grounds
anything, so a keep on the reason passes where nothing else speaks. A held absence of a
passage written without the code rests on the sources it did before. A body keep's
quote states the absence: one negated clause of it, its quoted values left out, holds
what the sentence denies something of,
so a keep quoting the passage that states what it denies, or one negating something
else beside it, is refused, and a refusal offers a keep only on the words of a source
that pass that check (T-652).

A sentence the ledger's own lines hold (T-600): one denying something of a name
the run holds (``ledger.N``), one of the limitations naming a failed call a later
call redid, or saying such a call failed. A negated clause writing a word a text is
held under ("not decoded") that names a data address a routine's listing names after
a declared data label, where no decoded row holds a text at it, holds its sentence on
a ``ledger.N`` fact of that routine's data: the routines its lines naming them call,
the texts the function index ties to it, and that no decoded row holds a text there,
said only where a row's address and a listing's are spelled alike (T-652).
Where no answer for such a sentence passes the checks after the retry, refused or
never given, it is left out, of the body as of a closing section, and recorded with
what holds it, unless the platform's own end (its fact qualification, a closing
sentence it leaves out) already changes it; the
question and every refusal of it say so. A drop of it is an answer in the body too.
A rewrite of it follows each clause denying something with a citation of an entry
shown for it (in the limitations, also a failed call no later call redid). An answer
that passes answers it, whatever another row says; one written twice in its passage is
left out each time; a question that got no answer at all leaves each such sentence out
for that one reason.

A record's value cell (a channel's protocol, encryption and packet layout; a scheme's
cipher, mode, library and IV) and each capability bullet of the summary is answered
whole, as a closing section is, held for being that kind of field, never for its words
(T-600): a sentence of one no answer passes is left out, a cell left with no sentence
printing "-" and a bullet left with none not printed; where no row could be read, it
prints as written. Their facts on a name come after the conclusion's and the
limitations'. On every path an answer that passes answers its sentence, and a refused
row for the same sentence is not applied. A quote shorter than
``absence_answers.QUOTE_FLOOR`` is refused as such, and the question states the floor.

Every step is one pass over the passages and the answer's rows.
"""

from __future__ import annotations

import bisect
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import cached_property, lru_cache, partial
from typing import TYPE_CHECKING, Any, Literal

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field, model_validator

from malspark.agents.tool_fence import (
    QUOTED_VALUE_STATEMENT,
    quoted_value,
    template_tokens_written_out,
)
from malspark.core.logger import logger
from malspark.core.spend import SpendCeilingStop
from malspark.pipeline.events import safe_finding_value
from malspark.pipeline.validation import (
    _BARE_ADDRESS,
    _HEX_ADDRESS,
    _MODIFIER_WORDS,
    _ROUTINE_NOUNS,
    _SUFFIXED_ADDRESS,
    EntryTexts,
    ValidationTally,
    Violation,
    _NegationReader,
    _read_dashes,
    citation_violations,
    generic_function_name,
    ledger_absence_contradictions,
    misstated_entry_contents,
    retry_with_feedback,
    schema_violations,
    wrong_entry_citations,
)
from malspark.reporting.absence_answers import (
    PREPOSITIONS,
    QUOTE_FLOOR,
    FailureCounts,
    carries_negation,
    content_words,
    count_disagrees,
    denied_groups,
    denied_heads,
    denied_items,
    denied_subject,
    denies_an_observation,
    denies_reading,
    frame_words,
    kept_absence,
    negated_clauses,
    observes,
    quote_stands,
    quote_too_short,
    reading_denied_in,
    said_of,
    set_in_a_run,
)
from malspark.reporting.models import (
    C2Channel,
    EncryptionScheme,
    FlowStep,
    HostIdentifier,
    KeyFinding,
    LimitationInventory,
    MalwareReport,
    TechnicalSubsection,
)
from malspark.schemas.evidence import entry_ids_in
from malspark.utils.sentence_cut import left_out_span
from malspark.utils.written_forms import pack_escaped, pack_reads

if TYPE_CHECKING:
    from malspark.reporting.agreement_facts import LedgerFacts
    from malspark.reporting.limitation_facts import FailedCall, LimitationFacts

# The producer the round's unresolved findings are recorded under.
AGREEMENT_PRODUCER = "agreement"
# The token ledger's name for the round's calls (``core.spend.TAIL_CALLS``).
AGREEMENT_CALL = "agreement"

# The round's answer, or one row of it, does not fit the object asked for.
SCHEMA_CODE = "agreement.schema"
# A row names a passage the round was not shown as one it may answer for.
UNKNOWN_PASSAGE_CODE = "agreement.unknown_passage"
# A row's sentence does not stand in its passage as copied.
SENTENCE_NOT_FOUND_CODE = "agreement.sentence_not_found"
# A row names a source the round was not shown, or answers a section 5
# passage with a source that is not a platform fact (a held absence of section 5
# rests a rewrite on any source that speaks of it too, a passage written without the
# code where it names an address the sentence's passage names and a fact holds).
UNKNOWN_SOURCE_CODE = "agreement.unknown_source"
# A rewrite cites an id that neither its sources nor its passage cite.
REWRITE_CITES_ELSEWHERE_CODE = "agreement.rewrite_cites_elsewhere"
# A rewrite that leaves out an id the sentence it replaces cites.
REWRITE_DROPS_CITATION_CODE = "agreement.rewrite_drops_citation"
# A rewrite that cites none of the ids its sources cite, or rests only on
# sources that cite none; for a section 5 sentence, one resting only on facts
# about nothing the sentence names (the routine or its caller, the address, the
# value or the call), or, for a routine or bound-value fact on a sentence
# stating that the run's own reading (the ledger, its entries, the listings or
# the function index) does not establish, show, settle, trace or list something
# and naming no address, nothing its passage names, or with no clause of their
# own; for a sentence the ledger's own lines hold, one with a clause denying
# something that no entry shown for that sentence follows at once.
REWRITE_UNGROUNDED_CODE = "agreement.rewrite_ungrounded"
# A sentence the agreement question rewrote: what stood, what replaced it and
# on which sources, recorded as the model's answer.
REWRITTEN_CODE = "agreement.rewritten"
# A sentence of a passage shown for reading only (a section 5 passage, a row
# of the configuration, command or flag tables), listed as saying otherwise than
# its sources and kept as written: the model's answer, recorded where a reader
# finds it.
LISTED_CODE = "agreement.listed"
# A rewrite of a limitations sentence that still says a call failed, or a
# reading could not be made, where a later call redid it.
FAILURE_REDONE_CODE = "agreement.failure_redone"
# A sentence of the conclusion or the limitations paragraph listed as saying
# otherwise than a section 5 passage, a fact or a closed debate line, whose
# rewrite passed no check: left out of the section, which only sums up what
# sections 4 to 6 state, and recorded here with what stood; one the answer
# leaves out with its reason, keeps while the ledger says otherwise (a failed call a
# later call redid), or keeps on no source or a quote the checks refused, the same
# way, with the refused keep's sources, quote or reason. Also a sentence the
# ledger's own lines hold, in the body as in a closing section, and a sentence of a
# record's value cell or a capability bullet of the summary, that no answer passing
# the checks answers after the retry (refused, never answered, or standing twice in
# its passage), or that the round dropped: left out with what holds it, a cell left
# with no sentence printing "-" and a bullet left with none not printed (T-600). Also a
# sentence of a passage printed in its writer's own words (an analyst's statement or claim
# sentence, the judge's note, reason or sentences) that the round dropped, or listed and no
# keep passing the checks answers: left out of the analyst report where it prints and
# counted there, its passage's text and the bundle keeping it whole, and recorded naming the
# passage (T-613).
DROPPED_CODE = "agreement.dropped"
# A held sentence (any sentence of the conclusion or the limitations, of a
# record's value cell or of a capability bullet; one calling open an address or a
# value a section 5 passage or a fact states; one the ledger's own lines hold, in
# the body too) that no row of the answer lists: the model decides each one, and
# is asked once more, told its ends and what becomes of it where none passes.
HELD_UNLISTED_CODE = "agreement.held_unlisted"
# A held sentence whose own clause calls code not read that an entry lists,
# left standing by the answer (no row; in the body a kept row, a refused drop or a
# failed rewrite; in a closing section a refused drop or a rewrite that failed resting
# on no source): the platform adds what the ledger shows to it, in
# the facts' own words, and records what stood. Never left as written; a sentence
# the ledger's own lines hold, and one of a value cell or a capability bullet where
# a row was read, is left out instead, as its question says (T-600). Also a
# section 5 denial a decoded value's fact contradicts whose rewrite in the model's
# words passed no check: the fact's clause is added, and what stood recorded.
QUALIFIED_CODE = "agreement.qualified"
# A sentence of the conclusion or the limitations, of a record's value cell or of a
# capability bullet, or a held absence of the body, that the answer kept on no
# source with its reason, or on a source a check refused (a body absence stands
# then too): it stands, and is recorded where a reader finds it. One kept on a
# source whose quote passed every check is counted, not recorded.
HELD_KEPT_CODE = "agreement.held_kept"
# A held sentence whose own clause calls code not read that an entry lists,
# which the answer left standing or rewrote still calling it not read: the
# retry names the listing, so the model may state it in its own words, and what
# becomes of the sentence where that answer is its last (T-600).
UNREAD_STANDING_CODE = "agreement.unread_standing"
# A rewrite resting on a fact that states again the absence of the sentence the
# fact contradicts, the same words on the same addresses.
ABSENCE_KEPT_CODE = "agreement.absence_kept"
# A kept closing sentence, or a kept held absence of the body, whose row quotes no
# words of a source it names that state the same (two or more of its own words, an
# absence on words stating one, of the body as of a closing section, a body absence's on
# a negated clause holding what it denies something of, so a quote of the passage stating
# what an absence denies backs no keep of it; never one shorter than
# ``absence_answers.QUOTE_FLOOR``, refused as such), or that names no source while a
# shown one speaks of it (the rows of an entry it cites among them). The refusal of a
# body absence names the sources that speak of it, which a rewrite of a section 5 one may
# rest on, and offers a keep on the words of each that state the same absence. Still so
# after the retry, a closing sentence is left out and recorded (``DROPPED_CODE``); a
# body absence stands, recorded (``HELD_KEPT_CODE``).
KEEP_UNQUOTED_CODE = "agreement.keep_unquoted"
# A sentence, or a rewrite, giving failed calls a number the ledger's count
# does not.
FAILURE_COUNT_CODE = "agreement.failure_count"
# What every retry turn of the round asks besides the fix: the whole answer.
_EVERY_ROW = " Answer with every row again, this one included."


# The kinds of passage the round is shown, by who wrote them from what.
CLAIM_LED = "claim-led"
SECTION_5 = "section 5"
FACT = "fact"
DEBATE = "debate"

# The fields of each record that hold the report model's sentences, which a
# rewrite may replace, and the fields that hold a value in a record's cell (a
# cipher's name, a channel's protocol), each answered whole as a closing passage is,
# and printed "-" where no answer passes (T-600). A host identifier's value or a
# channel's endpoint is the indicator itself and is not shown at all.
_PROSE_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    KeyFinding: ("text",),
    FlowStep: ("action",),
    HostIdentifier: ("purpose",),
    EncryptionScheme: ("key_source", "key_management", "partial_threshold"),
}
_VALUE_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    EncryptionScheme: ("cipher", "mode", "library", "iv"),
    C2Channel: ("protocol", "encryption", "packet_layout"),
}


@dataclass
class Passage:
    """One text the round is shown, under its id, with the ids it cites.

    ``write`` puts a rewritten text where the passage stands; a passage with
    none (a fact, a debate round, a table row) is a source only.
    """

    id: str
    label: str
    text: str
    kind: str
    cites: frozenset[str] = frozenset()
    write: Callable[[str], None] | None = None
    # What a fact is about, which a section 5 sentence it grounds a rewrite of
    # must name: the addresses it names, in every spelling, or its value.
    addresses: frozenset[int] = frozenset()
    value: str = ""
    # The call a bound value is passed to, by the API's name.
    call: str = ""
    # The fact's own clause, which the platform adds to a section 5 sentence
    # the model chose to qualify on it (``_qualified``); none for a fact that
    # grounds no rewrite.
    qualifier: str = ""
    # A fact about a routine (one whose code no entry lists, or one an entry
    # lists) or a decoded value bound to a call: it grounds a section 5 sentence
    # stating that the run's own reading does not establish, show, settle, trace
    # or list something wherever the sentence's passage names it (``_grounds``).
    on_absence: bool = False
    # The checks the field a passage stands in holds its text to, run on a
    # rewrite before it is put in (an ATT&CK procedure: one sentence, carrying
    # its technique's values); none for a passage held to the round's alone.
    check: Callable[[str], list[Violation]] | None = None
    # The same, for a check that reads the sources the row names beside the
    # rewrite (the limitations paragraph: a failure a later call redid).
    sourced_check: Callable[[str, Sequence[str], str, str], list[Violation]] | None = None
    # A closing passage (the conclusion, the limitations paragraph): a sentence
    # of it listed against a source whose rewrite passes no check is left out,
    # never kept as written (T-554).
    closing: bool = False
    # The sentences of a closing passage that call open what a section 5
    # passage or a fact states (:func:`held_closing_sentences`): each one is
    # listed in the answer, as the model decides (T-554).
    held: tuple[str, ...] = ()
    # A fact about a routine an entry lists, which contradicts a sentence that
    # calls that routine's code not read (``listed.N``).
    lists_code: bool = False
    # The sentences of a writable passage that call code not read which a
    # ``listed.N`` fact lists, each with those facts' ids and the ids of the
    # ones about the routine its own clause names (:func:`unread_listed_sentences`):
    # each one is held, and one its own clause names that the answer leaves
    # standing is qualified by the platform on those facts (T-562).
    unread_listed: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = ()
    # The sentences of a writable passage that state a branch (a condition and an
    # outcome) or an argument of a routine an entry lists, each with the ids of
    # the ``listing.N`` facts that show that routine's code
    # (:func:`branch_sense_sentences`): each is held, to be checked against the
    # listing and rewritten on it where it says otherwise.
    branch_sense: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # The sentences of a writable passage that call something absent from the
    # whole code read, naming no address (:func:`whole_code_absences`): each
    # is held, and one of section 5 may be rewritten in the model's words on a
    # fact or a section 5 passage, as a passage written without the code is.
    whole_code: tuple[str, ...] = ()
    # The sentences of a writable passage other than a closing one that state an
    # absence the body or the ledger may say otherwise of (:func:`body_absences`):
    # each is held, and a keep of one is held as a closing keep is, naming the
    # source it rests on with its words or the reason no source speaks of it; it is
    # never left out, and a keep not tied to a source's words is recorded (T-580),
    # unless the ledger's own lines hold it (:func:`_held_by_the_ledger`, T-600). A
    # rewrite of one may rest on any source that speaks of it (T-652).
    absences: tuple[str, ...] = ()
    # The held sentences a fact read off the rows of an entry they cite bears on
    # (:func:`_entry_field_passages`): such a fact speaks of each one (T-580).
    speaks_to: tuple[str, ...] = ()
    # Such a fact's rows as shown, and the values the sentences name in them: a keep
    # quoting it quotes inside one row, a value named (T-580).
    row_texts: tuple[str, ...] = ()
    row_values: tuple[str, ...] = ()
    # The sentences of a section 5 passage that deny something a decoded value
    # bound to a call states (a ``bound.N`` fact grounds them): each is held,
    # and answered in the model's words, never with the fact's clause appended
    # beside the denial it contradicts (T-568).
    on_fact: tuple[str, ...] = ()
    # The ledger's count of failed calls, which a sentence or a rewrite giving
    # failed calls a number is held to; ``None`` where the ledger holds none.
    counts: FailureCounts | None = None
    # The names a fact about a name the run holds is about (an API, an export, a
    # decoded text): a sentence writing one is about the fact (``_about``, T-600).
    names: tuple[str, ...] = ()
    # The sentences of a writable passage that deny something and name what a
    # ``ledger.N`` fact shows (:func:`name_readings`), each with those facts' ids: each
    # is held, the model reading it against the fact (T-600).
    ledger_named: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # The limitations sentences held to a failed call a later call redid that they name
    # or cite (:func:`redone_calls_named`), each with what a keep must cite: for each such
    # call, one of the calls that redid it (:func:`_redo_choices`, T-600).
    redone_named: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # The limitations sentences saying a call failed that a later call redid, which the
    # paragraph's failure check refuses as kept (:func:`_failure_redone_calls`), each with
    # the calls that redid those calls, one choice each (:func:`_redo_choices`).
    failure_said: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # The failed calls the limitations paragraph's own facts show that no later call redid
    # (the redo map holds none for them), by entry id: a denial in a rewrite of a sentence of
    # it the ledger's lines hold may rest on one (:func:`_shown_entries`, T-600).
    unredone_failed: frozenset[str] = frozenset()
    # A passage answered whole by being that kind of field, a record's value cell or a
    # capability bullet of the summary (T-600): what its record of a sentence left out
    # says of it, and what an emptied one prints. A sentence of it no answer passing the
    # checks answers is left out, as one the ledger's lines hold is (:func:`_ends_on_answer`).
    whole: str = ""
    emptied: str = ""
    # The sentences of a closing passage that no keep passes for, whatever it names: the
    # ledger itself says otherwise of each (a failed call a later call redid, code an entry
    # lists called not read, a count of failed calls the ledger's does not hold), as the
    # checks of a keep read it (:func:`_ledger_refuses_keep`). Each is offered a rewrite or a
    # drop alone (T-600).
    unkept: tuple[str, ...] = ()
    # A fact that speaks of no sentence: a row of the limitations inventory shown where the
    # paragraph is not held to the failed calls, where dev showed none of its facts. It is
    # shown and may be named, but raises no refusal of a row that does not name it, no item a
    # quote leaves out and no question of its own (T-601).
    silent: bool = False
    # A text the analyst report prints in its writer's own words (an analyst's statement or
    # claim sentence, the judge's note, reason or sentences): who wrote it, in the words of the
    # record of a sentence of it left out; ``""`` for any other passage. Such a passage is
    # shown to be listed and is never rewritten: a sentence of it listed is kept on a quote
    # that passes, or left out of the analyst report, and the bundle prints it whole (T-613).
    verbatim: str = ""
    # Where such a passage's sentence the round leaves out is recorded, the sentence given:
    # never its text, which stays whole for the bundle (T-613).
    leave_out: Callable[[str], None] | None = None
    # The label of the field a value cell fills ("channel encryption", "encryption scheme
    # library"): a sentence of the cell with no subject of its own ("Not established.") is read
    # against it, so a keep quotes a source about that field (T-613); ``""`` for any other.
    field: str = ""


def _ids(*sources: Any) -> frozenset[str]:
    """The entry ids in every text and list given, in the spelling the counter issues."""
    found: set[str] = set()
    for source in sources:
        if isinstance(source, str):
            found |= entry_ids_in(source)
        elif isinstance(source, Iterable):
            for item in source:
                found |= entry_ids_in(str(item or ""))
    return frozenset(found)


def _setter(obj: Any, name: str) -> Callable[[str], None]:
    """Write ``name`` on ``obj``, and add each id the text cites to the object's own list.

    A record that lists its entries (``evidence_ids``, ``evidence_refs``)
    gains the ids a rewrite cites that it did not list, after the ones it did.
    """

    def _write(text: str) -> None:
        setattr(obj, name, text)
        for listing in ("evidence_ids", "evidence_refs"):
            held = getattr(obj, listing, None)
            if isinstance(held, list):
                known = {str(value).strip().lower() for value in held}
                held.extend(found for found in sorted(entry_ids_in(text)) if found not in known)

    return _write


# What the record of a sentence left out of a value cell or a capability bullet says
# holds it, and what an emptied one prints, as the question says (T-600).
_CELL_WHOLE = "a table cell, every sentence of which is answered"
_CELL_EMPTIED = 'a cell left with no sentence prints "-"'
_BULLET_WHOLE = "a capability bullet of the summary, every sentence of which is answered"
_BULLET_EMPTIED = "a bullet left with no sentence is not printed"


def _record_passages(
    prefix: str,
    label: str,
    rows: Sequence[Any],
    kind: str,
    *,
    number: bool = True,
    record: str = "",
) -> list[Passage]:
    """The written fields of each record of a list, one passage each, numbered from 1.

    ``record`` names what one record is ("channel"): a value cell's field label is it and the
    field's name (``Passage.field``)."""
    out: list[Passage] = []
    for index, row in enumerate(rows, 1):
        prose = _PROSE_FIELDS.get(type(row), ())
        fields = (*prose, *_VALUE_FIELDS.get(type(row), ()))
        refs = [
            *(getattr(row, "evidence_refs", None) or []),
            *(getattr(row, "evidence_ids", None) or []),
            getattr(row, "evidence_ref", None) or "",
        ]
        for name in fields:
            text = getattr(row, name, None)
            if not isinstance(text, str) or not text.strip():
                continue
            where = f"{prefix}.{index}" if number else prefix
            single = len(fields) == 1
            said = label + (f" {index}" if number else "")
            cell = name not in prose
            out.append(
                Passage(
                    id=where if single else f"{where}.{name}",
                    label=said if single else f"{said}, {name.replace('_', ' ')}",
                    text=text,
                    kind=kind,
                    cites=_ids(refs, text),
                    write=_setter(row, name),
                    # A value cell is answered whole, as a closing sentence is (T-600).
                    closing=cell,
                    whole=_CELL_WHOLE if cell else "",
                    emptied=_CELL_EMPTIED if cell else "",
                    field=f"{record} {name.replace('_', ' ')}".strip() if cell else "",
                )
            )
    return out


# Who wrote a passage printed in its writer's own words, as the record of a sentence of it
# left out says (``Passage.verbatim``), by the writer the analyst report names (T-613).
_VERBATIM_WRITERS = {
    "analyst": "an analyst's own words, printed as written",
    "judge": "the judge's own words, printed as written",
}


def _verbatim_passages(report: MalwareReport) -> list[Passage]:
    """The texts the analyst report prints in their writer's own words
    (``renderers.analyst.verbatim_texts``), in the order it prints them: one passage for each
    distinct text, naming every place it prints, shown to be listed and never rewritten; a
    sentence of it left out is left out at every one of those places (T-613). None where the
    report is not rendered."""
    from malspark.reporting.renderers.analyst import verbatim_texts

    try:
        shown = verbatim_texts(report)
    except Exception as exc:  # noqa: BLE001 — the round asks of every other passage
        logger.warning("section agreement: the verbatim texts were not read (%s).", exc)
        return []
    places: dict[str, list[Any]] = {}
    for text in shown:
        if text.text.strip():
            places.setdefault(text.text.strip(), []).append(text)
    out: list[Passage] = []
    for said, where in places.items():
        first = where[0]
        ids = list(dict.fromkeys(text.id for text in where))
        out.append(
            Passage(
                id=first.id,
                label="; ".join(dict.fromkeys(text.label for text in where)),
                text=said,
                kind=CLAIM_LED,
                cites=_ids(*(text.cites for text in where), said),
                verbatim=_VERBATIM_WRITERS.get(first.writer, _VERBATIM_WRITERS["analyst"]),
                leave_out=_flagged_out(report, first.id, ids),
            )
        )
    return out


def _flagged_out(report: MalwareReport, pid: str, places: Sequence[str]) -> Callable[[str], None]:
    """Record a sentence of the passage ``pid`` printed in its writer's own words that the round
    left out, as a flagged statement under the round's code naming the passage and left out of
    each of its ``places`` (``models.FlaggedStatement.left_out``): the analyst report leaves it
    out at each, and the bundle prints it whole beside the round's record (T-613)."""
    from malspark.reporting.models import FlaggedStatement

    def _record(sentence: str) -> None:
        rows = getattr(report, "flagged_statements", None)
        if not isinstance(rows, list) or not sentence.strip():
            return
        row = FlaggedStatement(
            sentence=sentence, code=DROPPED_CODE, label=pid, left_out=list(places)
        )
        if row not in rows:
            rows.append(row)

    return _record


def left_out_of(text: str, sentences: Iterable[str]) -> tuple[str, int]:
    """``text`` without each of ``sentences`` that stands in it whole and once
    (:class:`_Sentences`), with the spaces ``left_out_span`` takes, and how many were left out:
    how the analyst report leaves out a sentence of a passage printed in its writer's own
    words that the round left out (T-613)."""
    cut = _Sentences(text)
    spans = sorted(
        {
            left_out_span(text, found[0], found[1])
            for sentence in dict.fromkeys(sentences)
            if (found := cut.span(sentence)) is not None
        },
        reverse=True,
    )
    for start, end in spans:
        text = text[:start] + text[end:]
    return text, len(spans)


def passages_of(
    report: MalwareReport,
    *,
    narrative_written: bool = True,
    discussion: Iterable[Any] = (),
    entries: Iterable[Any] = (),
) -> list[Passage]:
    """Every passage the round is shown, in the order the prompt lists them.

    The facts first, then section 5's passages written from the code, then
    the debate's mediations, then the passages written without the code, the texts
    the analyst report prints in their writer's own words last. The
    key findings and the summary are asked about only when the narrative round
    wrote them (``narrative_written``): the platform's own fallback is not the
    report model's to rewrite. ``entries`` is the run's ledger, in its order,
    which the facts after the bound values are read off.
    """
    from malspark.reporting.call_bindings import binding_words
    from malspark.reporting.composer import COMPOSED_SECTIONS
    from malspark.reporting.evidence_bundles import reads_code

    facts: list[Passage] = []
    for index, bound in enumerate(report.bound_values, 1):
        facts.append(
            Passage(
                id=f"bound.{index}",
                label="decoded text passed to an API argument",
                # The value and the chain both carry the sample's own text (an
                # import's name, a decoder's): each one quoted value.
                text=f"{quoted_value(bound.value)}: {quoted_value(binding_words(bound))}",
                kind=FACT,
                cites=_ids([bound.entry, bound.named_by]),
                addresses=frozenset(
                    address
                    for address in (
                        _hex_address(where)
                        for where in (bound.function, bound.site, bound.decoder_call, bound.call_at)
                    )
                    if address is not None
                ),
                value=str(bound.value or ""),
                call=str(bound.api or ""),
                on_absence=True,
                qualifier=(
                    f'the code passes "{_sample_text(bound.value)}" to '
                    f"{_sample_text(bound.api)} as argument {bound.argument}"
                    + (f" ({_sample_text(bound.parameter)})" if bound.parameter else "")
                ),
            )
        )

    ta = report.technical_analysis
    coded: list[Passage] = []
    uncoded: list[Passage] = []
    for section in COMPOSED_SECTIONS:
        sub = getattr(ta, section, None) if ta is not None else None
        if not isinstance(sub, TechnicalSubsection) or not sub.body.strip():
            continue
        group, kind = (coded, SECTION_5) if reads_code(section) else (uncoded, CLAIM_LED)
        group.append(
            Passage(
                id=section,
                label=f"5. Technical analysis, '{sub.title}'",
                text=sub.body,
                kind=kind,
                cites=_ids(sub.evidence_refs, sub.body),
                # A section 5 sentence is rewritten on a platform fact alone
                # (``_row_violations`` names the sources it may rest on).
                write=_setter(sub, "body"),
            )
        )
    if ta is not None:
        # The table rows read from the code are sources: their cells are values.
        for section, rows, cells in (
            ("configuration", ta.configuration, ("key", "value", "how_obtained")),
            ("commands", ta.commands, ("id", "name", "description")),
            ("cli_flags", ta.cli_flags, ("flag", "description")),
        ):
            if not reads_code(section):
                continue
            for index, row in enumerate(rows, 1):
                said = " | ".join(str(getattr(row, cell, None) or "-") for cell in cells)
                refs = [
                    *(getattr(row, "evidence_refs", None) or []),
                    getattr(row, "evidence_ref", None) or "",
                ]
                coded.append(
                    Passage(
                        id=f"{section}.{index}",
                        label=f"5. Technical analysis, {section.replace('_', ' ')} row {index}",
                        text=said,
                        kind=SECTION_5,
                        cites=_ids(refs, said),
                    )
                )

    debate: list[Passage] = []
    rounds = [
        arg
        for arg in discussion or ()
        if str(_field(arg, "agent_name") or "") == _mediator_name()
        and str(_field(arg, "finding") or "").strip()
    ]
    for index, arg in enumerate(rounds, 1):
        finding = str(_field(arg, "finding") or "")
        debate.append(
            Passage(
                id=f"debate.{index}",
                label=f"debate round {index}, the mediator's words",
                text=finding,
                kind=DEBATE,
                cites=_ids(finding),
            )
        )

    if narrative_written:
        uncoded[:0] = [
            *_record_passages(
                "key_findings", "1. Key findings, bullet", report.key_findings, CLAIM_LED
            ),
            *(
                [
                    Passage(
                        id="executive_summary",
                        label="1. Key findings, the summary paragraph",
                        text=report.executive_summary,
                        kind=CLAIM_LED,
                        cites=_ids(report.executive_summary),
                        write=_setter(report, "executive_summary"),
                    )
                ]
                if report.executive_summary.strip()
                else []
            ),
        ]
    if ta is not None:
        # The summary's capability bullets, each answered whole (T-600): a bullet is a
        # passage of its own, tied to no key finding.
        uncoded.extend(
            Passage(
                id=f"capability_summary.{index}",
                label=f"1. Executive summary, capability bullet {index}",
                text=bullet.text,
                kind=CLAIM_LED,
                cites=_ids(bullet.evidence_refs, bullet.text),
                write=_setter(bullet, "text"),
                closing=True,
                whole=_BULLET_WHOLE,
                emptied=_BULLET_EMPTIED,
            )
            for index, bullet in enumerate(ta.capability_summary, 1)
            if bullet.text.strip()
        )
        steps = sorted(ta.execution_flow, key=lambda step: step.order)
        uncoded.extend(
            _record_passages("execution_flow", "4. Execution flow, step", steps, CLAIM_LED)
        )
        uncoded.extend(
            _record_passages(
                "host_identifiers", "9. Host identifiers, row", ta.host_identifiers, CLAIM_LED
            )
        )
        if ta.encryption_scheme is not None and not reads_code("encryption_scheme"):
            uncoded.extend(
                _record_passages(
                    "encryption_scheme",
                    "5. Technical analysis, encryption scheme",
                    [ta.encryption_scheme],
                    CLAIM_LED,
                    number=False,
                    record="encryption scheme",
                )
            )
    if not reads_code("communications"):
        uncoded.extend(
            _record_passages(
                "communications",
                "5. Technical analysis, channel row",
                report.c2_channels,
                CLAIM_LED,
                record="channel",
            )
        )
    if ta is not None and ta.technique_procedures:
        # The ATT&CK table's procedures are written from the claims, one sentence
        # each, beside section 5 (T-494): asked like every other such passage,
        # and a rewrite held to what the composer holds a procedure to.
        held_to = _procedure_check(report)
        for index, row in enumerate(ta.technique_procedures, 1):
            if not row.procedure.strip():
                continue
            uncoded.append(
                Passage(
                    id=f"procedures.{index}",
                    label=(
                        "ATT&CK table, the procedure for "
                        f"{_sample_text(_one_line(row.technique_id))}"
                    ),
                    text=row.procedure,
                    kind=CLAIM_LED,
                    cites=_ids(row.evidence_refs, row.procedure),
                    write=_setter(row, "procedure"),
                    check=held_to(row.technique_id),
                )
            )
    if report.intro_background.strip():
        uncoded.append(
            Passage(
                id="introduction",
                label="12.3 Background",
                text=report.intro_background,
                kind=CLAIM_LED,
                cites=_ids(report.intro_background),
                write=_setter(report, "intro_background"),
            )
        )
    # The conclusion and the limitations paragraph sum up what sections 4 to 6
    # state, written without them: each is asked like every other such passage
    # (T-554), and the ledger's facts are read for what they name too.
    closing: list[Passage] = []
    if ta is not None:
        closing.extend(_closing_passage(ta.analyst_conclusion, "conclusion", "7. Conclusion"))
        closing.extend(_closing_passage(ta.analyst_limitations, "limitations", "11. Limitations"))
    uncoded.extend(closing)
    held = list(entries or ())
    found = None
    if held:
        from malspark.reporting.agreement_facts import ledger_facts

        found = ledger_facts(held)
    shown = [*facts, *coded, *debate, *uncoded]
    # Every routine a closing passage names is shown with its listing where an
    # entry lists it: each closing sentence is answered (T-568), and "0x6328,
    # 0x3074 and 0x8560 were not read" or "read only in part" names its routine
    # in no shape the unread reading knows.
    facts.extend(_ledger_passages(held, shown, found, also=_named_addresses(closing)))
    # The limitations inventory's rows are shown wherever the limitations
    # paragraph stands (``inv.N``, T-601), after the ledger's own facts, which
    # they leave as they were. The paragraph is held to the failed calls only
    # where a sentence of it says a call failed that the ledger says otherwise
    # of (T-526); it then stands where the paragraph alone stood.
    limitations, limitation_facts, limited = _limitation_passages(report, held, found, facts)
    if limitations:
        # A false failure is wrong in any section: while the paragraph is held
        # to the failed calls, a rewrite of any other passage adds none. A
        # section 5 rewrite is the platform's own (``_qualified``), whose fact
        # clauses write kind words ("decompiled or disassembled"): it is read
        # by its citations alone.
        for passage in (*coded, *uncoded):
            if passage.id == "limitations":
                continue
            if _writable(passage) and passage.sourced_check is None:
                passage.sourced_check = (
                    _failure_cited_check(limited, passage)
                    if passage.kind == SECTION_5
                    else _failure_added_check(limited, passage)
                )
        uncoded[:] = [p for p in uncoded if p.id != "limitations"]
        uncoded.extend(limitations)
    else:
        # Not held, the rows are shown where dev showed none of the paragraph's facts:
        # they speak of no sentence, so every hold, end and refusal is dev's (T-601).
        for fact in limitation_facts:
            fact.silent = True
    facts.extend(limitation_facts)
    failed = _failed_calls(held, found)
    counts = _failure_counts(failed)
    writable = [p for p in (*coded, *uncoded) if _writable(p)]
    if counts is not None:
        # A sentence giving failed calls a number is held to the ledger's count
        # in every section; the count is shown where one disagrees, or where the
        # limitations are held to the failed calls (T-568).
        miscounted = any(
            count_disagrees(sentence, counts)
            for passage in writable
            for sentence in _sentences_of(passage.text)
        )
        if miscounted or limitations:
            facts.append(_count_fact(counts, failed))
        for passage in writable:
            passage.counts = counts
    sources = [*facts, *coded]
    listed = [fact for fact in facts if fact.lists_code]
    valued = [fact for fact in facts if fact.value]
    for passage in (*coded, *uncoded):
        holding = held_closing_sentences(passage.text, sources) if passage.closing else ()
        if listed and _writable(passage):
            # A sentence calling code not read that an entry lists, in any
            # section, the body as well as the closing ones (T-562).
            passage.unread_listed = unread_listed_sentences(passage.text, listed)
            holding = (*holding, *(sentence for sentence, _ids, _own in passage.unread_listed))
        if _writable(passage):
            # A sentence calling something absent from the whole code read, and
            # a negation of the conclusion or the limitations, which the body
            # may state otherwise: each one is the model's to answer (T-562).
            # Section 5's and every other passage's alike: an absence the body or the
            # ledger may say otherwise of is the model's to answer in any section,
            # haiku13's "is therefore not shown to use anti-debug or environment checks"
            # beside the gates section 4 and the ATT&CK table describe (T-580).
            # A section 5 sentence naming an address is held where the clause stating
            # its absence names none (``by_clause``); one held as calling listed code
            # unread keeps that question, as before.
            listed_unread = {sentence for sentence, _ids, _own in passage.unread_listed}
            passage.whole_code = tuple(
                sentence
                for sentence in whole_code_absences(
                    passage.text,
                    unsettled=not passage.closing,
                    by_clause=passage.kind == SECTION_5,
                )
                if sentence not in listed_unread or not _addresses_named(sentence)
            )
            holding = (*holding, *passage.whole_code)
            if passage.closing:
                holding = (*holding, *closing_negations(passage.text))
            else:
                passage.absences = body_absences(passage)
                holding = (*holding, *passage.absences)
            if passage.kind == SECTION_5 and valued:
                passage.on_fact = _denied_by_a_fact(passage.text, valued)
                holding = (*holding, *passage.on_fact)
            if passage.counts is not None:
                holding = (
                    *holding,
                    *(s for s in _sentences_of(passage.text) if count_disagrees(s, passage.counts)),
                )
        if passage.closing and _writable(passage):
            # Every sentence of the conclusion and the limitations is answered:
            # the closing sections are short, and three runs in a row slipped a
            # contradiction past every shape that chose which ones (T-568).
            holding = (*_sentences_of(passage.text), *holding)
        passage.held = tuple(dict.fromkeys(holding))
    if found is not None and found.listed:
        # A sentence stating a branch or an argument of a routine an entry lists is
        # held to that routine's listing, shown in part (D4, D5 of T-580): the model
        # reads the condition and the argument against the code; nothing is decided
        # here. Only the routines held this way are shown.
        facts.extend(
            _branch_sense_passages(
                [*coded, *uncoded], found, {str(_field(e, "id") or ""): e for e in held}
            )
        )
    if held and found is not None:
        # A negated sentence naming an API, an export or a text the run holds is
        # held to what the ledger holds of it, the call lines of the routines calling an
        # API shown with their slots named, so no keep rests on no source (T-600).
        from malspark.reporting.ledger_entities import run_names

        names = run_names(held, found.image_bases)
        by_entry = {str(_field(e, "id") or ""): e for e in held}
        if names.apis or names.exports or names.texts or found.listed:
            name_facts, _readings = _name_passages(
                [*coded, *uncoded],
                names,
                found,
                by_entry,
                generic_words({p.id: p for p in coded}),
            )
            facts.extend(name_facts)
    if held:
        # A held sentence citing an entry whose rows record a value it names: the
        # rows are shown, and speak of it, so "no source states it" is read against
        # them (haiku13's parent of processes 83 and 88 beside ev_0012's ppids, T-580).
        facts.extend(
            _entry_field_passages(
                [p for p in (*coded, *uncoded) if _writable(p)],
                {str(_field(e, "id") or "").lower(): e for e in held},
            )
        )
    # The texts the analyst report prints in their writer's own words, last: listed only where
    # a source says otherwise, so no fact is read off them (T-613).
    every = [*facts, *coded, *debate, *uncoded, *_verbatim_passages(report)]
    by_id = {passage.id: passage for passage in every}
    for passage in (*coded, *uncoded):
        if _writable(passage):
            # Every sentence of a closing passage; in the body, those the ledger's lines hold,
            # the only ones a refusal there tells the ends of.
            passage.unkept = tuple(
                sentence
                for sentence in (
                    _sentences_of(passage.text)
                    if passage.closing
                    else [s for s, _ids in passage.ledger_named]
                )
                if _ledger_refuses_keep(passage, sentence, by_id)
            )
    return every


# What a fact read off an entry's rows shows at most: rows, fields of a row, and
# characters of a value; what is left out is counted in its text.
_ENTRY_ROWS = 4
_ENTRY_FIELDS = 8
_ENTRY_VALUE_CHARS = 80


def _entry_field_passages(passages: Sequence[Passage], entries: dict[str, Any]) -> list[Passage]:
    """One fact per entry a held sentence cites whose rows record a value the sentence
    names in a clause that denies something (:func:`entry_fields.cited_rows`): the
    rows' fields as the entry holds them, each value one quoted value, the sentences it
    bears on in :attr:`Passage.speaks_to`. Read for every closing sentence and every
    held absence of the body, each entry's answer read once; the same rows of one entry
    are one fact, naming every value the sentences name in its header."""
    from malspark.reporting.entry_fields import cited_rows

    answers: dict[str, Any] = {}
    found_by: dict[tuple[str, tuple[int, ...]], Any] = {}
    values_by: dict[tuple[str, tuple[int, ...]], dict[str, None]] = {}
    said_by: dict[tuple[str, tuple[int, ...]], dict[str, None]] = {}
    for passage in passages:
        asked = passage.held if passage.closing else passage.absences
        for sentence in asked:
            cited = sorted(entry_ids_in(sentence))
            for found in cited_rows(sentence, entries, cited, answers) if cited else ():
                key = (found.entry.lower(), tuple(at for at, _row in found.rows))
                found_by.setdefault(key, found)
                values_by.setdefault(key, {}).update(dict.fromkeys(found.values))
                said_by.setdefault(key, {})[sentence] = None
    out: list[Passage] = []
    for key, found in found_by.items():
        values = tuple(values_by[key])
        rows = tuple(_row_text(row) for _at, row in found.rows[:_ENTRY_ROWS])
        out.append(
            Passage(
                id=f"entry.{len(out) + 1}",
                label="rows of an entry a sentence cites, for a value it names",
                text=_rows_text(found, values, rows),
                kind=FACT,
                cites=_ids([found.entry]),
                speaks_to=tuple(said_by[key]),
                row_texts=rows,
                row_values=values,
            )
        )
    return out


def _entry_value(value: Any) -> str:
    """One field's value of an entry's row, as one quoted value."""
    return quoted_value(_capped(str(value), _ENTRY_VALUE_CHARS))


def _row_text(row: dict[str, Any]) -> str:
    """One row of an entry, field by field, in brackets."""
    scalar = [(k, v) for k, v in row.items() if not isinstance(v, (dict, list))]
    fields = "; ".join(
        f"{_sample_text(_one_line(key))} {_entry_value(value)}"
        for key, value in scalar[:_ENTRY_FIELDS]
    )
    more = len(row) - min(len(scalar), _ENTRY_FIELDS)
    return f"({fields}" + (f"; and {more} more fields" if more > 0 else "") + ")"


def _rows_text(found: Any, values: Sequence[str], rows: Sequence[str]) -> str:
    """The rows of an entry naming a sentence's values: a header naming the values, then
    each row shown, the rest counted, and where the entry's answer was read only in part."""
    left = len(found.rows) - len(rows)
    named = ", ".join(quoted_value(_capped(v, _ENTRY_VALUE_CHARS)) for v in values)
    return (
        f"{found.entry} ({quoted_value(found.tool)}) records "
        f"{len(found.rows)} {'row' if len(found.rows) == 1 else 'rows'} holding {named}: "
        + " ".join(rows)
        + (f"; and {left} more {'row' if left == 1 else 'rows'}" if left > 0 else "")
        + ("; the rest of the entry's answer was not read" if found.cut else "")
    )


def _failed_calls(entries: Sequence[Any], found: LedgerFacts | None) -> list[FailedCall]:
    """The calls that ran and failed (``limitation_facts.failed_calls``: the calls the run
    summary counts), with the later calls that redid them."""
    if not entries or found is None:
        return []
    from malspark.reporting.limitation_facts import failed_calls

    return failed_calls(entries, found.answered, found.image_bases, found.redone)


def _failure_counts(failed: Sequence[FailedCall]) -> FailureCounts | None:
    """The ledger's count of failed calls, by every kind stem and tool name too; ``None``
    for none."""
    if not failed:
        return None
    by_name: dict[str, tuple[int, int]] = {}
    for call in failed:
        for name in {*_stems_of(call), call.tool.lower()}:
            f, r = by_name.get(name, (0, 0))
            by_name[name] = (f + 1, r + (1 if call.redone else 0))
    return FailureCounts(
        failed=len(failed),
        redone=sum(1 for call in failed if call.redone),
        by_name=by_name,
    )


def _count_fact(counts: FailureCounts, failed: Sequence[FailedCall]) -> Passage:
    """The ledger's count of failed calls as a fact, citing each failed call and the calls
    that redid them."""
    left = counts.failed - counts.redone
    ids = [i for call in failed for i in (call.entry, *call.redone_by)]
    return Passage(
        id="calls.1",
        label="tool calls that failed, counted from the ledger",
        text=(
            f"{counts.failed} tool {'call' if counts.failed == 1 else 'calls'} failed; "
            f"{counts.redone} of them redone by a later call asking the same question; "
            f"{left} not redone"
        ),
        kind=FACT,
        cites=_ids(ids),
    )


def _denied_by_a_fact(text: str, bound: Sequence[Passage]) -> tuple[str, ...]:
    """The sentences of a section 5 passage a bound value's fact grounds (:func:`_grounds`:
    it names the value, the call or where it is passed, or calls something the run's
    reading does not establish beside a passage naming it) and one of whose clauses
    denies what that fact states (:func:`_contradicted_absences`)."""
    out: list[str] = []
    for sentence in _sentences_of(text):
        if not carries_negation(sentence):
            continue
        reading = _Reading(sentence, text)
        if any(
            _grounds(fact, reading) and _contradicted_absences(text, sentence, [fact])
            for fact in bound
        ):
            out.append(sentence)
    return tuple(out)


def _procedure_check(report: MalwareReport) -> Callable[[str], Callable[[str], list[Violation]]]:
    """For a technique, the check a rewrite of its procedure passes: one sentence, for a
    technique the report publishes, carrying its claims' values
    (``composer_pro.procedure_violations``, ``procedure_value_violations``). The
    technique's claims are read once for every procedure."""
    from malspark.reporting.composer_pro import (
        ValueReader,
        first_claim_sentences,
        procedure_value_violations,
        procedure_violations,
        published_techniques,
    )

    published = list(published_techniques(report))
    firsts = first_claim_sentences(report)
    reader = ValueReader.of(report)

    def _for(tid: str) -> Callable[[str], list[Violation]]:
        def _check(text: str) -> list[Violation]:
            payload = {"procedures": [{"technique_id": tid, "procedure": text}]}
            return [
                *procedure_violations(payload, published),
                *procedure_value_violations(payload, firsts, reader),
            ]

        return _check

    return _for


# A closing sentence calling something open: not determined, named, recovered,
# resolved, visible or established; unexplained; unresolved (T-554). What it
# is about is read from what it names, never from these words alone.
_CALLS_OPEN = re.compile(
    r"\b(?:not|never)\s+(?:been\s+|be\s+)?"
    r"(?:determined|named|recovered|resolved|visible|established)\b"
    r"|\bunexplained\b|\bunresolved\b",
    re.IGNORECASE,
)
# The run's own reading named by a closing sentence: what a held sentence naming
# no address must name ("the claims were not visible in this review").
_OWN_READING = re.compile(r"\b(?:claims?|review|reading|listings?|decompil\w*)\b", re.I)
# A value a sentence quotes: the text between a pair of straight or curly
# quotes, at least this long, so a quoted letter or digit names nothing.
_QUOTED = re.compile(r"[\"'\u2018\u201c]([^\"'\u2019\u201d\n]{3,200})[\"'\u2019\u201d]")


def held_closing_sentences(text: str, sources: Sequence[Passage]) -> tuple[str, ...]:
    """The sentences of a closing passage that call open what a source states, in order.

    A sentence is held where it calls something open (:data:`_CALLS_OPEN`) and
    names an address, or quotes a value, that a section 5 passage or a bound
    value's fact states: the address among those the passage names, the value
    in its text or the fact's own value; or, naming no address, where it says
    the run's own reading left that open (:func:`_unsettled_by_reading`: "the
    claims were not visible in this review"), beside a section 5 written from
    that reading. Holding only obliges the answer to
    list the sentence; whether a source says otherwise, and what becomes of
    the sentence, is the model's answer and the checks', never this read's.
    One pass over the sentences; the sources are read once.
    """
    named: set[int] = set()
    texts: list[str] = []
    values: set[str] = set()
    for source in sources:
        if source.kind == SECTION_5:
            named.update(_addresses_named(source.text))
            texts.append(source.text)
        elif source.kind == FACT and source.value:
            named.update(source.addresses)
            values.add(source.value)
    if not named and not texts and not values:
        return ()
    joined = "\n".join(texts)
    out: list[str] = []
    for sentence in _sentences_of(text):
        if not _CALLS_OPEN.search(sentence):
            continue
        addresses = set(_addresses_named(sentence))
        if (
            addresses & named
            or any(
                quoted in values or quoted in joined
                for quoted in (m.group(1).strip() for m in _QUOTED.finditer(sentence))
                if quoted
            )
            # Naming nothing, it says the run's own reading (a claim, the review,
            # a listing) left something open, which section 5, written from that
            # reading, may state.
            or (
                texts
                and not addresses
                and _OWN_READING.search(sentence)
                and _unsettled_by_reading(sentence)
            )
        ):
            out.append(sentence)
    return tuple(dict.fromkeys(out))


def _closing_passage(sub: TechnicalSubsection | None, pid: str, label: str) -> list[Passage]:
    """A closing section the composer wrote (the conclusion, the limitations), or none."""
    if not isinstance(sub, TechnicalSubsection) or not sub.body.strip():
        return []
    return [
        Passage(
            id=pid,
            label=label,
            text=sub.body,
            kind=CLAIM_LED,
            cites=_ids(sub.evidence_refs, sub.body),
            write=_setter(sub, "body"),
            closing=True,
        )
    ]


def _one_line(text: Any, limit: int = 40) -> str:
    """A short field as one line: whitespace collapsed, cut at ``limit`` characters."""
    return " ".join(str(text or "").split())[:limit]


def _sample_text(text: Any) -> str:
    """Text the sample may control, as the composer writes it in prose: escaped, every
    ledger id and every chat-template token written out, so it can neither cite an
    entry nor speak as the template."""
    return template_tokens_written_out(pack_escaped(str(text or ""), ids=True, delimiters=True))


def _hex_address(where: str) -> int | None:
    """An address a bound value's record writes (``0x…``), or ``None``."""
    found = re.fullmatch(r"\s*0x([0-9a-fA-F]{1,16})\s*", str(where or ""))
    return int(found.group(1), 16) if found else None


# Where a word ends, for reading an address a text names: a space, a bracket, a
# quote, a list or clause mark, an operator, an arrow. A path, a file name, a URL
# or a registry key is one word, and a longer identifier is one word.
_WORD_BREAK = re.compile(
    r"(?:->|<-|=>|[\s()\[\]{}<>\"'`,;:!?=*+&@|~#%"
    r"\u2014\u2018\u2019\u201c\u201d\u2190-\u21ff])+"
)
# What joins addresses into one word: a range or a pair (``0x10-0x40``,
# ``0x10..0x40``, ``0x7504/0xd1c8``). Every part of such a word is an address,
# or none is.
_ADDRESS_JOIN = re.compile(r"\.\.|[/\\\-\u2013]")


# A decompiler's name for a function written with ``0x`` before its address
# (``fcn.0x33ac``): the word before the address is read as a declared one.
_NAMED_HEX = re.compile(r"([A-Za-z]\w*?)([_.])0x([0-9a-f]{1,16})", re.IGNORECASE)


def _whole_address(part: str, function: re.Pattern[str]) -> int | None:
    """The address ``part`` is, written whole in a spelling the absence check reads, or
    ``None``. ``function`` is the declared decompiler names' pattern."""
    for pattern in (_HEX_ADDRESS, function, _SUFFIXED_ADDRESS, _BARE_ADDRESS):
        found = pattern.fullmatch(part)
        if found:
            return int(found.group(1), 16)
    named = _NAMED_HEX.fullmatch(part)
    if named and function.fullmatch(f"{named.group(1)}{named.group(2)}0"):
        return int(named.group(3), 16)
    return None


def _addresses_named(text: str) -> list[int]:
    """Every address ``text`` names as an address: a word that is one (``0x6f48``,
    ``FUN_00406f48``, ``6f48h``, bare hex), or a range or pair of them.

    A hex run inside a path, a file name, a URL, a registry key or a longer
    identifier (``files/0x00020000000003ba-104.dat``) names no address: it is
    part of a word that is not one. A slash with nothing on its other side
    (``0x401000/``, ``/0x5a10``) joins no path segment. One pass over the text.
    """
    function = generic_function_name()
    out: list[int] = []
    for word in _WORD_BREAK.split(text):
        word = word.rstrip(".\u2026").strip("/")
        if not word:
            continue
        found = [_whole_address(part, function) for part in _ADDRESS_JOIN.split(word)]
        if all(value is not None for value in found):
            out.extend(value for value in found if value is not None)
    return out


def _named_addresses(passages: Iterable[Passage]) -> set[int]:
    """Every address the passages name, in a spelling the absence check reads (``0x…``,
    a decompiler's name, ``…h``, bare hex), as a word of its own (:func:`_addresses_named`).
    One pass over each text."""
    named: set[int] = set()
    for passage in passages:
        named.update(_addresses_named(passage.text))
    return named


def _spelled_both(addresses: Iterable[int], bases: Sequence[int]) -> frozenset[int]:
    """Each address and its offset, where the one image base read makes one."""
    out: set[int] = set()
    for address in addresses:
        out.add(address)
        if len(bases) == 1 and address >= bases[0]:
            out.add(address - bases[0])
    return frozenset(out)


def _offsets(addresses: Sequence[int], bases: Sequence[int]) -> str:
    """Addresses by their offsets where the one base read makes them offsets, else as written."""
    if len(bases) == 1 and all(a >= bases[0] for a in addresses):
        word = "offset " if len(addresses) == 1 else "offsets "
        return word + ", ".join(hex(a - bases[0]) for a in addresses)
    return ", ".join(hex(a) for a in addresses)


# What a fact about a routine whose code no entry lists says, in the facts' words.
_NOT_LISTED = "no entry lists its code (decompiled or disassembled)"


# Words that call code not read, not listed or not in the evidence: what makes a
# listed routine a passage names a fact worth showing (``_said_unread``). Which
# sentence the listing contradicts is still the model's call.
_UNREAD_VERB = r"(?:read|decompiled|disassembled|listed|examined|opened|obtained)"
_SAID_UNREAD = re.compile(
    r"\b(?:is|are|was|were|be|been|being|has|have|had|remains?|remained)\s+(?:still\s+)?"
    rf"(?:not|never)\s+(?:yet\s+)?(?:been\s+)?{_UNREAD_VERB}\b"
    rf"|\b(?:code|body|bodies|listing|listings)\s+(?:not|never)\s+{_UNREAD_VERB}\b"
    r"|\b(?:is|are|was|were)\s+not\s+(?:in|part\s+of)\s+(?:this|the|my)\s+"
    r"(?:evidence|ledger|rows)\b"
    r"|\bunread\b",
    re.IGNORECASE,
)
# Where a clause ends inside a sentence: the code an absence is about stands in
# its own clause, or right before it ("0x7504 is called. Its body was not read.").
_CLAUSE_BREAK = re.compile(r"[;:,()\u2014\u2013]|\s(?:but|while|whereas|although|so)\s")


# The clause the platform adds to a section 5 sentence on an unread callee
# (``unread_callee_clause``): its callers are read routines, named by the fact.
_UNREAD_CLAUSE = re.compile(
    r"the routine at [^;]*?, called by the read routines? at [^;]*?, has no listed code "
    r"\(decompiled or disassembled\)",
    re.IGNORECASE,
)


def _addresses_before(text: str) -> set[int]:
    """The last address ``text`` names, read word by word from its end."""
    for word in reversed(text.split()):
        found = _addresses_named(word)
        if found:
            return set(found)
    return set()


def _said_unread(passages: Iterable[Passage]) -> set[int]:
    """Every address a passage says the code of is not read or not in the evidence.

    The passive statement only ("was not read", "is not in this evidence", never
    "does not read the key"), and only the addresses in its own clause, else the
    nearest one before it in the sentence, else the last one of the sentence
    before ("0x7504 is called. Its body was not read."). The platform's own
    clause on an unread callee names none. One pass over each text.
    """
    out: set[int] = set()
    for passage in passages:
        starts, _ends = _sentence_units(_UNREAD_CLAUSE.sub("", passage.text))
        ordered = [s for _at, s in sorted((at, s) for s, ats in starts.items() for at in ats)]
        for index, sentence in enumerate(ordered):
            found, _own = _unread_addresses(sentence, ordered[index - 1] if index else "")
            out.update(found)
    return out


# Words that make the address after them a modifier of a statement's subject
# ("the link from 0x4d20 to 0x5030", "the caller of 0x1400"), but for a routine's
# code ("the body of 0x3728") and a routine at an address ("the routine at 0x3728").
_MODIFYING = frozenset({*_MODIFIER_WORDS, "to", "into", "between"})
_CODE_NOUNS = frozenset(
    {
        "body",
        "bodies",
        "code",
        "listing",
        "listings",
        "decompile",
        "decompiles",
        "decompilation",
        "disassembly",
        "pseudocode",
    }
)


# The words that open a relative clause whose subject the clause before names.
_RELATIVE_OPENERS = frozenset({"which", "that"})
# A kind noun before an address ("routine 0x3728"): after "of" or "for" it is
# itself a modifier ("the callee 0x5000 of routine 0x3728").
_KIND_NOUN_WORDS = frozenset({*_ROUTINE_NOUNS, "callee", "callees", "caller", "callers"})


# What makes a "not read" say nothing of whether the code was listed: read as
# something ("is not read as a debug check") or not watched running ("was not
# read at runtime").
_NOT_A_LISTING = re.compile(
    r"\s+(?:as\b|(?:at|during)\s+(?:run-?\s?time|execution)\b)", re.IGNORECASE
)
# How far after a statement that reading is looked for.
_NOT_A_LISTING_REACH = 40


class _Words:
    """A sentence's words, their places, lowered forms and addresses, and its clause
    breaks, read once, so every statement in it is read by bisection."""

    def __init__(self, text: str) -> None:
        self.text = text
        spans = [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]
        self.starts = [a for a, _b in spans]
        self.ends = [b for _a, b in spans]
        self.lower = [text[a:b].strip(",;:()[]\"'`").lower() for a, b in spans]
        found = [frozenset(_addresses_named(text[a:b])) for a, b in spans]
        self.addressed = [i for i, named in enumerate(found) if named]
        self.addressed_ends = [self.ends[i] for i in self.addressed]
        self.found = found
        breaks = list(_CLAUSE_BREAK.finditer(text))
        self.break_starts = [m.start() for m in breaks]
        self.break_ends = [m.end() for m in breaks]
        self._clauses: dict[tuple[int, int], set[int]] = {}

    def clause_at(self, at: int) -> tuple[int, int]:
        """The index of the last break ending at or before ``at`` (-1 for none), and
        where the clause ``at`` stands in begins."""
        b = bisect.bisect_right(self.break_ends, at) - 1
        return b, self.break_ends[b] if b >= 0 else 0

    def clause_end(self, at: int) -> int | None:
        """Where the clause that ``at`` ends a statement of ends: the next break's start."""
        b = bisect.bisect_left(self.break_starts, at)
        return self.break_starts[b] if b < len(self.break_starts) else None

    def last_address(self, begin: int, end: int) -> int | None:
        """The index of the last word naming an address that ends by ``end`` and starts
        at or after ``begin``, or ``None``."""
        k = bisect.bisect_right(self.addressed_ends, end) - 1
        if k >= 0 and self.starts[self.addressed[k]] >= begin:
            return self.addressed[k]
        return None

    def addresses_between(self, begin: int, end: int | None) -> set[int]:
        """Every address the words from ``begin`` to ``end`` name, read once per span."""
        key = (begin, -1 if end is None else end)
        if key not in self._clauses:
            low = bisect.bisect_left(self.addressed_ends, begin + 1)
            out: set[int] = set()
            for k in range(low, len(self.addressed)):
                i = self.addressed[k]
                if end is not None and self.starts[i] >= end:
                    break
                out |= self.found[i]
            self._clauses[key] = out
        return self._clauses[key]

    def first_word(self, at: int) -> int:
        """The index of the first word starting at or after ``at``."""
        return bisect.bisect_left(self.starts, at)


# How many words may stand between a routine's address and the noun that ends
# its subject ("the 0x3728 task routine", "0x3728's body").
_TRAILING_WORDS = 3
# Determiners before an address, read past; words that call it an address; the
# nouns that name another routine than the one the address is.
_SUBJECT_DETERMINERS = frozenset({"the", "a", "an", "this", "its", "that's"})
_ADDRESS_WORDS = frozenset({"offset", "address", "va", "rva"})
_RELATED_NOUNS = frozenset({"callee", "callees", "caller", "callers"})
# The words that may end a subject after its address: a routine or its code, or
# the routine itself.
_SUBJECT_ENDS = frozenset({*_ROUTINE_NOUNS, *_CODE_NOUNS, "itself"})
# The marks that open and close an appositive after an address, and which closes
# which: "0x3728 (the registration routine)", "0x3728, the routine,", "0x3728 — it —".
_APPOSITIVES = {"(": ")", ",": ",", "\u2014": "\u2014", "\u2013": "\u2013"}


def _subject_address(words: _Words, begin: int, end: int, stop: int | None = None) -> set[int]:
    """The address a statement's clause, from ``begin`` to the statement at ``end``, writes
    last, where it heads the subject.

    The words after it may be a relative clause of its own ("0x3728 that
    performs the registration") or a few that end on a routine or its code ("the
    0x3728 task routine", "0x3728's body", "function 0x3728 itself"); any others
    make it a word inside another subject ("the registry value 0x2800 sets").
    Not one a relative word puts in another clause ("the buffer that 0x2800
    fills"), nor one a modifier word puts after another noun ("the link from
    0x4d20 to 0x5030"), unless the noun is a routine's code ("the body of 0x3728",
    "the code at 0x3728") or a routine at the address ("the routine at 0x3728");
    a kind noun before it ("routine 0x3728") is a modifier only after "of" or
    "for" that an address or a callee or caller noun stands before ("the callee
    0x5000 of routine 0x3728"). Read by bisection over the sentence's words; the
    words after the address are read up to ``stop`` where an aside follows it.
    """
    at = words.last_address(begin, end)
    if at is None:
        return set()
    first = words.first_word(begin)
    after = words.first_word(end if stop is None else stop)
    trailing = words.lower[at + 1 : after]
    if trailing and trailing[0] not in _RELATIVE_OPENERS:
        if len(trailing) > _TRAILING_WORDS or trailing[-1] not in _SUBJECT_ENDS:
            return set()
        # A callee or caller after it is another routine ("the 0x2800 routine's
        # callee body"), and a possessive owns a routine's code only.
        if any(_bare(word) in _RELATED_NOUNS for word in trailing):
            return set()
    if not _possessives_own_code([words.lower[at], *trailing]):
        return set()
    # Determiners say nothing of what the address is: read past them ("decrypted
    # by the 0x2800 routine" is a modifier, "the 0x2800 routine" a subject).
    lead = at - 1
    while lead >= first and words.lower[lead] in _SUBJECT_DETERMINERS:
        lead -= 1
    # An address read as such ("at offset 0x2800") is still the address.
    if lead >= first and words.lower[lead] in _ADDRESS_WORDS:
        lead -= 1
        while lead >= first and words.lower[lead] in _SUBJECT_DETERMINERS:
            lead -= 1
    before = words.lower[lead] if lead >= first else ""
    head = words.lower[lead - 1] if lead - 1 >= first else ""
    at_lead = lead
    if before in _RELATIVE_OPENERS:
        return set()
    if before in _MODIFYING and not (
        (before in ("of", "for") and head in _CODE_NOUNS)
        or (before == "at" and head in (_ROUTINE_NOUNS | _CODE_NOUNS))
    ):
        return set()
    if before in _KIND_NOUN_WORDS and head in ("of", "for"):
        owner = words.lower[at_lead - 2] if at_lead - 2 >= first else ""
        if owner in _RELATED_NOUNS or (at_lead - 2 >= first and words.found[at_lead - 2]):
            return set()
    # Any other noun before it makes the address its modifier ("the string table
    # 0x2800"): only a routine or its code is the subject.
    if before and before not in (_MODIFYING | _ROUTINE_NOUNS | _CODE_NOUNS):
        return set()
    return set(words.found[at])


def _bare(word: str) -> str:
    """A word without a possessive ending."""
    for ending in ("'s", "\u2019s"):
        if word.endswith(ending):
            return word[: -len(ending)]
    return word


def _possessives_own_code(run: Sequence[str]) -> bool:
    """Whether every possessive in ``run`` is followed by a routine's code ("0x3728's
    body"), never by another noun ("0x3728's callee's body")."""
    for index, word in enumerate(run):
        if _bare(word) != word:
            following = run[index + 1] if index + 1 < len(run) else ""
            if following not in _CODE_NOUNS:
                return False
    return True


def _appositive_subject(words: _Words, b: int) -> tuple[int, int] | None:
    """Where the subject before an appositive the break ``b`` closes stands, or ``None``.

    "Routine 0x3728 (the registration routine) was not read": the statement's
    own clause holds no word, and the pair of marks before it opens and closes
    an aside on the subject before them.
    """
    if b < 1:
        return None
    opened = words.text[words.break_starts[b - 1] : words.break_ends[b - 1]].strip()
    closed = words.text[words.break_starts[b] : words.break_ends[b]].strip()
    if _APPOSITIVES.get(opened) != closed:
        return None
    return (words.break_ends[b - 2] if b >= 2 else 0, words.break_ends[b - 1])


def _unread_addresses(sentence: str, previous: str) -> tuple[set[int], set[int]]:
    """The addresses ``sentence`` says the code of is not read, as :func:`_said_unread`
    reads them, and the one its statement's own clause writes last before it.

    A statement read as something, or about a run ("not read as", "not read at
    runtime"), says nothing of a listing and is not read. The sentence's words and
    breaks are read once; each statement is read by bisection over them, so a
    sentence of many statements costs time linear in its length.
    """
    found: set[int] = set()
    own: set[int] = set()
    words: _Words | None = None
    before_previous: set[int] | None = None
    for match in _SAID_UNREAD.finditer(sentence):
        if _NOT_A_LISTING.match(sentence, match.end(), match.end() + _NOT_A_LISTING_REACH):
            continue
        if words is None:
            words = _Words(sentence)
        b, begin = words.clause_at(match.start())
        named = words.addresses_between(begin, words.clause_end(match.end()))
        if match.group(0).lower() != "unread":
            # The bare word may be said of anything ("the buffer is unread in
            # 0x3728"); only a statement that code is not read names its own:
            # the address its clause writes last before it, its subject's; for
            # a clause a relative word opens ("routine 0x6634, which is not
            # read"), the one the clause before it writes last.
            first = words.first_word(begin)
            opener = words.first_word(match.start()) - first == 1
            aside = (
                _appositive_subject(words, b) if words.first_word(match.start()) == first else None
            )
            if opener and words.lower[first] in _RELATIVE_OPENERS and b >= 0:
                earlier = words.break_ends[b - 1] if b >= 1 else 0
                own |= _subject_address(words, earlier, words.break_ends[b])
            elif aside is not None:
                # The aside says what the subject is; the subject stands before it.
                own |= _subject_address(words, aside[0], aside[1], words.break_starts[b - 1])
            else:
                own |= _subject_address(words, begin, match.start())
        here = set(named)
        if not here:
            at = words.last_address(0, match.start())
            here = set(words.found[at]) if at is not None else set()
        if not here and previous:
            if before_previous is None:
                before_previous = _addresses_before(previous)
            here = before_previous
        found |= here
    return found, own


def unread_listed_sentences(
    text: str, listed: Sequence[Passage]
) -> tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...]:
    """Each sentence of ``text`` that calls code not read which a ``listed.N`` fact lists.

    Read as :func:`_said_unread` reads a sentence (the statement's own clause,
    else the nearest address before it, else the last of the sentence
    before), each with the ids of the facts about those addresses and of the
    ones about the address the statement's own clause names: such a sentence is
    contradicted by the ledger itself ("The body of 0x3728 that performs the
    registration is not read" beside an entry listing 0x3728, haiku11 §5.3),
    where an address read from around it may be another routine's. The
    platform's own clause on an unread callee is no part of a sentence here.
    One pass over the sentences, in the order they stand.
    """
    out: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
    ordered = _sentences_of(text)
    for index, sentence in enumerate(ordered):
        if not _SAID_UNREAD.search(sentence):
            continue
        found, own = _unread_addresses(
            _UNREAD_CLAUSE.sub("", sentence),
            _UNREAD_CLAUSE.sub("", ordered[index - 1]) if index else "",
        )
        facts = [fact for fact in listed if not fact.addresses.isdisjoint(found)]
        if facts:
            named = tuple(fact.id for fact in facts if not fact.addresses.isdisjoint(own))
            out.append((sentence, tuple(fact.id for fact in facts), named))
    return tuple(out)


# A sentence stating a branch: a condition ("if", "when", "unless", "otherwise",
# a failure or a success, a zero or nonzero result) and an outcome that is a
# branch's own (the code returns, loops, exits, skips, rejects, aborts, stops,
# sleeps or waits); and a sentence naming an argument or a parameter with such
# an outcome, or an argument by its place ("param_3", "argument 2", "its first
# argument").
_BRANCH_CONDITION = re.compile(
    r"\b(?:if|when|whenever|unless|otherwise|else|fail(?:s|ed|ure)?|succeed(?:s|ed)?"
    r"|success(?:ful)?|non-?zero|zero)\b",
    re.IGNORECASE,
)
_BRANCH_OUTCOME = re.compile(
    r"\b(?:return(?:s|ed)?|loop(?:s|ed)?|exit(?:s|ed)?|skip(?:s|ped)?|reject(?:s|ed)?"
    r"|abort(?:s|ed)?|stop(?:s|ped)?|sleep(?:s)?|wait(?:s|ed)?|branch(?:es|ed)?"
    r"|call(?:s|ed)?|runs?|proceed(?:s|ed)?|continue(?:s|d)?|jump(?:s|ed)?"
    r"|retr(?:y|ies|ied)|falls?\s+through|(?:is|are)\s+(?:taken|reached))\b",
    re.IGNORECASE,
)
# "calls" and "runs" say what code does on any path: they state a branch only
# beside a condition word of its own, never beside a failure, a zero or an
# argument alone ("0x3728 packs these arguments … and calls 0xb344").
_WEAK_OUTCOME = re.compile(r"call(?:s|ed)?|runs?", re.IGNORECASE)
_STRONG_CONDITION = re.compile(
    r"\b(?:if|when|whenever|unless|otherwise|else|only|until|while)\b"
    r"|\bon\s+(?:the\s+|its\s+)?(?:success|failure)\b",
    re.IGNORECASE,
)
_ARGUMENT_WORD = re.compile(r"\b(?:argument|arguments|parameter|parameters)\b", re.IGNORECASE)
_ARGUMENT_PLACE = re.compile(
    r"\bparam_\d+\b|\b(?:argument|parameter|arg)\s*\d+\b"
    r"|\b(?:first|second|third|fourth|fifth|sixth)\s+(?:argument|parameter)\b",
    re.IGNORECASE,
)
# What a routine's listing shows at most in a ``listing.N`` fact; the lines left
# out are counted where they fall.
_LISTING_CHARS = 1200
# The lines shown on each side of a line a held sentence anchors.
_LISTING_WINDOW = 3
# What one line of a listing shown in part (its signature included) shows at most;
# the rest of it is counted.
_SIGNATURE_CHARS = 200
# What the listings of one question show at most, filled in passage order; a
# routine past it is not shown, and the round says how many were left out.
_LISTINGS_PER_QUESTION = 24_000
LISTINGS_LEFT_ID = "listings.left"


def branch_sense_sentences(
    text: str, listed: Sequence[Passage]
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Each sentence of ``text`` that states a branch or an argument of a listed routine.

    ``listed`` holds one passage per routine an entry lists (its ``addresses``).
    A sentence is held when it states a condition (:data:`_BRANCH_CONDITION`; "only
    when" and "only if" among them) and a branch's outcome (:data:`_BRANCH_OUTCOME`),
    an argument with such an outcome, or an argument by its place
    (:data:`_ARGUMENT_PLACE`). It is held on every listed routine the clause of
    each outcome or argument names (:func:`_branch_clause_addresses`), else, for a
    clause naming none whose words before the outcome point back ("With a path
    argument it rejects …"), the first address of the sentence before it; never on
    an address another clause names. The listing shows which way the code goes and
    which argument it reads, and the model reads them. One pass over the
    sentences, in the order they stand.
    """
    out: list[tuple[str, tuple[str, ...]]] = []
    ordered = _sentences_of(text)
    for index, sentence in enumerate(ordered):
        places = list(_ARGUMENT_PLACE.finditer(sentence))
        if places:
            anchors = places
        elif _BRANCH_CONDITION.search(sentence) or _ARGUMENT_WORD.search(sentence):
            strong = _STRONG_CONDITION.search(sentence) is not None
            anchors = [
                m
                for m in _BRANCH_OUTCOME.finditer(sentence)
                if strong or not _WEAK_OUTCOME.fullmatch(m.group(0))
            ]
        else:
            continue
        named: list[int] = []
        for at in anchors:
            found = _branch_clause_addresses(sentence, at.start(), at.end())
            if found is None and index:
                earlier = _addresses_named(ordered[index - 1])
                found = earlier[:1]
            named.extend(found or ())
        ids = tuple(p.id for p in listed if not p.addresses.isdisjoint(named))
        if ids:
            out.append((sentence, ids))
    return tuple(out)


def _branch_clause_addresses(sentence: str, at: int, end: int) -> list[int] | None:
    """The addresses the clause of the outcome or argument at ``at`` names: every one
    of the clause (a clause a relative "which" opens adds the last address before
    that word); ``None`` where the clause names none and its words before ``at``
    point back ("it rejects"), for the sentence before to answer."""
    start = 0
    opened_by = ""
    for mark in _ABSENCE_CLAUSE_END.finditer(sentence):
        if mark.start() >= at:
            break
        start, opened_by = mark.end(), mark.group(0)
    stop = next((m.start() for m in _ABSENCE_CLAUSE_END.finditer(sentence, end)), len(sentence))
    found = list(_addresses_named(sentence[start:stop]))
    if opened_by.strip().lower() == "which":
        earlier = _addresses_named(sentence[: start - len(opened_by)])
        if earlier:
            found.insert(0, earlier[-1])
    if found:
        return found
    if _POINTS_BACK.search(sentence[start:at]):
        return None
    return []


def _listing_excerpt(code: str, sentences: Sequence[str], bases: Sequence[int]) -> str:
    """A routine's code as a ``listing.N`` fact shows it: whole within
    :data:`_LISTING_CHARS`; else its signature and the lines around each line that
    names what the held sentences name (another address in any spelling the image
    bases make, a ``param_N``, a function they name), :data:`_LISTING_WINDOW` lines on
    each side, joined within the budget with each gap counted ("[… N lines …]");
    else, where no line matches, its head, with what was left out counted."""
    from malspark.agents.function_map import address_spellings
    from malspark.reporting.claim_coverage import code_names

    if len(code) <= _LISTING_CHARS:
        return code
    lines = code.splitlines()
    words: set[str] = set()
    for sentence in sentences:
        for address in _addresses_named(sentence):
            for spelled_as in address_spellings(address, bases):
                digits = f"{spelled_as:x}"
                if len(digits) >= 4:
                    words.add(digits)
        words.update(m.group(0).lower() for m in _PARAM_NAME.finditer(sentence))
        words.update(
            written.lower()
            for (kind, _value), written in code_names(sentence).items()
            if kind == "name"
        )
    hits = [
        index
        for index, line in enumerate(lines)
        if any(_names_word(line.lower(), word) for word in words)
    ]
    signature = next((i for i, line in enumerate(lines) if "(" in line and line.strip()), 0)
    if not hits:
        head = code[:_LISTING_CHARS]
        return f"{head}[… {len(code) - len(head)} characters left out …]"
    # A line longer than a signature may be (a long signature, a string literal) is
    # cut, its rest counted, so no one line takes the budget; a line naming what the
    # sentences name keeps the window centred on that name.
    lines = [_line_window(line, words) for line in lines]
    keep: set[int] = {signature}
    used = len(lines[signature]) + 1
    # Each named thing's first line first, then the lines around those, then the
    # windows of its other lines: what the sentences name is shown before context.
    firsts = list(
        dict.fromkeys(
            next(i for i in hits if _names_word(lines[i].lower(), word))
            for word in words
            if any(_names_word(lines[i].lower(), word) for i in hits)
        )
    )
    firsts.sort()

    def _take(indexes: Iterable[int]) -> None:
        nonlocal used
        for index in indexes:
            if index in keep:
                continue
            cost = len(lines[index]) + 1
            if used + cost > _LISTING_CHARS:
                continue
            keep.add(index)
            used += cost

    def _around(hit: int) -> list[int]:
        return [
            i
            for step in range(1, _LISTING_WINDOW + 1)
            for i in (hit - step, hit + step)
            if 0 <= i < len(lines)
        ]

    _take(firsts)
    for hit in firsts:
        _take(_around(hit))
    for hit in hits:
        _take([hit, *_around(hit)])
    shown: list[str] = []
    previous = -1
    for index in sorted(keep):
        if index - previous > 1:
            shown.append(f"[… {index - previous - 1} lines …]")
        shown.append(lines[index])
        previous = index
    if previous < len(lines) - 1:
        shown.append(f"[… {len(lines) - 1 - previous} lines …]")
    return "\n".join(shown)


_PARAM_NAME = re.compile(r"\bparam_\d+\b", re.IGNORECASE)


def _line_window(line: str, words: Iterable[str]) -> str:
    """``line`` whole within :data:`_SIGNATURE_CHARS`; else that many characters,
    centred on the first thing it names of ``words`` (else its start), each cut
    counted."""
    if len(line) <= _SIGNATURE_CHARS:
        return line
    lowered = line.lower()
    at = min(
        (
            m.start()
            for word in words
            for m in [re.search(rf"(?<![0-9a-z])0*{re.escape(word)}(?![0-9a-z_])", lowered)]
            if m is not None
        ),
        default=0,
    )
    start = max(0, min(at - _SIGNATURE_CHARS // 2, len(line) - _SIGNATURE_CHARS))
    stop = start + _SIGNATURE_CHARS
    before = f"[… {start} characters …]" if start else ""
    after = f"[… {len(line) - stop} characters …]" if stop < len(line) else ""
    return f"{before}{line[start:stop]}{after}"


def _names_word(line: str, word: str) -> bool:
    """Whether ``line`` names ``word`` as a whole token (hex digits or a name); a
    decompiler's prefix before it (``FUN_``, ``DAT_``, ``fcn.``) and the zeros a 32-bit
    name is padded with (``FUN_004012f0``) are no part of the token."""
    return re.search(rf"(?<![0-9a-z])0*{re.escape(word)}(?![0-9a-z_])", line) is not None


def _routine_code(
    entries: dict[str, Any], address: int, listed_in: Sequence[str], bases: Sequence[int]
) -> str:
    """The code an entry of ``listed_in`` lists for the routine at ``address`` (spelled
    as ``agreement_facts`` spells a read routine), or ``""``: a batch answer's function
    under that address, or a single listing answered for it alone."""
    from malspark.agents.function_map import one_spelling
    from malspark.pipeline.validation import _batch_listings, _listing_text
    from malspark.reporting.agreement_facts import answered_addresses

    for entry_id in listed_in:
        entry = entries.get(entry_id)
        if entry is None:
            continue
        output = str(_field(entry, "output") or "")
        shown, listings = _batch_listings(output)
        if shown:
            for key, code in listings.items():
                if one_spelling(key, bases) == address:
                    return code
            continue
        answered = {one_spelling(a, bases) for a in answered_addresses(entry)}
        if answered == {address}:
            code = _listing_text(output)
            if code.strip():
                return code
    return ""


def _branch_sense_passages(
    passages: Sequence[Passage], found: LedgerFacts, entries: dict[str, Any]
) -> list[Passage]:
    """The ``listing.N`` facts of the routines a writable passage's branch or argument
    sentence names, and each such sentence held on them (:func:`branch_sense_sentences`).

    A fact shows the routine's code from an entry that lists it, whole or in the
    part its held sentences anchor (:func:`_listing_excerpt`), with what is left out
    counted; a routine none of whose entries' code is read here is not shown, and
    its sentences are not held on it.
    """
    from malspark.reporting.agreement_facts import spelled

    bases = tuple(found.image_bases)
    routines = [
        Passage(
            id=f"routine.{index}",
            label="",
            text="",
            kind=FACT,
            addresses=_spelled_both([routine.address], bases),
            cites=_ids(routine.listed_in),
        )
        for index, routine in enumerate(found.listed)
    ]
    held: dict[str, list[tuple[Passage, str]]] = {}
    for passage in passages:
        # A closing sentence is answered whole already (T-568).
        if not _writable(passage) or passage.closing:
            continue
        for sentence, ids in branch_sense_sentences(passage.text, routines):
            for rid in ids:
                held.setdefault(rid, []).append((passage, sentence))
    out: list[Passage] = []
    by_routine: dict[str, str] = {}
    used = 0
    left = 0
    by_id = {f"routine.{index}": routine for index, routine in enumerate(found.listed)}
    # In passage order: the routines the first held sentences name come first.
    for rid in held:
        routine = by_id[rid]
        code = _routine_code(entries, routine.address, routine.listed_in, bases)
        if not code.strip():
            continue
        shown = _listing_excerpt(code, [sentence for _p, sentence in held[rid]], bases)
        cut = f" [shown in part: {len(shown)} of {len(code)} characters]" if shown != code else ""
        text = (
            f"{spelled(routine.address, bases)}: "
            f"{', '.join(sorted(_ids(routine.listed_in)))} list its code: "
            f"{quoted_value(shown)}{cut}"
        )
        if used + len(text) > _LISTINGS_PER_QUESTION:
            # Past the question's budget: no sentence is held on this routine.
            left += 1
            continue
        used += len(text)
        fid = f"listing.{len(out) + 1}"
        by_routine[rid] = fid
        out.append(
            Passage(
                id=fid,
                label="the listing of a routine a sentence states a branch or an argument of",
                text=text,
                kind=FACT,
                cites=_ids(routine.listed_in),
                addresses=_spelled_both([routine.address], bases),
            )
        )
    if left:
        out.append(
            Passage(
                id=LISTINGS_LEFT_ID,
                label="routine listings not shown",
                text=(
                    f"{left} {'listing' if left == 1 else 'listings'} not shown: budget "
                    f"({_LISTINGS_PER_QUESTION} characters of listings per question); a "
                    "sentence held only on them is not held"
                ),
                kind=FACT,
            )
        )
    for rid, uses in held.items():
        fact_id = by_routine.get(rid)
        if fact_id is None:
            continue
        for passage, sentence in uses:
            known = dict(passage.branch_sense)
            known[sentence] = tuple(dict.fromkeys([*known.get(sentence, ()), fact_id]))
            passage.branch_sense = tuple(known.items())
            if sentence not in passage.held:
                passage.held = (*passage.held, sentence)
    return out


# ---------------------------------------------------------------------------
# A denial of a name the run holds, read against the ledger (T-600)
# ---------------------------------------------------------------------------

# What the ``ledger.N`` facts of one question show at most, filled closing passages
# first, then in passage order (T-580's bound for the round's facts); a name past it
# is not shown, and the round says how many were left out.
_NAMES_PER_QUESTION = 24_000
NAMES_LEFT_ID = "ledger.left"
# What the id of every such fact opens with.
_NAME_FACT = "ledger."


def _not_shown_for(source: Passage, sentence: str) -> bool:
    """Whether ``source`` is a fact of a name the run holds that was not shown for
    ``sentence``: such a fact speaks only to the sentences held on it
    (:attr:`Passage.speaks_to`), never to another sentence sharing its words."""
    return source.id.startswith(_NAME_FACT) and sentence not in source.speaks_to


# How many routines a fact names calling an API, and how many of their listings it
# shows the call lines of, at most; the rest are counted.
_CALLERS_SHOWN = 4
_CALL_LISTINGS = 2
# How many callees of an export, and of each of those, a fact names at most.
_CALLEES_SHOWN = 4
# What an export's own listing shows at most in its fact.
_EXPORT_LISTING_CHARS = 600
# A hex run as a listing writes an address, a decompiler's prefix aside
# (``FUN_``, ``DAT_``, ``fcn.``): what a line is read for a slot by.
_LINE_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?([0-9A-Fa-f]{4,16})(?![0-9A-Za-z_])")
_NAME_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# The endings a key's inflected word takes on its stem: "calls" is written "call",
# "calls", "called", "calling"; "decoded" "decode", "decodes", "decoded", "decoding".
_ENDINGS = ("", "s", "e", "es", "ed", "d", "ing")


def word_forms(word: str) -> frozenset[str]:
    """The words a key's word is written as: an inflected one ("calls", "resolved",
    "callees") its stem with each of :data:`_ENDINGS`, any other ("plain", "text",
    "slot") itself alone. Only these words are read as it, never a word that merely
    begins with its stem ("callee", "importer", "plainly")."""
    stem = word[:-2] if word.endswith("ed") else word
    stem = stem[:-1] if stem.endswith("s") else stem
    if stem == word:
        return frozenset({word})
    return frozenset(stem + ending for ending in _ENDINGS)


def _relation_forms() -> tuple[dict[str, frozenset[str]], dict[str, tuple[str, ...]]]:
    """The words each relation is written with, and the key words it is only held in,
    read off the keys the run's answers hold it under (``ledger_entities.RELATION_KEYS``).

    A word of a key one of whose forms (:func:`word_forms`) is the relation's own name
    writes the relation, in each of its forms: "slot_calls" gives "call", "calls",
    "called", "calling"; "plain_strings" gives "plain". A key's other words say what
    the relation is held in ("slot", "callees", "strings", "text"), never the relation
    itself."""
    from malspark.reporting.ledger_entities import NAME_FLOOR, RELATION_KEYS

    out: dict[str, frozenset[str]] = {}
    held_in: dict[str, tuple[str, ...]] = {}
    for relation, keys in RELATION_KEYS.items():
        forms: set[str] = set()
        other: dict[str, None] = {}
        for key in keys:
            for word in key.split("_"):
                found = word_forms(word)
                if min(len(form) for form in found) < NAME_FLOOR:
                    continue
                if relation in found:
                    forms |= found
                else:
                    other[word] = None
        out[relation] = frozenset(forms)
        held_in[relation] = tuple(other)
    return out, held_in


_RELATIONS, _HELD_IN = _relation_forms()
# The relations a name of each kind is held under where a clause writes it by its kind
# alone: the export table's word, or the words a quoted text is held in. Read only to
# hold a sentence for the model, never to decide one.
_KIND_RELATIONS = {
    "export": ("exported",),
    "text": ("decoded", "plain"),
}


def _kind_words(kind: str) -> frozenset[str]:
    """The word forms every relation of a kind is held in ("string", "text" of a decoded
    and a plain text: they say which kind of name it is)."""
    held = [set(_HELD_IN[relation]) for relation in _KIND_RELATIONS[kind]]
    every = set.intersection(*held) if held else set()
    return frozenset(form for word in every for form in word_forms(word))


_KIND_WORDS_HELD = {kind: _kind_words(kind) for kind in _KIND_RELATIONS}


def relation_of(word: str, relations: Sequence[str]) -> str | None:
    """The relation of ``relations`` a word writes, the word one of its forms
    (:func:`_relation_forms`), or ``None``."""
    return next((r for r in relations if word in _RELATIONS[r]), None)


def _writes_kind(word: str, kind: str) -> bool:
    """Whether a word writes a relation of ``kind`` or a word all of them are held in."""
    return relation_of(word, _KIND_RELATIONS[kind]) is not None or word in _KIND_WORDS_HELD[kind]


# The empty parentheses a name written as a call ends in ("connect()"): they say no
# word, and a parenthesis would otherwise end the clause the name stands in.
_CALL_MARKS = re.compile(r"(?<=[A-Za-z0-9_])\(\s*\)")


@dataclass(frozen=True)
class NameReading:
    """A name a negated sentence writes (or, pointing back, the sentence before it writes),
    which holds the sentence to what the ledger holds of it: ``kind`` is "api", "export"
    or "text", ``key`` the name as the ledger holds it (an API's lowered name, an export's
    address in hex, a text lowered), ``shown`` as the sentence writes it."""

    sentence: str
    kind: str
    key: str
    shown: str
    back: bool = False


# How far either side of a word its cue is read (``function_map._named_as_a_function``:
# a cue, a quote or a parenthesis stands straight beside it), so each look costs the
# same however long the text.
_CUE_REACH = 32


def _named_here(text: str, start: int, end: int) -> bool:
    """Whether the word at ``text[start:end]`` is written as code or beside a word saying
    it is a function (``function_map._named_as_a_function``), read around it."""
    from malspark.agents.function_map import _named_as_a_function

    window = text[max(0, start - _CUE_REACH) : end + _CUE_REACH]
    return _named_as_a_function(window, text[start:end])


def _held_names(text: str, names: Any, exports_denied: bool = False) -> list[tuple[str, str, str]]:
    """``(kind, key, shown)`` of each name the run holds that ``text`` writes, once each:
    an API or an export by its name as the ledger writes it, one spelled like a word of
    prose ("connect", "Sleep", "run") only as code or beside a word saying it is a
    function (``function_map._named_as_a_function``); every export where
    ``exports_denied`` (a negated clause denies something of what it writes with the word
    the export table is held under) and the text names none ("Which export the loader
    calls is not established"); a decoded text by its quoted words. Each occurrence is
    read where it stands, so the text is walked once."""
    from malspark.agents.function_map import _WORD_NAME
    from malspark.reporting.ledger_entities import NAME_FLOOR

    out: dict[tuple[str, str], str] = {}
    done: set[str] = set()
    for match in _NAME_TOKEN.finditer(text):
        token = match.group(0)
        if token in done:
            # Each word is read until it is found: a name written many times is one name.
            continue
        api = names.apis.get(token.lower()) if len(token) >= NAME_FLOOR else None
        export = names.exports.get(token)
        prose = bool(_WORD_NAME.fullmatch(token))
        cued: bool | None = None
        if api is not None and ("api", token.lower()) not in out:
            if prose or token != api.name:
                cued = _named_here(text, match.start(), match.end())
            if cued is not False and (cued or not prose):
                out[("api", token.lower())] = api.name
        if export is not None and ("export", hex(export.address)) not in out:
            if prose and cued is None:
                cued = _named_here(text, match.start(), match.end())
            if not prose or cued:
                out[("export", hex(export.address))] = token
        if (api is None or ("api", token.lower()) in out) and (
            export is None or ("export", hex(export.address)) in out
        ):
            done.add(token)
    if exports_denied and names.by_address and not any(kind == "export" for kind, _key in out):
        # The word must be what a clause denies something of: "the export tables of the
        # DLLs" a hash set was not reproduced against is no export of the sample's.
        for address, export in names.by_address.items():
            out.setdefault(("export", hex(address)), ", ".join(export.names))
    for match in _QUOTED.finditer(text):
        quoted = match.group(1).strip()
        if quoted.lower() in names.texts:
            out.setdefault(("text", quoted.lower()), quoted)
    return [(kind, key, shown) for (kind, key), shown in out.items()]


@lru_cache(maxsize=256)
def _subject_of(clause: str) -> frozenset[str]:
    """``absence_answers.denied_subject`` of a clause, read once per clause."""
    return denied_subject(clause)


@dataclass(frozen=True)
class _Clause:
    """A negated clause's words, read once for every name its sentence writes: its words
    (lowered), those after its negation, what it denies something of
    (``absence_answers.denied_subject``), its quoted texts and the addresses it names."""

    text: str
    words: frozenset[str]
    after: frozenset[str]
    subject: frozenset[str]
    quoted: frozenset[str]
    addresses: tuple[int, ...]


def _read_clause(clause: str) -> _Clause:
    from malspark.reporting.absence_answers import _NEGATION as NEGATION

    found = NEGATION.search(clause)
    after = clause[found.end() :] if found else ""
    return _Clause(
        text=clause,
        words=frozenset(w.lower() for w in _NAME_TOKEN.findall(clause)),
        after=frozenset(w.lower() for w in _NAME_TOKEN.findall(after)),
        subject=_subject_of(clause),
        quoted=frozenset(m.group(1).strip().lower() for m in _QUOTED.finditer(clause)),
        addresses=tuple(_addresses_named(clause)),
    )


class _Clauses:
    """The negated clauses of a sentence, read once and looked up by word, so a name is
    found in them by its words, never by walking them again (linear in the sentence and
    the names, T-600)."""

    def __init__(self, clauses: Sequence[str]) -> None:
        self.read = [_read_clause(clause) for clause in clauses]
        self.after: set[str] = set()
        self.by_word: dict[str, list[int]] = {}
        self.by_subject: dict[str, list[int]] = {}
        self.by_quote: dict[str, list[int]] = {}
        # The addresses a clause writing a word a text is held under names (T-652).
        self.text_at: dict[int, None] = {}
        # Whether one denies something of what it writes with the word the export table
        # is held under.
        self.exports_denied = False
        for at, clause in enumerate(self.read):
            self.after |= clause.after
            for word in clause.words:
                self.by_word.setdefault(word, []).append(at)
            for word in clause.subject:
                self.by_subject.setdefault(word, []).append(at)
            if any(relation_of(word, ("exported",)) for word in clause.subject):
                self.exports_denied = True
            if any(_writes_kind(word, "text") for word in clause.words):
                for quoted in clause.quoted:
                    self.by_quote.setdefault(quoted, []).append(at)
                self.text_at.update(dict.fromkeys(clause.addresses))

    def data(self, names: Any, sentence: str) -> list[tuple[str, str, str]]:
        """``(kind, key, shown)`` of each routine whose listing names a data address
        ``sentence`` names, where a clause writing a word a text is held under names one
        such address ("The texts at 0xf9a0 and 0xf9b0 are not decoded") and no decoded row
        holds a text at it in any spelling (``RunNames.decoded``): keyed by the routine and
        those addresses, shown as the sentence writes them. A routine's own address is no
        datum; where a decoded row's address and a listing's cannot be told one spelling
        (``RunNames.decoded_reconciled``), nothing is held (T-652)."""
        from malspark.agents.function_map import one_spelling

        if not names.decoded_reconciled():
            return []

        def _held(address: int) -> int | None:
            at = one_spelling(address, names.bases)
            if names.routine_at(at) or names.decoded(at) or at not in names.data_at:
                return None
            return at

        if not any(_held(address) is not None for address in self.text_at):
            return []
        out: dict[int, dict[int, str]] = {}
        for address in dict.fromkeys(_addresses_named(sentence)):
            at = _held(address)
            if at is None:
                continue
            for routine in names.data_at[at]:
                out.setdefault(routine, {})[at] = hex(address)
        return [
            ("data", f"{routine:x}:" + ",".join(f"{at:x}" for at in held), ", ".join(held.values()))
            for routine, held in out.items()
        ]

    def denies(self, kind: str, shown: str) -> bool:
        """Whether a clause denies something of a name: the name stands after its negation
        ("no call to OpenProcess is shown"), or among the words of what it denies
        something of ("the mutex name passed to CreateMutexW is not confirmed"); never a
        name a clause only writes beside a denial of something else ("emulating against the
        CreateMutexW value returned no match"). A decoded text is denied only where the
        clause writes a word it is held under; the export table's word only as what is
        denied something of."""
        if kind == "text":
            return shown.lower() in self.by_quote
        if kind == "export" and self.exports_denied:
            return True
        if any(part.strip().lower() in self.after for part in shown.split(",")):
            return True
        own = content_words(shown.replace(",", " "))
        if not own:
            return False
        rarest = min(own, key=lambda word: len(self.by_subject.get(word, ())))
        return any(own <= self.read[at].subject for at in self.by_subject.get(rarest, ()))


def _bare_clause(clause: str, generic: frozenset[str]) -> bool:
    """Whether a negated clause writes no word of its own but what it denies: its subject
    stands elsewhere in the sentence ("..., the target of the calls in 0x463c, and whether
    a write follows, were not established")."""
    skip = _ABSENCE_PREDICATES | PREPOSITIONS | generic
    return all(_plain_word(word, skip) for word in content_words(clause))


def _plain_word(word: str, skip: frozenset[str]) -> bool:
    """Whether a word says nothing of its own: one of ``skip``, or an address
    (:func:`_addresses_named`: "0x" alone begins none)."""
    return word in skip or bool(_addresses_named(word))


_WORD_CHARACTER = re.compile(r"\w")


def _uncited(text: str) -> str:
    """``text`` without its citations (``composer_pro._CITATIONS``): one written between
    two word characters ("QueryHostMode[ev_0109]is not called") leaves a space, so the
    words around it stay two; one inside a code span ("`Query[ev_0109]HostMode`"), which
    is one name, and any other leave nothing ("… `QueryHostMode` [ev_0109].")."""
    from malspark.reporting.composer_pro import _CITATIONS

    # Where each backtick stands: a citation with an odd number of them before it and one
    # after it stands inside a code span.
    ticks = [at for at, character in enumerate(text) if character == "`"]

    def _cut(match: re.Match[str]) -> str:
        start, end = match.span()
        before = bisect.bisect_left(ticks, start)
        if before % 2 and before < len(ticks):
            return ""
        between = (
            start > 0
            and _WORD_CHARACTER.match(text, start - 1) is not None
            and _WORD_CHARACTER.match(text, end) is not None
        )
        return " " if between else ""

    return _CITATIONS.sub(_cut, text)


def name_readings(
    sentence: str, previous: str, names: Any, generic: frozenset[str] = frozenset()
) -> list[NameReading]:
    """Each name the run holds that a negated sentence writes, each read as the model's to
    answer against the ledger's fact (T-600).

    A sentence denying nothing, or denying what a run saw (``absence_answers.set_in_a_run``:
    "was not observed at run time"), names nothing here: the ledger's code facts do not
    speak of a run. A sentence is held where a negated clause denies something of a name it
    writes (:meth:`_Clauses.denies`), or where a negated clause writes nothing of its own but
    what it denies (:func:`_bare_clause`), its subject the rest of the sentence; it is then
    held on every name it writes ("No call to A, B or C is shown"). A negated
    sentence naming no name the run holds and no address that opens pointing back ("These
    names are shown only as resolved; the code does not show them being called") is held on
    the names of the sentence before it: what "them" is the model reads. It is so held only
    where its denial is of what it points back to: a negated clause writes a word pointing
    back, or denies something of no subject of its own (``absence_answers.denied_subject``:
    "They serve the lookup, not a shadow-copy routine"); "It resolves the hashes, so the
    working API set is not in the import table" denies something of its own. Code decides
    nothing of a reading: each is a question for the model, with the fact shown. A name
    written as a call ("`connect()` is not called") is read as the name: the empty
    parentheses after it close no clause. Both sentences are read without their citations:
    an entry id in brackets, wherever it stands, cuts no clause and writes no name. The
    reading keeps the sentence as written. Linear in the sentence and the names: the
    sentence is read once, and a name is found in its clauses by its own words."""
    from malspark.reporting.absence_answers import clauses_of

    uncited = _uncited(sentence).strip()
    clauses = negated_clauses(_CALL_MARKS.sub("", uncited))
    if not clauses or set_in_a_run(uncited):
        return []
    read = _Clauses(clauses)
    bare = any(_bare_clause(clause, generic) for clause in clauses)
    written = _held_names(uncited, names, read.exports_denied)
    # A data address is held only where the clause denying a text names it (T-652).
    data = read.data(names, uncited) if names.data_at else []
    if any((bare and kind != "text") or read.denies(kind, shown) for kind, _key, shown in written):
        # Held on every name it writes: where a list of names is cut into clauses is no
        # reading of which of them the denial is of.
        return [NameReading(sentence, *name) for name in (*written, *data)]
    if data:
        return [NameReading(sentence, *name) for name in data]
    opening = next(iter(clauses_of(uncited)), "").strip()
    if (
        previous
        and _POINTS_BACK.match(opening)
        and any(_POINTS_BACK.search(clause.text) or not clause.subject for clause in read.read)
        and not _held_names(uncited, names)
        and not _addresses_named(uncited)
    ):
        # Only the names the sentence before writes: what "them" stands for is the model's.
        before = _uncited(previous)
        return [NameReading(sentence, *name, back=True) for name in _held_names(before, names)]
    return []


def _slot_noted(line: str, slots: dict[int, str], bases: Sequence[int]) -> str:
    """A listing's line with the API each slot it writes resolves to named after it."""
    from malspark.agents.function_map import one_spelling

    said = [
        f"{m.group(0)} = {slots[at]}"
        for m in _LINE_HEX.finditer(line)
        if (at := one_spelling(int(m.group(1), 16), bases)) in slots
    ]
    return f"{line}  /* {'; '.join(dict.fromkeys(said))} */" if said else line


def _call_lines(
    code: str, words: Sequence[str], slots: dict[int, str], bases: Sequence[int]
) -> str:
    """The lines of a routine's listing naming any of ``words`` (a slot's hex digits in any
    spelling, an API's name), each with the line on either side, the slots each line
    writes named (:func:`_slot_noted`), within :data:`_LISTING_CHARS` with each gap
    counted; ``""`` where no line names one."""
    lines = code.splitlines()
    lowered = [w.lower() for w in words if w]
    hits = [i for i, line in enumerate(lines) if any(_names_word(line.lower(), w) for w in lowered)]
    if not hits:
        return ""
    keep: list[int] = []
    used = 0
    for hit in hits:
        for index in (hit - 1, hit, hit + 1):
            if not 0 <= index < len(lines) or index in keep:
                continue
            line = _slot_noted(_line_window(lines[index], lowered), slots, bases)
            if used + len(line) + 1 > _LISTING_CHARS:
                break
            keep.append(index)
            lines[index] = line
            used += len(line) + 1
    shown: list[str] = []
    previous = -1
    for index in sorted(keep):
        if index - previous > 1:
            shown.append(f"[… {index - previous - 1} lines …]")
        shown.append(lines[index])
        previous = index
    if previous < len(lines) - 1:
        shown.append(f"[… {len(lines) - 1 - previous} lines …]")
    return "\n".join(shown)


@dataclass
class _NameFact:
    """A ``ledger.N`` fact's parts before its id is given."""

    text: str
    qualifier: str
    cites: frozenset[str]
    rows: tuple[str, ...]
    values: tuple[str, ...]
    addresses: frozenset[int] = frozenset()


def _api_fact(
    key: str, names: Any, listed: dict[int, tuple[str, ...]], entries: dict[str, Any]
) -> _NameFact | None:
    """What the ledger holds of an API: the routines the index lists calling it and through
    which slot, with the call lines of the listed ones; else that it lists no call, and
    where the API is resolved or imported."""
    from malspark.agents.function_map import address_spellings

    held = names.apis.get(key)
    if held is None:
        return None
    bases = names.bases
    index = names.index_entry
    routines: dict[int, int | None] = {}
    sources: dict[str, None] = {}
    for call in held.calls:
        routines.setdefault(call.routine, call.slot)
        sources.update(dict.fromkeys(call.named_by))
    rows: list[str] = []
    listings: list[str] = []
    if routines:
        shown = list(routines.items())[:_CALLERS_SHOWN]
        where = ", ".join(
            f"the routine at {_offsets([routine], bases)}"
            + (f" through the slot at {_offsets([slot], bases)}" if slot is not None else "")
            for routine, slot in shown
        )
        more = len(routines) - len(shown)
        head = (
            f"{quoted_value(held.name)}: the function index ({index}) lists a call to it from "
            f"{where}" + (f"; and {more} more routines" if more > 0 else "")
        )
        qualifier = (
            f"the function index lists a call to {_sample_text(held.name)} from the routine at "
            f"{_offsets([r for r, _slot in shown], bases)}"
        )
        for routine, slot in shown:
            if len(listings) >= _CALL_LISTINGS or routine not in listed:
                continue
            code = _routine_code(entries, routine, listed[routine], bases)
            words = [held.name]
            if slot is not None:
                words.extend(f"{s:x}" for s in address_spellings(slot, bases) if s >= 0x1000)
            lines = _call_lines(code, words, names.slots, bases) if code.strip() else ""
            if not lines:
                continue
            ids = ", ".join(sorted(_ids(listed[routine])))
            listings.append(
                f"{ids} {'lists' if len(_ids(listed[routine])) == 1 else 'list'} the code of "
                f"the routine at {_offsets([routine], bases)}: {quoted_value(lines)}"
            )
            rows.extend(line for line in lines.splitlines() if not line.startswith("[…"))
            sources.update(dict.fromkeys(listed[routine]))
    else:
        said = []
        if held.resolved_in:
            said.append(
                "it lists it resolved in the routine at "
                + _offsets(list(held.resolved_in)[:_CALLERS_SHOWN], bases)
            )
        if held.imported:
            said.append(f"{', '.join(sorted(_ids(held.imported)))} list it imported")
        head = (
            f"{quoted_value(held.name)}: the function index ({index}) lists no call to it"
            + ("" if names.index_whole else " among the routines it lists")
            + (f"; {'; '.join(said)}" if said else "")
        )
        qualifier = f"the function index lists no call to {_sample_text(held.name)}"
        sources.update(held.resolved)
        sources.update(held.imported)
    text = "; ".join([head, *listings])
    return _NameFact(
        text=text,
        qualifier=qualifier,
        cites=_ids([index, *sources]),
        rows=(head, *rows),
        values=(held.name,),
        addresses=_spelled_both(routines, bases),
    )


def _export_fact(
    key: str, names: Any, listed: dict[int, tuple[str, ...]], entries: dict[str, Any]
) -> _NameFact | None:
    """What the ledger holds of an export: the names at its address and the entries listing
    them, the callees the index lists (and theirs), and its listing where an entry lists it."""
    address = int(key, 16)
    export = names.by_address.get(address)
    if export is None:
        return None
    bases = names.bases
    said = ", ".join(quoted_value(n) for n in export.names)
    head = (
        f"the export table ({', '.join(sorted(_ids(export.entries)))}) names {said} at "
        f"{_offsets([address], bases)}"
    )
    parts = [head]
    cites: dict[str, None] = dict.fromkeys(export.entries)
    callees = list(names.callees.get(address, ()))[:_CALLEES_SHOWN]
    if callees:
        nested = []
        for callee in callees:
            theirs = list(names.callees.get(callee, ()))[:_CALLEES_SHOWN]
            nested.append(
                _offsets([callee], bases)
                + (f" (which calls {_offsets(theirs, bases)})" if theirs else "")
            )
        parts.append(
            f"the function index ({names.index_entry}) lists it calling {', '.join(nested)}"
        )
        cites[names.index_entry] = None
    if address in listed:
        code = _routine_code(entries, address, listed[address], bases)
        if code.strip():
            shown = code if len(code) <= _EXPORT_LISTING_CHARS else code[:_EXPORT_LISTING_CHARS]
            cut = (
                f" [shown in part: {len(shown)} of {len(code)} characters]" if shown != code else ""
            )
            ids = sorted(_ids(listed[address]))
            parts.append(
                f"{', '.join(ids)} {'lists' if len(ids) == 1 else 'list'} its code: "
                f"{quoted_value(shown)}{cut}"
            )
            cites.update(dict.fromkeys(listed[address]))
    qualifier = (
        f"the export table names {', '.join(export.names)} at {_offsets([address], bases)}"
        + (f", which calls {_offsets(callees, bases)}" if callees else "")
    )
    return _NameFact(
        text="; ".join(parts),
        qualifier=qualifier,
        cites=_ids(cites),
        rows=tuple(parts),
        values=export.names,
        addresses=_spelled_both([address], bases),
    )


def _text_fact(key: str, names: Any) -> _NameFact | None:
    """What the ledger holds of a decoded or plain text: the routines the index ties it to,
    and the entries it rests on."""
    held = names.texts.get(key)
    if held is None:
        return None
    bases = names.bases
    head = (
        f"{quoted_value(held.text)}: the function index ({names.index_entry}) ties it to the "
        f"routine at {_offsets(list(held.routines)[:_CALLERS_SHOWN], bases)}"
        + (f", from {', '.join(sorted(_ids(held.sources)))}" if _ids(held.sources) else "")
    )
    return _NameFact(
        text=head,
        qualifier=(
            f"the function index ties the text {quoted_value(_sample_text(held.text))} to the "
            f"routine at {_offsets(list(held.routines)[:_CALLERS_SHOWN], bases)}"
        ),
        cites=_ids([names.index_entry, *held.sources]),
        rows=(head,),
        values=(held.text,),
        addresses=_spelled_both(held.routines, bases),
    )


# How many data addresses, and texts, a fact of a routine's data names at most; the rest
# are counted.
_DATA_SHOWN = 6
_TEXTS_SHOWN = 6


def _hold_listed_data(names: Any, found: LedgerFacts, entries: dict[str, Any]) -> None:
    """Each data address the listing of a routine an entry lists names after a data label a
    source declares (``undeclared_tools.declared_labels``), held on ``names``
    (``ledger_entities.hold_data``, T-652). Each batch answer is read once."""
    from malspark.agents.function_map import one_spelling
    from malspark.core.undeclared_tools import declared_labels
    from malspark.pipeline.validation import _batch_listings
    from malspark.reporting.ledger_entities import hold_data

    prefixes = declared_labels().data
    batches: dict[str, dict[int, str]] = {}
    for routine in found.listed:
        code = ""
        for entry_id in routine.listed_in:
            if entry_id not in batches:
                entry = entries.get(entry_id)
                output = str(_field(entry, "output") or "") if entry is not None else ""
                shown, listings = _batch_listings(output)
                batches[entry_id] = (
                    {one_spelling(k, names.bases): c for k, c in listings.items()} if shown else {}
                )
            code = batches[entry_id].get(routine.address, "")
            if code:
                break
        if not code:
            # A single listing answered for the routine alone.
            code = _routine_code(entries, routine.address, routine.listed_in, names.bases)
        if code.strip():
            hold_data(names, routine.address, code, routine.listed_in, prefixes)


def _more(listed: str, more: int) -> str:
    """``listed``, and the count of what a cap left out."""
    return f"{listed} and {more} more" if more > 0 else listed


def _calls_said(called: Sequence[int], data: int, bases: Sequence[int]) -> str:
    """How the lines naming ``data`` addresses name the routines ``called``: one routine on a
    line naming each address, or several among the lines naming them, the first
    :data:`_CALLEES_SHOWN` and the count of the rest."""
    if not called:
        return ""
    if len(called) == 1:
        each = "" if data == 1 else ", each"
        return f"{each} on a line that calls the routine at {_offsets(list(called), bases)}"
    shown = list(called)[:_CALLEES_SHOWN]
    listed = _more(_offsets(shown, bases), len(called) - len(shown))
    return f" on one or more lines that call the routines at {listed}"


def _text_at_fact(key: str, names: Any) -> _NameFact | None:
    """What the ledger holds of data addresses a routine's listing names (``key``: the routine
    and the addresses) that no decoded row holds a text at: the routines its lines naming
    each call, the texts the function index ties to the routine, and that no decoded row
    holds a text at them (T-652). A line naming a datum and a routine is what the ledger
    holds, never that the datum is passed to it; nor which text is stored where. Each list
    a cap cuts counts the rest."""
    head_key, _, held_key = key.partition(":")
    routine = int(head_key, 16)
    ref = names.refs_of.get(routine)
    if ref is None or not names.decoded_reconciled():
        return None
    bases = names.bases
    every = [int(a, 16) for a in held_key.split(",") if a]
    every = [a for a in every if a in ref.addresses and not names.decoded(a)]
    data = every[:_DATA_SHOWN]
    if not data:
        return None
    more = len(every) - len(data)
    # The addresses by the routines the lines naming them call, in the order read.
    by_callee: dict[tuple[int, ...], list[int]] = {}
    for address in data:
        by_callee.setdefault(tuple(ref.addresses[address]), []).append(address)
    groups = list(by_callee.items())
    named = "; ".join(
        "names the data at "
        + _more(_offsets(at, bases), more if i == len(groups) - 1 else 0)
        + _calls_said(to, len(at), bases)
        for i, (to, at) in enumerate(groups)
    )
    keys = names.texts_of.get(routine, ())
    texts = [names.texts[k] for k in keys[:_TEXTS_SHOWN]]
    tied = _more(
        ", ".join(
            quoted_value(t.text)
            + (f" ({', '.join(sorted(_ids(t.sources)))})" if _ids(t.sources) else "")
            for t in texts
        ),
        len(keys) - len(texts),
    )
    listed = ", ".join(sorted(_ids(ref.listed_in)))
    head = f"the routine at {_offsets([routine], bases)} {named} ({listed})"
    index = (
        f"the function index ({names.index_entry}) ties to that routine the texts {tied}"
        if texts
        else f"the function index ({names.index_entry}) ties no text to that routine"
        if names.index_entry
        else ""
    )
    decoded = ", ".join(sorted(_ids(names.decoded_entries)))
    tail = f"no decoded row holds a text at {_more(_offsets(data, bases), more)}" + (
        f" ({decoded})" if decoded else ""
    )
    rows = tuple(part for part in (head, index, tail) if part)
    one = len(bases) == 1
    return _NameFact(
        text="; ".join(rows),
        qualifier=tail.split(" (", 1)[0],
        cites=_ids(
            [names.index_entry, *ref.listed_in, *names.decoded_entries]
            + [source for t in texts for source in t.sources]
        ),
        rows=rows,
        values=tuple(hex(a - bases[0]) if one and a >= bases[0] else hex(a) for a in data),
        addresses=_spelled_both([routine, *data], bases),
    )


def _name_passages(
    passages: Sequence[Passage],
    names: Any,
    found: LedgerFacts,
    entries: dict[str, Any],
    generic: frozenset[str],
) -> tuple[list[Passage], list[NameReading]]:
    """The ``ledger.N`` facts of the names the writable passages' negated sentences write,
    each held on them (:func:`name_readings`), and every reading made.

    One fact per name, shared by every sentence naming it, filled for the conclusion
    and the limitations first, then for the value cells and capability bullets, and then
    in passage order within :data:`_NAMES_PER_QUESTION` characters; a
    name past it is not shown, its sentences not held on it, and the count is said. A
    sentence held this way is answered as a held absence of the body is (or as every
    closing sentence is): code decides none of them. The data addresses the listings name
    are read first (:func:`_hold_listed_data`, T-652)."""
    _hold_listed_data(names, found, entries)
    listed = {routine.address: routine.listed_in for routine in found.listed}
    # The conclusion and the limitations first, then the fields answered whole (a value
    # cell, a capability bullet), then the rest: a cell or bullet never takes a closing
    # sentence's fact (T-600).
    ordered = sorted(
        (p for p in passages if _writable(p)),
        key=lambda p: 0 if p.closing and not p.whole else 1 if p.whole else 2,
    )
    made: dict[tuple[str, str], str | None] = {}
    out: list[Passage] = []
    # The sentences each fact speaks to, by its id, in the order they are read: set on
    # the facts once every sentence is read, so each costs one look.
    speaks: dict[str, dict[str, None]] = {}
    readings: list[NameReading] = []
    used = 0
    left = 0

    def _fact(kind: str, key: str, sentence: str) -> str | None:
        nonlocal used, left
        if (kind, key) in made:
            fid = made[(kind, key)]
            if fid is not None:
                speaks[fid][sentence] = None
            return fid
        built = (
            _api_fact(key, names, listed, entries)
            if kind == "api"
            else _export_fact(key, names, listed, entries)
            if kind == "export"
            else _text_at_fact(key, names)
            if kind == "data"
            else _text_fact(key, names)
        )
        if built is None or not built.cites:
            made[(kind, key)] = None
            return None
        if used + len(built.text) > _NAMES_PER_QUESTION:
            left += 1
            made[(kind, key)] = None
            return None
        used += len(built.text)
        fid = f"ledger.{len(out) + 1}"
        out.append(
            Passage(
                id=fid,
                label="what the run's answers hold of a name a sentence denies something of",
                text=built.text,
                kind=FACT,
                cites=built.cites,
                addresses=built.addresses,
                qualifier=built.qualifier,
                names=built.values,
                row_texts=built.rows,
                row_values=built.values,
            )
        )
        speaks[fid] = {sentence: None}
        made[(kind, key)] = fid
        return fid

    for passage in ordered:
        previous = ""
        named: dict[str, list[str]] = {}
        for sentence in _sentences_of(passage.text):
            found_here = name_readings(sentence, previous, names, generic)
            previous = sentence
            readings.extend(found_here)
            for reading in found_here:
                fid = _fact(reading.kind, reading.key, sentence)
                if fid is not None:
                    named.setdefault(sentence, []).append(fid)
        if not named:
            continue
        passage.ledger_named = tuple((s, tuple(dict.fromkeys(ids))) for s, ids in named.items())
        if not passage.closing:
            passage.absences = tuple(dict.fromkeys([*passage.absences, *named]))
        passage.held = tuple(dict.fromkeys([*passage.held, *named]))
    for fact in out:
        fact.speaks_to = tuple(speaks[fact.id])
    if left:
        out.append(
            Passage(
                id=NAMES_LEFT_ID,
                label="facts of names not shown",
                text=(
                    f"{left} {'name' if left == 1 else 'names'} the ledger holds not shown: "
                    f"budget ({_NAMES_PER_QUESTION} characters of such facts per question); a "
                    "sentence held only on them is not held"
                ),
                kind=FACT,
            )
        )
    return out, readings


# How a listed routine's code was read, in the facts' words.
_LISTED_AS = "decompiled or disassembled"


def listed_routine_clause(routine: str, ids: str, verb: str) -> str:
    """The clause a section 5 sentence qualified on a listed routine gains, in its words."""
    return f"{ids} {verb} the code of the routine at {routine} ({_LISTED_AS})"


def unread_callee_clause(routine: str, callers: str, plural: str) -> str:
    """The clause a section 5 sentence qualified on an unread callee gains, in its words.

    The renderers read it back by these words (``renderers.prose_forms``) to
    print a long caller list as a list.
    """
    return (
        f"the routine at {routine}, called by the read {plural} at {callers}, has no listed "
        "code (decompiled or disassembled)"
    )


def _ledger_passages(
    entries: Sequence[Any],
    shown: Sequence[Passage],
    found: LedgerFacts | None = None,
    also: Iterable[int] = (),
) -> list[Passage]:
    """The ledger's facts as passages: the unread callees, the listed routines, then each
    failed call answered later.

    An unread callee is a fact of its own where a passage shown names its
    address; the ones no passage names are one count, citing nothing: a
    routine no passage names bears on no sentence by its address, and listing
    each one per caller cost the prompt more than every fact of its own. A
    routine whose code an entry lists is a fact only where a passage shown
    names it in a sentence that, or whose next sentence, calls code not read or
    not in the evidence (:func:`_said_unread`): it bears on such a sentence
    (T-494) and on no other, and every read routine a passage names would be
    most of the prompt; a routine a closing passage names (``also``) is one too, as every
    closing sentence is answered (T-568). Which passage a fact bears on is the model's call.
    The addresses are the
    platform's own; a tool's name is the run's record of a server's word, one
    quoted value. ``found`` is what the ledger's facts were read as, read here
    when not given.
    """
    from malspark.reporting.agreement_facts import ledger_facts, spelled

    if not entries:
        return []
    if found is None:
        found = ledger_facts(entries)
    bases = found.image_bases
    named = _named_addresses(shown)
    out: list[Passage] = []
    left = 0
    for unread in found.unread:
        cites = _ids([*unread.read_in, *unread.stated_in])
        if _spelled_both([unread.address], bases) & named:
            plural = "routine" if len(unread.callers) == 1 else "routines"
            out.append(
                Passage(
                    id=f"unread.{len(out) + 1}",
                    label="routine a read routine calls whose code no entry lists",
                    # The entries that read the callers and state the calls are
                    # the passage's citations, listed beside it.
                    text=(
                        f"{spelled(unread.address, bases)} is called by the read {plural} at "
                        f"{_offsets(unread.callers, bases)}; {_NOT_LISTED}"
                    ),
                    kind=FACT,
                    cites=cites,
                    addresses=_spelled_both([unread.address, *unread.callers], bases),
                    on_absence=True,
                    qualifier=unread_callee_clause(
                        _offsets([unread.address], bases), _offsets(unread.callers, bases), plural
                    ),
                )
            )
            continue
        left += 1
    if left:
        out.append(
            Passage(
                id=f"unread.{len(out) + 1}",
                label="routines read routines call whose code no entry lists",
                text=(
                    f"{left} more {'routine' if left == 1 else 'routines'} that read routines "
                    f"call, none of them named by a passage; for each, {_NOT_LISTED}"
                ),
                kind=FACT,
            )
        )
    listed_facts = 0
    said_unread = _said_unread(shown) if found.listed else set()
    if found.listed:
        said_unread |= _spelled_both(also, bases)
    for listed in found.listed:
        cites = _ids(listed.listed_in)
        if not cites or not _spelled_both([listed.address], bases) & said_unread:
            continue
        ids = ", ".join(sorted(cites))
        verb = "lists" if len(cites) == 1 else "list"
        listed_facts += 1
        out.append(
            Passage(
                id=f"listed.{listed_facts}",
                label="routine whose code an entry lists",
                text=f"{spelled(listed.address, bases)}: {ids} {verb} its code ({_LISTED_AS})",
                kind=FACT,
                cites=cites,
                addresses=_spelled_both([listed.address], bases),
                on_absence=True,
                qualifier=listed_routine_clause(_offsets([listed.address], bases), ids, verb),
                lists_code=True,
            )
        )
    for index, link in enumerate(found.answered, 1):
        out.append(
            Passage(
                id=f"answered.{index}",
                label="failed call answered by a later call for the same address",
                text=(
                    f"{link.failed} ({quoted_value(link.failed_tool)}) for "
                    f"{spelled(link.address, bases)} failed; the later call {link.answered} "
                    f"({quoted_value(link.answered_tool)}) for the same address answered"
                    # The call the run summary names as its redo (``redone_calls.redo_map``).
                    + (", asking the same question again" if link.redone else "")
                ),
                kind=FACT,
                cites=_ids([link.failed, link.answered]),
                addresses=_spelled_both([link.address], bases),
                qualifier=(
                    f"a later call for {_offsets([link.address], bases)} answered it"
                    # Read only where the answer is a listing of the code there.
                    + (", so the address was not left unread" if link.answered_lists_code else "")
                ),
            )
        )
    return out


# Words that say a call failed or a reading could not be made: what holds a
# sentence of the limitations paragraph to the ledger's failed calls (T-526).
# Which sentence a fact contradicts is still the model's call.
_SAYS_FAILED = re.compile(
    r"\b(?:failed|fails|failing|errored|impossible)\b"
    r"|\b(?:was|were|is|are)\s+not\s+possible\b"
    r"|\b(?:could|can)\s*not\s+(?:be\s+)?(?:read|run|decompiled?|disassembled?|emulated?|"
    r"listed|lifted|loaded|opened|reached)\b"
    r"|\bdid\s+not\s+(?:run|complete|succeed|answer)\b",
    re.IGNORECASE,
)
# Words that say the call was redone. Read only where no negation stands within
# the three words before it ("never redone", "no later call answered it"), and
# only to tell which sentences are held: a rewrite is decided by what it cites.
# A later call is named as one or by its kind ("its code was read in a later
# disassembly of the same address", haiku13's rewrite of its own limitation).
_SAYS_REDONE = re.compile(
    r"\b(?:redone|redid|re-?ran|re-?run|retried|re-?read|re-?issued|"
    r"later\s+(?:calls?|decompil\w*|disassembl\w*|emulat\w*|listings?)|"
    r"answered\s+later)\b",
    re.IGNORECASE,
)
_NEGATION = frozenset({"no", "not", "never", "without"})
# The words before a redo word read for a negation.
_NEGATION_REACH = 3
# What a call's kind is called in prose, by the start of a word: a sentence
# naming one names every call of that kind.
_KIND_WORDS = {
    "decompil": re.compile(r"\bdecompil\w*", re.IGNORECASE),
    "disassembl": re.compile(r"\bdisassembl\w*", re.IGNORECASE),
    "emulat": re.compile(r"\bemulat\w*", re.IGNORECASE),
}
# A listing named as one of code, which is what a call that lists code is: a
# "process listing" or a "listing of the server's commands" is none.
_CODE_LISTING = re.compile(
    r"\b(?:routine|function|decompiler|disassembly|code)\s+listings?\b"
    r"|\blistings?\s+of\s+(?:the\s+|its\s+|a\s+)?(?:routine|function|code)",
    re.IGNORECASE,
)
# Any listing or lister, which the rewrite check reads as naming a call that
# lists code (``_names_call`` with ``broad``).
_ANY_LISTING = re.compile(r"\blist(?:ing|er)s?\b", re.IGNORECASE)
# Words that deny a call was ever redone, whatever the rewrite cites; read, like
# a redo word, only where no negation stands before them ("did not fail for good").
_SAYS_FOR_GOOD = re.compile(r"\bfor\s+good\b|\bpermanently\b|\bnever\s+succeeded\b", re.I)
# A tool's name shorter than this is never read as named by a sentence.
_TOOL_NAME_FLOOR = 3
# What a fact quotes of a tool's message or an analyst's question, at most.
_QUOTED_CHARS = 200


def _capped(text: Any, limit: int = _QUOTED_CHARS) -> str:
    """Text on one line, cut at ``limit`` characters with the cut marked."""
    line = " ".join(str(text or "").split())
    return line if len(line) <= limit else line[: limit - 1].rstrip() + "…"


def _negated(text: str, at: int) -> bool:
    """Whether a negation stands within the few words before ``at``."""
    before = re.findall(r"[a-z']+", text[:at].lower())[-_NEGATION_REACH:]
    return bool(_NEGATION.intersection(before))


def _says_redone(sentence: str) -> bool:
    """Whether the sentence says a call was redone, in words no negation stands before."""
    return any(not _negated(sentence, m.start()) for m in _SAYS_REDONE.finditer(sentence))


def _denies_redo(text: str) -> bool:
    """Whether the text says a call was never redone: a redo word under a negation, or a
    failure "for good", "permanently", "never succeeded" no negation stands before."""
    return any(_negated(text, m.start()) for m in _SAYS_REDONE.finditer(text)) or any(
        not _negated(text, m.start()) for m in _SAYS_FOR_GOOD.finditer(text)
    )


def _sentences_of(text: str) -> list[str]:
    """The sentences of ``text`` in the order they stand."""
    starts, _ends = _sentence_units(text)
    return [s for _at, s in sorted((at, s) for s, ats in starts.items() for at in ats)]


def _names_call(
    text: str,
    call: FailedCall,
    bases: Sequence[int],
    *,
    broad: bool = False,
    words_only: bool = False,
) -> bool:
    """Whether the text names a failed call: an address it was asked for, its tool's name
    as a whole word, or the kind its entry stored (never read off the tool's name), a
    call that lists code by a listing of code.

    ``broad`` is the rewrite check's reading, where naming a call too often only
    keeps a sentence as written: any word starting "listing" or "lister" names
    every call that lists code ("the listing tool"). The gate reads narrowly, as
    a sentence held too often costs the prompt: only a listing of code does.
    ``words_only`` reads its tool's name alone, as the rewrite check reads a
    clause, which reads the kind words itself.
    """
    if not words_only and set(_addresses_named(text)) & _spelled_both(call.asked, bases):
        return True
    tool = call.tool.lower()
    if len(tool) >= _TOOL_NAME_FLOOR:
        for spelling in dict.fromkeys((tool, tool.replace("_", " "))):
            if re.search(r"(?<![\w-])" + re.escape(spelling) + r"(?![\w-])", text, re.I):
                return True
    if words_only:
        return False
    kind = call.kind.lower()
    if any(stem in kind and word.search(text) for stem, word in _KIND_WORDS.items()):
        return True
    listing = _ANY_LISTING if broad else _CODE_LISTING
    return call.lists_code and bool(listing.search(text))


def redone_calls_named(
    sentence: str, failed: Sequence[FailedCall], bases: Sequence[int]
) -> list[FailedCall]:
    """The calls a later call redid that a negated sentence is held to (T-600), read by
    entities alone: each it names by an address the call asked for together with the call's
    tool or kind (:func:`_names_call`, the narrow listing of code among them), or cites,
    while it cites none of the calls that redid it. What the sentence says of the call or of
    the code its redo read is the model's to answer, citing a call that redid it."""
    if not carries_negation(sentence):
        return []
    cited = entry_ids_in(sentence)
    named: set[int] | None = None
    out: list[FailedCall] = []
    for call in failed:
        if not call.redone or cited & {by.lower() for by in call.redone_by}:
            continue
        if call.entry.lower() in cited:
            out.append(call)
            continue
        if not call.asked:
            continue
        if named is None:
            named = set(_addresses_named(sentence))
        if named & _spelled_both(call.asked, bases) and _names_call(
            sentence, replace(call, asked=()), ()
        ):
            out.append(call)
    return out


def _redo_choices(calls: Sequence[FailedCall]) -> tuple[str, ...]:
    """What a text naming ``calls`` must cite, once each: for each call, one of the calls
    that redid it ("ev_0063 or ev_0065")."""
    return tuple(dict.fromkeys(" or ".join(call.redone_by) for call in calls))


def _redone_calls_in(
    text: str, failed: Sequence[FailedCall], bases: Sequence[int]
) -> list[FailedCall]:
    """The calls the sentences of ``text`` are held to (:func:`redone_calls_named`), once
    each, in the order they are read."""
    return list(
        dict.fromkeys(
            call
            for sentence in _sentences_of(text)
            for call in redone_calls_named(sentence, failed, bases)
        )
    )


def _stale_citations(sentence: str, redone: Sequence[FailedCall]) -> list[FailedCall]:
    """The redone calls a sentence cites without citing a call that redid them."""
    cited = entry_ids_in(sentence)
    return [
        call
        for call in redone
        if call.entry.lower() in cited and not cited & {by.lower() for by in call.redone_by}
    ]


def held_limitation_sentences(
    text: str, failed: Sequence[FailedCall], listed: Iterable[int], bases: Sequence[int]
) -> list[str]:
    """The sentences of a limitations paragraph held to the ledger's failed calls.

    A negated sentence naming a call a later call redid by an address it asked for and
    its tool or kind, or citing it, and citing none of the calls that redid it, is held
    (:func:`redone_calls_named`, T-600), whatever else it says. A sentence that says a
    call failed or a reading could not be made is held where it cites a failed call a
    later call redid and none of the calls that redid it, whatever else it says; and,
    where it does not say the call was redone, where it names a redone call
    (:func:`_names_call`: an address it was asked for, its tool, its kind) or an address
    whose code an entry lists, whatever it cites. A sentence of a sample's behaviour
    ("the beacon failed to connect", "the process listing failed") names none. One pass
    over the sentences.
    """
    redone = [call for call in failed if call.redone]
    listed = _spelled_both(listed, bases)
    if not redone and not listed:
        return []
    held: list[str] = []
    for sentence in _sentences_of(text):
        if redone_calls_named(sentence, redone, bases):
            held.append(sentence)
            continue
        if not _SAYS_FAILED.search(sentence):
            continue
        if _stale_citations(sentence, redone):
            held.append(sentence)
            continue
        if _says_redone(sentence):
            continue
        if set(_addresses_named(sentence)) & listed or any(
            _names_call(sentence, call, bases) for call in redone
        ):
            held.append(sentence)
    return held


def _clauses_of(text: str) -> list[str]:
    """The clauses of ``text``: its sentences, each cut at its semicolons."""
    return [part for sentence in _sentences_of(text) for part in sentence.split(";") if part]


def _stems_of(call: FailedCall) -> set[str]:
    """The kind words a call answers to: its stored kind's stems, and a listing where it
    lists code."""
    kind = call.kind.lower()
    stems = {stem for stem in _KIND_WORDS if stem in kind}
    if call.lists_code:
        stems.add("listing")
    return stems


def _stale_calls(
    text: str,
    failed: Sequence[FailedCall],
    bases: Sequence[int],
    *,
    broad: bool,
    sourced: Sequence[FailedCall] = (),
) -> list[FailedCall]:
    """The redone calls ``text`` says failed for good, clause by clause.

    In each clause a redone call is named where the clause cites it or a call
    that redid it, writes its tool's name whole, or (``broad`` only) an address
    it was asked for; and by a kind word ("decompiling", or with ``broad`` any
    "listing"), every redone call of that kind, unless the clause, or a fact the
    row rests on (``sourced``), already accounts for a call of that kind. A
    named call is stale where no call that redid it is cited anywhere in the
    text, or where its own clause denies the redo (:func:`_denies_redo`). With
    ``broad``, each redone call of ``sourced`` is named too.
    """
    redone = [call for call in failed if call.redone]
    if not redone:
        return []
    cited_all = entry_ids_in(text)

    def _ids_of(call: FailedCall) -> set[str]:
        return {call.entry.lower(), *(by.lower() for by in call.redone_by)}

    def _redo_cited(call: FailedCall) -> bool:
        return bool(cited_all & {by.lower() for by in call.redone_by})

    sourced_stems = set().union(*(_stems_of(call) for call in sourced)) if sourced else set()
    stale: list[FailedCall] = []
    before: list[FailedCall] = []
    for clause in _clauses_of(text):
        cited = entry_ids_in(clause)
        named = [
            call
            for call in redone
            if cited & _ids_of(call)
            or _names_call(clause, call, (), words_only=True)
            or (broad and bool(set(_addresses_named(clause)) & _spelled_both(call.asked, bases)))
        ]
        # A kind word names its kind's calls, unless the clause or the row's
        # facts account for a call of that kind already.
        accounted: set[str] = set()
        for call in failed:
            if cited & _ids_of(call):
                accounted |= _stems_of(call)
        said = {stem for stem, word in _KIND_WORDS.items() if word.search(clause)}
        if broad and _ANY_LISTING.search(clause):
            said.add("listing")
        for stem in sorted(said - accounted):
            # The facts the row rests on account for their calls of the kind,
            # which the clause then speaks of; else it names every one. In the
            # stems' order, so the finding reads the same in every run.
            of_kind = [c for c in sourced if stem in _stems_of(c)] if stem in sourced_stems else []
            pool = of_kind or [c for c in redone if stem in _stems_of(c)]
            named.extend(c for c in pool if c.redone and c not in named)
        denied = _denies_redo(clause)
        if denied and not named:
            # A denial of its own ("; it was never redone", ". It never
            # succeeded") is about the calls the clause before it named.
            stale.extend(call for call in before if call not in stale)
        for call in named:
            if (denied or not _redo_cited(call)) and call not in stale:
                stale.append(call)
        before = named
    if broad:
        for call in sourced:
            if call.redone and not _redo_cited(call) and call not in stale:
                stale.append(call)
    return stale


def _failure_cited_check(
    failed: Sequence[FailedCall], passage: Passage
) -> Callable[[str, Sequence[str], str, str], list[Violation]]:
    """What a rewrite of the section 5 ``passage`` is held to while the limitation facts are
    shown: by its citations alone, it cites no failed call a later call redid that the
    sentence it replaces did not cite, unless it cites a call that redid it. No kind word
    and no address is read: the platform's own fact clauses write them."""
    redone = [call for call in failed if call.redone]

    def _check(
        rewrite: str, sources: Sequence[str], sentence: str = "", _kept: str = ""
    ) -> list[Violation]:
        cited, had = entry_ids_in(rewrite), entry_ids_in(sentence)
        stale = [
            call
            for call in redone
            if call.entry.lower() in cited
            and call.entry.lower() not in had
            and not cited & {by.lower() for by in call.redone_by}
        ]
        return (
            _failure_redone_violation(stale, otherwise=_otherwise(passage, sentence))
            if stale
            else []
        )

    return _check


def _failure_redone_violation(
    stale: Sequence[FailedCall],
    says_failed: bool = True,
    *,
    otherwise: str = "",
    held: Sequence[FailedCall] = (),
    of_held: bool = False,
    unredone: bool = False,
    keep: bool = False,
) -> list[Violation]:
    """The finding on a text naming calls a later call redid: one saying a call failed is
    told the call was redone; one held only by the calls it names
    (:func:`redone_calls_named`) is told what it may do: a rewrite in its own words on what
    the calls that redid them answered, citing them, or a drop. The same words with a
    citation added are a keep (:func:`repeats_sentence`), so they are no way out.

    ``otherwise``: what the sentence the text answers may do instead (:func:`_otherwise`),
    offered beside citing the redo, where a keep of it passes. ``""``: the text answers a
    sentence of a closing passage where a keep of it is refused (the limitations sentence
    saying a redone call failed, a closing sentence the ledger's lines hold): it is told to
    rewrite citing the calls that redid it, or to drop it.
    ``held``: the redone calls the sentence a rewrite replaces is held to; the rewrite
    cites none of the calls that redid ``stale``, some or all of them, and is told the ends
    a keep of that sentence is told, for every call in ``held``.
    ``of_held``: the text answers a sentence the ledger's lines hold (a keep of it), whose
    rewrite is told to cite each denial (:func:`_denial_cited`, with ``unredone``: a failed
    call no later call redid is among the facts shown), as with ``held``.
    ``keep``: the text is a keep, read as its own text: it is told what it says, never what a
    rewrite still says, and ``otherwise`` is the keep that passes for its sentence."""
    said = "; ".join(f"{call.entry} by {', '.join(call.redone_by)}" for call in stale)
    choices = _redo_choices(held or stale)
    ends = (
        _cite_redo(choices, otherwise)
        if says_failed and otherwise and not held
        else _failed_ends(choices, held=bool(held) or of_held, unredone=unredone)
        if says_failed
        else _redone_ends(choices, held=bool(held) or of_held, unredone=unredone)
    )
    return [
        Violation(
            code=FAILURE_REDONE_CODE,
            message=(
                (
                    "it replaces a sentence held to a call that failed and a later call redid "
                    f"({safe_finding_value(said)}) and cites none of the calls that redid it. "
                    if len(stale) == 1
                    else "it replaces a sentence held to calls that failed and later calls "
                    f"redid ({safe_finding_value(said)}) and cites none of the calls that redid "
                    "them. "
                )
                + _sentence_start(ends)
                if held
                else "the rewrite still says a call failed or a reading could not be made, "
                f"but a later call redid it ({safe_finding_value(said)}). " + _sentence_start(ends)
                if says_failed and otherwise and not keep
                else "it says a call failed or a reading could not be made, while a later call "
                f"redid it ({safe_finding_value(said)}). " + _sentence_start(ends)
                if says_failed
                else "it names a call that failed and a later call redid "
                f"({safe_finding_value(said)}) and cites none of the calls that redid it. "
                + _sentence_start(ends)
            ),
            path="rewrite",
        )
    ]


def _failure_redone_check(
    failed: Sequence[FailedCall],
    facts: Sequence[Passage],
    bases: Sequence[int],
    held: Mapping[str, tuple[bool, Sequence[FailedCall]]],
) -> Callable[[str, Sequence[str], str, str], list[Violation]]:
    """What a rewrite of the limitations paragraph is held to: it says no call failed for
    good that a later call redid.

    A rewrite of a sentence ``held`` to redone calls (whether it says a call failed, and
    the calls) cites, for each of those calls, one of the calls that redid it, read by its
    entry ids alone; else it is told the ends a keep of the sentence is told
    (:func:`_failure_redone_violation`).

    A rewrite that says a call failed fails for each redone call it cites,
    rests on (a fact among its sources citing that call: a failed-call fact,
    an answered-later fact, an open question) or names, read clause by clause
    and broadly (:func:`_stale_calls`), unless it cites a call that redid it
    and the clause naming it does not deny the redo. Its words for a redo
    never pass it alone. Any other fails for exactly the redone calls its
    sentences are held to (:func:`redone_calls_named`), the ones the question
    names for it. ``facts`` are the facts shown, read when the check runs. The check's
    fourth argument is what the sentence may do instead where a keep of it passes
    (:func:`_otherwise`, ``""`` where none does): a text refused for a redone call is told it
    beside citing the calls that redid them, as for any other passage.
    """

    # Whether the facts shown hold a failed call no later call redid, which a denial in a
    # rewrite of a held sentence may rest on (``Passage.unredone_failed``).
    unredone = any(not call.redone for call in failed)

    def _check(
        rewrite: str, sources: Sequence[str], sentence: str = "", kept: str = ""
    ) -> list[Violation]:
        says, calls = held.get(sentence, (False, ()))
        cited = entry_ids_in(rewrite)
        uncited = [call for call in calls if not cited & {by.lower() for by in call.redone_by}]
        if uncited:
            return _failure_redone_violation(uncited, says, held=calls, unredone=unredone)
        says_failed, stale = _failure_redone_calls(rewrite, sources, failed, facts, bases)
        # A keep is read as its own text (``sentence`` empty): held, it is told so.
        of_held = (sentence or rewrite) in held
        return (
            _failure_redone_violation(
                stale,
                says_failed,
                otherwise=kept,
                of_held=of_held,
                unredone=unredone,
                keep=not sentence,
            )
            if stale
            else []
        )

    return _check


def _failure_redone_calls(
    text: str,
    sources: Sequence[str],
    failed: Sequence[FailedCall],
    facts: Sequence[Passage],
    bases: Sequence[int],
) -> tuple[bool, list[FailedCall]]:
    """Whether a text of the limitations paragraph says a call failed, and the redone
    calls it is held to (:func:`_failure_redone_check`)."""
    if not _SAYS_FAILED.search(text):
        # Held by the calls its sentences name or cite alone: those, and no other, are
        # what it is told to cite, as the question names them.
        return False, _redone_calls_in(text, failed, bases)
    by_entry = {call.entry.lower(): call for call in failed}
    by_id = {fact.id: fact for fact in facts}
    sourced: list[FailedCall] = []
    for source in sources:
        fact = by_id.get(_form(source))
        for entry in sorted(fact.cites & by_entry.keys()) if fact is not None else ():
            if by_entry[entry] not in sourced:
                sourced.append(by_entry[entry])
    return True, _stale_calls(text, failed, bases, broad=True, sourced=sourced)


def _failure_added_check(
    failed: Sequence[FailedCall], passage: Passage
) -> Callable[[str, Sequence[str], str, str], list[Violation]]:
    """What a rewrite of ``passage``, any other than the limitations paragraph, is held to
    while the limitation facts are shown: it adds no failure of a call a later call redid.

    Read narrowly (:func:`_stale_calls` without ``broad``: the ids it cites, a
    tool's name, a kind word; never an address or a bare listing, which a
    sentence of the sample's behaviour writes), and only for what the rewrite
    adds: a failure the sentence it replaces did not claim, or a redone call
    it did not name. A rewrite that keeps what the sentence said passes. The finding
    offers a closing sentence no keep passes for (:func:`_closing_ends`) a drop, and so a
    keep of a closing sentence, read as its own text (no ``sentence``), which it refuses; any
    other the keep that passes for it (:func:`_otherwise`, :func:`_failure_redone_violation`).
    """

    def _check(
        rewrite: str, sources: Sequence[str], sentence: str = "", kept: str = ""
    ) -> list[Violation]:
        if not _SAYS_FAILED.search(rewrite):
            return []
        stale = _stale_calls(rewrite, failed, (), broad=False)
        if not stale:
            return []
        if _SAYS_FAILED.search(sentence):
            before = _stale_calls(sentence, failed, (), broad=False)
            stale = [call for call in stale if call not in before]
        # A keep, read as its own text (``sentence`` empty), is told what its caller says a
        # keep of it may do instead (``kept``: ``""`` where none passes); a closing sentence
        # no keep passes for, its ends (``""``); any other, what passes for it.
        otherwise = (
            kept
            if not sentence
            else ""
            if _closing_ends(passage, sentence)
            else _otherwise(passage, sentence)
        )
        return (
            _failure_redone_violation(stale, otherwise=otherwise, keep=not sentence)
            if stale
            else []
        )

    return _check


def _limitation_passages(
    report: MalwareReport,
    entries: Sequence[Any],
    found: LedgerFacts | None,
    shown_facts: Sequence[Passage] = (),
) -> tuple[list[Passage], list[Passage], list[FailedCall]]:
    """The limitations paragraph where it is held to the failed calls, the limitations
    inventory's rows as facts, and the failed calls those rows show.

    The rows (``inv.N``, :func:`_inventory_passages`) are shown wherever the composed
    paragraph stands, read off the report's limitations inventory, or built from the
    ledger for a report stored without one (T-601). The paragraph is held this way only
    where a sentence of it is held to the ledger (:func:`held_limitation_sentences`): a
    paragraph that agrees with the ledger, or one written where no call failed, stays the
    closing passage it is (:func:`passages_of`), and the first list is empty. ``shown_facts``
    are the facts shown before these, which a rewrite may rest on too.
    """
    from malspark.reporting.limitation_facts import limitation_facts

    ta = report.technical_analysis
    sub = ta.analyst_limitations if ta is not None else None
    if not isinstance(sub, TechnicalSubsection) or not sub.body.strip() or found is None:
        return [], [], []
    bases = found.image_bases
    read = limitation_facts(report, entries, found.answered, bases, found.redone)
    inventory = report.limitation_inventory
    if inventory is None:
        from malspark.reporting.limitation_inventory import build_inventory

        inventory = build_inventory(report, entries)
    facts = _inventory_passages(inventory, read, bases)
    failed = list(read.failed)
    # A paragraph that says a call failed, or names a failed call (an address it was
    # asked for, its tool, its kind) or cites one, is read further (T-600).
    cited = entry_ids_in(sub.body)
    if not _SAYS_FAILED.search(sub.body) and not any(
        call.entry.lower() in cited or _names_call(sub.body, call, bases) for call in read.failed
    ):
        return [], facts, failed
    listed = [routine.address for routine in found.listed]
    held = held_limitation_sentences(sub.body, read.failed, listed, bases)
    if not held:
        return [], facts, failed
    # The sentences held by the redone calls they name, with the calls that redid them:
    # the entries a keep must cite (T-600).
    redone_named = []
    failure_said = []
    # Each held this way, with whether it says a call failed and its calls: what a rewrite
    # of it cites.
    held_to: dict[str, tuple[bool, Sequence[FailedCall]]] = {}
    for sentence in held:
        calls = redone_calls_named(sentence, read.failed, bases)
        if calls:
            redone_named.append((sentence, _redo_choices(calls)))
            held_to[sentence] = (False, calls)
            continue
        # A sentence saying a redone call failed, as the failure check reads a keep of it.
        says, stale = _failure_redone_calls(sentence, (), read.failed, (), bases)
        if says and stale:
            failure_said.append((sentence, _redo_choices(stale)))
            held_to[sentence] = (True, stale)
    paragraph = Passage(
        id="limitations",
        label=(
            "11. Limitations, the composed paragraph (each sentence saying a call failed or a "
            "reading could not be made is held to the failed calls, the tools not run, the "
            "recorded limitations and the open questions among the facts)"
        ),
        text=sub.body,
        kind=CLAIM_LED,
        cites=_ids(sub.evidence_refs, sub.body),
        write=_setter(sub, "body"),
        sourced_check=_failure_redone_check(read.failed, [*shown_facts, *facts], bases, held_to),
        closing=True,
        redone_named=tuple(redone_named),
        failure_said=tuple(failure_said),
        unredone_failed=_ids([call.entry for call in read.failed if not call.redone]),
    )
    return [paragraph], facts, failed


# The label every row of the limitations inventory is shown under.
_INVENTORY_LABEL = "limitations inventory row, measured by the platform"


def _inventory_passages(
    inventory: LimitationInventory, read: LimitationFacts, bases: Sequence[int]
) -> list[Passage]:
    """The limitations inventory's rows as the round's facts, ``inv.1`` onwards (T-601).

    Each failed call with the later calls that redid it, or, where none did, the ones that
    answered for some of its addresses (one fact each, citing the call and its redo, which
    the paragraph's failure check reads its sources by); then every other row of the
    inventory in its own words (``limitation_inventory.inventory_rows``), a reason the run
    recorded one quoted value cut at :data:`_QUOTED_CHARS` characters with the cut marked;
    after the open questions' row, each one filed on a failed call or a missing tool
    (:func:`_open_question_facts`). Which sentence a row bears on is the model's call.
    """
    from malspark.reporting.limitation_inventory import (
        FAILED,
        QUESTIONS,
        REDONE,
        inventory_rows,
    )

    facts: list[Passage] = []

    def _add(label: str, text: str, cites: Iterable[str] = (), **more: Any) -> None:
        facts.append(
            Passage(
                id=f"inv.{len(facts) + 1}",
                label=label,
                text=text,
                kind=FACT,
                cites=_ids(list(cites)),
                **more,
            )
        )

    for call in inventory.failed:
        if call.redone_by:
            ids = ", ".join(call.redone_by)
            # A call asked for no address was redone by the same question asked again
            # (``redone_calls``): no empty address list is written (T-568).
            asked = (
                f"answered for every address it asked ({_offsets(list(call.asked), bases)})"
                if call.asked
                else "asked the same question again and was answered"
            )
            after = (
                f"the later call{'s' if len(call.redone_by) > 1 else ''} {ids} {asked}, so it "
                "did not fail for good"
            )
        elif call.answered:
            answered = dict(call.answered)
            missing = [a for a in call.asked if a not in answered]
            by = ", ".join(dict.fromkeys(answered.values()))
            after = f"later calls answered for {_offsets(list(answered), bases)} ({by})" + (
                f"; none for {_offsets(missing, bases)}"
                if missing
                else "; none asked the same question whole, so it is not read as redone"
            )
        elif call.asked:
            after = f"no later call answered for {_offsets(list(call.asked), bases)}"
        else:
            after = "it asked for no address, so no later call is read as its redo"
        _add(
            "tool call that failed, and whether a later call redid it",
            f"{call.entry} ({quoted_value(call.tool)}) failed: "
            f"{quoted_value(_capped(call.error))}; {after}",
            [call.entry, *call.redone_by],
            addresses=_spelled_both(call.asked, bases),
        )
    for row in inventory_rows(inventory, quote=lambda text: quoted_value(_capped(text))):
        if row.part in (FAILED, REDONE):
            continue
        if row.part == QUESTIONS:
            _add(_INVENTORY_LABEL, row.text, row.cites)
            for fact in _open_question_facts(read.questions, read.failed, bases):
                _add(fact.label, fact.text, fact.cites, addresses=fact.addresses)
            continue
        _add(_INVENTORY_LABEL, row.text, row.cites)
    return facts


def _open_question_facts(
    questions: Sequence[Any], failed: Sequence[FailedCall], bases: Sequence[int]
) -> list[Passage]:
    """Each open question filed on a failed call or a missing tool.

    A question is marked where a later call redid a failed call for an
    address it names, or a failed call it cites: an analyst may have
    filed it on that failure, which did not stand. Whether the question is
    answered is the model's reading; the mark says only what the ledger says.
    It is shown, never dropped. The others are counted in the inventory's own row.
    """
    from malspark.reporting.limitation_facts import FAILURE_REASONS

    redid: dict[int, tuple[str, str]] = {}
    for call in failed:
        if not call.redone:
            continue
        for address in call.asked:
            for spelling in _spelled_both([address], bases):
                redid.setdefault(spelling, (call.entry, ", ".join(call.redone_by)))
    by_entry = {call.entry.lower(): call for call in failed if call.redone}
    out: list[Passage] = []
    for question in questions:
        if question.reason not in FAILURE_REASONS:
            continue
        marks: dict[str, tuple[str, str]] = {}
        for address in question.addresses:
            if address in redid:
                failed_id, by = redid[address]
                marks.setdefault(
                    f"the failed call {failed_id} for {_offsets([address], bases)}, an address "
                    "it names,",
                    (failed_id, by),
                )
        for cited in question.cites:
            redone = by_entry.get(cited.lower())
            if redone is not None:
                marks.setdefault(
                    f"the failed call {redone.entry} it cites",
                    (redone.entry, ", ".join(redone.redone_by)),
                )
        said = "; ".join(f"{what} was answered by {by}" for what, (_id, by) in marks.items())
        out.append(
            Passage(
                id=f"open.{len(out) + 1}",
                label="open question an analyst filed on a failed call or a missing tool",
                text=(
                    f"{quoted_value(_capped(question.question))}, filed as {question.reason}"
                    + (f"; redone: {said}" if said else "")
                ),
                kind=FACT,
                cites=_ids([*question.cites, *(i for pair in marks.values() for i in pair)]),
                addresses=_spelled_both(question.addresses, bases),
            )
        )
    return out


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def _mediator_name() -> str:
    from malspark.core.config import MEDIATOR_AGENT_NAME

    return MEDIATOR_AGENT_NAME


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------


class AgreementRow(BaseModel):
    """One sentence as the report model answers for it."""

    model_config = ConfigDict(extra="ignore")

    passage: str = Field(min_length=1)
    sentence: str = Field(min_length=1)
    # Every row but one on a closing sentence names its sources; the row checks
    # say which (``_row_violations``), as the schema cannot see the passage.
    sources: list[str] = Field(default_factory=list)
    decision: Literal["keep", "rewrite", "drop"]
    rewrite: str = ""
    # A kept closing sentence: the words of a named source that state the same.
    quote: str = ""
    # A closing sentence kept with no source, or left out: why, in the model's words.
    reason: str = ""

    @model_validator(mode="after")
    def _a_rewrite_is_written(self) -> AgreementRow:
        if self.decision == "rewrite" and not self.rewrite.strip():
            raise ValueError("a row whose decision is rewrite gives the rewritten sentence")
        if self.decision == "drop" and not self.reason.strip():
            raise ValueError("a row whose decision is drop gives the reason")
        return self


class AgreementOutput(BaseModel):
    """The round's answer: one row per sentence that says otherwise, or none."""

    model_config = ConfigDict(extra="ignore")

    sentences: list[AgreementRow] = Field(default_factory=list)


def _rows(payload: Any) -> list[tuple[int, AgreementRow]]:
    """Each row of the payload that fits the schema, with its place.

    A row that does not fit costs only itself.
    """
    raw = payload.get("sentences") if isinstance(payload, dict) else None
    out: list[tuple[int, AgreementRow]] = []
    for index, row in enumerate(raw if isinstance(raw, list) else []):
        try:
            out.append((index, AgreementRow.model_validate(row)))
        except Exception:  # noqa: BLE001 — the schema check says why
            continue
    return out


def _sentence_units(text: str) -> tuple[dict[str, list[int]], set[int]]:
    """Where each sentence of ``text`` starts, by its words, and where each one ends.

    A sentence ends after a ``.``, ``!`` or ``?`` (and any closing quote or
    bracket after it) that a space or the end follows, or at a line break,
    or at the end of the text. One pass. A sentence is keyed by its text from
    its first character to its end, so a copied sentence is found whole by its
    words.
    """
    starts: dict[str, list[int]] = {}
    ends: set[int] = set()
    length = len(text)
    at = 0
    while at < length and text[at].isspace():
        at += 1
    begin = at
    while at < length:
        char = text[at]
        stop = None
        if char in "\n\r":
            stop = at
        elif char in ".!?":
            after = at + 1
            while after < length and text[after] in "\"')]":
                after += 1
            if after == length or text[after].isspace():
                stop = after
                at = after - 1
        if stop is not None:
            end = stop
            while end > begin and text[end - 1].isspace():
                end -= 1
            if end > begin:
                starts.setdefault(text[begin:end], []).append(begin)
                ends.add(end)
            at = stop
            while at < length and text[at].isspace():
                at += 1
            begin = at
            continue
        at += 1
    end = length
    while end > begin and text[end - 1].isspace():
        end -= 1
    if end > begin:
        starts.setdefault(text[begin:end], []).append(begin)
        ends.add(end)
    return starts, ends


class _Sentences:
    """One passage's sentences, cut once, for every row about the passage."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts, self.ends = _sentence_units(text)

    def span(self, sentence: str) -> tuple[int, int, str, int] | None:
        """Where the one sentence copied stands, once, or ``None``.

        As copied, or with the escapes a quoted value is shown with read back
        (``written_forms.pack_reads``): the model was shown each passage quoted.
        The last item says which: ``-1`` as copied, else the reading's place in
        ``pack_reads``, so a rewrite is read back the same way. It has to be
        exactly one sentence of the passage, standing there exactly once; a
        fragment, a word, a run of sentences or a sentence the passage writes
        twice is not one.
        """
        for reading, form in enumerate((sentence, *pack_reads(sentence)), -1):
            copied = form.strip()
            found = self.starts.get(copied, []) if copied else []
            if len(found) == 1:
                return found[0], found[0] + len(copied), copied, reading
        return None


def located(text: str, sentence: str) -> str | None:
    """The spelling of ``sentence`` that stands whole and once in ``text``, or ``None``."""
    span = _Sentences(text).span(sentence)
    return span[2] if span else None


def _form(value: Any) -> str:
    return str(value or "").strip().strip("[]").strip()


def _writable(passage: Passage) -> bool:
    """Whether a sentence of the passage may be rewritten: prose written without the code,
    or section 5 prose, whose rows rest on facts alone (``_row_violations``)."""
    return passage.write is not None and passage.kind in (CLAIM_LED, SECTION_5)


# What else grounds a rewrite of a held absence of section 5, as the refusals say (T-652).
_HELD_ABSENCE_GROUNDS = (
    "; a held absence of section 5 also by a source that speaks of it, a passage written "
    "without the code where it names an address the sentence's passage names and a fact holds"
)


def _an_open_question(source: Passage) -> bool:
    """Whether ``source`` is the fact of a question an analyst left open (``open.N``, and its
    ``inv.N`` copy): its words, and the addresses read off them, are an analyst's, so it
    states nothing to say otherwise with and holds no address of the ledger's."""
    return source.kind == FACT and "open question" in source.label


def _ledger_named(passage: Passage, by_id: dict[str, Passage]) -> frozenset[int]:
    """The addresses ``passage`` names that a fact shown holds (a routine, a slot, a datum
    the ledger's own lines name): a constant both passages write is no such address, nor
    one only an open question names (:func:`_an_open_question`)."""
    held = frozenset().union(
        *(s.addresses for s in by_id.values() if s.kind == FACT and not _an_open_question(s))
    )
    return frozenset(_addresses_named(passage.text)) & held


def _tied(source: Passage, held: frozenset[int]) -> bool:
    """Whether ``source`` speaks of a held absence of section 5 and grounds its rewrite
    beyond the facts and section 5: any source but a passage written without the code, and
    one of those where it names an address of ``held`` (:func:`_ledger_named`), so a claim
    about another routine, file or family sharing only words, or a constant, does neither;
    and then a keep on the reason passes where no other source speaks (T-652)."""
    if source.kind != CLAIM_LED:
        return True
    return not held.isdisjoint(_addresses_named(source.text))


def _listed_when_kept(passage: Passage) -> bool:
    """Whether a kept sentence of the passage is recorded as listed: section 5, or read only; a
    passage printed in its writer's own words is counted, as a closing keep is (T-613)."""
    return (passage.kind == SECTION_5 or not _writable(passage)) and not passage.verbatim


def _row_violations(
    row: AgreementRow,
    index: int,
    by_id: dict[str, Passage],
    sentences_of: Callable[[Passage], _Sentences],
) -> list[Violation]:
    """What is structurally wrong with one row, against the passages shown."""
    path = f"sentences.{index}"
    passage = by_id.get(_form(row.passage))
    if passage is None or passage.kind not in (CLAIM_LED, SECTION_5):
        return [
            Violation(
                code=UNKNOWN_PASSAGE_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)} names the passage "
                    f"{safe_finding_value(row.passage)!r}, "
                    "which is not one of the passages listed for you to answer for. Name a "
                    "passage by its id in square brackets as the list writes it."
                ),
                path=f"{path}.passage",
            )
        ]
    out: list[Violation] = []
    if row.decision == "rewrite" and passage.verbatim:
        # Its writer's own words: a rewrite would not be them (T-613).
        out.append(
            Violation(
                code=UNKNOWN_PASSAGE_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)}: {safe_finding_value(passage.id)} "
                    f"prints {safe_finding_value(passage.verbatim)} and is never rewritten: "
                    f"{_VERBATIM_ENDS}."
                ),
                path=f"{path}.decision",
            )
        )
    elif row.decision == "rewrite" and not _writable(passage):
        out.append(
            Violation(
                code=UNKNOWN_PASSAGE_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)}: {safe_finding_value(passage.id)} is "
                    "shown for reading: list its sentence with the decision keep; it is not "
                    "rewritten."
                ),
                path=f"{path}.decision",
            )
        )
    span = sentences_of(passage).span(row.sentence)
    if span is None:
        out.append(
            Violation(
                code=SENTENCE_NOT_FOUND_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)}: the sentence does not stand in "
                    f"{safe_finding_value(passage.id)} as copied. {_COPY_THE_SENTENCE}; it "
                    "must stand there once."
                ),
                path=f"{path}.sentence",
            )
        )
    sources = [by_id.get(_form(source)) for source in row.sources]
    # A section 5 sentence calling something absent from the whole code read
    # names nothing a fact is about: it may rest on a fact or a section 5
    # passage, never on a debate round, nor on another model's claim unless that
    # claim speaks of a held absence (T-562, T-652, below).
    whole = span is not None and _in_own_words(passage, span[2], sources)
    in_words = span is not None and (
        _whole_code_sentence(passage, span[2])
        or (passage.kind == SECTION_5 and bool(_decisive_unread(passage, span[2])))
        or (passage.kind == SECTION_5 and span[2] in passage.on_fact)
    )
    # A held absence of the body kept on a passage that states the same absence: any
    # passage but its own, since a keep changes no word of it (T-580).
    absent_keep = (
        row.decision == "keep"
        and span is not None
        and not passage.closing
        and span[2] in passage.absences
    )
    allowed = (
        (FACT, SECTION_5, DEBATE, CLAIM_LED)
        if absent_keep
        else (FACT, SECTION_5)
        if in_words
        else (FACT,)
        if passage.kind == SECTION_5
        else (FACT, SECTION_5, DEBATE)
    )
    # A held absence of section 5 rewritten rests on any source that speaks of it
    # (:func:`_body_speaking`), a passage written without the code included where it names
    # an address of the sentence's passage a fact holds (:func:`_tied`): the passage stating
    # what it denies is the one that says otherwise of it (T-652).
    widened = (
        row.decision == "rewrite"
        and span is not None
        and passage.kind == SECTION_5
        and not passage.closing
        and span[2] in passage.absences
    )
    speaking = (
        frozenset(pid for pid, _excerpt in _body_speaking(span[2], by_id, passage))
        if widened
        and span is not None
        and any(s is not None and s.kind not in allowed for s in sources)
        else frozenset()
    )
    # A drop of a body sentence nothing holds is refused for that alone
    # (:func:`_answer_violations`): the sources it names ask nothing more.
    unheld_drop = (
        row.decision == "drop"
        and not passage.closing
        and span is not None
        and not _held_by_the_ledger(passage, span[2])
    )
    wrong = [
        _form(name)
        for name, source in zip(row.sources, sources, strict=True)
        if source is None
        or (source.kind not in allowed and source.id not in speaking)
        # A sentence answered in the model's words never rests on its own
        # passage: that would state what the passage says otherwise of.
        or ((in_words or absent_keep) and source.id == passage.id)
        # The count of listings left out says nothing of the code: no rewrite rests on it.
        or (row.decision == "rewrite" and source.id == LISTINGS_LEFT_ID)
    ]
    if unheld_drop:
        wrong = []
    if wrong:
        out.append(
            Violation(
                code=UNKNOWN_SOURCE_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)} names "
                    f"{safe_finding_value(', '.join(wrong))} as what "
                    f"states otherwise than {safe_finding_value(passage.id)}, but "
                    + (
                        "a section 5 passage is answered by a platform fact (bound.N, "
                        "unread.N, listed.N, answered.N, ledger.N) alone"
                        + (f"{_HELD_ABSENCE_GROUNDS}." if widened else ".")
                        if passage.kind == SECTION_5
                        else "only the facts, the section 5 passages and the debate rounds "
                        "listed are sources."
                    )
                    + f" {_NAME_THE_SOURCES}"
                ),
                path=f"{path}.sources",
            )
        )
    decisive = _decisive_unread(passage, span[2]) if span is not None else ()
    if passage.closing and span is not None:
        # A closing rewrite calls no routine unread that a listing it rests on, or
        # one about any routine the sentence names, shows read (T-568).
        named = frozenset(_addresses_named(span[2]))
        decisive = (
            *decisive,
            *(s.id for s in sources if s is not None and s.lists_code),
            *(f.id for f in by_id.values() if f.lists_code and not f.addresses.isdisjoint(named)),
        )
    if row.decision == "rewrite" and decisive:
        facts = [f for f in (by_id.get(i) for i in dict.fromkeys(decisive)) if f is not None]
        if any(
            ids if passage.closing else own
            for _s, ids, own in unread_listed_sentences(row.rewrite, facts)
        ):
            out.append(
                replace(
                    _unread_standing(
                        passage,
                        span[2] if span else row.sentence,
                        facts,
                        _unread_end(passage, span[2] if span else row.sentence, row, by_id),
                        row.rewrite,
                    ),
                    path=f"{path}.rewrite",
                )
            )
    out.extend(_answer_violations(row, index, passage, sources, span, by_id))
    if row.decision == "rewrite" and passage.check is not None:
        # What the field the passage stands in holds its text to holds the
        # rewrite too: a procedure stays one sentence carrying its values.
        out.extend(
            replace(
                violation,
                message=(
                    f"row {safe_finding_value(index + 1)}: the rewrite of "
                    f"{safe_finding_value(passage.id)}: {safe_finding_value(violation.message)}"
                ),
                sentence="",
                path=f"{path}.rewrite",
            )
            for violation in passage.check(row.rewrite)
        )
    if row.decision == "rewrite" and passage.sourced_check is not None:
        out.extend(
            replace(
                failure_finding,
                # The finding of a failure check (:func:`_failure_redone_violation`) is the
                # platform's words, each value in it already made fit to print: whole, so
                # what it says to do is never cut off.
                message=(
                    f"row {safe_finding_value(index + 1)}: the rewrite of "
                    f"{safe_finding_value(passage.id)}: {failure_finding.message}"
                ),
                sentence="",
                path=f"{path}.rewrite",
            )
            for failure_finding in passage.sourced_check(
                row.rewrite,
                row.sources,
                span[2] if span is not None else row.sentence,
                # What the sentence may do instead, where a keep of it passes (T-600).
                ""
                if span is None or _keep_refused(passage, span[2])
                else _otherwise(passage, span[2]),
            )
        )
    if row.decision == "rewrite" and _writable(passage):
        # Only a source the passage may rest on grounds its rewrite: a section
        # 5 sentence's, a fact about what the sentence or its rewrite names.
        grounds = [s for s in sources if s is not None and (s.kind in allowed or s.id in speaking)]
        if passage.kind == SECTION_5 and not whole:
            reading = _Reading(row.sentence, passage.text)
            about = [s for s in grounds if _grounds_section_5(s, reading)]
            if about and span is not None and row.rewrite != _qualified(span[2], about):
                # Every section 5 rewrite is the platform's (``_platform_rewrites``):
                # a row carrying other words is not one.
                about = []
            if grounds and not about:
                out.append(
                    Violation(
                        code=REWRITE_UNGROUNDED_CODE,
                        message=(
                            f"row {safe_finding_value(index + 1)}: "
                            f"{safe_finding_value(', '.join(s.id for s in grounds))} "
                            "is about nothing the sentence names. A fact qualifies a "
                            "section 5 sentence only where the sentence names the routine, "
                            "the address, the value or the call it is about, or, for a "
                            "fact about a routine or a bound value, where the sentence "
                            "states that the run's own reading (the ledger, its entries, "
                            "the listings or the function index) does not establish, "
                            "show, settle, trace or list something, names no address and "
                            "its passage names what the fact is about. Keep the sentence."
                        ),
                        path=f"{path}.rewrite",
                    )
                )
                out.extend(
                    _grounding_violations(row, index, passage, grounds, span, ungrounded=False)
                )
                return out
            grounds = about
        out.extend(_grounding_violations(row, index, passage, grounds, span))
    return out


# What becomes of a sentence the ledger's own lines hold (:func:`_held_by_the_ledger`) that no
# answer passing the checks answers after the round's retry, refused or never answered, as the
# question and every refusal of an answer for it say: it is left out, in a closing passage and
# in the body alike (T-600).
_LEFT_OUT_END = "if no answer for it passes the checks, it is left out of the report"
# What a rewrite of such a sentence carries, as every text describing one says: each clause
# denying something (``absence_answers.negated_clauses``) followed at once by a citation of an
# entry shown for that sentence (:func:`_uncited_denials`, T-600).
_DENIAL_CITED = "each denial in it followed at once by the entry it rests on, one shown for it"
# The same in a closing passage: in the limitations a denial may rest on a failed call the
# paragraph's facts show that no later call redid (``Passage.unredone_failed``, T-600).
_UNREDONE_DENIAL_CITED = f"{_DENIAL_CITED} or a failed call the facts show that no later call redid"

# The words by which a refusal, or the question, offers an end, each where the texts write it:
# what a test reads off a message to know the ends it offers (T-600).
# A drop; a keep as written; a keep naming a source.
_OR_DROP = "or drop it"
_OR_KEEP = "or keep the sentence"
_OR_KEEP_NAMING = "or keep it naming"
# A rewrite on the lines a ledger.N fact shows, on what the calls that redid a failed call
# answered, or citing those calls.
_ON_THE_LINES = "rewrite it in your own words on the lines shown"
_ON_THE_REDO = "rewrite it in your own words on what"
_CITING_THE_REDO = "rewrite it citing"
_SAY_THE_REDO = "and say what"
# What a row naming no source is told: a drop on its reason (a keep every keep of which is
# refused, this alone), a keep or a drop on it, a kept absence on it; the sources a row
# names; the passage's own sentence, copied.
_LEAVING_REASON = "leaving it out, give the reason"
_REASON_LEAVING = f"or, {_LEAVING_REASON}"
_REASON_KEEPING = "or, keeping a sentence no source speaks of, or leaving one out, give the reason"
_REASON_ABSENCE = "or, keeping an absence no source speaks of, give the reason"
_NAME_THE_SOURCES_READ = "Name the ids of the sources you read for the sentence of"
_NAME_THE_SOURCES = "Name the sources by their ids."
_COPY_THE_SENTENCE = "Copy the whole sentence as the passage writes it"
# A body sentence that is not left out.
_KEEP_OR_REWRITE = "with keep or rewrite"
# A rewrite mended: its citations, a clause the fact contradicts, a reading of listed code,
# the ledger's count.
_CITE_ONLY = "Cite only what the sources you name, or the passage itself, cite."
_KEEP_EVERY_ID = "Keep every id the sentence cites"
_CITE_A_SOURCE = "Cite the entry a source rests on"
_EACH_DENIAL_CITED = (
    "in a rewrite of this sentence each denial is followed at once by the entry it rests on"
)
_LEAVE_THE_CLAUSE = "Leave that clause out and state what the fact states"
_STATE_THE_READING = "Rewrite it in your own words to state that the code was read"
_STATE_THE_COUNT = "State the ledger's count, or no number."
# A keep refused for its quote or its sources: what it may do instead.
_QUOTE_OR_REWRITE = (
    "quote the words of a source that state the same thing, or rewrite the sentence on the "
    "source that states otherwise."
)
_NAME_AND_QUOTE = (
    "name the source and quote its words that state the same thing, or rewrite the sentence on it."
)
_TO_THE_SOURCES = "rewrite it to what the sources state, or drop it."
_ON_THE_ROWS = "rewrite it on them, or drop it"
_ON_A_CANDIDATE = "Keep it on one of these, quoting its words, or rewrite or drop it."
_ON_THE_ONE = "Rewrite it on the one that states otherwise"
# A held sentence no row lists, asked to be listed.
_LIST_IT = (
    "rewrite it on the source that states otherwise, or keep it naming the source you read "
    "and found agreeing"
)
_LIST_IT_LEAVING = "or leave it out giving the reason"
_LIST_IT_ABSENCE = "or with the reason where no source speaks of it"


def _denial_cited(unredone: bool) -> str:
    """:data:`_DENIAL_CITED`, or, where the passage's own facts show a failed call no later
    call redid (``unredone``), :data:`_UNREDONE_DENIAL_CITED`."""
    return _UNREDONE_DENIAL_CITED if unredone else _DENIAL_CITED


def _held_by_the_ledger(passage: Passage, sentence: str) -> str:
    """What holds ``sentence`` of ``passage`` to the ledger's own lines (T-600), in the words
    of the record of one left out: what the ``ledger.N`` facts shown for it hold lines on, the
    redone calls it names, or a failed call a later call redid that it says failed; ``""``
    for a sentence none of these holds."""
    said = []
    ids = dict(passage.ledger_named).get(sentence, ())
    if ids:
        said.append(
            f"held on what {', '.join(ids)} {'holds' if len(ids) == 1 else 'hold'} lines on"
        )
    redos = dict(passage.redone_named).get(sentence, ())
    if redos:
        said.append(f"held to the redone calls it names (redone by {' and '.join(redos)})")
    failed = dict(passage.failure_said).get(sentence, ())
    if failed:
        said.append(f"saying a call failed that a later call redid ({' and '.join(failed)})")
    return "; ".join(said)


def _ends_on_answer(passage: Passage, sentence: str) -> str:
    """What leaves ``sentence`` of ``passage`` out where no answer for it passes the checks,
    in the words of its record: the ledger's lines that hold it (:func:`_held_by_the_ledger`),
    or the kind of field answered whole it stands in (``Passage.whole``), or who wrote the
    passage printed in its writer's own words it stands in (``Passage.verbatim``, T-613);
    ``""`` for any other sentence, which ends as before."""
    return _held_by_the_ledger(passage, sentence) or passage.whole or passage.verbatim


def _shown_entries(passage: Passage, sentence: str, by_id: Mapping[str, Passage]) -> frozenset[str]:
    """The entries the round was shown for ``sentence`` of ``passage``, held by the ledger's
    lines: the ones each ``ledger.N`` fact shown for it cites, the calls that redid the
    redone calls it names or says failed, and, in the limitations paragraph, each failed
    call its own facts show that no later call redid: a denial resting on one is what the
    paragraph is for."""
    shown: set[str] = set(passage.unredone_failed)
    for fid in dict(passage.ledger_named).get(sentence, ()):
        fact = by_id.get(fid)
        if fact is not None:
            shown |= fact.cites
    for choice in (
        *dict(passage.redone_named).get(sentence, ()),
        *dict(passage.failure_said).get(sentence, ()),
    ):
        shown |= entry_ids_in(choice)
    return frozenset(shown)


def _uncited_denials(rewrite: str, shown: frozenset[str]) -> list[str]:
    """The clauses of ``rewrite`` that deny something (``absence_answers.negated_clauses``,
    cut by ``clauses_of``, which parts a citation's bracket from its clause) that no entry of
    ``shown`` follows at once: the clauses made only of entry ids directly after one name
    none of them (T-600). In order; one pass over the clauses."""
    from malspark.reporting.absence_answers import clauses_of
    from malspark.schemas.evidence import ENTRY_ID_RE

    out: list[str] = []
    denial = ""
    cited: set[str] = set()
    for clause in [*clauses_of(rewrite), "."]:
        ids = entry_ids_in(clause)
        if ids and _WORD_CHARACTER.search(ENTRY_ID_RE.sub("", clause)) is None:
            cited |= ids
            continue
        if denial and not cited & shown:
            out.append(denial)
        denial = clause if carries_negation(clause) else ""
        cited = set()
    return out


def _told_the_end(
    passage: Passage | None,
    sentence: str | None,
    found: Sequence[Violation],
    *,
    beside: Sequence[Violation] = (),
    last: bool = True,
) -> list[Violation]:
    """``found``, the refusals of an answer for ``sentence`` of ``passage``, each saying what
    becomes of a sentence the ledger's lines hold when its last answer is refused
    (:data:`_LEFT_OUT_END`) where it does not say so already, and, once, on its last refusal,
    its own ends where no refusal of the row carries them; a closing sentence no keep passes
    for (``Passage.unkept``) that nothing else holds is told its ends the same way, once, and
    ends as before, unsaid; as they are for any other.
    A row answering a sentence of a field answered whole is told, once, on its last refusal
    (``last``: ``found`` holds it), what the field is, every end that passes for it and that
    end (:func:`_whole_ends`), each part no refusal of the row (``found`` and ``beside``, its
    others) carries already (T-600)."""
    if not found or passage is None or sentence is None:
        return list(found)
    held = bool(_ends_on_answer(passage, sentence))
    if not held and not (passage.closing and sentence in passage.unkept):
        return list(found)
    if passage.whole:
        if not last:
            return list(found)
        ends = _whole_ends(passage, sentence)
        what = f"{safe_finding_value(passage.id)} is {safe_finding_value(passage.whole)}"
        said = [violation.message for violation in (*beside, *found)]
        if any(what in message for message in said):
            return list(found)
        *before, violation = found
        return [
            *before,
            replace(violation, message=f"{violation.message.rstrip()} {what}.")
            if any(ends in message for message in said)
            else replace(violation, message=f"{violation.message.rstrip()} {what}: {ends}"),
        ]
    # What becomes of it, said by every refusal: a sentence the ledger's lines hold is left
    # out; one no keep passes for that nothing else holds ends as before, unsaid (``""``).
    end = _left_out_end(passage) if held else ""
    told = [
        violation
        if end[:-1] in violation.message or _LEFT_OUT_END in violation.message
        else replace(violation, message=f"{violation.message.rstrip()} {end}")
        for violation in found
    ]
    # Its own ends, ahead of what becomes of it (:func:`_held_ends`, :func:`_named_body_ends`),
    # are told once, on the row's last refusal, where none of its refusals carries them.
    ends = (_closing_ends(passage, sentence) or _named_body_ends(passage, sentence)).removesuffix(
        f" {end}"
    )
    said = [violation.message for violation in (*beside, *found)]
    offers = _held_offers(passage, sentence)
    if (
        not last
        or not ends
        or all(
            any(offer in m or _sentence_start(offer)[:-1] in m for m in said) for offer in offers
        )
    ):
        return told
    violation = found[-1]
    ends = _sentence_start(ends)[:-1]
    return [
        *told[:-1],
        replace(violation, message=f"{violation.message.rstrip()} {ends}")
        if end[:-1] in violation.message or _LEFT_OUT_END in violation.message
        else replace(violation, message=f"{violation.message.rstrip()} {ends} {end}"),
    ]


def _held_name_ends(unredone: bool = False) -> str:
    """What a closing sentence held on a name the run holds may do, as the question and
    every refusal of a keep of it say: the same words with a citation added are a keep
    (:func:`repeats_sentence`), and a keep of a held sentence is refused; ``unredone`` as
    for :func:`_denial_cited`."""
    return (
        "a keep of it as written is refused, and the same words with a citation added are a "
        f"keep; {_ON_THE_LINES}, citing the entry they come from, saying what the lines show "
        f"and what stays unknown, {_denial_cited(unredone)}, {_OR_DROP}"
    )


# What a body sentence held on a name the run holds may do, as the question and every
# refusal of a keep of it say: the fact speaks to it, so a keep names the fact and quotes a
# row of it naming what the sentence names; a drop leaves it out, as one no answer passes is.
_HELD_NAME_BODY_ENDS = (
    'keep it naming that fact, with "quote": words inside one of its rows that name what '
    f"the sentence names, copied exactly; or {_ON_THE_LINES}, citing an entry the fact "
    f"cites, {_DENIAL_CITED}; {_OR_DROP}"
)
# The same for one no keep passes for, whatever it names (``Passage.unkept``).
_HELD_UNKEPT_BODY_ENDS = (
    f"a keep of it is refused whatever it names; {_ON_THE_LINES}, citing an entry the fact "
    f"cites, {_DENIAL_CITED}; {_OR_DROP}"
)


def _redone_ends(redos: Sequence[str], *, held: bool = True, unredone: bool = False) -> str:
    """What a sentence held to the redone calls it names may do: ``redos`` are the calls
    that redid them, one choice each (:func:`_redo_choices`); ``held``: the rewrite replaces
    a sentence the ledger's lines hold, so each denial in it is cited (:func:`_denial_cited`,
    with ``unredone``)."""
    return (
        _redone_rewrite(
            safe_finding_value(" and ".join(redos)), len(redos), held=held, unredone=unredone
        )
        + "; the same words with a citation added are a keep"
    )


def _redone_rewrite(said: str, count: int, *, held: bool = True, unredone: bool = False) -> str:
    """The rewrite or drop a sentence held to ``count`` redone calls may end as, ``said``
    naming the calls that redid them: in the number of the calls, and, for a rewrite of a
    sentence the ledger's lines hold (``held``), each denial in it cited."""
    return (
        f"{_ON_THE_REDO} {said} answered, citing "
        f"{'it' if count == 1 else 'each'}, "
        + (f"{_denial_cited(unredone)}, " if held else "")
        + _OR_DROP
    )


def _failed_ends(redos: Sequence[str], *, held: bool = True, unredone: bool = False) -> str:
    """What a closing sentence saying a call failed that a later call redid may do:
    ``redos`` are the calls that redid them, one choice each (:func:`_redo_choices`);
    ``held`` and ``unredone`` as for :func:`_redone_rewrite`."""
    return (
        f"{_CITING_THE_REDO} {safe_finding_value(' and '.join(redos))} and saying what "
        f"{'it' if len(redos) == 1 else 'each'} answered, "
        + (f"{_denial_cited(unredone)}, " if held else "")
        + _OR_DROP
    )


def _cite_redo(redos: Sequence[str], otherwise: str) -> str:
    """What a text of a passage other than a closing one still saying a redone call failed
    may do: cite the calls that redid them, ``redos`` (:func:`_redo_choices`), in their
    number, or what ``otherwise`` says (:func:`_otherwise`)."""
    return (
        f"cite {safe_finding_value(' and '.join(redos))} {_SAY_THE_REDO} "
        f"{'it' if len(redos) == 1 else 'each'} answered, {otherwise}"
    )


def _sentence_start(text: str) -> str:
    """``text`` as a sentence of its own: its first letter upper case, a full stop after."""
    return f"{text[:1].upper()}{text[1:]}."


def _left_out_end(passage: Passage) -> str:
    """:data:`_LEFT_OUT_END` as a sentence of its own, saying, for a field answered whole,
    what it prints once every sentence of it is left out (``Passage.emptied``), and for a
    passage printed in its writer's own words that the bundle prints it whole."""
    if passage.verbatim:
        return _sentence_start(_VERBATIM_LEFT_OUT)
    return _sentence_start(
        f"{_LEFT_OUT_END}, and {passage.emptied}" if passage.whole else _LEFT_OUT_END
    )


# What a sentence of a field answered whole (a value cell, a capability bullet) may end as,
# as the question and every text asking for it say: an answer a closing sentence may give.
_WHOLE_ENDS = (
    "rewrite it on the source that states otherwise, citing an entry that source cites; keep "
    'it naming the source you read and found agreeing, with "quote": its words that state '
    'the same thing, copied exactly, or with "sources": [] and "reason" where no source '
    'speaks of it; or drop it with "reason"'
)


# What a sentence of a passage printed in its writer's own words (``Passage.verbatim``) may end
# as, as the question and every refusal of an answer for it say: a keep on a source's words, or
# a drop; never a rewrite. Where none passes it is left out of the analyst report, and the
# bundle prints it whole (T-613).
_VERBATIM_ENDS = (
    'keep it naming the source you read and found agreeing, with "quote": its words that state '
    'the same thing, copied exactly, or drop it with "reason"'
)
_VERBATIM_LEFT_OUT = f"{_LEFT_OUT_END}, and the bundle prints it whole"


def _whole_ends(passage: Passage, sentence: str) -> str:
    """Every end that passes for ``sentence`` of a field answered whole, and what becomes of
    it where none does: its own where the ledger's lines hold it or no keep passes for it
    (:func:`_closing_ends`), :data:`_WHOLE_ENDS` for any other."""
    return _closing_ends(passage, sentence) or (
        f"{_WHOLE_ENDS}. {safe_finding_value(_left_out_end(passage))}"
    )


# What a closing sentence no keep passes for (``Passage.unkept``) may end as, as every refusal
# of an answer for it and the retry's question on it say: a rewrite or a drop (T-600).
_UNKEPT_ENDS = (
    "a keep of it is refused whatever it names, and the same words with a citation added are "
    "a keep; rewrite it on the source that states otherwise, citing an entry that source cites, "
    'or drop it with "reason"'
)


def _closing_ends(passage: Passage, sentence: str) -> str:
    """What a closing ``sentence`` of ``passage`` may do where a keep of it never passes: its
    own ends where the ledger's lines hold it (:func:`_held_ends`), else, for one the ledger
    says otherwise of whatever a keep names (``Passage.unkept``), :data:`_UNKEPT_ENDS`, with
    what becomes of a field answered whole where none passes; ``""`` for any other."""
    held = _held_ends(passage, sentence)
    if held or not passage.closing or sentence not in passage.unkept:
        return held
    return f"{_UNKEPT_ENDS}." + (
        f" {safe_finding_value(_left_out_end(passage))}" if passage.whole else ""
    )


def _listing_says_read(
    passage: Passage, sentence: str, by_id: Mapping[str, Passage]
) -> list[Passage]:
    """The ``listed.N`` facts that say otherwise of a keep of ``sentence`` of a closing
    ``passage``: about each routine its own clause calls not read (:func:`_decisive_unread`),
    or, where it names none such, about the address the clause denying a reading of it names;
    none for any other sentence."""
    listing = [by_id[i] for i in _decisive_unread(passage, sentence) if i in by_id]
    if not listing and denies_reading(sentence):
        # "read only in part" of code an entry lists: the listing says otherwise. Only the
        # address the denying clause names ("the routine at 0x1030 was read" beside it
        # is no denial of 0x1030).
        clause = reading_denied_in(sentence)
        # A denying clause naming none ("…at 0x3868, which calls X, was read only in
        # part") is said of the address written last before it.
        named = frozenset(_addresses_named(clause)) or frozenset(
            _addresses_named(sentence[: sentence.find(clause)])[-1:]
        )
        listing = [f for f in by_id.values() if f.lists_code and not f.addresses.isdisjoint(named)]
    return listing


def _ledger_refuses_keep(passage: Passage, sentence: str, by_id: Mapping[str, Passage]) -> bool:
    """Whether the checks of a keep refuse every keep of ``sentence`` of a closing ``passage``,
    whatever sources it names: the ledger's listing says otherwise of it
    (:func:`_listing_says_read`), its failure check refuses it as kept on none (a failed call a
    later call redid; a keep naming sources is held to their calls too), or it gives failed
    calls a number the ledger's count does not; of a body sentence, the count, or its own
    clause calling code an entry lists not read, which a keep leaves to be asked again
    (:func:`_held_unlisted`, T-600)."""
    if not passage.closing:
        return bool(
            count_disagrees(sentence, passage.counts) or _decisive_unread(passage, sentence)
        )
    return bool(
        _listing_says_read(passage, sentence, by_id)
        or (passage.sourced_check is not None and passage.sourced_check(sentence, (), "", ""))
        or count_disagrees(sentence, passage.counts)
    )


def _unread_end(
    passage: Passage, sentence: str, row: AgreementRow | None, by_id: dict[str, Passage]
) -> str:
    """What becomes of ``sentence`` where ``row`` (``None``: no row lists it), a row whose
    refusal names a listing of code it or its rewrite calls not read, is its last answer and
    refused: in a closing passage, a keep leaves it out, and a rewrite too where every source
    it names is one the passage rests on (:func:`_rests_on_a_source`); else, for a sentence
    whose own clause calls code not read that an entry lists (:func:`_decisive_unread`), the
    platform appends the ledger's listing fact to it, in the body whatever the row, in a
    closing passage where a rewrite names no such source, where a drop of it is refused, or
    where no row lists it. ``""`` for any other sentence, which ends as before, unsaid; for
    a sentence of a field answered whole or one the ledger's lines hold, each told its own
    end, left out (:func:`_told_the_end`, T-600)."""
    appended = "the platform appends the ledger's listing fact to it"
    if passage.whole or _held_by_the_ledger(passage, sentence):
        return ""
    if passage.closing and row is not None and row.decision == "keep":
        return "a keep of it is refused whatever it names, and leaves it out of the report"
    if passage.closing and row is not None and row.decision == "rewrite":
        if _rests_on_a_source(row, by_id):
            return "refused, a rewrite resting on the sources it names leaves it out of the report"
    if not _decisive_unread(passage, sentence):
        return ""
    if not passage.closing:
        return f"left standing, {appended}"
    if row is None:
        return f"left with no row, {appended}"
    if row.decision == "drop":
        return f"refused, a drop leaves it standing, and {appended}"
    return (
        "refused, a rewrite naming no source, or one that is no fact, section 5 passage or "
        f"debate round, leaves it standing, and {appended}"
    )


def _held_offers(passage: Passage, sentence: str) -> list[str]:
    """The ends a sentence the ledger's lines hold is offered, one per thing that holds it, as
    :func:`_held_ends` and :func:`_named_body_ends` write them, and those of a closing
    sentence no keep passes for that nothing else holds, :data:`_UNKEPT_ENDS`: a refusal
    carrying each one has told it its ends (:func:`_told_the_end`)."""
    if not passage.closing:
        if not dict(passage.ledger_named).get(sentence, ()):
            return []
        return [_HELD_UNKEPT_BODY_ENDS if sentence in passage.unkept else _HELD_NAME_BODY_ENDS]
    unredone = bool(passage.unredone_failed)
    redos = dict(passage.redone_named).get(sentence, ())
    failed = dict(passage.failure_said).get(sentence, ())
    held = [
        *([_held_name_ends(unredone)] if dict(passage.ledger_named).get(sentence, ()) else []),
        *([_redone_ends(redos, unredone=unredone)] if redos else []),
        *([_failed_ends(failed, unredone=unredone)] if failed else []),
    ]
    return held or ([_UNKEPT_ENDS] if sentence in passage.unkept else [])


def _held_ends(passage: Passage, sentence: str) -> str:
    """For a closing sentence held on a name the run holds, to the redone calls it names,
    or saying a call failed that a later call redid, what it may do, naming the facts it
    was shown or the calls to cite; ``""`` for any other. No source states such a
    sentence's absence, so none is offered to quote."""
    if not passage.closing:
        return ""
    ids = dict(passage.ledger_named).get(sentence, ())
    redos = dict(passage.redone_named).get(sentence, ())
    failed = dict(passage.failure_said).get(sentence, ())
    unredone = bool(passage.unredone_failed)
    said = []
    if ids:
        said.append(
            f"it names what {safe_finding_value(', '.join(ids))} "
            f"{'holds' if len(ids) == 1 else 'hold'} lines on: {_held_name_ends(unredone)}"
        )
    if redos:
        said.append(
            "it names a call that failed and a later call redid: a keep of it as written is "
            f"refused; {_redone_ends(redos, unredone=unredone)}"
        )
    if failed:
        said.append(
            "it says a call failed that a later call redid: a keep of it as written is "
            f"refused; {_failed_ends(failed, unredone=unredone)}"
        )
    if not said:
        return ""
    return " ".join(
        [
            f"{said[0]}.",
            *(_sentence_start(part) for part in said[1:]),
            _left_out_end(passage),
        ]
    )


def _named_body_ends(passage: Passage, sentence: str) -> str:
    """For a body sentence held on a name the run holds, what it may do, naming the facts
    it was shown; ``""`` for any other."""
    if passage.closing:
        return ""
    ids = dict(passage.ledger_named).get(sentence, ())
    if not ids:
        return ""
    return (
        f"it names what {safe_finding_value(', '.join(ids))} "
        f"{'holds' if len(ids) == 1 else 'hold'} lines on: "
        + (_HELD_UNKEPT_BODY_ENDS if sentence in passage.unkept else _HELD_NAME_BODY_ENDS)
        + ". "
        + _sentence_start(_LEFT_OUT_END)
    )


def _keep_refused(passage: Passage, sentence: str) -> bool:
    """Whether every keep of ``sentence`` of ``passage`` is refused, whatever it names: a
    closing sentence told its own ends (:func:`_closing_ends`), or a body sentence held on a
    name the run holds that the ledger says otherwise of (``Passage.unkept``)."""
    return bool(_closing_ends(passage, sentence)) or (
        not passage.closing and sentence in passage.unkept
    )


def _otherwise(passage: Passage, sentence: str) -> str:
    """What a refusal offers a sentence beside mending the text that answers it: a closing
    sentence no keep passes for (:func:`_closing_ends`) is dropped; a body
    sentence held on a name the run holds (:func:`_named_body_ends`) is kept naming the
    facts shown for it and quoting a row of one, in their number, or dropped; any other is
    kept."""
    if _keep_refused(passage, sentence):
        return _OR_DROP
    ids = () if passage.closing else dict(passage.ledger_named).get(sentence, ())
    if not ids:
        return _OR_KEEP
    rows = "its" if len(ids) == 1 else "their"
    return (
        f'{_OR_KEEP_NAMING} {safe_finding_value(" or ".join(ids))}, with "quote": words '
        f"inside one of {rows} rows that name what the sentence names, copied exactly, "
        f"{_OR_DROP}"
    )


def _answer_violations(
    row: AgreementRow,
    index: int,
    passage: Passage,
    sources: Sequence[Passage | None],
    span: tuple[int, int, str, int] | None,
    by_id: dict[str, Passage] | None = None,
) -> list[Violation]:
    """What is wrong with how a row answers its sentence (T-568).

    A row names its sources, but one on a closing sentence that keeps it where no
    source speaks of it, or leaves it out, with the reason; only a closing
    sentence is left out. A kept closing sentence quotes the words of a source it
    names that state the same (:func:`_quote_problem`); one kept on no source has
    no shown source speaking of it (:func:`_speaking_of`). A kept sentence the
    ledger itself contradicts (a failed call a later call redid) is not kept; one
    giving failed calls a number the ledger's count does not is told so. A rewrite
    gives failed calls no such number, and states no absence again that a fact it
    rests on contradicts (:func:`absence_answers.kept_absence`), whatever either cites.
    """
    path = f"sentences.{index}"
    number = safe_finding_value(index + 1)
    where = safe_finding_value(passage.id)
    out: list[Violation] = []
    # A sentence the ledger's own lines hold is left out where no answer for it passes
    # (:data:`_LEFT_OUT_END`): a drop of it is an answer, in the body as in a closing passage.
    held = span is not None and bool(_held_by_the_ledger(passage, span[2]))
    # A passage printed in its writer's own words: a sentence of it is kept on a source's words
    # or dropped on its reason, never rewritten (T-613).
    verbatim = bool(passage.verbatim)
    # A row whose sentence does not stand in its passage is refused for that alone: which
    # sentence it drops is not known.
    unheld_drop = (
        row.decision == "drop"
        and not passage.closing
        and not held
        and not verbatim
        and span is not None
    )
    if unheld_drop:
        out.append(
            Violation(
                code=UNKNOWN_PASSAGE_CODE,
                message=(
                    f"row {number}: only a sentence of the conclusion, the limitations, a "
                    "value cell or a capability bullet, or one the ledger's lines hold, is "
                    f"left out; answer the sentence of {where} {_KEEP_OR_REWRITE}."
                ),
                path=f"{path}.decision",
            )
        )
    # A held absence of the body is kept as a closing sentence is: on a source's words,
    # or on the reason where no source speaks of it (T-580).
    absent = (
        not passage.closing
        and span is not None
        and span[2] in passage.absences
        and row.decision == "keep"
    )
    reasoned = (
        (passage.closing or absent or ((held or verbatim) and row.decision == "drop"))
        and row.decision != "rewrite"
        and bool(row.reason.strip())
    )
    # A closing sentence held on a name the run holds, or to a redone call, is told its
    # ends, not a source to quote; a body sentence held on a name, the row to quote. Neither
    # is kept on a reason.
    closing_ends = _closing_ends(passage, span[2]) if span is not None else ""
    body_ends = _named_body_ends(passage, span[2]) if span is not None else ""
    verbatim_ends = f"{_VERBATIM_ENDS}." if verbatim else ""
    # A drop of the body naming no sentence of its passage is refused for that alone: which
    # sentence it drops is not known, so no source it names is asked for (T-600).
    unknown_drop = row.decision == "drop" and not passage.closing and span is None
    # A drop of a body sentence nothing holds is refused for that alone, above (T-652).
    if not row.sources and not reasoned and not unknown_drop and not unheld_drop:
        out.append(
            Violation(
                code=UNKNOWN_SOURCE_CODE,
                message=(
                    # A keep of a sentence every keep of which is refused is asked for no
                    # source: only its drop's reason (T-600).
                    f"row {number} names no source; {_LEAVING_REASON}."
                    if row.decision == "keep"
                    and span is not None
                    and _keep_refused(passage, span[2])
                    else f"row {number} names no source. {_NAME_THE_SOURCES_READ} {where}"
                    + (
                        f", {_REASON_LEAVING}"
                        if closing_ends or body_ends or verbatim_ends
                        else f", {_REASON_KEEPING}"
                        if passage.closing
                        else f", {_REASON_ABSENCE}"
                        if absent
                        else ""
                    )
                    + "."
                ),
                path=f"{path}.sources",
            )
        )
    if span is None:
        return out
    sentence = span[2]
    # A rewrite of a body sentence the ledger's lines hold in the same words, a citation
    # added wherever it stands, is the keep it is: the keep's checks run on it, its quote
    # one of a fact's rows (T-600). A section 5 rewrite the platform writes on a fact
    # (``_qualified``) is not the model's.
    kept_as_written = (
        row.decision == "rewrite"
        and not passage.closing
        and held
        and (passage.kind != SECTION_5 or _in_own_words(passage, sentence, sources))
        and repeats_sentence(sentence, row.rewrite)
    )
    keeping = row.decision == "keep" and (passage.closing or absent or verbatim)
    held_ends = closing_ends or body_ends or verbatim_ends
    if row.decision == "rewrite" and passage.closing and repeats_sentence(sentence, row.rewrite):
        # A rewrite saying what the sentence says is a keep on the sources it names,
        # quoting the one of their sentences that matches it best (T-568).
        named_sources = [
            s for s in sources if s is not None and s.kind in (FACT, SECTION_5, DEBATE)
        ]
        quote = _best_quote(sentence, named_sources, generic_words(by_id or {}))
        problem = (
            _quote_problem(sentence, quote, named_sources, generic_words(by_id or {}), by_id or {})
            if quote
            else "no sentence of the sources it names states it"
        )
        if problem and _rests_on_its_own_sources(sentence, quote, row.sources, by_id or {}):
            # The sources it names hold the absence in their own words, and no other
            # source speaks of it: kept, and recorded by the rewrite's own record.
            problem = ""
        if problem:
            out.append(
                Violation(
                    code=KEEP_UNQUOTED_CODE,
                    message=(
                        f"row {number}: {where} rewrites {safe_finding_value(sentence)!r} into "
                        "the same words, which keeps it, on "
                        f"{safe_finding_value(', '.join(_form(n) for n in row.sources))}, but "
                        "the best sentence of those sources "
                        f"{safe_finding_value(_quote_said(problem, passage, sentence))}: "
                        + (
                            held_ends
                            or _TO_THE_SOURCES + _candidates(sentence, by_id or {}, passage)
                        )
                    ),
                    path=f"{path}.rewrite",
                )
            )
    if (keeping or kept_as_written) and row.sources:
        body = absent or kept_as_written
        named_sources = [
            s
            for s in sources
            if s is not None
            and (s.kind in (FACT, SECTION_5, DEBATE) or (body and s.kind == CLAIM_LED))
        ]
        problem = _quote_problem(
            sentence,
            row.quote,
            named_sources,
            generic_words(by_id or {}),
            by_id or {},
            body=body,
            field=passage.field,
        )
        if problem:
            out.append(
                Violation(
                    code=KEEP_UNQUOTED_CODE,
                    message=(
                        f"row {number}: {where} "
                        + (
                            f"rewrites {safe_finding_value(sentence)!r} into the same words, "
                            "which keeps it,"
                            if kept_as_written
                            else f"keeps {safe_finding_value(sentence)!r}"
                        )
                        + f" on {safe_finding_value(', '.join(_form(n) for n in row.sources))}, "
                        "but "
                        + ("" if problem == _QUOTE_NONE else "its quote ")
                        + f"{safe_finding_value(_quote_said(problem, passage, sentence))}: "
                        + (
                            held_ends
                            or _QUOTE_OR_REWRITE + _candidates(sentence, by_id or {}, passage)
                            # The candidates the platform found, so a true limitation is
                            # kept on its source on the retry rather than lost (T-568).
                        )
                    ),
                    path=f"{path}.quote",
                )
            )
    repeating = (
        row.decision == "rewrite" and passage.closing and repeats_sentence(sentence, row.rewrite)
    )
    # Code an entry lists, called not read: the ledger itself says otherwise of a closing
    # keep; a body sentence's is qualified on the listing as before (T-562).
    ledger_read = (keeping and passage.closing) or repeating
    listing = _listing_says_read(passage, sentence, by_id or {}) if ledger_read else []
    if listing:
        # A closing sentence calling code not read that an entry lists says the
        # opposite of the ledger whatever it is kept on (T-568).
        out.append(
            replace(
                _unread_standing(
                    passage, sentence, listing, _unread_end(passage, sentence, row, by_id or {})
                ),
                path=f"{path}.decision",
            )
        )
    speaking = (
        _speaking_of(sentence, by_id or {}, passage)
        if keeping and not row.sources and not verbatim
        else []
    )
    if speaking:
        # "No source speaks of it" while a fact about a routine it names, or a
        # passage or fact about what it denies something of, is shown: the model
        # names it and quotes it, or rewrites (T-568).
        out.append(
            Violation(
                code=KEEP_UNQUOTED_CODE,
                message=(
                    f"row {number}: {where} keeps {safe_finding_value(sentence)!r} naming no "
                    f"source, but {safe_finding_value(', '.join(speaking))} speaks of what it "
                    "names: "
                    + (held_ends or _NAME_AND_QUOTE + _candidates(sentence, by_id or {}, passage))
                ),
                path=f"{path}.sources",
            )
        )
    # The same words with a citation added are a keep, of a sentence no keep passes for as
    # of any other (T-600); a sentence the ledger's lines hold is told so by its own checks.
    kept_same = (
        repeating and sentence in passage.unkept and not _held_by_the_ledger(passage, sentence)
    )
    if (
        (row.decision == "keep" or kept_same)
        and passage.closing
        and passage.sourced_check is not None
    ):
        # A keep is read as its own text (no sentence it replaces): told the ends of a
        # sentence no keep passes for (:func:`_failure_added_check`), and, of one a keep of
        # which can pass, the keep that does beside citing the calls that redid them.
        kept_otherwise = "" if _keep_refused(passage, sentence) else _otherwise(passage, sentence)
        out.extend(
            replace(
                failure_finding,
                # The finding is the platform's words, each value in it already made fit
                # to print: whole, so what it says to do is never cut off.
                message=(
                    f"row {number}: {where} "
                    + (
                        "rewrites the sentence into the same words, which keeps it"
                        if kept_same
                        else "keeps the sentence"
                    )
                    + f", but {failure_finding.message}"
                ),
                sentence="",
                path=f"{path}.decision",
            )
            for failure_finding in passage.sourced_check(sentence, row.sources, "", kept_otherwise)
        )
    counted = (
        row.rewrite if row.decision == "rewrite" else sentence if row.decision == "keep" else ""
    )
    if counted and count_disagrees(counted, passage.counts):
        out.append(_count_violation(number, where, passage.counts, path))
    if (
        row.decision == "rewrite"
        and held
        and (passage.kind != SECTION_5 or _in_own_words(passage, sentence, sources))
        and not repeats_sentence(sentence, row.rewrite)
    ):
        # A rewrite in the model's words of a sentence the ledger's lines hold: each clause of
        # it denying something is followed at once by an entry shown for that sentence (T-600).
        # A section 5 rewrite the platform writes on a fact (``_qualified``) is not the model's,
        # and the same words with a citation added are a keep, answered as one.
        shown = _shown_entries(passage, sentence, by_id or {})
        denials = _uncited_denials(row.rewrite, shown)
        if denials:
            # One finding, naming the first few denials and counting the rest.
            more = len(denials) - _DENIALS_NAMED
            out.append(
                Violation(
                    code=REWRITE_UNGROUNDED_CODE,
                    message=(
                        f"row {number}: the rewrite of {where} denies something in "
                        + "; ".join(repr(safe_finding_value(d)) for d in denials[:_DENIALS_NAMED])
                        + (
                            f" and in {safe_finding_value(more)} more "
                            + ("clause" if more == 1 else "clauses")
                            if more > 0
                            else ""
                        )
                        + " and no entry shown for the sentence follows "
                        + ("that denial" if len(denials) == 1 else "any of them")
                        + f" at once: {_EACH_DENIAL_CITED}, cited in square brackets, one of "
                        f"{safe_finding_value(', '.join(sorted(shown)))}."
                    ),
                    path=f"{path}.rewrite",
                )
            )
    if row.decision == "rewrite":
        facts = [s for s in sources if s is not None and s.kind == FACT]
        # Both read without their citations: an entry id in brackets cuts no clause, so a
        # rewrite citing an entry mid-sentence restates the same absence.
        kept = kept_absence(
            _contradicted_absences(passage.text, _uncited(sentence), facts),
            _uncited(row.rewrite),
        )
        if kept:
            out.append(
                Violation(
                    code=ABSENCE_KEPT_CODE,
                    message=(
                        f"row {number}: the rewrite of {where} still states "
                        f"{safe_finding_value(kept)!r}, which "
                        f"{safe_finding_value(', '.join(f.id for f in facts if f is not None))} "
                        f"states otherwise. {_LEAVE_THE_CLAUSE}, keeping what else the "
                        "sentence says that no source contradicts."
                    ),
                    path=f"{path}.rewrite",
                )
            )
    return out


# How many uncited denials of a rewrite its one finding names; the rest are counted.
_DENIALS_NAMED = 3
# How many of a kept sentence's own words its quote shares, at least (fewer where the
# sentence has fewer), so "is not established" quotes no particular absence.
_QUOTE_SHARED = 2
# How many sources a no-source keep is told of, at most; the count of the rest is said.
_SPEAKING_SHOWN = 3


# Words that say what an absence denies, not what it is about: an overlap on them
# ties a quote to no particular subject ("established", "read").
_ABSENCE_PREDICATES = frozenset(
    (
        "established establish known recovered read observed shown passed found appears "
        "appear present attributed determined identified resolved confirmed listed "
        "recorded seen captured reached executed exercised completed tied matched examined "
        "decompiled disassembled traced stated"
    ).split()
)


def kept_subject(sentence: str, generic: frozenset[str] = frozenset()) -> frozenset[str]:
    """What a kept closing sentence denies something of (:func:`absence_answers.denied_subject`:
    the item before its negation, never a frame), but the words saying what is denied
    (:data:`_ABSENCE_PREDICATES`) and the report's generic words (:func:`generic_words`)."""
    own = frozenset(
        w
        for w in denied_subject(sentence)
        if w not in _ABSENCE_PREDICATES and w not in PREPOSITIONS
    )
    # Where the generic words are all it names, what it names stands as it is.
    return (own - generic) or own


# A word standing in at least this share of the section 5 prose passages, and in at
# least :data:`_GENERIC_LEAST` of them, says nothing of what one sentence is about.
_GENERIC_SHARE = 0.8
_GENERIC_LEAST = 3


# A word the body's own frames use in at least this many sentences is a scene word.
_FRAME_LEAST = 2


def generic_words(by_id: dict[str, Passage]) -> frozenset[str]:
    """The report's generic words, read off its own vocabulary, never off a list of tool
    or sample names: those standing in four fifths or more (three at least) of its
    section 5 prose passages ("sandbox", "code", "routine"), and those its section 5
    sentences set the scene with in two or more frames ("analysed", "sample" of "In the
    analysed sample, …"). A table row is no passage here."""
    texts = [p.text for p in by_id.values() if p.kind == SECTION_5 and p.write is not None]
    return _generic_of(tuple(texts))


@lru_cache(maxsize=32)
def _generic_of(texts: tuple[str, ...]) -> frozenset[str]:
    counts: dict[str, int] = {}
    framed: dict[str, int] = {}
    for text in texts:
        for word in content_words(text):
            counts[word] = counts.get(word, 0) + 1
        for sentence in _sentences_of(text):
            for word in frame_words(sentence):
                framed[word] = framed.get(word, 0) + 1
    least = max(_GENERIC_LEAST, math.ceil(len(texts) * _GENERIC_SHARE))
    common = {w for w, n in counts.items() if n >= least} if len(texts) >= _GENERIC_LEAST else set()
    scene = {w for w, n in framed.items() if n >= _FRAME_LEAST}
    # An address names one routine however often it is written: never generic.
    return frozenset(w for w in common | scene if not _addresses_named(w))


def quote_overlap(sentence: str, quote: str, generic: frozenset[str] = frozenset()) -> int:
    """How many of :func:`kept_subject`'s words the quote holds (a shared beginning
    counts)."""
    return said_of(quote).count(kept_subject(sentence, generic))


# What a quote shorter than :data:`absence_answers.QUOTE_FLOOR` is refused for, and what the
# TASK says of every quote once (T-600).
_QUOTE_SHORT = f"is shorter than {QUOTE_FLOOR} characters, so it quotes nothing"
# What a keep naming a source with no quote at all is refused for (T-600).
_QUOTE_NONE = "gives no quote"
# The mend of either, said only where a keep of the sentence can pass (:func:`_quote_said`).
_QUOTE_MEND = f"quote at least {QUOTE_FLOOR} characters of the source's words"
_QUOTE_FLOOR_SAID = (
    f'A "quote" is at least {QUOTE_FLOOR} characters of the source\'s words, copied exactly.'
)


def _quote_said(problem: str, passage: Passage, sentence: str) -> str:
    """``problem``, what :func:`_quote_problem` refuses a quote for, as a refusal says it: a
    quote too short, or none, is told the floor (:data:`_QUOTE_MEND`) only where a keep of
    ``sentence`` can pass (:func:`_keep_refused`), never where every keep is refused."""
    if problem in (_QUOTE_SHORT, _QUOTE_NONE) and not _keep_refused(passage, sentence):
        return f"{problem}; {_QUOTE_MEND}"
    return problem


def _quote_problem(
    sentence: str,
    quote: str,
    sources: Sequence[Passage],
    generic: frozenset[str] = frozenset(),
    by_id: dict[str, Passage] | None = None,
    *,
    body: bool = False,
    speaking: bool = False,
    field: str = "",
) -> str:
    """What is wrong with a kept closing sentence's quote, or ``""``.

    ``field``: the label of the field a value cell fills (``Passage.field``). A sentence of
    it with no subject of its own ("Not established.", "None.") is read with that label as
    its subject, so its quote holds two (all, where fewer) of the label's words: "the request
    path … is not established" backs no "Not established." of a channel's encryption (T-613).

    ``body``: a held absence of the body, left out only where the ledger's own lines hold
    it (:func:`_held_by_the_ledger`), which may be kept on the rows of an entry it cites:
    a keep on them is the model's reading of them, and is recorded
    (:func:`entry_keep_reason`, T-580). ``speaking``: the quote is read for whether its
    source speaks of the sentence at all (:func:`_body_speaking`), where a source stating
    what the sentence denies does, so it need state no absence; a keep's quote, of the
    body as of a closing section, does: the passage stating what an absence denies backs
    no keep of it (T-652).

    It stands whole in a named source (:func:`absence_answers.quote_stands`), and
    states an absence where the sentence does. Where the sentence names addresses, the
    quote, or a fact it names, names one of them (haiku12's "0x3868 was read only in
    part" kept on a sentence about 0x7acc). A quote taken from a fact tying the address,
    where both deny that code was read or listed ("0xc42c was not read" on "no entry
    lists its code"), needs no more: the address is the subject. Any other quote holds
    two (all, where fewer) of the words of what the sentence denies something of
    (:func:`kept_subject`: never a frame, a word saying what is denied or a generic
    word) and names what a denied item is, so "no entry lists its code" backs no "the
    routine at 0xc42c never contacts the C2 host". A quote leaving out an item of a
    coordinated list that a shown source could say otherwise of is refused; one leaving
    out an item no source speaks of is recorded (:func:`_unbacked_items`).
    """
    if quote_too_short(quote):
        # Shorter than the floor it quotes nothing, wherever it stands: said so, as the
        # TASK states the floor; an empty one is said to give none (T-600).
        return _QUOTE_SHORT if quote.strip() else _QUOTE_NONE
    if not quote_stands(quote, [s.text for s in sources]):
        return "does not stand in a source it names"
    rows = [s for s in sources if sentence in s.speaks_to and quote_stands(quote, [s.text])]
    if rows:
        # The rows of an entry the sentence cites (T-580): a quote of them lies inside
        # one row and names a value the sentence names, never the header alone. They
        # state no absence, so they back no closing keep; a body absence kept on them
        # is the model's reading, recorded (:func:`entry_keep_reason`).
        if not any(_quotes_a_row(quote, s) for s in rows):
            return "quotes no single row of the entry holding a value the sentence names"
        if not body:
            return (
                "quotes the rows of an entry, which state no absence, while the sentence "
                f"states one: {_ON_THE_ROWS}"
            )
        return ""
    absent = carries_negation(sentence)
    if absent and not speaking and not carries_negation(quote):
        return "states no absence, while the sentence states one"
    named = frozenset(_addresses_named(sentence))
    by_quote = bool(named & set(_addresses_named(quote)))
    tying = [s for s in sources if s.kind == FACT and not s.addresses.isdisjoint(named)]
    if named and not (by_quote or tying):
        return "names none of the addresses the sentence names"
    if (
        named
        and any(quote_stands(quote, [s.text]) for s in tying)
        and denies_reading(sentence)
        and denies_reading(quote)
    ):
        return ""
    subject = kept_subject(sentence, generic)
    labelled = _field_subject(field, generic) if not subject else frozenset()
    if labelled:
        if said_of(quote).count(labelled) < min(_QUOTE_SHARED, len(labelled)):
            return f"shares too few of the words of the field the cell fills ({field})"
    elif quote_overlap(sentence, quote, generic) < min(_QUOTE_SHARED, len(subject)):
        return "shares too few of the words the sentence denies something of"
    # What an item denied is ("protocol" of "The C2 protocol beyond the request keys in
    # the decoded strings"): a quote holding only its modifiers ("decoded strings") is
    # about something else.
    heads = frozenset(h for h in denied_heads(sentence) if h not in _ABSENCE_PREDICATES)
    if heads and not said_of(quote).count(heads):
        return "names none of what the sentence denies something of"
    if absent and body and not speaking and not _states_the_denial(sentence, quote, generic):
        # A negation of something else ("it does not sleep") beside the words stating
        # what the sentence denies is no statement of its absence (T-652).
        return "states no absence of what the sentence denies something of"
    if by_id is not None:
        contradicted = [
            item for item in _unbacked_items(sentence, quote) if _could_contradict(item, by_id)
        ]
        if contradicted:
            return "leaves out an item of the sentence a source speaks of: " + "; ".join(
                " ".join(sorted(item)) for item in contradicted
            )
    return ""


def _field_subject(field: str, generic: frozenset[str]) -> frozenset[str]:
    """The words of a value cell's field label (``Passage.field``) a quote of a sentence with no
    subject of its own holds: its content words, but the words saying what is denied and the
    report's generic words, where others remain."""
    own = frozenset(w for w in content_words(field) if w not in _ABSENCE_PREDICATES)
    return (own - generic) or own


def _states_the_denial(sentence: str, quote: str, generic: frozenset[str]) -> bool:
    """Whether one negated clause of ``quote`` (``absence_answers.negated_clauses``), its
    quoted values left out (:data:`_QUOTED_VALUE`), holds what ``sentence`` denies something
    of, as a closing keep's quote holds it (:func:`quote_overlap`: two of those words, all
    where fewer)."""
    least = min(_QUOTE_SHARED, len(kept_subject(sentence, generic)))
    # A negation inside a quoted value is the sample's text ('compares the reply with "no"').
    bare = _QUOTED_VALUE.sub(" ", quote)
    return any(
        quote_overlap(sentence, clause, generic) >= least for clause in negated_clauses(bare)
    )


# A value quoted in double, single, curly or back quotes, however short, each bounded by
# what is no word character, so an apostrophe inside a word ("sample's") opens none.
_QUOTED_VALUE = re.compile(
    r"(?<!\w)(?:\"[^\"\n]{0,200}\"|\u201c[^\u201d\n]{0,200}\u201d|'[^'\n]{0,200}'(?!\w)"
    r"|\u2018[^\u2019\n]{0,200}\u2019(?!\w)|`[^`\n]{0,200}`)"
)


# How much of a sentence's own words a rewrite repeats, and the reverse, to say the same.
_REPEAT_SHARE = 0.8


def repeats_sentence(sentence: str, rewrite: str) -> bool:
    """Whether a rewrite says what its sentence says: each holds at least
    :data:`_REPEAT_SHARE` of the other's content words (case, spacing and citations aside),
    so changing a word or two is no way round the keep checks, and it still states every
    absence of the sentence (:func:`absence_answers.kept_absence`): "0x2800 and 0x2c00
    were read, 0x7000 was not" corrects "0x2800, 0x2c00 and 0x7000 were not read" in the
    same words. Both are read without their citations, wherever they stand: an entry id
    in brackets cuts no clause, so the same words citing an entry mid-sentence are the
    same words."""
    sentence, rewrite = _uncited(sentence), _uncited(rewrite)
    mine, theirs = content_words(sentence), content_words(rewrite)
    if not mine or not theirs:
        return False
    if said_of(rewrite).count(mine) < _REPEAT_SHARE * len(mine):
        return False
    if said_of(sentence).count(theirs) < _REPEAT_SHARE * len(theirs):
        return False
    return all(
        kept_absence([clause], rewrite) is not None
        for clause in negated_clauses(sentence)
        if len(content_words(clause)) >= _QUOTE_SHARED
    )


def _rests_on_its_own_sources(
    sentence: str, quote: str, cited: Sequence[str], by_id: dict[str, Passage]
) -> bool:
    """Whether a closing sentence repeated as its own rewrite rests on the sources it names
    though no word check proves it: their best sentence states the absence where it does
    and names a word of what a denied item is ("a file-mode download does not store the
    body" of "The file-mode disk write is not reached"), and every source that could say
    otherwise of it (:func:`_speaking_sources`) is one of them."""
    if carries_negation(sentence) and not carries_negation(quote):
        return False
    groups = frozenset(w for w in denied_groups(sentence) if w not in _ABSENCE_PREDICATES)
    if not groups or not said_of(quote).count(groups):
        return False
    named = {_form(n) for n in cited}
    return all(pid in named for pid, _excerpt in _speaking_sources(sentence, by_id))


def _best_quote(sentence: str, sources: Sequence[Passage], generic: frozenset[str]) -> str:
    """The sentence of the sources that matches a closing sentence best: naming one of its
    addresses, stating an absence where it does, then holding the most of what it denies
    something of (:func:`kept_subject`); ``""`` for no source."""
    named = frozenset(_addresses_named(sentence))
    absent = carries_negation(sentence)
    subject = kept_subject(sentence, generic)
    best: tuple[tuple[int, int, int], str] | None = None
    for source in sources:
        for part in _sentences_of(source.text):
            score = (
                int(bool(named & set(_addresses_named(part)))),
                int(carries_negation(part) or not absent),
                said_of(part).count(subject),
            )
            if best is None or score > best[0]:
                best = (score, part)
    return best[1] if best else ""


def _unbacked_items(sentence: str, quote: str) -> list[frozenset[str]]:
    """The own words of each item of a coordinated list the sentence denies something of
    that the quote names none of ("the C2 reply format" of "Whether the gates pass, and
    the C2 reply format, were not established" on a quote about the gates)."""
    items = denied_items(sentence)
    if len(items) < _QUOTE_SHARED:
        return []
    said = said_of(quote)
    return [words - PREPOSITIONS for words, group in items if group and not said.count(group)]


def _could_contradict(item: frozenset[str], by_id: dict[str, Passage]) -> bool:
    """Whether a shown section 5 passage, or a fact citing an entry, holds two or more of an
    item's words (all, where it has one, the report's generic words left out): "the
    request keys in the decoded strings" of the protocol item, which section 6 states."""
    words = (item - generic_words(by_id) - _ABSENCE_PREDICATES) or item
    least = min(_QUOTE_SHARED, len(words))
    return any(
        said_of(p.text).count(words) >= least
        for p in by_id.values()
        if (p.kind == SECTION_5 or (p.kind == FACT and p.cites))
        and not _an_open_question(p)
        and not p.silent
    )


def _quotes_a_row(quote: str, fact: Passage) -> bool:
    """Whether ``quote`` stands inside one row an entry fact shows and names a value the
    sentences it speaks to name, as a whole word ("41" is no part of "412") (T-580)."""
    return any(quote_stands(quote, [row]) for row in fact.row_texts) and any(
        re.search(r"(?<!\w)" + re.escape(value) + r"(?!\w)", quote, re.IGNORECASE)
        for value in fact.row_values
    )


def entry_keep_reason(sentence: str, quote: str, sources: Sequence[Passage | None]) -> str:
    """Why a keep quoting the rows of an entry the sentence cites is recorded, or ``""``:
    the rows state no absence, so the keep is the model's reading of them (T-580)."""
    if any(s is not None and sentence in s.speaks_to and _quotes_a_row(quote, s) for s in sources):
        return "resting on the rows of an entry the sentence cites, which state no absence"
    return ""


def absence_keep_reason(
    sentence: str, quote: str, sources: Sequence[Passage | None], passage: Passage
) -> str:
    """Why a kept held absence of the body is recorded, or ``""`` (T-580): it rests only on
    other written passages or debate rounds (one model's words agreeing with another's
    ground nothing); or it is a section 5 sentence, every keep of which is recorded, as
    before it could be rewritten. A keep whose quote states no absence passes no check
    (:func:`_quote_problem`, T-652), so none is recorded for that; ``quote`` is read by the
    caller's other readers."""
    named = [s for s in sources if s is not None]
    if named and all(s.kind in (CLAIM_LED, DEBATE) for s in named):
        return "resting only on another written passage, not on the code or the ledger"
    if passage.kind == SECTION_5:
        return "a section 5 sentence, whose every keep is recorded"
    return ""


def keep_record_reason(sentence: str, quote: str, generic: frozenset[str] = frozenset()) -> str:
    """Why a closing keep on a quote that passed the checks is still recorded, or ``""``:
    it rests on fewer than two of the words the sentence denies something of, or leaves
    out an item of a coordinated list (named)."""
    if quote_overlap(sentence, quote, generic) < _QUOTE_SHARED:
        return "resting on fewer than two of the words the sentence denies something of"
    left = _unbacked_items(sentence, quote)
    if left:
        return "leaving out " + "; ".join(" ".join(sorted(item)) for item in left)
    return ""


# What a candidate source's excerpt quotes at most, in characters.
_EXCERPT_CHARS = 160


def _speaking_sources(
    sentence: str, by_id: dict[str, Passage], passage: Passage | None = None
) -> list[tuple[str, str]]:
    """The shown sources that could say otherwise than a closing sentence, each with an
    excerpt, best first.

    A source could where it is a fact about an address the sentence names, or where it
    (a section 5 passage, or a fact citing an entry) holds two or more words of what the
    sentence denies something of (:func:`kept_subject`, the report's generic words left
    out), one of them what a denied item is (:func:`absence_answers.denied_groups`): in one
    sentence where the sentence denies an observation
    (:func:`absence_answers.denies_an_observation`), anywhere in it otherwise. A question
    an analyst left open states nothing to say otherwise with, and a fact of a name the run
    holds speaks only to the sentences it is shown for (:func:`_not_shown_for`). The
    excerpt is the source's sentence whose own first address the closing sentence names,
    then the one naming the most of those words; the sources rank the same way, a fact
    writing that address first ("0x7acc … is called by …") before one naming it as a
    caller. On one line, cut at :data:`_EXCERPT_CHARS`
    characters with the cut marked. Each source's sentences are read once per text.

    For a held absence of the body (``passage`` given, not a closing one, holding the
    sentence among its :attr:`Passage.absences`), :func:`_body_speaking`: a source speaks
    only where one sentence of it is a quote the keep check passes but for stating an
    absence, so every refusal can be answered by rewriting on what it names, or by quoting
    it where it states the same absence (T-580, T-652).
    """
    body = passage is not None and not passage.closing and sentence in passage.absences
    if body and passage is not None:
        return _body_speaking(sentence, by_id, passage)
    own_id = passage.id if passage is not None else ""
    named = frozenset(_addresses_named(sentence))
    # An address it names speaks through the facts tying it, never as a word of its own.
    subject = frozenset(
        w for w in kept_subject(sentence, generic_words(by_id)) if not _addresses_named(w)
    )
    observed = denies_an_observation(sentence)
    reading_denied = denies_reading(sentence)
    # What each denied item is: a source says otherwise of it only naming one of these.
    heads = frozenset(h for h in denied_groups(sentence) if h in subject)
    ranked: list[tuple[tuple[int, int, int, int], int, str, str]] = []
    for order, source in enumerate(by_id.values()):
        if source.id == own_id or source.silent or _not_shown_for(source, sentence):
            continue
        claimed = body and source.kind == CLAIM_LED and _writable(source)
        if not claimed and (
            source.kind not in (FACT, SECTION_5) or not (source.kind == SECTION_5 or source.cites)
        ):
            continue
        if _an_open_question(source):
            # A question an analyst left open states nothing to say otherwise with.
            continue
        # A fact on whether a routine's code was listed says otherwise only of a sentence
        # denying a reading ("0x463c's purpose was not established" it does not touch).
        reading_fact = source.lists_code or _NOT_LISTED in source.text
        by_address = bool(
            named
            and source.kind == FACT
            and not source.addresses.isdisjoint(named)
            and (reading_denied or not reading_fact)
        )
        # A denied observation is said otherwise of only by a sentence holding two of its
        # words (a passage of code describing an exchange observes none); any other
        # denial by a passage holding them (the request built over several sentences).
        texts = _sentences_of(source.text) if observed else [source.text]
        by_subject = len(subject) >= _QUOTE_SHARED and any(
            said_of(text).count(subject) >= _QUOTE_SHARED
            and (not heads or said_of(text).count(heads) > 0)
            for text in texts
        )
        # The rows of an entry the sentence cites, recording a value it names (T-580).
        by_entry = source.kind == FACT and sentence in source.speaks_to
        if not (by_address or by_subject or by_entry):
            continue
        best: tuple[tuple[int, int, int, int], str] | None = None
        for part in _sentences_of(source.text):
            words = said_of(part).count(subject) if subject else 0
            # A fact writes its address first, the virtual address and its offset.
            first = _addresses_named(part)[:2] if named else []
            own = int(any(address in named for address in first))
            # A fact opening on the address is about that routine ("0x…c42c (offset
            # 0xc42c) is called by …"), before a question or a passage naming it.
            head = " ".join(part.split()[:3])  # the address, and its offset in brackets
            opens = int(bool(named) and bool(named & set(_addresses_named(head))))
            score = (int(by_entry), opens, own, words)
            if best is None or score > best[0]:
                best = (score, part)
        if best is not None:
            ranked.append((best[0], order, source.id, _capped(best[1], _EXCERPT_CHARS)))
    ranked.sort(key=lambda item: (tuple(-n for n in item[0]), item[1]))
    return [(pid, excerpt) for _score, _order, pid, excerpt in ranked]


def _body_speaking(
    sentence: str, by_id: dict[str, Passage], passage: Passage
) -> list[tuple[str, str]]:
    """The sources that speak of a held absence of the body, each with the sentence of it
    the keep check passes as a quote but for stating an absence (:func:`_quote_problem`
    with ``speaking``), best first. A rewrite of a held absence of section 5 may rest on any
    of them (:func:`_tied`); a keep quoting one passes only where its words state the same
    absence (:func:`_keep_quotes`, T-652).

    Every other passage written without the code speaks as section 5 does: the body's
    claims say otherwise of an absence too (haiku13's "not shown to use anti-debug or
    environment checks" beside section 4's gates, T-580); its own passage never does,
    and nor does an open question. An absence set in what a run saw ("in the sandbox",
    "not observed") is spoken of only by a sentence stating what a run saw and denying
    nothing (:func:`absence_answers.observes`): no passage of code says otherwise of
    it, and a run that saw nothing agrees with it. Each excerpt is the shortest run of
    a sentence (or row) between clause marks that the check passes
    and a finding row prints whole (:func:`_shortest_quote`); a source with none does
    not speak, so every refusal names an excerpt the model can rest an answer on. The
    rows of an entry it cites speak through a row naming a value. Such a keep is never left
    out, so a source speaking costs a question, never the sentence.
    """
    generic = generic_words(by_id)
    subject = kept_subject(sentence, generic)
    least = min(_QUOTE_SHARED, len(subject))
    run_set = set_in_a_run(sentence)
    # Of a section 5 passage, the addresses it names that a fact shown holds: a passage
    # written without the code speaks of its absence only naming one (:func:`_tied`).
    held = _ledger_named(passage, by_id) if passage.kind == SECTION_5 else None
    ranked: list[tuple[int, int, str, str]] = []
    for order, source in enumerate(by_id.values()):
        if source.id == passage.id or source.silent:
            continue
        if sentence in source.speaks_to and source.row_texts:
            row = next(
                (
                    q
                    for r in source.row_texts
                    if (q := _shortest_quote(r, partial(_quotes_a_row, fact=source)))
                ),
                None,
            )
            if row is not None:
                ranked.append((len(subject) + 1, order, source.id, row))
            continue
        if _not_shown_for(source, sentence):
            continue
        claimed = source.kind == CLAIM_LED and _writable(source)
        if not (claimed or source.kind == SECTION_5 or (source.kind == FACT and source.cites)):
            continue
        if _an_open_question(source):
            continue
        if claimed and held is not None and not _tied(source, held):
            continue
        best: tuple[int, str] | None = None
        for part in _sentences_of(source.text):
            words = said_of(part).count(subject)
            if not subject or words < least:
                continue
            if run_set and (not observes(part) or carries_negation(part)):
                # A run-set absence is said otherwise of only by a run seeing something;
                # a sentence that saw nothing either agrees with it or speaks of another.
                continue
            quote = _shortest_quote(
                part, partial(_passes_as_body_quote, sentence, [source], generic, by_id)
            )
            if quote is None:
                continue
            if best is None or words > best[0]:
                best = (words, quote)
        if best is not None:
            ranked.append((best[0], order, source.id, best[1]))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [(pid, excerpt) for _score, _order, pid, excerpt in ranked]


def _passes_as_body_quote(
    sentence: str,
    sources: Sequence[Passage],
    generic: frozenset[str],
    by_id: dict[str, Passage],
    quote: str,
) -> bool:
    """Whether ``quote`` speaks of a held body absence as :func:`_quote_problem` reads a
    keep's quote, but for stating an absence: what states what it denies speaks of it."""
    return not _quote_problem(sentence, quote, sources, generic, by_id, body=True, speaking=True)


# Where a quote of a source sentence may end short of its end: a clause mark.
_QUOTE_CUT = re.compile(r"[,;:](?=\s)")


def _shortest_quote(part: str, passes: Callable[[str], bool]) -> str | None:
    """The shortest run of ``part``'s words between clause marks (or its ends), on one
    line, that ``passes`` and that a finding row prints whole (``FINDING_VALUE_LIMIT``
    characters), the earliest of equal length, or ``None``: a refusal names only a
    quote the model can copy and the keep check passes (T-580). Each start reads ends
    only up to that length, so a sentence of many clauses costs no more than its marks."""
    from malspark.pipeline.events import FINDING_VALUE_LIMIT

    line = " ".join(part.split())
    marks = [m.start() for m in _QUOTE_CUT.finditer(line)]
    starts = [0, *(at + 1 for at in marks)]
    ends = [*marks, len(line)]
    best: str | None = None
    for start in starts:
        for end in ends:
            if end <= start:
                continue
            quote = line[start:end].strip()
            if len(quote) > FINDING_VALUE_LIMIT:
                break
            if best is not None and len(quote) >= len(best):
                break
            if passes(quote):
                best = quote
                break
    return best


def _speaking_of(
    sentence: str, by_id: dict[str, Passage], passage: Passage | None = None
) -> list[str]:
    """The ids of :func:`_speaking_sources`, the first :data:`_SPEAKING_SHOWN` and the
    count of the rest."""
    out = [pid for pid, _excerpt in _speaking_sources(sentence, by_id, passage)]
    if len(out) > _SPEAKING_SHOWN:
        return [*out[:_SPEAKING_SHOWN], f"{len(out) - _SPEAKING_SHOWN} more"]
    return out


def _candidates(sentence: str, by_id: dict[str, Passage], passage: Passage | None = None) -> str:
    """The retry's list of the sources a refused closing keep may rest on, each by id with
    its excerpt as one quoted value, and what to do with them; ``""`` for none (T-568).
    For a held absence of the body, what it may do instead: it is never left out
    (T-580)."""
    found = _speaking_sources(sentence, by_id, passage)
    if not found:
        return ""
    shown = "; ".join(
        f"[{safe_finding_value(pid)}] {quoted_value(safe_finding_value(excerpt))}"
        for pid, excerpt in found[:_SPEAKING_SHOWN]
    )
    more = len(found) - _SPEAKING_SHOWN
    body = passage is not None and not passage.closing
    # A keep of a body absence quoting a source passes only where its words state the same
    # absence (:func:`_quote_problem`): the shortest such words of each source shown, which
    # need not be its excerpt; the rest are rewritten on (T-652).
    keeps = _keep_quotes(sentence, found[:_SPEAKING_SHOWN], by_id) if body else []
    return (
        f" The shown sources that speak of it: {shown}"
        + (f"; and {more} more" if more > 0 else "")
        + (
            f". {_ON_THE_ONE}"
            + (
                " (a section 5 sentence too: on any of these, a passage written without the "
                "code where it names an address the sentence's passage names and a fact holds)"
                if (passage is not None and passage.kind == SECTION_5)
                else ""
            )
            + (
                f", {_OR_KEEP_NAMING} the one you read, quoting its words that state the same "
                "absence: "
                + "; ".join(
                    f"[{safe_finding_value(pid)}] {quoted_value(safe_finding_value(quote))}"
                    for pid, quote in keeps
                )
                + "."
                if keeps
                else "; the excerpts shown state no absence, so no keep rests on them."
            )
            if body
            else f". {_ON_A_CANDIDATE}"
            + (
                # Rows state no absence: they back no closing keep (T-580).
                f" The rows of an entry state no absence: rewrite the sentence on them, {_OR_DROP}."
                if any(by_id[pid].row_texts for pid, _excerpt in found if pid in by_id)
                else ""
            )
        )
    )


def _keep_quotes(
    sentence: str, found: Sequence[tuple[str, str]], by_id: dict[str, Passage]
) -> list[tuple[str, str]]:
    """Each source of ``found`` with the shortest run of its words a keep of the held body
    absence ``sentence`` passes every check on (:func:`_quote_problem` with ``body``): its
    excerpt where that passes, else the shortest of its sentences' runs between clause marks
    (:func:`_shortest_quote`); a source with none is left out (T-652)."""
    generic = generic_words(by_id)
    out: list[tuple[str, str]] = []
    for pid, excerpt in found:
        source = by_id.get(pid)
        if source is None:
            continue

        def passes(quote: str, source: Passage = source) -> bool:
            return not _quote_problem(sentence, quote, [source], generic, by_id, body=True)

        if passes(excerpt):
            out.append((pid, excerpt))
            continue
        quotes = [q for part in _sentences_of(source.text) if (q := _shortest_quote(part, passes))]
        if quotes:
            out.append((pid, min(quotes, key=len)))
    return out


def _count_violation(number: str, where: str, counts: FailureCounts | None, path: str) -> Violation:
    said = (
        f"{counts.failed} failed, {counts.redone} of them redone, "
        f"{counts.failed - counts.redone} not redone"
        if counts is not None
        else ""
    )
    return Violation(
        code=FAILURE_COUNT_CODE,
        message=(
            f"row {safe_finding_value(number)}: {safe_finding_value(where)} gives failed calls "
            f"a number the ledger's count (calls.1: {safe_finding_value(said)}) does not. "
            f"{_STATE_THE_COUNT}"
        ),
        path=f"{path}.rewrite",
    )


def _contradicted_absences(text: str, sentence: str, facts: Sequence[Passage]) -> list[str]:
    """The clauses of ``sentence`` denying what a fact a row rests on states: a decoded
    value bound to a call, or a routine an entry lists.

    The negated clauses naming what the fact is about (its address, value or call);
    for a bound value's fact about the sentence whose clauses name none of it ("so
    the mutex name is not passed in that call"), the negated clauses sharing at least
    two of the fact's own words ("name", "mutex", "call" of "the name of the mutex
    the call creates"). A routine's listing is about its address alone: another
    absence of the sentence ("whether they pass is not known") stays its own.
    """
    clauses = negated_clauses(sentence)
    if not clauses:
        return []
    reading = _Reading(sentence, text)
    out: list[str] = []
    for fact in facts:
        if not (fact.value or fact.lists_code):
            continue
        named = [clause for clause in clauses if _about(fact, clause)]
        if named or fact.lists_code:
            out.extend(named)
        elif _about(fact, sentence, reading.named) or _grounds(fact, reading):
            words = content_words(fact.text)
            out.extend(c for c in clauses if len(content_words(c) & words) >= _SHARED_WORDS)
    return list(dict.fromkeys(out))


# How many of a fact's own words a clause shares to be the absence the fact is about.
_SHARED_WORDS = 2


def _whole_code_sentence(passage: Passage, sentence: str) -> bool:
    """Whether ``sentence``, as it stands, is one of a section 5 passage's whole-code
    absences, rewritten in the model's words rather than qualified by the platform."""
    return passage.kind == SECTION_5 and sentence in passage.whole_code


def _decisive_unread(passage: Passage, sentence: str) -> tuple[str, ...]:
    """The ``listed.N`` facts about the routine ``sentence``'s own clause calls not read,
    or none: a sentence reporting or refuting another's claim is that claim's. In a
    closing passage, every routine it calls not read: each of its sentences is answered,
    and "0x6328, 0x3074 and 0x8560 were not read" names three (T-568)."""
    for held, ids, own in passage.unread_listed:
        if held == sentence:
            if _reports_a_claim(sentence):
                return ()
            return ids if passage.closing else own
    return ()


def _in_own_words(passage: Passage, sentence: str, sources: Sequence[Passage | None]) -> bool:
    """Whether a row on a section 5 sentence is answered in the model's words.

    A sentence whose own clause calls listed code not read is, always: the
    platform never puts the listing beside words saying the opposite, and adds
    its correction only to one the answer leaves standing (T-562). A whole-code
    absence is, unless every source it names is a fact that grounds the
    sentence, where the platform qualifies it as any section 5 sentence
    (``_qualified``). The words are read as any passage's rewrite is; the
    passage itself is never their source.
    """
    if passage.kind == SECTION_5 and _decisive_unread(passage, sentence):
        return True
    if passage.kind == SECTION_5 and sentence in passage.on_fact:
        # A denial a bound value's fact contradicts: the fact's clause beside it
        # would state both (haiku12's mutex sentences, T-568).
        return True
    listings = dict(passage.branch_sense).get(sentence, ())
    if (
        passage.kind == SECTION_5
        and listings
        and any(s is not None and s.id in listings for s in sources)
    ):
        # A branch or an argument rewritten on the routine's listing: what the listing
        # shows is the model's to state; no fact clause says which way the code goes.
        # A row on another fact is the platform's, as before.
        return True
    if not _whole_code_sentence(passage, sentence):
        return False
    others = [s for s in sources if s is None or s.id != passage.id]
    if not others:
        return False
    reading = _Reading(sentence, passage.text)
    return not all(s is not None and s.kind == FACT and _grounds(s, reading) for s in others)


def _grounds_section_5(fact: Passage, reading: _Reading) -> bool:
    """Whether a fact grounds a rewrite of a section 5 sentence: where the sentence names
    what the fact is about (a routine whose code no entry lists or its caller, the address
    of an answered call, a bound value, its call or where it is passed), or, for a
    fact about a routine or a bound value, where the sentence states that the run's own
    reading (the ledger, its entries, the listings or the function index) does not
    establish, show, settle, trace or list something, names no address and its passage
    names what the fact is about. The platform writes the rewrite (``_qualified``); a fact
    with no clause of its own grounds none."""
    return _grounds(fact, reading)


class _Reading:
    """What a section 5 sentence and its passage name, read once for every fact asked
    about the sentence."""

    def __init__(self, sentence: str, passage: str) -> None:
        self.sentence = sentence
        self.lowered = sentence.lower()
        self.passage = passage

    @cached_property
    def named(self) -> frozenset[int]:
        return frozenset(_addresses_named(self.sentence))

    @cached_property
    def passage_named(self) -> frozenset[int]:
        return frozenset(_addresses_named(self.passage))

    @cached_property
    def unestablished(self) -> bool:
        return _unsettled_by_reading(self.sentence) and _states_an_absence(self.sentence)


def _grounds(fact: Passage, reading: _Reading) -> bool:
    """:func:`_grounds_section_5` for a sentence as copied: a fact with a clause of its
    own, whose clause the sentence does not already carry, about what the sentence
    names; or a fact about a routine or a bound value, about what the passage names,
    where the sentence states that the run's own reading does not establish, show,
    settle, trace or list something (:func:`_unsettled_by_reading`) and names no
    address of its own ("No environment check is established.", T-404; "The mutex name
    is not established.", T-398; "The ledger does not show whether the gate passed.").
    An absence naming an address is about that address ("The call at 0x3808 was not
    read"); an absence the run recorded ("The sandbox recorded no API call trace.") is
    about no routine (T-537).

    Any other fact is about the sentence alone: a section names many routines, and
    a failed call answered later is not about every sentence beside the one naming
    it (a sentence on dropped files gained a clause on a download routine two
    paragraphs on). A fact of a name the run holds grounds only the sentences it is
    shown for (:func:`_not_shown_for`).
    """
    if not fact.qualifier or fact.qualifier.lower() in reading.lowered:
        return False
    if _not_shown_for(fact, reading.sentence):
        return False
    if _about(fact, reading.sentence, reading.named):
        return True
    return (
        fact.on_absence
        and reading.unestablished
        and not reading.named
        and _about(fact, reading.passage, reading.passage_named)
    )


# An absence a routine or bound-value fact bears on without the sentence naming its
# address: one the run's own reading (the ledger, its entries, the listings or the
# function index) leaves unsettled. It is said by a negation and a reading word in one
# clause ("No environment check is established.", "The mutex name is not established.",
# "No listed call path selects Startup."); by that reading as the subject of a negated
# reading verb ("The ledger does not show whether the gate passed.", "This run did not
# trace the key assembly.", "we do not settle that question"); by a negation beside the
# code read ("No row of the function index lists them."); or by a routine, a caller or a
# call site not in that reading ("That caller trace is not in the ledger."). An absence
# the run recorded ("The sandbox recorded no API call trace."), a reading word before the
# negation ("all packets read, contains no DNS query") or a reading word in another clause
# ("carries no api_calls section [ev_0026], so the test is established from static
# reading") is not about code a routine fact is about (T-537).
#
# A negation reaches its reading word across at most this many characters of its
# clause: the longest reach in the stored runs' prose is 118. The bound keeps the read
# linear on a sentence quoting the sample's own text ("no no no ..."); a negation
# farther from its verb than this, within one clause, is not read as one.
_CLAUSE_REACH = 240
_IN_CLAUSE = rf"[^.;:()\u2014\u2013]{{0,{_CLAUSE_REACH}}}?"
# A sentence calling something absent from the whole code read: "no X ...
# appears", "no Y is present" or "is found", in one clause, in the present: what
# a run did not see ("no C2 was seen") is an observation, not the code's. Which code, and
# whether a fact or section 5 says otherwise, is the model's to read; a
# sentence naming an address is about that address and is held by what it names.
_WHOLE_CODE_ABSENCE = re.compile(
    r"\bno\b" + _IN_CLAUSE + r"\b(?:appears?|(?:is|are)\s+(?:present|found))\b"
    # In the past only where the same clause names the code read ("no reference
    # was found in the listings read"); never what a run saw or observed.
    r"|\bno\b(?="
    + _IN_CLAUSE
    + r"\b(?:code|listings?|decompil\w*|disassembl\w*)\b)"
    + _IN_CLAUSE
    + r"\b(?:was|were)\s+(?:found|present)\b",
    re.IGNORECASE,
)
# A negation of the conclusion or the limitations: something not attributed,
# known, tied, matched, identified, recovered, established, determined, named,
# resolved, read, shown, confirmed, exercised, watched or observed; unknown; or
# "no X is known". The body may state what it denies (T-562).
_CLOSING_NEGATION = re.compile(
    r"\b(?:not|never)\s+(?:been\s+|be\s+)?(?:\w+ly\s+)?(?:attributed|known|tied|matched|"
    r"linked|identified|recovered|established|determined|named|resolved|read|shown|"
    r"confirmed|exercised|watched|observed)\b"
    r"|\bunknown\b"
    r"|\bno\b" + _IN_CLAUSE + r"\b(?:is|are|was|were)\s+known\b",
    re.IGNORECASE,
)


# What a passage calls unsettled: "What the FNV routine hashes is not established",
# "the information-class values ... were not established" (haiku12, T-568), "The
# analysed sample is therefore not shown to use anti-debug or environment checks", "the
# exact flag test is not separately confirmed", "there is no evidence of" (haiku13,
# T-580); "unknown" or "unconfirmed" only as what is said of something ("is unknown",
# "unknown whether", "mechanism unknown" at a clause's end), never a noun's modifier.
# Such a sentence is held whether it is set in the code read or in what a run saw
# ("whether it passes in the sandbox is not established"); one set in a run is spoken of
# only by a sentence stating what a run saw (:func:`_body_speaking`). "Not observed"
# alone is an observation and no shape here.
_UNSETTLED_ABSENCE = re.compile(
    r"\b(?:is|are|was|were|be|been|has|have|had|remains?|remained)\s+"
    r"(?:(?:still|therefore|thus|hence|also|yet|so\s+far|as\s+yet|\w+ly)\s+){0,2}"
    r"(?:not|never)\s+(?:yet\s+)?(?:been\s+)?(?:\w+ly\s+)?"
    r"(?:established|recovered|determined|identified|known|resolved|shown|confirmed|"
    r"demonstrated|proven|evidenced)\b"
    r"|\b(?:is|are|was|were|remains?|remained)\s+(?:still\s+)?un(?:known|confirmed)\b"
    r"|\bun(?:known|confirmed)\s+(?:whether|how|what|which|why|who|where|when)\b"
    r"|\bun(?:known|confirmed)\s*(?:[.;:,()\[\]]|$)"
    r"|\bno\s+(?:\w+\s+){0,2}?evidence\s+(?:of|that|for)\b",
    re.IGNORECASE,
)


def whole_code_absences(
    text: str, *, unsettled: bool = False, by_clause: bool = False
) -> tuple[str, ...]:
    """The sentences of ``text`` that call something absent from the code read, naming
    no address (:data:`_WHOLE_CODE_ABSENCE`), in the order they stand; with
    ``unsettled`` (a section 5 passage), also those calling something not established
    (:data:`_UNSETTLED_ABSENCE`).

    With ``by_clause`` (a section 5 passage, the one written from the code), a sentence
    that names an address is held too where a clause stating the absence
    (:func:`_absence_clauses`) names none: "the code calls wrappers from 0x33ac, but
    the copy destination is not established" denies a destination, not anything of
    0x33ac (T-580). A clause that points back ("its body is not read", "…, which is
    not established", "…, though its write is not shown") names what the sentence
    names. In the passages written from the claims (key findings, identifier rows,
    procedures) such a clause is most often about the row's own code or about what a
    run saw, so there a sentence naming an address is read whole, as before."""
    out: list[str] = []
    for sentence in _sentences_of(text):
        named = bool(_addresses_named(sentence))
        if not named and (
            _WHOLE_CODE_ABSENCE.search(sentence)
            or (unsettled and _UNSETTLED_ABSENCE.search(sentence))
        ):
            # Read whole, as before: naming no address, the sentence is held.
            out.append(sentence)
            continue
        if (
            by_clause
            and named
            and any(
                not back and not _addresses_named(clause)
                for clause, back in _absence_clauses(sentence, unsettled=unsettled)
            )
        ):
            out.append(sentence)
    return tuple(out)


def _absence_clauses(sentence: str, *, unsettled: bool) -> list[tuple[str, bool]]:
    """The clauses of ``sentence`` that state an absence, as :func:`whole_code_absences`
    reads them, each with whether it points back to what an earlier clause names: a
    word pointing back (:data:`_POINTS_BACK`), or a clause a relative, a concession
    or a reason opens (:data:`_BACK_JOINS`)."""
    out: list[tuple[str, bool]] = []
    start = 0
    opened_by = ""
    for end in [*_ABSENCE_CLAUSE_END.finditer(sentence), None]:
        clause = sentence[start : end.start() if end is not None else len(sentence)]
        if _WHOLE_CODE_ABSENCE.search(clause) or (unsettled and _UNSETTLED_ABSENCE.search(clause)):
            back = bool(_POINTS_BACK.search(clause)) or (
                _JOIN_WORD.sub(r"\1", opened_by.strip().lower()) in _BACK_JOINS
            )
            out.append((clause, back))
        if end is not None:
            start, opened_by = end.end(), end.group(0)
    return out


def body_absences(passage: Passage) -> tuple[str, ...]:
    """The sentences of a passage other than a closing one that state an absence the body
    or the ledger may say otherwise of, in the order they stand (T-580): its whole-code
    absences (:func:`whole_code_absences`, with what it calls unsettled), in section 5 and
    in every passage written without the code alike. One naming an address is held to the
    ledger by what it names (``validation.ledger_absence_contradictions``, the unread
    listing of :func:`unread_listed_sentences`), as before."""
    return passage.whole_code


def closing_negations(text: str) -> tuple[str, ...]:
    """The sentences of a closing passage that deny or call unknown something the body
    may state (:data:`_CLOSING_NEGATION`), in the order they stand."""
    return tuple(s for s in _sentences_of(text) if _CLOSING_NEGATION.search(s))


_NEGATION_WORD = r"\b(?:no|not|never|none)\b"
_NOT_DONE = r"(?:\b(?:does|do|did|can|could)\s+not\s+|\bcannot\s+|\b(?:doesn|don|didn)'t\s+)"
_READ_VERB = (
    r"\b(?:establish|show|settle|trace|list|read|identify|recover|decompile|disassemble|"
    r"examine|name|link|sustain)(?:e?s)?\b"
)
_CODE_READ = r"\b(?:(?:function\s+)?index|these\s+functions|code\s+reads?|traced\s+(?:path|code))\b"
_UNESTABLISHED = re.compile(
    "|".join(
        (
            _NEGATION_WORD
            + _IN_CLAUSE
            + r"\b(?:established|shown|read|listed|traced|identified|recovered|decompiled|"
            r"disassembled|examined|settled)\b",
            r"\bunread\b",
            r"\b(?:ledger|entries|this\s+record|this\s+run|listings?|decompiles?|"
            r"(?:function\s+)?index|code\s+reads?)\b" + _IN_CLAUSE + _NOT_DONE + _READ_VERB,
            r"\bwe\s+" + _NOT_DONE + _READ_VERB,
            _NEGATION_WORD + _IN_CLAUSE + _CODE_READ,
            _CODE_READ + _IN_CLAUSE + _NEGATION_WORD,
            r"\b(?:caller|callee|call\s+(?:site|path)|routine)s?\b"
            + _IN_CLAUSE
            + _NEGATION_WORD
            + r"\s+in\s+the\s+(?:ledger|listings?|index|entries)\b",
        )
    ),
    re.IGNORECASE,
)
# Where a negation's clause ends for :data:`_UNESTABLISHED`: a joined clause or a citation.
# A citation holds no bracket of its own and is read only where its bracket closes, so
# an unclosed "[ev_..." is read once.
_CLAUSE_JOIN = re.compile(
    r",\s*(?:so|but|and)\s|\b(?:while|though|although|which|because)\b"
    r"|\[(?=[^\[\]]*\])[^\[\]]*\bev_\w+[^\[\]]*\]",
    re.IGNORECASE,
)
# Where an absence's clause ends inside a sentence: a joined clause or a citation
# (:data:`_CLAUSE_JOIN`), a semicolon or a colon.
_ABSENCE_CLAUSE_END = re.compile(_CLAUSE_JOIN.pattern + r"|[;:]", re.IGNORECASE)
# The joins whose clause speaks of what the clause before it names: a relative
# "which", and a concession or a reason ("…, though its write is not shown").
_BACK_JOINS = frozenset({"which", "though", "although", "because", "while"})
_JOIN_WORD = re.compile(r"^\W*(\w+)\W*$")
# A clause that points back to what an earlier clause names.
_POINTS_BACK = re.compile(
    r"\b(?:it|its|they|them|their)\b|^\W*(?:this|that|these|those|the\s+(?:routine|function))\b",
    re.IGNORECASE,
)


def _unsettled_by_reading(sentence: str) -> bool:
    """Whether a clause of the sentence says the run's own reading left something
    unsettled (:data:`_UNESTABLISHED`), read clause by clause."""
    return any(_UNESTABLISHED.search(part) for part in _CLAUSE_JOIN.split(sentence))


# A word an absence may be stated of.
_A_WORD = re.compile(r"[A-Za-z][\w-]*")


def _states_an_absence(sentence: str) -> bool:
    """Whether the sentence names something to say it is absent: a word of it the absence
    question reads as named absent (``validation.states_absence``'s reading of a
    mention)."""
    reader = _NegationReader(_read_dashes(sentence))
    return any(reader.named_as_absent(m.start(), m.end()) for m in _A_WORD.finditer(sentence))


def _qualified(sentence: str, facts: Sequence[Passage]) -> str:
    """The sentence as written, with each fact's own clause and the entries they cite added.

    The rewrite of a section 5 sentence on a fact is the platform's: the model
    decides that the sentence is qualified, and its words for it are not read.
    """
    base = sentence.rstrip()
    # A quote or a bracket closing after the end mark stays with the words it
    # closes; the end mark moves after the clauses.
    core = base.rstrip("\"')]")
    closers = base[len(core) :]
    end = "."
    if core and core[-1] in ".!?":
        end = core[-1]
        base = core[:-1].rstrip() + closers
    clauses = "; ".join(dict.fromkeys(fact.qualifier for fact in facts))
    cites = "".join(f"[{c}]" for c in sorted(set().union(*(fact.cites for fact in facts))))
    return f"{base}; {clauses} {cites}{end}"


def _platform_rewrites(payload: Any, by_id: dict[str, Passage]) -> Any:
    """The payload with each section 5 rewrite resting on a fact written by the platform:
    the sentence unchanged and the facts' clauses (``_qualified``). Every other row as the
    model wrote it. One pass over the rows."""
    rows = payload.get("sentences") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return payload
    out: list[Any] = []
    for row in rows:
        passage = by_id.get(_form(row.get("passage"))) if isinstance(row, dict) else None
        if (
            passage is not None
            and passage.kind == SECTION_5
            and isinstance(row, dict)
            and row.get("decision") == "rewrite"
        ):
            named = row.get("sources")
            standing = located(passage.text, str(row.get("sentence") or ""))
            if standing and _in_own_words(
                passage,
                standing,
                [by_id.get(_form(n)) for n in (named if isinstance(named, list) else [])],
            ):
                # The model's words, read as any passage's rewrite is.
                out.append(row)
                continue
            reading = _Reading(standing or "", passage.text)
            facts = [
                fact
                for fact in (
                    by_id.get(_form(n)) for n in (named if isinstance(named, list) else [])
                )
                if fact is not None and fact.kind == FACT and standing and _grounds(fact, reading)
            ]
            if standing and facts:
                row = {**row, "rewrite": _qualified(standing, facts)}
        out.append(row)
    return {**payload, "sentences": out}


# A bound value is named only whole and at least this long: a shorter one is
# part of too many words.
_VALUE_FLOOR = 3


def _about(fact: Passage, text: str, named: frozenset[int] | None = None) -> bool:
    """Whether a fact is about what the text names: an address it names, in any spelling
    the absence check reads, as a word of its own (:func:`_addresses_named`; ``named``
    when already read), or the value it binds or the call it is passed to, written
    whole."""
    for word in (fact.value, fact.call, *fact.names):
        if len(word) >= _VALUE_FLOOR and re.search(
            r"(?<!\w)" + re.escape(word) + r"(?!\w)", text, re.IGNORECASE
        ):
            return True
    if not fact.addresses:
        return False
    return not fact.addresses.isdisjoint(_addresses_named(text) if named is None else named)


def _grounding_violations(
    row: AgreementRow,
    index: int,
    passage: Passage,
    sources: list[Passage],
    span: tuple[int, int, str, int] | None,
    *,
    ungrounded: bool = True,
) -> list[Violation]:
    """What a rewrite cites against what its sources, its passage and its sentence cite.

    ``ungrounded`` off: the caller has said already why no source grounds it.
    """
    path = f"sentences.{index}.rewrite"
    number = safe_finding_value(index + 1)
    out: list[Violation] = []
    otherwise = _otherwise(passage, span[2] if span is not None else "")
    cited = entry_ids_in(row.rewrite)
    grounds = set().union(*(source.cites for source in sources))
    elsewhere = sorted(cited - grounds - set(passage.cites))
    if elsewhere:
        out.append(
            Violation(
                code=REWRITE_CITES_ELSEWHERE_CODE,
                message=(
                    f"row {number}: the rewrite cites "
                    f"{safe_finding_value(', '.join(elsewhere))}, which neither its sources "
                    f"nor {safe_finding_value(passage.id)} cite. {_CITE_ONLY}"
                ),
                path=path,
            )
        )
    dropped = sorted(entry_ids_in(span[2]) - cited) if span is not None else []
    if dropped:
        out.append(
            Violation(
                code=REWRITE_DROPS_CITATION_CODE,
                message=(
                    f"row {number}: the sentence cites "
                    f"{safe_finding_value(', '.join(dropped))}, which the rewrite does not. "
                    f"{_KEEP_EVERY_ID}, {otherwise}."
                ),
                path=path,
            )
        )
    if ungrounded and not cited & grounds:
        out.append(
            Violation(
                code=REWRITE_UNGROUNDED_CODE,
                message=(
                    f"row {number}: the rewrite cites none of the ids its sources cite"
                    + ("" if grounds else ", and sources that cite none ground no rewrite")
                    + f". {_CITE_A_SOURCE}, {otherwise}."
                ),
                path=path,
            )
        )
    return out


def agreement_violations(
    payload: Any,
    passages: Sequence[Passage],
    citable: Sequence[str] = (),
    items: Any = None,
    entries: EntryTexts | None = None,
) -> list[Violation]:
    """What is structurally wrong with the answer's rows, as the retry turn shows it.

    Nothing for an answer that does not fit the schema: the schema check
    speaks for it. Each passage is cut into sentences once; a section 5
    rewrite on a fact is read as the platform writes it (``_platform_rewrites``).
    A refused row for a sentence another row answers passing every check, its
    rewrite read against ``citable``, ``items`` and ``entries`` (:func:`_checked_rows`),
    asks nothing more (T-600).
    """
    by_id = {passage.id: passage for passage in passages}
    payload = _platform_rewrites(payload, by_id)
    cut: dict[str, _Sentences] = {}

    def _sentences(passage: Passage) -> _Sentences:
        if passage.id not in cut:
            cut[passage.id] = _Sentences(passage.text)
        return cut[passage.id]

    out: list[Violation] = []
    listed: set[tuple[str, int]] = set()
    rewritten: set[tuple[str, int]] = set()
    # The row answering each sentence, the last where more than one does, and the sentences
    # a row's own refusals name the listing for (T-600).
    answering: dict[tuple[str, int], AgreementRow] = {}
    unread_told: set[tuple[str, int]] = set()
    rows = _rows(payload)
    checked, passed = _checked_rows(rows, by_id, _sentences, citable, items, entries)
    for _index, row, passage, found, rewritten_found, span in checked:
        if passage is not None and span is not None and (passage.id, span[0]) not in passed:
            # The row's last refusal is its rewrite's, where one is refused
            # (:func:`rewrites_violations`, asked after this check).
            out.extend(
                _told_the_end(
                    passage, span[2], found, beside=rewritten_found, last=not rewritten_found
                )
            )
        elif passage is None or span is None:
            out.extend(found)
        if passage is not None and span is not None:
            listed.add((passage.id, span[0]))
            answering[(passage.id, span[0])] = row
            if any(v.code == UNREAD_STANDING_CODE for v in found):
                unread_told.add((passage.id, span[0]))
            # A rewrite whose own finding names the listing is asked about once.
            if row.decision in ("rewrite", "drop") and (
                not found or any(v.code == UNREAD_STANDING_CODE for v in found)
            ):
                rewritten.add((passage.id, span[0]))
    if isinstance(payload, dict):
        out.extend(
            _held_unlisted(
                passages,
                listed,
                _sentences,
                rewritten,
                read=bool(rows),
                answering=answering,
                unread_told=unread_told,
            )
        )
    return out


def _unread_standing(
    passage: Passage, sentence: str, facts: Sequence[Passage], end: str, rewrite: str = ""
) -> Violation:
    """The retry's question on a sentence calling listed code not read, or on its ``rewrite``
    still calling it so: the listing named, a drop offered where it passes (a closing
    passage, a sentence the ledger's lines hold), and ``end``, what becomes of it where the
    answer refused is its last (:func:`_unread_end`)."""
    shown = "; ".join(fact.text for fact in facts)
    return Violation(
        code=UNREAD_STANDING_CODE,
        message=(
            f"{safe_finding_value(passage.id)}: "
            + (
                f"the rewrite {safe_finding_value(rewrite)!r} of "
                f"{safe_finding_value(sentence)!r} still calls"
                if rewrite
                else f"{safe_finding_value(sentence)!r} calls"
            )
            + " code not read that the ledger lists "
            f"({safe_finding_value(', '.join(f.id for f in facts))}: "
            f"{safe_finding_value(shown)}). {_STATE_THE_READING} and what the sentence can "
            "still say, citing an entry that fact cites"
            + (f", {_OR_DROP}" if passage.closing or _held_by_the_ledger(passage, sentence) else "")
            + (f"; {safe_finding_value(end)}." if end else ".")
            + _EVERY_ROW
        ),
        path=f"held.{passage.id}",
    )


def _held_unlisted(
    passages: Sequence[Passage],
    listed: set[tuple[str, int]],
    sentences_of: Callable[[Passage], _Sentences],
    rewritten: set[tuple[str, int]] | None = None,
    *,
    read: bool = True,
    answering: Mapping[tuple[str, int], AgreementRow] | None = None,
    unread_told: set[tuple[str, int]] | None = None,
) -> list[Violation]:
    """Each held sentence no row lists, in the passages' order; one whose own clause calls
    listed code not read and that no row rewrote is asked about with the listing named. One
    the passage writes more than once, which no row can name, is not asked about: a refusal
    the round cannot act on opens no retry, and one the ledger's own lines hold is left out
    each time it stands (:func:`apply_rows`, T-600). A sentence of a field answered whole
    is told what the field is, its ends and what an emptied one prints; where no row could
    be read (``read`` false), one nothing but its field's kind holds is not asked about:
    it prints as written then, with no record of its own (T-600). A closing sentence a row
    lists (``answering``) is asked about only where that row's own refusals do not name the
    listing already (``unread_told``), told the end that row's refusal brings it to
    (:func:`_unread_end`, T-600)."""
    by_id = {passage.id: passage for passage in passages}
    out: list[Violation] = []
    for passage in passages:
        unread = {sentence: ids for sentence, ids, _own in passage.unread_listed}
        for sentence in passage.held:
            span = sentences_of(passage).span(sentence)
            if span is None:
                continue
            if passage.whole and not read and not _held_by_the_ledger(passage, sentence):
                continue
            decisive = _decisive_unread(passage, sentence)
            if (
                decisive
                and passage.write is not None
                and (passage.id, span[0]) not in (rewritten or ())
                # A row answering a closing sentence whose own refusals name the listing has
                # been told its end by them.
                and not (passage.closing and (passage.id, span[0]) in (unread_told or ()))
            ):
                facts = [f for f in (by_id.get(i) for i in decisive) if f is not None]
                if facts:
                    row = (answering or {}).get((passage.id, span[0]))
                    asked = _unread_standing(
                        passage, sentence, facts, _unread_end(passage, sentence, row, by_id)
                    )
                    # A field answered whole, or a sentence the ledger's lines hold, is told its
                    # end, and what the field is.
                    out.extend(_told_the_end(passage, sentence, [asked]))
                    continue
            if (passage.id, span[0]) in listed:
                continue
            ids = unread.get(sentence)
            # A sentence held on a name or to a redone call, or one no keep passes for, is
            # told its own ends.
            ends = _closing_ends(passage, sentence) or _named_body_ends(passage, sentence)
            said = (
                f"calls code not read that {safe_finding_value(', '.join(ids))} "
                "states an entry lists"
                if ids
                else "calls something absent from the whole code read"
                if sentence in passage.whole_code
                else "states a branch or an argument of a routine a listing.N fact shows"
                if any(s == sentence for s, _ids in passage.branch_sense)
                else "names what a ledger.N fact shows"
                if any(s == sentence for s, _ids in passage.ledger_named)
                else "denies what a decoded value's fact may state"
                if sentence in passage.on_fact
                else "states an absence the body or the ledger may say otherwise of"
                if sentence in passage.absences and not passage.closing
                else f"is {passage.whole}"
                if passage.whole
                else "holds a sentence of a closing section, every one of which is answered"
                if passage.closing
                else "gives failed calls a number the ledger's count may not"
                if count_disagrees(sentence, passage.counts)
                else "calls open what a section 5 passage or a fact may state"
            )
            out.append(
                Violation(
                    code=HELD_UNLISTED_CODE,
                    message=(
                        f"{safe_finding_value(passage.id)} {said}, and no row lists this "
                        f"sentence: {safe_finding_value(sentence)!r}. List it: "
                        + (
                            _whole_ends(passage, sentence)
                            if passage.whole
                            else ends
                            or _LIST_IT
                            + (
                                f", quoting its words, {_LIST_IT_LEAVING}"
                                if passage.closing
                                else f", quoting its words, {_LIST_IT_ABSENCE}"
                                if sentence in passage.absences
                                else ""
                            )
                            + "."
                        )
                        + _EVERY_ROW
                    ),
                    path=f"held.{passage.id}",
                )
            )
    return out


def _rewrite_violations(
    text: str,
    citable: Sequence[str],
    items: Any,
    entries: EntryTexts | None,
) -> list[Violation]:
    """A rewrite read as the report rounds read their prose."""
    prose = {"rewrite": text}
    return [
        *citation_violations(prose, citable, prose=("rewrite",), items=items),
        *wrong_entry_citations(prose, entries, prose=("rewrite",)),
        *misstated_entry_contents(prose, entries, prose=("rewrite",)),
        *ledger_absence_contradictions(prose, entries),
    ]


def rewrites_violations(
    payload: Any,
    citable: Sequence[str],
    items: Any,
    entries: EntryTexts | None,
    passages: Sequence[Passage] = (),
) -> list[Violation]:
    """Each rewrite's prose findings, its row named in the path; a rewrite of a sentence
    the ledger's lines hold, among ``passages``, is told what becomes of it, and one of a
    sentence another row answers passing every check (:func:`_checked_rows`) asks nothing
    more (T-600)."""
    by_id = {passage.id: passage for passage in passages}
    cut: dict[str, _Sentences] = {}

    def _sentences(passage: Passage) -> _Sentences:
        if passage.id not in cut:
            cut[passage.id] = _Sentences(passage.text)
        return cut[passage.id]

    out: list[Violation] = []
    checked, passed = _checked_rows(_rows(payload), by_id, _sentences, citable, items, entries)
    for index, _row, passage, own, rewritten, span in checked:
        if passage is not None and span is not None and (passage.id, span[0]) in passed:
            continue
        found = [
            replace(
                violation,
                message=(
                    f"row {safe_finding_value(index + 1)}: {safe_finding_value(violation.message)}"
                ),
                sentence="",
                path=f"sentences.{index}.rewrite",
            )
            for violation in rewritten
        ]
        out.extend(_told_the_end(passage, span[2] if span is not None else None, found, beside=own))
    return out


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

EXPECTED_OBJECT = """{
  "sentences": [
    {
      "passage": "execution_flow.3",
      "sentence": "The sentence exactly as the passage writes it.",
      "sources": ["persistence_detail"],
      "decision": "rewrite",
      "rewrite": "The sentence as it should read, stating what the sources state [ev_0007]."
    }
  ]
}"""

SYSTEM_PROMPT = (
    "You are a senior malware reverse engineer reading one analysis report for agreement "
    "between its parts. Its sections were written at the same time by separate calls: the "
    "passages under PASSAGES WRITTEN WITHOUT THE CODE from the analysts' claims, shown "
    "neither the code nor section 5; section 5's passages from the code and the tool "
    "answers. The facts were read from the evidence by code and outrank every model's "
    "words. A routine no entry lists means its code was not examined, not that it does or "
    "does not do anything; it contradicts only a sentence that says that code was read, or "
    "that calls a behaviour absent from the sample on the grounds of the code read; it never "
    "contradicts what another entry (a rule match, an emulation, a call graph) states about "
    "that routine. A routine an entry lists was read: the listing contradicts a sentence that "
    "calls that routine's code or body not read, not shown or not in the evidence. "
    "A call a later call answered did not fail for good. "
    "A ledger.N fact states what the run's answers hold of a name: the routines calling an "
    "API (the call lines, each slot named), an export's address and callees, a decoded "
    "text's routines. "
    "A debate round is the mediator's words: a line it closed counts as settled only "
    "with the entry it closed it on. " + QUOTED_VALUE_STATEMENT + "\n"
    "List each sentence of a passage written without the code that calls absent, unknown, "
    "open, unresolved, not shown or not established what a section 5 passage, a fact or a "
    "closed debate line states, or that states the opposite of what one of them states; and "
    "each sentence of a section 5 passage that a fact contradicts. For each, give the "
    "passage's id, the whole sentence copied exactly as it stands, the ids of the sources "
    "that state otherwise (a section 5 passage is answered by a fact alone), and one "
    "decision:\n"
    "  - rewrite: the sentence as it should read, stating what the sources state with their "
    "certainty (what they assess, it assesses; what they say is not shown, it says is not "
    "shown), in the passage's style, keeping every ev_ id the sentence cites and citing in "
    "square brackets at least one ev_ id its sources cite, and no id that neither the "
    "sources nor the passage cite;\n"
    "  - keep: the sources do not state otherwise on reading (they speak of another routine, "
    "value or run), or the passage is marked (read only): a passage so marked is listed with "
    "keep and never rewritten. A section 5 sentence is rewritten only where a fact contradicts it, "
    "and then states what the fact states and nothing a passage written without the code or "
    "a debate round says. A section 5 sentence answered by a fact is not reworded: the "
    "decision rewrite only asks that it be qualified, and the platform adds the fact's own "
    "words and its ids to the sentence as it stands; it is qualified only where the "
    "sentence names the routine, the address, the value or the call the fact is about, or, "
    "for a fact about a routine or a bound value, where the sentence states that the run's own "
    "reading (the ledger, its entries, the listings or the function index) does not "
    "establish, show, settle, trace or list something, names no address and its passage "
    "names what the fact is about.\n"
    "Leave out every sentence no source states otherwise than. List each sentence once. "
    "Answer with exactly this JSON object, with an empty list when no sentence disagrees:\n"
    + EXPECTED_OBJECT
)

_HEADINGS = (
    (FACT, "FACTS THE PLATFORM STATES"),
    (SECTION_5, "SECTION 5, WRITTEN FROM THE CODE AND THE TOOL ANSWERS"),
    (DEBATE, "THE DEBATE'S MEDIATIONS, IN ROUND ORDER"),
    (CLAIM_LED, "PASSAGES WRITTEN WITHOUT THE CODE"),
)


def prompt_text(passages: Sequence[Passage]) -> str:
    """The round's human turn: each kind of passage under its heading, then the task."""
    lines: list[str] = []
    for kind, heading in _HEADINGS:
        group = [passage for passage in passages if passage.kind == kind]
        if not group:
            continue
        lines.extend([heading, "-" * len(heading)])
        for passage in group:
            cites = f" (cites {', '.join(sorted(passage.cites))})" if passage.cites else ""
            # Model-written text and the sample's own: one quoted value each.
            text = passage.text if passage.kind == FACT else quoted_value(passage.text)
            shown = (
                _VERBATIM_MARK
                if passage.verbatim
                else " (read only)"
                if passage.kind in (CLAIM_LED, SECTION_5) and passage.write is None
                else ""
            )
            lines.append(f"- [{passage.id}] {passage.label}{shown}{cites}: {text}")
            noted = passage.whole_code if passage.kind == SECTION_5 else ()
            denied = passage.on_fact if passage.kind == SECTION_5 else ()
            # A body absence written without the code, asked with how it is kept (T-580).
            absent = (
                tuple(a for a in passage.absences if a not in noted and a not in denied)
                if passage.kind == CLAIM_LED and not passage.closing
                else ()
            )
            branch = tuple(
                s for s, _ids in passage.branch_sense if s not in noted and s not in denied
            )
            # Read against what the ledger holds of a name (T-600): asked once, under it.
            named = dict(passage.ledger_named)
            absent = tuple(a for a in absent if a not in named)
            held = [
                sentence
                for sentence in passage.held
                if sentence not in noted
                and sentence not in denied
                and sentence not in absent
                and sentence not in branch
                and sentence not in named
            ]
            if passage.closing and _writable(passage):
                # Every sentence is held: the passage is shown once, not again. A field
                # answered whole is told so once, in the TASK, for every such field (T-600).
                count = len(_sentences_of(passage.text))
                if not passage.whole:
                    lines.append(
                        f"  [{passage.id}] answer every sentence of this passage, one row each "
                        f"({count} {'sentence' if count == 1 else 'sentences'}), as the TASK asks."
                    )
                held = []
            if held:
                # Read off the passage by code: each one is listed, as the model decides.
                lines.append(
                    f"  [{passage.id}] list each of these sentences: "
                    + "; ".join(quoted_value(sentence) for sentence in held)
                )
            if noted:
                # Read off the passage by code: no address names what they deny.
                lines.append(
                    f"  [{passage.id}] each of these calls something absent from the whole "
                    "code read; if a fact or another section 5 passage shows it, rewrite it in "
                    "your own words, citing an entry that source cites, else list it with "
                    f"keep{_ABSENCE_KEPT}: "
                    + "; ".join(quoted_value(sentence) for sentence in noted)
                )
            if absent:
                # Read off the passage by code: each states an absence (T-580).
                lines.append(
                    f"  [{passage.id}] each of these states an absence; if a source states "
                    "otherwise, rewrite it on that source, else list it with "
                    f"keep{_ABSENCE_KEPT}: "
                    + "; ".join(quoted_value(sentence) for sentence in absent)
                )
            if branch and not passage.closing:
                # Read off the passage by code: a listing.N fact shows the routine (T-580).
                lines.append(
                    f"  [{passage.id}] each of these states a branch (a condition and what "
                    "follows it) or an argument of a routine a listing.N fact shows; read it "
                    "against that listing: where the listing shows otherwise (the other branch, "
                    "another argument or local), rewrite it on the listing, citing an entry the "
                    "fact cites, else list it with keep: "
                    + "; ".join(quoted_value(sentence) for sentence in branch)
                )
            # Read off the passage by code: a ledger.N fact shows what each one names. A body
            # sentence no keep passes for is offered none (``Passage.unkept``, T-600).
            for ends, by_ends in (
                (
                    _held_name_ends(bool(passage.unredone_failed))
                    if passage.closing
                    else _HELD_NAME_BODY_ENDS,
                    {
                        s: ids
                        for s, ids in named.items()
                        if passage.closing or s not in passage.unkept
                    },
                ),
                (
                    _HELD_UNKEPT_BODY_ENDS,
                    {
                        s: ids
                        for s, ids in named.items()
                        if not passage.closing and s in passage.unkept
                    },
                ),
            ):
                if by_ends:
                    lines.append(
                        f"  [{passage.id}] each of these denies something and names what a "
                        f"ledger.N fact shows (an API's call lines, an export, a decoded text); "
                        f"{ends}; {_LEFT_OUT_END}: "
                        + "; ".join(
                            f"{quoted_value(sentence)} ({', '.join(ids)})"
                            for sentence, ids in by_ends.items()
                        )
                    )
            if passage.redone_named:
                # Read off the passage by code: the redone calls each one names (T-600),
                # in the number of the most any one names.
                most = max(len(ids) for _sentence, ids in passage.redone_named)
                lines.append(
                    f"  [{passage.id}] each of these names a call that failed and a later call "
                    "redid, and cites none of the calls that redid it: a keep of it as written "
                    "is refused, and the same words with a citation added are a keep; "
                    + _redone_rewrite(
                        "the call named here" if most == 1 else "the calls named here",
                        most,
                        unredone=bool(passage.unredone_failed),
                    )
                    + f"; {_LEFT_OUT_END}: "
                    + "; ".join(
                        f"{quoted_value(sentence)} (cite {' and '.join(ids)})"
                        for sentence, ids in passage.redone_named
                    )
                )
            redone = dict(passage.redone_named)
            unkept = [s for s in passage.unkept if s not in named and s not in redone]
            if passage.closing and unkept:
                # Read off the passage by code: the ledger says otherwise of each one whatever
                # a keep of it names (``Passage.unkept``), so each is told the ends that pass
                # for it and what becomes of it where none does, once for the sentences told
                # the same (T-600).
                told: dict[str, list[str]] = {}
                for sentence in unkept:
                    told.setdefault(_closing_ends(passage, sentence), []).append(sentence)
                lines.extend(
                    f"  [{passage.id}] {'; '.join(quoted_value(s) for s in alike)}: {ends}"
                    for ends, alike in told.items()
                )
            if denied:
                # Read off the passage by code: a decoded value's fact may contradict them.
                lines.append(
                    f"  [{passage.id}] each of these denies something; where a bound.N fact "
                    "states it, rewrite it in your own words, stating what the fact states and "
                    "keeping no clause the fact contradicts, citing an entry the fact cites, "
                    "else list it with keep: "
                    + "; ".join(quoted_value(sentence) for sentence in denied)
                )
        lines.append("")
    lines.extend(
        [
            "TASK",
            "----",
            "List each sentence that says otherwise than its sources, as the system prompt "
            f"asks. Return ONLY the JSON object shown there. {_QUOTE_FLOOR_SAID}",
        ]
    )
    closing = [p.id for p in passages if p.closing and _writable(p)]
    if closing:
        lines.append(_CLOSING_TASK.format(ids=", ".join(f"[{pid}]" for pid in closing)))
    if any(p.verbatim for p in passages):
        lines.append(_VERBATIM_TASK)
    whole = [p for p in passages if p.whole and _writable(p)]
    if whole:
        # Said once for every field answered whole, not per passage (T-600).
        lines.append(
            f"Of these, {', '.join(f'[{p.id}]' for p in whole)} are value cells and capability "
            f"bullets: for each sentence of them, {_LEFT_OUT_END}; "
            + "; ".join(dict.fromkeys(p.emptied for p in whole))
            + "."
        )
    return "\n".join(lines)


# How the question marks a passage printed in its writer's own words, and what the TASK says
# of every such passage once (T-613).
_VERBATIM_MARK = " (verbatim)"
_VERBATIM_TASK = (
    "A passage marked (verbatim) prints an analyst's or the judge's own words: list a sentence "
    f"of it only where a source states otherwise; never rewrite it: {_VERBATIM_ENDS}. "
    + _sentence_start(_VERBATIM_LEFT_OUT)
)


# What the round asks of the conclusion and the limitations, every sentence of which
# is answered (T-568): a closing section sums up the body, and a closing denial of
# what the body states from the code says otherwise even where it means "not seen".
_CLOSING_TASK = (
    "Besides, answer EVERY sentence of {ids}, one row each, against section 5, the facts "
    "and the closed debate lines. A sentence calling something not established, not "
    "recovered, not known, not read, read only in part, failed or not passed says otherwise "
    "where section 5 states it from the code, or a fact shows the code listed or the call "
    "redone, even where it means that the run did not observe it: then rewrite it to say "
    "what was not observed and what the code shows, keeping no clause a source contradicts. "
    'Keep a sentence only naming the sources you read, with "quote": the words of one of '
    "them that state the same thing, copied exactly (an absence is kept only on words that "
    'state that absence); where no source speaks of it, keep it with "sources": [] and '
    '"reason". Where it cannot be stated truly, answer "decision": "drop" with "reason".'
)


# How a held absence of the body is kept (T-580): as a closing sentence is, never left out.
_ABSENCE_KEPT = (
    ', naming the source you read with "quote": its words that state the same absence, '
    'copied exactly, or with "sources": [] and "reason" where no source speaks of it'
)


def build_messages(passages: Sequence[Passage]) -> list[BaseMessage]:
    """The system turn and the human turn."""
    return [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt_text(passages))]


# ---------------------------------------------------------------------------
# The round
# ---------------------------------------------------------------------------


@dataclass
class AgreementRound:
    """What the round did: its counts, what it was told, and what it could not do."""

    summary: dict[str, int] = field(default_factory=dict)
    tally: ValidationTally = field(default_factory=ValidationTally)
    degradations: list[str] = field(default_factory=list)


def _rests_on_a_source(row: AgreementRow, by_id: dict[str, Passage]) -> bool:
    """Whether every source a row names is one a passage written without the code is
    answered by: a fact, a section 5 passage or a debate round it was shown."""
    return bool(row.sources) and all(
        (source := by_id.get(_form(name))) is not None and source.kind in (FACT, SECTION_5, DEBATE)
        for name in row.sources
    )


# A row as :func:`_checked_rows` reads it: its index, the row, its passage, its own
# refusals, its rewrite's, and the span of its sentence.
_CheckedRow = tuple[
    int,
    AgreementRow,
    Passage | None,
    list[Violation],
    list[Violation],
    tuple[int, int, str, int] | None,
]


def _checked_rows(
    rows: Sequence[tuple[int, AgreementRow]],
    by_id: dict[str, Passage],
    sentences_of: Callable[[Passage], _Sentences],
    citable: Sequence[str],
    items: Any,
    entries: EntryTexts | None,
) -> tuple[list[_CheckedRow], set[tuple[str, int]]]:
    """Each row with the passage and the sentence it names, its own refusals
    (:func:`_row_violations`) and its rewrite's (:func:`_rewrite_violations`); and the
    sentences a row that passed every check answers, read over every row first: such an
    answer stands, and a refused row for the same sentence, before or after it, ends
    nothing and asks nothing more, in a closing passage as in any other (T-600)."""
    passed: set[tuple[str, int]] = set()
    checked: list[_CheckedRow] = []
    for index, row in rows:
        passage = by_id.get(_form(row.passage))
        own = _row_violations(row, index, by_id, sentences_of)
        rewritten = (
            _rewrite_violations(row.rewrite, citable, items, entries)
            if row.decision == "rewrite"
            else []
        )
        span = sentences_of(passage).span(row.sentence) if passage is not None else None
        if passage is not None and span is not None and not own and not rewritten:
            passed.add((passage.id, span[0]))
        checked.append((index, row, passage, own, rewritten, span))
    return checked, passed


def apply_rows(
    payload: Any,
    passages: Sequence[Passage],
    *,
    citable: Sequence[str] = (),
    items: Any = None,
    entries: EntryTexts | None = None,
    asked: bool = True,
) -> tuple[dict[str, int], list[Violation]]:
    """Put each rewrite that passes every check where its sentence stands; the counts.

    Every row is read against each passage as it was written, so a row never
    finds its sentence inside another row's rewrite; a row whose sentence
    overlaps one an earlier row already rewrites is not applied. The rewrites
    of one passage are put in together, from its end; a sentence found through
    its escapes read back has its rewrite read back the same way. Each rewrite
    put in is returned as a finding the model answered (``REWRITTEN_CODE``),
    with what stood; a sentence of a passage shown for reading is listed:
    kept, and returned the same way (``LISTED_CODE``). A section 5 rewrite
    resting on a routine whose code no entry lists is the platform's
    (``_platform_rewrites``). A sentence of a closing passage (the conclusion,
    the limitations) whose rewrite still fails, on a row every source of which it
    may rest on, is left out of the passage and returned with what stood
    (``DROPPED_CODE``). A sentence the ledger's own lines hold (:func:`_held_by_the_ledger`)
    that no answer passing the checks answers is left out the same way, of a closing passage
    or of the body, where it would otherwise print as written: one whose answer a check
    refuses, recorded with what holds it and every code refusing the answer, and one no row
    answers, recorded with what holds it; where this function already changes or leaves out
    the sentence, that end stands, with its own record, and the platform's qualification
    takes neither such a sentence nor, where a row was read, one of a field answered whole
    (:func:`_qualify_unread_left`). A drop of it is the round's answer, recorded with what
    holds it (T-600). A row that passes answers its sentence, whatever another row for it
    says. One the passage writes more than once, which no row can name, is left out each
    time it stands. Where
    no row at all can be read, or the question got no answer (``asked`` false: the call
    failed; nothing else is changed then), each such sentence is left out for that one
    reason. Every other answer ends as before.
    """
    by_id = {passage.id: passage for passage in passages}
    payload = _platform_rewrites(payload, by_id)
    cut: dict[str, _Sentences] = {}

    def _sentences(passage: Passage) -> _Sentences:
        if passage.id not in cut:
            cut[passage.id] = _Sentences(passage.text)
        return cut[passage.id]

    counts = {
        "passages": sum(1 for passage in passages if _writable(passage)),
        "claim_led_passages": sum(
            1 for passage in passages if _writable(passage) and passage.kind == CLAIM_LED
        ),
        "sentences": 0,
        "rewritten": 0,
        "kept": 0,
        "listed": 0,
        "not_applied": 0,
        "dropped": 0,
        "qualified": 0,
        "held_kept": 0,
    }
    listed: list[Violation] = []
    written: list[Violation] = []
    spans: dict[str, list[tuple[int, int, str]]] = {}
    # Each sentence the ledger's own lines hold that would print as written though no answer
    # for it passed: left out once every other end is in (T-600), with the record of why.
    unpassed: list[tuple[Passage, tuple[int, int, str, int], str, Sequence[Violation], str]] = []
    answered: set[tuple[str, int]] = set()
    rows = _rows(payload) if asked else []
    checked, passed = _checked_rows(rows, by_id, _sentences, citable, items, entries)
    for index, row, passage, own, rewritten, span in checked:
        found = [*own, *rewritten]
        if passage is not None and span is not None:
            answered.add((passage.id, span[0]))
        counts["sentences"] += 1
        if found and passage is not None and span is not None and (passage.id, span[0]) in passed:
            # Another row's answer passed: this refused one is not applied.
            counts["not_applied"] += 1
            continue
        held = _ends_on_answer(passage, span[2]) if passage and span else ""
        # Why such a sentence is left out where its answer is refused.
        refused = (
            ("the ledger says otherwise; " if _ledger_says_otherwise(found) else "")
            + (
                "no rewrite of it passed the checks"
                if row.decision == "rewrite"
                else f"its last answer, a {row.decision}, was refused"
            )
            + f"; {held}"
            if held and found
            else ""
        )
        if refused and passage is not None and span is not None:
            if row.decision == "drop" or (
                row.decision == "keep"
                and not (passage.closing and (_ledger_says_otherwise(found) or _unbacked(found)))
            ):
                # A refused drop, or a refused keep this function would let stand: left out
                # below, unless the platform's qualification takes the sentence first.
                unpassed.append((passage, span, refused, found, f"sentences.{index}"))
                continue
        if row.decision == "keep":
            standing = span
            # A held absence of the body, kept: never left out, counted where its quote
            # passed every check on two or more of its words, else recorded (T-580).
            absent = (
                passage is not None
                and not passage.closing
                and standing is not None
                and standing[2] in passage.absences
            )
            # A section 5 sentence a fact was listed against is recorded as
            # listed, as it was before it could be rewritten.
            if passage is not None and _listed_when_kept(passage) and not found and not absent:
                counts["listed"] += 1
                listed.append(
                    Violation(
                        code=LISTED_CODE,
                        message=(
                            f"The agreement question lists a sentence of "
                            f"{safe_finding_value(passage.label)} as saying otherwise than "
                            f"{safe_finding_value(', '.join(_form(s) for s in row.sources))}; "
                            "the sentence stands as written."
                        ),
                        path=f"sentences.{index}",
                        answered=True,
                    )
                )
            elif (
                passage is not None
                and passage.closing
                and (_ledger_says_otherwise(found) or _unbacked(found))
            ):
                # A closing sentence the ledger itself says otherwise of (a failed
                # call a later call redid), or kept on no source or a quote the checks
                # refused, is never kept as written: the closing sections state only
                # what a source backs. Left out, and recorded with what stood and the
                # refused keep's sources, quote or reason (T-568).
                taken = spans.setdefault(passage.id, [])
                if span is None or any(
                    span[0] < end and start < span[1] for start, end, _ in taken
                ):
                    counts["not_applied"] += 1
                    continue
                taken.append((*left_out_span(passage.text, span[0], span[1]), ""))
                counts["dropped"] += 1
                why = (
                    "the ledger says otherwise"
                    if _ledger_says_otherwise(found)
                    else "kept on no source a check accepts: "
                    + (
                        f"{', '.join(_form(s) for s in row.sources)}, quoting "
                        f"{_capped(row.quote)!r}"
                        if row.sources
                        else f"no source, because {_capped(row.reason)!r}"
                    )
                )
                written.append(_left_out(passage, f"sentences.{index}", span[2], why, found))
            else:
                counts["kept"] += 1
                if (
                    passage is not None
                    and (passage.closing or absent)
                    and standing is not None
                    and standing[2] in passage.held
                ):
                    counts["held_kept"] += 1
                    # A closing sentence kept on a source whose quote passed every
                    # check, on two or more words of what it denies something of, is
                    # counted; one kept on no source, on a source a check refused, or
                    # on fewer of those words, is recorded with what it rests on (T-568).
                    reason = (
                        entry_keep_reason(
                            standing[2], row.quote, [by_id.get(_form(n)) for n in row.sources]
                        )
                        or (
                            absence_keep_reason(
                                standing[2],
                                row.quote,
                                [by_id.get(_form(n)) for n in row.sources],
                                passage,
                            )
                            if absent
                            else ""
                        )
                        or keep_record_reason(standing[2], row.quote, generic_words(by_id))
                    )
                    if row.sources and not found and not reason:
                        continue
                    rests = (
                        f"{', '.join(_form(s) for s in row.sources)}, quoting "
                        f"{_capped(row.quote)!r}, "
                        + (f"a source the checks refused ({_codes_of(found)})" if found else reason)
                        if row.sources
                        else f"no source, because {_capped(row.reason)!r}"
                        + (f", which the checks refused ({_codes_of(found)})" if found else "")
                    )
                    listed.append(
                        Violation(
                            code=HELD_KEPT_CODE,
                            message=(
                                "The agreement question kept a held sentence of "
                                f"{safe_finding_value(passage.label)} on "
                                f"{safe_finding_value(rests)}: "
                                f"{safe_finding_value(standing[2])!r} stands as written."
                            ),
                            path=f"sentences.{index}",
                            answered=True,
                        )
                    )
            continue
        if row.decision == "drop":
            taken = spans.setdefault(passage.id, []) if passage is not None else []
            if (
                found
                or passage is None
                or span is None
                or any(span[0] < end and start < span[1] for start, end, _ in taken)
            ):
                counts["not_applied"] += 1
                continue
            # Left out on the model's reason, recorded with what stood (T-568), and, for a
            # sentence the ledger's lines hold, what holds it (T-600).
            taken.append((*left_out_span(passage.text, span[0], span[1]), ""))
            counts["dropped"] += 1
            written.append(
                _left_out(
                    passage,
                    f"sentences.{index}",
                    span[2],
                    f"the round dropped it; {held}; its reason: {row.reason}"
                    if held
                    else row.reason,
                    (),
                )
            )
            continue
        taken = spans.setdefault(passage.id, []) if passage is not None else []
        if (
            passage is None
            or span is None
            or any(span[0] < end and start < span[1] for start, end, _ in taken)
        ):
            counts["not_applied"] += 1
            continue
        if found:
            if passage.closing and _rests_on_a_source(row, by_id):
                # A closing sentence a source says otherwise than is never kept
                # as written: left out, and recorded with what stood.
                taken.append((*left_out_span(passage.text, span[0], span[1]), ""))
                counts["dropped"] += 1
                written.append(
                    Violation(
                        code=DROPPED_CODE,
                        message=(
                            "The agreement question lists a sentence of "
                            f"{safe_finding_value(passage.label)} as saying otherwise than "
                            f"{safe_finding_value(', '.join(_form(s) for s in row.sources))}, "
                            "and no rewrite of it passed the checks: it is left out of the "
                            f"section: {safe_finding_value(span[2])!r}."
                        ),
                        path=f"sentences.{index}",
                        # The section it was left out of, which the analyst report counts.
                        subject=passage.id,
                    )
                )
            elif (fallback := _fact_fallback(passage, span[2], row, by_id)) is not None:
                # A section 5 denial a bound value's fact contradicts, whose rewrite in
                # the model's words passed no check: the fact's clause is added, as
                # before the model's words were asked for, and recorded (T-568).
                taken.append((span[0], span[1], fallback))
                counts["qualified"] += 1
                written.append(
                    Violation(
                        code=QUALIFIED_CODE,
                        message=(
                            "A sentence of "
                            f"{safe_finding_value(passage.label)} denies what "
                            f"{safe_finding_value(', '.join(_form(s) for s in row.sources))} "
                            "states, and no rewrite of it in the model's words passed the "
                            f"checks ({safe_finding_value(_codes_of(found))}): "
                            f"the platform adds the fact: {safe_finding_value(span[2])!r} now "
                            f"reads {safe_finding_value(fallback)!r}."
                        ),
                        path=f"sentences.{index}",
                    )
                )
            elif refused:
                # A refused rewrite of a sentence the ledger's lines hold, which would print
                # as written: left out below, unless the platform's qualification takes it.
                unpassed.append((passage, span, refused, found, f"sentences.{index}"))
            else:
                counts["not_applied"] += 1
            continue
        # A section 5 rewrite is the platform's, built from the passage's own
        # text: put in as it stands, never read back.
        platform = passage.kind == SECTION_5 and not _in_own_words(
            passage, span[2], [by_id.get(_form(name)) for name in row.sources]
        )
        rewrite = row.rewrite if platform else " ".join(row.rewrite.split())
        if span[3] >= 0 and not platform:
            # Read back as the sentence was: the model copied both from quoted text.
            reads = pack_reads(rewrite)
            rewrite = reads[min(span[3], len(reads) - 1)] if reads else rewrite
        taken.append((span[0], span[1], rewrite))
        counts["rewritten"] += 1
        written.append(
            Violation(
                code=REWRITTEN_CODE,
                message=(
                    "The agreement question rewrote a sentence of "
                    f"{safe_finding_value(passage.label)} on "
                    f"{safe_finding_value(', '.join(_form(s) for s in row.sources))}: "
                    f"{safe_finding_value(span[2])!r} now reads "
                    f"{safe_finding_value(rewrite)!r}."
                ),
                path=f"sentences.{index}",
                answered=True,
            )
        )
    if asked:
        written.extend(
            _qualify_unread_left(passages, by_id, spans, _sentences, counts, whole=not rows)
        )
    # Why a held sentence no row answers is left out: one reason for every such sentence
    # where the question got no answer at all.
    unanswered = (
        "no answer was given for it" if rows else "the agreement question got no answer at all"
    )
    for passage in passages:
        if not _writable(passage) or passage.write is None:
            continue
        ledger_held = [
            s for s, _ids in (*passage.ledger_named, *passage.redone_named, *passage.failure_said)
        ]
        # A field answered whole leaves out each sentence no answer reached, but not where
        # the question got no answer at all: a failed call blanks no table and no summary.
        whole = _sentences_of(passage.text) if passage.whole and rows else []
        for sentence in dict.fromkeys([*ledger_held, *whole]):
            span = _sentences(passage).span(sentence)
            held = _ends_on_answer(passage, sentence)
            if span is not None and (passage.id, span[0]) not in answered:
                unpassed.append((passage, span, f"{unanswered}; {held}", (), f"held.{passage.id}"))
            elif span is None:
                # Written more than once: no row can name it, so it is left out each time.
                copied = sentence.strip()
                for start in _sentences(passage).starts.get(copied, []):
                    unpassed.append(
                        (
                            passage,
                            (start, start + len(copied), copied, -1),
                            f"it stands more than once in the passage, so no answer could "
                            f"name it; {held}",
                            (),
                            f"held.{passage.id}",
                        )
                    )
    for passage, span, why, refusals, path in unpassed:
        # A sentence the ledger's own lines hold that no answer passing the checks answers
        # never prints as it stood: left out, in a closing passage and in the body alike.
        # Where another end took it first (the platform's qualification), that end stands.
        taken = spans.setdefault(passage.id, [])
        if any(span[0] < end and start < span[1] for start, end, _ in taken):
            if refusals:
                counts["not_applied"] += 1
            continue
        taken.append((*left_out_span(passage.text, span[0], span[1]), ""))
        counts["dropped"] += 1
        written.append(_left_out(passage, path, span[2], why, refusals, every_code=True))
    for pid, rewrites in spans.items():
        if not rewrites:
            continue
        passage = by_id[pid]
        if passage.leave_out is not None:
            # A passage printed in its writer's own words keeps its text: each sentence left
            # out is recorded where the renderers read it (T-613).
            for start, end, rewrite in sorted(rewrites):
                if not rewrite:
                    passage.leave_out(passage.text[start:end].strip())
        text = passage.text
        for start, end, rewrite in sorted(rewrites, reverse=True):
            text = text[:start] + rewrite + text[end:]
        if passage.write is not None:
            passage.write(text)
    return counts, [*listed, *written]


def _codes_of(found: Sequence[Violation]) -> str:
    """The codes of the findings, each once, in order."""
    return ", ".join(dict.fromkeys(violation.code for violation in found))


def _fact_fallback(
    passage: Passage, sentence: str, row: AgreementRow, by_id: dict[str, Passage]
) -> str | None:
    """The platform's qualification of a section 5 denial a bound value's fact grounds
    (``_qualified``), or ``None`` where the sentence is no such denial or no fact the row
    names grounds it."""
    if passage.kind != SECTION_5 or sentence not in passage.on_fact:
        return None
    reading = _Reading(sentence, passage.text)
    facts = [
        fact
        for fact in (by_id.get(_form(name)) for name in row.sources)
        if fact is not None and fact.kind == FACT and _grounds(fact, reading)
    ]
    return _qualified(sentence, facts) if facts else None


# The codes by which the ledger itself, not a model's words, says a kept sentence
# is false: a failed call a later call redid, or code an entry lists called not read
# in a closing sentence. A count of failed calls the ledger's does not hold is read
# off the words and recorded, never a reason to leave a sentence out.
_LEDGER_CODES = frozenset({FAILURE_REDONE_CODE, UNREAD_STANDING_CODE})


def _ledger_says_otherwise(found: Sequence[Violation]) -> bool:
    """Whether a row's findings include one the ledger decides (:data:`_LEDGER_CODES`)."""
    return any(violation.code in _LEDGER_CODES for violation in found)


def _unbacked(found: Sequence[Violation]) -> bool:
    """Whether a closing keep's findings say no source backs it (``KEEP_UNQUOTED_CODE``)."""
    return any(violation.code == KEEP_UNQUOTED_CODE for violation in found)


def _left_out(
    passage: Passage,
    path: str,
    sentence: str,
    why: str,
    found: Sequence[Violation],
    *,
    every_code: bool = False,
) -> Violation:
    """The record of a sentence left out: what stood, and why, with the codes of ``found``
    that leave a closing keep out, or with ``every_code``, each code refusing the answer."""
    codes = ", ".join(
        dict.fromkeys(
            v.code
            for v in found
            if every_code or v.code in _LEDGER_CODES or v.code == KEEP_UNQUOTED_CODE
        )
    )
    where = (
        f" ({safe_finding_value(passage.id)}) out of the analyst report, which the bundle "
        "prints whole "
        if passage.verbatim
        else " out of the section "
    )
    return Violation(
        code=DROPPED_CODE,
        message=(
            "The agreement question leaves a sentence of "
            f"{safe_finding_value(passage.label)}{where}"
            f"({safe_finding_value(_capped(why))}"
            + (f": {safe_finding_value(codes)}" if codes else "")
            + f"): {safe_finding_value(sentence)!r}."
        ),
        path=path,
        subject=passage.id,
    )


# A sentence that reports or refutes another's claim ("They say 0x8690 was not
# read", "The statement that ... were not read is also wrong", "claim 4 says",
# "the static analyst holds"): what it says not read is that claim's, and the
# platform adds no ledger clause to it; it stays held, the model's to answer.
_REPORTED = re.compile(
    r"\b(?:is|are|was|were)\s+(?:also\s+)?(?:wrong|incorrect|mistaken|refuted|false)\b"
    r"|\brefut\w*"
    r"|\b(?:is|are|was|were)\s+(?:said|claimed|reported)\b"
    r"|\bclaims?\s+\d+"
    r"|\b(?:they|analysts?|reports?|claims?|the\s+\w+\s+analyst)\s+(?:say|says|said|claim|"
    r"claims|claimed|state|states|stated|hold|holds|held|argue|argues|argued)\b"
    r"|\bthe\s+(?:statement|claim|reading|assertion|view)\s+that\b"
    r"|\baccording\s+to\b"
    r"|\b(?:noted|suggested|wrote|written|reported|believed|believes|thought|assumed|"
    r"argued|stated|claimed|asserted|concluded|said)\s+that\b",
    re.IGNORECASE,
)


def _reports_a_claim(sentence: str) -> bool:
    """Whether a sentence reports or refutes another's claim, by its shape (:data:`_REPORTED`)."""
    return _REPORTED.search(sentence) is not None


# A listed fact's own clause, by what the ledger lists: "the code of the routine
# at offset 0x2800 (decompiled or disassembled)".
_LISTS_WHAT = re.compile(r"\blists?\s+(the code of .*)$")


def _corrected(sentence: str, facts: Sequence[Passage]) -> str:
    """The sentence as written, with the ledger's fact appended after a semicolon.

    "... is not read; the ledger lists the code of the routine at offset 0x2800
    (decompiled or disassembled) [ev_0003]." Only the ledger's fact is added,
    never an inference about the sentence: a subject read wrong adds a true fact
    at worst. The model's words stand as written before it, after any dash or
    bracket of theirs.
    """
    base = sentence.rstrip()
    core = base.rstrip("\"')]")
    closers = base[len(core) :]
    end = "."
    if core and core[-1] in ".!?":
        end = core[-1]
        base = core[:-1].rstrip() + closers
    said: list[str] = []
    for fact in facts:
        found = _LISTS_WHAT.search(fact.qualifier)
        said.append(f"the ledger lists {found.group(1)}" if found else fact.qualifier)
    clauses = "; ".join(dict.fromkeys(said))
    cites = "".join(f"[{c}]" for c in sorted(set().union(*(fact.cites for fact in facts))))
    return f"{base}; {clauses} {cites}{end}"


def _qualify_unread_left(
    passages: Sequence[Passage],
    by_id: dict[str, Passage],
    spans: dict[str, list[tuple[int, int, str]]],
    sentences_of: Callable[[Passage], _Sentences],
    counts: dict[str, int],
    *,
    whole: bool = True,
) -> list[Violation]:
    """Qualify each held sentence the ledger contradicts that the answer left standing.

    A sentence whose own clause calls code not read that an entry lists
    (:func:`unread_listed_sentences`) says the opposite of the ledger, in the
    body as much as in the closing sections: where no row rewrote or left it
    out, the platform appends its correction to it as it stands (``_corrected``),
    so every section that names the routine says the ledger lists it (T-562).
    A sentence reporting or refuting another's claim gets none. The model's
    words are never changed, only appended to; what stood is recorded. A sentence the
    ledger's own lines hold is never qualified, and one of a field answered whole only with
    ``whole``, where no row could be read: else each such sentence no answer passing the
    checks answers is left out, as its question says (:func:`apply_rows`, T-600).
    """
    out: list[Violation] = []
    for passage in passages:
        if not passage.unread_listed or passage.write is None or (passage.whole and not whole):
            continue
        taken = spans.setdefault(passage.id, [])
        for sentence, _ids, _own in passage.unread_listed:
            if _held_by_the_ledger(passage, sentence):
                # Held by the ledger's lines: left out where no answer passes, as its question
                # says (:func:`apply_rows`, T-600).
                continue
            decisive = _decisive_unread(passage, sentence)
            facts = [by_id[i] for i in decisive if i in by_id and by_id[i].qualifier]
            span = sentences_of(passage).span(sentence) if facts else None
            if span is None or not facts:
                continue
            if any(span[0] < end and start < span[1] for start, end, _ in taken):
                continue
            facts = [f for f in facts if f.qualifier.lower() not in span[2].lower()]
            if not facts:
                continue
            rewrite = _corrected(span[2], facts)
            taken.append((span[0], span[1], rewrite))
            counts["qualified"] += 1
            out.append(
                Violation(
                    code=QUALIFIED_CODE,
                    message=(
                        "A sentence of "
                        f"{safe_finding_value(passage.label)} calls code not read that "
                        f"{safe_finding_value(', '.join(f.id for f in facts))} states an entry "
                        "lists, and no row rewrote it: the platform adds what the ledger "
                        f"shows: {safe_finding_value(span[2])!r} now reads "
                        f"{safe_finding_value(rewrite)!r}."
                    ),
                    path=f"held.{passage.id}",
                )
            )
    return out


def _merged_rows(
    first: Any,
    last: Any,
    sound: Callable[[Any], bool] = bool,
    where: Callable[[Any], tuple[str, str]] | None = None,
) -> Any:
    """The retry's rows, with each sound row of the first answer the retry leaves out.

    A retry asked about one held sentence may answer that one alone: the first
    answer's rows ``sound`` keeps (the ones that passed every check, and the one
    answering a sentence the ledger's lines hold, :func:`apply_rows`) are kept, the retry's row
    winning for the same passage and sentence: where it stands in the passage
    (``where``, the place :class:`_Sentences` locates it at, so the same sentence
    copied with its escapes read back is one), else its words. Either answer that
    is no object stands for none.
    """

    def _key(row: Any) -> tuple[str, str]:
        if where is not None:
            return where(row)
        return (_form(_field(row, "passage")), " ".join(str(_field(row, "sentence") or "").split()))

    before = first.get("sentences") if isinstance(first, dict) else None
    after = last.get("sentences") if isinstance(last, dict) else None
    if not isinstance(before, list):
        return last
    if not isinstance(after, list):
        return first
    seen = {_key(row) for row in after if isinstance(row, dict)}
    kept = [row for row in before if isinstance(row, dict) and _key(row) not in seen and sound(row)]
    return {**last, "sentences": [*after, *kept]}


async def ask_section_agreement(
    reporter: Any,
    report: MalwareReport,
    *,
    narrative_written: bool = True,
    discussion: Iterable[Any] = (),
    citable_ids: Iterable[str] = (),
    items: Any = None,
    evidence_texts: EntryTexts | None = None,
    call: str = AGREEMENT_CALL,
) -> AgreementRound:
    """Ask the reporter's model once whether a passage says otherwise than its sources.

    ``reporter`` is the narrative round's agent (``NarrativeAgent.ask``). No
    reporter, no passage written without the code or no source asks nothing.
    A round that fails, wherever it fails, leaves the report as written (or
    with the rewrites already put in), with the reason said, but for the sentences
    the ledger's own lines hold where the call itself got no answer: each is left
    out, as for an answer no row of which can be read (:func:`apply_rows`). Never raises.
    """
    tally = ValidationTally()
    mark = len(list(getattr(reporter, "degradations", None) or []))

    def _said() -> list[str]:
        return [str(r) for r in list(getattr(reporter, "degradations", None) or [])[mark:]]

    try:
        return await _ask(
            reporter,
            report,
            tally,
            _said,
            narrative_written=narrative_written,
            discussion=discussion,
            citable_ids=citable_ids,
            items=items,
            evidence_texts=evidence_texts,
            call=call,
        )
    except SpendCeilingStop as stop:
        said = f"The section agreement question was not asked: {stop}."
        logger.warning("section agreement: %s", said)
        return AgreementRound(tally=tally, degradations=[*_said(), said])
    except Exception as exc:  # noqa: BLE001 — a failed round leaves the report as written
        logger.error("section agreement: the round failed (%s).", exc)
        said = f"The section agreement question was not answered ({type(exc).__name__})."
        return AgreementRound(tally=tally, degradations=[*_said(), said])


async def _ask(
    reporter: Any,
    report: MalwareReport,
    tally: ValidationTally,
    said: Callable[[], list[str]],
    *,
    narrative_written: bool,
    discussion: Iterable[Any],
    citable_ids: Iterable[str],
    items: Any,
    evidence_texts: EntryTexts | None,
    call: str,
) -> AgreementRound:
    """:func:`ask_section_agreement`'s body, which may raise."""
    from malspark.llm.answer_text import structured_answer_text
    from malspark.reporting.narrative_agent import _message_text
    from malspark.utils.json_cleaner import safe_parse_json

    if reporter is None:
        return AgreementRound(tally=tally)
    passages = passages_of(
        report,
        narrative_written=narrative_written,
        discussion=discussion,
        entries=(evidence_texts.entries.values() if evidence_texts is not None else ()),
    )
    left = next((p for p in passages if p.id == LISTINGS_LEFT_ID), None)
    held_by = getattr(reporter, "degradations", None)
    if left is not None and isinstance(held_by, list):
        # Said where the report says what it is missing (``AgreementRound.degradations``).
        held_by.append(f"The section agreement question: {left.text}.")
    claim_led = any(_writable(p) and p.kind == CLAIM_LED for p in passages)
    coded = any(_writable(p) and p.kind == SECTION_5 for p in passages)
    # A fact that rests on entries: the count of routines no passage names
    # grounds no rewrite, and asks nothing on its own.
    facts = any(p.kind == FACT and p.cites and not p.silent for p in passages)
    # A passage written without the code is asked against any source; a
    # section 5 passage against a fact alone.
    sourced = any(
        (p.kind == FACT and p.cites and not p.silent) or p.kind in (SECTION_5, DEBATE)
        for p in passages
    )
    if not (claim_led and sourced) and not (coded and facts):
        return AgreementRound(tally=tally)
    citable = list(dict.fromkeys(str(value) for value in citable_ids))
    by_id = {passage.id: passage for passage in passages}
    answer_read = [""]

    answered: list[Any] = [None]

    def _parse(answer: Any) -> Any:
        answer_read[0] = structured_answer_text(answer, _message_text)
        parsed = safe_parse_json(answer_read[0])
        # Shape only: a bare list of rows is the object the schema names.
        if isinstance(parsed, list):
            parsed = {"sentences": parsed}
        if not isinstance(parsed, dict):
            return None
        # A retry answering only what it was asked keeps the first answer's rows
        # that passed every check; one that did not is the retry's to fix or leave,
        # but for a sentence the ledger's lines hold, whose refused row stays its last
        # answer: no answer for it passed, and it is left out as refused (T-600).
        parsed = _merged_rows(answered[0], parsed, lambda row: _sound(row) or _held(row), _where)
        answered[0] = parsed
        return _platform_rewrites(parsed, by_id)

    located_in: dict[str, _Sentences] = {}

    def _span(row: Any) -> tuple[Passage, tuple[int, int, str, int]] | None:
        passage = by_id.get(_form(_field(row, "passage")))
        if passage is None:
            return None
        if passage.id not in located_in:
            located_in[passage.id] = _Sentences(passage.text)
        span = located_in[passage.id].span(str(_field(row, "sentence") or ""))
        return (passage, span) if span is not None else None

    def _where(row: Any) -> tuple[str, str]:
        found = _span(row)
        if found is not None:
            return (found[0].id, str(found[1][0]))
        return (_form(_field(row, "passage")), " ".join(str(_field(row, "sentence") or "").split()))

    def _held(row: Any) -> bool:
        # A row fitting the schema that answers a sentence the ledger's own lines hold, or
        # one of a field answered whole.
        try:
            AgreementRow.model_validate(row)
        except Exception:  # noqa: BLE001 — a row that fits no schema answers nothing
            return False
        found = _span(row)
        return found is not None and bool(_ends_on_answer(found[0], found[1][2]))

    def _sound(row: Any) -> bool:
        try:
            read = AgreementRow.model_validate(row)
        except Exception:  # noqa: BLE001 — a row that fits no schema is no sound row
            return False
        payload = _platform_rewrites({"sentences": [row]}, by_id)
        cut: dict[str, _Sentences] = {}

        def _sentences(passage: Passage) -> _Sentences:
            if passage.id not in cut:
                cut[passage.id] = _Sentences(passage.text)
            return cut[passage.id]

        shown = AgreementRow.model_validate(payload["sentences"][0])
        if _row_violations(shown, 0, by_id, _sentences):
            return False
        return read.decision != "rewrite" or not _rewrite_violations(
            shown.rewrite, citable, items, evidence_texts
        )

    # The call failing, wherever it fails, is no answer at all: each sentence the ledger's
    # lines hold is left out for that reason, every other stands as written (T-600).
    failed = ""
    try:
        payload, violations, retries = await retry_with_feedback(
            lambda turns: reporter.ask(turns, call=call, what="section agreement question's"),
            build_messages(passages),
            [
                lambda p: schema_violations(
                    AgreementOutput, p, code=SCHEMA_CODE, answer=answer_read[0]
                ),
                lambda p: agreement_violations(p, passages, citable, items, evidence_texts),
                lambda p: rewrites_violations(p, citable, items, evidence_texts, passages),
            ],
            parse=_parse,
            on_feedback=tally.count,
        )
    except SpendCeilingStop as stop:
        failed = f"The section agreement question was not asked: {stop}."
        logger.warning("section agreement: %s", failed)
        payload, violations, retries = None, [], 0
    except Exception as exc:  # noqa: BLE001 — a failed call answers nothing
        logger.error("section agreement: the round failed (%s).", exc)
        failed = f"The section agreement question was not answered ({type(exc).__name__})."
        payload, violations, retries = None, [], 0
    tally.retries += retries
    tally.count(violations)
    if violations:
        tally.record_unresolved(AGREEMENT_PRODUCER, violations)
    counts, listed = apply_rows(
        payload,
        passages,
        citable=citable,
        items=items,
        entries=evidence_texts,
        asked=not failed,
    )
    if listed:
        tally.count(listed)
        tally.record_unresolved(AGREEMENT_PRODUCER, listed)
    logger.info(
        "section agreement: %d passage(s) asked about; %d sentence(s) listed, %d rewritten, "
        "%d kept, %d listed for reading, %d not applied, %d left out, %d qualified on the "
        "ledger.",
        counts["passages"],
        counts["sentences"],
        counts["rewritten"],
        counts["kept"],
        counts["listed"],
        counts["not_applied"],
        counts["dropped"],
        counts["qualified"],
    )
    return AgreementRound(
        summary=counts, tally=tally, degradations=[*said(), *([failed] if failed else [])]
    )
