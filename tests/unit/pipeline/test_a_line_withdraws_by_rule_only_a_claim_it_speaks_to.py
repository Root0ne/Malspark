"""A blocking line withdraws by rule only a claim it speaks to.

The test is relative, within one line. Where a claim the line names, of any
analyst, shares a ledger id or a value with the whole line, the line speaks
only to the claims that share one, or whose sentence it quotes in four
consecutive words; a named claim it does not speak to is never withdrawn by
rule by that line and gets no replacement without the address test from it,
keeps the line's mark, and the reference is stated. Where no named claim
shares one or is quoted, the line's rule reaches every claim it names.
Content words take no part otherwise.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

from typing import Any

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.revision_merge import anchored_lines, claims_named_in_force, merge_revision
from malspark.schemas.isr_models import AgentISR
from tests.linear_cost import assert_scales

PARTICIPANTS = ["static", "dynamic"]
STATIC = "[analysts: STATIC ANALYST]"
BOTH = "[analysts: STATIC ANALYST, DYNAMIC ANALYST]"
BLOCKS = "[blocking: the listing shows another call.]"


def _block(sentence: str, evidence: str) -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [{evidence}]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


LOADER = "0x40cf14 loads the saved URL list from the file at 0x4103b8."
GATE = "0x406328 returns 1 only when the tables at 0x4084e4 and 0x40abd4 resolve."
MUTEX = "The mutex name at 0x403962 is not recovered."
ADDED = "0x409000 enumerates the running processes with a snapshot."
IN_FORCE = _block(LOADER, "ev_0011") + _block(GATE, "ev_0012") + _block(MUTEX, "ev_0013")
WRITE = "Process 2240 writes into process 3704 through WriteProcessMemory."
DYNAMIC_IN_FORCE = _block(WRITE, "ev_0031")


def _isr(text: str, agent: str = "static") -> AgentISR:
    isr = AgentISR(agent_id=agent, domain=agent, claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    return isr


def _merge(line: str, answer: str) -> Any:
    in_force = {"static": _isr(IN_FORCE), "dynamic": _isr(DYNAMIC_IN_FORCE, "dynamic")}
    named = claims_named_in_force([line], PARTICIPANTS, in_force)
    return merge_revision(in_force["static"], _isr(answer), answer, 2, named.get("static"))


class TestALineAnchoredByTheClaimItIsAbout:
    def test_another_number_it_names_withdraws_nothing_of_that_claim(self) -> None:
        line = (
            f"{STATIC} STATIC claims 1 and 2 say 0x40cf14 loads the URL list; the listing "
            f"shows it reads the config. {BLOCKS}"
        )

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [1]
        assert [n for n, _s in merge.carried] == [2, 3]
        assert merge.merged is not None
        gate = next(c for c in merge.merged.claims if c.claim == GATE)
        assert gate.carried_contested_by == ["L1 (round 2)"]
        assert [(n, line_number) for n, _s, line_number, _ref in merge.not_spoken_to] == [(2, 1)]
        said = merge.sentences("static", 2)
        assert any(
            s.startswith("Blocking line L1 of the round-2 mediation names claims 1-2 of the static")
            and s.endswith(
                "so the line withdraws nothing of it by rule, and the claim is carried with the "
                "line's mark."
            )
            for s in said
        )

    def test_the_claim_left_out_keeps_the_subject_test_of_an_unnamed_claim(self) -> None:
        line = f"{STATIC} STATIC claims 1 and 2 say 0x40cf14 loads the URL list. {BLOCKS}"
        again = "0x406328 returns 1 only when the table at 0x4084e4 resolves."

        merge = _merge(line, _block(again, "ev_0012"))

        assert 2 not in merge.replaced
        assert [n for n, *_rest in merge.beside] == [2]

    def test_a_ledger_id_anywhere_on_the_line_anchors(self) -> None:
        line = (
            f"{STATIC} STATIC claims 2 and 3 overstate the gate. [blocking: ev_0013 shows a name.]"
        )

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [3]
        assert [n for n, *_rest in merge.not_spoken_to] == [2]

    def test_another_analysts_claim_anchors_the_line_for_every_analyst(self) -> None:
        line = (
            f"{BOTH} DYNAMIC claim 1 and STATIC claim 2 put process 2240 writing into 3704; "
            f"the record names no pid. {BLOCKS}"
        )

        merge = _merge(line, _block(ADDED, "ev_0020"))

        # The dynamic analyst's claim shares 2240 and 3704; the static claim shares nothing.
        assert merge.withdrawn_by_rule == ()
        assert [n for n, *_rest in merge.not_spoken_to] == [2]


class TestTheClaimAPeersValuesAnchorTheLineAwayFrom:
    # The line contests the static loader claim; the dynamic claim on the same
    # line shares the pids by accident, and the static claim shares nothing.
    LINE = (
        f"{BOTH} STATIC claim 1 says the saved list is loaded, versus DYNAMIC claim 1, which "
        f"saw process 2240 write into 3704 only. {BLOCKS}"
    )

    def test_the_contested_claim_keeps_the_lines_mark(self) -> None:
        merge = _merge(self.LINE, _block(ADDED, "ev_0020"))

        assert merge.withdrawn_by_rule == () and [n for n, *_r in merge.not_spoken_to] == [1]
        assert merge.merged is not None
        loader = next(c for c in merge.merged.claims if c.claim == LOADER)
        assert loader.carried_contested_by == ["L1 (round 2)"]

    def test_a_block_restating_it_without_its_address_leaves_it_beside(self) -> None:
        again = "The saved URL list is loaded from the file at 0x4103b8."

        merge = _merge(self.LINE, _block(again, "ev_0011"))

        assert 1 not in merge.replaced and [n for n, *_r in merge.beside] == [1]
        assert merge.merged is not None
        loader = next(c for c in merge.merged.claims if c.claim == LOADER)
        assert loader.carried_contested_by == ["L1 (round 2)"]


class TestALineThatQuotesAClaimSpeaksToIt:
    def test_a_run_of_four_words_of_its_sentence_speaks_to_it(self) -> None:
        line = (
            f"{BOTH} DYNAMIC claim 1 puts 2240 writing into 3704, and STATIC claim 2 says the "
            f"gate returns 1 only when a table resolves. {BLOCKS}"
        )

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2]
        assert merge.not_spoken_to == ()

    def test_a_run_of_three_words_does_not(self) -> None:
        line = (
            f"{BOTH} DYNAMIC claim 1 puts 2240 writing into 3704, and STATIC claim 2 says the "
            f"gate returns 1 only if a table resolves. {BLOCKS}"
        )

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert merge.withdrawn_by_rule == ()
        assert [n for n, *_rest in merge.not_spoken_to] == [2]


class TestALineNoClaimAnchors:
    def test_it_speaks_to_every_claim_it_names(self) -> None:
        line = f"{STATIC} STATIC claims 1 and 2 overstate what the listing shows. {BLOCKS}"

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [1, 2]
        assert merge.not_spoken_to == ()

    def test_one_claim_named_and_anchored_nowhere_is_spoken_to(self) -> None:
        line = f"{STATIC} STATIC claim 3 says the beacon at 0x40cf14 sleeps 60 s. {BLOCKS}"

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [3]

    def test_shared_words_alone_anchor_nothing(self) -> None:
        line = f"{STATIC} STATIC claims 1 and 3 say the mutex name is not recovered. {BLOCKS}"

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [1, 3]


class TestALineThatParaphrasesItsClaim:
    def test_with_a_shared_token_it_still_withdraws_the_claim(self) -> None:
        line = (
            f"{STATIC} STATIC claim 2 overstates the gate: ev_0012 shows the check at "
            f"0x406328 returns 0 on a single table. {BLOCKS}"
        )

        merge = _merge(line, _block(ADDED, "ev_0020"))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2]
        assert merge.not_spoken_to == ()


class TestTheAnchorsCostTheLinesLength:
    def test_a_long_line_against_a_long_claim(self) -> None:
        def build(size: int) -> Any:
            words = " ".join(f"word{i}" for i in range(size))
            in_force = {
                "static": _isr(_block(f"0x401000 {words}.", "ev_0001") + _block(GATE, "ev_0012")),
            }
            line = f"{STATIC} STATIC claims 1 and 2 hold ev_0012 and {words} again. {BLOCKS}"
            named = claims_named_in_force([line], ["static"], in_force)
            return lambda: anchored_lines([line], named, in_force)

        assert_scales(build, 4_000)

    def test_a_line_naming_many_claims(self) -> None:
        def build(size: int) -> Any:
            in_force = {
                "static": _isr(
                    "".join(
                        _block(f"0x{0x401000 + i:x} reads table {i}.", "ev_0001")
                        for i in range(size)
                    )
                )
            }
            refs = ", ".join(f"claim {i + 1}" for i in range(size))
            line = f"{STATIC} STATIC {refs} say 0x401000 reads the table. {BLOCKS}"
            named = claims_named_in_force([line], ["static"], in_force)
            return lambda: anchored_lines([line], named, in_force)

        assert_scales(build, 800)


class TestTheAnalystsFieldAnchorsNothing:
    def test_a_name_in_the_field_shared_with_a_claims_value_does_not_speak_to_it(self) -> None:
        in_force = {
            "static_r2": _isr(
                _block(LOADER, "ev_0011") + _block('The mutex "STATIC_R2" is set.', "ev_0012"),
                "static_r2",
            )
        }
        line = f"[analysts: STATIC_R2 ANALYST] Claims 1 and 2 say 0x40cf14 loads the list. {BLOCKS}"
        named = claims_named_in_force([line], ["static_r2"], in_force)
        answer = _block(ADDED, "ev_0020")

        merge = merge_revision(
            in_force["static_r2"], _isr(answer, "static_r2"), answer, 2, named.get("static_r2")
        )

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [1]
        assert [n for n, *_r in merge.not_spoken_to] == [2]
