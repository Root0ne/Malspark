"""A revision restates a claim in force only in one block, and only with the claim's subject.

A revision's claims are deltas: every claim in force it neither writes again
nor withdraws stays. A claim is written again by one block of the revision
that restates it and states every address the claim names that no other
block states; a claim's helpers recurring over several of the revision's
claims never write it again. A claim neither written again by one block nor
withdrawn (a ``WITHDRAW CLAIM`` line, or by rule on a blocking line) stays in
force whole; one a block states again without an address of it stays marked
beside that block, the addresses named.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from malspark.agents.base_agent import read_claim_blocks
from malspark.pipeline.nodes import make_revision_node
from malspark.pipeline.revision_merge import merge_revision
from malspark.schemas.isr_models import AgentISR, carried_note


def _block(sentence: str, technique: str = "NONE") -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: {technique}\n---\n"


def _isr(text: str) -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    return isr


def _carried(merge: Any) -> list[int]:
    return [n for n, _s in merge.carried]


LOADER = (
    "0x40cf14 loads the saved URL list from the file at 0x4103b8 through 0x40cea4 and 0x40c964."
)
# The loader's helpers, each in a block of its own, the loader named nowhere.
LOADER_HELPERS = (
    _block("0x40cea4 reads a file into a buffer.")
    + _block("0x40c964 decrypts a buffer with RC4 keyed from the GUID.")
    + _block("The file at 0x4103b8 is named update_data.dat.")
)
LOADER_AGAIN = "0x40cf14 reads the saved URL list from 0x4103b8 through 0x40cea4 and 0x40c964."
GATE = "0x406328 returns 1 only when the tables at 0x4084e4 and 0x40abd4 resolve."
GATE_HELPERS = _block("0x4084e4 resolves the first table.") + _block(
    "0x40abd4 resolves the second table."
)
GATE_AGAIN = "0x406328 returns 1 when both tables at 0x4084e4 and 0x40abd4 resolve."
IN_FORCE = _block(LOADER) + _block(GATE)


class TestValuesPooledOverBlocksRestateNothing:
    def test_helpers_spread_over_other_blocks_leave_the_claim_carried(self) -> None:
        answer = LOADER_HELPERS + _block(GATE_AGAIN)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert merge.replaced == (2,) and _carried(merge) == [1]
        loader = next(c for c in merge.merged.claims if c.claim == LOADER)
        assert loader.carried_since_round == 1 and loader.carried_beside == ""
        assert merge.added == 3 and merge.beside == ()

    def test_one_block_with_the_helpers_but_not_the_subject_restates_nothing(self) -> None:
        # Three of the claim's four values in one block, but not the routine
        # the claim is about, which the revision states nowhere.
        answer = _block("0x40cea4 reads the file at 0x4103b8 and 0x40c964 decrypts it.")
        answer += _block(GATE_AGAIN)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 1)

        assert merge.replaced == (2,) and _carried(merge) == [1]


class TestOneBlockNamingTheSubjectReplacesTheClaim:
    def test_a_real_restatement_replaces_it_and_the_pooled_one_is_carried(self) -> None:
        answer = _block(LOADER_AGAIN) + GATE_HELPERS

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert merge.replaced == (1,) and _carried(merge) == [2]
        sentences = [c.claim for c in merge.merged.claims]
        # Written again, the claim stands once, in the revision's words.
        assert LOADER not in sentences and sentences.count(LOADER_AGAIN) == 1

    def test_a_correction_naming_the_subject_replaces_it(self) -> None:
        crypto = "0x403000 decrypts the configuration with the key 0x5a."
        answer = _block("0x403000 decrypts the configuration with the key 0x5b.") + GATE_HELPERS

        merge = merge_revision(_isr(_block(crypto) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (1,) and _carried(merge) == [2]

    def test_a_restatement_with_nothing_pooled_beside_it_replaces_the_claim(self) -> None:
        added = "0x409000 enumerates the running processes with a snapshot."
        answer = _block(LOADER_AGAIN) + _block(added)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert merge.replaced == (1,) and _carried(merge) == [2] and merge.added == 1
        assert [c.claim for c in merge.merged.claims] == [LOADER_AGAIN, GATE, added]
        assert merge.beside == ()


class TestAClaimWithSeveralSubjectAddresses:
    TWO = "0x40cf14 and 0x40d020 both load the saved URL list through 0x40cea4."

    def test_a_block_naming_one_subject_leaves_the_claim_while_the_other_is_stated_nowhere(
        self,
    ) -> None:
        answer = _block("0x40cf14 loads the saved URL list through 0x40cea4.") + _block(GATE_AGAIN)

        merge = merge_revision(_isr(_block(self.TWO) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (2,) and _carried(merge) == [1]

    def test_the_other_subject_stated_in_another_block_lets_the_first_block_restate_it(
        self,
    ) -> None:
        answer = (
            _block("0x40cf14 loads the saved URL list through 0x40cea4.")
            + _block("0x40d020 is the second entry of the loader table.")
            + GATE_HELPERS
        )

        merge = merge_revision(_isr(_block(self.TWO) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (1,) and _carried(merge) == [2]

    def test_a_block_naming_both_subjects_replaces_it(self) -> None:
        answer = _block("0x40cf14 and 0x40d020 load the URL list through 0x40cea4.")
        answer += GATE_HELPERS

        merge = merge_revision(_isr(_block(self.TWO) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (1,) and _carried(merge) == [2]

    def test_a_decompiler_name_states_the_offset_it_holds(self) -> None:
        offset = "Routine 0xcf14 loads the saved URL list through 0xcea4 and 0xc964."
        answer = _block("FUN_1360bc0cf14 loads the URL list through 0xcea4 and 0xc964.")
        answer += GATE_HELPERS

        merge = merge_revision(_isr(_block(offset) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (1,) and _carried(merge) == [2]

    def test_a_whole_address_written_again_only_as_its_offset_is_stated(self) -> None:
        # An address and its offset under an image base are one address,
        # read either way.
        named = "FUN_1360bc0cf14 (0x1360bc0cf14) loads the saved URL list through 0xcea4."
        answer = _block("Routine 0xcf14 loads the URL list through 0xcea4.") + GATE_HELPERS

        merge = merge_revision(_isr(_block(named) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (1,) and _carried(merge) == [2] and merge.beside == ()

    def test_a_routine_named_whole_is_replaced_by_its_offset(self) -> None:
        named = "FUN_140005000 (0x140005000) starts the C2 thread with start routine 0x5750."
        again = "0x5000 starts the C2 thread with start routine 0x5750."
        answer = _block(again) + GATE_HELPERS

        merge = merge_revision(_isr(_block(named) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert merge.replaced == (1,) and _carried(merge) == [2]
        assert [c.claim for c in merge.merged.claims][0] == again

    def test_a_decimal_number_states_no_address(self) -> None:
        # "4096 bytes" is a size: an address is read as hex or in a
        # decompiler's name only.
        claim = "Routine 0x1000 allocates the staging buffer for the payload."
        answer = _block("The routine allocates 4096 bytes for the staging buffer of the payload.")
        answer += GATE_HELPERS

        merge = merge_revision(_isr(_block(claim) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == () and _carried(merge) == [1, 2]
        assert [(n, k, a) for n, _s, k, a in merge.beside] == [(1, 3, ("0x1000",))]


class TestAClaimWithNoAddress:
    CONFIG = (
        'The configuration names the group "Littlehw", the campaign "qx7camp" and the build "b77x".'
    )

    def test_its_values_pooled_over_blocks_restate_nothing(self) -> None:
        answer = (
            _block('The group is "Littlehw".')
            + _block('The campaign is "qx7camp".')
            + _block('The build is "b77x".')
            + _block(GATE_AGAIN)
        )

        merge = merge_revision(_isr(_block(self.CONFIG) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (2,) and _carried(merge) == [1]

    def test_one_block_with_half_its_values_restates_it(self) -> None:
        answer = _block('The group "Littlehw" and the campaign "qx7camp" are set.') + GATE_HELPERS

        merge = merge_revision(_isr(_block(self.CONFIG) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (1,) and _carried(merge) == [2]


class TestAWithdrawalStaysExplicit:
    def test_a_withdraw_line_removes_a_claim_its_helpers_recur_beside(self) -> None:
        answer = (
            LOADER_HELPERS
            + _block(GATE_AGAIN)
            + "WITHDRAW CLAIM 1: the URL list loader is another routine.\n"
        )

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 1)

        assert merge.withdrawn == ((1, LOADER, "the URL list loader is another routine."),)
        assert merge.merged is None

    def test_a_correction_omitting_the_subject_leaves_the_claim_and_adds_the_block(
        self,
    ) -> None:
        corrected = (
            "0x40cea4 reads the URL list from the file at 0x4103b8 and 0x40c964 decrypts it."
        )
        answer = _block(corrected) + _block(GATE_AGAIN)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 1)

        assert merge.merged is not None
        assert [c.claim for c in merge.merged.claims] == [LOADER, GATE_AGAIN, corrected]
        assert _carried(merge) == [1] and merge.added == 1
        # Not in silence: the claim stands beside the block that states it
        # again without its subject.
        assert merge.beside == ((1, LOADER, 3, ("0x40cf14",)),)

    def test_a_blocking_line_withdraws_the_claim_a_correction_omitted_the_subject_of(
        self,
    ) -> None:
        corrected = (
            "0x40cea4 reads the URL list from the file at 0x4103b8 and 0x40c964 decrypts it."
        )
        answer = _block(corrected) + _block(GATE_AGAIN)

        merge = merge_revision(_isr(IN_FORCE), _isr(answer), answer, 2, {1: [(3, True)]})

        assert merge.withdrawn_by_rule == (
            (
                1,
                LOADER,
                "named by blocking line L3 of the round-2 mediation; the revision did not "
                "restate it",
            ),
        )
        assert merge.merged is None


class TestAClaimCarriedBesideItsRestatementIsMarked:
    NET_VIEW = "0x405000 runs net view through 0x1030 into net_view."

    def test_a_correction_that_changes_a_helper_address_is_carried_and_marked(self) -> None:
        corrected = "0x405000 runs net view through 0x1034 into net_view."
        answer = _block(corrected, "T1018") + _block(GATE_AGAIN)

        merge = merge_revision(
            _isr(_block(self.NET_VIEW, "T1018") + _block(GATE)), _isr(answer), answer, 2
        )

        assert merge.merged is not None
        assert [c.claim for c in merge.merged.claims] == [self.NET_VIEW, GATE_AGAIN, corrected]
        assert merge.beside == ((1, self.NET_VIEW, 3, ("0x1030",)),)
        carried = merge.merged.claims[0]
        assert carried.carried_since_round == 2
        assert carried_note(carried) == (
            "carried forward beside claim 3 of the answer the round-2 revision left in force, "
            "which states it again without 0x1030"
        )
        assert (
            "Claim 1 of the static analyst's answer in force (\"0x405000 runs net view through "
            '0x1030 into net_view.") is carried beside claim 3 of the answer the round-2 '
            "revision left in force, which states it again without 0x1030."
        ) in merge.sentences("static", 2)

    def test_a_changed_constant_is_read_as_an_address_and_the_claim_is_marked(self) -> None:
        # The rule reads no meaning into a number: a hex value of 0x100 or
        # more is an address of the claim's subject, whether it is a call
        # target, a hash or a seed. A block that writes the claim again with
        # another polynomial leaves the earlier value stated nowhere, so the
        # earlier claim stays beside it, marked, and the reader sees both
        # values rather than the merge choosing one.
        crc = "0x407000 hashes each API name with the CRC32 polynomial 0xEDB88320."
        changed = "0x407000 hashes each API name with the CRC32 polynomial 0x82F63B78."
        answer = _block(changed) + _block(GATE_AGAIN)

        merge = merge_revision(_isr(_block(crc) + _block(GATE)), _isr(answer), answer, 1)

        assert [c.claim for c in merge.merged.claims] == [crc, GATE_AGAIN, changed]
        assert merge.beside == ((1, crc, 3, ("0xedb88320",)),)

    def test_the_same_constant_written_again_replaces_the_claim(self) -> None:
        crc = "0x407000 hashes each API name with the CRC32 polynomial 0xEDB88320."
        again = "0x407000 hashes every API name with CRC32, polynomial 0xedb88320."
        answer = _block(again) + GATE_HELPERS

        merge = merge_revision(_isr(_block(crc) + _block(GATE)), _isr(answer), answer, 1)

        assert merge.replaced == (1,) and merge.beside == ()

    def test_a_later_merge_that_carries_it_unwritten_drops_the_mark(self) -> None:
        # The mark names a claim by its number in one merged answer; the next
        # merge numbers anew, so it says only what that merge read.
        corrected = "0x405000 runs net view through 0x1034 into net_view."
        answer = _block(corrected, "T1018") + _block(GATE_AGAIN)
        first = merge_revision(
            _isr(_block(self.NET_VIEW, "T1018") + _block(GATE)), _isr(answer), answer, 1
        ).merged
        added = "0x409000 enumerates the running processes with a snapshot."
        later = _block(added)

        merge = merge_revision(first, _isr(later), later, 2)

        assert merge.merged is not None and merge.beside == ()
        carried = merge.merged.claims[0]
        assert carried.claim == self.NET_VIEW and carried.carried_beside == ""
        assert carried.carried_since_round == 1


class TestTheRecordOfDroppedClaims:
    def test_a_carried_claim_is_not_recorded_as_dropped(self) -> None:
        from malspark.core.config import MEDIATOR_AGENT_NAME
        from malspark.pipeline.state import AgentArgument

        answer = LOADER_HELPERS + _block(GATE_AGAIN)
        container = MagicMock()
        container.is_mock = False
        container.agent_registry.list_agents.return_value = ["static"]
        container.analyst_keys.return_value = ["static"]
        container.agent_role.side_effect = lambda n: n
        container.config.llm.parallel_analysts = False
        agent = MagicMock()
        agent.safe_revise_isr.return_value = (answer, _isr(answer))
        container.get_agent.return_value = agent
        container.load_chunked.return_value = [MagicMock(content="data")]
        container.load_data.return_value = "data"
        mediation = AgentArgument(
            agent_name=MEDIATOR_AGENT_NAME,
            finding="revise",
            contradictions=[
                "[analysts: STATIC ANALYST] Claim 2 says the gate needs both tables, versus "
                "the listing. [blocking: the listing shows one table.]",
            ],
            revise=["static"],
        )
        state = {
            "file_hash": "abc",
            "iteration_count": 1,
            "discussion_history": [mediation],
            "reports": {"static": IN_FORCE},
            "isr_reports": {"static": _isr(IN_FORCE)},
        }

        out = asyncio.run(make_revision_node(container)(state))

        stands = out["isr_reports"]["static"].claims
        assert LOADER in [c.claim for c in stands]
        assert not [r for r in out.get("dropped_claims") or [] if r["claim"] == LOADER]
