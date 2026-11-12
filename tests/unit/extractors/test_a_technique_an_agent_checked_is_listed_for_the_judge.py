"""A technique id an agent checked, or a tool's answer named, that nothing carries is listed.

The ids any entry's call arguments write, whatever the tool, and the ids an
answer names where its tool declares a technique field, that no final claim,
finding or bundle object carries, are the judge's ``checked`` questions
(``capability_matrix.checked_technique_questions``). Each says where it was
seen and what the final claims of the agent that passed it cite. The ledgers
here are built by hand; none is a stored run.
"""

from __future__ import annotations

from typing import Any

from malspark.analysis.checked_techniques import (
    IN_ANSWER,
    IN_ARGUMENTS,
    CheckedMention,
    answer_technique_ids,
    checked_techniques,
)
from malspark.extractors.capability_matrix import (
    carried_technique_ids,
    checked_technique_questions,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, ClaimEvidence, Finding
from tests.linear_cost import assert_scales


def _entry(
    n: int,
    *,
    agent: str = "analyst_a",
    tool: str = "any_tool",
    args: dict[str, Any] | None = None,
    structured: Any = None,
    facts: dict[str, Any] | None = None,
) -> LedgerEntry:
    return LedgerEntry(
        id=f"ev_{n:04d}",
        agent=agent,
        tool=tool,
        args=args or {},
        structured=structured,
        source="mcp:somewhere" if facts is not None else None,
        facts=facts,
    )


def _claim(tid: str | None, evidence: str = "read at [ev_0001]") -> ClaimEvidence:
    return ClaimEvidence(
        claim="the routine does the thing", evidence_ref=evidence, confidence=0.6, technique_id=tid
    )


def _isr(agent: str, *claims: ClaimEvidence, findings: list[Finding] | None = None) -> AgentISR:
    return AgentISR(agent_id=agent, domain=agent, claims=list(claims), findings=findings or [])


# A tool that declares where its answer names techniques, under a field name no
# built-in tool uses.
_DECLARES = {"v": 1, "kind": "rule_hits", "techniques": [{"path": "/hits/*/ttp"}]}


def test_an_id_a_final_claim_carries_is_not_listed() -> None:
    ledger = [_entry(1, args={"ids": ["T1041", "T1082"]})]
    isrs = {"analyst_a": _isr("analyst_a", _claim("T1082"))}

    questions = checked_technique_questions(None, isrs, ledger)

    assert [q.technique_id for q in questions] == ["T1041"]
    assert questions[0].kind == "checked"


def test_an_id_in_any_tool_s_arguments_is_listed_with_who_passed_it_and_where() -> None:
    ledger = [
        _entry(1, agent="analyst_a", tool="first_tool", args={"q": {"deep": ["t1041 here"]}}),
        _entry(2, agent="analyst_b", tool="second_tool", args={"text": "see T1041 and T1083"}),
    ]

    found = checked_techniques(ledger, carried=set())

    assert found == {
        "T1041": [
            CheckedMention("analyst_a", "ev_0001", IN_ARGUMENTS),
            CheckedMention("analyst_b", "ev_0002", IN_ARGUMENTS),
        ],
        "T1083": [CheckedMention("analyst_b", "ev_0002", IN_ARGUMENTS)],
    }


def test_an_argument_s_key_is_not_read_as_an_id() -> None:
    ledger = [_entry(1, args={"T1041": "no id in the value"})]

    assert checked_techniques(ledger, carried=set()) == {}


def test_an_answer_names_ids_only_where_its_tool_declares_a_technique_field() -> None:
    answer = {"hits": [{"ttp": "Exfiltration [T1041]"}], "note": "T1083 in prose"}
    declared = _entry(1, structured=answer, facts=_DECLARES)
    undeclared = _entry(2, structured=answer, facts={"v": 1, "kind": "rule_hits"})

    assert answer_technique_ids(declared) == ["T1041"]
    assert answer_technique_ids(undeclared) == []
    assert checked_techniques([declared, undeclared], carried=set()) == {
        "T1041": [CheckedMention("analyst_a", "ev_0001", IN_ANSWER)]
    }


def test_an_id_in_the_arguments_and_the_answer_of_one_entry_is_seen_in_both_places() -> None:
    entry = _entry(
        1, args={"ids": ["T1041"]}, structured={"hits": [{"ttp": "T1041"}]}, facts=_DECLARES
    )

    assert checked_techniques([entry], carried=set())["T1041"] == [
        CheckedMention("analyst_a", "ev_0001", IN_ARGUMENTS, whole=True),
        CheckedMention("analyst_a", "ev_0001", IN_ANSWER),
    ]


def test_an_id_a_finding_or_the_bundle_carries_is_not_listed() -> None:
    ledger = [_entry(1, args={"ids": ["T1041", "T1083", "T1057"]})]
    isrs = {
        "analyst_a": _isr(
            "analyst_a", findings=[Finding(title="listing", detail="", technique_ids=["T1083"])]
        )
    }
    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Process Discovery",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1057"}],
            }
        ]
    }

    assert carried_technique_ids(bundle, isrs) == {"T1083", "T1057"}
    assert [q.technique_id for q in checked_technique_questions(bundle, isrs, ledger)] == ["T1041"]


def test_a_parent_and_its_sub_technique_are_two_ids() -> None:
    # The family rule is applied where a mapped id would be published: a parent
    # is listed beside a carried sub-technique, and a sub-technique beside a
    # carried parent, each to be decided on its own.
    ledger = [_entry(1, args={"ids": ["T1547", "T1027.005"]})]
    isrs = {"analyst_a": _isr("analyst_a", _claim("T1547.001"), _claim("T1027"))}

    assert [q.technique_id for q in checked_technique_questions(None, isrs, ledger)] == [
        "T1547",
        "T1027.005",
    ]


def test_each_question_names_the_entries_the_passing_agent_s_final_claims_cite() -> None:
    ledger = [
        _entry(5, agent="analyst_a", args={"ids": ["T1041"]}),
        _entry(6, agent="pack", args={"ids": ["T1041"]}),
    ]
    isrs = {
        "analyst_a": _isr(
            "analyst_a",
            _claim(None, "beacon body [ev_0002], [ev_0003]"),
            _claim("T1071.001", "posts [EV_0003]"),
        ),
        "analyst_b": _isr("analyst_b", _claim(None, "other [ev_0009]")),
    }

    (question,) = checked_technique_questions(None, isrs, ledger)

    assert question.checked == [
        ("analyst_a", "ev_0005", IN_ARGUMENTS),
        ("pack", "ev_0006", IN_ARGUMENTS),
    ]
    assert question.claim_entries == {"analyst_a": ["ev_0002", "ev_0003"], "pack": []}


def test_nothing_is_listed_without_a_ledger_or_when_everything_is_carried() -> None:
    isrs = {"analyst_a": _isr("analyst_a", _claim("T1041"))}

    assert checked_technique_questions(None, isrs, None) == []
    assert checked_technique_questions(None, isrs, []) == []
    assert checked_technique_questions(None, isrs, [_entry(1, args={"ids": ["T1041"]})]) == []


def test_the_collector_is_linear_in_the_ledger() -> None:
    def built(n: int) -> tuple[list[LedgerEntry], dict[str, Any]]:
        ledger = [
            _entry(
                i + 1,
                agent=f"analyst_{i % 7}",
                args={"ids": [f"T{1000 + i % 900}", "T1041"], "note": "x" * 40},
                structured={"hits": [{"ttp": f"T{1000 + (i * 7) % 900}"}]},
                facts=_DECLARES,
            )
            for i in range(n)
        ]
        isrs = {
            f"analyst_{a}": _isr(f"analyst_{a}", _claim("T1041", f"[ev_{a + 1:04d}]"))
            for a in range(7)
        }
        return ledger, isrs

    def read(made: tuple[list[LedgerEntry], dict[str, Any]]) -> None:
        ledger, isrs = made
        assert checked_technique_questions(None, isrs, ledger)

    assert_scales(built, 300, read, factor=10, repeats=5)
