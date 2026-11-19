"""The agreement harness re-runs a stored round on its stored answers, at zero cost.

A stored run keeps the report after the agreement round, the round's requests in the worker
log (the retry request repeating the model's first answer) and, since T-736, the round's
answers in its record. The harness recovers the first answer from the retry request, puts
each passage back to what the first request showed so that the round's own code builds the
logged prompt again, replays the answers through the round with a stub in place of the
model, names every end that differs between two versions of the code, and says of each
labelled sentence whether it is printed. Every stored run here is built in the test from a
live round over neutral synthetic values.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from scripts.replay import agreement_round as harness

from malspark.pipeline.validation import EntryTexts
from malspark.reporting import section_agreement
from malspark.reporting.section_agreement import ask_section_agreement, passages_of, prompt_text
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _UNKNOWN,
    CALLED,
    _ledger,
    _report,
    _row,
)

FIRST = "The gate reads a host mode [ev_0107]."
_PLAIN = f"Routine 0x5a10 calls `{CALLED}` through a slot [ev_0109]."
# The first answer opens the retry with no row for the held sentence; the retry rewrites it.
_ANSWERS: tuple[dict[str, Any], ...] = (
    {"sentences": []},
    {
        "sentences": [
            {**_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=_PLAIN), "passage": "introduction"}
        ]
    },
)


def _written() -> Any:
    return _report(FIRST, background=f"{FIRST} {_UNKNOWN}")


class _Logging:
    """The model's place in a live round: answers in turn, every request kept."""

    def __init__(self, *answers: Any) -> None:
        self.answers = [json.dumps(a) for a in answers]
        self.asked: list[list[BaseMessage]] = []
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        self.asked.append(list(turns))
        said = self.answers.pop(0) if self.answers else '{"sentences": []}'
        # A thinking block before the text, as a reasoning model answers.
        return AIMessage(
            content=[{"type": "thinking", "thinking": ""}, {"type": "text", "text": said}]
        )


def _request_line(turns: list[BaseMessage]) -> str:
    """One logged request, as the provider's client logs it."""
    system = next(str(t.content) for t in turns if isinstance(t, SystemMessage))
    messages: list[dict[str, Any]] = []
    for turn in turns:
        if isinstance(turn, HumanMessage):
            messages.append({"role": "user", "content": turn.content})
        elif isinstance(turn, AIMessage):
            messages.append({"role": "assistant", "content": turn.content})
    options = {"method": "post", "json_data": {"system": system, "messages": messages}}
    return f"2026-01-01 00:00:00 DEBUG [client] Request options: {options!r}\n"


def _stored_run(tmp_path: Path, *, keep_answers: bool) -> tuple[Path, Any, Any, list[str]]:
    """A stored run made by a live round: its log, its post-round report and its ledger."""
    ledger = _ledger()
    report = _written()
    given = [prompt_text(passages_of(_written(), entries=ledger))]
    reporter = _Logging(*_ANSWERS)
    done = asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=[str(e.id) for e in ledger],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    summary = dict(done.summary)
    if not keep_answers:
        summary.pop("answers")
        summary.pop("answers_masked")
    report.run_summary = {"section_agreement": summary, "validation": done.tally.to_dict()}
    run = tmp_path / "family-r1" / "1"
    run.mkdir(parents=True)
    other = {"json_data": {"system": "You are the narrative writer.", "messages": []}}
    (run / "worker.log").write_text(
        "2026-01-01 00:00:00 INFO worker started\n"
        f"2026-01-01 00:00:00 DEBUG [client] Request options: {other!r}\n"
        + "".join(_request_line(turns) for turns in reporter.asked),
        encoding="utf-8",
    )
    (run / "report.json").write_text(json.dumps(report.model_dump(mode="json")), encoding="utf-8")
    (run / "evidence.json").write_text(
        json.dumps({"items": [e.model_dump(mode="json") for e in ledger]}), encoding="utf-8"
    )
    return run, report, done, given


def test_the_first_answer_is_recovered_from_the_retry_request(tmp_path: Path) -> None:
    run, _report_after, _done, given = _stored_run(tmp_path, keep_answers=False)

    requests = harness.agreement_requests(run / "worker.log")

    assert requests.count == 2
    assert requests.first is not None and requests.retry is not None
    assert harness.prompt_of(requests.first) == given[0]
    # The assistant turn the retry repeats, its text block alone.
    assert harness.first_answer(requests.retry) == json.dumps(_ANSWERS[0])
    # The first request repeats no answer.
    assert harness.first_answer(requests.first) is None


def test_the_rebuilt_report_gives_the_logged_prompt(tmp_path: Path) -> None:
    run, after, _done, given = _stored_run(tmp_path, keep_answers=False)
    # The round rewrote the held sentence: the stored report is not the one it was given.
    assert _UNKNOWN not in after.intro_background

    found = harness.recover(run)

    assert found.run == "family-r1/1"
    assert found.request_found and found.first_answer_found
    assert not found.final_answers_stored
    assert found.prompt_reproduced, found.difference_context
    assert found.first_difference is None
    assert not found.not_found and not found.not_writable
    assert found.passages_differing == []
    assert found.case is not None and found.case["first_turn_only"]
    assert found.case["report"]["intro_background"] == f"{FIRST} {_UNKNOWN}"
    # A prompt the rebuilt report does not give is said, with where it first differs.
    changed = found.case["report"]["intro_background"]
    pre = harness.pre_round_report(json.loads((run / "report.json").read_bytes()), given[0])
    pre.report.intro_background = changed + " One more sentence."
    rebuilt = harness.rebuilt_prompt(pre, run)
    assert rebuilt != given[0]
    assert harness._first_difference(rebuilt, given[0]) == given[0].index(changed) + len(changed)


def test_the_replay_of_the_stored_answers_gives_the_stored_round(tmp_path: Path) -> None:
    run, after, done, _given = _stored_run(tmp_path, keep_answers=True)

    found = harness.recover(run)
    assert found.final_answers_stored and found.first_answer_matches_record
    assert found.case is not None and not found.case["first_turn_only"]
    record = harness.replay_case(found.case)

    assert record["turns_asked"] == 2 and record["turns_unanswered"] == 0
    assert record["before"]["introduction"]["text"] == f"{FIRST} {_UNKNOWN}"
    assert record["after"]["introduction"]["text"] == after.intro_background
    assert [r["code"] for r in record["records"]] == [
        r["code"] for r in done.tally.to_dict()["unresolved"]
    ]
    assert harness.against_stored(run, found.case, record) == []
    (row,) = [r for r in record["rows"] if r["turn"] == 2]
    assert row["end"] == "rewritten as answered"
    assert "agreement.rewritten" in row["codes"]


def test_a_first_turn_only_run_is_answered_no_rows_on_the_retry(tmp_path: Path) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=False)
    found = harness.recover(run)
    assert found.case is not None

    record = harness.replay_case(found.case)

    assert record["first_turn_only"]
    assert record["turns_asked"] == 2 and record["turns_unanswered"] == 1


def _stubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Another version of the round: it applies no row and records nothing."""

    def _applies_nothing(*_args: Any, **_kwargs: Any) -> tuple[dict[str, int], list[Any]]:
        return dict.fromkeys(
            (
                "passages",
                "sentences",
                "rewritten",
                "kept",
                "listed",
                "not_applied",
                "dropped",
                "qualified",
                "kept_on_quote",
            ),
            0,
        ), []

    monkeypatch.setattr(section_agreement, "apply_rows", _applies_nothing)


def test_an_end_that_differs_between_two_versions_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    found = harness.recover(run)
    assert found.case is not None
    first = harness.replay_case(found.case)
    with monkeypatch.context() as patched:
        _stubbed(patched)
        second = harness.replay_case(found.case)

    differences = harness.diff_records(first, second)

    assert {
        "run": "family-r1/1",
        "kind": "text",
        "passage": "introduction",
        "only": "B",
        "sentence": _UNKNOWN,
    } in differences
    assert {
        "run": "family-r1/1",
        "kind": "left_out",
        "passage": "introduction",
        "only": "A",
        "sentence": _UNKNOWN,
    } in differences
    assert any(
        d["kind"] == "code" and d["code"] == "agreement.rewritten" and d["change"] == "lost"
        for d in differences
    )
    assert harness.diff_records(first, first) == []
    # Expected differences excuse what they match, and nothing else.
    assert harness.unexpected(differences, [{"run": "family-r1/1"}]) == []
    left = harness.unexpected(differences, [{"kind": "code"}])
    assert left and all(d["kind"] != "code" for d in left)


def test_each_label_says_whether_its_sentence_is_printed_under_each_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    found = harness.recover(run)
    assert found.case is not None
    first = harness.replay_case(found.case)
    with monkeypatch.context() as patched:
        _stubbed(patched)
        second = harness.replay_case(found.case)
    labels = [
        {"run": "family-r1/1", "passage": "introduction", "text": _UNKNOWN, "label": "false"},
        {"run": "family-r1/1", "text": FIRST, "label": "true"},
        {"run": "another/1", "text": FIRST, "label": "true"},
    ]

    lines = harness.label_lines(labels, {"A": {"family-r1/1": first}, "B": {"family-r1/1": second}})

    assert lines[0]["printed"] == {"before": True, "A": False, "B": True}
    assert lines[0]["label"] == "false"
    assert lines[1]["printed"] == {"before": True, "A": True, "B": True}
    assert lines[2]["printed"] == {"A": None, "B": None}


def test_the_limits_are_stated_in_the_help() -> None:
    said = harness._parser().format_help()

    assert "two runs only" in " ".join(said.split())
    assert "not what a model" in " ".join(said.split())
    assert "two runs only" in (harness.__doc__ or "")


def test_the_rows_are_masked_as_the_worker_masks_them_and_the_registry_put_back() -> None:
    from malspark.pipeline import events

    before = dict(events._SECRET_SCOPES)
    url = "http://198.51.100.7/r/one.crl"
    with harness._rows_as_the_worker_keeps_them():
        # With the job's values registered a row keeps its words, a URL's path among them.
        assert events._rows_kept_as_written()
        assert url in events.safe_finding_value(f"fetched {url}")
    assert events._SECRET_SCOPES == before
