"""The agreement harness re-runs a stored round on its stored answers, at zero cost.

A stored run keeps the report after the agreement round, the round's requests in the worker
log (the retry request repeating the model's first answer) and, where its record keeps them,
the round's answers. The harness recovers the first answer from the retry request, puts
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
from tests.unit.reporting._report_inventory import stored_runs
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


def _stored_run(
    tmp_path: Path, *, keep_answers: bool, answers: tuple[dict[str, Any], ...] = _ANSWERS
) -> tuple[Path, Any, Any, list[str]]:
    """A stored run made by a live round: its log, its post-round report and its ledger."""
    ledger = _ledger()
    report = _written()
    given = [prompt_text(passages_of(_written(), entries=ledger))]
    reporter = _Logging(*answers)
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


def _holding(rows: list[dict[str, Any]], wanted: dict[str, Any]) -> bool:
    """Whether a row holds every field of ``wanted`` with the value it gives."""
    return any(all(row.get(k) == v for k, v in wanted.items()) for row in rows)


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

    assert _holding(
        differences,
        {
            "run": "family-r1/1",
            "kind": "text",
            "passage": "introduction",
            "only": "B",
            "sentence": _UNKNOWN,
        },
    )
    assert _holding(
        differences,
        {
            "run": "family-r1/1",
            "kind": "left_out",
            "passage": "introduction",
            "only": "A",
            "sentence": _UNKNOWN,
        },
    )
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


@pytest.mark.parametrize(("given", "said"), [(False, "false"), (True, "true")])
def test_a_boolean_label_is_printed_and_kept_as_true_or_false(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], given: bool, said: str
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps([{"run": "family-r1/1", "text": FIRST, "label": given}]), encoding="utf-8"
    )
    out = tmp_path / "out"

    harness.main([str(run), "--out", str(out), "--labels", str(labels)])

    (line,) = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith(" - label")]
    assert line.startswith(f" - label {said} [family-r1/1]")
    (kept,) = json.loads((out / "labels.json").read_text(encoding="utf-8"))
    assert kept["label"] == said


def test_a_label_of_a_run_not_replayed_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps([{"run": "another/1", "text": FIRST, "label": "true"}]), encoding="utf-8"
    )

    harness.main([str(run), "--labels", str(labels)])

    (line,) = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith(" - label")]
    assert "printed: HEAD: -" in line and line.endswith(f"({harness.NOT_REPLAYED})")
    assert "refused" not in line
    # A run that is replayed carries no such reason.
    (replayed,) = harness.label_lines(
        [{"run": "family-r1/1", "text": FIRST, "label": "true"}],
        {"A": {"family-r1/1": harness.recover(run).record or {}}},
    )
    assert "not_replayed" not in replayed


def test_the_limits_are_stated_in_the_help() -> None:
    said = " ".join(harness._parser().format_help().split())
    doc = " ".join((harness.__doc__ or "").split())

    # The rule, not a count of the runs that hold it today.
    rule = "final answers are replayed only where the run's record stores them"
    assert rule in said and rule in doc
    assert "two runs only" not in said and "two runs only" not in doc
    assert "not what a model" in said
    # The source of the facts, and the answer fed re-serialised.
    assert "shortened stored ledger" in said and "shortened stored ledger" in doc
    assert "re-serialised" in said and "answer_reserialised" in said
    # What a replay of a rebuilt input and a retry the run never had are.
    assert harness.REPLAY_NOTE in said and harness.REBUILT_NOTE in said
    assert "said to be " + harness.REPLAY_NOTE + " (under --compare, " in said
    assert harness.EMPTY_RETRY_NOTE in said
    # The help's first paragraph says what the tool is on the stored runs as they stand.
    first = " ".join(str(harness._parser().description or "").split())
    assert "comparison instrument on rebuilt inputs only" in first
    assert "not a reproduction of what a run did" in first
    # Results are judged by the labels, never by the code's own reading.
    assert "judged by the labels, not by the code's own reading" in said
    # The empty retry of a run whose retry answer is not stored.
    assert "answered with no rows" in said
    # A run whose written passages differ is replayed only on request, and marked.
    assert "--allow-differing" in said
    # Under --compare the pre-round report is the parent's code; each ref checks its own turns.
    assert "rebuilt and a run refused by the code this command runs from" in said
    assert "each ref checks the turns its own round sends" in said


def test_the_rows_are_masked_as_the_worker_masks_them_and_the_registry_put_back() -> None:
    from malspark.pipeline import events

    before = dict(events._SECRET_SCOPES)
    url = "http://198.51.100.7/r/one.crl"
    with harness._rows_as_the_worker_keeps_them():
        # With the job's values registered a row keeps its words, a URL's path among them.
        assert events._rows_kept_as_written()
        assert url in events.safe_finding_value(f"fetched {url}")
    assert events._SECRET_SCOPES == before


def _differing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The round's code under this tree builds one written passage unlike the logged one."""
    built = harness.rebuilt_prompt

    def _rebuilt(pre: Any, run: Path) -> str:
        return built(pre, run).replace("reads a host mode", "reads a guest mode", 1)

    monkeypatch.setattr(harness, "rebuilt_prompt", _rebuilt)


def test_a_run_whose_written_passages_differ_is_refused_without_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    _differing(monkeypatch)

    found = harness.recover(run)

    assert len(found.passages_differing) == 1
    assert found.prompt_reproduced is False
    assert found.case is None
    assert "--allow-differing" in found.refused
    out = tmp_path / "out"
    assert harness.main([str(run), "--out", str(out)]) == harness.REFUSED
    said = capsys.readouterr().out
    assert "refused" in said and "--allow-differing" in said
    # Nothing is replayed for the refused run.
    assert not (out / "family-r1-1.json").exists()


def test_a_run_whose_written_passages_differ_is_marked_on_every_line_when_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    _differing(monkeypatch)
    found = harness.recover(run, allow_differing=True)
    assert found.case is not None and not found.refused

    record = harness.replay_case(found.case)

    marks = {
        "prompt_reproduced": False,
        "first_difference": found.first_difference,
        "passages_differing": found.passages_differing,
    }
    assert len(found.passages_differing) == 1
    assert isinstance(found.first_difference, int)
    assert _holding([record], marks)
    with monkeypatch.context() as patched:
        _stubbed(patched)
        second = harness.replay_case(found.case)
    differences = harness.diff_records(record, second)
    assert differences and all(_holding([d], marks) for d in differences)
    labels = [{"run": "family-r1/1", "text": FIRST, "label": "true"}]
    (line,) = harness.label_lines(labels, {"A": {"family-r1/1": record}})
    assert _holding([line], marks)
    # Every printed line of the run says its prompt is not the logged one.
    out = tmp_path / "out"
    capsys.readouterr()
    harness.main(
        [str(run), "--allow-differing", "--out", str(out), "--labels", str(_labels(tmp_path))]
    )
    printed = [
        ln
        for ln in capsys.readouterr().out.splitlines()
        if ln.startswith(("==", "   turn", " - label"))
    ]
    assert printed and all("written passage(s) differ" in ln for ln in printed)
    kept = json.loads((out / "family-r1-1.json").read_text(encoding="utf-8"))
    assert _holding([kept], marks)


def _labels(tmp_path: Path) -> Path:
    path = tmp_path / "labels.json"
    path.write_text(
        json.dumps([{"run": "family-r1/1", "text": FIRST, "label": "true"}]), encoding="utf-8"
    )
    return path


def test_a_run_whose_retry_answer_is_not_stored_is_marked_first_turn_only_everywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=False)
    found = harness.recover(run)
    assert found.case is not None and found.first_turn_only

    record = harness.replay_case(found.case)
    with monkeypatch.context() as patched:
        _stubbed(patched)
        second = harness.replay_case(found.case)
    differences = harness.diff_records(second, record)
    labels = [{"run": "family-r1/1", "text": FIRST, "label": "true"}]
    (line,) = harness.label_lines(labels, {"A": {"family-r1/1": record}})

    assert record["first_turn_only"]
    assert differences and all(d["first_turn_only"] for d in differences)
    assert line["first_turn_only"]
    capsys.readouterr()
    harness.main([str(run), "--labels", str(_labels(tmp_path))])
    printed = [
        ln
        for ln in capsys.readouterr().out.splitlines()
        if ln.startswith(("==", "   turn", " - label"))
    ]
    assert printed and all("first turn only" in ln for ln in printed)


def test_the_harness_refuses_to_start_on_the_round_s_code_of_another_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import malspark

    elsewhere = tmp_path / "another-checkout" / "src" / "malspark" / "__init__.py"
    monkeypatch.setattr(malspark, "__file__", str(elsewhere))

    status = harness.main([str(tmp_path)])

    assert status == harness.WRONG_TREE
    said = capsys.readouterr().err
    assert str(elsewhere.parent) in said
    assert str(harness._TREE) in said


def test_the_tree_the_round_ran_under_is_in_every_record(tmp_path: Path) -> None:
    import malspark

    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    found = harness.recover(run)
    assert found.case is not None

    record = harness.replay_case(found.case)

    tree = str(Path(malspark.__file__).resolve().parents[1])
    assert record["tree"] == tree
    assert found.row()["tree"] == tree


def test_a_log_with_more_than_the_round_s_two_requests_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    log = run / "worker.log"
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    # A second job's round in the same log.
    log.write_text("".join(lines) + "".join(lines[2:]), encoding="utf-8")

    found = harness.recover(run)

    assert found.requests == 4
    assert found.case is None
    assert "4 agreement requests" in found.refused
    assert harness.main([str(run)]) == harness.REFUSED
    assert "4 agreement requests" in capsys.readouterr().out


def test_the_log_s_raw_first_answer_is_the_one_replayed_and_a_differing_record_is_said(
    tmp_path: Path,
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    stored = json.loads((run / "report.json").read_bytes())
    kept = stored["run_summary"]["section_agreement"]
    kept["answers"][0] = {"sentences": [], "note": "kept by the record"}
    (run / "report.json").write_text(json.dumps(stored), encoding="utf-8")

    found = harness.recover(run)

    assert found.first_answer_matches_record is False
    assert found.case is not None
    # The model's raw text as the log repeats it, never the record's parsed copy.
    assert found.case["answers"][0] == json.dumps(_ANSWERS[0])
    record = harness.replay_case(found.case)
    assert record["first_answer_matches_record"] is False


def test_the_check_against_the_stored_round_compares_the_whole_report(tmp_path: Path) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    found = harness.recover(run)
    assert found.case is not None
    record = harness.replay_case(found.case)
    assert harness.against_stored(run, found.case, record) == []

    # A field no passage, record, count or flagged statement shows.
    record["report"]["malware_category"] = "another category"
    found_now = harness.against_stored(run, found.case, record)

    assert found_now and all(line.startswith("report") for line in found_now)
    assert any("malware_category" in line for line in found_now)


def _fact_differing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The round's code under this tree builds one fact unlike the logged one and one fact the
    logged prompt does not show; every written passage is as logged."""
    built = harness.rebuilt_prompt

    def _rebuilt(pre: Any, run: Path) -> str:
        said = built(pre, run)
        line = next(ln for ln in said.split("\n") if ln.startswith("- [inv.3] "))
        return said.replace(
            line,
            line.replace("no sandbox observation", "one sandbox observation")
            + "\n- [inv.9] limitations inventory row, measured by the platform: Added.",
            1,
        )

    monkeypatch.setattr(harness, "rebuilt_prompt", _rebuilt)


_FACT_BLOCKS = {"fact": {"only_logged": [], "only_rebuilt": ["inv.9"], "text": ["inv.3"]}}


def test_a_run_whose_only_difference_is_in_its_facts_is_refused_without_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    _fact_differing(monkeypatch)

    found = harness.recover(run)

    assert found.passages_differing == []
    assert found.facts_differing == ["inv.3", "inv.9"]
    assert found.blocks_differing == _FACT_BLOCKS
    assert found.prompt_reproduced is False
    assert found.case is None
    assert "2 fact block(s) differ" in found.refused and "inv.3" in found.refused
    assert "--allow-differing" in found.refused
    assert harness.main([str(run)]) == harness.REFUSED
    said = capsys.readouterr().out
    assert "refused" in said and "fact block(s) differ" in said
    assert "fact 0/1/1" in said


def test_a_run_whose_facts_differ_is_marked_with_the_kinds_on_every_line_when_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    _without_a_stored_record(run)
    _fact_differing(monkeypatch)
    found = harness.recover(run, allow_differing=True)
    assert found.case is not None and not found.refused

    record = harness.replay_case(found.case)

    marks = {"facts_differing": ["inv.3", "inv.9"], "blocks_differing": _FACT_BLOCKS}
    assert _holding([record], marks)
    with monkeypatch.context() as patched:
        _stubbed(patched)
        second = harness.replay_case(found.case)
    differences = harness.diff_records(record, second)
    assert differences and all(_holding([d], marks) for d in differences)
    (line,) = harness.label_lines(
        [{"run": "family-r1/1", "text": FIRST, "label": "true"}], {"A": {"family-r1/1": record}}
    )
    assert _holding([line], marks)
    said = "2 fact block(s) differ (0 only logged, 1 only rebuilt, 1 in text)"
    assert said in harness.mark_text(record)
    capsys.readouterr()
    harness.main(
        [str(run), "--allow-differing", "--check-stored", "--labels", str(_labels(tmp_path))]
    )
    printed = [
        ln
        for ln in capsys.readouterr().out.splitlines()
        if ln.startswith(("==", "   turn", " - label", "   against the stored round", "     "))
    ]
    assert len(printed) > 3 and all(said in ln for ln in printed)
    # Each difference from the stored round carries the marks as well.
    assert any(ln.startswith("     records:") for ln in printed)
    assert "written passage(s)" not in " ".join(printed)


def test_the_lines_against_the_stored_round_and_the_summary_carry_the_marks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=False)
    found = harness.recover(run)
    assert found.case is not None
    record = harness.replay_case(found.case)

    line = harness.against_line(["one", "two"], record)

    assert "2 difference(s), 2 of them on marked input" in line
    assert line.endswith(harness.mark_text(record)) and "first turn only" in line
    clean = {k: v for k, v in record.items() if k not in harness.MARKS}
    assert harness.against_line(["one"], clean) == (
        "against the stored round: 1 difference(s), 0 of them on marked input"
    )
    with monkeypatch.context() as patched:
        _stubbed(patched)
        second = harness.replay_case(found.case)
    differences = harness.diff_records(record, second)
    summary = harness.summary_line(differences, differences[:1])
    assert summary.startswith(
        f"{len(differences)} difference(s), 1 not expected, {len(differences)} on marked input"
    )
    assert f"; family-r1/1{harness.mark_text(record)}" in summary


def _without_a_stored_record(run: Path) -> None:
    """The run's stored round without its rewrite's record, which the replay keeps."""
    stored = json.loads((run / "report.json").read_bytes())
    stored["run_summary"]["validation"]["unresolved"] = [
        r
        for r in stored["run_summary"]["validation"]["unresolved"]
        if r.get("code") != "agreement.rewritten"
    ]
    (run / "report.json").write_text(json.dumps(stored), encoding="utf-8")


def _two_runs(tmp_path: Path) -> tuple[Path, Path]:
    """A run whose stored round lacks one of the replay's records, and a run refused."""
    differing, _after, _done, _given = _stored_run(tmp_path / "a", keep_answers=True)
    _without_a_stored_record(differing)
    refused, _after, _done, _given = _stored_run(tmp_path / "b", keep_answers=True)
    moved = tmp_path / "b" / "other-r1" / "1"
    moved.parent.mkdir(parents=True)
    refused.rename(moved)
    log = moved / "worker.log"
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    log.write_text("".join(lines) + "".join(lines[2:]), encoding="utf-8")
    return differing, moved


def test_differences_found_with_a_run_refused_end_with_a_status_of_their_own(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    differing, refused = _two_runs(tmp_path)
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps([{"run": "other-r1/1", "text": FIRST, "label": "true"}]), encoding="utf-8"
    )

    status = harness.main([str(differing), str(refused), "--check-stored", "--labels", str(labels)])

    assert status == harness.REFUSED_AND_DIFFERING
    said = capsys.readouterr().out
    closing = said[said.rindex("1 run(s) refused:") :]
    assert "other-r1/1: the worker log holds 4 agreement requests" in closing
    assert "not expected in the runs replayed:" in closing
    assert "family-r1/1: records: 1 more agreement.rewritten replayed than stored" in closing
    # The label of the refused run says why it was not replayed.
    (label,) = [ln for ln in said.splitlines() if ln.startswith(" - label")]
    assert "HEAD: -" in label and "(refused: the worker log holds 4 agreement requests" in label
    # Each run alone ends with its own status.
    assert harness.main([str(differing), "--check-stored"]) == harness.DIFFERENCES
    assert harness.main([str(refused)]) == harness.REFUSED
    helped = " ".join(harness._parser().format_help().split())
    for status_said in ("Exit status: 0", "1 where", "3 where", "4 where", "5 where"):
        assert status_said in helped


def _raw_record_answers(run: Path) -> None:
    """The run's record keeping each answer as the text the model gave, not a parsed copy."""
    stored = json.loads((run / "report.json").read_bytes())
    kept = stored["run_summary"]["section_agreement"]
    kept["answers"] = [json.dumps(a) for a in kept["answers"]]
    (run / "report.json").write_text(json.dumps(stored), encoding="utf-8")


def _two_refs(monkeypatch: pytest.MonkeyPatch, *, b_changes_counts: bool = False) -> None:
    """Two refs replayed in this process, ref B's replay counting otherwise where asked."""
    from scripts.replay import compare

    monkeypatch.setattr(compare, "materialise", lambda _repo, _ref, path: path)

    def _replayed(tree: Path, cases: Any, _out: Path, _timeout: float) -> list[Any]:
        records = [harness.replay_case(json.loads(Path(c).read_bytes())) for c in cases]
        if b_changes_counts and tree.name == "tree-B":
            for record in records:
                record["summary"]["passages"] = -1
        return records

    monkeypatch.setattr(harness, "_replay_under", _replayed)


def test_two_refs_each_check_their_own_turns_and_ref_a_s_stored_differences_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    differing, refused = _two_runs(tmp_path)
    # Both answers as the model gave them: the run carries no mark.
    _raw_record_answers(differing)
    _two_refs(monkeypatch)

    status = harness.main(
        [str(differing), str(refused), "--check-stored", "--compare", "A", "B"]
        + ["--out", str(tmp_path / "out")]
    )

    said = capsys.readouterr().out
    assert said.count(harness.COMPARE_NOTE) == 1
    assert "no ref checks its own prompt" not in harness.COMPARE_NOTE
    # Each ref's own round checked each turn it sent against the logged one.
    assert "family-r1/1 under A: turn 1 as logged; turn 2 as logged" in said
    assert "family-r1/1 under B: turn 1 as logged; turn 2 as logged" in said
    assert "0 difference(s), 0 not expected, 0 on marked input" in said
    assert "family-r1/1 under A against the stored round: 2 difference(s), 0 of them" in said
    # Ref A's differences from the stored round on an unmarked run are the harness testing
    # itself: they count, beside the refused run.
    assert status == harness.REFUSED_AND_DIFFERING
    closing = said[said.rindex("1 run(s) refused:") :]
    assert (
        "family-r1/1 under A: records: 1 more agreement.rewritten replayed than stored" in closing
    )
    assert "under B:" not in closing


def test_ref_b_s_differences_from_the_stored_round_are_not_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    clean, _after, _done, _given = _stored_run(tmp_path / "a", keep_answers=True)
    _raw_record_answers(clean)
    _two_refs(monkeypatch, b_changes_counts=True)

    status = harness.main(
        [str(clean), "--check-stored", "--compare", "A", "B", "--out", str(tmp_path / "o1")]
    )

    said = capsys.readouterr().out
    assert "family-r1/1 under A against the stored round: 0 difference(s)" in said
    assert "family-r1/1 under B against the stored round: 1 difference(s)" in said
    assert "0 difference(s), 0 not expected" in said
    # Ref B is the change measured: printed, never counted.
    assert status == 0
    helped = " ".join(harness._parser().format_help().split())
    assert "ref A's replay from the stored round on a run whose first turn is reproduced" in helped
    assert "ref B's being printed and never counted" in helped


def test_ref_a_s_stored_differences_count_where_the_first_turn_is_reproduced_whatever_the_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The retry turn differs and the retry's answer is fed re-serialised: both are marked.
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    _without_a_stored_record(run)
    _rewrite_retry(run)
    _two_refs(monkeypatch)

    status = harness.main(
        [str(run), "--allow-differing", "--check-stored", "--compare", "A", "B"]
        + ["--out", str(tmp_path / "out")]
    )

    said = capsys.readouterr().out
    assert "under A against the stored round: 2 difference(s), 2 of them on marked input" in said
    assert status == harness.DIFFERENCES
    # The counted differences carry the run's marks.
    lines = said.splitlines()
    head = next(i for i, ln in enumerate(lines) if "under A against the stored round:" in ln)
    counted = lines[head + 1 : head + 3]
    assert len(counted) == 2 and all(
        ln.startswith("   ") and "retry turn not reproduced" in ln and "re-serialised" in ln
        for ln in counted
    )
    # Under two refs the run's replay is said to be a comparison of refs.
    assert said.count(f"family-r1/1: note: {harness.REBUILT_NOTE}") == 1
    assert harness.REPLAY_NOTE not in said


def test_ref_a_s_stored_differences_do_not_count_where_the_first_turn_is_not_reproduced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    _without_a_stored_record(run)
    _differing(monkeypatch)
    _two_refs(monkeypatch)

    status = harness.main(
        [str(run), "--allow-differing", "--check-stored", "--compare", "A", "B"]
        + ["--out", str(tmp_path / "out")]
    )

    said = capsys.readouterr().out
    line = next(ln for ln in said.splitlines() if "under A against the stored round:" in ln)
    assert "prompt not reproduced" in line and " 0 difference(s)" not in line
    assert status == 0


def _rewrite_retry(run: Path) -> None:
    """The logged retry request with a correction turn the replay's round does not send."""
    import ast

    log = run / "worker.log"
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    head, body = lines[-1].split("Request options: ", 1)
    options = ast.literal_eval(body.strip())
    messages = options["json_data"]["messages"]
    messages[-1]["content"] = str(messages[-1]["content"]) + "\nAlso name entry fn.9."
    lines[-1] = f"{head}Request options: {options!r}\n"
    log.write_text("".join(lines), encoding="utf-8")


def test_the_retry_turn_the_round_sends_is_checked_against_the_logged_one(
    tmp_path: Path,
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)

    found = harness.recover(run)

    assert found.case is not None and found.record is not None
    assert len(found.case["logged_turns"]) == 2
    assert found.first_turn_sent_reproduced is True
    assert found.retry_reproduced is True
    assert found.retry_first_difference is None and found.retry_blocks_differing == {}
    assert [(c["turn"], c["reproduced"]) for c in found.record["turns_checked"]] == [
        (1, True),
        (2, True),
    ]


def test_a_run_whose_retry_turn_differs_is_refused_without_the_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    _rewrite_retry(run)

    found = harness.recover(run)

    # The first turn is the logged one; the retry's correction is not.
    assert found.prompt_reproduced is True and found.first_turn_sent_reproduced is True
    assert found.retry_reproduced is False
    assert isinstance(found.retry_first_difference, int)
    assert "outside" in found.retry_blocks_differing
    assert found.case is None
    assert "the retry turn the round sends is not the logged one" in found.refused
    assert "fn.9" in found.refused and "--allow-differing" in found.refused
    assert harness.main([str(run)]) == harness.REFUSED
    said = capsys.readouterr().out
    assert "refused family-r1/1: the retry turn the round sends" in said


def test_a_run_whose_retry_turn_differs_is_marked_on_every_line_when_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    _rewrite_retry(run)
    found = harness.recover(run, allow_differing=True)
    assert found.case is not None and not found.refused

    record = harness.replay_case(found.case)

    marks = {"retry_reproduced": False, "retry_first_difference": found.retry_first_difference}
    assert _holding([record], marks)
    with monkeypatch.context() as patched:
        _stubbed(patched)
        second = harness.replay_case(found.case)
    differences = harness.diff_records(record, second)
    assert differences and all(_holding([d], marks) for d in differences)
    (line,) = harness.label_lines(
        [{"run": "family-r1/1", "text": FIRST, "label": "true"}], {"A": {"family-r1/1": record}}
    )
    assert _holding([line], marks)
    assert "retry turn not reproduced" in harness.mark_text(record)
    assert "retry: the text outside the passages differs" in harness.mark_text(record)
    capsys.readouterr()
    harness.main([str(run), "--allow-differing", "--labels", str(_labels(tmp_path))])
    said = capsys.readouterr().out
    printed = [ln for ln in said.splitlines() if ln.startswith(("==", "   turn", " - label"))]
    assert printed and all("retry turn not reproduced" in ln for ln in printed)
    # Said once for the run: what its replay is, with no refs compared.
    assert said.count(f"note: {harness.REPLAY_NOTE}") == 1
    assert harness.REBUILT_NOTE not in said
    summary = harness.summary_line(differences, [], [record])
    assert f"{harness.REBUILT_NOTE}: family-r1/1" in summary


# A first answer that lists every held sentence: the round needs no retry.
_WHOLE: tuple[dict[str, Any], ...] = (
    {
        "sentences": [
            _row(FIRST, "drop", [], reason="It restates the body's sentence."),
            *_ANSWERS[1]["sentences"],
        ]
    },
)


def test_a_run_with_no_logged_retry_keeps_its_first_turn_only_mark(tmp_path: Path) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True, answers=_WHOLE)
    assert harness.agreement_requests(run / "worker.log").count == 1

    found = harness.recover(run)

    assert found.case is not None and found.record is not None
    assert found.first_turn_only is True
    assert found.retry_reproduced is None and found.retry_first_difference is None
    assert [c["turn"] for c in found.record["turns_checked"]] == [1]
    assert found.record["turns_unanswered"] == 0
    assert "first turn only" in harness.mark_text(found.record)
    # No retry was asked: none was answered by the harness.
    assert harness.EMPTY_RETRY_NOTE not in harness.run_notes(found.record)


def test_a_retry_the_replay_sends_and_the_log_does_not_hold_is_refused(tmp_path: Path) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    log = run / "worker.log"
    # The log without its retry request.
    log.write_text("".join(log.read_text(encoding="utf-8").splitlines(True)[:-1]), "utf-8")

    found = harness.recover(run)

    assert found.retry_reproduced is False and found.case is None
    assert "sends a retry turn the log does not hold" in found.refused
    allowed = harness.recover(run, allow_differing=True)
    assert allowed.record is not None
    assert "retry turn not reproduced" in harness.mark_text(allowed.record)
    assert "turn 2 sent, not logged" in harness.checks_text(allowed.record)


def test_a_retry_the_run_never_had_is_said_once_per_run_and_in_the_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=False)
    found = harness.recover(run)
    assert found.case is not None and found.record is not None
    # The logged retry turn is still checked; its answer is the harness's own.
    assert found.retry_reproduced is True and found.first_turn_only

    capsys.readouterr()
    harness.main([str(run)])
    said = capsys.readouterr().out

    assert said.count(f"note: {harness.EMPTY_RETRY_NOTE}") == 1
    assert harness.REBUILT_NOTE not in said and harness.REPLAY_NOTE not in said
    with monkeypatch.context() as patched:
        _stubbed(patched)
        second = harness.replay_case(found.case)
    differences = harness.diff_records(found.record, second)
    summary = harness.summary_line(differences, [], [found.record])
    assert f"{harness.EMPTY_RETRY_NOTE}: family-r1/1" in summary
    assert harness.REBUILT_NOTE not in summary


def test_an_answer_only_the_record_keeps_is_marked_re_serialised(tmp_path: Path) -> None:
    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    found = harness.recover(run)
    assert found.case is not None and found.record is not None

    # The first answer as the log repeats it, the retry's as the record parsed it.
    assert found.case["answers"][0] == json.dumps(_ANSWERS[0])
    assert found.answer_reserialised == [2]
    assert "answer(s) 2 re-serialised from the record" in harness.mark_text(found.record)
    # Where the record keeps the text the model gave, nothing is re-serialised or marked.
    _raw_record_answers(run)
    raw = harness.recover(run)
    assert raw.case is not None and raw.record is not None
    assert raw.answer_reserialised == []
    assert harness.mark_text(raw.record) == ""
    assert harness.against_stored(run, raw.case, raw.record) == []


def test_a_reordered_block_is_named_as_an_order_difference() -> None:
    head = "FACTS THE PLATFORM STATES"
    one, two = "- [inv.1] row, measured: One.", "- [inv.2] row, measured: Two."
    logged = f"{head}\n{one}\n{two}\n"
    rebuilt = f"{head}\n{two}\n{one}\n"

    found = harness.block_differences(logged, rebuilt)

    assert found == {"order": {"only_logged": [], "only_rebuilt": [], "text": ["inv.1", "inv.2"]}}
    assert harness._differing_text(found) == ["order differs (inv.1, inv.2)"]
    assert harness.block_differences(logged, logged) == {}


def test_importing_the_harness_leaves_the_path_as_it_was(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    run, _after, _done, _given = _stored_run(tmp_path, keep_answers=True)
    # Importing either module, and a recovery that reads the prompt's passages with the
    # names reader, leave the importer's path as it was.
    probe = (
        "import sys; from pathlib import Path; before = list(sys.path); "
        "import scripts.replay.agreement_names; "
        "import scripts.replay.agreement_round as h; "
        "imported = sys.path == before; "
        f"found = h.recover(Path({str(run)!r})); "
        "print(imported, sys.path == before, found.case is not None)"
    )
    env = {**os.environ, harness.TREE_VARIABLE: str(harness._ROOT)}

    done = subprocess.run(
        [sys.executable, "-c", probe],
        env=env,
        cwd=harness._ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )

    assert done.returncode == 0, done.stderr
    assert done.stdout.strip().splitlines()[-1] == "True True True"


def test_the_program_refuses_to_start_on_a_package_earlier_on_the_path(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    fake = tmp_path / "earlier"
    (fake / "malspark").mkdir(parents=True)
    (fake / "malspark" / "__init__.py").write_text("", encoding="utf-8")
    script = Path(harness.__file__).resolve()
    # The package is found on the path ahead of this tree's before the program starts.
    start = (
        "import runpy, sys; "
        f"sys.path.insert(0, {str(fake)!r}); import malspark; "
        f"sys.argv = [{str(script)!r}, {str(tmp_path)!r}]; "
        f"runpy.run_path({str(script)!r}, run_name='__main__')"
    )

    done = subprocess.run(
        [sys.executable, "-c", start],
        env={k: v for k, v in os.environ.items() if k != harness.TREE_VARIABLE},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )

    assert done.returncode == harness.WRONG_TREE, done.stderr
    assert str(fake / "malspark") in done.stderr


def _runs_keeping_answers() -> list[Path]:
    """The stored runs whose record keeps the round's answers: a run directory directly under
    the benchmark, or a numbered job directory under a family's."""
    root = stored_runs()
    if root is None:
        return []
    return sorted(
        path.parent
        for path in (*root.glob("*/report.json"), *root.glob("*/*/report.json"))
        if b'"answers_masked"' in path.read_bytes()
    )


@pytest.mark.skipif(
    not _runs_keeping_answers(),
    reason="no stored benchmark run keeping the round's answers is in this checkout "
    "(the stored runs are kept outside git)",
)
def test_a_stored_run_whose_first_turn_is_reproduced_replays_to_its_stored_report() -> None:
    checked = 0
    for run in _runs_keeping_answers():
        found = harness.recover(run)
        if found.case is not None:
            # Replayed without the flag: every turn is the logged one.
            assert found.prompt_reproduced and not found.blocks_differing
            assert found.retry_reproduced is not False
        else:
            # Refused for an input the model was not shown, or giving nothing to replay.
            assert found.refused or found.why
            if not (found.prompt_reproduced and found.first_turn_sent_reproduced):
                continue
            found = harness.recover(run, allow_differing=True)
            assert found.case is not None and found.record is not None
            assert harness.REPLAY_NOTE in harness.run_notes(found.record)
        record = found.record
        assert found.case is not None and record is not None
        assert harness.against_stored(run, found.case, record) == [], found.run
        checked += 1
    assert checked
