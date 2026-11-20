"""The replay's comparison sees a finding's words and a detection draft's body.

A finding is keyed by its producer, answer, claim and code, a digest of its
words and every value-free field beside them (``asked``, ``advisory``, the
linter's ``severity``, ...), and the findings of one key are compared as a
multiset: words that change while everything else stays are a difference, and
the words themselves are printed only when the records hold them (the text
option). A detection draft is compared by its kind, a digest of its name and a
digest of its body, drafted under the stored run's clock, so a body moves only
where the rules write it differently. A record of an earlier schema holds
neither: against one, each is listed as not compared and the comparison is
partial.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from scripts.replay import rules
from scripts.replay.compare import diff_records, differs, flag_keys, is_partial
from scripts.replay.output import render_diff
from scripts.replay.record import NOT_COMPARED_IN_A_FINDING, REPLAY_SCHEMA, digest
from scripts.replay.stored import read_run, stored_clock

from tests.unit.scripts._replay_tiny import FIXTURE

MESSAGE = "'copy a.txt' is not in ev_0006, ev_0002 (3 entries)"


def _finding(message: str, **fields: Any) -> dict[str, Any]:
    """A finding as the replay records it, through the replay's own writer."""
    violation = SimpleNamespace(code="report.citation_wrong_entry", path="body", message=message)
    return {**rules._flag(violation, show_text=True), **fields}


def _record(flags: list[dict[str, Any]], drafts: list[dict[str, Any]] | None = None) -> dict:
    return {
        "schema": REPLAY_SCHEMA,
        "run": "1",
        "composer": {"replayed": True, "sections": {"configuration": {"flags": flags}}},
        "report": {"replayed": True, "detection_drafts": drafts or []},
    }


def _quiet(record: dict[str, Any]) -> dict[str, Any]:
    """The record as a replay without the text writes it: no words, no draft text."""
    out = copy.deepcopy(record)
    for flag in out["composer"]["sections"]["configuration"]["flags"]:
        flag.pop("message", None)
    for draft in out["report"]["detection_drafts"]:
        for key in ("name_text", "body_text", "compile_error_text"):
            draft.pop(key, None)
    return out


class TestTheWordsOfAFinding:
    def test_a_finding_carries_the_digest_of_its_words_and_the_words_only_with_the_text(
        self,
    ) -> None:
        violation = SimpleNamespace(code="c", path="body", message=MESSAGE)
        quiet = rules._flag(violation, show_text=False)
        assert quiet["words"] == digest(MESSAGE) and "message" not in quiet
        assert rules._flag(violation, show_text=True)["message"] == MESSAGE

    def test_a_changed_message_with_an_unchanged_key_is_a_difference(self) -> None:
        a = _record([_finding(MESSAGE)])
        b = _record([_finding("'copy a.txt' stands in the answer of ev_0006")])
        diff = diff_records(_quiet(a), _quiet(b))
        assert differs(diff)
        [lost], [gained] = diff["codes_lost"], diff["codes_gained"]
        assert (lost["code"], lost["path"]) == (gained["code"], gained["path"])
        assert lost["words"] != gained["words"]
        # Without the text no word is printed, only the digests.
        shown = render_diff(diff, "A", "B")
        assert "copy a.txt" not in shown and lost["words"] in shown and "said:" not in shown

    @pytest.mark.parametrize(
        "changed",
        [
            MESSAGE.replace(" is ", "  is "),
            MESSAGE.replace("'copy", "'COPY"),
            MESSAGE.replace("3 entries", "4 entries"),
            MESSAGE.replace("ev_0006, ev_0002", "ev_0002, ev_0006"),
        ],
        ids=["whitespace", "case", "count", "id order"],
    )
    def test_every_change_of_the_words_shows(self, changed: str) -> None:
        diff = diff_records(_record([_finding(MESSAGE)]), _record([_finding(changed)]))
        assert differs(diff)
        assert [row["count"] for row in diff["codes_lost"] + diff["codes_gained"]] == [1, 1]

    def test_the_same_words_are_no_difference(self) -> None:
        diff = diff_records(_record([_finding(MESSAGE)]), _record([_finding(MESSAGE)]))
        assert not differs(diff)

    def test_findings_sharing_a_key_are_compared_as_a_multiset_of_their_words(self) -> None:
        x, y, z = _finding("first"), _finding("second"), _finding("third")
        assert not differs(diff_records(_record([x, y]), _record([y, x])))
        diff = diff_records(_record([x, y]), _record([x, z]))
        assert [row["message"] for row in diff["codes_lost"]] == ["second"]
        assert [row["message"] for row in diff["codes_gained"]] == ["third"]
        twice = diff_records(_record([x]), _record([x, x]))
        assert [(r["count"], r["in_a"], r["in_b"]) for r in twice["codes_gained"]] == [(1, 1, 2)]

    def test_with_the_text_the_words_of_a_lost_and_a_gained_row_are_printed(self) -> None:
        diff = diff_records(_record([_finding("old words")]), _record([_finding("new words")]))
        shown = render_diff(diff, "A", "B").split("\n")
        assert "        said: old words" in shown and "        said: new words" in shown

    @pytest.mark.parametrize(
        ("field", "a", "b"),
        [("asked", None, False), ("advisory", None, True), ("severity", "low", "high")],
    )
    def test_asked_advisory_and_severity_are_compared_in_the_same_rows(
        self, field: str, a: Any, b: Any
    ) -> None:
        before = _finding(MESSAGE) if a is None else _finding(MESSAGE, **{field: a})
        diff = diff_records(_record([before]), _record([_finding(MESSAGE, **{field: b})]))
        assert differs(diff)
        assert diff["codes_gained"][0]["fields"][field] == b

    def test_the_parts_never_compared_are_said_in_one_list_in_every_comparison(self) -> None:
        from scripts.replay.record import NEVER_COMPARED

        a = _record([_finding(MESSAGE, claim="one sentence", statements=["body#1"])])
        b = _record([_finding(MESSAGE, claim="another sentence", statements=["body#2"])])
        diff = diff_records(a, b)
        assert not differs(diff)
        shown = render_diff(diff, "A", "B").split("\n")
        assert [name for name, _why in NOT_COMPARED_IN_A_FINDING] == [
            "claim",
            "values",
            "statements",
        ]
        [listed] = [line for line in shown if "never compared" in line]
        assert listed.startswith("  never compared: a finding's claim (")
        assert "a finding's statements (its place in the checked text)" in listed
        assert all(f"{name} ({why})" in listed for name, why in NEVER_COMPARED)
        assert "the record's own keys (against_stored, format, rules, run," in listed
        assert "a detection draft's sample check (matches_sample, matched_by," in listed
        assert "drafts_not_built) (not held by the record)" in listed

    def test_a_record_of_the_earlier_schema_leaves_the_words_not_compared(self) -> None:
        new = _quiet(_record([_finding(MESSAGE, asked=False)]))
        old = copy.deepcopy(new)
        old["schema"] = REPLAY_SCHEMA - 1
        for flag in old["composer"]["sections"]["configuration"]["flags"]:
            del flag["words"]
        del old["report"]["detection_drafts"]
        diff = diff_records(old, new)
        assert diff["not_compared"] == {
            "b": [
                "findings: the fields beside code, path and subject",
                "findings: words",
                "report.detection_drafts",
            ]
        }
        assert is_partial(diff) and not differs(diff)
        assert flag_keys(old) == flag_keys(new, words=False)
        shown = render_diff(diff, "A", "B")
        assert "PARTIAL COMPARISON" in shown and "findings: words" in shown


def _draft(body: str, *, name: str = "Rule_one", kind: str = "yara") -> dict[str, Any]:
    return {
        "kind": kind,
        "name": digest(name),
        "body": digest(body),
        "name_text": name,
        "body_text": body,
    }


BODY = (
    'rule Rule_one {\n  strings:\n    $a = "beacon"\n    $b = "tasking"\n'
    "  condition:\n    any of them\n}"
)


class TestTheBodyOfADraft:
    def test_a_changed_body_is_a_difference_and_prints_its_lines_with_the_text(self) -> None:
        changed = BODY.replace('    $b = "tasking"\n', "")
        a, b = _record([], [_draft(BODY)]), _record([], [_draft(changed)])
        diff = diff_records(a, b)
        assert differs(diff)
        drafts = diff["report"]["detection_drafts"]
        assert [row["body"] for row in drafts["lost"]] == [digest(BODY)]
        assert [row["body"] for row in drafts["gained"]] == [digest(changed)]
        shown = render_diff(diff, "A", "B").split("\n")
        assert (
            f"    changed: yara {digest('Rule_one')}: body {digest(BODY)} -> " + digest(changed)
            in shown
        )
        assert '        -    $b = "tasking"' in shown
        quiet = render_diff(diff_records(_quiet(a), _quiet(b)), "A", "B")
        assert "tasking" not in quiet and "Rule_one" not in quiet and digest(BODY) in quiet

    def test_a_changed_compile_error_is_a_difference_by_its_digest(self) -> None:
        def failing(error: str) -> dict[str, Any]:
            return {
                **_draft(BODY),
                "not_compiled": True,
                "compile_error": digest(error),
                "compile_error_text": error,
            }

        a = _record([], [failing("line 3: syntax error near 'tasking'")])
        b = _record([], [failing("line 4: unexpected end of rule")])
        diff = diff_records(a, b)
        assert differs(diff)
        drafts = diff["report"]["detection_drafts"]
        assert [r["compile_error"] for r in drafts["lost"]] == [
            digest(a["report"]["detection_drafts"][0]["compile_error_text"])
        ]
        assert [r["body"] for r in drafts["gained"]] == [digest(BODY)]
        shown = render_diff(diff, "A", "B").split("\n")
        changed = [line for line in shown if line.startswith("    changed: yara")]
        assert len(changed) == 1 and "compile error" in changed[0]
        assert "        compile error under B: line 4: unexpected end of rule" in shown
        quiet = render_diff(diff_records(_quiet(a), _quiet(b)), "A", "B")
        assert "syntax error" not in quiet and "unexpected end" not in quiet
        assert not differs(diff_records(a, copy.deepcopy(a)))

    def test_a_draft_that_does_not_compile_carries_a_digest_of_its_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting.builder import MalwareReportBuilder

        error = "line 2: the rule names no condition"
        attach = MalwareReportBuilder.attach_detection_signatures

        def failing(report: Any) -> Any:
            built = attach(report)
            for rule in built.detection_signatures:
                rule.compile_error = error
            return built

        monkeypatch.setattr(MalwareReportBuilder, "attach_detection_signatures", failing)
        quiet = rules.replay_run(read_run(FIXTURE))
        shown = rules.replay_run(read_run(FIXTURE), show_text=True)
        drafts = quiet["report"]["detection_drafts"]
        assert drafts and all(d["compile_error"] == digest(error) for d in drafts)
        assert all("compile_error_text" not in d for d in drafts)
        assert all(d["compile_error_text"] == error for d in shown["report"]["detection_drafts"])

    @pytest.mark.parametrize("field", ["evidence", "left_out"])
    def test_a_changed_evidence_or_value_left_out_is_a_difference_by_its_digest(
        self, field: str
    ) -> None:
        a = _record([], [{**_draft(BODY), field: digest("one")}])
        b = _record([], [{**_draft(BODY), field: digest("two")}])
        diff = diff_records(a, b)
        assert differs(diff)
        assert [r[field] for r in diff["report"]["detection_drafts"]["gained"]] == [digest("two")]
        named = {"evidence": "evidence", "left_out": "values left out"}[field]
        shown = render_diff(diff, "A", "B")
        assert f"; {named} {digest('one')} -> {digest('two')}" in shown
        assert not differs(diff_records(a, copy.deepcopy(a)))

    def test_a_draft_carries_the_digests_of_its_evidence_and_its_values_left_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting.builder import MalwareReportBuilder
        from malspark.reporting.models import ValueLeftOut

        attach = MalwareReportBuilder.attach_detection_signatures

        def built(report: Any) -> Any:
            out = attach(report)
            for rule in out.detection_signatures:
                rule.source_evidence = ["ev_0002", "ev_0001"]
                rule.values_left_out = [ValueLeftOut(value="cmd.exe", why="too common")]
            return out

        monkeypatch.setattr(MalwareReportBuilder, "attach_detection_signatures", built)
        drafts = rules.replay_run(read_run(FIXTURE))["report"]["detection_drafts"]
        assert drafts
        for draft in drafts:
            assert draft["evidence"] == digest('["ev_0002", "ev_0001"]')
            assert draft["left_out"] == digest('[["cmd.exe", "too common"]]')

    def test_a_draft_one_side_lacks_is_named_with_its_counts(self) -> None:
        diff = diff_records(_record([], [_draft(BODY)]), _record([], []))
        [lost] = diff["report"]["detection_drafts"]["lost"]
        assert (lost["count"], lost["in_a"], lost["in_b"]) == (1, 1, 0)
        assert "in A, not in B: yara" in render_diff(diff, "A", "B")

    def test_the_drafts_of_the_tiny_run_do_not_move_with_the_clock(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built_by = rules._build

        def replay_at(moment: datetime) -> dict[str, Any]:
            def _build(*args: Any, **kwargs: Any) -> Any:
                values = built_by(*args, **kwargs)
                args[2].report.generated_at = moment
                return values

            monkeypatch.setattr(rules, "_build", _build)
            return rules.replay_run(read_run(FIXTURE), show_text=True)

        early = replay_at(datetime(2026, 1, 1, tzinfo=UTC))
        late = replay_at(datetime(2031, 7, 15, 5, tzinfo=UTC))
        assert early["report"]["detection_drafts"]
        assert early["report"]["detection_drafts"] == late["report"]["detection_drafts"]
        assert not differs(diff_records(early, late))
        # The drafts are dated by the stored report's clock, and the rebuilt report's
        # own clock is put back once they are drafted.
        stored = read_run(FIXTURE)
        clock = stored_clock(stored.report, stored.job)
        bodies = [d["body_text"] for d in early["report"]["detection_drafts"]]
        assert any(f"{clock:%Y-%m-%d}" in body for body in bodies)
        assert not any("2031" in body or "2026-01-01" in body for body in bodies)
        assert early["report"]["detection_rules"] == {"suricata": 1, "yara": 1}


class TestTheStoredClock:
    def test_the_stored_report_s_time_then_the_job_s_times_then_the_epoch(self) -> None:
        job = {"completed_at": "2026-03-02T10:00:00Z", "created_at": "2026-03-01T09:00:00Z"}
        built = {"generated_at": "2026-03-03T08:00:00+00:00"}
        assert stored_clock(built, job) == datetime(2026, 3, 3, 8, tzinfo=UTC)
        assert stored_clock({}, job) == datetime(2026, 3, 2, 10, tzinfo=UTC)
        assert stored_clock(None, {"created_at": "2026-03-01T09:00:00Z"}) == datetime(
            2026, 3, 1, 9, tzinfo=UTC
        )
        assert stored_clock({"generated_at": "not a time"}, None) == datetime(
            1970, 1, 1, tzinfo=UTC
        )

    def test_the_surface_render_dates_its_build_by_the_same_function(self) -> None:
        from scripts.replay import render_surfaces as rs

        job = {"created_at": "2026-03-01T09:00:00Z"}
        stored: Any = SimpleNamespace(report={}, job=job)
        assert rs._clock(stored) == stored_clock({}, job)
        own = rs._own_module("stored")
        assert Path(own.__file__) == Path(rs.__file__).with_name("stored.py")


class TestTheReasonOfAnUnpublishedTechnique:
    def test_the_reason_is_a_digest_and_its_words_are_added_only_with_the_text(self) -> None:
        quiet = rules.replay_run(read_run(FIXTURE))
        shown = rules.replay_run(read_run(FIXTURE), show_text=True)
        rows = {t: r for t, r in quiet["report"]["techniques"].items() if not r["published"]}
        assert rows
        for tid, row in rows.items():
            said = shown["report"]["techniques"][tid]["why_text"]
            assert said and "why_text" not in row
            assert row["why"] == f"sha256:{digest(said)}"

    def test_a_record_of_an_earlier_schema_leaves_the_reasons_not_compared(self) -> None:
        def with_reason(schema: int, why: str) -> dict[str, Any]:
            record = _record([])
            record["schema"] = schema
            record["report"]["techniques"] = {"T1105": {"published": False, "why": why}}
            return record

        new = with_reason(REPLAY_SCHEMA, f"sha256:{digest('the judge dropped it: x')}")
        old = with_reason(REPLAY_SCHEMA - 1, "the judge dropped it")
        diff = diff_records(old, new)
        assert diff["not_compared"]["differently"] == ["report.techniques: why"]
        assert "techniques" not in diff.get("report", {})
        # One schema on both sides compares the reasons.
        other = with_reason(REPLAY_SCHEMA, f"sha256:{digest('the judge dropped it: y')}")
        assert diff_records(new, other)["report"]["techniques"]["changed"]["T1105"]
        assert not is_partial(diff_records(new, other))
