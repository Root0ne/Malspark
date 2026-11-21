"""A publish answer is given as parts by its writer, and every reader composes from them.

The function that writes a ``no:`` answer gives, beside the printed text, its
refusing parts (each test that closed a way to publish the value, each its own
part, in the order the rule asks them) and its facts (what a record holds that
did not decide: what a tool recorded, who listed it, who mentioned it). The
printed answer is their composition, and nothing reads it back: a part may
hold ``;`` or ``,`` and is never split, and a refusing part is never cut.

* The state (a cell where the same render prints the whole answer, a mark's
  label, the writers' retry feedback, the reason a restatement is read
  against) is every refusing part.
* The whole answer (the recommendation retry, the export's decline) is every
  refusing part whole, then the facts in order until the first that does not
  fit the bound; that one and every later one are counted. A cell in a layout
  that prints the whole answer nowhere else is its only carrier and prints
  every part, with no bound.
* A mark of the unpublished-value code is labelled from the render's own
  reading of its sentence, composed as the stored label is.
* An answer read from a stored file has no parts: it prints as stored and is
  read as before, its state the text before the first ``;``.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from malspark.pipeline import validation
from malspark.pipeline.events import FINDING_VALUE_LIMIT, safe_finding_value
from malspark.pipeline.validation import (
    UNPUBLISHED_VALUE_CODE,
    _states_publish_state,
    _unstated_values,
    recommendation_indicator_violations,
    unpublished_value_violations,
)
from malspark.reporting import builder
from malspark.reporting.models import (
    ConsolidatedIOC,
    FileHashes,
    FlaggedStatement,
    MalwareReport,
    SampleIdentity,
    key_ordered,
)
from malspark.reporting.narrative_agent import published_answers
from malspark.reporting.publish_parts import (
    PublishAnswer,
    answer_state,
    refused,
    refusing_parts,
    told,
    told_whole,
    whole_answer,
)
from malspark.reporting.renderers import markdown
from malspark.reporting.renderers import stix_renderer as S
from malspark.reporting.renderers.analyst import _whole_answer_printed
from malspark.reporting.renderers.markdown import _Context
from malspark.schemas.stix_models import Indicator

ROOT = Path(__file__).resolve().parents[3]
REDACTED = ROOT / "tests" / "fixtures" / "reporting" / "stored_report_redacted.json"

FACT = "the sandbox report says it was made by a process the report does not list (procid 35)"
LONG_WHY = (
    "the sandbox report attributes its flows to StartMenuExperienceHost.exe (procid 101), "
    "which the sandbox marks as the sample's but which runs none of the submitted file's "
    "names and descends from none of its processes"
)
MENTIONERS = ", ".join(
    f"a claim by the {who} analyst" for who in ("triage", "static", "dynamic", "network")
)
LISTER = "an analyst artifact"
PASSED_TO = (
    "the address of its encoded bytes is argument 1 of the call at 0x6a1f to the function at "
    "0xae78; the frame slot [rsp+0x40], given to that call as argument 2, is then argument 1 "
    "of the call at 0x6a4e to the function at 0xbc1c; it is not followed past that call"
)
TWO_PLACES = "; ".join(
    [
        "recovered by FLOSS, ev_0018 (decoded string, routine 0xae78, called at 0x6a1f)",
        "decode_string_blobs, ev_0020 (xor8_rolling_header, at file offset 0xe078, in "
        f"function 0x6988, {PASSED_TO})",
    ]
)
SIX_ENTRIES = "; ".join(
    f"{entry} ({tool})"
    for entry, tool in [
        ("ev_0006", "iocs_from_file"),
        ("ev_0055", "extract_iocs"),
        ("ev_0075", "extract_iocs_with_context"),
        ("ev_0081", "search_strings"),
        ("ev_0230", "extract_iocs"),
        ("ev_0231", "decompile_function"),
    ]
)
NOT_ASKED_IN_TIME = S.judge_not_told(S.JUDGE_NOT_ASKED_IN_TIME)
RESOLVER_FACTS = (
    FACT,
    f"{LISTER} lists it",
    f"{MENTIONERS} mentions it and does not keep it",
)
LISTING = f"{LISTER} lists it, and a listing does not change what the sandbox recorded about it"
# A run's record in which a sweep row of iocs_from_file holds two values and a cited
# decompile entry holds each of them.
SWEPT_RECORD = S.SecondSources(
    swept={
        "c:\\x\\a.dll": (("iocs_from_file", "ev_0006"),),
        "relay.example.net": (("iocs_from_file", "ev_0006"),),
    },
    reads=(
        (
            "ev_0068",
            "batch_decompile",
            "rereads",
            True,
            frozenset({"c:\\x\\a.dll", "relay.example.net"}),
        ),
        ("ev_0053", "extract_iocs", "undeclared", True, frozenset({"relay.example.net"})),
    ),
)
BENIGN = ", but the verdict is Benign, which publishes no malicious indicator"

# (form, kind, value, source, keywords, refusing parts, facts)
FORMS: list[tuple[str, str, str, str, dict[str, Any], tuple[str, ...], tuple[str, ...]]] = [
    (
        "resolver with the sandbox's fact, a lister and mentioners",
        "ip",
        "8.8.8.8",
        "sandbox",
        {"unattributed": FACT, "listed_by": LISTER, "mentioned_by": MENTIONERS},
        (S.PUBLIC_RESOLVER,),
        RESOLVER_FACTS,
    ),
    (
        "resolver with the sandbox's fact and mentioners",
        "ip",
        "8.8.8.8",
        "sandbox",
        {"unattributed": FACT, "mentioned_by": MENTIONERS},
        (S.PUBLIC_RESOLVER,),
        (FACT, f"{MENTIONERS} mentions it and does not keep it"),
    ),
    ("resolver alone", "ip", "8.8.8.8", "sandbox", {}, (S.PUBLIC_RESOLVER,), ()),
    (
        "listing with a long why, mentioners",
        "ip",
        "20.74.46.118",
        "sandbox",
        {"unattributed": LONG_WHY, "listed_by": LISTER, "mentioned_by": MENTIONERS},
        (LONG_WHY, S.JUDGE_DID_NOT_KEEP),
        (LISTING, f"{MENTIONERS} mentions it and does not keep it"),
    ),
    (
        "listing with a short why",
        "ip",
        "172.217.76.94",
        "sandbox",
        {"unattributed": S.FLOW_NOT_PLACED, "listed_by": LISTER},
        (S.FLOW_NOT_PLACED, S.JUDGE_DID_NOT_KEEP),
        (LISTING,),
    ),
    (
        "unlisted, mentioned",
        "ip",
        "172.217.76.95",
        "sandbox",
        {"unattributed": S.FLOW_NOT_PLACED, "mentioned_by": MENTIONERS},
        (S.FLOW_NOT_PLACED, S.NO_MODEL_KEPT),
        (f"{MENTIONERS} mentions it and does not keep it",),
    ),
    (
        "judge untold, not asked in time, a lister",
        "ip",
        "45.77.10.18",
        "sandbox",
        {"unattributed": S.FLOW_NOT_PLACED, "untold": NOT_ASKED_IN_TIME, "listed_by": LISTER},
        (S.FLOW_NOT_PLACED, NOT_ASKED_IN_TIME),
        (f"{LISTER} lists it",),
    ),
    (
        "judge untold, a Benign recovery with two places, a lister",
        "ip",
        "45.77.10.20",
        "sandbox",
        {
            "unattributed": S.FLOW_NOT_PLACED,
            "untold": NOT_ASKED_IN_TIME,
            "recovered": TWO_PLACES,
            "verdict": "Benign",
            "listed_by": LISTER,
        },
        (S.FLOW_NOT_PLACED, NOT_ASKED_IN_TIME, f"{TWO_PLACES}{BENIGN}"),
        (f"{LISTER} lists it",),
    ),
    (
        "two routes: unattributed and a Benign recovery, a lister",
        "ip",
        "45.77.10.21",
        "sandbox",
        {
            "unattributed": S.FLOW_NOT_PLACED,
            "recovered": TWO_PLACES,
            "verdict": "Benign",
            "listed_by": LISTER,
        },
        (S.FLOW_NOT_PLACED, S.JUDGE_DID_NOT_KEEP, f"{TWO_PLACES}{BENIGN}"),
        (LISTING,),
    ),
    (
        "two routes: unattributed and a Benign recovery, mentioned",
        "ip",
        "45.77.10.22",
        "sandbox",
        {
            "unattributed": S.FLOW_NOT_PLACED,
            "recovered": TWO_PLACES,
            "verdict": "Benign",
            "mentioned_by": MENTIONERS,
        },
        (S.FLOW_NOT_PLACED, S.NO_MODEL_KEPT, f"{TWO_PLACES}{BENIGN}"),
        (f"{MENTIONERS} mentions it and does not keep it",),
    ),
    (
        "a recovery with two places, Benign",
        "domain",
        "evil-c3.example.com",
        "strings",
        {"recovered": TWO_PLACES, "verdict": "Benign"},
        (f"{TWO_PLACES}{BENIGN}",),
        (),
    ),
    (
        "a benign name in a published URL that holds ';', a lister",
        "domain",
        "www.google.com",
        "sandbox",
        {
            "unattributed": S.FLOW_NOT_PLACED,
            "in_published_url": "https://www.google.com/a;jsessionid=1,2",
            "listed_by": LISTER,
        },
        (
            f"{S.BENIGN_NAME_IN_A_URL} (https://www.google.com/a;jsessionid=1,2)",
            S.JUDGE_DID_NOT_KEEP,
        ),
        (LISTING,),
    ),
    (
        "six sightings, a lister",
        "domain",
        "tox.chat",
        "analyst",
        {"seen_in": SIX_ENTRIES, "listed_by": LISTER},
        (f"seen only in the text of {SIX_ENTRIES}, and no second source in this run records it",),
        (f"{LISTER} lists it",),
    ),
    (
        "named only by an analyst",
        "domain",
        "evil.example.net",
        "analyst",
        {"listed_by": LISTER},
        (
            f"{S.NAMED_ONLY_BY_AN_ANALYST} ({LISTER}); no tool in this run saw it, and "
            f"{S.JUDGE_DID_NOT_KEEP}",
        ),
        (),
    ),
]
# A why that holds a bracket inside a bracket, as a stored run's state does, and one of three
# levels.
LINEAGE = (
    "the sandbox report says it was made by a process whose lineage the report's two facts "
    "dispute (StartMenuExperienceHost.exe (procid 99))"
)
THREE_LEVELS = (
    "the sandbox report attributes its flows to svchost.exe (procid 7 (child of services.exe "
    "[procid 3 (session 0)]))"
)


def _combinations() -> list[tuple[str, Any]]:
    """Every combination of refusing parts the network branches of ``publish_answer`` write,
    each why among them, and the one-part forms of the other branches."""
    out: list[tuple[str, Any]] = []
    whys = {
        "flow": S.FLOW_NOT_PLACED,
        "long": LONG_WHY,
        "lineage": LINEAGE,
        "three": THREE_LEVELS,
    }
    who = {
        "alone": {},
        "listed": {"listed_by": LISTER},
        "mentioned": {"mentioned_by": MENTIONERS},
        "both": {"listed_by": LISTER, "mentioned_by": MENTIONERS},
    }
    recovery = {"": {}, "benign recovery": {"recovered": TWO_PLACES, "verdict": "Benign"}}
    for why_name, why in whys.items():
        for who_name, named in who.items():
            for untold in ("", NOT_ASKED_IN_TIME):
                for rec_name, rec in recovery.items():
                    label = " ".join(
                        part
                        for part in (why_name, who_name, "untold" if untold else "", rec_name)
                        if part
                    )
                    keywords: dict[str, Any] = {"unattributed": why, **named, **rec}
                    if untold:
                        keywords["untold"] = untold
                    out.append(
                        (label, S.publish_answer("ip", "45.77.10.30", "sandbox", **keywords))
                    )
    out += [
        ("resolver", S.public_resolver_reason(LINEAGE, LISTER, MENTIONERS)),
        ("seen in six entries", S.seen_in_reason(SIX_ENTRIES, LISTER)),
        ("named only, the report searched", S.named_only_reason(LISTER, S.SEARCHED_THE_REPORT)),
        ("judge only", S.judge_only_reason()),
        ("not resolving", S.publish_answer("domain", "host.local", "sandbox")),
        ("string cut", refused(S.CUT_REASON, facts=('the string reads "evil.ex"',))),
        (
            "strings, a cited holder",
            S.publish_answer("path", "C:\\x\\a.dll", "strings", corroborating=SWEPT_RECORD),
        ),
        ("strings, no sweep row", S.publish_answer("mutex", "Global\\x", "strings")),
        (
            "strings, a network value with a cited holder",
            S.publish_answer("domain", "relay.example.net", "strings", corroborating=SWEPT_RECORD),
        ),
        (
            "strings, a URL whose host has a reputation record",
            S.publish_answer(
                "url",
                "http://relay.example.net/a",
                "strings",
                {"malicious": 0, "suspicious": 0},
                corroborating=SWEPT_RECORD,
            ),
        ),
        ("bound browser user agent", refused(f"{S.BOUND}; {S.BROWSER_LIKE}")),
        (
            "benign name in a URL, lineage",
            S.not_kept_reason(f"{S.BENIGN_NAME_IN_A_URL} (https://a.example/x;y=1)", "", LISTER),
        ),
    ]
    return out


COMBINATIONS = _combinations()


def _named_states(text: str) -> list[str]:
    return validation._named_states(text)


# The forms whose state is longer than the text before their first ";".
LONGER_STATES = {
    "resolver with the sandbox's fact, a lister and mentioners",
    "resolver with the sandbox's fact and mentioners",
    "listing with a long why, mentioners",
    "listing with a short why",
    "judge untold, not asked in time, a lister",
    "judge untold, a Benign recovery with two places, a lister",
    "two routes: unattributed and a Benign recovery, a lister",
    "two routes: unattributed and a Benign recovery, mentioned",
    "a recovery with two places, Benign",
    "a benign name in a published URL that holds ';', a lister",
    "six sightings, a lister",
    "named only by an analyst",
}


def _answer(kind: str, value: str, source: str, keywords: dict[str, Any]) -> PublishAnswer:
    answer = S.publish_answer(kind, value, source, **keywords)
    assert isinstance(answer, PublishAnswer), answer
    return answer


def _ids(forms: list[Any]) -> list[str]:
    return [form[0] for form in forms]


class TestTheWriterGivesParts:
    @pytest.mark.parametrize(
        ("form", "kind", "value", "source", "keywords", "refusing", "facts"),
        FORMS,
        ids=_ids(FORMS),
    )
    def test_each_form_is_its_refusing_parts_then_its_facts(
        self,
        form: str,
        kind: str,
        value: str,
        source: str,
        keywords: dict[str, Any],
        refusing: tuple[str, ...],
        facts: tuple[str, ...],
    ) -> None:
        answer = _answer(kind, value, source, keywords)

        assert isinstance(answer, PublishAnswer)
        assert not S.publishes(answer)
        assert answer.refusing == refusing
        assert answer.facts == facts

    @pytest.mark.parametrize(
        ("form", "kind", "value", "source", "keywords", "refusing", "facts"),
        FORMS,
        ids=_ids(FORMS),
    )
    def test_the_printed_answer_is_the_composition_of_its_parts(
        self,
        form: str,
        kind: str,
        value: str,
        source: str,
        keywords: dict[str, Any],
        refusing: tuple[str, ...],
        facts: tuple[str, ...],
    ) -> None:
        answer = _answer(kind, value, source, keywords)
        rebuilt = PublishAnswer(answer.refusing, answer.facts, bracketed=answer.bracketed)

        assert answer == rebuilt
        assert str(answer).startswith("no: " + ", and ".join(refusing))

    def test_the_resolver_is_the_deciding_test_and_comes_first(self) -> None:
        answer = S.public_resolver_reason(FACT, LISTER, MENTIONERS)

        assert answer == (
            f"no: {S.PUBLIC_RESOLVER}; {FACT}; {LISTER} lists it; {MENTIONERS} mentions it and "
            "does not keep it"
        )

    def test_the_listing_form_states_the_judge_s_test_with_its_why(self) -> None:
        answer = S.not_kept_reason(S.FLOW_NOT_PLACED, "", LISTER)

        assert answer == f"no: {S.FLOW_NOT_PLACED}, and {S.JUDGE_DID_NOT_KEEP}; {LISTING}"

    def test_an_unlisted_row_keeps_its_mentioners_bracket_after_its_keep_test(self) -> None:
        answer = S.not_kept_reason(S.FLOW_NOT_PLACED, MENTIONERS)

        assert answer == (
            f"no: {S.FLOW_NOT_PLACED}, and no model kept it as an indicator "
            f"({MENTIONERS} mentions it and does not keep it)"
        )
        assert answer_state(answer) == f"no: {S.FLOW_NOT_PLACED}, and {S.NO_MODEL_KEPT}"

    def test_the_withheld_form_keeps_the_verdict_first_and_the_evidence_as_a_fact(self) -> None:
        answer = S.publish_answer("domain", "c2.example.com", "sandbox", verdict="Benign")

        assert isinstance(answer, PublishAnswer)
        (withheld,) = answer.refusing
        assert withheld == S.withheld_by_the_verdict("Benign")
        assert answer.facts and answer.facts[0].startswith(S.EVIDENCE_ALONE)
        assert answer == f"no: {withheld}; {answer.facts[0]}"

    def test_the_string_cut_form_refuses_with_the_cut_and_quotes_the_string_as_a_fact(
        self,
    ) -> None:
        record = S.SecondSources(cut={"c:\\x\\a.dll": "c:\\x\\a.dll;c:\\y"})
        answer = S.publish_answer("path", "C:\\x\\a.dll", "strings", corroborating=record)

        assert isinstance(answer, PublishAnswer)
        assert answer.refusing == (S.CUT_REASON,)
        assert len(answer.facts) == 1 and answer.facts[0].startswith("the string reads ")
        assert answer == f"no: {S.CUT_REASON}; {answer.facts[0]}"

    def test_the_strings_form_refuses_with_its_row_and_names_each_holder_as_a_fact(
        self,
    ) -> None:
        record = S.SecondSources(
            rereads=(("capa", "c:\\x\\a.dll"),), uncited=(("floss", "c:\\x\\a.dll"),)
        )
        answer = S.publish_answer("path", "C:\\x\\a.dll", "strings", corroborating=record)

        assert isinstance(answer, PublishAnswer)
        (first,) = answer.refusing
        assert first == (
            f"{S.NO_SWEEP_ROW.format(source='strings')} and {S.LOOKUP_FOUND_NO_SECOND_SOURCE}"
        )
        assert len(answer.facts) == 2
        assert answer == "; ".join([f"no: {first}", *answer.facts])

    def test_a_host_row_the_judge_was_not_told_of_gives_each_test_its_part(self) -> None:
        answer = S.publish_answer(
            "mutex", "Global\\x", "sandbox", unattributed="the record says no", untold="t"
        )

        assert isinstance(answer, PublishAnswer)
        assert answer.refusing == ("the record says no", "t")

    def test_a_refused_answer_without_a_refusing_part_cannot_be_written(self) -> None:
        with pytest.raises(ValueError):
            PublishAnswer(())

    def test_parts_survive_a_copy_and_a_pickle(self) -> None:
        import copy
        import pickle

        answer = S.public_resolver_reason(FACT, LISTER, MENTIONERS)

        # The bytes unpickled are the ones this test pickled, never data from outside.
        # nosemgrep: python.lang.security.deserialization.pickle.avoid-pickle
        pickled = pickle.loads(pickle.dumps(answer))
        for again in (copy.deepcopy(answer), pickled):
            assert isinstance(again, PublishAnswer)
            assert (again.refusing, again.facts) == (answer.refusing, answer.facts)


class TestTheBound:
    def test_every_refusing_part_is_kept_whole_and_the_facts_that_do_not_fit_are_counted(
        self,
    ) -> None:
        long_part = "x " * 130
        answer = refused(long_part.strip(), "a second test", facts=("fact one", "fact two"))

        said = told_whole(answer)

        assert said.startswith(f"no: {long_part.strip()}, and a second test")
        assert said.endswith("; and 2 more facts")

    def test_facts_print_in_order_until_the_first_that_does_not_fit(self) -> None:
        long_fact = "a listing of every entry " * 12
        answer = refused("short", facts=("a short fact", long_fact.strip(), "c"))

        assert told_whole(answer) == "no: short; a short fact; and 2 more facts"

    def test_a_part_that_holds_a_semicolon_is_never_split(self) -> None:
        answer = S.publish_answer(
            "domain", "evil-c3.example.com", "strings", recovered=TWO_PLACES, verdict="Benign"
        )

        assert answer_state(answer) == str(answer)
        assert told_whole(answer) == safe_finding_value(answer, whole=True)

    def test_a_bracketed_fact_is_told_in_its_bracket(self) -> None:
        answer = S.not_kept_reason("why", "a claim by the x analyst")

        assert told_whole(answer) == str(answer)

    def test_the_bound_is_the_finding_value_limit(self) -> None:
        answer = refused("r", facts=("f" * (FINDING_VALUE_LIMIT - len("no: r; ")),))

        assert whole_answer(answer) == str(answer)
        assert whole_answer(answer, limit=10) == "no: r; and 1 more fact"


class TestAStoredAnswerIsReadAsBefore:
    STORED = f"no: {FACT}; it is {S.PUBLIC_RESOLVER}; {LISTER} lists it"

    def test_its_state_is_the_text_before_its_first_semicolon(self) -> None:
        assert refusing_parts(self.STORED) is None
        assert answer_state(self.STORED) == f"no: {FACT}"

    def test_its_whole_answer_is_bounded_as_a_finding_value_is(self) -> None:
        assert told_whole(self.STORED) == safe_finding_value(self.STORED)
        assert told("x" * 300) == safe_finding_value("x" * 300)

    def test_a_row_read_from_a_stored_file_has_no_parts_and_prints_its_text(self) -> None:
        answer = S.public_resolver_reason(FACT, LISTER)
        row = ConsolidatedIOC(type="IPv4", kind="ip", value="8.8.8.8", published=answer)

        assert isinstance(row.published, PublishAnswer)
        dumped = json.loads(row.model_dump_json())
        assert dumped["published"] == str(answer)
        again = ConsolidatedIOC.model_validate(dumped)
        assert type(again.published) is str
        assert again.published == answer


class TestTheStateReaders:
    LONG = S.publish_answer("ip", "45.77.10.20", "sandbox", **FORMS[7][4])

    def _answers(self, kind: str, value: str) -> str:
        return self.LONG if value == "45.77.10.20" else ""

    def test_the_writer_is_told_every_refusing_part_whole(self) -> None:
        (found,) = unpublished_value_violations(
            {"body": "It connects to 45.77.10.20 on port 443."}, self._answers
        )

        state = answer_state(self.LONG)
        assert len(state) > FINDING_VALUE_LIMIT
        assert f"({state})" in found.message
        assert "(lists it" not in found.message
        assert found.labels == (f"45.77.10.20 ({state})",)

    def test_a_stored_answer_is_told_its_first_clause_bounded_as_before(self) -> None:
        stored = str(self.LONG)
        (found,) = unpublished_value_violations(
            {"body": "It connects to 45.77.10.20 on port 443."},
            lambda kind, value: stored if value == "45.77.10.20" else "",
        )

        assert f"({safe_finding_value(stored.split(';', 1)[0].strip())})" in found.message

    def test_the_recommendation_is_told_the_whole_answer_bounded_at_a_part_s_end(self) -> None:
        answer = S.public_resolver_reason(FACT, LISTER, MENTIONERS)
        payload = {
            "defensive_recommendations": [
                {"category": "dns", "action": "Block 8.8.8.8.", "priority": "P1"}
            ]
        }

        (found,) = recommendation_indicator_violations(
            payload, lambda kind, value: answer if value == "8.8.8.8" else ""
        )

        assert f"8.8.8.8 ({told_whole(answer)})" in found.message
        assert S.PUBLIC_RESOLVER in found.message and "more fact" in found.message

    def test_the_export_s_decline_is_the_whole_answer_bounded_at_a_part_s_end(self) -> None:
        answer = S.not_kept_reason(LONG_WHY, MENTIONERS, LISTER)
        row = ConsolidatedIOC(type="Domain", kind="domain", value="x.example.org", published=answer)
        indicator = Indicator(
            name="X",
            pattern="[domain-name:value = 'x.example.org']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
        )

        found = S._judge_indicator_unpublished(indicator, [row])

        assert found is not None
        assert f"({told_whole(answer)})" in found[1]
        assert S.JUDGE_DID_NOT_KEEP in found[1]

    def test_an_unstated_value_s_state_is_its_refusing_parts(self) -> None:
        answer = S.public_resolver_reason(FACT, LISTER)

        ((_kind, _value, state),) = _unstated_values(
            "It asks 8.8.8.8 for names.", lambda kind, value: answer
        )

        assert state == f"no: {S.PUBLIC_RESOLVER}"
        assert refusing_parts(state) == (S.PUBLIC_RESOLVER,)


class TestTheRestatement:
    """A word-for-word restatement of a printed state passes on every form."""

    @staticmethod
    def _written(how: str, state: str) -> str:
        body = state[len("no: ") :]
        written = {
            "no": f"({state})",
            "named": f"(publish state: {body})",
            "bare": f"({body})",
        }[how]
        return f" {written} during the run.".lower()

    @pytest.mark.parametrize("how", ["no", "named", "bare"])
    @pytest.mark.parametrize(
        ("form", "kind", "value", "source", "keywords", "refusing", "facts"),
        FORMS,
        ids=_ids(FORMS),
    )
    def test_a_printed_state_restated_word_for_word_passes(
        self,
        how: str,
        form: str,
        kind: str,
        value: str,
        source: str,
        keywords: dict[str, Any],
        refusing: tuple[str, ...],
        facts: tuple[str, ...],
    ) -> None:
        answer = _answer(kind, value, source, keywords)

        assert _states_publish_state(self._written(how, answer_state(answer)), answer)

    @pytest.mark.parametrize(
        ("form", "kind", "value", "source", "keywords", "refusing", "facts"),
        [form for form in FORMS if form[0] in LONGER_STATES and len(form[5]) > 1],
        ids=_ids([form for form in FORMS if form[0] in LONGER_STATES and len(form[5]) > 1]),
    )
    def test_the_first_refusing_part_alone_is_no_restatement(
        self,
        form: str,
        kind: str,
        value: str,
        source: str,
        keywords: dict[str, Any],
        refusing: tuple[str, ...],
        facts: tuple[str, ...],
    ) -> None:
        answer = _answer(kind, value, source, keywords)

        assert not _states_publish_state(f" ({refusing[0]}) during the run.".lower(), answer)

    def test_the_old_first_clause_of_a_resolver_row_is_no_restatement(self) -> None:
        answer = S.public_resolver_reason(FACT, LISTER)

        assert not _states_publish_state(f" ({FACT}) during the run.".lower(), answer)
        assert not _states_publish_state(f" (publish state: {FACT}) then.".lower(), answer)

    def test_two_refusing_parts_restated_in_another_order_pass(self) -> None:
        answer = S.not_kept_reason(S.FLOW_NOT_PLACED, "", LISTER)
        written = f" ({S.JUDGE_DID_NOT_KEEP}; {S.FLOW_NOT_PLACED}) during the run."

        assert _states_publish_state(written.lower(), answer)

    def test_a_named_state_is_read_to_the_end_of_its_own_bracket(self) -> None:
        answer = refused(FACT)

        assert _states_publish_state(f" (publish state: {FACT}) during the run.".lower(), answer)

    @pytest.mark.parametrize("how", ["no", "named", "bare"])
    @pytest.mark.parametrize("why", [LINEAGE, THREE_LEVELS], ids=["two levels", "three levels"])
    def test_a_bracket_inside_a_bracket_of_a_state_is_part_of_it(self, how: str, why: str) -> None:
        answer = S.not_kept_reason(why)
        value = "fd.api.iris.microsoft.com"
        sentence = f"The sample reaches {value}{self._written(how, answer_state(answer))}"

        assert str(answer_state(answer)).endswith(f"), and {S.NO_MODEL_KEPT}")
        assert _unstated_values(sentence, lambda kind, held: answer if held == value else "") == []

    def test_a_state_holding_a_semicolon_and_an_and_is_read_whole(self) -> None:
        answer = S.named_only_reason(LISTER)
        state = str(answer_state(answer))

        assert ";" in state and ", and " in state
        for how in ("no", "named", "bare"):
            assert _states_publish_state(self._written(how, state), answer), how

    def test_an_unbalanced_bracket_is_read_to_the_end_of_its_line(self) -> None:
        text = f"publish state: {FACT} (and more [of it\nthe next line) here"

        assert _named_states(text) == [f"{FACT} (and more [of it"]
        assert _named_states("publish state: (((") == ["((("]
        assert _named_states("no named state here") == []

    def test_named_states_are_read_in_one_pass_over_the_text(self) -> None:
        class Counted(str):
            reads = 0

            def __getitem__(self, key: Any) -> Any:
                Counted.reads += 1
                return str.__getitem__(self, key)

        for body in ("(" * 5000, "publish state: x (" * 2000, "publish state: " + "([" * 3000):
            Counted.reads = 0
            text = Counted(f"publish state: {body}")
            _named_states(text)
            assert Counted.reads <= len(text), (body[:20], Counted.reads, len(text))

    @pytest.mark.parametrize("how", ["no", "named", "bare"])
    @pytest.mark.parametrize(("label", "answer"), COMBINATIONS, ids=[c[0] for c in COMBINATIONS])
    def test_every_built_combination_of_refusing_parts_restated_word_for_word_passes(
        self, how: str, label: str, answer: PublishAnswer
    ) -> None:
        assert isinstance(answer, PublishAnswer), label

        assert _states_publish_state(self._written(how, answer_state(answer)), answer)


def _report() -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))


class TestTheCells:
    def _context(self, answer: str, printed: bool | None) -> _Context:
        ctx = _Context.of(_report())
        ctx._answers = lambda kind, value: answer if value == "8.8.8.8" else ""
        if printed is not None:
            ctx.whole_answer_printed = lambda kind, value, said: printed
        return ctx

    def test_a_cell_prints_the_state_where_the_render_prints_the_whole_answer(self) -> None:
        answer = S.public_resolver_reason(FACT, LISTER, MENTIONERS)

        for printed in (None, True):
            said = self._context(answer, printed).publish_state("8.8.8.8")
            assert "public DNS resolver" in said and "procid" not in said

    def test_a_cell_prints_the_whole_answer_where_the_render_prints_it_nowhere_else(
        self,
    ) -> None:
        answer = S.public_resolver_reason(FACT, LISTER, MENTIONERS)

        said = self._context(answer, False).publish_state("8.8.8.8")

        assert len(str(answer)) > FINDING_VALUE_LIMIT
        assert said == f" ({answer})"
        assert "procid 35" in said and MENTIONERS in said and "more fact" not in said

    def test_a_cell_that_is_the_only_carrier_prints_every_part_whole_however_long(
        self,
    ) -> None:
        answer = S.not_kept_reason(LONG_WHY, MENTIONERS, LISTER)
        ctx = _Context.of(_report())
        ctx._answers = lambda kind, value: answer if value == "x.example.org" else ""
        ctx.whole_answer_printed = lambda kind, value, said: False

        said = ctx.publish_state("x.example.org")

        assert said == f" ({answer})"
        assert all(part in said for part in (*answer.refusing, *answer.facts))

    def test_the_analyst_layout_prints_the_whole_answer_of_an_observed_only_row(self) -> None:
        answer = S.public_resolver_reason(FACT)
        listed = S.named_only_reason(LISTER)
        ctx = _Context.of(_report())
        ctx.iocs = [
            ConsolidatedIOC(
                type="IPv4", kind="ip", value="8.8.8.8", source="sandbox", published=answer
            ),
            ConsolidatedIOC(
                type="Domain",
                kind="domain",
                value="a.example.net",
                source="analyst",
                published=listed,
            ),
        ]

        printed = _whole_answer_printed(ctx)

        assert not printed("ip", "8.8.8.8", answer)
        assert printed("domain", "a.example.net", listed)


class TestTheMarks:
    """A stored mark of the unpublished-value code is labelled from the render's own reading."""

    SENTENCE = f"The sample asks 8.8.8.8 for names (publish state: {FACT})."
    STORED = f"8.8.8.8 (no: {FACT})"

    @staticmethod
    def _context(monkeypatch: pytest.MonkeyPatch, answer: str, *rows: FlaggedStatement) -> _Context:
        table = [
            ConsolidatedIOC(
                type="IPv4", kind="ip", value="8.8.8.8", source="sandbox", published=answer
            )
        ]
        monkeypatch.setattr(markdown, "_indicator_rows", lambda report, word=str: list(table))
        return _Context.of(_report().model_copy(update={"flagged_statements": list(rows)}))

    def _mark(self, code: str = UNPUBLISHED_VALUE_CODE, *, asked: bool = False) -> FlaggedStatement:
        return FlaggedStatement(sentence=self.SENTENCE, code=code, label=self.STORED, asked=asked)

    def test_the_label_is_the_state_the_render_s_table_gives_not_the_stored_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answer = S.public_resolver_reason(FACT, LISTER, MENTIONERS)

        ((sentence, mark),) = self._context(monkeypatch, answer, self._mark()).flagged

        assert sentence == self.SENTENCE
        label = f"8[.]8[.]8[.]8 (no: {S.PUBLIC_RESOLVER})"
        assert mark == f"**[not published by this run: {label}; not asked]**"
        assert "procid" not in mark

    def test_the_label_is_composed_as_validation_composes_the_stored_label(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answer = S.public_resolver_reason(FACT, LISTER, MENTIONERS)
        answers = lambda kind, value: answer if value == "8.8.8.8" else ""  # noqa: E731
        (found,) = unpublished_value_violations({"body": self.SENTENCE}, answers)

        ((_sentence, mark),) = self._context(monkeypatch, answer, self._mark(asked=True)).flagged

        assert found.labels == (
            validation.unpublished_value_label(_unstated_values(self.SENTENCE, answers)),
        )
        assert (
            mark == f"**[not published by this run: {markdown._defanged_text(found.labels[0])}]**"
        )

    def test_asked_stays_the_stored_fact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answer = S.public_resolver_reason(FACT)

        for asked in (True, False):
            ((_sentence, mark),) = self._context(
                monkeypatch, answer, self._mark(asked=asked)
            ).flagged
            assert mark.endswith("; not asked]**") is not asked

    def test_a_sentence_whose_state_the_render_s_table_agrees_with_is_not_marked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answer = refused(FACT)

        assert self._context(monkeypatch, answer, self._mark()).flagged == []

    def test_the_stored_label_prints_where_the_reading_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def unread(*_args: Any) -> list[tuple[str, str, str]]:
            raise RuntimeError("unread")

        monkeypatch.setattr(validation, "_unstated_values", unread)
        answer = S.public_resolver_reason(FACT)

        ((_sentence, mark),) = self._context(monkeypatch, answer, self._mark()).flagged

        assert "procid 35" in mark and S.PUBLIC_RESOLVER not in mark

    def test_a_mark_of_another_code_prints_its_stored_label(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answer = S.public_resolver_reason(FACT)
        row = self._mark("report.citation_wrong_entry")

        ((_sentence, mark),) = self._context(monkeypatch, answer, row).flagged

        assert "procid 35" in mark and S.PUBLIC_RESOLVER not in mark


def _redacted() -> MalwareReport:
    return MalwareReport.model_validate(key_ordered(json.loads(REDACTED.read_text())))


class TestEveryBuildPathCarriesTheParts:
    def test_every_refused_row_of_a_rebuilt_table_carries_parts_and_prints_their_composition(
        self,
    ) -> None:
        rows = builder.ioc_table(_redacted(), raise_unread=True)
        refused_rows = [row for row in rows if row.published and not S.publishes(row.published)]

        assert refused_rows
        for row in refused_rows:
            answer = row.published
            assert isinstance(answer, PublishAnswer), (row.kind, row.value, answer)
            assert answer == PublishAnswer(
                answer.refusing, answer.facts, bracketed=answer.bracketed
            )

    def test_the_table_s_answers_keep_their_parts(self) -> None:
        report = _redacted()
        rows = builder.ioc_table(report, raise_unread=True)
        answers = published_answers(report, rows=rows)

        for row in rows:
            if row.published and not S.publishes(row.published):
                assert isinstance(answers(row.kind or "", row.value), PublishAnswer)

    def test_a_table_read_from_its_stored_rows_prints_today_s_text(self) -> None:
        report = _redacted()
        stored = [row for row in report.consolidated_iocs if row.kind]

        assert stored and all(not isinstance(row.published, PublishAnswer) for row in stored)

    def test_a_report_whose_rebuild_fails_prints_its_stored_answers_on_every_surface(
        self,
    ) -> None:
        import html
        import re

        from malspark.reporting.misp import build_misp_attributes
        from malspark.reporting.renderers import HtmlRenderer
        from malspark.reporting.renderers.markdown import MarkdownRenderer

        def failed(*_args: Any, **_kwargs: Any) -> list[ConsolidatedIOC]:
            raise RuntimeError("the rebuild failed")

        def plain(text: str) -> str:
            text = html.unescape(re.sub(r"<[^>]+>", "", text))
            text = text.replace("\\", "").replace("[.]", ".").replace("[:]", ":")
            return " ".join(re.sub(r"[*_`]", "", text).split()).lower()

        report = _redacted()
        stored = [row for row in report.consolidated_iocs if row.kind]
        refused_text = [
            str(row.published) for row in stored if row.published and not S.publishes(row.published)
        ]
        assert any(text.startswith("no: the sandbox report") for text in refused_text)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(builder, "build_consolidated_iocs", failed)
            rows = builder.ioc_table(report, raise_unread=True)
            printed = {
                layout: MarkdownRenderer(layout=layout).render(report)
                for layout in ("full", "bundle", "analyst")
            }
            printed["html"] = HtmlRenderer().render(report, nonce="fixed")
            S.ExtendedSTIXRenderer().render(report)
            build_misp_attributes(report, rows, owner="a-report-id")

        assert [str(row.published) for row in rows] == [str(row.published) for row in stored]
        assert not any(isinstance(row.published, PublishAnswer) for row in rows)
        for surface in ("full", "bundle", "html"):
            for text in refused_text:
                assert plain(text) in plain(printed[surface]), (surface, text)

    # The answer writers a ``published=`` site or a ``.published =`` assignment may be fed by,
    # the names their answers are bound to, and a copy of another row's answer.
    WRITERS = frozenset(
        {"publish_answer", "_publish_answer", "_sandbox_host", "_captured", "_from_strings"}
    )
    HELD = frozenset({"answer", "published"})

    def test_no_site_of_the_builder_sets_an_answer_s_text_without_its_parts(self) -> None:
        tree = ast.parse(Path(builder.__file__).read_text())
        values: list[ast.expr] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "published":
                values.append(node.value)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "published":
                        values.append(node.value)
        assert len(values) >= 15
        for value in values:
            if isinstance(value, ast.Call):
                func = value.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                assert name in self.WRITERS, ast.unparse(value)
            elif isinstance(value, ast.Name):
                assert value.id in self.HELD, ast.unparse(value)
            else:
                assert isinstance(value, ast.Attribute) and value.attr == "published", ast.unparse(
                    value
                )

    def _assert_written_with_parts(self, value: ast.expr) -> None:
        if isinstance(value, ast.Call):
            func = value.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            assert name in self.WRITERS, ast.unparse(value)
        elif isinstance(value, ast.Name):
            assert value.id in self.HELD, ast.unparse(value)
        else:
            assert isinstance(value, ast.Attribute) and value.attr == "published", ast.unparse(
                value
            )

    def test_no_module_sets_a_row_s_answer_text_without_its_parts(self) -> None:
        # Every site in the package that sets a row's answer: a row built with one, a row
        # copied with one, or one assigned to a row; each takes it from an answer writer, a
        # name an answer is bound to, or another row's answer.
        package = Path(builder.__file__).resolve().parents[1]
        writers: set[str] = set()
        for path in sorted(package.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                values: list[ast.expr] = []
                if isinstance(node, ast.Call):
                    func = node.func
                    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                    for keyword in node.keywords:
                        if name == "ConsolidatedIOC" and keyword.arg == "published":
                            values.append(keyword.value)
                        if (
                            name in ("model_copy", "model_construct")
                            and keyword.arg == "update"
                            and isinstance(keyword.value, ast.Dict)
                        ):
                            values += [
                                held
                                for key, held in zip(
                                    keyword.value.keys, keyword.value.values, strict=True
                                )
                                if isinstance(key, ast.Constant) and key.value == "published"
                            ]
                if isinstance(node, ast.Assign):
                    values += [
                        node.value
                        for target in node.targets
                        if isinstance(target, ast.Attribute) and target.attr == "published"
                    ]
                for value in values:
                    self._assert_written_with_parts(value)
                    writers.add(path.relative_to(package).as_posix())

        assert "reporting/builder.py" in writers, writers


def test_every_stored_refused_value_s_state_restated_word_for_word_passes() -> None:
    from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import (
        _benchmark,
    )

    root = _benchmark()
    if root is None:
        pytest.skip("the stored benchmark runs are not on this machine")
    # A stored run is a directory holding its report and its ledger.
    runs = sorted(
        path.parent
        for path in root.rglob("report.json")
        if (path.parent / "evidence.json").is_file()
    )
    if not runs:
        pytest.skip("the stored benchmark runs are not on this machine")
    restated = own = 0
    failing: set[tuple[str, str, str]] = set()
    for run in runs:
        name = run.relative_to(root).as_posix()
        report = MalwareReport.model_validate(json.loads((run / "report.json").read_text()))
        seen: set[tuple[str, str]] = set()
        for row in builder.ioc_table(report, raise_unread=True):
            answer = row.published
            key = (str(row.kind), str(row.value))
            if row.kind not in ("ip", "domain", "url") or S.publishes(answer) or key in seen:
                continue
            seen.add(key)
            assert isinstance(answer, PublishAnswer), (name, key, answer)
            state = str(answer_state(answer))
            wanted = str(row.value)
            if wanted.lower() in state.lower():
                # A state that writes its own value is read as a second place of that
                # value, by the rule of a value written twice (T-821): not this test's.
                own += 1
                continue

            def answers(kind: str, value: str, held: str = answer, wanted: str = wanted) -> str:
                return held if value == wanted else ""

            for written in (f"({state})", f"({state[4:]})", f"(publish state: {state[4:]})"):
                restated += 1
                found = _unstated_values(
                    f"The sample reaches {wanted} {written} during the run.", answers
                )
                if any(value == wanted for _kind, value, _state in found):
                    failing.add((name, *key))

    assert restated + 3 * own == 2235, (restated, own)
    assert not failing, sorted(failing)
