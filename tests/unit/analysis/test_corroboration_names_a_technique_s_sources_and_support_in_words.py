"""A technique's row says in words what stands behind it, and says nothing it does not hold.

The ATT&CK table, the export's support note, the report models and the judge
read one set of words (``analysis.corroboration``): the label of a technique
no source of which is behaviour (``support_label``), its sources counted by
kind in one order, singular or plural, with how many were cited only for an
absence (``sources_phrase``), and the clause that no sandbox observation, code
listing or rule match stands behind it (``NO_BEHAVIOUR_SOURCE``). A technique
only a rule match stands behind is named with each rule and how many strings
matched (``rule_match_only``); an id is printed with the release that retired
it and the reason it was not published (``technique_label``). Each wording is
pinned whole here, with the branch that prints nothing (T-770).

Every value is synthetic.
"""

from __future__ import annotations

from types import SimpleNamespace

from malspark.analysis.corroboration import (
    rule_match_only,
    sources_phrase,
    support_label,
    support_sentence,
    technique_label,
)
from malspark.reporting.renderers.markdown import support_words


class TestTheSupportLabel:
    def test_a_capability_and_an_unobserved_technique_are_named_and_any_other_is_not(
        self,
    ) -> None:
        assert support_label("capability") == "capability, not observed"
        assert support_label("unobserved") == "not observed"
        assert support_label("") == ""
        assert support_label("observed") == ""


class TestTheSourcesAreCountedByKind:
    def test_each_kind_is_named_once_in_its_order_singular_or_plural(self) -> None:
        assert sources_phrase({"unplaced": 1, "report": 2, "artefact": 1}, 4) == (
            "4 sources: 1 artefact of the file (a name, string, table or index row), "
            "2 external assessments of the whole file, 1 citation that gives no root"
        )
        assert sources_phrase({"artefact": 2, "report": 1, "unplaced": 2}, 5) == (
            "5 sources: 2 artefacts of the file (names, strings, tables or index rows), "
            "1 external assessment of the whole file, 2 citations that give no root"
        )

    def test_the_total_alone_where_the_kinds_were_not_recorded(self) -> None:
        assert sources_phrase(None, 1) == "1 source"
        assert sources_phrase({}, 3) == "3 sources"

    def test_the_sources_cited_for_an_absence_are_named_after_the_total(self) -> None:
        assert sources_phrase({"artefact": 3}, 3, absent=1) == (
            "3 sources (1 of them cited for an absence): "
            "3 artefacts of the file (names, strings, tables or index rows)"
        )


class TestTheSentenceOnATechniqueNoSourceOfWhichIsBehaviour:
    def test_the_export_and_the_models_are_told_the_label_the_kinds_and_the_clause(
        self,
    ) -> None:
        assert support_sentence("capability", {"artefact": 1}, 1) == (
            "capability, not observed: 1 source: 1 artefact of the file (a name, string, "
            "table or index row); no sandbox observation, code listing or rule match "
            "stands behind it"
        )
        assert support_sentence("", {"artefact": 1}, 1) == ""

    def test_the_attack_table_row_says_the_same_clause(self) -> None:
        assert support_words("unobserved", {"report": 1}, 1, 0) == (
            "as not observed (1 source: 1 external assessment of the whole file; "
            "no sandbox observation, code listing or rule match stands behind it)"
        )
        assert support_words("", {"report": 1}, 1, 0) == ""


class TestARuleMatchAloneIsNamedWithHowMuchMatched:
    @staticmethod
    def _report(claimed_by: list[str], strings: list[dict[str, object]]) -> SimpleNamespace:
        return SimpleNamespace(
            run_summary={
                "corroboration": {"T1003": {"asserted_by": ["yara"], "claimed_by": claimed_by}}
            },
            rule_match_strings={"T1003": strings},
            ttp_mappings=[SimpleNamespace(technique_id="T1003")],
        )

    def test_each_rule_is_named_with_its_count_of_strings(self) -> None:
        rows: list[dict[str, object]] = [
            {"rule": "dump_lsass", "strings": 3, "source": "yara"},
            {"rule": "mimikatz_words", "strings": 1, "source": "yara"},
        ]

        assert rule_match_only(self._report([], rows)) == {
            "T1003": (
                "rule match only (yara `dump_lsass`, 3 strings; yara `mimikatz_words`, "
                "1 string), no analyst claim"
            )
        }

    def test_an_analyst_claim_leaves_no_note(self) -> None:
        rows: list[dict[str, object]] = [{"rule": "dump_lsass", "strings": 3, "source": "yara"}]

        assert rule_match_only(self._report(["static"], rows)) == {}


class TestTheIdIsPrintedWithWhatItsRowSays:
    def test_the_retired_release_and_the_unpublished_reason_are_joined(self) -> None:
        row = {"retired_in": "19.2", "not_published": "outside the domain"}

        assert technique_label("T1562.001", row) == (
            "T1562.001 (retired in ATT&CK 19.2; claimed, not published: outside the domain)"
        )

    def test_a_row_with_neither_prints_the_id_alone(self) -> None:
        assert technique_label("T1027", {"asserted_by": ["yara"]}) == "T1027"
        assert technique_label("T1027", None) == "T1027"
