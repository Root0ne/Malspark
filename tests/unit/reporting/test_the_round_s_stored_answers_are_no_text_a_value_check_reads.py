"""The agreement round's stored answers are no text a value check reads.

The round keeps every answer it read in its record in the run summary
(``section_agreement.answers``), shown to no model and printed in no report. What the report
holds for the composer's value checks is read from the report and its run summary
(``composer_pro.held_text``): an answer's words there would count as a value the report holds,
so the stored answers are left out of it, the rest of the record kept (T-736). Every name here
is a neutral synthetic value.
"""

from __future__ import annotations

from malspark.reporting.composer_pro import held_text
from malspark.reporting.section_agreement import ANSWERS
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _report,
)

_ONLY_IN_AN_ANSWER = "QuietLanternNine"
_IN_THE_RECORD = "verbatim-shown-7c2e"


def test_a_value_standing_only_in_a_stored_answer_is_not_held() -> None:
    report = _report("The gate reads a host mode [ev_0107].")
    report.run_summary = {
        "section_agreement": {
            "verbatim_shown": {"introduction": _IN_THE_RECORD},
            ANSWERS: [
                {"sentences": [{"reason": f"the routine {_ONLY_IN_AN_ANSWER} is not called"}]},
                f"no rows: {_ONLY_IN_AN_ANSWER}",
            ],
        }
    }
    held = held_text(report)
    assert _ONLY_IN_AN_ANSWER not in held
    # The rest of the round's record, and the stored answers themselves, are as they were.
    assert _IN_THE_RECORD in held
    assert _ONLY_IN_AN_ANSWER in repr(report.run_summary["section_agreement"][ANSWERS])
