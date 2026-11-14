"""The replay reads a passage the round's prompt marks (verbatim) as one never rewritten.

A stored prompt shows a text printed in its writer's own words marked (verbatim): the
replay's reading of the prompt keeps its label and text, and gives it no writer, as the round
does (T-613). A stored prompt with no mark reads with no such passage. Every value here is a
neutral synthetic one.
"""

from __future__ import annotations

from scripts.replay.agreement_names import _passages

_PROMPT = "\n".join(
    [
        "SECTION 5, WRITTEN FROM THE CODE AND THE TOOL ANSWERS",
        "-----------------------------------------------------",
        "- [string_resolution] 5. Technical analysis, 'Strings' (cites ev_0103): \"Routine "
        '0x5b20 reads a byte [ev_0103]."',
        "PASSAGES WRITTEN WITHOUT THE CODE",
        "---------------------------------",
        '- [conclusion] 7. Conclusion: "The file is a loader."',
        "- [statements.T1057.1] Appendix, an analyst's statement on T1057 (verbatim) (cites "
        'ev_0101): "Routine 0x5a10 lists processes [ev_0101]."',
    ]
)


def test_a_verbatim_passage_is_read_with_no_writer_and_its_text_whole() -> None:
    shown = {p.id: p for p in _passages(_PROMPT)}

    statement = shown["statements.T1057.1"]
    assert statement.label == "Appendix, an analyst's statement on T1057"
    assert statement.text == "Routine 0x5a10 lists processes [ev_0101]."
    assert statement.write is None and statement.verbatim
    assert shown["conclusion"].write is not None and not shown["conclusion"].verbatim
    assert shown["string_resolution"].write is not None


def test_a_cell_s_place_label_is_rebuilt_from_its_identity() -> None:
    from malspark.reporting.section_agreement import place_labels
    from tests.unit.reporting.test_a_cell_with_no_subject_is_kept_only_on_its_own_field import (
        _report,
    )

    prompt = "\n".join(
        [
            "PASSAGES WRITTEN WITHOUT THE CODE",
            "---------------------------------",
            "- [communications.2.encryption] 5. Technical analysis, channel row 2, encryption: "
            '"Not established."',
        ]
    )
    (cell,) = _passages(prompt, place_labels(_report()))

    assert cell.place_label == (("encryption",), ("DNS channel", "channel 2"))
    assert _passages(prompt)[0].place_label is None


def test_a_source_only_passage_is_read_as_a_source_with_its_text_whole() -> None:
    prompt = "\n".join(
        [
            "PASSAGES WRITTEN WITHOUT THE CODE",
            "---------------------------------",
            "- [judge.business_impact.unprinted] 7. Conclusion, the judge's severity rationale, "
            "not printed in the analyst report (verbatim, a source only) (cites ev_0103): "
            '"The loader checks for a debugger [ev_0103]."',
        ]
    )
    (source,) = _passages(prompt)

    assert source.label == (
        "7. Conclusion, the judge's severity rationale, not printed in the analyst report"
    )
    assert source.text == "The loader checks for a debugger [ev_0103]."
    assert source.source_only and source.verbatim and source.write is None
