"""The replay reads a passage the round's prompt marks (verbatim) as one never rewritten.

A stored prompt shows a text printed in its writer's own words marked (verbatim): the
replay's reading of the prompt keeps its label and text, and gives it no writer, as the round
does (T-613). A stored prompt written before the mark reads as before. Every value here is a
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
