"""The replay rebuilds what a stored prompt does not show from the stored report.

A stored agreement prompt shows a passage's id, label and text, never the label of the
place a sentence with no subject of its own is read against, nor who wrote a verbatim text.
The replay reads the run's stored prompt and rebuilds both from the passage's identity in
the stored report, as the live round builds them; a passage the report no longer shows reads
with the live round's own default (T-613). Every value here is a neutral synthetic one.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.replay.agreement_names import shown_passages

from malspark.reporting.section_agreement import passages_of
from tests.unit.reporting.test_a_cell_with_no_subject_is_kept_only_on_its_own_field import (
    _report,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

_HEAD = "FACTS THE PLATFORM STATES\n------\nPASSAGES WRITTEN WITHOUT THE CODE\n------"


def _run(tmp_path: Path, report: object, *lines: str) -> Path:
    """A stored run: its report, and a worker log holding one agreement request."""
    prompt = "\n".join([_HEAD, *lines])
    options = {"json_data": {"messages": [{"role": "user", "content": prompt}]}}
    (tmp_path / "worker.log").write_text(
        f"2026-11-14 DEBUG Request options: {options!r}\n", encoding="utf-8"
    )
    (tmp_path / "report.json").write_text(
        json.dumps(report.model_dump(mode="json")),  # type: ignore[attr-defined]
        encoding="utf-8",
    )
    return tmp_path


def test_a_cell_s_place_label_is_rebuilt_from_the_stored_report(tmp_path: Path) -> None:
    run = _run(
        tmp_path,
        _report(),
        "- [communications.2.encryption] 5. Technical analysis, channel row 2, encryption: "
        '"Not established."',
    )
    (cell,) = shown_passages(run)

    assert cell.place_label == (("encryption",), ("DNS channel", "channel 2"))


def test_a_verbatim_passage_carries_its_writer_as_the_live_round_names_it(
    tmp_path: Path,
) -> None:
    live = {p.id: p for p in passages_of(report_of())}
    run = _run(
        tmp_path,
        report_of(),
        "- [attack_note.T1055] ATT&CK table, the reason T1055 is not published (verbatim) "
        '(cites ev_0104): "No write into another process is shown [ev_0104]."',
        "- [statements.T1099.1] Appendix, an analyst's statement on T1099 (verbatim): "
        '"Routine 0x5f00 reads a key."',
    )
    shown = {p.id: p for p in shown_passages(run)}

    assert shown["attack_note.T1055"].verbatim == live["attack_note.T1055"].verbatim
    assert shown["attack_note.T1055"].place_label == live["attack_note.T1055"].place_label
    # Not shown by the stored report: the live round's default writer.
    assert shown["statements.T1099.1"].verbatim == live["statements.T1057.1"].verbatim
