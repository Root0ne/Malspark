"""A model-written table cell of the analyst report cites as its prose does.

The analyst report moves each bracketed group of evidence ids its prose holds
to a numbered note that links into the bundle. A table cell the report model
wrote went through the shared cell writer, which printed "[ev_0008, ev_0021]"
as written. The cell writer now writes a cell's citations as the layout's
prose does: a note marker in the analyst report, the ids as written in the
single-file report and the bundle. An id the evidence index does not hold is
cited as prose cites it: a note the bundle lists as holding no entry (T-566).
"""

from __future__ import annotations

import re

from malspark.reporting.models import (
    EncryptionScheme,
    EvidenceIndexRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE

# The haiku13 shape of the scheme, the values changed.
_SCHEME = EncryptionScheme(
    cipher=(
        "RC4 (stream cipher, key schedule and PRGA), used for C2 beacon traffic [ev_0008, ev_0021]"
    ),
    library="None: RC4 is implemented in the sample's own code [ev_0004; ev_0023]",
    key_source='Hard-coded text key "k3y", decoded from the blob at 0xfd30 [ev_0021]',
    key_management="Static shared key compiled into the sample [ev_0099]",
    per_file_key=False,
    evidence_ref="ev_0021",
)
# A bracketed list of ids printed as written, no link after it.
_BRACKETED = re.compile(r"\[ev_\d+(?:\s*[,;]\s*ev_\d+)*\](?!\()")
_NOTE = re.compile(r"\[\[(\d+)\]\]\(evidence-bundle\.html#cite-\1\)")


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.dll"),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            encryption_scheme=_SCHEME,
            packing_obfuscation=TechnicalSubsection(
                title="Packing", body="Strings are decoded by 0xae78 [ev_0023].", evidence_refs=[]
            ),
        ),
        evidence_index=[
            EvidenceIndexRow(id=f"ev_{n:04d}", agent="static", tool="tool") for n in (4, 8, 21, 23)
        ],
    )


def _row(markdown: str, label: str) -> str:
    return next(line for line in markdown.splitlines() if line.startswith(f"| {label} |"))


def _mark(text: str) -> str:
    """The one note marker ``text`` holds."""
    found = _NOTE.findall(text)
    assert len(found) == 1, text
    return f"[[{found[0]}]](evidence-bundle.html#cite-{found[0]})"


def test_a_cell_s_bracketed_ids_become_the_note_markers_prose_prints() -> None:
    markdown = MarkdownRenderer(layout=ANALYST).render(_report())

    cipher = _row(markdown, "Cipher")
    library = _row(markdown, "Library")
    key_source = _row(markdown, "Key source")
    assert "[ev_" not in "\n".join(line for line in markdown.splitlines() if line.startswith("|"))
    assert cipher.endswith("used for C2 beacon traffic" + _mark(cipher) + " |")
    assert library.endswith("own code" + _mark(library) + " |")
    # The same id is the same note, in a cell as beside the table's heading.
    heading = next(line for line in markdown.splitlines() if line.startswith("Encryption scheme"))
    assert _mark(key_source) == _mark(heading)


def test_an_unknown_id_is_cited_as_prose_cites_it() -> None:
    report = _report()
    markdown = MarkdownRenderer(layout=ANALYST).render(report)
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    number = _NOTE.findall(_row(markdown, "Key management"))
    assert len(number) == 1
    assert f"**Note {number[0]}**" in bundle
    assert "**ev_0099**: no entry of the evidence index carries this id." in bundle


def test_the_single_file_report_and_the_bundle_print_the_ids_as_written() -> None:
    report = _report()

    for layout in (None, BUNDLE):
        renderer = MarkdownRenderer() if layout is None else MarkdownRenderer(layout=layout)
        markdown = renderer.render(report)
        assert _row(markdown, "Cipher").endswith("beacon traffic [ev_0008, ev_0021] |")
        assert "[ev_0004; ev_0023]" in _row(markdown, "Library")


def _first_seen(markdown: str) -> list[int]:
    """The note numbers in the order the report first prints each."""
    return list(dict.fromkeys(int(n) for n in _NOTE.findall(markdown)))


def test_the_notes_are_numbered_in_reading_order() -> None:
    markdown = MarkdownRenderer(layout=ANALYST).render(_report())

    # The prose above the table, then the table's heading, then its cells.
    prose = next(line for line in markdown.splitlines() if "decoded by 0xae78" in line)
    heading = next(line for line in markdown.splitlines() if line.startswith("Encryption scheme"))
    cells = [_mark(_row(markdown, label)) for label in ("Cipher", "Library", "Key source")]
    first = int(_NOTE.findall(prose)[0])
    assert first < int(_NOTE.findall(heading)[0])
    assert int(_NOTE.findall(heading)[0]) <= min(int(_NOTE.findall(c)[0]) for c in cells)
    seen = _first_seen(markdown)
    assert seen == list(range(1, len(seen) + 1))


def test_a_ransomware_scheme_s_notes_follow_reading_order() -> None:
    # A scheme that encrypts files is printed in the ransomware block, its table
    # under its prose: one pass numbers both.
    report = _report()
    report.technical_analysis.encryption_scheme = _SCHEME.model_copy(
        update={"per_file_key": True, "extension": ".lockx [ev_0008]"}
    )
    markdown = MarkdownRenderer(layout=ANALYST).render(report)

    rows = "\n".join(line for line in markdown.splitlines() if line.startswith("|"))
    assert ".lockx[[" in rows and not _BRACKETED.search(rows)
    seen = _first_seen(markdown)
    assert seen == list(range(1, len(seen) + 1))
