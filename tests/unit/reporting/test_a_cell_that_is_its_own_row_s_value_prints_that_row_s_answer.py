"""A table cell whose whole text is the value of its own indicator row prints that row's answer.

The reader of a cell's values reads a URL as its host. Where the cell's whole
text is the value of an indicator row and that reader did not find the row,
the cell prints the row's own answer: nothing where the row is published, its
state where it is not. A cell that prints no state otherwise prints none. A
cell with more words than the value, a value no row holds, a value two rows
hold with different answers and a row the reader found are read as the
reader reads them.

Every value is synthetic.
"""

from __future__ import annotations

import re
from pathlib import Path

from malspark.reporting.models import (
    ConsolidatedIOC,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from malspark.reporting.renderers.markdown import _Context

URL = "https://files.example.net/get/a.bin"
HOST = "files.example.net"
URL_NO = "no: the publish rule found no recovery of the URL"
HOST_NO = "no: the publish rule read no reputation record of the host"


def _row(kind: str, value: str, published: str, type_: str = "") -> ConsolidatedIOC:
    return ConsolidatedIOC(
        type=type_ or kind, kind=kind, value=value, source="iocs_from_file", published=published
    )


def _context(*rows: ConsolidatedIOC) -> _Context:
    ctx = _Context.of(MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64))))
    ctx.iocs = list(rows)
    ctx._table_read = True
    ctx._answers = None
    return ctx


class TestTheCellsOwnRow:
    def test_a_url_cell_prints_the_url_row_s_answer(self) -> None:
        ctx = _context(_row("url", URL, URL_NO), _row("domain", HOST, HOST_NO))

        assert ctx.publish_state(URL) == f" ({URL_NO})"

    def test_a_published_url_row_prints_nothing_where_its_host_is_refused(self) -> None:
        ctx = _context(_row("url", URL, "yes: two sources"), _row("domain", HOST, HOST_NO))

        assert ctx.publish_state(URL) == ""

    def test_a_cell_written_in_another_spelling_of_the_row_s_value(self) -> None:
        ctx = _context(_row("url", URL, URL_NO), _row("domain", HOST, HOST_NO))

        assert ctx.publish_state(" HTTPS://FILES.EXAMPLE.NET/get/a.bin ") == f" ({URL_NO})"


class TestTheReaderDecides:
    def test_a_cell_holding_the_url_and_other_words(self) -> None:
        ctx = _context(_row("url", URL, URL_NO), _row("domain", HOST, HOST_NO))

        assert ctx.publish_state(f"{URL} (download)") == f" ({HOST_NO})"

    def test_a_url_no_row_holds(self) -> None:
        ctx = _context(_row("domain", HOST, HOST_NO))

        assert ctx.publish_state(URL) == f" ({HOST_NO})"

    def test_a_value_two_rows_hold_with_different_answers(self) -> None:
        other = "no: the row from strings holds it and nothing reads it as a URL"
        ctx = _context(
            _row("url", URL, URL_NO), _row("path", URL, other), _row("domain", HOST, HOST_NO)
        )

        assert ctx.publish_state(URL) == f" ({HOST_NO})"

    def test_a_value_two_rows_hold_with_one_answer(self) -> None:
        ctx = _context(
            _row("url", URL, URL_NO), _row("path", URL, URL_NO), _row("domain", HOST, HOST_NO)
        )

        assert ctx.publish_state(URL) == f" ({URL_NO})"

    def test_a_row_the_reader_found(self) -> None:
        ctx = _context(_row("domain", HOST, HOST_NO), _row("path", HOST, URL_NO))

        assert ctx.publish_state(HOST) == f" ({HOST_NO})"


class TestACellWithNoStateStaysSo:
    def test_a_url_cell_whose_host_is_published(self) -> None:
        ctx = _context(_row("url", URL, URL_NO), _row("domain", HOST, "yes: two sources"))

        assert ctx.publish_state(URL) == ""

    def test_a_cell_the_reader_reads_no_value_of(self) -> None:
        ctx = _context(_row("path", "C:\\a\\b.dat", URL_NO))

        assert ctx.publish_state("C:\\a\\b.dat") == ""


def test_no_model_reads_the_cell_s_state() -> None:
    """The cell's state is written by the report renderers only: no module of the pipeline,
    the agents, the prompts or the model-facing reporting code names it."""
    root = Path(__file__).resolve().parents[3]
    texts = {
        str(path.relative_to(root)): path.read_text(encoding="utf-8")
        for path in (root / "src").rglob("*.py")
    }
    assert sorted(name for name, text in texts.items() if "_own_row_state" in text) == [
        "src/malspark/reporting/renderers/markdown.py"
    ]
    assert sorted(
        name for name, text in texts.items() if re.search(r"\.publish_state\(", text)
    ) == [
        "src/malspark/reporting/renderers/analyst.py",
        "src/malspark/reporting/renderers/markdown.py",
    ]
