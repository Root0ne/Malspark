"""``strings`` gives a text the pattern matched inside a run the offset of that text.

A row is one run of printable bytes, and its ``offset`` is where the run
starts. A run can hold many texts one after another (string data joined into
one long run), so where ``pattern`` matched a text that begins inside the run,
the row also gives ``match_offsets``: the byte offset in the file of each
matched text. ``offset`` keeps meaning the run's start, and which runs come
back, in what order and on which page, does not change.
"""

from __future__ import annotations

from pathlib import Path

from malspark.tools import strings as tool

# A joined run with the marker deep inside it, behind NULs and a lead-in.
LEAD = b"\x00" * 64
HEAD = b"runtime: stack split at bad timepanic while printing panic value" * 20
MARKER = b"del /f /q C:\\Temp\\*.*"
TAIL = b"slice bounds out of range [%x:%y]" * 10


def _file(tmp_path: Path, payload: bytes) -> str:
    target = tmp_path / "joined.bin"
    target.write_bytes(payload)
    return str(target)


class TestATextInsideARun:
    def test_the_matched_text_gets_its_own_offset_beside_the_run_s_start(
        self, tmp_path: Path
    ) -> None:
        path = _file(tmp_path, LEAD + HEAD + MARKER + TAIL + b"\x00")

        (row,) = tool.strings(path, pattern="del /f /q")["strings"]

        assert row["offset"] == len(LEAD)
        assert row["match_offsets"] == [len(LEAD) + len(HEAD)]
        assert row["text"] == (HEAD + MARKER + TAIL).decode()

    def test_every_match_in_the_run_is_given_in_order(self, tmp_path: Path) -> None:
        path = _file(tmp_path, LEAD + HEAD + MARKER + TAIL + MARKER + b"\x00")

        (row,) = tool.strings(path, pattern="DEL /F")["strings"]

        second = len(LEAD) + len(HEAD) + len(MARKER) + len(TAIL)
        assert row["match_offsets"] == [len(LEAD) + len(HEAD), second]

    def test_a_regular_expression_is_placed_the_same_way(self, tmp_path: Path) -> None:
        path = _file(tmp_path, LEAD + HEAD + MARKER + TAIL + b"\x00")

        (row,) = tool.strings(path, pattern=r"re:del\s+/f")["strings"]

        assert row["match_offsets"] == [len(LEAD) + len(HEAD)]

    def test_a_wide_run_counts_two_bytes_per_character(self, tmp_path: Path) -> None:
        wide = (HEAD[:40] + MARKER).decode().encode("utf-16-le")
        path = _file(tmp_path, LEAD + wide + b"\x00\x00")

        (row,) = tool.strings(path, encodings=("utf16le",), pattern="del /f")["strings"]

        assert row["offset"] == len(LEAD)
        assert row["match_offsets"] == [len(LEAD) + 2 * 40]

    def test_the_offsets_given_are_capped_and_the_count_says_how_many_there_are(
        self, tmp_path: Path
    ) -> None:
        path = _file(tmp_path, LEAD + b"ab" + MARKER * 40 + b"\x00")

        (row,) = tool.strings(path, pattern="del")["strings"]

        assert len(row["match_offsets"]) == 16
        assert row["match_count"] == 40
        assert row["match_offsets"][1] - row["match_offsets"][0] == len(MARKER)


class TestNothingElseMoves:
    def test_a_run_the_pattern_matches_at_its_start_is_answered_as_before(
        self, tmp_path: Path
    ) -> None:
        path = _file(tmp_path, LEAD + MARKER + b"\x00")

        rows = tool.strings(path, pattern="del /f")["strings"]

        assert rows == [{"offset": len(LEAD), "enc": "ascii", "text": MARKER.decode()}]

    def test_an_answer_without_a_pattern_is_answered_as_before(self, tmp_path: Path) -> None:
        path = _file(tmp_path, LEAD + HEAD + MARKER + TAIL + b"\x00")

        rows = tool.strings(path)["strings"]

        assert rows == [
            {"offset": len(LEAD), "enc": "ascii", "text": (HEAD + MARKER + TAIL).decode()}
        ]

    def test_the_runs_returned_their_order_and_the_paging_are_unchanged(
        self, tmp_path: Path
    ) -> None:
        runs = [b"x" * 30 + MARKER, MARKER + b"y" * 5, b"no match here at all", b"z" + MARKER]
        path = _file(tmp_path, b"".join(LEAD + run for run in runs) + b"\x00")

        page = tool.strings(path, pattern="del /f", limit=2)

        assert [row["text"] for row in page["strings"]] == [runs[0].decode(), runs[1].decode()]
        assert "match_offsets" in page["strings"][0]
        assert "match_offsets" not in page["strings"][1]
        assert (page["total"], page["total_matched"], page["next_offset"]) == (4, 3, 2)
        assert list(page["strings"][0]) == ["offset", "match_offsets", "enc", "text"]
