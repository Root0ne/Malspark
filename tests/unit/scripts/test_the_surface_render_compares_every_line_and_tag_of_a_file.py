"""Every line of a rendered file and every start tag of its HTML is a unit, and the file one too.

``file.lines`` holds each rendered file's lines in order, split at each line
feed and nothing else, so the file is its units joined again. ``html.tags``
holds every start tag as written, each attribute and its value in it. A
rendered file that differs is a change of its own whatever else changed in it:
a change on another surface never stands for it. What a unit reads more
loosely than the file is written (a whitespace run said as one space, a style
line's indentation, a line break other than a line feed, a final newline, a
STIX ref said as its target's key) is a ``file.lines`` change of that file.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from scripts.replay import render_surfaces as rs

Reader = Callable[[str, rs._Units], None]


def _rendered(name: str, text: str, read: Reader | None = None) -> dict[str, Any]:
    """A record of one rendered file: the units ``read`` takes from it, its lines and digest."""
    units = rs._Units("serve")
    if read is not None:
        read(text, units)
    rs.file_line_units({name: text}, units)
    return {
        "run": "r",
        "units": units.rows,
        "not_produced": [],
        "file_digests": {"serve": {name: rs.digest(text)}},
    }


def _surfaces(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    return sorted({c["surface"] for c in rs.compare_records(old, new)["changes"]})


def _changes(old: dict[str, Any], new: dict[str, Any], surface: str) -> list[dict[str, Any]]:
    return [c for c in rs.compare_records(old, new)["changes"] if c["surface"] == surface]


class TestEveryLineOfAFile:
    def test_a_file_is_split_at_each_line_feed_and_at_nothing_else(self) -> None:
        units = rs._Units("serve")
        rs.file_line_units({"report.md": "a\r\nb\x0cc\n"}, units)
        assert [u["text"] for u in units.rows] == ["a\r", "b\x0cc", ""]
        assert {(u["surface"], u["group"]) for u in units.rows} == {(rs.FILE_LINES, "report.md")}

    def test_a_line_put_in_is_one_line_added(self) -> None:
        old = _rendered("misp-event.json", '{\n "a": 1,\n "b": 2\n}\n')
        new = _rendered("misp-event.json", '{\n "a": 1,\n "c": 3,\n "b": 2\n}\n')
        [added] = _changes(old, new, rs.FILE_LINES)
        assert (added["change"], added["new"]) == ("added", ' "c": 3,')

    def test_a_key_moved_in_a_served_json_file_is_a_change(self) -> None:
        old = _rendered("misp-event.json", '{\n "info": "x",\n "uuid": "u"\n}\n')
        new = _rendered("misp-event.json", '{\n "uuid": "u",\n "info": "x"\n}\n')
        assert _surfaces(old, new) == [rs.FILE_SURFACE, rs.FILE_LINES]


class TestWhatAUnitReadsLooselyIsALineChange:
    def test_a_whitespace_run_said_as_one_space(self) -> None:
        old = _rendered("report.html", "<p>The sample decodes it.</p>\n", rs.html_units)
        new = _rendered("report.html", "<p>The sample  decodes\n it.</p>\n", rs.html_units)
        assert _surfaces(old, new) == [rs.FILE_SURFACE, rs.FILE_LINES]

    def test_a_style_line_s_indentation(self) -> None:
        old = _rendered("report.html", "<style>\n  .a { color: red; }\n</style>\n", rs.html_units)
        new = _rendered("report.html", "<style>\n\t.a { color: red; }\n</style>\n", rs.html_units)
        assert _surfaces(old, new) == [rs.FILE_SURFACE, rs.FILE_LINES]

    @pytest.mark.parametrize(
        "changed",
        ["# Report\r\n\nThe sample decodes it.\n", "# Report\n\nThe sample decodes it."],
    )
    def test_a_carriage_return_or_the_final_newline(self, changed: str) -> None:
        old = _rendered("report.md", "# Report\n\nThe sample decodes it.\n", rs.markdown_units)
        new = _rendered("report.md", changed, rs.markdown_units)
        assert _surfaces(old, new) == [rs.FILE_SURFACE, rs.FILE_LINES]

    def test_a_carriage_return_in_a_bundle_section(self) -> None:
        def _bundle(markdown: str) -> str:
            return json.dumps({"sections": [{"title": "A", "markdown": markdown}]}, indent=1)

        def _read(text: str, units: rs._Units) -> None:
            rs._bundle_units(json.loads(text), units)

        old = _rendered("evidence-bundle.json", _bundle("## A\nline\n"), _read)
        new = _rendered("evidence-bundle.json", _bundle("## A\r\nline\n"), _read)
        assert _surfaces(old, new) == [rs.FILE_SURFACE, rs.FILE_LINES]

    def test_a_ref_said_as_its_target_s_key(self) -> None:
        def _bundle(target: str) -> str:
            objects = [
                {"type": "malware", "id": target, "name": "loader"},
                {"type": "note", "id": "note--1", "content": "c", "object_refs": [target]},
            ]
            return json.dumps({"type": "bundle", "objects": objects}, indent=1)

        def _read(text: str, units: rs._Units) -> None:
            rs._stix_units(json.loads(text), units, dynamic=False)

        first = "malware--00000000-0000-4000-8000-000000000001"
        second = "malware--00000000-0000-4000-8000-000000000002"
        old = _rendered("stix-bundle.json", _bundle(first), _read)
        new = _rendered("stix-bundle.json", _bundle(second), _read)
        # The note's unit reads its ref as the malware's key and does not change.
        assert [c["key"] for c in _changes(old, new, "stix")] == ["malware loader id"]
        lines = [str(c["new"]) for c in _changes(old, new, rs.FILE_LINES)]
        assert sum(second in line for line in lines) == 2


# A figure and a cited sentence as the analyst report prints them.
_REPORT = (
    '<nav><ol><li><a href="#sec-1">1. Summary</a></li></ol></nav>'
    '<h2 id="sec-1">1. Summary</h2>'
    '<figure id="fig-attack-matrix"><svg><text x="4" y="20">Defense Evasion</text></svg>'
    "<figcaption><b>Figure 1.</b> MITRE ATT&amp;CK tactic coverage</figcaption></figure>"
    '<p>It decodes its configuration.<sup class="cite">'
    '<a href="evidence-bundle.html#cite-1">1</a></sup></p>\n'
)


def _html(**replaced: str) -> dict[str, Any]:
    text = _REPORT
    for old, new in replaced.items():
        assert old in text
        text = text.replace(old, new)
    return _rendered("report.html", text, rs.html_units)


class TestEveryStartTag:
    @pytest.mark.parametrize(
        ("old", "new"),
        [
            ('href="#sec-1"', 'href="#xsec-1"'),
            ('class="cite"', 'class="citex"'),
            ('class="cite"', 'class="cite" data-x="1"'),
            ('href="evidence-bundle.html#cite-1"', 'href="https://evil.example/#cite-1"'),
        ],
    )
    def test_an_attribute_changed_is_a_tag_unit_change(self, old: str, new: str) -> None:
        [tag] = _changes(_html(), _html(**{old: new}), "html.tags")
        assert new in tag["new"] and new not in tag["old"]

    def test_every_start_tag_is_a_unit_as_written(self) -> None:
        tags = [u["text"] for u in _html()["units"] if u["surface"] == "html.tags"]
        assert tags[:3] == ["<nav>", "<ol>", "<li>"]
        assert '<a href="evidence-bundle.html#cite-1">' in tags
        assert '<figure id="fig-attack-matrix">' in tags

    def test_a_caption_and_an_off_site_href_in_one_file_are_two_changes_and_the_file(
        self,
    ) -> None:
        old = _html()
        new = _html(
            **{
                "tactic coverage": "tactic coverage J",
                'href="evidence-bundle.html#cite-1"': 'href="https://evil.example/#cite-1"',
            }
        )
        assert _surfaces(old, new) == ["file", "file.lines", "html.figure", "html.tags"]
        [caption] = _changes(old, new, "html.figure")
        assert caption["new"].endswith("tactic coverage J")
        [href] = _changes(old, new, "html.tags")
        assert "evil.example" in href["new"]
        # Expecting the caption leaves the href unexpected.
        diff = rs.compare_records(old, new)
        expected = [{"surface": "html.figure", "new": "coverage J$", "reason": "r", "index": 0}]
        unexpected, _unexercised = rs.judge_changes([diff], expected)
        assert {c["surface"] for c in unexpected} == {"html.tags", "file.lines", "file"}
