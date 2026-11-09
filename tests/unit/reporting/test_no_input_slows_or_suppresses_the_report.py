"""No input makes the report slow superlinearly or drop a section.

Each adversarial shape, about 200 KB of it, goes into a report's prose and into
an indicator's value and context in §9: long runs of the characters a forge
starts a link after, a hundred thousand dots, ``www.`` repeated, fifty thousand
reference links, thousands of distinct hosts and addresses, and a value
holding every private-use character. The Markdown renders within a bound in
seconds, keeps §1 and §9, and substitutes no section, and the defanger reads
the whole input, uncut, within a bound of its own.
"""

from __future__ import annotations

import re

import pytest

from malspark.reporting.models import (
    ConsolidatedIOC,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.renderers.markdown import MarkdownRenderer, _defanged_text
from tests.linear_cost import assert_under

SIZE = 200_000
SHA = "a" * 64
SHAPES = {
    "link starts": "_*~/(" * (SIZE // 5) + "www.evil.com",
    "dots": "." * (SIZE // 2) + "evil.com" + "." * (SIZE // 2),
    "dotted labels": "a." * (SIZE // 2) + "com",
    "www repeated": "www." * (SIZE // 4) + "evil.com",
    "reference links": " ".join(
        f"https://www.virustotal.com/gui/file/{index:064x}" for index in range(50_000)
    ),
    "distinct hosts": " ".join(f"h{index}.example.com" for index in range(SIZE // 16)),
    "distinct addresses": " ".join(
        f"10.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}"
        for index in range(SIZE // 12)
    ),
    "mailbox runs": "a." * (SIZE // 4) + "a@" * (SIZE // 4),
    "nested schemes": "http://a.b*" * (SIZE // 11),
    "link syntax": "<irc:a](ws:b]: x:" * (SIZE // 17),
    "scheme characters": "a.b-c+" * (SIZE // 6) + "://evil.com",
    "private use": "".join(chr(cp) for cp in range(0xE000, 0xF900)) * 4,
}


def _report(text: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA)),
        verdict="Malware",
        executive_summary=text,
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(title="Command and control", body=text)
        ),
        consolidated_iocs=[
            ConsolidatedIOC(
                type="Domain",
                kind="domain",
                value=text,
                source="strings",
                context=text,
                description="",
                published=None,
                is_network=True,
            )
        ],
    )


@pytest.mark.parametrize("shape", list(SHAPES))
def test_an_adversarial_input_renders_quickly_and_keeps_every_section(shape: str) -> None:
    rendered: list[str] = []
    assert_under(
        lambda: rendered.append(MarkdownRenderer().render(_report(SHAPES[shape]))), 10, what=shape
    )
    markdown = rendered[0]

    assert "rendering failed" not in markdown
    assert re.search(r"^## 1\. ", markdown, re.M)
    assert re.search(r"^## 9\. ", markdown, re.M)


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_defanger_reads_a_whole_adversarial_input_in_seconds(shape: str) -> None:
    assert_under(lambda: _defanged_text(SHAPES[shape]), 50, what=shape)
