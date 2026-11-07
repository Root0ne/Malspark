"""Model prose in the raw Markdown: no protocol-relative target, no entity in a fence info."""

from __future__ import annotations

import re

import pytest

from malspark.reporting.renderers import markdown as md
from tests.linear_cost import TIME_RATIO_LIMIT, assert_ratio


@pytest.mark.parametrize(
    "prose",
    [
        "[x](//evil)",
        "[x](//2130706433/)",
        "![i](//intranet/p.png)",
        "[x](<//evil>)",
        "[x]: //evil",
        "[x](\\\\evil\\share)",
        "[x](\n//evil)",
        "[x](\r\n//evil)",
        "[x](<\n//evil>)",
        "[x]\n\n[x]:\n//evil",
        "[x]:\r\n  //evil",
        "[x](/\t/evil)",
        "[x](\t//evil)",
        "[x](/\n/evil)",
        '<a href="//evil">x</a>',
        "<a HREF = '//evil'>x</a>",
        '<img src="//2130706433/p">',
        '<form action="//evil"><button formaction=//evil>',
        '<video poster="//evil"><object data="\\\\evil"><td background=" //evil">',
        '<img srcset="//evil 2x" src=\n//evil>',
        '<a ping="//evil">x</a>',
        '<blockquote cite="//evil">x</blockquote>',
        '<img longdesc="//evil" lowsrc=//evil dynsrc="//evil">',
        '<link icon="//evil"><html manifest="//evil"><applet codebase="//evil">',
        "> [x]: //evil",
        "- [x]: //evil",
        "1. [x]: //evil",
        "2) [x]: //evil",
        "> - [x]: //evil",
        "  > 1. > * [x]:\t//evil",
    ],
)
def test_a_protocol_relative_target_is_no_two_slashes(prose: str) -> None:
    written = md._defanged_text(prose)

    assert not re.search(r"[/\\\\][\t\r\n]*[/\\\\]", re.sub(r"https?://", "", written)), written
    assert "[/]" in written or "[\\]" in written
    # Written once more, it is the same text.
    assert md._defanged_text(written) == written


def test_prose_that_is_no_link_target_keeps_its_slashes() -> None:
    prose = "It wrote //tmp//x and a//b, and read [the note](#notes)."

    assert md._defanged_text(prose) == prose


def test_an_entity_in_a_fence_info_string_is_escaped_and_the_fence_is_not() -> None:
    text = "```&lt;x&gt;\nbody &amp; more\n```\n&amp; outside\n"

    out = md._escaped_references(text)

    assert out.splitlines()[0] == "```\\&lt;x\\&gt;"
    assert out.splitlines()[1] == "body &amp; more"
    assert out.splitlines()[3] == "\\&amp; outside"


def test_a_fence_with_a_plain_info_string_is_left_as_it_is() -> None:
    text = "```yara\nrule a { }\n```\n&amp;\n"

    assert md._escaped_references(text).splitlines()[0] == "```yara"


def test_code_that_looks_like_a_reference_definition_is_untouched() -> None:
    prose = "switch (x) { case a[0]: //note\n  case b[1]: //other }"

    assert md._defanged_text(prose) == prose


def test_a_name_that_only_ends_in_an_attribute_word_is_untouched() -> None:
    prose = "metadata=//x and a data = b"

    assert md._defanged_text(prose) == prose


def _assert_linear(small: str, large: str, what: str) -> None:
    """Four times the input is read in less than eight times the CPU time of the process."""
    assert_ratio(
        lambda: md._defanged_text(small),
        lambda: md._defanged_text(large),
        TIME_RATIO_LIMIT,
        what=what,
        whole_process=True,
    )


@pytest.mark.parametrize(
    "opener",
    ["href=", "src='", 'src = "', "](", "](<", "[x]:", "action=<", "data ="],
)
def test_a_hostile_run_of_white_space_costs_in_proportion(opener: str) -> None:
    def hostile(size: int) -> str:
        # The run ends where no slash follows, so every way of splitting it fails.
        return (opener + " \t\r\n" * (size // 4) + "x") * 3

    _assert_linear(hostile(50_000), hostile(200_000), f"200,000 characters after {opener!r}")


_CONTAINERS = ["> ", "- ", "+ ", "* ", "1. ", "12) ", "> - ", "- > ", "> 1. > * ", "   > "]


@pytest.mark.parametrize("container", _CONTAINERS)
def test_a_reference_definition_in_a_container_is_a_link_only_unmarked(container: str) -> None:
    from markdown_it import MarkdownIt

    def hrefs(text: str) -> list[str]:
        html = MarkdownIt("commonmark").render(text)
        return re.findall(r'href="([^"]*)"', html)

    raw = f"{container}[x]: //evil\n\n[x]\n"
    marked = md._defanged_text(raw)

    # A CommonMark parser makes the raw text a protocol-relative link ...
    assert hrefs(raw) == ["//evil"], container
    # ... and the marked text is not one.
    assert not [h for h in hrefs(marked) if re.match(r"[/\\]", h)], marked
    assert "[/]" in marked


def test_code_that_follows_a_container_word_is_untouched() -> None:
    prose = "> case a[0]: //note\n- if b[1]: //other"

    assert md._defanged_text(prose) == prose


def test_a_line_of_container_prefixes_costs_in_proportion() -> None:
    def hostile(size: int) -> str:
        return ("> " * size + "x\n") * 2

    _assert_linear(hostile(25_000), hostile(100_000), "100,000 container prefixes")


@pytest.mark.parametrize("lead", ["\x01", "\x00", "\x1f", " \x0b", "\x0c\x0e"])
def test_c0_controls_before_an_attribute_value_s_slashes_are_no_way_round(lead: str) -> None:
    """A URL parser drops leading C0 controls, so they cannot hide the two slashes."""
    for opener in ('<a href="', "<img src='", "<a href="):
        out = md._defanged_text(f"{opener}{lead}//evil/x")
        assert f"{lead}//evil" not in out


def test_c0_controls_before_an_attribute_value_cost_a_linear_read() -> None:
    small, large = 'href="' + "\x01" * 50_000, 'href="' + "\x01" * 200_000
    assert_ratio(
        lambda: md._defanged_text(small),
        lambda: md._defanged_text(large),
        TIME_RATIO_LIMIT,
        what="200,000 controls",
        floor=1e-3,
        whole_process=True,
    )
