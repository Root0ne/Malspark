"""A long run of backslashes before a quote is written out in one pass.

The question an analyst asks reaches the pack's quoting, so a text made
of many backslashes must not cost time in the square of its length.
"""

from __future__ import annotations

from tests.linear_cost import assert_scales

from malspark.utils.written_forms import quoted_backslashes_written_out


def test_every_backslash_before_a_quote_is_written_out() -> None:
    assert quoted_backslashes_written_out('a\\\\"b') == 'a\\x5c\\x5c"b'
    assert quoted_backslashes_written_out('x\\"y\\z') == 'x\\x5c"y\\z'
    assert quoted_backslashes_written_out("no quote \\\\") == "no quote \\\\"


def test_a_long_run_with_no_quote_after_it_grows_linearly() -> None:
    # Eight times the run: linear is about 8x, a rescan from every backslash about 64x.
    # The run is split and joined in C, a few microseconds for the small one,
    # so each side is written out 5,000 times; grown instead, the copies of a
    # large run cost more per character than those of a small one.
    assert_scales(
        lambda n: '"' + "\\" * n,
        5_000,
        lambda text: [quoted_backslashes_written_out(text) for _ in range(5_000)],
        factor=8,
        limit=24,
        floor=0.01 / 24,
    )
