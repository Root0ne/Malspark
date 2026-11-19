"""A value as a code listing stored as JSON writes it in a C string literal: two escape levels.

The C literal doubles each backslash and escapes each double quote, and
nothing else; the JSON that carries the listing escapes that literal once
more. Only the forms the value's other spellings do not already give are
returned, none for a value without a backslash or a quote, and the other
spellings are what they were.
"""

from __future__ import annotations

from malspark.utils.written_forms import code_literal, code_literal_forms, written_forms


class TestTheLiteral:
    def test_changes_backslashes_and_quotes_only(self) -> None:
        assert code_literal('Local\\a "b"\n\tc\x01') == 'Local\\\\a \\"b\\"\n\tc\x01'

    def test_is_carried_as_a_json_string(self) -> None:
        assert code_literal_forms("A\\B") == ("A\\\\\\\\B",)
        assert code_literal_forms('say "hi"') == ('say \\\\\\"hi\\\\\\"',)

    def test_with_and_without_non_ascii_escaped(self) -> None:
        assert code_literal_forms("Café\\x") == ("Café\\\\\\\\x", "Caf\\u00e9\\\\\\\\x")

    def test_none_for_a_value_without_a_backslash_or_a_quote(self) -> None:
        assert code_literal_forms("plain value") == ()
        assert code_literal_forms("") == ()

    def test_never_a_form_the_other_spellings_give(self) -> None:
        for value in ("A\\B", 'say "hi"', "Café\\x", "\\\\.\\pipe\\x"):
            assert not set(code_literal_forms(value)) & set(written_forms(value))


class TestTheOtherSpellingsAreUnchanged:
    def test_a_backslash_value(self) -> None:
        assert written_forms("A\\B") == ("A\\B", "A\\\\B")
