"""The analyst report's appendix prints an analyst's statement in the sample's terms.

An analyst writes a statement for the debate: it numbers the claims it leans
on ("(claim 72)", "in CLAIM 43"), labels a claim it checked again ("Verdict:
CONFIRMED.", "CONFIRMED, …") and may name an analyst. The appendix prints the
statement without those markers where the sentence stands without them,
leaves out a sentence that does not and says how many it left out; the bundle
prints every statement whole. Only claim numbers, the outcome words and the
run's analysts' names are markers: the sample's own words never are, and a
statement adds a value only by what it prints (T-566).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import partial

import pytest

from malspark.reporting.models import (
    CapabilityCell,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.analyst import _Analyst, _Shield
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from tests.linear_cost import assert_scales, repeated

# The haiku13 shapes, the values changed.
_PARENTHESISED = (
    "static: [Static] Routine 0x3808 deletes the installed copy. It builds the install path "
    'with 0x30d0 (the folder "Custom_upd" and the volume-derived "Upd_%x" name, claim 72) '
    "and 0x3250. It renames the running image to the stream (0x3a24, claim 43), then "
    "deletes the copy through NtDeleteFile."
)
_LABELLED = (
    "static: [Static] Process listing: 0x1c38 lists processes with CreateToolhelp32Snapshot "
    'and writes "&plist=[". Verdict: CONFIRMED. Child processes are gathered through '
    "0x14d8."
)
_OWN_BRACKET = (
    "static: The reply is decrypted and split into tokens by 0x541c, which is carried over "
    "the HTTP session (claim 11). Tokens: CLEARURL calls 0xce20."
)
_EMBEDDED = (
    "static: The beacon report carries the process list (PLIST_FIELD). The report travels "
    "over the HTTP channel in claim 5, and no other channel is asserted, so T1048 is not "
    "used. The host-reading routines are in CLAIM 43."
)
# The haiku10 shapes: a claim number closing a phrase, a bare outcome label.
_CLOSING = (
    "static: The reply is base64-decoded by 0x6370 and parsed over the HTTP(S) channel of CLAIM 26."
)
_BARE_LABELS = (
    "static: CONFIRMED, command dispatch in 0x3cf4 selects the handler. CONFIRMED in "
    "structure. VERDICT: refined. 0x7777 parses VALUE_Y."
)
_NAMED = "static_r2: The routine 0x7b98 reads the AppDataDir name, as static_r2 found."


def _report(*statements: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.dll"),
        verdict="Malware",
        static=StaticAnalysis(
            api_technique_hits=[
                {
                    "technique_id": "T1057",
                    "matched_apis": ["Process32FirstW"],
                    "resolved_apis": ["Process32FirstW"],
                }
            ]
        ),
        capability_matrix=[
            CapabilityCell(
                tactic="TA0007",
                tactic_name="Discovery",
                technique_id="T1057",
                technique_name="Process Discovery",
                statements=list(statements),
            )
        ],
        run_summary={"profile": {"analysts": ["static_r2", "dynamic"]}},
    )


def _appendix(report: MalwareReport) -> str:
    markdown = MarkdownRenderer(layout=ANALYST).render(report)
    if "### Analyst statements that add detail" not in markdown:
        return ""
    return markdown.split("### Analyst statements that add detail", 1)[1].split("\n### ", 1)[0]


def test_a_marker_that_stands_apart_is_taken_out_and_the_sentence_kept() -> None:
    printed = _appendix(_report(_PARENTHESISED, _LABELLED, _OWN_BRACKET, _CLOSING))

    assert '"Upd_%x" name) and 0x3250.' in printed
    assert "to the stream (0x3a24), then deletes" in printed
    assert 'writes "&plist=[". Child processes' in printed
    assert "over the HTTP session. Tokens: CLEARURL" in printed
    assert "base64-decoded by 0x6370 and parsed over the HTTP(S) channel." in printed
    for marker in ("claim", "CLAIM", "Verdict", "CONFIRMED"):
        assert marker not in printed
    assert "left out" not in printed


def test_an_outcome_label_goes_and_what_it_labels_stays() -> None:
    printed = _appendix(_report(_BARE_LABELS))

    assert "Command dispatch in 0x3cf4 selects the handler. 0x7777 parses VALUE_Y." in printed
    for marker in ("CONFIRMED", "refined", "VERDICT", "structure"):
        assert marker not in printed
    assert "1 sentence of them was left out; the bundle prints every statement whole." in printed


def test_a_sentence_that_does_not_stand_without_it_is_left_out_and_counted() -> None:
    printed = _appendix(_report(_EMBEDDED, _NAMED))

    assert "carries the process list (PLIST_FIELD)." in printed
    assert "over the HTTP channel, and no other channel is asserted, so T1048" in printed
    assert "host-reading" not in printed and "CLAIM" not in printed
    assert "static_r2 found" not in printed
    assert "2 sentences of them were left out; the bundle prints every statement whole." in (
        printed
    )


def test_a_statement_left_out_whole_is_still_counted() -> None:
    printed = _appendix(_report("static: The routine 0x9999 is in CLAIM 43."))

    assert "0x9999" not in printed
    assert "1 sentence of them was left out; the bundle prints every statement whole." in printed


def test_a_label_takes_no_word_of_the_sample_with_it() -> None:
    printed = _appendix(
        _report(
            "static: 0x1c38 lists processes. Verdict: CONFIRMED API hashing resolves NtQsi_X.",
            "static: Verdict: REFINED HTTP POST beacon to ZZ_HOST_VALUE.",
            'static: The sample logs "Verdict: MALICIOUS" through LOG_FN_X.',
        )
    )

    assert "0x1c38 lists processes. API hashing resolves NtQsi_X." in printed
    assert "HTTP POST beacon to ZZ_HOST_VALUE." in printed
    assert 'The sample logs "Verdict: MALICIOUS" through LOG_FN_X.' in printed
    assert "left out" not in printed


def test_a_claim_of_the_debate_is_known_by_the_words_around_it() -> None:
    # The haiku7, haiku9, haiku11 and run5 shapes, the values changed.
    printed = _appendix(
        _report(
            "static: The window is hidden (NO_WINDOW_X). The fetch is the claim 17 path.",
            "static: 0x3a24 sets INFO_CLASS_X. The point in peer claim 31 is superseded.",
            "static: 0x6e04 runs PAYLOAD_X. T1218 is not asserted here; Claim 12 covers it.",
            "static: CORRECTION of my round-0 claims 20 and 51. 0x6f48 writes FILE_X.",
            "static: [Command dispatch — CONFIRMED] 0x3cf4 selects HANDLER_X.",
        )
    )

    for kept in (
        "The window is hidden (NO_WINDOW_X).",
        "0x3a24 sets INFO_CLASS_X.",
        "0x6e04 runs PAYLOAD_X.",
        "0x6f48 writes FILE_X.",
        "[Command dispatch] 0x3cf4 selects HANDLER_X.",
    ):
        assert kept in printed
    for marker in ("claim", "Claim", "CONFIRMED", "CORRECTION"):
        assert marker not in printed
    assert "4 sentences of them were left out" in printed


@pytest.mark.parametrize(
    "statement",
    [
        "static: The ransom note at 0x5555 claims 2 victims via NOTE_X.",
        "static: The stealer copies the Ledger Live data and the WALLET_DIR_X folder at 0x4444.",
        "static: The implant answers tool calls from its MCP_CLIENT_X at 0x8888.",
        "static: The earlier analysis by the vendor names DROPPER_X at 0x9999.",
        'static: The panel string "Claim 7 payload" is decoded at 0xa002 (CLAIM_Y).',
        "static: The license check at 0xa004 cites PATENT_X, see claim 2 in the patent.",
        "static: REFUTED: access denied is printed by 0xa005 via PRINT_X.",
        'static: The sample prints "REFUTED: access denied" via 0xa006 PRINT_Y.',
        "static: CONFIRMED orders are exfiltrated by 0xa007 ORDERS_X.",
        "static: The tool writes a [CONFIRMED] tag via 0xa008 TAG_X.",
        "static: The ransom note at 0xa009 claims 4 and 8 GB were taken (NOTE_Y).",
        "static: Claim 1 BTC is the demand at 0xa00a WALLET_Y.",
        # A claim number inside a phrase that goes on is no clause to take out.
        "static: The dropper writes the file named in claims 3 to 5 of the config, at 0xa00b "
        "CFG_X.",
        "static: The handler reads field of claim 9 from 0xa00c (FIELD_X).",
    ],
)
def test_the_sample_s_own_words_are_never_markers(statement: str) -> None:
    printed = _appendix(_report(statement))

    assert statement.removeprefix("static: ") in printed
    assert "left out" not in printed


def test_a_claim_number_is_no_value_that_earns_a_statement_its_place() -> None:
    # Every value but the label is printed already; the label adds none.
    report = _report(_OWN_BRACKET, "static: 0x541c splits the reply. Verdict: REFINED.")

    printed = _appendix(report)

    assert "0x541c splits the reply" not in printed


def test_a_statement_adds_a_value_only_by_what_it_prints() -> None:
    # Its only new value stands in the sentence left out: the rest is printed once.
    printed = _appendix(
        _report(
            "static: 0x1c38 lists processes.",
            "static: 0x1c38 lists processes. The key KEY_ONLY_HERE is in claim 5.",
        )
    )

    assert printed.count("0x1c38 lists processes.") == 1
    assert "KEY_ONLY_HERE" not in printed
    assert "1 sentence of them was left out" in printed


def test_the_bundle_prints_every_statement_whole() -> None:
    report = _report(_PARENTHESISED, _LABELLED, _OWN_BRACKET, _EMBEDDED, _NAMED, _BARE_LABELS)

    bundle = MarkdownRenderer(layout=BUNDLE).render(report)

    for text in (
        "claim 72",
        "Verdict: CONFIRMED.",
        "(claim 11)",
        "in claim 5",
        "in CLAIM 43",
        "static_r2 found",
        "CONFIRMED in structure.",
    ):
        assert text in bundle


def test_an_analyst_s_name_is_read_as_written_and_whole() -> None:
    report = _report("win32: Win32 API calls at 0xa00d resolve GetProcAddress_X.")
    report.run_summary = {"profile": {"analysts": ["win32", "static_r2"]}}

    printed = _appendix(report)

    assert "Win32 API calls at 0xa00d resolve GetProcAddress_X." in printed
    assert "left out" not in printed


def test_a_claim_the_debate_owns_inside_a_phrase_is_left_out_and_counted() -> None:
    # Telling a noun that goes on from a verb would take reading the grammar: the
    # sentence is left out, counted, and printed whole in the bundle.
    printed = _appendix(
        _report(
            "static: The beacon follows the claim 3 of the C2 protocol at 0xa001 (CLAIM_X).",
            "static: Claim 7 payload is fetched by 0xa003 (CLAIM_Z).",
        )
    )

    assert "0xa001" not in printed and "0xa003" not in printed
    assert "2 sentences of them were left out; the bundle prints every statement whole." in (
        printed
    )


def test_a_lone_quote_shields_no_marker() -> None:
    # An inch mark opens no quotation: the claim number after it is the analyst's.
    printed = _appendix(
        _report(
            'static: The 5" drive image is read by 0xa00e (claim 4) and hashed (DRIVE_X).',
            'static: 0xa010 trims 3" of padding (claim 6), then logs "done" via LOG_Z.',
        )
    )

    assert 'The 5" drive image is read by 0xa00e and hashed (DRIVE_X).' in printed
    assert '0xa010 trims 3" of padding, then logs "done" via LOG_Z.' in printed
    assert "claim" not in printed
    assert "left out" not in printed


def test_an_analyst_s_name_with_a_file_extension_is_a_file() -> None:
    report = _report("static: The loader maps static_r2.dll at 0xa00f via LOAD_X.")

    printed = _appendix(report)

    assert "The loader maps static_r2.dll at 0xa00f via LOAD_X." in printed
    assert "left out" not in printed


@pytest.mark.parametrize("lead", ["see", "per", "in", "cf.", "See", "Cf."])
def test_a_bracketed_pointer_to_a_claim_goes_and_the_sentence_stays(lead: str) -> None:
    printed = _appendix(_report(f"static: 0xa011 decrypts the config ({lead} claim 8) with KEY_X."))

    assert "0xa011 decrypts the config with KEY_X." in printed
    assert "claim" not in printed
    assert "left out" not in printed


@pytest.mark.parametrize(
    "statement",
    [
        'static: 0xa001 compares the input with L"see claim 4" via CMP_X.',
        'static: 0xa001 sends b"claim 4" to the C2 via SEND_X.',
    ],
)
def test_a_prefixed_literal_is_a_quoted_string(statement: str) -> None:
    printed = _appendix(_report(statement))

    assert statement.removeprefix("static: ") in printed
    assert "left out" not in printed


def test_an_analyst_s_name_closing_a_sentence_or_in_brackets_is_still_the_name() -> None:
    printed = _appendix(
        _report(
            "static: The loader maps LOADER_Y at 0xa013. 0xa014 reads the table, as static_r2.",
            "static: 0xa015 writes FILE_Q (static_r2).",
        )
    )

    assert "The loader maps LOADER_Y at 0xa013." in printed
    assert "0xa014" not in printed
    assert "0xa015 writes FILE_Q." in printed
    assert "static_r2" not in printed
    assert "1 sentence of them was left out; the bundle prints every statement whole." in printed


@pytest.mark.parametrize(
    "statement",
    [
        "static: 0xa016 reads the table (in claim-free text) via TABLE_X.",
        "static: 0xa017 parses the reply (in 3 claims) via REPLY_X.",
        "static: 0xa018 reserves the buffer (see claims 4 GB) via ALLOC_X.",
    ],
)
def test_a_bracket_that_points_to_no_claim_is_the_sample_s(statement: str) -> None:
    printed = _appendix(_report(statement))

    assert statement.removeprefix("static: ") in printed
    assert "left out" not in printed


@pytest.mark.parametrize(
    "statement",
    [
        'static: 0xa001 compares the input with L"static_r2" via CMP_X.',
        "static: 0xa019 logs `static_r2 ready` through LOG_X.",
        "static: 0xa01a prints “static_r2” via PRINT_Z.",
        'static: 0xa01b writes "(static_r2)" to the log via LOG_Y.',
    ],
)
def test_an_analyst_s_name_inside_a_quoted_string_is_the_sample_s(statement: str) -> None:
    printed = _appendix(_report(statement))

    assert statement.removeprefix("static: ") in printed
    assert "left out" not in printed


def test_an_analyst_s_name_in_brackets_goes_with_the_stop_it_holds() -> None:
    printed = _appendix(
        _report(
            "static: 0xa01c writes FILE_R (static_r2.) The table is read by 0xa01d.",
            "static: 0xa01e reads KEY_R (static_r2;) then decrypts BLOB_R.",
            "static: 0xa022 maps VIEW_R (static_r2.).",
        )
    )

    assert "0xa01c writes FILE_R. The table is read by 0xa01d." in printed
    assert "0xa01e reads KEY_R; then decrypts BLOB_R." in printed
    assert "0xa022 maps VIEW_R." in printed and "VIEW_R.." not in printed
    assert "static_r2" not in printed
    assert "left out" not in printed


@pytest.mark.parametrize(
    ("statement", "kept"),
    [
        # A stop that ends no sentence there goes with the bracket.
        (
            "static: 0xa023 writes FILE_S (static_r2.) next to 0xa024.",
            "0xa023 writes FILE_S next to 0xa024.",
        ),
        (
            "static: 0xa025 writes FILE_T (static_r2?) the table.",
            "0xa025 writes FILE_T the table.",
        ),
        # Nor does one at the sentence's head.
        ("static: (static_r2.) 0xa026 writes FILE_U.", "0xa026 writes FILE_U."),
        (
            "static: 0xa027 writes FILE_V (static_r2!) Next 0xa028 reads it.",
            "0xa027 writes FILE_V! Next 0xa028 reads it.",
        ),
    ],
)
def test_a_bracket_s_stop_stays_only_where_it_ends_the_sentence(statement: str, kept: str) -> None:
    printed = _appendix(_report(statement))

    assert kept in printed
    assert f". {kept}" not in printed and f".. {kept}" not in printed
    assert "static_r2" not in printed
    assert "left out" not in printed


@pytest.mark.parametrize(
    "statement",
    [
        'static: 0xa01f compares the reply with id2"claim 4" via CMP_Y.',
        'static: 0xa020 decodes u8"(claim 4)" via DECODE_X.',
        'static: 0xa029 compares the input with id2"static_r2" via CMP_Z.',
        'static: 0xa02a cuts a model3" plate (claim 6) and pads 5" more via CUT_X.',
    ],
)
def test_a_string_only_one_reading_of_its_quotes_makes_leaves_the_sentence_out(
    statement: str,
) -> None:
    # A quote after a digit is an inch mark or closes a literal's prefix (id2"…");
    # where the readings disagree on a marker, the sentence is neither cut nor
    # printed: it is left out, counted, and printed whole in the bundle.
    printed = _appendix(_report(statement))

    assert statement.split()[1] not in printed
    assert "1 sentence of them was left out; the bundle prints every statement whole." in printed


@pytest.mark.parametrize(
    ("statement", "kept"),
    [
        (
            'static: 0xa02b cuts a model3" plate (claim 6) and labels it "x" via CUT_Y.',
            '0xa02b cuts a model3" plate and labels it "x" via CUT_Y.',
        ),
        (
            'static: 0xa02c cuts a model3" plate (static_r2) and labels it "x" via CUT_Z.',
            '0xa02c cuts a model3" plate and labels it "x" via CUT_Z.',
        ),
        (
            'static: 0xa02d reads a size2" disk (see claim 6) per "spec" via DISK_X.',
            '0xa02d reads a size2" disk per "spec" via DISK_X.',
        ),
        (
            'static: 0xa02e reads a M3" bolt (claim 6) and "x" via BOLT_X.',
            '0xa02e reads a M3" bolt and "x" via BOLT_X.',
        ),
        (
            'static: 0xa02f reads a model3" thick plate "claim 4" (claim 6) via PLATE_X.',
            '0xa02f reads a model3" thick plate "claim 4" via PLATE_X.',
        ),
    ],
)
def test_a_quote_the_plain_reading_pairs_closes_no_literal_s_prefix(
    statement: str, kept: str
) -> None:
    # The quote after model3 is an inch mark: the next quote opens the string.
    printed = _appendix(_report(statement))

    assert kept in printed
    assert "(claim 6)" not in printed and "static_r2" not in printed
    assert "left out" not in printed


def test_a_name_inside_a_string_only_one_reading_makes_is_left_out_and_counted() -> None:
    # The name stands only in the string a prefix's quotes open (id2"…"): read as
    # the sample's under one reading and as the analyst's under the other.
    printed = _appendix(_report('static: 0xa030 compares id2"static_r2 found" via X_Q.'))

    assert "static_r2" not in printed and "0xa030" not in printed
    assert "1 sentence of them was left out; the bundle prints every statement whole." in printed


def test_a_quote_closing_an_inch_mark_opens_no_literal() -> None:
    # The x3 between two inch marks is no prefix: the quoted string after it shields.
    printed = _appendix(
        _report('static: 0xa021 prints a 5"x3" label "claim 4" (claim 6) via LABEL_X.')
    )

    assert '0xa021 prints a 5"x3" label "claim 4" via LABEL_X.' in printed
    assert "(claim 6)" not in printed
    assert "left out" not in printed


def _reader() -> tuple[_Analyst, re.Pattern[str]]:
    """An analyst report's reader of markers and the run's analysts' names as it reads them."""
    analyst = object.__new__(_Analyst)
    analyst.report = _report()
    named = analyst._named()
    assert named is not None
    return analyst, named


def test_markers_are_read_in_linear_time() -> None:
    # Many names and claim numbers, quoted and not, in one long sentence: each
    # quoted string is found once per pass, not once per marker.
    analyst, named = _reader()
    chunk = '0xa1 w "static_r2" and "claim 4" (static_r2) (claim 5) id2"x" 5" more '
    assert_scales(
        lambda size: chunk * size + "end.",
        400,
        lambda text: analyst._without_markers(text, named),
    )


def test_quoted_strings_are_found_in_linear_time() -> None:
    # Long identifiers no quote follows, inch marks and literals with no closing
    # quote: each is read once, whatever its length.
    assert_scales(
        lambda size: ("word9" * 64 + ' 5"x ') * size + 'id2"open ' * size,
        2000,
        _Shield.of,
    )


@pytest.mark.parametrize(
    "shape",
    [
        # A run of spaces before a claim number, a bracket and an outcome: each
        # run is entered at its first space, not at every one (T-590).
        lambda size: "0xa1" + " " * size + "claim 4 x.",
        lambda size: "0xa1" + " " * size + "(x) and" + " " * size + ", x) via X.",
        lambda size: "0xa1" + " " * size + "[x]" + " " * size + "x.",
        # ... a run of dashes before one, and a word as long.
        lambda size: "[0xa1" + "-" * size + "x] via X.",
        lambda size: "0xa1 " + "w" * size + " in claim 4 x.",
    ],
    ids=["spaces-claim", "spaces-bracket", "spaces-outcome", "dashes", "long-word"],
)
def test_a_long_run_of_one_character_is_read_in_linear_time(shape: Callable[[int], str]) -> None:
    analyst, named = _reader()
    assert_scales(
        lambda size: repeated(partial(analyst._without_markers, shape(size), named), 24),
        1000,
    )
