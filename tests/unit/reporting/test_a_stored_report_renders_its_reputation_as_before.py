"""A report stored before reputation records renders byte for byte as it did.

The four stored benchmark runs carry no ``reputation`` records (the field is
absent from their JSON), so their reputation line is read by the legacy
reading of their section rows (``core.legacy_reputation``). Their Markdown,
their HTML and their STIX bundle (ids and timestamps normalised) are the
digests ``origin/dev`` 2c2522b2 renders. Skipped where the stored runs are not
on the machine.
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from malspark.reporting.models import MalwareReport
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import (
    _benchmark,
    stored_ledger_ids,
)

# ``(markdown, html with the nonce "fixed", normalised STIX)`` as dev 2c2522b2 renders them.
# The Markdown and HTML were re-pinned when a sample's, a tool's or a finding's
# text came to print escaped (F7); the STIX did not change.
# Re-pinned when every IOC-table row came to carry a publish answer and the
# export to name the sample by its identity digests (T-344, T-345): a dropped file's
# digest row the record names no process for now prints its refusal, so does
# a command line, the sample's indicator adds its SHA-1 and MD5, its imphash
# is an anomalous-activity indicator of its own, and an indicator's reason is
# read from the rebuilt table.
# The Markdown and HTML re-pinned when §10.2's introduction came to say each
# draft rule's body is printed as written (T-357): that one line is the only
# change; the STIX did not change.
# The STIX re-pinned when the export's own malware object came to carry the
# types the published category names after the category as written (T-337):
# ``loader`` gains ``downloader``. run4's Markdown and HTML re-pinned with it:
# its eight key findings wrote their citations into the sentence, and each is
# no longer printed a second time after it; nothing else changed.
# The Markdown and HTML re-pinned when Appendix A came to draw held code whole
# as listings and to say where a cut value is whole (T-384): only Appendix A and
# Appendix D changed; the STIX did not change.
# The Markdown and HTML re-pinned when the host identifier table came to mark
# each row the IOC table publishes and its footer to say the table publishes
# nothing itself (T-386); the STIX did not change.
# Re-pinned when no table cell of the body came to be cut (T-399) and every
# indicator to indicate the malware object (T-402): the only Markdown and HTML
# changes are body cells that ended in … printed whole, the methodology's
# sentence about cut values and the HTML print stylesheet's fixed table layout;
# the STIX gains one platform ``indicates`` edge per indicator related to no
# malware object (the similarity digests aside), each named by the report
# object, and nothing else.
# Re-pinned when a decoded text the pack spells with a closing ``\x5c`` came to
# print as the text (T-493): run4, run5 and run7 print ``\Registry\Machine\``
# where they printed ``\Registry\Machine\x5c``, and nothing else changed (the STIX
# did not change).
# local8 re-pinned when the commands table came to list only what descends from a
# process running the sample (T-494): explorer.exe under sihost.exe leaves the
# table, which has no row left and is not printed; nothing else changed (nor the STIX).
# The STIX re-pinned when a process the sample's lineage rule leaves out of its
# tree came to say so (T-511): each desktop process carries
# ``x_malspark_sample_process_tree: false`` (run4 six: svchost.exe and
# SecurityHealthHost.exe, each in the three readings the stored tree lists;
# run5 and run7 one; local8 five), and nothing else changed; the Markdown and
# HTML did not change. The readings of a pid of the sample's tree that record
# no lineage of their own (run4's pid 83 and 89 rows) carry nothing.
# Re-pinned when the product took its new name (T-576): the HTML's generator
# line, and the export's producer name and ``x_malspark_*`` properties; with
# the previous name each digest is the one pinned before, and the Markdown did
# not change.
# The STIX re-pinned when the export came to carry the report's TLP level
# (T-621): the level's marking definition, and ``object_marking_refs`` naming
# it on every domain object and relationship; the Markdown and HTML did not
# change.
# Re-pinned when the debate's last mean claim confidence came to be printed
# under its own label (T-662): that one line of the run summary appendix is the
# only change in run5, run7 and local8's Markdown and HTML; run4 carries no debate
# figure and the STIX did not change.
# Re-pinned when the report model's host identifier table came to print the
# publish rule's answer for each row in a Published column, its footer saying
# so: that table's rows and footer are the only change in each run.
# The Markdown and HTML re-pinned when every surface came to print a technique's
# evidence as one set (T-597): the ATT&CK table's Evidence cells are the only
# change. A rule's entry the stored mapping does not list is named "rule
# matches", and a mapping that stores its sources (run5, run7) lists
# the entries among them.
# The STIX is rendered with the stored ledger's ids, as the report node renders
# it, and re-pinned for each technique's evidence on its ``uses`` edge (T-597).
# Against dev 74618ab38 rendering with the same ids and the evidence it read
# from the ledger, only ``x_malspark_evidence_refs`` and
# ``x_malspark_evidence_note`` on the ``uses`` edges differ: an edge carries
# the entries among the sources its stored mapping lists (run5 eleven edges,
# run7 twenty-three, run4 one, local8 none), and an asserting tool's entry
# the stored mapping does not list is not on the edge (run7 T1036.005 and
# T1218.011, run5 and run4 T1027 and T1218.011, local8 T1027, T1027.005 and
# T1218.011). A stored mapping records no set, so no edge carries a note.
# run5's Markdown and HTML re-pinned when a count of trimmed ledger entries came
# to take the verb its number takes (T-749): "1 of 350 ledger entries was
# trimmed" is the only change; no other stored run prints a count of one.
# The STIX re-pinned when a process image wholly one path came to be exported as
# its base name in a ``directory`` object (T-763(d)): each such image file
# carries its base name and ``parent_directory_ref``, one directory per folder
# is added to the observed-data, and the process and report objects name the
# new ids; directory joined to name is each stored name, and nothing else
# changed. The Markdown and HTML did not change.
# The Markdown re-pinned when text of the sample, a tool, a sandbox or the
# operator came to be written by the inline rule and every list item and step
# by the block-start rule (T-735): characters Markdown reads gain a backslash
# in the evidence appendix and the run summary, and the HTML, read from it,
# did not change.
# A stored run's Markdown and HTML re-pinned when a tool's failure message came to be
# written by the inline rule (T-735): each backtick it holds is printed as a
# character in the tool failures list, the only change.
# A stored run's Markdown and HTML re-pinned when a platform sentence quoting a
# model's words, alone or with a value, came to be written whole as text
# (T-735): in the validation findings, retry and mediator lines each
# backtick, star and backslash the record holds is printed as a character and
# a pair no longer forms a code span, the only change.
# A stored run's Markdown re-pinned when a judge's reason in the ATT&CK table
# came to be written as text, cut and marked on its characters (T-735): each
# backtick and backslash of the reason is printed as a character, the only
# change.
# A stored run's Markdown re-pinned when a judge's reason in the run summary's
# corroboration table came to be written as text (T-735): each character Markdown
# reads in the reason gains a backslash in that table, the only change, and the
# HTML did not change.
# The Markdown and HTML re-pinned for the rules of T-780 and T-811: a platform sentence about
# every row it speaks of is a count of those rows where they hold an exception, and each cut a
# page makes to a technique's reason is counted in a line under the ATT&CK section, with where
# each reason stands whole (T-780); the context cell of a sandbox address the publish rule places
# in no tree states the sentence of the row's own publish answer (T-811). Those are the only
# changes; the STIX did not change.
# The Markdown and HTML re-pinned when a publish answer came to be given as its parts (T-782b):
# a public DNS resolver's §9 row states the resolver first and the sandbox's fact after it, a
# listed row's states the judge's test with its why and the listing after them, and a cell beside
# such a value states its refusing parts. Those are the only changes; the STIX did not change.
# local8's Markdown and HTML re-pinned when a mark of a value the run does not publish came to be
# labelled from the render's own reading of its sentence (T-782b): the mark states the refusing
# parts the render's IOC table gives the value. That is the only change. The STIX did not change.
# run4's and run5's Markdown and HTML re-pinned when a value the string sweep holds and nothing
# admitted came to be refused with the row it is from and what the rule's lookup found (T-782c):
# the one such path row, in the strings table and in §9's table, is the only change. The STIX
# did not change.
# The Markdown and HTML re-pinned when a host row no record of which the publish rule could
# place came to say what the rule found (T-782d): each such digest row in §9's table is the
# only change. The STIX did not change.
# The Markdown and HTML re-pinned when every clause of a strings refusal came to name its
# finding as the publish rule's and its row by what the row records (T-782c): the one such
# path row, in the strings table and in §9's table, is the only change. The STIX did not change.
# The Markdown and HTML re-pinned when a sandbox address row's refusal came to say what the
# publish rule read in the flow rows to it, under one subject for every network row (T-811):
# read from its stored file, each such row with no reading prints "the publish rule placed no
# flow to it inside the sample's process tree" and each disputed one "the publish rule found a
# flow to it made by …", wherever the row's answer or its context cell prints. Those are the
# only changes; the STIX did not change.
# local8's Markdown and HTML re-pinned when a disputed address row read from its
# stored file, with no reading of its flow rows, came to say the publish rule "counted flows to
# it as made by" its processes, with no count of flows and no word of the other flows to it
# (T-811): that row's answer and context cell are the only change; the STIX did not change.
# The STIX re-pinned when the indicator of the sample's similarity digests came to be described
# by the digests its pattern holds (T-785), and run7's Markdown and HTML when the line under an
# analyst's table the report reads no value of came to say so (T-780): the only changes.
# local8's Markdown and HTML re-pinned when a held sandbox report's rows came to be counted by
# the list each was read from (C49, C47): its two sandbox lines now count rows of the
# dropped-files list. Those are the only changes; the STIX did not change.
# The Markdown and HTML re-pinned when the ATT&CK table's note on `(rule match)` came to name
# the sources that table marks and to say "with no sandbox" only of the rules over the binary
# (T-845): the note is the only change; the STIX did not change.
STORED_RENDERS = {
    "run7": ("c3bb06a69a94e5db", "61b3e2d4aa59715c", "b15eda451166721a"),
    "run5": ("38196a8d18b426a7", "a3e4ed960ae63a31", "da124711a6423447"),
    "run4": ("502a231af6a028ec", "d83e0bbf3fb37551", "c98bd74e8825a72a"),
    "local8": ("7b0a7a7f136f3a81", "a15b3ffe20645d11", "5ef0ca19f5e5ec42"),
}

_UUID = re.compile(r"--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


@pytest.mark.parametrize("run", sorted(STORED_RENDERS))
def test_a_stored_run_renders_as_dev_rendered_it(run: str) -> None:
    from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer
    from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

    root = _benchmark()
    if root is None or not (root / run / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    data = json.loads((root / run / "report.json").read_text())
    assert "reputation" not in data
    report = MalwareReport.model_validate(data)
    assert report.reputation is None
    assert "reputation" not in json.loads(report.model_dump_json())

    markdown = MarkdownRenderer().render(report)
    html = HtmlRenderer().render(report, nonce="fixed")
    bundle = ExtendedSTIXRenderer().render(report, ledger_ids=stored_ledger_ids(run))
    stix = json.dumps(json.loads(bundle.model_dump_json()), indent=1, sort_keys=True)
    stix = _STAMP.sub("TS", _UUID.sub("--ID", stix))

    assert (_digest(markdown), _digest(html), _digest(stix)) == STORED_RENDERS[run]
