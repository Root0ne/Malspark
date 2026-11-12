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
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

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
# Re-pinned when the report model's host identifier table came to print the
# publish rule's answer for each row in a Published column, its footer saying
# so: that table's rows and footer are the only change in each run.
STORED_RENDERS = {
    "run7": ("09c7b588718f2532", "e633209d5cdd24d9", "6f5f4f1b2ed8ea58"),
    "run5": ("35c50111c95b0847", "27ed8d4cf052ec8a", "b7c19ebb4cb31921"),
    "run4": ("95cc2744a52ef0af", "4669cfe8d40d01f1", "07a486002a8891ac"),
    "local8": ("59bfc74f81199d4e", "cfbded2298ab38bd", "86c2fdd68be6dde0"),
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
    bundle = ExtendedSTIXRenderer().render(report)
    stix = json.dumps(json.loads(bundle.model_dump_json()), indent=1, sort_keys=True)
    stix = _STAMP.sub("TS", _UUID.sub("--ID", stix))

    assert (_digest(markdown), _digest(html), _digest(stix)) == STORED_RENDERS[run]
