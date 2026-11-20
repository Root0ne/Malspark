"""Render every published surface of a stored run, and compare the surfaces of two git refs.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/render_surfaces.py runs/<family>/1 --out DIR

renders what a reader of the run is shown, at zero cost, and writes a surface
record (``DIR/surfaces.json``) beside the rendered files (``DIR/<run>/<mode>/``:
``report.md``, ``report.html``, ``evidence-bundle.json``,
``evidence-bundle.html``, ``full.json``, ``iocs.json``, ``iocs-default.json``,
one ``iocs-<kind>.json`` per kind served only to a filter naming it,
``stix-bundle.json``, ``stix-judge.json``, ``stix-note.txt``, ``mitre.json``,
``misp-event.json``, ``attack-layer.json``, ``call-map.json``,
``signatures.json`` and three rule downloads per kind: the route's default,
``include=all`` and ``include=printed``; beside each served file, the status
it was served with and every header, in order (``<file>.headers``), and a
file a route refused holds the error it served). Nothing is written into a
run's directory: every file of it is digested before and after, and the
command fails when a digest changed.

The record is a list of units, each with its ``surface``, the ``mode`` that
produced it, a ``group`` (a section path, a figure id, a rule kind), a stable
``key`` and its ``text``, and the digest of each rendered file. The rule is
that everything a surface holds is compared, and what is not is named: no
value is left out unless it is shown to vary without a code change (the same
ref rendered twice, and once more with the clock moved), and each such
exclusion is listed with its proof in :data:`EXCLUDED`, in the record and in
the comparison's output. None is listed: rendered twice and with the clock
moved five years on, every unit and every file of a run is byte-equal. The
build's clock is pinned (see build mode). The string hash seed is not: a
comparison renders build mode under two seeds per ref, the same two for both
refs, and a unit that differs between the two seeds of one ref is its own
class, "order depends on the interpreter's hash seed", listed by surface and
unit path; a difference between the refs in such a unit is left out of the
comparison only when the refs agree under the other seed, and one they differ
in under both seeds is a difference. What each surface compares:

=====================  ==========================================================
surface                compared
=====================  ==========================================================
``report.md``          every line as printed, blank and fenced ones too, under
                       its section path, in the layout the API serves (the
                       run's ``reporting.full_report_in_one_file``)
``banner``             every line of the title block, before the first section
``html.*``             ``report.html``: the cover's fields (``.header``); each
                       figure's caption, legend, SVG ``<text>`` labels,
                       ``<title>`` tooltips and any other text in it
                       (``.figure``); note paragraphs (``.notes``); every other
                       text node as a block, a table row's cells joined, each
                       line of a style or a script (``.body``); every
                       ``title``, ``aria-label`` and ``alt`` attribute
                       (``.attrs``); every start tag as written, each attribute
                       and its value in it, in order (``.tags``)
``bundle.html.*``      the same, over ``/evidence-bundle.html``
``bundle.lines``       every line of every section of ``/evidence-bundle.json``,
                       blank and fenced ones too
``bundle.notes``       each numbered note, every field, as canonical JSON
``bundle.index``       each section's other fields, the header, the format, each
                       evidence entry and every other field of the document, as
                       canonical JSON
``full``               each top-level field of ``/full`` as served, as JSON in
                       its served key order
``iocs.default``,      each row ``/iocs`` serves (by default; with
``iocs.all``           ``include=all`` and the filter-only kinds), keyed by kind
                       and value, every other field as canonical JSON
``stix``,              the bundle ``/stix`` serves (export; ``source=judge``):
``stix.judge``         its envelope, the bundle's own properties, and per object
                       its ``id`` and every other property, timestamps included,
                       as canonical JSON, each ref said as its target's key;
                       keyed by type and identity, a relationship by its
                       source, its type and its target
``stix.notice``,       the notice an unpublished bundle is served with, the
``stix.judge.notice``  judge view's envelope, the STIX note the report detail
``stix.note``          serves
``mitre``              each ``/mitre`` row keyed by technique, every other field
``misp``               the event without its lists, each attribute, each object
                       without its attributes and each object attribute, every
                       field as canonical JSON
``navigator``          the layer's own fields, each legend item and each
                       technique, every field as canonical JSON
``call_map``           the map's own fields and each function, every field
``rules``              each drafted rule's every field but its body, as
                       canonical JSON; ``rules.body``: every line of its body;
                       ``rules.download``: every line of each kind's download,
                       both ``include`` values
``file.lines``         every line of every rendered file, in order, exactly as
                       written: split at each line feed only, so a carriage
                       return, the whitespace, the order of rows and keys and the
                       final newline are each in a unit
``file``               each rendered file by digest: one that differs (or is on
                       one side only) is a change, whatever else changed in it,
                       shown at its first differing line
``http``               per request (route and variant): the status it was
                       served with, each header in order, and its body: a
                       success's digest and length, an error's text, compared
                       whether or not the surface read from it was produced
=====================  ==========================================================

The units of a surface may read a file more loosely than it is written: an
HTML text has its whitespace runs said as one space, a style or script line
its indentation stripped, a Markdown or rule line is split at every line
break, a canonical JSON unit sorts its keys, and a STIX ref is said as its
target's key. Each of these is kept for the unit's readability, and what it
hides is a ``file.lines`` change of the same file.

The API is the tree's own, served through its own HTTP stack: the tree's
``create_app`` builds the application, and each request of :data:`REQUESTS`
is sent to it through a test client, so its middleware, its request
validation, each route's response model, response class and status all run,
and what is compared is what a client is served: the status, every header
and the body, for each route with its defaults (no query) and with each
variant listed. The dependencies are overridden: the user, the reports'
service (the tree's own, reading a row of the stored or rebuilt columns, for
``/markdown``, ``/html``, ``/evidence-bundle.html``, ``/evidence-bundle.json``,
``/full``, ``/iocs``, ``/signatures/{kind}``, ``/stix``, ``/mitre``,
``/misp-event``, ``/attack-layer``), the jobs' service and the database
(``/jobs/{id}/evidence/call-map``: the stored ledger rows in an in-memory
SQLite database with the tree's own table, on which the route's own statement
runs). A JSON body is written in its served key order, never sorted, so a key
moved or a value of another JSON type is a change. The HTML is rendered with a
fixed nonce, so its ``<style nonce>`` and the policy header are the served
ones. Every GET route of the application's route table is served or named in
:data:`NOT_RENDERED`.

Two modes produce the units, and each unit says which:

* **serve**: the stored report (``report-byjob.json``'s ``malware_report``, else
  ``report.json``) typed under the tree's own models and passed to its
  renderers and the API's writers, as the API does for a stored job. The STIX
  bundle and ``/mitre`` are the stored report row's columns, and the judge
  column is read back from the served view (``stix-judge.json``).
* **build**: the report rebuilt by the replay (``scripts/replay/rules.py``: the
  deterministic build, the stored composed sections put back, the export, the
  IOC table, the MISP attributes and the detection drafts), its figures drawn
  as the report node draws them, then rendered and exported the same way. Its
  clock is the stored report's: ``generated_at`` and every value the builder
  dates from the current time (the cover's date, the date inside the report
  number, the copyright year, the revision history's date) are set to the
  stored report's before the export and the drafts read them. The tree's STIX
  models read the same clock while the build runs (``get_utcnow``), so a
  timestamp a model fills by default (an indicator's ``valid_from`` nobody
  wrote) is the stored report's time, never the time of the render.

A surface a tree cannot produce (a function its tree does not have, a stored
file the run lacks, a report the replay could not rebuild) is listed under
``not_produced`` with the reason; it is never skipped and never compared as
equal. One that raised is listed there too, marked as an error.

``--compare REF_A REF_B`` writes both refs out of the object store
(``scripts.replay.compare.materialise``) and runs *this* driver against each
tree in a process of its own, with that tree first on the import path: the
driver resolves the tree's entry points by name at run time, so a ref from
before this tool is rendered too, and an entry point it lacks is a surface not
produced. Build mode is rendered under two string hash seeds per ref
(``--hash-seeds``, else two drawn afresh and printed). The record says where
the platform, the API and the replay scripts
were imported from, and a package imported from outside the tree fails the
comparison (the plain ``--out`` render is checked the same way, against this
checkout). It prints, per run and grouped by surface, every unit changed,
added or removed with both texts; then the count of units compared, of
differences and of surfaces not compared, the units compared per mode and
surface beside their differences, what was excluded and the units whose order
depends on the hash seed. Every unit is compared, those marked ``dynamic`` too
(see the limits). A surface produced by neither ref is listed NOT COMPARED
with both reasons; when the reasons differ it is a difference, and what each
route served (its status, its error) is compared in its ``http`` units either
way. ``--expect FILE`` (JSON: a list
of ``{"surface", "mode"?, "key"?, "old"?, "new"?, "reason"}``, each pattern a
regular expression searched in the key or the text) names the changes
expected: a difference no expectation matches is UNEXPECTED, and an
expectation no difference matches is UNEXERCISED. The exit status is the first
that applies of: 2 when a surface raised in either tree, a tree could not be
written out or rendered, or on an error; 1 when a difference was not expected,
a served status or error among them; 3 when a surface both refs lack for the
same reason (unless ``--accept-not-compared``, which accepts nothing else); 4
when an expectation was not exercised; 0 otherwise.

Limits:

* serve mode cannot change platform text that was written before rendering
  and stored: clauses appended to section bodies, degradation reasons, the
  indicators' reasons, the figures a stored report holds and the stored STIX
  bundle (its export reasons among them) are read as stored;
* build mode rebuilds without the sandbox report, so the units that only it
  fills (the process tree and network figures, the sandbox's IOC rows, the
  export's process, observed-data and network objects) are drawn from no
  sandbox data. Both refs draw them alike, so they are compared, but they are
  marked ``dynamic``: read against the stored report, they differ;
* build mode's judge view carries the stored record's label map: the replay
  keeps none of its own;
* the report detail is read for its STIX note only (``with_current_iocs``):
  its other fields (the transcript, the findings, the verdict reading, the
  section tabs) are not rendered; nor are the PDF (the HTML through WeasyPrint),
  the job package and the console, which draws the API's JSON;
* GET routes and variants not rendered (:data:`NOT_RENDERED`): ``/iocs`` with
  ``include=unpublished`` or a ``kind`` filter other than the kinds served only
  when named, ``/signatures/{kind}`` with a kind other than yara, sigma,
  suricata and snort, ``/attack-layer`` with a ``domain``, the ``download`` variant of
  ``/html`` and ``/evidence-bundle.html``, the report list, the report detail
  and the report by its job, ``/pdf``, ``/timeline``, ``/reports/diff``, the job
  list, the job, its evidence, its evidence check, an evidence entry's objects,
  its follow-ups, its package, its usage and its events, and every route of
  the samples, the sandbox report formats, the dashboard, the accounts, the
  audit, the system, the settings and the health checks; nor any route that
  changes state (POST, PUT, PATCH, DELETE), nor the WebSocket routes;
* the dependencies are overridden: the services read one row and no settings
  store, so the layout a service reads from the store falls back to the
  process's settings, which the replay guard sets to the run's; the router
  dependency that reads the tool servers' declarations does nothing; the
  database and the queue the process is configured with are a closed local
  port, and the rest of its settings are the caller's environment (``DEBUG``,
  for one, decides the HSTS header);
* the rate limiter is taken out of the stack (its headers count the caller's
  requests in a shared store), so nothing it serves is compared: its
  ``X-RateLimit-*`` headers, its 429 and ``Retry-After``, which requests it
  limits; a request carries no Origin, so no CORS header is served, and
  carries a fixed request id, which the stack echoes;
* the call map's database is SQLite: what only PostgreSQL answers fails the
  surface rather than being answered;
* functions of the report node build mode does not run (:data:`NOT_REBUILT`,
  every function the node names that neither the replay's build nor the
  render calls, read from the node's code by :func:`report_node_stages`): the
  section agreement round (``_ask_section_agreement``), the analyst question
  round (``answer_questions``, ``asked_questions``), the verbatim record
  (``record_verbatim_unseen``), the limitations inventory
  (``build_inventory``), the amended validation block
  (``_amended_validation``), the limitations as recorded
  (``_limitations_as_recorded``), the notes on unlinked techniques and on the
  export's findings (``_note_unlinked_techniques``, ``_note_export_findings``),
  filing only the published family (``_file_only_the_published_family``,
  ``_remember_the_published_techniques``), the retry's additions
  (``retry_additions_report``), the corroboration with publication
  (``_corroboration_with_publication``), the sandbox degradation reason
  (``sandbox_degradation_reason``), fitting the structures to the budget
  (``fit_structures_to_budget``), and the node's records of the run, its
  budgets, its progress events and its helpers (``_generation_snapshot``,
  ``_job_id_of``, ``_narrative_timeout``, ``_normalised_by_of``,
  ``_noting_the_report_read``, ``_report_entry_texts``,
  ``_reporter_ledger_reads``, ``_restart_reporter``, ``_rule_check_budget``,
  ``_spend_snapshot``, ``_verdict_record``, ``announce_finished``,
  ``announce_skipped``, ``announce_started``, ``citable_ids``,
  ``efficiency_record``, ``environment_record``, ``evidence_entries``,
  ``hold_the_report_in_progress``, ``kinds_declared_by``, ``pack_text``,
  ``provider_source``, ``relabelled``, ``render_run_state``,
  ``resolve_reporter_mode``, ``rules_already_recorded``, ``run_coverage``,
  ``run_disclosure``, ``sandbox_item_citations``, ``spend_blocks``,
  ``stage_rollup``, ``stage_runs``, ``static_pass_summary``,
  ``summary_counts_line``, ``with_reasons``); the run summary's blocks other
  than the validation, the corroboration, the STIX counts, the evidence and
  the sections without evidence are copied from the stored summary;
* fields an older build lacked default to empty when typed under a newer
  model, so a re-render shows the differences between two refs only, and is
  not what a new run would print;
* the findings the run's checks left unresolved are read as the run summary
  stored them in serve mode, and build mode prints none of the narrative
  findings: a finding's message changed in the code is reported by neither
  mode. The replay comparison (``scripts/replay/run.py --compare``) does not
  report it either: it keys a finding by its producer, answer, claim, path and
  code, not by its words, so no tool here compares a finding's message;
* only the branches of the code the chosen runs reach are compared: text a
  renderer prints under a condition no chosen run meets is never rendered, so
  a change in it is not reported;
* serve mode is rendered under the first hash seed only, so an order it takes
  from the seed is not classed, and shows only when one ref takes it and the
  other does not; a plain ``--out`` render runs under the process's own seed
  and classes nothing.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 — this driver under another tree, an argument list only
import sys
import tempfile
import traceback
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, NoReturn

_ROOT = Path(__file__).resolve().parents[2]
# Set to the tree a run of this driver renders under: that tree's import path is
# the process's own, and nothing of this checkout is put on it.
TREE_VARIABLE = "MALSPARK_SURFACES_TREE"
# The variable a process takes its string hash seed from. A comparison renders
# build mode under two seeds per ref (:func:`apply_hash_seeds`); nothing pins one.
HASH_SEED_VARIABLE = "PYTHONHASHSEED"
# The class a unit is put in when it differs between two hash seeds of one ref.
SEED_CLASS = "order depends on the interpreter's hash seed"
# The stores a render under another tree is pointed at: a closed port on this
# machine, so a call no dependency override answers fails rather than reaching
# a database or a queue.
CLOSED_STORES: dict[str, str] = {
    "DATABASE_URL": "postgresql+asyncpg://render:render@127.0.0.1:9/render",
    "REDIS_URL": "redis://127.0.0.1:9/0",
}
# The middleware taken out of the served stack: its headers count the caller's
# requests in a shared store, so they say how often the route was asked, never
# what the code serves.
LEFT_OUT_MIDDLEWARE: tuple[str, ...] = ("RateLimitMiddleware",)
# The request id every request carries; the stack echoes it in a header.
REQUEST_ID = "render-surfaces"
# The surface each served answer's status, headers and body are units of.
HTTP_SURFACE = "http"
# The package names the tree's platform may be imported under, current first.
PACKAGES_VARIABLE = "MALSPARK_SURFACES_PACKAGES"
# The ATT&CK loader's cache directory, read at import (``scripts.replay.guard``).
ATTCK_CACHE_VARIABLE = "MALSPARK_ATTCK_CACHE"
SCHEMA = 1
MODES: tuple[str, ...] = ("serve", "build")
RECORD_FILE = "surfaces.json"
# The exit statuses of a comparison, the first that applies.
EXIT_ERROR = 2
EXIT_UNEXPECTED = 1
EXIT_NOT_COMPARED = 3
EXIT_UNEXERCISED = 4
EXIT_STATUSES: tuple[tuple[int, str], ...] = (
    (EXIT_ERROR, "a surface raised in either tree, a tree could not be written out or rendered"),
    (EXIT_UNEXPECTED, "a difference no expectation names, a served status or error among them"),
    (EXIT_NOT_COMPARED, "a surface both refs lack alike, unless --accept-not-compared"),
    (EXIT_UNEXERCISED, "an expectation no difference matched"),
    (0, "the refs render the same, or every difference was expected"),
)

# The rule kinds the API serves a download of.
RULE_KINDS: tuple[str, ...] = ("yara", "sigma", "suricata", "snort")
# The IOC kinds ``/iocs`` serves only to a ``kind`` filter that names them.
_FILTERED_IOC_KINDS: tuple[str, ...] = ("secret", "crypto_wallet")
# Each request the render serves, by the file its body is written to: the
# route's path as the route table has it, with the API's prefix left off and a
# report's or a job's id said ``{id}``; the values of its other path
# parameters; and its query. A route is asked once with no query (its
# defaults), and once more for each variant listed.
REQUESTS: dict[str, tuple[str, tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]] = {
    "report.md": ("/reports/{id}/markdown", (), ()),
    "report.html": ("/reports/{id}/html", (), ()),
    "full.json": ("/reports/{id}/full", (), ()),
    "iocs-default.json": ("/reports/{id}/iocs", (), ()),
    "iocs.json": ("/reports/{id}/iocs", (), (("include", "all"),)),
    **{
        f"iocs-{kind}.json": ("/reports/{id}/iocs", (), (("include", "all"), ("kind", kind)))
        for kind in _FILTERED_IOC_KINDS
    },
    "stix-bundle.json": ("/reports/{id}/stix", (), ()),
    "stix-judge.json": ("/reports/{id}/stix", (), (("source", "judge"),)),
    "mitre.json": ("/reports/{id}/mitre", (), ()),
    "misp-event.json": ("/reports/{id}/misp-event", (), ()),
    "attack-layer.json": ("/reports/{id}/attack-layer", (), ()),
    "call-map.json": ("/jobs/{id}/evidence/call-map", (), ()),
    **{
        name: ("/reports/{id}/signatures/{kind}", (("kind", kind),), query)
        for kind in RULE_KINDS
        for name, query in (
            (f"signatures-{kind}-default.txt", ()),
            (f"signatures-{kind}.txt", (("include", "all"),)),
            (f"signatures-{kind}-printed.txt", (("include", "printed"),)),
        )
    },
    "evidence-bundle.json": ("/reports/{id}/evidence-bundle.json", (), ()),
    "evidence-bundle.html": ("/reports/{id}/evidence-bundle.html", (), ()),
}
# The GET routes and variants the API serves that the render does not, each by
# its path as :data:`REQUESTS` says one; ``/*`` names a path and every path
# under it, ``?name=`` a query parameter, a path with a note after it the
# values of its path parameters the note names. Every GET route of the application's
# route table is in :data:`REQUESTS` or here.
NOT_RENDERED: tuple[str, ...] = (
    "/reports/{id}/iocs?include=unpublished",
    "/reports/{id}/iocs?kind= (a kind other than the ones served only when named)",
    "/reports/{id}/signatures/{kind} (a kind other than " + ", ".join(RULE_KINDS) + ")",
    "/reports/{id}/attack-layer?domain=",
    "/reports/{id}/html?download=true",
    "/reports/{id}/evidence-bundle.html?download=true",
    "/reports",
    "/reports/{id}",
    "/reports/job/{id}",
    "/reports/{id}/pdf",
    "/reports/{id}/timeline",
    "/reports/diff",
    "/jobs",
    "/jobs/{id}",
    "/jobs/{id}/evidence",
    "/jobs/{id}/evidence/verify",
    "/jobs/{id}/evidence/{entry_id}/objects/{part}",
    "/jobs/{id}/follow-ups",
    "/jobs/{id}/package",
    "/jobs/{id}/usage",
    "/jobs/{id}/events",
    "/samples/*",
    "/sandbox-report-formats/*",
    "/dashboard/*",
    "/auth/*",
    "/audit/*",
    "/system/*",
    "/settings/*",
    "/health",
    "/healthz",
)
# The report node's calls the render runs itself where the replay's build does
# not: the figures, drawn as the node draws them when the rebuilt report has none.
RERUN_BY_THE_RENDER: tuple[str, ...] = ("build_figures",)
# The functions the report node names that build mode never runs: neither the
# replay's build (``scripts.replay.rules`` and the replay modules it imports)
# nor :data:`RERUN_BY_THE_RENDER` name them
# (``malspark.pipeline.nodes``, derived by :func:`report_node_stages`), and
# two more of the node's module the replay never calls.
NOT_REBUILT: tuple[str, ...] = (
    "_ask_section_agreement",
    "answer_questions",
    "asked_questions",
    "record_verbatim_unseen",
    "build_inventory",
    "_amended_validation",
    "_limitations_as_recorded",
    "_note_unlinked_techniques",
    "_note_export_findings",
    "_file_only_the_published_family",
    "_remember_the_published_techniques",
    "retry_additions_report",
    "_corroboration_with_publication",
    "sandbox_degradation_reason",
    "fit_structures_to_budget",
    "_generation_snapshot",
    "_job_id_of",
    "_narrative_timeout",
    "_normalised_by_of",
    "_noting_the_report_read",
    "_report_entry_texts",
    "_reporter_ledger_reads",
    "_restart_reporter",
    "_rule_check_budget",
    "_spend_snapshot",
    "_verdict_record",
    "announce_finished",
    "announce_skipped",
    "announce_started",
    "citable_ids",
    "efficiency_record",
    "environment_record",
    "evidence_entries",
    "hold_the_report_in_progress",
    "kinds_declared_by",
    "pack_text",
    "provider_source",
    "relabelled",
    "render_run_state",
    "resolve_reporter_mode",
    "rules_already_recorded",
    "run_coverage",
    "run_disclosure",
    "sandbox_item_citations",
    "spend_blocks",
    "stage_rollup",
    "stage_runs",
    "static_pass_summary",
    "summary_counts_line",
    "with_reasons",
)

LIMITS: tuple[str, ...] = (
    "serve mode cannot change platform text that was written before rendering and stored: "
    "clauses appended to section bodies, degradation reasons, the indicators' reasons and the "
    "stored figures and the stored STIX bundle are read as stored",
    "build mode rebuilds without the sandbox report, so the units only it fills are drawn from "
    "no sandbox data: both refs draw them alike and they are compared, but they are marked "
    "dynamic, as read against the stored report they differ",
    "build mode's judge view carries the stored record's label map",
    "the report detail is read for its STIX note only; its other fields, the PDF, the job "
    "package and the console are not rendered",
    "GET routes and variants not rendered: " + ", ".join(NOT_RENDERED),
    "routes that change state (POST, PUT, PATCH, DELETE) and the WebSocket routes are not rendered",
    "each route is served through the application's own HTTP stack (its middleware, request "
    "validation, response model, response class and status), with dependency overrides for "
    "the user, the report and job services and the database: the services read one row and "
    "no settings store, so the layout a service reads from the store falls back to the "
    "process's settings, which the replay guard sets to the run's; the router dependency that "
    "reads the tool servers' declarations does nothing; the database and the queue the process "
    "is configured with are a closed local port, and the rest of its settings are the caller's "
    "environment (DEBUG, for one, decides the HSTS header)",
    "the rate limiter ("
    + ", ".join(LEFT_OUT_MIDDLEWARE)
    + ") is taken out of the stack: its headers count the caller's requests in a shared store, so "
    "nothing the rate limiter serves (its X-RateLimit-* headers, its 429 and Retry-After, which "
    "requests it limits) is compared; a request carries no Origin, so no CORS header is "
    "served, and carries the request id "
    f"{REQUEST_ID!r}, which the stack echoes",
    "the call map's ledger is the stored rows loaded into an in-memory SQLite database with "
    "the tree's own table, and the route's own statement runs on it: what only PostgreSQL "
    "answers (a JSONB operator, a PostgreSQL function) fails the surface rather than being "
    "answered",
    "the report node's functions build mode does not run: "
    + ", ".join(NOT_REBUILT)
    + "; the run summary's blocks other than the validation, the corroboration, the STIX "
    "counts, the evidence and the sections without evidence are copied from the stored summary",
    "only the branches of the code the chosen runs reach are compared: text a renderer prints "
    "under a condition no chosen run meets is never rendered, so a change in it is not reported",
    "a comparison renders build mode under two hash seeds per ref, the same two for both refs; "
    f"a unit that differs between the two seeds of one ref is listed as {SEED_CLASS!r}, by "
    "surface and unit path, and a difference between the refs in it is left out of the "
    "comparison only when the refs agree under the other seed; serve mode is rendered under "
    "the first seed only, so an order it takes from the seed is not classed, and shows only "
    "when one ref takes it and the other does not; a plain --out render runs under the "
    "process's own seed and classes nothing",
    "fields an older build lacked default to empty, so a re-render shows the differences "
    "between two refs only and is not what a new run would print",
    "the run's unresolved findings are read as the run summary stored them in serve mode and "
    "build mode prints none of the narrative findings, so a finding's message changed in the "
    "code is reported by neither mode; the replay comparison (scripts/replay/run.py --compare) "
    "keys a finding by its producer, answer, claim, path and code, not by its words, so no tool "
    "here compares a finding's message",
    "a comparison given --work makes its temporary folders inside that folder and leaves none in "
    "the system's temporary directory (without --work its work folder is made there); a plain "
    "--out render run by itself lets the replay guard keep its ATT&CK cache folder in the "
    "system's temporary directory for the length of the run",
)

# The surfaces of each mode, in the order they are rendered.
SURFACES: tuple[str, ...] = (
    "report.md",
    "banner",
    "html.header",
    "html.figure",
    "html.notes",
    "html.body",
    "html.attrs",
    "html.tags",
    "full",
    "iocs.default",
    "iocs.all",
    "stix",
    "stix.notice",
    "stix.note",
    "stix.judge",
    "stix.judge.notice",
    "mitre",
    "misp",
    "navigator",
    "call_map",
    "rules",
    "rules.body",
    "rules.download",
    "bundle.notes",
    "bundle.lines",
    "bundle.index",
    "bundle.html.header",
    "bundle.html.figure",
    "bundle.html.notes",
    "bundle.html.body",
    "bundle.html.attrs",
    "bundle.html.tags",
    HTTP_SURFACE,
)
# The surface every line of every rendered file is a unit of, in order.
FILE_LINES = "file.lines"
# The surfaces whose units are lines in order: compared by aligning each
# group's texts, so a line put in does not move every key after it.
ORDERED: frozenset[str] = frozenset(
    {
        "report.md",
        "banner",
        "html.header",
        "html.notes",
        "html.body",
        "html.attrs",
        "html.tags",
        "rules.body",
        "rules.download",
        "bundle.lines",
        "bundle.html.header",
        "bundle.html.notes",
        "bundle.html.body",
        "bundle.html.attrs",
        "bundle.html.tags",
        FILE_LINES,
    }
)
# The surface a rendered file's own change is reported on: a file that differs
# is a change whatever else changed in it, never left to the other units.
FILE_SURFACE = "file"
# What is left out of the comparison, each with the proof that it varies
# without a code change (the same ref rendered twice, and once more with the
# clock moved): (surface, what, proof). Every other value is compared.
EXCLUDED: tuple[tuple[str, str, str], ...] = ()
# What only the sandbox report fills, which build mode rebuilds without: the
# figures drawn from its process tree and its network block, the IOC rows it
# is the source of, and the export's objects made from its process tree and
# network block (``scripts.replay.rules``).
DYNAMIC_FIGURES: frozenset[str] = frozenset({"fig-process-tree", "fig-network"})
DYNAMIC_IOC_SOURCES: frozenset[str] = frozenset({"sandbox"})
DYNAMIC_STIX_TYPES: frozenset[str] = frozenset(
    {
        "process",
        "observed-data",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "network-traffic",
    }
)
# A STIX identifier: what a ``*_ref`` names.
_STIX_ID = re.compile(r"^[a-z][a-z0-9-]*--[0-9a-fA-F-]{36}$")


class Absent(LookupError):
    """An entry point the tree does not have, or an input the stored run does not hold."""


# ---------------------------------------------------------------------------
# The tree's entry points, resolved by name
# ---------------------------------------------------------------------------


def _packages() -> tuple[str, ...]:
    named = [p for p in os.environ.get(PACKAGES_VARIABLE, "").split(",") if p.strip()]
    if named:
        return tuple(p.strip() for p in named)
    try:
        from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME
    except Exception:  # noqa: BLE001 — a tree with one name
        return ("malspark",)
    return (CURRENT_NAME, PREVIOUS_NAME)


def entry(module: str, name: str) -> Any:
    """``module.name`` of the tree this process imports, or :class:`Absent` saying which.

    A module of the platform is written ``platform.<path>`` and tried under each
    of the tree's package names; ``app.*`` and ``scripts.*`` are the tree's API
    and scripts as they are.
    """
    if module.startswith("platform."):
        candidates = [f"{p}.{module.removeprefix('platform.')}" for p in _packages()]
    else:
        candidates = [module]
    for candidate in candidates:
        try:
            found = importlib.import_module(candidate)
        except ModuleNotFoundError as exc:
            # The module itself or a package above it is not there; a module it
            # imports that is not there is a broken tree, and raises.
            missing = str(exc.name or "")
            if candidate != missing and not candidate.startswith(f"{missing}."):
                raise
            continue
        if hasattr(found, name):
            return getattr(found, name)
        raise Absent(f"this tree's {candidate} has no {name}")
    raise Absent(f"this tree has no module {candidates[0]}")


def _where(exc: BaseException) -> str:
    """An exception's class and where it was raised: never its message."""
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return type(exc).__name__
    last = frames[-1]
    return f"{type(exc).__name__} at {Path(last.filename).name}:{last.lineno} ({last.name})"


# ---------------------------------------------------------------------------
# What the render covers, read from the code
# ---------------------------------------------------------------------------


def served_routes(app: Any) -> list[tuple[frozenset[str], str, Any]]:
    """Every route of the application's route table: its methods, its path and its endpoint.

    A router the application includes is read route by route, whether the
    installed FastAPI flattens it on inclusion or keeps it whole; a route with
    no methods (a WebSocket route) has none.
    """
    try:
        from fastapi.routing import iter_route_contexts
    except ImportError:
        listed: Iterable[Any] = list(app.routes)
    else:
        listed = iter_route_contexts(app.routes)
    return [
        (
            frozenset(getattr(route, "methods", None) or ()),
            str(getattr(route, "path", "") or ""),
            getattr(route, "endpoint", None),
        )
        for route in listed
    ]


def route_key(path: str) -> str:
    """A route's path as :data:`REQUESTS` says it: the API's prefix off, an id said ``{id}``."""
    return re.sub(r"\{(report|job)_id\}", "{id}", re.sub(r"^/api/v\d+(?=/)", "", path))


def not_rendered_covers(path: str, named: Iterable[str] = NOT_RENDERED) -> bool:
    """Whether :data:`NOT_RENDERED` names the route ``path`` (in :func:`route_key`'s form)."""
    for said in named:
        whole = said.split("?", 1)[0].split(" ", 1)[0]
        if "?" in said or whole != said and not whole.endswith("/*"):
            continue  # a variant of the route, never the route
        if whole.endswith("/*"):
            if path == whole[:-2] or path.startswith(whole[:-1]):
                return True
        elif path == whole:
            return True
    return False


def code_names(paths: Iterable[Path]) -> set[str]:
    """Every name the code of ``paths`` reads, calls or imports: never one in a comment or text."""
    import ast

    out: set[str] = set()
    for path in paths:
        for node in ast.walk(ast.parse(Path(path).read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name):
                out.add(node.id)
            elif isinstance(node, ast.Attribute):
                out.add(node.attr)
            elif isinstance(node, ast.alias):
                out.add(node.name.rsplit(".", 1)[-1])
    return out


def report_node_stages(nodes: Any, node: str = "make_report_node") -> list[str]:
    """Each function the report node's code names, read from the code, never listed by hand.

    A name the node reads that is a function of the node's module (``nodes``),
    one the module imports from the platform, or one the node imports itself
    from the platform, that resolves to a function: a class, a constant or a
    model is left out.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(nodes))
    found = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == node
    )
    imported: dict[str, tuple[str, str]] = {}
    for scope in (tree.body, list(ast.walk(found))):
        for stmt in scope:
            if isinstance(stmt, ast.ImportFrom) and stmt.module and stmt.level == 0:
                for alias in stmt.names:
                    imported[alias.asname or alias.name] = (stmt.module, alias.name)
    read = {n.id for n in ast.walk(found) if isinstance(n, ast.Name)}
    out: set[str] = set()
    for name in read:
        if name in imported:
            module, real = imported[name]
            if module.split(".", 1)[0] not in _packages():
                continue
            try:
                value = getattr(importlib.import_module(module), real)
            except (ImportError, AttributeError):
                continue
            label = real
        elif name in vars(nodes):
            value, label = vars(nodes)[name], name
        else:
            continue
        if (
            inspect.isfunction(value)
            and str(getattr(value, "__module__", "")).split(".", 1)[0] in _packages()
        ):
            out.add(label)
    return sorted(out)


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------


def _space(text: Any) -> str:
    return " ".join(str(text or "").split())


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


class _Units:
    """The units of one mode, each key unique within its surface."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.rows: list[dict[str, Any]] = []
        self._seen: dict[tuple[str, str], int] = {}

    def add(
        self, surface: str, key: str, text: Any, *, group: str = "", dynamic: bool = False
    ) -> None:
        said = str(text if text is not None else "")
        base = f"{group} | {key}" if group and surface in ORDERED else key
        count = self._seen.get((surface, base), 0) + 1
        self._seen[(surface, base)] = count
        row: dict[str, Any] = {
            "mode": self.mode,
            "surface": surface,
            "group": group,
            "key": base if count == 1 else f"{base} ({count})",
            "text": said,
        }
        if dynamic:
            row["dynamic"] = True
        self.rows.append(row)


_HEADING = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")


def markdown_units(markdown: str, units: _Units) -> None:
    """Every line of the Markdown as it is, blank and fenced ones too, under its section path.

    ``banner``: every line of the title block, before the first section.
    """
    path: list[str] = []
    fenced = False
    before_body = True
    for text in markdown.splitlines():
        if _FENCE.match(text):
            fenced = not fenced
        heading = None if fenced else _HEADING.match(text)
        if heading is not None:
            level = len(heading.group(1))
            path = [*path[: level - 1], heading.group(2)]
            path += [""] * (level - len(path))
            if level == 2:
                before_body = False
        group = " > ".join(p for p in path if p)
        units.add("report.md", "line", text, group=group)
        if before_body:
            units.add("banner", "line", text, group="title block")


# The attributes whose value a reader is shown: a tooltip, a name read aloud, an
# image's text. Each is a unit (``html.attrs``) wherever it stands.
_SHOWN_ATTRIBUTES: tuple[str, ...] = ("title", "aria-label", "alt")


class _HtmlReader(HTMLParser):
    """The cover's fields, each figure's text, note paragraphs, and every shown attribute.

    A figure's parts: its caption, its legend, each SVG ``<text>`` label, each
    ``<title>`` (a tooltip) and any other text inside it.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.header: list[str] = []
        self.figures: list[tuple[str, str, str]] = []  # (figure id, part, text)
        self.notes: list[tuple[str, str]] = []  # (section, text)
        self.attributes: list[tuple[str, str, str]] = []  # (where, "tag attribute", value)
        self._in_header = 0
        self._chunk: list[str] = []
        self._section: list[str] = ["", ""]
        self._heading: list[str] | None = None
        self._heading_level = 0
        self._figure: str | None = None
        self._figures_seen = 0
        self._svg_text: list[str] | None = None
        self._title: list[str] | None = None
        self._caption: list[str] | None = None
        self._legend: list[str] | None = None
        self._paragraph: dict[str, Any] | None = None
        self._notes_list = False
        self._note_item: list[str] | None = None

    def _flush_header(self) -> None:
        said = _space("".join(self._chunk))
        if said:
            self.header.append(said)
        self._chunk = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        named = dict(attrs)
        classes = set(str(named.get("class") or "").split())
        if tag == "figure":
            self._figures_seen += 1
            self._figure = str(named.get("id") or f"figure {self._figures_seen}")
        where = self._figure or ("cover" if self._in_header or tag == "header" else self.section)
        for name in _SHOWN_ATTRIBUTES:
            if named.get(name) is not None:
                self.attributes.append((where, f"{tag} {name}", str(named[name])))
        if tag == "header":
            self._in_header += 1
            self._chunk = []
            return
        if self._in_header:
            if tag in {"br", "span", "p", "h1"}:
                self._flush_header()
            return
        if tag in {"h2", "h3"}:
            self._heading = []
            self._heading_level = int(tag[1])
        elif tag == "figure":
            pass
        elif self._figure is not None and tag == "text":
            self._svg_text = []
        elif self._figure is not None and tag == "title":
            self._title = []
        elif self._figure is not None and tag == "figcaption":
            self._caption = []
        elif self._caption is not None and tag == "span" and "fig-legend" in classes:
            self._legend = []
        elif tag == "p" and self._figure is None:
            self._paragraph = {"em": 0, "notes": [], "current": None, "outside": []}
        elif tag == "em" and self._paragraph is not None:
            self._paragraph["em"] += 1
            if self._paragraph["em"] == 1:
                self._paragraph["current"] = []
        elif tag == "ol" and "notes" in classes:
            self._notes_list = True
        elif tag == "li" and self._notes_list:
            self._note_item = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "header" and self._in_header:
            self._flush_header()
            self._in_header -= 1
            return
        if self._in_header:
            if tag in {"span", "p", "h1"}:
                self._flush_header()
            return
        if tag in {"h2", "h3"} and self._heading is not None:
            title = _space("".join(self._heading))
            if self._heading_level == 2:
                self._section = [title, ""]
            else:
                self._section = [self._section[0], title]
            self._heading = None
        elif tag == "text" and self._svg_text is not None and self._figure is not None:
            self.figures.append((self._figure, "label", _space("".join(self._svg_text))))
            self._svg_text = None
        elif tag == "title" and self._title is not None and self._figure is not None:
            self.figures.append((self._figure, "title", _space("".join(self._title))))
            self._title = None
        elif tag == "span" and self._legend is not None and self._figure is not None:
            self.figures.append((self._figure, "legend", _space("".join(self._legend))))
            self._legend = None
        elif tag == "figcaption" and self._caption is not None and self._figure is not None:
            self.figures.append((self._figure, "caption", _space("".join(self._caption))))
            self._caption = None
        elif tag == "figure":
            self._figure = None
        elif tag == "em" and self._paragraph is not None and self._paragraph["em"]:
            self._paragraph["em"] -= 1
            if self._paragraph["em"] == 0:
                said = _space("".join(self._paragraph["current"] or []))
                if said:
                    self._paragraph["notes"].append(said)
                self._paragraph["current"] = None
        elif tag == "p" and self._paragraph is not None:
            paragraph, self._paragraph = self._paragraph, None
            if paragraph["notes"] and not _space("".join(paragraph["outside"])):
                for said in paragraph["notes"]:
                    self.notes.append((self.section, said))
        elif tag == "li" and self._note_item is not None:
            said = _space("".join(self._note_item))
            if said:
                self.notes.append((self.section, said))
            self._note_item = None
        elif tag == "ol" and self._notes_list:
            self._notes_list = False

    @property
    def section(self) -> str:
        return " > ".join(p for p in self._section if p)

    def handle_data(self, data: str) -> None:
        if self._in_header:
            self._chunk.append(data)
            return
        if self._heading is not None:
            self._heading.append(data)
        if self._svg_text is not None:
            self._svg_text.append(data)
        elif self._title is not None:
            self._title.append(data)
        elif self._legend is not None:
            self._legend.append(data)
        elif self._caption is not None:
            self._caption.append(data)
        elif self._figure is not None and _space(data):
            # Any other text inside a figure: a description, a styled block.
            self.figures.append((self._figure, "text", _space(data)))
        if self._paragraph is not None:
            if self._paragraph["current"] is not None:
                self._paragraph["current"].append(data)
            else:
                self._paragraph["outside"].append(data)
        if self._note_item is not None:
            self._note_item.append(data)


class _HtmlBody(HTMLParser):
    """The text of every block of the body outside the cover and the figures, in order.

    A block (a paragraph, a list item, a heading, a preformatted block, a table
    row, a quote, a definition, the document's title, an SVG outside a figure)
    is one text; the cells of a row are joined with `` | ``. Each line of a
    style or a script is a block of its own, grouped under ``<style>`` or
    ``<script>``. The cover and the figures are :class:`_HtmlReader`'s.

    ``tags``: every start tag of the whole document, the cover's and the
    figures' too, as written (each attribute and its value), under the section
    it stands in.
    """

    _BLOCKS = frozenset(
        {
            "p",
            "li",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "pre",
            "blockquote",
            "dt",
            "dd",
            "tr",
            "caption",
            "summary",
            "div",
            "section",
            "article",
            "aside",
            "nav",
            "footer",
            "main",
            "details",
            "table",
            "ul",
            "ol",
            "dl",
            "title",
            "br",
            "hr",
        }
    )
    _CELLS = frozenset({"td", "th"})
    _SKIPPED = frozenset({"header", "figure"})
    _RAW = frozenset({"style", "script"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[tuple[str, str]] = []  # (section, text)
        self.tags: list[tuple[str, str]] = []  # (section, the start tag as written)
        self._chunk: list[str] = []
        self._skipping: list[str] = []
        self._raw: str | None = None
        self._section: list[str] = ["", ""]
        self._heading: list[str] | None = None
        self._heading_level = 0

    @property
    def section(self) -> str:
        return " > ".join(p for p in self._section if p)

    def _flush(self) -> None:
        # A row whose first cells are empty starts with a separator: dropped.
        said = _space("".join(self._chunk)).strip(" |")
        if said:
            self.blocks.append((self.section, said))
        self._chunk = []

    def _tag(self) -> None:
        self.tags.append((self.section, str(self.get_starttag_text() or "")))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tag()
        if self._skipping:
            if tag in self._SKIPPED:
                self._skipping.append(tag)
            return
        if tag in self._SKIPPED:
            self._flush()
            self._skipping.append(tag)
        elif tag in self._RAW:
            self._flush()
            self._raw = tag
        elif tag in self._CELLS:
            if _space("".join(self._chunk)):
                self._chunk.append(" | ")
        elif tag in self._BLOCKS:
            self._flush()
            if tag in {"h2", "h3"}:
                self._heading = []
                self._heading_level = int(tag[1])

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tag()
        if not self._skipping and tag in self._BLOCKS:
            self._flush()

    def handle_endtag(self, tag: str) -> None:
        if self._skipping:
            if tag == self._skipping[-1]:
                self._skipping.pop()
            return
        if tag == self._raw:
            self._raw = None
            return
        if tag in self._BLOCKS:
            if tag in {"h2", "h3"} and self._heading is not None:
                title = _space("".join(self._heading))
                self._heading = None
                # The heading is a block of the section it opens.
                if self._heading_level == 2:
                    self._section = [title, ""]
                else:
                    self._section = [self._section[0], title]
            self._flush()

    def handle_data(self, data: str) -> None:
        if self._skipping:
            return
        if self._raw is not None:
            for line in data.splitlines():
                if line.strip():
                    self.blocks.append((f"<{self._raw}>", line.strip()))
            return
        self._chunk.append(data)
        if self._heading is not None:
            self._heading.append(data)

    def close(self) -> None:
        super().close()
        self._flush()


def html_units(
    document: str,
    units: _Units,
    *,
    dynamic_figures: Iterable[str] = (),
    prefix: str = "html",
) -> None:
    """Every text of the HTML and every shown attribute, under the surfaces ``prefix.*``.

    The cover's fields (``.header``), each figure's caption, legend, SVG
    labels, tooltips and other text (``.figure``), the note paragraphs
    (``.notes``), every other block (``.body``), each ``title``,
    ``aria-label`` and ``alt`` attribute (``.attrs``) and every start tag as
    written, each attribute in it (``.tags``).
    """
    reader = _HtmlReader()
    reader.feed(document)
    reader.close()
    body = _HtmlBody()
    body.feed(document)
    body.close()
    for section, said in body.blocks:
        units.add(f"{prefix}.body", "block", said, group=section)
    for section, said in body.tags:
        units.add(f"{prefix}.tags", "tag", said, group=section)
    marked = set(dynamic_figures)
    for said in reader.header:
        units.add(f"{prefix}.header", "field", said, group="cover")
    for figure, part, said in reader.figures:
        units.add(
            f"{prefix}.figure", f"{figure} {part}", said, group=figure, dynamic=figure in marked
        )
    for section, said in reader.notes:
        units.add(f"{prefix}.notes", "note", said, group=section)
    for where, name, said in reader.attributes:
        units.add(f"{prefix}.attrs", name, said, group=where, dynamic=where in marked)


def canonical(value: Any) -> str:
    """``value`` as canonical JSON: sorted keys, one line, the text as it is."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(", ", ": "), default=str
    )


def _without(row: Mapping[str, Any], *names: str) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in names}


def _ioc_units(
    surface: str, rows: Sequence[Mapping[str, Any]], units: _Units, *, dynamic: bool
) -> None:
    """Each row as served, keyed by its kind and value, every other field its text."""
    for row in rows:
        key = f"{row.get('kind') or ''} {row.get('value') or ''}"
        text = canonical(_without(row, "kind", "value"))
        units.add(
            surface,
            key,
            text,
            group=str(row.get("kind") or ""),
            dynamic=dynamic and str(row.get("source") or "") in DYNAMIC_IOC_SOURCES,
        )


def _full_units(document: Mapping[str, Any], units: _Units) -> None:
    """Each top-level field of ``/full`` as served, as JSON in its served key order."""
    for name, value in document.items():
        units.add("full", str(name), json.dumps(value, ensure_ascii=False, separators=(", ", ": ")))


def file_line_units(files: Mapping[str, str], units: _Units) -> None:
    """Every line of every rendered file, in order, split at each line feed and at nothing else.

    The file is its lines joined by line feeds again: a carriage return stays
    in its line, and a file that ends with a newline ends with an empty unit.
    """
    for name, text in sorted(files.items()):
        for line in text.split("\n"):
            units.add(FILE_LINES, "line", line, group=name)


def _stix_ident(obj: Mapping[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, Mapping) and ref.get("external_id"):
            return str(ref["external_id"])
    for name in ("name", "pattern", "value", "abstract", "content", "path", "key"):
        if obj.get(name):
            return _space(obj[name])[:200]
    return ""


def stix_keys(objects: Sequence[Mapping[str, Any]]) -> tuple[list[str], dict[str, str]]:
    """Each object's key, in order, and the map from an object's id to its key.

    An object is keyed by its type and identity (:func:`_stix_ident`), numbered
    on a repeat; a relationship by its source's key, its type and its target's
    key, so one pointed elsewhere is another unit. A ref to an object the
    bundle does not hold stays the id it is.
    """
    seen: dict[str, int] = {}
    by_id: dict[str, str] = {}
    keys: list[str] = [""] * len(objects)

    def _numbered(base: str) -> str:
        count = seen.get(base, 0) + 1
        seen[base] = count
        return base if count == 1 else f"{base} ({count})"

    relationships = [i for i, o in enumerate(objects) if o.get("type") == "relationship"]
    for index, obj in enumerate(objects):
        if index in relationships:
            continue
        keys[index] = _numbered(f"{obj.get('type') or ''} {_stix_ident(obj)}".strip())
        if obj.get("id"):
            by_id[str(obj["id"])] = keys[index]
    for index in relationships:
        obj = objects[index]
        source = str(obj.get("source_ref") or "")
        target = str(obj.get("target_ref") or "")
        keys[index] = _numbered(
            f"relationship {by_id.get(source, source)} {obj.get('relationship_type') or ''} "
            f"{by_id.get(target, target)}"
        )
        if obj.get("id"):
            by_id[str(obj["id"])] = keys[index]
    return keys, by_id


def _stix_value(value: Any, by_id: Mapping[str, str], *, top: bool = False) -> Any:
    """``value`` with each id of the bundle a ref names said as its object's key.

    ``top``: the object itself, whose ``id`` is a unit of its own.
    """
    if isinstance(value, Mapping):
        return {str(k): _stix_value(v, by_id) for k, v in value.items() if not (top and k == "id")}
    if isinstance(value, list):
        return [_stix_value(v, by_id) for v in value]
    if isinstance(value, str) and _STIX_ID.match(value) and value in by_id:
        return f"-> {by_id[value]}"
    return value


def _stix_text(obj: Mapping[str, Any], by_id: Mapping[str, str] | None = None) -> str:
    """Every property of the object but its id (a unit of its own), timestamps too, as JSON."""
    return canonical(_stix_value(obj, by_id or {}, top=True))


def _stix_units(
    served: Mapping[str, Any],
    units: _Units,
    *,
    dynamic: bool,
    surface: str = "stix",
    notice_surface: str = "stix.notice",
) -> None:
    """The bundle as served: its envelope, its own properties, and each object and its id.

    Each object is two units: its ``id``, and every other property as
    canonical JSON, each ref said as its target's key. The bundle's own
    properties (its id, its flags) are the unit ``bundle``; the envelope an
    unpublished bundle is served in, the unit ``envelope``.
    """
    found = served.get("bundle")
    bundle: Mapping[str, Any] = found if isinstance(found, Mapping) else served
    notice = served.get("notice") or bundle.get("x_malspark_notice")
    units.add(notice_surface, "notice", notice or "(none)")
    if isinstance(found, Mapping):
        units.add(surface, "envelope", canonical(_without(served, "bundle")))
    units.add(surface, "bundle", canonical(_without(bundle, "objects")))
    objects = [o for o in bundle.get("objects") or [] if isinstance(o, Mapping)]
    keys, by_id = stix_keys(objects)
    for obj, key in zip(objects, keys, strict=True):
        kind = str(obj.get("type") or "")
        moving = dynamic and kind in DYNAMIC_STIX_TYPES
        units.add(surface, key, _stix_text(obj, by_id), group=kind, dynamic=moving)
        units.add(surface, f"{key} id", str(obj.get("id") or ""), group=kind, dynamic=moving)


def _judge_view_units(view: Mapping[str, Any], units: _Units) -> None:
    """The judge-source view: its envelope (kept, reason, labels, notice) and its objects."""
    units.add("stix.judge.notice", "envelope", canonical(_without(view, "bundle")))
    found = view.get("bundle")
    if isinstance(found, Mapping):
        _stix_units(
            {"bundle": found, "notice": view.get("notice")},
            units,
            dynamic=False,
            surface="stix.judge",
            notice_surface="stix.judge.notice",
        )


def _mitre_units(rows: Sequence[Mapping[str, Any]] | None, units: _Units) -> None:
    if not rows:
        units.add("mitre", "techniques", "(none)")
        return
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        units.add(
            "mitre", str(row.get("technique_id") or ""), canonical(_without(row, "technique_id"))
        )


def _misp_units(event: Mapping[str, Any], units: _Units) -> None:
    """The event without its lists, each attribute, each object and each object attribute.

    Each as canonical JSON with every field it has: the event keyed ``event``,
    an attribute by its type and value, an object by its name, an object's
    attribute by its object's name and its relation.
    """
    found = event.get("Event")
    body: Mapping[str, Any] = found if isinstance(found, Mapping) else event
    if isinstance(found, Mapping) and len(event) > 1:
        units.add("misp", "envelope", canonical(_without(event, "Event")))
    units.add("misp", "event", canonical(_without(body, "Attribute", "Object")))
    for attribute in body.get("Attribute") or []:
        if not isinstance(attribute, Mapping):
            continue
        key = f"attribute {attribute.get('type') or ''} {attribute.get('value') or ''}"
        units.add("misp", key, canonical(attribute), group=str(attribute.get("type") or ""))
    for obj in body.get("Object") or []:
        if not isinstance(obj, Mapping):
            continue
        name = str(obj.get("name") or "")
        units.add("misp", f"object {name}", canonical(_without(obj, "Attribute")), group="object")
        for attribute in obj.get("Attribute") or []:
            if isinstance(attribute, Mapping):
                key = f"object {name} {attribute.get('object_relation') or ''}"
                units.add("misp", key, canonical(attribute), group="object")


def _layer_units(layer: Mapping[str, Any], units: _Units) -> None:
    """The layer's own fields, each legend item, and each technique with every field it has."""
    units.add("navigator", "description", layer.get("description") or "")
    units.add("navigator", "layer", canonical(_without(layer, "techniques", "legendItems")))
    for item in layer.get("legendItems") or []:
        if isinstance(item, Mapping):
            units.add("navigator", f"legend {item.get('label') or ''}", canonical(item))
    for row in layer.get("techniques") or []:
        if not isinstance(row, Mapping):
            continue
        units.add(
            "navigator",
            f"technique {row.get('techniqueID') or ''}",
            canonical(_without(row, "techniqueID")),
        )


def _call_map_units(found: Mapping[str, Any], units: _Units) -> None:
    """The map without its functions, and each function with every field it has."""
    units.add("call_map", "map", canonical(_without(found, "functions")))
    for function in found.get("functions") or []:
        if not isinstance(function, Mapping):
            continue
        key = str(function.get("address") or ", ".join(function.get("names") or []) or "?")
        units.add("call_map", f"function {key}", canonical(_without(function, "address")))


def _rule_units(
    signatures: Sequence[Mapping[str, Any]],
    downloads: Mapping[str, str],
    units: _Units,
) -> None:
    """Each drafted rule's every field, every line of its body, and every line of each download."""
    for rule in signatures:
        if not isinstance(rule, Mapping):
            continue
        name = f"{rule.get('kind') or ''} {rule.get('name') or ''}"
        units.add("rules", name, canonical(_without(rule, "body")))
        for line in str(rule.get("body") or "").splitlines():
            units.add("rules.body", "line", line, group=name)
    if not signatures:
        units.add("rules", "drafts", "(none)")
    for kind, download in downloads.items():
        for line in download.splitlines():
            units.add("rules.download", "line", line, group=kind)


def _bundle_units(document: Mapping[str, Any], units: _Units) -> None:
    """The bundle's numbered notes, every line of its sections, and the rest of the document.

    A line is a unit whether the model or the platform wrote it, blank and
    fenced ones too: a heading with its tag, a note in italics, a quote, a
    table row, a list item, a line of a code block. Each section's other
    fields, the header, each evidence entry and every other field of the
    document are units of ``bundle.index``.
    """
    for note in document.get("notes") or []:
        if isinstance(note, Mapping):
            units.add(
                "bundle.notes",
                f"note {note.get('number')}",
                canonical(_without(note, "number")),
                group="notes",
            )
    for section in document.get("sections") or []:
        if not isinstance(section, Mapping):
            continue
        group = str(section.get("title") or section.get("anchor") or "")
        units.add("bundle.index", f"section {group}", canonical(_without(section, "markdown")))
        for line in str(section.get("markdown") or "").splitlines():
            units.add("bundle.lines", "line", line, group=group)
    header = document.get("report")
    if isinstance(header, Mapping):
        units.add("bundle.index", "report", canonical(header))
    units.add("bundle.index", "format", str(document.get("format") or ""))
    rest = _without(document, "notes", "sections", "report", "format", "evidence_index")
    units.add("bundle.index", "document", canonical(rest))
    for row in document.get("evidence_index") or []:
        if isinstance(row, Mapping):
            units.add("bundle.index", f"entry {row.get('id')}", canonical(_without(row, "id")))


# ---------------------------------------------------------------------------
# One run under the tree this process imports
# ---------------------------------------------------------------------------


def _digests(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(p for p in Path(root).rglob("*") if p.is_file()):
        found = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                found.update(block)
        out[path.relative_to(root).as_posix()] = found.hexdigest()
    return out


def _read(root: Path, name: str) -> Any:
    path = root / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None


def _evidence_rows(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, dict):
        found = document.get("items") or document.get("entries")
    else:
        found = document
    return [row for row in found if isinstance(row, dict)] if isinstance(found, list) else []


class _Stored:
    """What a stored run holds that the surfaces read, read once and never written."""

    def __init__(self, root: Path) -> None:
        self.root = root
        byjob = _read(root, "report-byjob.json")
        self.byjob: dict[str, Any] = byjob if isinstance(byjob, dict) else {}
        report = self.byjob.get("malware_report")
        self.report_source = "report-byjob.json"
        if not isinstance(report, dict):
            report = _read(root, "report.json")
            self.report_source = "report.json"
        self.report: dict[str, Any] | None = report if isinstance(report, dict) else None
        job = _read(root, "job.json")
        self.job: dict[str, Any] = job if isinstance(job, dict) else {}
        self.evidence = _evidence_rows(_read(root, "evidence.json"))
        summary = _read(root, "run-summary.json")
        if not isinstance(summary, dict):
            summary = self.byjob.get("run_summary")
        self.run_summary: dict[str, Any] = summary if isinstance(summary, dict) else {}
        # The judge-source view as the run served it: the row's judge column is
        # what it holds besides the envelope the route adds.
        judge = _read(root, "stix-judge.json")
        self.judge_view: dict[str, Any] | None = judge if isinstance(judge, dict) else None

    @property
    def judge_column(self) -> dict[str, Any] | None:
        """The report row's ``judge_stix_bundle`` column, read back from the served view."""
        view = self.judge_view
        if view is None:
            raise Absent("the stored run holds no judge-source view (stix-judge.json)")
        if view.get("kept") is False:
            return None
        return {k: v for k, v in view.items() if k in {"bundle", "labels", "as_written"}}

    @property
    def report_id(self) -> str:
        return str(self.byjob.get("id") or "")

    @property
    def job_id(self) -> str | None:
        return str(self.byjob.get("job_id") or self.job.get("id") or "") or None

    @property
    def settings(self) -> dict[str, Any]:
        snapshot = self.run_summary.get("settings_snapshot")
        return snapshot if isinstance(snapshot, dict) else {}


class _Mode:
    """The units, the reasons and the rendered files of one mode over one run."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.units = _Units(mode)
        self.not_produced: list[dict[str, Any]] = []
        self.files: dict[str, str] = {}
        # The files that hold what a route served (its headers, an error's
        # body): kept when the surface read from the answer is not produced.
        self.served: set[str] = set()

    def lack(self, surfaces: Iterable[str], why: str, *, error: bool = False) -> None:
        for surface in surfaces:
            row: dict[str, Any] = {"mode": self.mode, "surface": surface, "reason": why}
            if error:
                row["error"] = True
            self.not_produced.append(row)

    def produce(self, surfaces: Sequence[str], make: Callable[[], None]) -> None:
        """Run ``make``; the surfaces it fills are not produced, with why, when it cannot."""
        before = len(self.units.rows)
        written = set(self.files)
        try:
            make()
            # A surface rendered with nothing on it is said as one unit, so its
            # appearing on the other side is a change, never a silence.
            held = {row["surface"] for row in self.units.rows[before:]}
            for surface in surfaces:
                if surface not in held:
                    self.units.add(surface, "(empty)", "(nothing printed)")
        except Absent as exc:
            self._drop(before, written)
            self.lack(surfaces, str(exc))
        except Exception as exc:  # noqa: BLE001 — named as an error, the other surfaces stand
            self._drop(before, written)
            self.lack(surfaces, f"raised: {_where(exc)}", error=True)

    def _drop(self, before: int, written: set[str]) -> None:
        """The units and the files a surface that could not be produced left behind.

        What a route served stays: its status, its headers and its body are
        units of :data:`HTTP_SURFACE`, compared whether or not the surface read
        from the answer was produced.
        """
        self.units.rows[before:] = [
            row for row in self.units.rows[before:] if row["surface"] == HTTP_SURFACE
        ]
        for name in set(self.files) - written - self.served:
            del self.files[name]


def _environment(stored: _Stored) -> Any:
    """The tree's replay guard over the run's settings, or a block that changes nothing."""
    try:
        guard = entry("scripts.replay.guard", "replay_environment")
    except Absent:
        from contextlib import nullcontext

        return nullcontext()
    return guard(stored.settings)


def _typed(report: Mapping[str, Any]) -> Any:
    """The stored report as the tree's model, read in sorted key order as the API reads it."""
    model = entry("platform.reporting.models", "MalwareReport")
    try:
        ordered = entry("platform.reporting.models", "key_ordered")(report)
    except Absent:
        ordered = report
    return model.model_validate(ordered)


class _FixedSecrets:
    """The ``secrets`` module with every token fixed: a route's nonce is the same on each render."""

    def __getattr__(self, name: str) -> Any:
        import secrets

        return getattr(secrets, name)

    @staticmethod
    def token_bytes(nbytes: int | None = None) -> bytes:
        return bytes(32 if nbytes is None else nbytes)

    @classmethod
    def token_hex(cls, nbytes: int | None = None) -> str:
        return cls.token_bytes(nbytes).hex()

    @classmethod
    def token_urlsafe(cls, nbytes: int | None = None) -> str:
        import base64

        return base64.urlsafe_b64encode(cls.token_bytes(nbytes)).rstrip(b"=").decode("ascii")


def _uuid(said: Any) -> Any:
    """``said`` as the UUID a row's id column holds, else ``None``."""
    import uuid

    try:
        return uuid.UUID(str(said))
    except ValueError:
        return None


class _Served:
    """What one request was served: its status, every header in order, and the body's bytes."""

    def __init__(self, status: int, headers: Sequence[tuple[str, str]], body: bytes) -> None:
        self.status = status
        self.headers = list(headers)
        self.body = body

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "surrogateescape")

    def json(self) -> Any:
        return json.loads(self.body)


class _Application:
    """The tree's application, served through its own HTTP stack in this process.

    Built once by the tree's ``app.main.create_app`` with the middleware of
    :data:`LEFT_OUT_MIDDLEWARE` taken out; each request is sent through a test
    client, so the middleware, the request validation, the response model, the
    response class and the status all run. The dependencies a request is
    served with are overridden for that request alone, and the ``secrets``
    module of every route's module is fixed while it runs
    (:class:`_FixedSecrets`), so a nonce is the same on each render.
    """

    _built: dict[int, _Application] = {}

    def __init__(self, create_app: Any) -> None:
        from fastapi.testclient import TestClient

        self.app = create_app()
        self.app.user_middleware[:] = [
            m
            for m in self.app.user_middleware
            if getattr(getattr(m, "cls", None), "__name__", "") not in LEFT_OUT_MIDDLEWARE
        ]
        self.routes = served_routes(self.app)
        self.modules = sorted(
            {
                str(getattr(endpoint, "__module__", ""))
                for _methods, _path, endpoint in self.routes
                if endpoint is not None
            }
        )
        self.client = TestClient(self.app)

    @classmethod
    def of_this_tree(cls) -> _Application:
        create_app = entry("app.main", "create_app")
        built = cls._built.get(id(create_app))
        if built is None:
            built = cls._built[id(create_app)] = cls(create_app)
        return built

    def path_of(self, key: str) -> str:
        """The route table's path for a path as :data:`REQUESTS` says it, else :class:`Absent`."""
        for methods, path, _endpoint in self.routes:
            if "GET" in methods and route_key(path) == key:
                return path
        raise Absent(f"this tree's application serves no GET {key}")

    def get(
        self,
        key: str,
        path_values: Mapping[str, str],
        query: Sequence[tuple[str, str]],
        overrides: Mapping[Any, Callable[[], Any]],
    ) -> _Served:
        path = self.path_of(key)
        for name, value in path_values.items():
            path = path.replace("{" + name + "}", value)
        held = [sys.modules[name] for name in self.modules if name in sys.modules]
        drawn = {module: module.secrets for module in held if hasattr(module, "secrets")}
        self.app.dependency_overrides.clear()
        self.app.dependency_overrides.update(overrides)
        for module in drawn:
            module.secrets = _FixedSecrets()  # type: ignore[attr-defined]
        try:
            answer = self.client.get(path, params=list(query), headers={"X-Request-ID": REQUEST_ID})
        finally:
            for module, real in drawn.items():
                module.secrets = real  # type: ignore[attr-defined]
            self.app.dependency_overrides.clear()
        return _Served(answer.status_code, answer.headers.multi_items(), answer.content)


def request_label(file: str) -> str:
    """The request a file's body was served by, as the units name it."""
    key, path_values, query = REQUESTS[file]
    for name, value in path_values:
        key = key.replace("{" + name + "}", value)
    return "GET " + key + ("?" + "&".join(f"{k}={v}" for k, v in query) if query else "")


def _user() -> Any:
    """The user every request is served as: one id, standing for the row's owner."""
    import uuid
    from types import SimpleNamespace

    return SimpleNamespace(id=uuid.UUID(int=0), is_active=True)


def _overrides(**given: Any) -> dict[Any, Callable[[], Any]]:
    """The tree's dependencies a request is served with, each overridden by what ``given`` holds.

    ``report_svc`` stands for the reports' service, ``job_svc`` for the jobs'
    and ``db`` for the database session; the user is :func:`_user`, and the
    router dependency that reads the tool servers' declarations does nothing.
    A dependency the tree does not have is left out.
    """
    out: dict[Any, Callable[[], Any]] = {}
    wanted: list[tuple[str, str, Any]] = [
        ("app.deps", "get_current_user", _user()),
        ("app.deps", "reads_served_declarations", None),
    ]
    if "report_svc" in given:
        wanted.append(("app.api.v1.reports", "_get_service", given["report_svc"]))
    if "job_svc" in given:
        wanted.append(("app.api.v1.jobs", "_get_service", given["job_svc"]))
    if "db" in given:
        wanted.append(("app.database", "get_db", given["db"]))
    for module, name, value in wanted:
        try:
            dependency = entry(module, name)
        except Absent:
            continue
        out[dependency] = _answering(value)
    return out


def _answering(value: Any) -> Callable[[], Any]:
    """A dependency that takes nothing and answers ``value``."""

    def _given() -> Any:
        return value

    return _given


def serve(file: str, mode: _Mode, *, allow_error: bool = False, **given: Any) -> _Served:
    """The request :data:`REQUESTS` names for ``file``, served; what it served is a unit.

    Its status, each header in order and its body (an error's body as served,
    a success's digest and length) are units of :data:`HTTP_SURFACE`, and the
    status line and the headers are written to ``<file>.headers``. An answer
    that is not a success writes its body to ``file`` and is :class:`Absent`
    for the surface read from it, unless ``allow_error``: the surface is not
    produced, and what was served is compared all the same.
    """
    key, path_values, query = REQUESTS[file]
    ids = {"report_id": given.pop("report_id", ""), "job_id": given.pop("job_id", "")}
    application = _Application.of_this_tree()
    served = application.get(key, {**ids, **dict(path_values)}, query, _overrides(**given))
    label = request_label(file)
    mode.units.add(HTTP_SURFACE, f"{label} status", str(served.status), group=label)
    for name, value in served.headers:
        mode.units.add(HTTP_SURFACE, f"{label} header {name}", value, group=label)
    said = (
        f"sha256:{hashlib.sha256(served.body).hexdigest()} ({len(served.body)} bytes)"
        if served.ok
        else served.text
    )
    mode.units.add(HTTP_SURFACE, f"{label} body", said, group=label)
    mode.files[f"{file}.headers"] = f"status: {served.status}\n" + "".join(
        f"{name}: {value}\n" for name, value in served.headers
    )
    mode.served.add(f"{file}.headers")
    if not served.ok:
        mode.files[file] = served.text
        mode.served.add(file)
        if not allow_error:
            raise Absent(f"{label} answers {served.status} (what it served is compared)")
    return served


def _report_row(stored: _Stored, **columns: Any) -> Any:
    """A report row of the stored run: its ids, its run summary, and ``columns``."""
    from types import SimpleNamespace

    row: dict[str, Any] = {
        "id": _uuid(stored.report_id),
        "job_id": _uuid(stored.job_id),
        "malware_report": None,
        "stix_bundle": None,
        "judge_stix_bundle": None,
        "mitre_techniques": None,
        "run_summary": stored.run_summary,
    }
    row.update(columns)
    return SimpleNamespace(**row)


def serve_report(file: str, mode: _Mode, row: Any, *, allow_error: bool = False) -> _Served:
    """``file``'s request to the tree's report routes, its service reading ``row``.

    The service is the tree's ``ReportService`` reading ``row`` where it reads
    the store, so every step between the row and the answer is the tree's.
    """
    import uuid

    service = entry("app.services.report_service", "ReportService")

    class _Row(service):  # type: ignore[misc, valid-type]
        async def get_report(self, *_args: Any, **_kwargs: Any) -> Any:
            return row

    return serve(
        file,
        mode,
        allow_error=allow_error,
        report_id=str(row.id or uuid.UUID(int=0)),
        report_svc=_Row(None),
    )


class _AwaitedSession:
    """A synchronous ORM session's calls, awaited as an asynchronous session's are."""

    def __init__(self, session: Any) -> None:
        self.session = session

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self.session.execute(statement, *args, **kwargs)

    async def scalar(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self.session.scalar(statement, *args, **kwargs)

    async def scalars(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self.session.scalars(statement, *args, **kwargs)

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        return self.session.get(*args, **kwargs)

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None

    async def close(self) -> None:
        return None


@contextmanager
def ledger_database(stored: _Stored, job_id: Any) -> Iterator[Any]:
    """The stored ledger rows in an in-memory SQLite database, in the tree's own table.

    The table is the tree's ``EvidenceEntry`` table, created with the columns
    its model declares, a JSON column and an id column in the types SQLite
    stores them in; each stored row is one of its rows, written through the
    tree's model, every column the stored row holds set from it (a timestamp
    and an id read as the column types them) and the job's id its ``job_id``.
    A statement a route makes runs on it as it would on the application's
    database: what it selects, filters, orders and limits is the statement's
    own.
    """
    import uuid

    import sqlalchemy as sa
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool

    model = entry("app.models.evidence", "EvidenceEntry")
    engine = sa.create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    session = Session(engine, expire_on_commit=False)
    try:
        created = model.__table__.to_metadata(sa.MetaData())
        for column in created.columns:
            if isinstance(column.type, sa.JSON):
                column.type = sa.JSON()
            elif isinstance(column.type, sa.Uuid):
                column.type = (
                    sa.Uuid(as_uuid=True)
                    if getattr(column.type, "as_uuid", True)
                    else sa.Uuid(as_uuid=False)
                )
        for constraint in list(created.foreign_key_constraints):
            created.constraints.discard(constraint)
        created.create(engine)
        for stored_row in stored.evidence:
            values: dict[str, Any] = {}
            for column in model.__table__.columns:
                if column.name not in stored_row:
                    continue
                value = stored_row[column.name]
                if isinstance(value, str) and isinstance(column.type, sa.DateTime):
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                elif isinstance(value, str) and getattr(column.type, "as_uuid", False):
                    value = uuid.UUID(value)
                values[column.name] = value
            values["job_id"] = job_id
            session.add(model(**values))
        session.commit()
        yield _AwaitedSession(session)
    finally:
        session.close()
        engine.dispose()


def serve_call_map(mode: _Mode, stored: _Stored) -> _Served:
    """``/jobs/{id}/evidence/call-map`` over the stored ledger rows, through the tree's route.

    Its service is the tree's ``AnalysisService`` finding the job, and its
    database the stored ledger rows in an in-memory SQLite database
    (:func:`ledger_database`): the route's own statement selects the rows.
    """
    import uuid
    from types import SimpleNamespace

    if not stored.evidence:
        raise Absent("the stored run holds no evidence ledger")
    if any("id" not in row for row in stored.evidence):
        raise Absent("the stored ledger's rows hold no id column, which the route reads them with")
    service = entry("app.services.analysis_service", "AnalysisService")
    job = SimpleNamespace(id=_uuid(stored.job_id) or uuid.UUID(int=0))

    class _Job(service):  # type: ignore[misc, valid-type]
        async def get_job(self, *_args: Any, **_kwargs: Any) -> Any:
            return job

    with ledger_database(stored, job.id) as db:
        return serve("call-map.json", mode, job_id=str(job.id), job_svc=_Job(None), db=db)


def _render(
    mode: _Mode,
    stored: _Stored,
    report: Any,
    mr: dict[str, Any],
    *,
    untyped: str = "",
    **columns: Any,
) -> None:
    """Every surface of one report, each as the tree's application serves it over the report's row.

    ``report`` is the typed report, ``None`` when it does not read as the tree's
    model (``untyped`` says why): every route is asked all the same, and what
    it served is compared; a surface read from the typed report is not
    produced when its route answers a success the tool cannot type.
    ``columns`` holds what fills the row's other columns: ``stix`` and
    ``judge`` (the export and judge columns, as keyword arguments of the row)
    and ``mitre`` (the column), each raising :class:`Absent` when the run has
    none. Each request of :data:`REQUESTS` is served through the application's
    HTTP stack (:func:`serve`).
    """
    dynamic = mode.mode == "build"
    figures = DYNAMIC_FIGURES if dynamic else ()

    def _typed_or_absent(file: str) -> None:
        # A success served over a report that does not type: what it served is
        # kept and compared, and the surface read from it is not produced.
        if report is None:
            mode.served.add(file)
            raise Absent(untyped)

    def _row(**more: Any) -> Any:
        return _report_row(stored, malware_report=mr, **more)

    def _get(file: str, row: Any = None, *, allow_error: bool = False) -> _Served:
        return serve_report(file, mode, row if row is not None else _row(), allow_error=allow_error)

    def _json_file(file: str, row: Any = None) -> Any:
        served = _get(file, row).json()
        mode.files[file] = _json(served)
        return served

    def _markdown() -> None:
        text = _get("report.md").text
        mode.files["report.md"] = text
        _typed_or_absent("report.md")
        markdown_units(text, mode.units)

    def _html() -> None:
        text = _get("report.html").text
        mode.files["report.html"] = text
        _typed_or_absent("report.html")
        html_units(text, mode.units, dynamic_figures=figures)

    def _full() -> None:
        _full_units(_json_file("full.json"), mode.units)

    def _iocs_default() -> None:
        default = _json_file("iocs-default.json")
        _ioc_units("iocs.default", default.get("items") or [], mode.units, dynamic=dynamic)

    def _iocs_all() -> None:
        rows = list(_json_file("iocs.json").get("items") or [])
        # The kinds served only to a filter that names them, after the rest.
        for kind in _FILTERED_IOC_KINDS:
            rows += list(_json_file(f"iocs-{kind}.json").get("items") or [])
        _ioc_units("iocs.all", rows, mode.units, dynamic=dynamic)

    def _stix() -> None:
        served = _json_file("stix-bundle.json", _row(**columns["stix"]()))
        _stix_units(served, mode.units, dynamic=dynamic)

    def _stix_note() -> None:
        # The note the detail endpoint serves beside the report (``with_current_iocs``).
        with_current_iocs = entry("app.services.report_service", "with_current_iocs")
        _served_mr, note = with_current_iocs(dict(mr), stored.report_id)
        mode.files["stix-note.txt"] = f"{note or '(none)'}\n"
        mode.units.add("stix.note", "note", note or "(none)")

    def _judge_view() -> None:
        view = _json_file("stix-judge.json", _row(**columns["judge"]()))
        _judge_view_units(view, mode.units)

    def _mitre() -> None:
        served = _json_file("mitre.json", _row(mitre_techniques=columns["mitre"]()))
        _mitre_units(served.get("techniques"), mode.units)

    def _misp() -> None:
        served = _json_file("misp-event.json")
        _typed_or_absent("misp-event.json")
        _misp_units(served, mode.units)

    def _layer() -> None:
        _layer_units(_json_file("attack-layer.json"), mode.units)

    def _call_map() -> None:
        found = serve_call_map(mode, stored).json()
        mode.files["call-map.json"] = _json(found)
        _call_map_units(found, mode.units)

    def _rules() -> None:
        signatures = [r for r in mr.get("detection_signatures") or [] if isinstance(r, dict)]
        mode.files["signatures.json"] = _json(signatures)
        row = _row()
        downloads: dict[str, str] = {}
        for kind in RULE_KINDS:
            for variant, file in (
                ("default", f"signatures-{kind}-default.txt"),
                ("all", f"signatures-{kind}.txt"),
                ("printed", f"signatures-{kind}-printed.txt"),
            ):
                # A kind the route refuses is served all the same: its status and
                # its error are units, and its download has no line.
                served = _get(file, row, allow_error=True)
                if served.ok:
                    mode.files[file] = downloads[f"{kind} {variant}"] = served.text
        _rule_units(signatures, downloads, mode.units)

    def _bundle() -> None:
        text = _get("evidence-bundle.json").text
        mode.files["evidence-bundle.json"] = text
        _typed_or_absent("evidence-bundle.json")
        _bundle_units(json.loads(text), mode.units)

    def _bundle_html() -> None:
        # ``/reports/{id}/evidence-bundle.html``: the bundle layout, whatever the run's.
        text = _get("evidence-bundle.html").text
        mode.files["evidence-bundle.html"] = text
        _typed_or_absent("evidence-bundle.html")
        html_units(text, mode.units, dynamic_figures=figures, prefix="bundle.html")

    mode.produce(("report.md", "banner"), _markdown)
    mode.produce(
        ("html.header", "html.figure", "html.notes", "html.body", "html.attrs", "html.tags"),
        _html,
    )
    mode.produce(("full",), _full)
    mode.produce(("iocs.default",), _iocs_default)
    mode.produce(("iocs.all",), _iocs_all)
    mode.produce(("stix", "stix.notice"), _stix)
    mode.produce(("stix.note",), _stix_note)
    mode.produce(("stix.judge", "stix.judge.notice"), _judge_view)
    mode.produce(("mitre",), _mitre)
    mode.produce(("misp",), _misp)
    mode.produce(("navigator",), _layer)
    mode.produce(("call_map",), _call_map)
    mode.produce(("rules", "rules.body", "rules.download"), _rules)
    mode.produce(("bundle.notes", "bundle.lines", "bundle.index"), _bundle)
    mode.produce(
        (
            "bundle.html.header",
            "bundle.html.figure",
            "bundle.html.notes",
            "bundle.html.body",
            "bundle.html.attrs",
            "bundle.html.tags",
        ),
        _bundle_html,
    )


def _json(value: Any) -> str:
    """A served JSON value written in its served key order: never sorted, nothing coerced."""
    return json.dumps(value, indent=1, ensure_ascii=False) + "\n"


def _serve(stored: _Stored) -> _Mode:
    mode = _Mode("serve")
    if stored.report is None:
        mode.lack(
            SURFACES,
            "the stored run holds no report document (report-byjob.json's malware_report or "
            "report.json)",
        )
        return mode
    mr = stored.report
    with _environment(stored):
        report: Any = None
        untyped = ""
        try:
            report = _typed(mr)
        except Absent as exc:
            untyped = str(exc)
        except Exception as exc:  # noqa: BLE001 — the API answers 404 for these surfaces
            untyped = f"the stored report does not read as this tree's report model: {_where(exc)}"

        def _stix() -> Any:
            if "stix_bundle" not in stored.byjob:
                raise Absent("report-byjob.json holds no stix_bundle column")
            judge = stored.judge_column if stored.judge_view is not None else None
            return {"stix_bundle": stored.byjob.get("stix_bundle"), "judge_stix_bundle": judge}

        def _judge() -> Any:
            return {
                "stix_bundle": stored.byjob.get("stix_bundle"),
                "judge_stix_bundle": stored.judge_column,
            }

        def _mitre() -> Any:
            if "mitre_techniques" not in stored.byjob:
                raise Absent("report-byjob.json holds no mitre_techniques column")
            return stored.byjob.get("mitre_techniques")

        _render(mode, stored, report, mr, untyped=untyped, stix=_stix, judge=_judge, mitre=_mitre)
    return mode


def _clock(stored: _Stored) -> datetime:
    """When the stored report was built, else when its job was made; the epoch with neither.

    Read by ``scripts.replay.stored.stored_clock``, the one clock the replay's detection
    drafts are dated by too. The driver loads that module from its own directory, never
    from the tree it renders, so a tree from before the function is rendered by the same
    clock.
    """
    clock: Callable[[Any, Any], datetime] = _own_module("stored").stored_clock
    return clock(stored.report, stored.job)


def _own_module(name: str) -> Any:
    """A module of this driver's own directory, loaded from its file under a private name."""
    import importlib.util

    private = f"_render_surfaces_own_{name}"
    if private in sys.modules:
        return sys.modules[private]
    spec = importlib.util.spec_from_file_location(private, Path(__file__).with_name(f"{name}.py"))
    if spec is None or spec.loader is None:
        raise ImportError(f"this driver has no {name}.py beside it")
    module = importlib.util.module_from_spec(spec)
    sys.modules[private] = module
    spec.loader.exec_module(module)
    return module


def pin_clock(report: Any, stored: Mapping[str, Any] | None, clock: datetime) -> None:
    """Every value the build derived from the current time, set to the stored report's.

    The builder dates the cover from the clock it reads (``_build_front_matter``):
    the report date, the date inside the report number, the copyright year and
    the revision history's date. Each is set to the stored report's date
    (its ``front_matter.report_date``, else ``clock``'s), and ``generated_at``,
    which the export, the MISP event and the drafted rules read, to ``clock``.
    Only the date in each value is replaced, so a prefix, a digest or a wording
    the tree changed still shows.
    """
    report.generated_at = clock
    front = getattr(report, "front_matter", None)
    built = str(getattr(front, "report_date", "") or "")
    if front is None or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", built):
        return
    stored_front = (stored or {}).get("front_matter")
    stored_front = stored_front if isinstance(stored_front, Mapping) else {}
    pinned = str(stored_front.get("report_date") or "")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", pinned):
        pinned = f"{clock:%Y-%m-%d}"
    if front.report_number:
        front.report_number = str(front.report_number).replace(
            built.replace("-", ""), pinned.replace("-", "")
        )
    if getattr(front, "copyright", None):
        front.copyright = re.sub(rf"\b{built[:4]}\b", pinned[:4], str(front.copyright))
    front.report_date = pinned
    for row in getattr(report, "version_history", None) or []:
        if getattr(row, "date", None) == built:
            row.date = pinned


@contextmanager
def pinned_stix_clock(clock: datetime) -> Iterator[None]:
    """The tree's STIX models dated by ``clock`` while the block runs, and as they were after.

    Every timestamp a model fills by default is read from the models' own
    clock (``stix_models.get_utcnow``, which asks the module's ``datetime``
    for the time): that clock answers ``clock``, so an object built at render
    time and validated again, which freezes the default into the fields set,
    carries the stored report's time. A tree without the clock is left as it is.
    """
    moment = clock if clock.tzinfo is not None else clock.replace(tzinfo=UTC)
    try:
        source = entry("platform.schemas.stix_models", "get_utcnow")
    except Absent:
        yield
        return
    held = getattr(source, "__globals__", {})
    real = held.get("datetime")
    if not isinstance(real, type) or not issubclass(real, datetime):
        yield
        return

    class _Pinned(real):  # type: ignore[misc, valid-type]
        @classmethod
        def now(cls, tz: Any = None) -> Any:
            return moment.astimezone(tz) if tz is not None else moment.replace(tzinfo=None)

    held["datetime"] = _Pinned
    try:
        yield
    finally:
        held["datetime"] = real


def _build(run_dir: Path, stored: _Stored) -> _Mode:
    """The report the replay rebuilds, under the stored report's clock (``pinned_stix_clock``)."""
    with pinned_stix_clock(_clock(stored)):
        return _rebuilt(run_dir, stored)


def _rebuilt(run_dir: Path, stored: _Stored) -> _Mode:
    """The report the replay rebuilds, captured where the export decided its values."""
    mode = _Mode("build")
    try:
        rules: Any = importlib.import_module("scripts.replay.rules")
        read_run = entry("scripts.replay.stored", "read_run")
        built_by = rules._build
        original = rules._report_values
    except (ImportError, AttributeError, Absent) as exc:
        mode.lack(SURFACES, f"this tree has no replay build to rebuild the report with ({exc})")
        return mode
    captured: dict[str, Any] = {}
    clock = _clock(stored)

    def _clocked(*args: Any, **kwargs: Any) -> Any:
        # The build's clock is the stored report's, set before the export and
        # the drafts read it: their object ids and dates derive from it, and
        # the cover's dates and report number are the stored report's.
        values = built_by(*args, **kwargs)
        built: Any = args[2] if len(args) > 2 else kwargs.get("built")
        if getattr(built, "report", None) is not None:
            pin_clock(built.report, stored.report, clock)
        return values

    def _capturing(*args: Any, **kwargs: Any) -> Any:
        values = original(*args, **kwargs)
        built: Any = args[1] if len(args) > 1 else kwargs.get("built")
        captured["report"] = built.report.model_copy(deep=True)
        captured["judged"] = args[2] if len(args) > 2 else kwargs.get("judged")
        return values

    rules._build, rules._report_values = _clocked, _capturing
    try:
        record = rules.replay_run(read_run(run_dir))
    except Exception as exc:  # noqa: BLE001 — the build raised: nothing to render
        mode.lack(SURFACES, f"the replay's build raised: {_where(exc)}", error=True)
        return mode
    finally:
        rules._build, rules._report_values = built_by, original
    report = captured.get("report")
    if report is None:
        why = "; ".join(
            f"{row.get('part')}: {row.get('why')}"
            for row in record.get("not_replayed") or []
            if row.get("error")
        )
        mode.lack(SURFACES, f"the replay did not rebuild the report ({why or 'no reason given'})")
        return mode
    with _environment(stored):
        if not report.figures:
            try:
                report.figures = entry("platform.reporting.figures", "build_figures")(report)
            except Absent as exc:
                mode.lack(
                    ("html.figure",),
                    f"the report node's figures are not drawn ({exc}); only the ones the "
                    "renderer draws itself are",
                )
        mr = report.model_dump(mode="json")

        def _judge_column() -> Any:
            # The column the worker stores (``judge_bundle_record``): the judge's
            # answer as written when the run kept it, else the rebuilt parse. The
            # label map is the stored record's: the replay keeps none of its own.
            judge = getattr(captured.get("judged"), "bundle", None)
            record = stored.judge_column if stored.judge_view is not None else None
            if judge is None:
                return None
            written = (record or {}).get("bundle") if (record or {}).get("as_written") else None
            build_record = entry("app.worker.analysis_worker", "judge_bundle_record")
            return build_record(
                {
                    "stix_output": judge.model_dump(),
                    "stix_labels": (record or {}).get("labels") or {},
                    "stix_written": written,
                }
            )

        def _export_column() -> Any:
            bundle = report.stix_bundle_extended
            if bundle:
                return bundle
            judge = getattr(captured.get("judged"), "bundle", None)
            if judge is None:
                raise Absent("the rebuilt report holds no export and the judge's bundle is absent")
            # The worker stores the judge's draft, marked unpublished, when no export exists.
            as_json = entry("app.worker.analysis_worker", "judge_bundle_json")(judge.model_dump())
            only = entry("platform.schemas.stix_models", "JUDGE_ONLY_PROPERTIES")
            flag = entry("platform.schemas.stix_models", "UNPUBLISHED_PROPERTY")
            notice = entry("platform.schemas.stix_models", "UNPUBLISHED_NOTICE")
            draft = {k: v for k, v in as_json.items() if k not in only}
            return {**draft, flag: False, "x_malspark_notice": notice}

        def _stix() -> Any:
            return {"stix_bundle": _export_column()}

        def _judge() -> Any:
            return {"judge_stix_bundle": _judge_column()}

        def _mitre() -> Any:
            extract = entry("app.worker.analysis_worker", "_extract_mitre")
            return extract({"malware_report": mr, "stix_bundle_extended": mr.get("stix_bundle")})

        _render(mode, stored, report, mr, stix=_stix, judge=_judge, mitre=_mitre)
    return mode


def platform_tree() -> str:
    """Where the platform this process renders with was imported from."""
    for package in _packages():
        try:
            found = importlib.import_module(package)
        except ModuleNotFoundError:
            continue
        return str(Path(str(found.__file__)).resolve().parents[2])
    return ""


def imported_from() -> dict[str, str | None]:
    """The directory each package the render reads was imported from, by name.

    The API (``app``) and the replay scripts (``scripts.replay``); ``None`` for
    one this tree does not hold. The platform's is the record's ``tree``.
    """
    out: dict[str, str | None] = {}
    for name in ("app", "scripts.replay"):
        try:
            found = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            missing = str(exc.name or "")
            if name != missing and not name.startswith(f"{missing}."):
                raise  # a module the package imports is missing: a broken tree
            out[name] = None
            continue
        at = getattr(found, "__file__", None)
        if at:
            out[name] = str(Path(at).resolve().parent)
        else:
            # A namespace package: each of its directories is said.
            out[name] = os.pathsep.join(str(Path(p).resolve()) for p in found.__path__)
    return out


def render_run(
    run_dir: Path, *, modes: Sequence[str] = MODES, work: Path | None = None
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    """One stored run's surface record under the tree this process imports, and its files.

    Every file of ``run_dir`` is digested before and after; a run changed while
    it was rendered raises ``RuntimeError``. Nothing is written but, when this
    process renders under no tree named to it and ``work`` is given, an ATT&CK
    cache of the render's own in a folder under ``work``, removed at the end.
    """
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FileNotFoundError(f"no stored run at {run_dir}")
    before = _digests(run_dir)
    stored = _Stored(run_dir)
    done: list[_Mode] = []
    # A cache of the render's own, as the replay keeps one: the machine's ATT&CK
    # cache is neither read nor written. A render under a named tree is given
    # one by its caller (:func:`render_under`); without ``work`` the replay
    # guard's own is the one read.
    cache = None
    if work is not None and not os.environ.get(TREE_VARIABLE):
        work.mkdir(parents=True, exist_ok=True)
        cache = tempfile.mkdtemp(prefix="attck-cache-", dir=work)
    previous = os.environ.get(ATTCK_CACHE_VARIABLE)
    if cache is not None:
        os.environ[ATTCK_CACHE_VARIABLE] = cache
    try:
        for name in modes:
            done.append(_serve(stored) if name == "serve" else _build(run_dir, stored))
    finally:
        if previous is None:
            os.environ.pop(ATTCK_CACHE_VARIABLE, None)
        else:
            os.environ[ATTCK_CACHE_VARIABLE] = previous
        if cache is not None:
            shutil.rmtree(cache, ignore_errors=True)
    if _digests(run_dir) != before:
        raise RuntimeError(f"the stored run {run_dir} changed while it was rendered")
    for mode in done:
        file_line_units(mode.files, mode.units)
    record = {
        "schema": SCHEMA,
        # A repeat's directory is named by its number alone: the run is named with its parent.
        "run": f"{run_dir.parent.name}/{run_dir.name}" if run_dir.name.isdigit() else run_dir.name,
        "path": str(run_dir),
        "tree": platform_tree(),
        "imported_from": imported_from(),
        "modes": list(modes),
        # The string hash seed the process ran under; "random" when none was set.
        "hash_seed": os.environ.get(HASH_SEED_VARIABLE) or "random",
        "report_source": stored.report_source if stored.report is not None else None,
        "limits": list(LIMITS),
        "excluded": [list(row) for row in EXCLUDED],
        "units": [row for mode in done for row in mode.units.rows],
        # Each rendered file's digest: a file that differs is a change of its own.
        "file_digests": {
            mode.mode: {name: digest(text) for name, text in sorted(mode.files.items())}
            for mode in done
        },
        "not_produced": [row for mode in done for row in mode.not_produced],
    }
    return record, {mode.mode: mode.files for mode in done}


def counts(record: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    """Units per mode and surface."""
    out: dict[str, dict[str, int]] = {}
    for row in record.get("units") or []:
        per = out.setdefault(str(row["mode"]), {})
        per[row["surface"]] = per.get(row["surface"], 0) + 1
    return out


# ---------------------------------------------------------------------------
# Two records compared, and the expectations
# ---------------------------------------------------------------------------


def _change(row_a: Mapping[str, Any] | None, row_b: Mapping[str, Any] | None) -> dict[str, Any]:
    row = row_a or row_b or {}
    kind = "changed" if row_a and row_b else "removed" if row_a else "added"
    return {
        "change": kind,
        "mode": row.get("mode"),
        "surface": row.get("surface"),
        "group": row.get("group") or "",
        "key": (row_b or row_a or {}).get("key"),
        "old": row_a.get("text") if row_a else None,
        "new": row_b.get("text") if row_b else None,
    }


def compare_records(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    """Every unit changed, added or removed between two records of one run.

    Every unit is compared, those marked dynamic too: both refs rebuild them
    from the same stored ledger without the sandbox report, so a difference
    between them is the trees'. A surface neither side produced is listed
    under ``not_compared`` with both reasons and counted in ``neither``.
    """
    changes: list[dict[str, Any]] = []
    rows_a = list(a.get("units") or [])
    rows_b = list(b.get("units") or [])
    # Each unit marked dynamic on either side, counted once.
    dynamic = len(
        {(r["mode"], r["surface"], r["key"]) for r in [*rows_a, *rows_b] if r.get("dynamic")}
    )
    keyed_a = {
        (r["mode"], r["surface"], r["key"]): r for r in rows_a if r["surface"] not in ORDERED
    }
    keyed_b = {
        (r["mode"], r["surface"], r["key"]): r for r in rows_b if r["surface"] not in ORDERED
    }
    for key in sorted(keyed_a.keys() | keyed_b.keys()):
        row_a, row_b = keyed_a.get(key), keyed_b.get(key)
        if row_a is None or row_b is None or row_a["text"] != row_b["text"]:
            changes.append(_change(row_a, row_b))
    groups: dict[tuple[str, str, str], tuple[list[Any], list[Any]]] = {}
    for side, rows in ((0, rows_a), (1, rows_b)):
        for row in rows:
            if row["surface"] in ORDERED:
                groups.setdefault((row["mode"], row["surface"], row["group"]), ([], []))[
                    side
                ].append(row)
    for key in sorted(groups):
        seq_a, seq_b = groups[key]
        matcher = difflib.SequenceMatcher(
            None, [r["text"] for r in seq_a], [r["text"] for r in seq_b], autojunk=False
        )
        for op, i1, i2, j1, j2 in matcher.get_opcodes():
            if op == "equal":
                continue
            olds, news = seq_a[i1:i2], seq_b[j1:j2]
            for index in range(max(len(olds), len(news))):
                changes.append(
                    _change(
                        olds[index] if index < len(olds) else None,
                        news[index] if index < len(news) else None,
                    )
                )
    changes += _file_changes(a, b)
    compared: dict[str, int] = {}
    for mode, surface, _key in {(r["mode"], r["surface"], r["key"]) for r in [*rows_a, *rows_b]}:
        compared[f"{mode} {surface}"] = compared.get(f"{mode} {surface}", 0) + 1
    files_a, files_b = a.get("file_digests") or {}, b.get("file_digests") or {}
    for mode in set(files_a) & set(files_b):
        compared[f"{mode} {FILE_SURFACE}"] = len(set(files_a[mode]) | set(files_b[mode]))
    reasons_a = {(r["mode"], r["surface"]): r for r in a.get("not_produced") or []}
    reasons_b = {(r["mode"], r["surface"]): r for r in b.get("not_produced") or []}
    not_compared = [
        {
            "mode": key[0],
            "surface": key[1],
            "a": (reasons_a.get(key) or {}).get("reason"),
            "b": (reasons_b.get(key) or {}).get("reason"),
            # Produced by neither side: nothing of it was compared at all.
            "neither": key in reasons_a and key in reasons_b,
        }
        for key in sorted(reasons_a.keys() | reasons_b.keys())
    ]
    # Absent from both, for reasons that differ: not absent alike, so a change.
    # What a route served is compared in its own units (``http``) besides.
    for row in not_compared:
        if row["neither"] and row["a"] != row["b"]:
            changes.append(
                {
                    "change": "changed",
                    "mode": row["mode"],
                    "surface": row["surface"],
                    "group": "not produced",
                    "key": "(not produced)",
                    "old": row["a"],
                    "new": row["b"],
                }
            )
    errors = [
        {"side": side, **row}
        for side, rows in (("a", a.get("not_produced")), ("b", b.get("not_produced")))
        for row in rows or []
        if row.get("error")
    ]
    out: dict[str, Any] = {"run": a.get("run") or b.get("run"), "changes": changes}
    out["summary"] = _summary(changes)
    out["compared"] = dict(sorted(compared.items()))
    out["dynamic_compared"] = dynamic
    out["neither"] = sum(1 for row in not_compared if row["neither"])
    if not_compared:
        out["not_compared"] = not_compared
    if errors:
        out["errors"] = errors
    return out


def _file_changes(a: Mapping[str, Any], b: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Each rendered file that differs, or is on one side only, whatever else changed in it.

    A change on another surface never stands for the file: its every line is a
    unit of ``file.lines`` besides, so what changed in it is said line by line.
    """
    out: list[dict[str, Any]] = []
    digests_a = a.get("file_digests") or {}
    digests_b = b.get("file_digests") or {}
    for mode in sorted(set(digests_a) & set(digests_b)):
        held_a, held_b = digests_a[mode], digests_b[mode]
        for name in sorted(set(held_a) | set(held_b)):
            old, new = held_a.get(name), held_b.get(name)
            if old == new:
                continue
            out.append(
                {
                    "change": "changed" if old and new else "removed" if old else "added",
                    "mode": mode,
                    "surface": FILE_SURFACE,
                    "group": "the file differs",
                    "key": name,
                    "old": f"sha256:{old}" if old else None,
                    "new": f"sha256:{new}" if new else None,
                }
            )
    return out


def first_difference(old: str, new: str) -> tuple[str, str]:
    """The first line at which two texts differ, each side said with its line number."""
    lines_a, lines_b = old.splitlines(), new.splitlines()
    for index in range(max(len(lines_a), len(lines_b))):
        line_a = lines_a[index] if index < len(lines_a) else None
        line_b = lines_b[index] if index < len(lines_b) else None
        if line_a != line_b:
            return (
                f"line {index + 1}: {line_a if line_a is not None else '(no line)'}",
                f"line {index + 1}: {line_b if line_b is not None else '(no line)'}",
            )
    return ("the same lines; the line ends differ", "the same lines; the line ends differ")


def _summary(changes: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for change in changes:
        per = out.setdefault(f"{change['mode']} {change['surface']}", {})
        per[change["change"]] = per.get(change["change"], 0) + 1
    return dict(sorted(out.items()))


def read_expectations(path: Path) -> list[dict[str, Any]]:
    """The expected changes in ``path``, each checked to name a surface, a pattern and a reason."""
    found = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(found, dict):
        found = found.get("expectations")
    if not isinstance(found, list):
        raise ValueError(f"{path} holds no list of expectations")
    out: list[dict[str, Any]] = []
    for index, row in enumerate(found):
        if not isinstance(row, dict) or not row.get("surface") or not row.get("reason"):
            raise ValueError(f"expectation {index} names no surface or no reason")
        if not any(row.get(name) for name in ("key", "old", "new")):
            raise ValueError(f"expectation {index} names no key, old or new pattern")
        for name in ("key", "old", "new"):
            if row.get(name):
                re.compile(str(row[name]))
        out.append({**row, "index": index})
    return out


def _matches(expectation: Mapping[str, Any], change: Mapping[str, Any]) -> bool:
    if expectation["surface"] != change["surface"]:
        return False
    if expectation.get("mode") and expectation["mode"] != change["mode"]:
        return False
    for name, said in (("key", change["key"]), ("old", change["old"]), ("new", change["new"])):
        pattern = expectation.get(name)
        if pattern and (said is None or re.search(str(pattern), str(said)) is None):
            return False
    return True


def judge_changes(
    diffs: Sequence[dict[str, Any]], expectations: Sequence[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], list[Mapping[str, Any]]]:
    """Mark each change expected or not; return the unexpected and the unexercised expectations."""
    used: set[int] = set()
    unexpected: list[dict[str, Any]] = []
    for diff in diffs:
        for change in diff["changes"]:
            hit = next((e for e in expectations if _matches(e, change)), None)
            if hit is None:
                change["expected"] = False
                unexpected.append({"run": diff["run"], **change})
            else:
                change["expected"] = True
                change["reason"] = hit["reason"]
                used.add(int(hit["index"]))
    unexercised = [e for e in expectations if int(e["index"]) not in used]
    return unexpected, unexercised


# ---------------------------------------------------------------------------
# The two refs
# ---------------------------------------------------------------------------


def render_under(
    tree: Path,
    runs: Sequence[Path],
    out: Path,
    *,
    modes: Sequence[str] = MODES,
    timeout: float | None = None,
    hash_seed: str | None = None,
) -> list[dict[str, Any]]:
    """This driver run against ``tree`` in a process of its own; the records it wrote.

    ``tree`` and its API come first on the import path and nothing of this
    checkout is put on it, so every entry point is the tree's own. The process
    hashes strings with ``hash_seed``, else with the seed this process's
    environment names, else with a random one; its stores are
    :data:`CLOSED_STORES`. Its temporary directory is a folder beside ``out``,
    removed when it ends, so nothing it makes lands in the system's.
    """
    from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME

    env = {**os.environ, **CLOSED_STORES}
    env["PYTHONPATH"] = os.pathsep.join([str(tree / "src"), str(tree / "apps" / "api"), str(tree)])
    env[TREE_VARIABLE] = str(tree.resolve())
    if hash_seed is not None:
        env[HASH_SEED_VARIABLE] = hash_seed
    env[PACKAGES_VARIABLE] = f"{CURRENT_NAME},{PREVIOUS_NAME}"
    cache = out.with_name(f"{out.name}-attck")
    cache.mkdir(parents=True, exist_ok=True)
    env[ATTCK_CACHE_VARIABLE] = str(cache.resolve())
    previous = PREVIOUS_NAME.upper() + ATTCK_CACHE_VARIABLE.removeprefix(CURRENT_NAME.upper())
    env[previous] = str(cache.resolve())
    temporary = out.with_name(f"{out.name}-tmp")
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir(parents=True)
    env["TMPDIR"] = str(temporary.resolve())
    if out.exists():
        shutil.rmtree(out)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        *(str(Path(run).resolve()) for run in runs),
        "--out",
        str(out.resolve()),
        "--quiet",
        *(f"--mode={mode}" for mode in modes),
    ]
    try:
        done = subprocess.run(  # nosec B603 — this driver, an argument list
            command, env=env, cwd=tree, capture_output=True, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"the render under {tree} did not finish within {timeout:g} s and was stopped"
        ) from exc
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    record_file = out / RECORD_FILE
    if done.returncode not in (0, 2) or not record_file.is_file():
        kept = out.with_name(f"{out.name}-stderr.txt")
        kept.write_bytes(done.stderr)
        raise RuntimeError(
            f"the render under {tree} wrote no record (exit status {done.returncode}; its error "
            f"output is kept in {kept})"
        )
    records = json.loads(record_file.read_text(encoding="utf-8"))
    for record in records:
        check_imports(record, tree)
    return list(records)


def check_imports(record: Mapping[str, Any], tree: Path) -> None:
    """Raise ``RuntimeError`` unless the record's packages were all imported from ``tree``.

    The platform, the API and the replay scripts; a package the tree does not
    hold passes as absent.
    """
    root = tree.resolve()
    if Path(str(record.get("tree") or "")).resolve() != root:
        raise RuntimeError(
            f"the render under {tree} imported its platform from {record.get('tree')}"
        )
    found = record.get("imported_from")
    if not isinstance(found, Mapping):
        raise RuntimeError(f"the render under {tree} did not say where it imported its API from")
    for name in ("app", "scripts.replay"):
        if name not in found:
            raise RuntimeError(f"the render under {tree} did not say where it imported {name} from")
        if found[name] is None:
            continue
        for at in str(found[name]).split(os.pathsep):
            where = Path(at).resolve()
            if where != root and root not in where.parents:
                raise RuntimeError(f"the render under {tree} imported {name} from {at}")


def _show_file_changes(diff: Mapping[str, Any], at_a: Path, at_b: Path) -> None:
    """Each changed file's first differing line beside its digests, read from the files written."""
    for change in diff["changes"]:
        if change["surface"] != FILE_SURFACE or change["change"] != "changed":
            continue
        try:
            old = (at_a / change["mode"] / change["key"]).read_text(encoding="utf-8")
            new = (at_b / change["mode"] / change["key"]).read_text(encoding="utf-8")
        except OSError:
            continue
        line_a, line_b = first_difference(old, new)
        change["old"] = f"{change['old']}; {line_a}"
        change["new"] = f"{change['new']}; {line_b}"


def draw_hash_seeds() -> tuple[str, str]:
    """Two different string hash seeds, drawn afresh: neither is pinned."""
    import random

    first, second = random.SystemRandom().sample(range(1, 2**32), 2)
    return str(first), str(second)


def only_modes(record: Mapping[str, Any], modes: Iterable[str]) -> dict[str, Any]:
    """``record`` with the units, files and reasons of ``modes`` alone."""
    kept = set(modes)
    return {
        **record,
        "modes": [m for m in record.get("modes") or [] if m in kept],
        "units": [r for r in record.get("units") or [] if r["mode"] in kept],
        "file_digests": {m: d for m, d in (record.get("file_digests") or {}).items() if m in kept},
        "not_produced": [r for r in record.get("not_produced") or [] if r["mode"] in kept],
    }


def _unit_path(change: Mapping[str, Any]) -> tuple[str, str, str]:
    return (str(change["mode"]), str(change["surface"]), str(change["key"]))


def seed_dependent(
    first: Mapping[str, Any], second: Mapping[str, Any]
) -> set[tuple[str, str, str]]:
    """Each unit (mode, surface, unit path) that differs between two hash seeds of one ref.

    ``second`` is rendered under the other seed, in the modes it lists; the
    units of ``first`` in those modes are compared with it as two refs are.
    """
    diff = compare_records(only_modes(first, second.get("modes") or []), second)
    return {_unit_path(c) for c in diff["changes"]}


def apply_hash_seeds(
    diff: dict[str, Any],
    seeds: tuple[str, str],
    a: Mapping[str, Any],
    a2: Mapping[str, Any],
    b: Mapping[str, Any],
    b2: Mapping[str, Any],
) -> None:
    """Class the units whose order depends on the hash seed, and keep every real difference.

    ``a``, ``b``: the refs' records under the first seed (``diff`` compares
    them); ``a2``, ``b2``: under the second, in build mode. A unit that differs
    between the two seeds of one ref is listed as :data:`SEED_CLASS`; a
    difference between the refs in such a unit is left out of the comparison
    only when the refs agree under the second seed, and kept when they differ
    under both. A surface that raised under the second seed is an error.
    """
    under_a, under_b = seed_dependent(a, a2), seed_dependent(b, b2)
    classed = under_a | under_b
    second = {_unit_path(c) for c in compare_records(a2, b2)["changes"]}
    kept: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for change in diff["changes"]:
        path = _unit_path(change)
        (excluded if path in classed and path not in second else kept).append(change)
    diff["changes"] = kept
    diff["summary"] = _summary(kept)
    diff["hash_seed"] = {
        "class": SEED_CLASS,
        "seeds": list(seeds),
        "a": [{"mode": m, "surface": s, "key": k} for m, s, k in sorted(under_a)],
        "b": [{"mode": m, "surface": s, "key": k} for m, s, k in sorted(under_b)],
        "excluded": excluded,
    }
    errors = [
        {"side": f"{side} (second seed)", **row}
        for side, record in (("a", a2), ("b", b2))
        for row in record.get("not_produced") or []
        if row.get("error")
    ]
    if errors:
        diff["errors"] = [*(diff.get("errors") or []), *errors]


def _compare(
    runs: list[Path],
    refs: tuple[str, str],
    *,
    repo: Path,
    work: Path | None,
    timeout: float | None,
    modes: Sequence[str] = MODES,
    hash_seeds: tuple[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Both refs rendered and compared; build mode under two hash seeds per ref, the same two.

    Every mode is rendered under the first seed; build mode once more under
    the second, and the units that differ between the two seeds of one ref
    are classed (:func:`apply_hash_seeds`).
    """
    from scripts.replay import compare

    seeds = hash_seeds or draw_hash_seeds()
    twice = [mode for mode in modes if mode == "build"]
    owned = work is None
    base = Path(tempfile.mkdtemp(prefix="malspark-surfaces-")) if work is None else work
    try:
        records: dict[str, list[dict[str, Any]]] = {}
        seconds: dict[str, list[dict[str, Any]]] = {}
        for side, ref in zip(("a", "b"), refs, strict=True):
            tree = compare.materialise(repo, ref, base / f"{side}-tree", harness=None)
            records[side] = render_under(
                tree, runs, base / f"{side}-out", modes=modes, timeout=timeout, hash_seed=seeds[0]
            )
            if twice:
                seconds[side] = render_under(
                    tree,
                    runs,
                    base / f"{side}-out-seed2",
                    modes=twice,
                    timeout=timeout,
                    hash_seed=seeds[1],
                )
        diffs: list[dict[str, Any]] = []
        for index, (a, b) in enumerate(zip(records["a"], records["b"], strict=True)):
            diff = compare_records(a, b)
            if twice:
                apply_hash_seeds(diff, seeds, a, seconds["a"][index], b, seconds["b"][index])
            _show_file_changes(
                diff, base / "a-out" / str(a.get("files")), base / "b-out" / str(b.get("files"))
            )
            diffs.append(diff)
        return diffs
    finally:
        if owned:
            shutil.rmtree(base, ignore_errors=True)


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def _safe(text: Any) -> str:
    try:
        from scripts.replay.output import terminal_safe
    except Exception:  # noqa: BLE001 — a tree without it: shown escaped all the same
        return str(text).encode("unicode_escape").decode("ascii")
    return terminal_safe(text)


def render_comparison(
    diffs: Sequence[Mapping[str, Any]],
    refs: tuple[str, str],
    unexercised: Sequence[Mapping[str, Any]],
) -> str:
    """The comparison as text: per run, the changes grouped by surface, then the counts."""
    ref_a, ref_b = refs
    lines: list[str] = []
    for diff in diffs:
        lines.append(f"run {_safe(diff['run'])}: {ref_a} -> {ref_b}")
        by_surface: dict[str, list[Mapping[str, Any]]] = {}
        for change in diff["changes"]:
            by_surface.setdefault(f"{change['mode']} {change['surface']}", []).append(change)
        for surface, changes in sorted(by_surface.items()):
            lines.append(f"  [{surface}]")
            for change in changes:
                mark = "expected" if change.get("expected") else "UNEXPECTED"
                where = f"{change['group']} | " if change["group"] else ""
                lines.append(f"    {change['change'].upper()} {mark}: {_safe(where)}")
                lines.append(f"      key: {_safe(change['key'])}")
                if change["old"] is not None:
                    lines.append(f"      - {_safe(change['old'])}")
                if change["new"] is not None:
                    lines.append(f"      + {_safe(change['new'])}")
                if change.get("reason"):
                    lines.append(f"      reason: {_safe(change['reason'])}")
        for row in diff.get("not_compared") or []:
            if row.get("neither"):
                lines.append(
                    f"  NOT COMPARED [{row['mode']} {row['surface']}]: produced by neither ref: "
                    f"A: {_safe(row['a'])}; B: {_safe(row['b'])}"
                )
            else:
                lines.append(
                    f"  PRODUCED BY ONE REF [{row['mode']} {row['surface']}]: A: "
                    f"{_safe(row['a'] or 'produced')}; B: {_safe(row['b'] or 'produced')}"
                )
        for row in diff.get("errors") or []:
            lines.append(
                f"  ERROR under {row['side'].upper()} [{row['mode']} {row['surface']}]: "
                f"{_safe(row['reason'])}"
            )
        seeded = diff.get("hash_seed")
        if seeded:
            first, second = seeded["seeds"]
            lines.append(
                f"  {seeded['class'].upper()} (build mode rendered under the seeds {first} and "
                f"{second}): {len(seeded['a'])} unit(s) under A, {len(seeded['b'])} under B; "
                f"{len(seeded['excluded'])} difference(s) between the refs in them left out, "
                "each because the refs agree under the other seed"
            )
            for side in ("a", "b"):
                for row in seeded[side]:
                    lines.append(
                        f"    {side.upper()} [{row['mode']} {row['surface']}] {_safe(row['key'])}"
                    )
        if diff.get("dynamic_compared"):
            lines.append(
                f"  {diff['dynamic_compared']} unit(s) marked dynamic (drawn without the sandbox "
                "report) compared"
            )
        total = sum(sum(per.values()) for per in diff["summary"].values())
        unexpected = sum(1 for c in diff["changes"] if not c.get("expected"))
        neither = int(diff.get("neither") or 0)
        compared: Mapping[str, int] = diff.get("compared") or {}
        lines.append(
            f"  summary: {sum(compared.values())} unit(s) compared on {len(compared)} "
            f"surface(s), {total} difference(s), {unexpected} unexpected, "
            f"{neither} surface(s) not compared"
        )
        for surface in sorted(set(compared) | set(diff["summary"])):
            per = diff["summary"].get(surface) or {}
            said = ", ".join(f"{k} {v}" for k, v in sorted(per.items())) or "no difference"
            lines.append(f"    {surface}: {compared.get(surface, 0)} compared, {said}")
        if EXCLUDED:
            for surface, what, proof in EXCLUDED:
                lines.append(f"  excluded [{surface}] {what}: {proof}")
        else:
            lines.append(
                "  excluded from the comparison: nothing"
                + (f", but the units {SEED_CLASS} listed above" if seeded else "")
            )
        if not diff["changes"] and not neither:
            lines.append("  no difference: both refs render the same units")
        elif not diff["changes"]:
            lines.append(
                f"  no difference in the units compared; {neither} surface(s) produced by "
                "neither ref were not compared (listed above)"
            )
    for expectation in unexercised:
        lines.append(
            f"UNEXERCISED expectation {expectation['index']} [{_safe(expectation['surface'])}]: "
            f"{_safe(expectation['reason'])}: no difference matched it"
        )
    return "\n".join(lines)


class _HelpFormatter(argparse.HelpFormatter):
    """The help wrapped at spaces only: a path or a name with a hyphen in it stays whole."""

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        import textwrap

        return textwrap.fill(
            " ".join(text.split()),
            width,
            initial_indent=indent,
            subsequent_indent=indent,
            break_on_hyphens=False,
            break_long_words=False,
        )

    def _split_lines(self, text: str, width: int) -> list[str]:
        import textwrap

        return textwrap.wrap(
            " ".join(text.split()), width, break_on_hyphens=False, break_long_words=False
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/replay/render_surfaces.py",
        formatter_class=_HelpFormatter,
        description=(
            "Render every published surface of stored runs, at zero cost, in two modes (serve: "
            "the stored report rendered as the API renders it; build: the report the replay "
            "rebuilds, rendered and exported), and compare two git refs unit by unit."
        ),
        epilog=(
            "Every value of every surface is compared, every line of every rendered file is a "
            "unit (file.lines), and a rendered file that differs is a change of its own "
            "whatever else changed in it. Excluded from the comparison: "
            + ("; ".join(f"[{s}] {what}: {proof}" for s, what, proof in EXCLUDED) or "nothing")
            + ". Limits: "
            + " ".join(f"({n}) {limit}." for n, limit in enumerate(LIMITS, 1))
        ),
    )
    parser.add_argument("runs", nargs="+", type=Path, help="stored run directories")
    parser.add_argument(
        "--out", type=Path, help="write the surface record and the rendered files here"
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("REF_A", "REF_B"),
        help="render under two git refs and list every unit changed, added or removed",
    )
    parser.add_argument("--expect", type=Path, help="the expected changes (JSON), with --compare")
    parser.add_argument("--json", type=Path, help="write the comparison here, with --compare")
    parser.add_argument(
        "--work", type=Path, help="where --compare writes the trees (temporary by default)"
    )
    parser.add_argument(
        "--repo", type=Path, default=_ROOT, help="the repository the refs are read from"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        metavar="SECONDS",
        help="how long each render may take (a ref is rendered once per hash seed)",
    )
    parser.add_argument(
        "--hash-seeds",
        nargs=2,
        type=int,
        metavar=("SEED_1", "SEED_2"),
        help=(
            "with --compare: the two string hash seeds build mode is rendered under, the same "
            "for both refs (two drawn afresh by default, and printed)"
        ),
    )
    parser.add_argument(
        "--mode", choices=MODES, action="append", help="render one mode only (both by default)"
    )
    parser.add_argument(
        "--accept-not-compared",
        action="store_true",
        help=(
            "with --compare: a surface both refs lack for the same reason (listed NOT COMPARED "
            f"with both reasons) does not end the comparison with status {EXIT_NOT_COMPARED}; "
            "one they lack for different reasons, or whose served status or error differs, is "
            "a difference all the same"
        ),
    )
    parser.add_argument("--quiet", action="store_true", help="print nothing; write files only")
    return parser


def comparison_status(
    diffs: Sequence[Mapping[str, Any]],
    unexpected: Sequence[Any],
    unexercised: Sequence[Any],
    *,
    accept_not_compared: bool = False,
) -> int:
    """The comparison's exit status, the first that applies of :data:`EXIT_STATUSES`."""
    if any(diff.get("errors") for diff in diffs):
        return EXIT_ERROR
    if unexpected:
        return EXIT_UNEXPECTED
    if not accept_not_compared and any(diff.get("neither") for diff in diffs):
        return EXIT_NOT_COMPARED
    if unexercised:
        return EXIT_UNEXERCISED
    return 0


def _error(words: str) -> NoReturn:
    print(f"render_surfaces: {_safe(words)}", file=sys.stderr)
    raise SystemExit(2)


def _outside(path: Path, runs: Sequence[Path]) -> None:
    target = path.resolve()
    for run in runs:
        if target == run.resolve() or run.resolve() in target.parents:
            _error(f"refused: {path} is inside the stored run {run}")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8", "backslashreplace"))


def rendered_tree() -> Path:
    """The tree this process renders under: the one named to it, else this checkout."""
    named = os.environ.get(TREE_VARIABLE)
    return Path(named).resolve() if named else _ROOT


def write_out(out: Path, runs: Sequence[Path], modes: Sequence[str]) -> list[dict[str, Any]]:
    """Each run rendered into ``out``: the records in ``surfaces.json``, the files per run.

    The record is written, then each is checked to have imported the
    platform, the API and the replay scripts from the tree rendered under
    (:func:`check_imports`): ``RuntimeError`` when one came from elsewhere.
    """
    out.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for index, run in enumerate(runs):
        record, files = render_run(run, modes=modes, work=out)
        name = f"{index:02d}-{re.sub(r'[^A-Za-z0-9._-]+', '-', record['run'])}"
        for mode, rendered in files.items():
            for file_name, text in rendered.items():
                _write_text(out / name / mode / file_name, text)
        record["files"] = name
        records.append(record)
    _write_text(out / RECORD_FILE, json.dumps(records, indent=1, ensure_ascii=True) + "\n")
    for record in records:
        check_imports(record, rendered_tree())
    return records


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    runs = [Path(run) for run in args.runs]
    for run in runs:
        if not run.is_dir():
            _error(f"no stored run at {run}")
    for written in (args.out, args.json, args.work):
        if written is not None:
            _outside(written, runs)
    modes = tuple(args.mode or MODES)
    if args.compare:
        expectations: list[dict[str, Any]] = []
        if args.expect is not None:
            try:
                expectations = read_expectations(args.expect)
            except (OSError, ValueError) as exc:
                _error(f"the expectations cannot be read: {exc}")
        seeds: tuple[str, str] | None = None
        if args.hash_seeds is not None:
            first, second = args.hash_seeds
            if first == second or not all(0 <= s < 2**32 for s in args.hash_seeds):
                _error("--hash-seeds takes two different seeds from 0 to 4294967295")
            seeds = (str(first), str(second))
        try:
            diffs = _compare(
                runs,
                (args.compare[0], args.compare[1]),
                repo=args.repo,
                work=args.work,
                timeout=args.timeout,
                modes=modes,
                hash_seeds=seeds,
            )
        except Exception as exc:  # noqa: BLE001 — said, and the status says it failed
            _error(str(exc))
        unexpected, unexercised = judge_changes(diffs, expectations)
        if args.json is not None:
            _write_text(
                args.json,
                json.dumps({"runs": diffs, "unexercised": unexercised}, indent=1, ensure_ascii=True)
                + "\n",
            )
        if not args.quiet:
            print(render_comparison(diffs, (args.compare[0], args.compare[1]), unexercised))
        return comparison_status(
            diffs, unexpected, unexercised, accept_not_compared=args.accept_not_compared
        )
    if args.out is None:
        parser.error("name --out DIR, or --compare REF_A REF_B")
    try:
        records = write_out(args.out, runs, modes)
    except RuntimeError as exc:
        _error(f"refused: {exc}")
    raised = [row for record in records for row in record["not_produced"] if row.get("error")]
    if not args.quiet:
        for record in records:
            print(f"run {_safe(record['run'])}: {args.out / record['files']}")
            for mode, per in counts(record).items():
                print(f"  {mode}: " + ", ".join(f"{s} {n}" for s, n in sorted(per.items())))
            dynamic = sum(1 for row in record["units"] if row.get("dynamic"))
            if dynamic:
                print(
                    f"  note: {dynamic} unit(s) marked dynamic: the build drew them without the "
                    "sandbox report, so read against the stored report they differ"
                )
            for row in record["not_produced"]:
                mark = "ERROR " if row.get("error") else ""
                print(
                    f"  {mark}not produced [{row['mode']} {row['surface']}]: {_safe(row['reason'])}"
                )
    return 2 if raised else 0


def _prepare_path() -> None:
    """The tree rendered under first on the import path, and nothing outside it that competes.

    The tree is the one named in :data:`TREE_VARIABLE`, else this checkout:
    its root, its ``src`` and its API come before every other entry, so an
    editable install of another checkout is never what is imported, and every
    entry outside the tree that holds the platform, the API or the scripts is
    taken off, so a module the tree lacks is a module not found.
    """
    here = Path(__file__).resolve().parent
    root = rendered_tree()
    first = [str(root / "src"), str(root / "apps" / "api"), str(root)]
    sys.path[:] = first + [
        p for p in sys.path if p not in first and Path(p or ".").resolve() != here
    ]
    names = (*_packages(), "app", "scripts")

    def _foreign(entry: str) -> bool:
        at = Path(entry or ".").resolve()
        if at == root or root in at.parents or {"site-packages", "dist-packages"} & set(at.parts):
            return False
        return any((at / name).is_dir() for name in names)

    sys.path[:] = [p for p in sys.path if not _foreign(p)]


if __name__ == "__main__":
    # A store no dependency override answers is a closed port, never one configured.
    os.environ.update(CLOSED_STORES)
    _prepare_path()
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — said, and the status says it failed
        print(f"render_surfaces failed: {_where(exc)}", file=sys.stderr)
        sys.exit(2)
