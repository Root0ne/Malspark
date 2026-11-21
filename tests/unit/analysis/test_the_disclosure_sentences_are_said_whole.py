"""Each sentence of the disclosure block is said whole, in every form its row gives it.

The block of Appendix B (``disclosure_lines``) and the analyst report's row on
what left this machine (``left_the_machine``) are written from the stored
record alone. Each writer is pinned here word for word under each condition
that changes its words, and where it says nothing, that it says nothing, so
a changed word is a changed test (T-770). Every value here is made up.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from malspark.analysis.disclosure import (
    FOOTNOTE_SENTENCE,
    INTRO_SENTENCE,
    LEFT_THE_MACHINE_RECORD,
    RUNTIME_ASSUMPTION,
    STAGED_FILES,
    TRACING_SENTENCE,
    _again,
    _asked_parts,
    _counts,
    _enrichment_left,
    _enrichment_state_lines,
    _how,
    _lookup_line,
    _mark,
    _model_line,
    _not_recorded_line,
    _nothing_sentence,
    _partial_line,
    _reach,
    _server,
    _server_line,
    _short,
    _stayed_line,
    _store_line,
    _undeclared_line,
    _unreadable_line,
    _untold,
    _upload_line,
    _withheld_lines,
    disclosure_lines,
    left_the_machine,
    not_built,
    not_built_line,
)


def _code(text: str) -> str:
    return f"`{text}`"


REMOTE = {"where": "remote", "host": "far.example", "why": ""}
LOCAL = {"where": "local", "host": "127.0.0.1", "why": ""}
SERVICE = {"where": "local", "host": "tools", "why": ""}
UNPLACED = {"where": "unknown", "host": "", "why": "the record names no host"}
NAMED_UNPLACED = {"where": "unknown", "host": "10.0.0.5", "why": "it is a local gateway"}


# ---------------------------------------------------------------------------
# The pieces every sentence is made of
# ---------------------------------------------------------------------------


def test_a_host_is_marked_and_a_receiver_named_as_the_record_places_it() -> None:
    assert _mark(REMOTE) == "(outside this machine)"
    assert _mark(UNPLACED) == "(outside this machine)"
    assert _mark(SERVICE) == "(taken as local: a service name)"
    assert _mark(LOCAL) == "(local)"

    assert _untold(UNPLACED) == "; the record names no host, so where they went cannot be told"
    assert _untold({}, "it") == "; the record does not say, so where it went cannot be told"

    assert _counts({"judge": 2, "": 1}) == "judge 2, no agent 1"
    assert _again({"served": 2}) == " (+2 answered without a run)"
    assert _again({"served": 0}) == _again({}) == ""

    assert _server("mcp:intel", _code) == "tool server `intel`"
    assert _server("provider:ghidra", _code) == "the `ghidra` provider's tool server"
    assert _server("odd", _code) == "tool server `odd`"
    assert _server("", _code) == "a tool server"

    assert _how({"transport": "stdio"}) == "stdio, run on this machine"
    assert _how({"transport": "sse"}) == "sse"
    assert _how({}) == "transport not recorded"


def test_a_short_form_says_who_received_how_often_or_that_no_call_is_recorded() -> None:
    no_call = "no answered call recorded, so whether it received anything cannot be told"
    assert _short("Lookups", "`far.example`", " was asked once", REMOTE, 1) == (
        "Lookups: `far.example` was asked once."
    )
    assert _short("Lookups", "`far.example`", "", REMOTE, 0) == (
        f"Lookups: `far.example`: {no_call}."
    )
    assert _short("Model prompts", "", " 3 calls", UNPLACED, 0) == (
        f"Model prompts: {no_call}, destination not recorded."
    )
    assert _short("Model prompts", "", " 3 calls", UNPLACED, 3) == (
        "Model prompts: 3 calls, destination not recorded."
    )
    assert _short("Tool calls", "x", ": 1 call", NAMED_UNPLACED, 1, "; tail") == (
        "Tool calls: x: 1 call, where it runs is not recorded; tail."
    )
    assert _short("Case memory", "the store", "", REMOTE, None) == "Case memory: the store."


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def test_a_model_row_is_said_by_its_place_its_calls_and_its_runtime() -> None:
    answered = {
        **LOCAL,
        "calls": 3,
        "agents": {"static": 3},
        "configured_for": ["judge", "mediator"],
        "runtime": "llama.cpp /props",
    }
    assert _model_line(answered, _code) == (
        "Model prompts: `127.0.0.1` (local) received 3 calls (static 3); it answered as a model "
        "runtime (llama.cpp /props). It is also in the model list of judge and mediator, which "
        "recorded no answered call there."
    )
    assert _model_line({**answered, "runtime": "", "configured_for": []}, _code) == (
        "Model prompts: `127.0.0.1` (local) received 3 calls (static 3); a local address that "
        "did not answer as a model runtime may forward the prompts, so where they went cannot "
        "be told."
    )
    vendor = {"where": "remote", "host": "", "service": "a vendor API", "calls": 1, "agents": {}}
    assert _model_line(vendor, _code) == (
        "Model prompts: a vendor API (outside this machine) received 1 call."
    )
    lost = {**UNPLACED, "why": "the token ledger filed them under no model"}
    assert _model_line({**lost, "calls": 1, "agents": {"": 1}}, _code) == (
        "Model prompts: 1 call (no agent 1); the token ledger filed them under no model, so "
        "where it went cannot be told."
    )
    assert _model_line({**lost, "calls": 2}, _code) == (
        "Model prompts: 2 calls; the token ledger filed them under no model, so where they went "
        "cannot be told."
    )


def test_a_model_endpoint_with_no_answered_call_says_why_it_is_listed() -> None:
    listed = {**REMOTE, "calls": 0, "configured_for": ["judge"]}
    failed = (
        "; a request that failed is not always recorded, so whether it received prompts cannot "
        "be told."
    )
    assert _model_line({**listed, "global": True}, _code) == (
        "Model prompts: `far.example` (outside this machine) is the endpoint of the global "
        "model, which every agent without a model entry of its own calls, and in the model list "
        "of judge, which recorded no answered call there; no answered call is recorded there"
        + failed
    )
    assert _model_line({**listed, "global": True, "configured_for": []}, _code) == (
        "Model prompts: `far.example` (outside this machine) is the endpoint of the global "
        "model, which every agent without a model entry of its own calls; no answered call is "
        "recorded there" + failed
    )
    assert _model_line(listed, _code) == (
        "Model prompts: `far.example` (outside this machine) is in the model list of judge, "
        "which recorded no answered call there" + failed
    )
    assert _model_line({**listed, "configured_for": []}, _code) == (
        "Model prompts: `far.example` (outside this machine) is in no model list of an agent "
        "that called a model" + failed
    )
    runtime = {**LOCAL, "calls": 0, "configured_for": ["judge"], "runtime": "ollama /api/tags"}
    assert _model_line(runtime, _code) == (
        "Model prompts: `127.0.0.1` (local) is in the model list of judge, which recorded no "
        "answered call there; it answered as a model runtime (ollama /api/tags)."
    )


def test_a_model_row_s_short_form_names_the_receiver_and_the_calls_only() -> None:
    row = {**REMOTE, "calls": 4, "agents": {"judge": 4}, "configured_for": ["mediator"]}
    assert _model_line(row, _code, short=True) == (
        "Model prompts: `far.example` (outside this machine) received 4 calls."
    )
    service = {"where": "remote", "host": "", "service": "a vendor API", "calls": 1}
    assert _model_line(service, _code, short=True) == (
        "Model prompts: a vendor API (outside this machine) received 1 call."
    )
    assert _model_line({**UNPLACED, "calls": 2}, _code, short=True) == (
        "Model prompts: 2 calls, destination not recorded."
    )


# ---------------------------------------------------------------------------
# Lookups, tool servers, undeclared tools, calls that stayed
# ---------------------------------------------------------------------------


def test_a_lookup_row_says_who_was_asked_how_often_and_about_what() -> None:
    row = {
        **REMOTE,
        "source": "mcp:intel",
        "transport": "http",
        "calls": 3,
        "served": 1,
        "kinds": {"hash": 2},
        "without_indicator": 1,
    }
    assert _lookup_line(row, _code) == (
        "Lookups: `far.example` (outside this machine) was asked 3 times (+1 answered without a "
        "run) through tool server `intel` (http): hash 2, 1 giving no argument declared as an "
        "indicator."
    )
    unplaced = {**row, **NAMED_UNPLACED, "calls": 1, "served": 0, "without_indicator": 0}
    assert _lookup_line(unplaced, _code) == (
        "Lookups: tool server `intel` (http) at `10.0.0.5` was asked once: hash 2; it is a local "
        "gateway, so where they went cannot be told."
    )
    assert _lookup_line(row, _code, short=True) == (
        "Lookups: `far.example` (outside this machine) was asked 3 times: hash 2, 1 giving no "
        "argument declared as an indicator."
    )
    nameless = {**row, **UNPLACED, "calls": 1, "kinds": {}, "without_indicator": 0}
    assert _lookup_line(nameless, _code, short=True) == (
        "Lookups: tool server `intel` was asked once, destination not recorded."
    )


def test_a_tool_server_row_says_where_the_server_is_and_its_calls() -> None:
    row = {**REMOTE, "source": "mcp:far", "transport": "sse", "calls": 2, "served": 1}
    assert _server_line(row, _code) == (
        "Tool calls: tool server `far` over sse at `far.example` (outside this machine): "
        "2 calls (+1 answered without a run)."
    )
    gateway = {**row, **NAMED_UNPLACED, "transport": "http", "calls": 1, "served": 0}
    assert _server_line(gateway, _code) == (
        "Tool calls: tool server `far` (http) at `10.0.0.5`: 1 call; it is a local gateway, so "
        "where they went cannot be told."
    )
    assert _server_line(row, _code, short=True) == (
        "Tool calls: tool server `far` at `far.example` (outside this machine): 2 calls."
    )
    assert _server_line({**gateway, "host": ""}, _code, short=True) == (
        "Tool calls: tool server `far`: 1 call, destination not recorded."
    )


def test_calls_to_undeclared_tools_say_what_the_servers_hinted_and_stated() -> None:
    rows: list[dict[str, Any]] = [
        {"source": "mcp:a", "transport": "stdio", "calls": 2, "served": 1, "open_world_hints": 1},
        {"source": "mcp:b", "transport": "http", "calls": 1, "server_stated": 2},
    ]
    assert _undeclared_line(rows, _code) == (
        "Tool calls: 3 calls (+1 answered without a run) to tools that declare no effects (tool "
        "server `a` (stdio, run on this machine) 2, tool server `b` (http) 1): whether they "
        "reached the network cannot be told; the servers' own hints (openWorldHint) say 1 of "
        "them may reach it; for 2 of them the servers say more of their own tools, which no "
        "declaration the operator trusts says (the tool-effects part)."
    )
    assert _undeclared_line([{"source": "mcp:a", "transport": "stdio", "calls": 1}], _code) == (
        "Tool calls: 1 call to tools that declare no effects (tool server `a` (stdio, run on "
        "this machine) 1): whether they reached the network cannot be told."
    )


def test_the_calls_that_stayed_are_named_by_source_with_what_did_not_run() -> None:
    from malspark.agents.delegation import TEAM_SERVER

    rows = [
        {"source": "platform", "made": 2, "served": 0, "not_run": 0},
        {"source": TEAM_SERVER, "made": 1, "served": 1, "not_run": 1},
        {"source": "pack", "made": 0, "served": 1, "not_run": 0},
        {"source": "mcp:analysis", "made": 0, "served": 0, "not_run": 2},
    ]
    assert _stayed_line(rows, _code) == (
        "Tool calls that stayed on this machine: 3 calls (+2 answered without a run, 3 not run) "
        "(the platform's own tools 2, questions put to the team 1 (+1 answered without a run, "
        "1 not run), the platform's in-process source `pack` 1 answered without a run, tool "
        "server `analysis` 2 not run)."
    )
    assert _stayed_line([{"source": "pack", "made": 0, "served": 1, "not_run": 1}], _code) == (
        "Tool calls that stayed on this machine: 1 call answered without a run, 1 call not run "
        "(the platform's in-process source `pack` 1 answered without a run, 1 not run)."
    )


# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------


def test_each_upload_row_says_what_was_sent_to_whom_and_whether_it_arrived() -> None:
    sandbox = {**REMOTE, "by": "sandbox", "source": "triage", "calls": 2, "failed": 1}
    assert _upload_line(sandbox, _code) == (
        "Sample upload: the sample was submitted 2 times to the `triage` sandbox at "
        "`far.example` (outside this machine); 1 of the attempts failed or did not finish, so "
        "whether it arrived cannot be told."
    )
    unplaced = {**sandbox, **UNPLACED, "calls": 1, "failed": 0}
    assert _upload_line(unplaced, _code) == (
        "Sample upload: the sample was submitted once to the `triage` sandbox; the record names "
        "no host, so where it went cannot be told."
    )
    staged = {**REMOTE, "by": "staging", "source": "mcp:re", "transport": "http", "calls": 1}
    assert _upload_line(staged, _code) == (
        "Sample upload: the sample was staged once to tool server `re` (http) at `far.example` "
        "(outside this machine) through its put_sample tools, for its tools to read."
    )
    assert STAGED_FILES == {
        "artefact": "a file a tool wrote out of the sample",
        "capture": "the sandbox's packet capture",
        "sandbox_report": "the sandbox report",
    }
    assert _upload_line({**staged, "what": "capture", "failed": 2, "calls": 2}, _code) == (
        "Sample upload: the sandbox's packet capture was staged 2 times to tool server `re` "
        "(http) at `far.example` (outside this machine) through its put_sample tools, for its "
        "tools to read; 2 of the attempts failed or did not finish, so whether they arrived "
        "cannot be told."
    )
    assert _upload_line({**staged, "what": "dump"}, _code).startswith(
        "Sample upload: a file of the job (`dump`) was staged once to tool server `re` "
    )
    handed = {**UNPLACED, "by": "tool", "source": "mcp:vt", "transport": "stdio", "calls": 1}
    assert _upload_line({**handed, "served": 1}, _code) == (
        "Sample upload: tool server `vt` (stdio, run on this machine) was handed the sample once "
        "(+1 answered without a run) by a tool declared to send it out of the deployment; the "
        "record names no host, so where it went cannot be told."
    )


def test_a_submission_names_its_detonation_its_archive_and_its_launch_arguments() -> None:
    row = {
        **REMOTE,
        "by": "sandbox",
        "source": "cape2",
        "calls": 1,
        "detonation": "d2",
        "requested_by": ["reverser", "judge"],
        "launch_arguments": "--quiet",
        "launch_arguments_honoured": True,
        "launch_arguments_via": "arguments=",
        "launch_arguments_note": "passed as given",
        "launch_launcher": {
            "archive_sha256": "b" * 4,
            "sample_sha256": "a" * 4,
            "script_host": "PowerShell",
        },
    }
    assert _upload_line(row, _code) == (
        "Sample upload (detonation 2, asked for by reverser, judge): an archive (SHA-256 `bbbb`) "
        "holding the sample (SHA-256 `aaaa`) and a generated PowerShell launcher, not the bare "
        "sample, was submitted once to the `cape2` sandbox at `far.example` (outside this "
        "machine). The launch arguments an agent found `--quiet` were sent with the submission "
        "through arguments= (passed as given)."
    )
    own = {
        **REMOTE,
        "by": "sandbox",
        "source": "cape2",
        "calls": 1,
        "launch_arguments": "-x",
        "launch_launcher": {"archive_sha256": "c" * 4},
    }
    assert _upload_line(own, _code) == (
        "Sample upload: an archive (SHA-256 `cccc`) holding the sample (SHA-256 ``) and a "
        "generated script launcher, not the bare sample, was submitted once to the `cape2` "
        "sandbox at `far.example` (outside this machine). The job's launch arguments `-x` were "
        "requested and not honoured."
    )
    assert _upload_line({**own, "launch_arguments_note": "no field for them"}, _code).endswith(
        " The job's launch arguments `-x` were requested and not honoured: no field for them."
    )
    sent = {**own, "launch_arguments_honoured": True, "launch_launcher": {}}
    assert _upload_line(sent, _code).endswith(
        "the sample was submitted once to the `cape2` sandbox at `far.example` (outside this "
        "machine). The job's launch arguments `-x` were sent with the submission."
    )
    unobserved = {**sent, "launch_arguments_unobserved": True, "detonation": "x"}
    assert _upload_line(unobserved, _code) == (
        "Sample upload (detonation x, asked for by an agent): the sample was submitted once to "
        "the `cape2` sandbox at `far.example` (outside this machine). The launch arguments an "
        "agent found `-x` were sent with the submission, but no sandbox report came back, so "
        "nothing was observed with them."
    )
    via = {**unobserved, "launch_arguments_via": "options", "launch_arguments_note": "late"}
    assert _upload_line(via, _code).endswith(
        " The launch arguments an agent found `-x` were sent with the submission through "
        "options, but no sandbox report came back, so nothing was observed with them (late)."
    )
    assert "launch arguments" not in _upload_line({**REMOTE, "by": "sandbox", "calls": 1}, _code)


def test_an_upload_row_s_short_form_says_what_was_sent_and_to_whom() -> None:
    no_call = "no answered call recorded, so whether it received anything cannot be told"
    sandbox = {**REMOTE, "by": "sandbox", "source": "triage", "calls": 1, "failed": 1}
    assert _upload_line(sandbox, _code, short=True) == (
        "Sample upload: the sample was submitted once to the `triage` sandbox at `far.example` "
        "(outside this machine); 1 of the attempts failed or did not finish, so whether it "
        "arrived cannot be told."
    )
    assert _upload_line({**sandbox, "calls": 0, "failed": 0}, _code, short=True) == (
        f"Sample upload: the `triage` sandbox at `far.example` (outside this machine): {no_call}."
    )
    staged = {**REMOTE, "by": "staging", "source": "mcp:re", "calls": 2, "what": "artefact"}
    assert _upload_line(staged, _code, short=True) == (
        "Sample upload: a file a tool wrote out of the sample was staged 2 times to tool server "
        "`re` at `far.example` (outside this machine)."
    )
    assert _upload_line({**staged, "calls": 0}, _code, short=True) == (
        f"Sample upload: tool server `re` at `far.example` (outside this machine): {no_call}."
    )
    handed = {**NAMED_UNPLACED, "by": "tool", "source": "mcp:vt", "calls": 3}
    assert _upload_line(handed, _code, short=True) == (
        "Sample upload: tool server `vt` at `10.0.0.5` was handed the sample 3 times, where it "
        "runs is not recorded."
    )


# ---------------------------------------------------------------------------
# The memory store, unreadable rows, tracing, the intro and the footnote
# ---------------------------------------------------------------------------


def test_the_store_unreadable_rows_and_tracing_are_said_whole() -> None:
    store = {**REMOTE, "backend": "qdrant"}
    configured = (
        "Case memory: the `qdrant` case-memory store at `far.example` (outside this machine), "
        "configured as this job's case memory."
    )
    # A row stored before the job recorded its case memory.
    assert _store_line(store, _code) == (
        f"{configured} This record does not say whether the judge read similar cases from it "
        "or whether the job filed its case in it."
    )
    assert _store_line(store, _code, partial="the run was stopped part-way") == (
        f"{configured} The run stopped part-way, and a job that does not complete files no "
        "case. This record does not say whether the judge read similar cases from it."
    )
    unplaced = (
        "Case memory: the `qdrant` case-memory store at `10.0.0.5`, configured as this job's "
        "case memory; it is a local gateway, so where it runs cannot be told."
    )
    assert _store_line({**store, **NAMED_UNPLACED}, _code) == (
        f"{unplaced} This record does not say whether the judge read similar cases from it or "
        "whether the job filed its case in it."
    )
    # The job's case, as the platform decided it, then how the judge's read ended.
    shown = {**store, "case": "held", "case_why": "", "similar_read": "shown", "similar_shown": 2}
    assert _store_line(shown, _code) == (
        f"{configured} The run held its case to file there once the job completes; whether it "
        "was filed is not recorded in this report. The judge was shown 2 similar cases of other "
        "samples read from it."
    )
    assert _store_line({**shown, "similar_shown": 1}, _code).endswith(
        " The judge was shown 1 similar case of another sample read from it."
    )
    withheld = {**shown, "case": "withheld", "case_why": "no negotiation round completed"}
    assert _store_line({**withheld, "similar_read": "none_shown"}, _code) == (
        f"{configured} The run held no case to file there (no negotiation round completed). "
        "The judge read it for similar cases of other samples and was shown none."
    )
    assert _store_line(
        {**withheld, **NAMED_UNPLACED, "case": "none", "case_why": "", "similar_read": "failed"},
        _code,
    ) == (
        f"{unplaced} The run held no case to file there. The judge's read of similar cases from "
        "it failed, so it was shown none."
    )
    assert _store_line({**shown, "similar_read": "not_opened"}, _code, partial="stopped") == (
        f"{configured} The run stopped part-way, and a job that does not complete files no "
        "case. The store could not be opened when the judge was to read similar cases from it, "
        "so it was shown none."
    )
    assert _store_line({**shown, "similar_read": "nothing_to_search"}, _code).endswith(
        " The judge had no analyst claim to search it with, so it read no similar case from it."
    )
    assert _store_line({**shown, "similar_read": "not_reached"}, _code).endswith(
        " The run did not reach the judge's read of similar cases from it."
    )
    assert _store_line({**shown, "similar_read": "garbage"}, _code).endswith(
        " This record does not say whether the judge read similar cases from it."
    )
    assert _store_line(store, _code, short=True) == (
        "Case memory: the `qdrant` case-memory store at `far.example` (outside this machine)."
    )
    assert _store_line({**store, **UNPLACED}, _code, short=True) == (
        "Case memory: the `qdrant` case-memory store, destination not recorded."
    )
    assert _unreadable_line(1) == (
        "The ledger held 1 row the report could not read, so where its call went cannot be told."
    )
    assert _unreadable_line(3) == (
        "The ledger held 3 rows the report could not read, so where their calls went cannot be "
        "told."
    )
    assert TRACING_SENTENCE == (
        "Tracing is on (the setting `langchain_tracing_v2`, or the process environment): every "
        "prompt and answer was also sent to the tracing service, whose address the settings do "
        "not record, so where they went cannot be told."
    )
    record = {"models": [], "tracing": True}
    assert disclosure_lines(record) == [TRACING_SENTENCE]
    assert disclosure_lines({**record, "tracing": False}) == []


def test_the_appendix_opens_with_the_intro_and_closes_with_the_footnote() -> None:
    from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from malspark.reporting.renderers.markdown import MarkdownRenderer

    assert INTRO_SENTENCE == (
        "**Disclosure:** what this run sent beyond this machine, read from the settings it ran "
        "with and the recorded source of each model call, tool call and sample upload."
    )
    assert FOOTNOTE_SENTENCE == (
        "_This machine, here, covers its loopback addresses, the private, link-local and shared "
        "address ranges, names only a local resolver answers, and single-label names, which are "
        "taken as a compose service's._"
    )
    record = {"models": [{**REMOTE, "calls": 1, "agents": {}}]}
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"final_decision": "Malware", "disclosure": record},
        generated_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    rendered = MarkdownRenderer().render(report)
    assert INTRO_SENTENCE in rendered and FOOTNOTE_SENTENCE in rendered
    assert rendered.index(INTRO_SENTENCE) < rendered.index(FOOTNOTE_SENTENCE)
    report.run_summary = {"final_decision": "Malware"}
    rendered = MarkdownRenderer().render(report)
    assert INTRO_SENTENCE not in rendered and FOOTNOTE_SENTENCE not in rendered


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------


def test_the_sources_an_enrichment_may_reach_and_asked_are_named() -> None:
    assert _reach({"source": "", "kinds": ["ip"], "why": "they could not be read"}, _code) == (
        "the configured sources (ip), not named here because they could not be read"
    )
    assert _reach({"source": "rdap", "kinds": ["ip"], "hosts": ["rdap.example"]}, _code) == (
        "RDAP (ip) at `rdap.example` (the ARIN bootstrap alone: a referral to a regional "
        "registry is not followed), with no key"
    )
    server = {
        "source": "intel",
        "kinds": ["domain", "ip"],
        "hosts": ["intel.example"],
        "server": "lookups",
        "transport": "http",
    }
    assert _reach(server, _code) == (
        "source `intel` (domain, ip) through tool server `lookups` (http) at `intel.example`"
    )
    assert _reach({**server, "hosts": [], "transport": "stdio"}, _code) == (
        "source `intel` (domain, ip) through tool server `lookups` (stdio, run on this machine)"
    )
    assert _reach({"source": "x", "kinds": ["ip"], "hosts": ["a.example", "b.example"]}, _code) == (
        "source `x` (ip) at `a.example`, `b.example`"
    )
    assert _reach({"source": "x", "kinds": ["ip"]}, _code) == "source `x` (ip) with no host named"

    asked = [
        {"source": "rdap", "host": "rdap.example", "where": "remote", "kinds": {"ip": 2}},
        {
            "source": "intel",
            "host": "",
            "where": "unknown",
            "kinds": {"domain": 3},
            "failed": 1,
            "errored": 1,
            "why": "the server runs here",
        },
    ]
    assert _asked_parts(asked, _code) == (
        "`rdap.example` (outside this machine) about ip 2 (RDAP, the ARIN bootstrap alone: a "
        "referral to a regional registry is not followed); a tool server; the server runs here, "
        "so where the questions went cannot be told about domain 3 (source `intel`, 1 of them "
        "failed in transport or did not finish and may have arrived, 1 of them answered with an "
        "error status (it arrived))"
    )
    withheld = {"withheld": [{"server": "s", "tool": "t", "reason": "no key"}, {"server": "u"}]}
    assert _withheld_lines(withheld, _code) == [
        "Enrichment: `s`'s tool `t` was not asked, because its host withheld it: no key.",
        "Enrichment: `u`'s tool `` was not asked, because its host withheld it: no reason was "
        "given.",
    ]
    assert _withheld_lines({}, _code) == []


def test_the_enrichment_is_said_by_its_state() -> None:
    asked = [{"source": "x", "host": "x.example", "where": "remote", "kinds": {"ip": 1}}]
    parts = "`x.example` (outside this machine) about ip 1 (source `x`)"
    assert _enrichment_state_lines({"state": "done"}, _code) == [
        "Enrichment: the follow-up job ran and asked no service about an indicator."
    ]
    assert _enrichment_state_lines({"state": "done", "asked": asked}, _code) == [
        f"Enrichment: the follow-up job asked {parts}."
    ]
    assert _enrichment_state_lines({"state": "stopped", "asked": asked}, _code) == [
        f"Enrichment: the follow-up job stopped part-way after asking {parts}; a question in "
        "flight when it stopped is counted as not finished."
    ]
    assert _enrichment_state_lines({"state": "stopped"}, _code) == [
        "Enrichment: the follow-up job stopped part-way; a question in flight when it stopped "
        "is counted as not finished."
    ]
    running = (
        "Enrichment: a follow-up job began sending questions about the report's indicators and "
        "recorded nothing after that, so where its questions went cannot be told."
    )
    assert _enrichment_state_lines({"state": "running"}, _code) == [running]
    assert _enrichment_state_lines({"state": "running", "asked": asked}, _code) == [
        f"{running} An earlier enrichment asked {parts}."
    ]
    queued = {"state": "queued", "may_reach": [{"source": "x", "kinds": ["ip"]}]}
    assert _enrichment_state_lines(queued, _code) == [
        "Enrichment: a follow-up job queued after this report may send the report's public "
        "domains and addresses to source `x` (ip) with no host named. What it sends is added "
        "here once it has run."
    ]
    assert _enrichment_state_lines({"state": "queued"}, _code) == [
        "Enrichment: a follow-up job queued after this report may send the report's public "
        "domains and addresses to no source. What it sends is added here once it has run."
    ]


# ---------------------------------------------------------------------------
# Nothing, a partial record, a block not built
# ---------------------------------------------------------------------------


def test_nothing_left_says_every_thing_it_rests_on() -> None:
    assert RUNTIME_ASSUMPTION == (
        "a local address that answered as a model runtime is taken as running here, and a "
        "tunnel or proxy to a remote runtime cannot be told apart"
    )
    record = {
        "models": [{**LOCAL, "runtime": "llama.cpp /props"}],
        "local_servers": ["mcp:analysis", "provider:r2"],
        "stores": [{**LOCAL, "backend": "qdrant"}],
        "uploads": [{**LOCAL, "by": "sandbox"}],
    }
    assert _nothing_sentence(record, _code) == (
        "Nothing left this machine. This rests on: every model endpoint in this run's settings "
        "is a local address that answered as a model runtime: `127.0.0.1` (llama.cpp /props) "
        f"({RUNTIME_ASSUMPTION}); the local tool servers called (tool server `analysis`, the "
        "`r2` provider's tool server) were taken as local by their tools' declarations; the "
        "case-memory store is at a local address; the sample went only to local addresses; no "
        "lookup was asked, and tracing is off."
    )
    assert _nothing_sentence({}, _code) == (
        "Nothing left this machine. This rests on: the case-memory store is kept in the process "
        "or not configured; no lookup was asked, and tracing is off."
    )
    assert disclosure_lines({"models": [], "nothing_left": True})[0] == _nothing_sentence({}, _code)


def test_a_partial_record_and_a_block_not_built_are_said_so() -> None:
    record = {"models": [], "partial_reason": "the run was stopped part-way"}
    assert _partial_line(record) == (
        "This record may be incomplete: the run was stopped part-way, and a call made in the "
        "step it stopped in may not be recorded, so it cannot be said that nothing left this "
        "machine."
    )
    assert disclosure_lines(record) == [_partial_line(record)]
    assert not_built_line("coverage", not_built("reporting is off")) == (
        "The coverage block was not built: reporting is off."
    )
    assert not_built_line("coverage", {"v": 1, "not_built": "x"}) == ""
    assert not_built_line("coverage", None) == ""


# ---------------------------------------------------------------------------
# What left this machine, for the analyst report
# ---------------------------------------------------------------------------


def test_a_kind_whose_destination_is_not_recorded_is_named_with_its_count() -> None:
    assert _not_recorded_line("Tracing of every prompt and answer", None) == (
        "Tracing of every prompt and answer: count not recorded, destination not recorded."
    )
    assert _not_recorded_line("Lookups", 2, ["`a`", "`b`", "`a`"]) == (
        "Lookups: 2 calls, may reach `a` and `b`."
    )
    assert _enrichment_left(None, _code) == []
    assert _enrichment_left({"state": "queued", "asked": [{"source": "x"}]}, _code) == []
    assert _enrichment_left({"state": "done", "asked": []}, _code) == []
    asked = [{"source": "x", "host": "x.example", "where": "remote", "kinds": {"ip": 1}}]
    running = {"state": "running", "asked": asked, "may_reach": [{"hosts": ["r.example"]}]}
    assert _enrichment_left(running, _code) == [
        "Enrichment questions about the report's indicators: count not recorded, may reach "
        "`r.example`.",
        "Enrichment: an earlier enrichment asked `x.example` (outside this machine) about ip 1 "
        "(source `x`).",
    ]
    assert _enrichment_left({"state": "done", "asked": asked}, _code) == [
        "Enrichment: the follow-up job asked `x.example` (outside this machine) about ip 1 "
        "(source `x`)."
    ]


def test_what_left_this_machine_is_one_run_of_sentences_ending_on_the_bundle() -> None:
    assert LEFT_THE_MACHINE_RECORD == "The full record of what left this machine is in the bundle."
    record = {
        "models": [{**REMOTE, "calls": 2}, {**LOCAL, "calls": 5}],
        "servers": [{**REMOTE, "source": "mcp:far", "calls": 1}],
        "tracing": True,
        "partial_reason": "the run was stopped part-way",
    }
    assert left_the_machine(record) == (
        "This record may be incomplete: the run was stopped part-way, and a call made in the "
        "step it stopped in may not be recorded, so it cannot be said that nothing left this "
        "machine. Model prompts: `far.example` (outside this machine) received 2 calls. Tool "
        "calls: tool server `far` at `far.example` (outside this machine): 1 call. Tracing of "
        "every prompt and answer: count not recorded, destination not recorded. The full record "
        "of what left this machine is in the bundle."
    )
    assert left_the_machine({"models": [{**LOCAL, "calls": 5}]}) == ""
    assert left_the_machine({**record, "nothing_left": True}) == ""
    assert left_the_machine({"servers": record["servers"]}) == ""
    assert left_the_machine(None) == ""
