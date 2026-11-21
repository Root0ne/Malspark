"""The isolation part says each reader of the sample, and what kept it, in whole sentences.

Every sentence the part prints is pinned here word for word under the reading
that prints it: how each kind of source is named, each check as measured,
failed or unread, the worker's own facts, the tree under a started process
with and without a declared launcher, a server reached at an address, and the
headline over the whole part. A field that was not read is said as not read,
never as passing (T-770).
"""

from __future__ import annotations

from typing import Any

from malspark.analysis import isolation
from malspark.analysis.isolation import (
    BY_DECLARATION,
    BY_MEASUREMENT,
    CHILD,
    IN_PROCESS,
    LOCAL_SERVICE,
    NOT_MEASURED_CHILD,
    NOT_MEASURED_DISAGREE,
    NOT_MEASURED_REMOTE,
    NOT_MEASURED_SERVICE,
    REMOTE_SERVICE,
    UNPLACED,
    isolation_lines,
)

CODE = isolation._code
# A started process measured as kept from the worker on every count.
KEPT: dict[str, Any] = {
    "where": CHILD,
    "source": "mcp:analysis",
    "measured_by": "worker",
    "attaches": 1,
    "uid": 10002,
    "same_uid_as_worker": False,
    "shares_group_with_worker": False,
    "own_pid_namespace": True,
    "own_mount_namespace": True,
    "own_net_namespace": True,
    "cap_eff_zero": True,
    "cap_prm_zero": True,
    "cap_amb_zero": True,
    "no_new_privs": True,
    "platform_names_in_env": [],
    "descendants": 0,
    "descendants_failing": 0,
    "descendants_judged": True,
    "descendants_why": "",
    "launcher_depth": 0,
    "under_launcher": 0,
    "needs_network": False,
    "isolated": True,
    "isolated_by": BY_MEASUREMENT,
    "why_not_measured": "",
}
LAUNCHER_ONE = (
    "Its block declares the process the worker started a launcher that does not read the "
    "sample (the block's word, not measured), so the launcher is held only to carrying none "
    "of the platform's own variables, and every process under it to every check."
)
WHICH = (
    "Which process of its tree reads the sample cannot be told, so every one is held to the checks."
)


def test_each_kind_of_source_is_named_by_its_kind() -> None:
    pack = {"where": IN_PROCESS, "source": "pack", "label": "Triage pack"}
    assert isolation._who(pack, CODE) == "Triage pack (`pack`)"
    assert isolation._who({**pack, "label": ""}, CODE) == "the in-process source `pack`"
    assert isolation._who({"source": "mcp:analysis"}, CODE) == "tool server `analysis`"
    assert (
        isolation._who({"source": "provider:detonator"}, CODE)
        == "the `detonator` provider's tool server"
    )
    assert isolation._who({"source": "odd"}, CODE) == "source `odd`"
    assert isolation._who({"source": "mcp:"}, CODE) == "source `mcp:`"


def test_an_environment_is_said_as_read_empty_or_holding_names() -> None:
    assert isolation._env_clause(None, CODE, "its") == "its environment could not be read"
    assert isolation._env_clause([], CODE, "its") == (
        "its environment held none of the platform's own variables"
    )
    assert isolation._env_clause(["DATABASE_URL", "JWT_SECRET_KEY"], CODE, "its") == (
        "its environment held the platform's own variables `DATABASE_URL`, `JWT_SECRET_KEY`"
    )


def test_a_user_is_said_with_whether_any_of_its_ids_is_the_workers() -> None:
    assert isolation._user(1000, True) == (
        "user 1000 (one of its real, effective, saved or filesystem user ids is the worker's)"
    )
    assert isolation._user(10002, False) == (
        "user 10002 (none of its real, effective, saved or filesystem user ids is the worker's)"
    )
    assert isolation._user(None, None) == (
        "a user that could not be read (its user ids could not all be read)"
    )


def test_the_three_capability_sets_are_said_together() -> None:
    clear = {"cap_eff_zero": True, "cap_prm_zero": True, "cap_amb_zero": True}
    assert isolation._capabilities(clear) == "no effective, permitted or ambient capabilities"
    assert isolation._capabilities({**clear, "cap_eff_zero": False, "cap_prm_zero": False}) == (
        "effective and permitted capabilities"
    )
    held = {"cap_eff_zero": False, "cap_prm_zero": False, "cap_amb_zero": False}
    assert isolation._capabilities(held) == "effective, permitted and ambient capabilities"
    assert isolation._capabilities({**clear, "cap_amb_zero": None}) == (
        "ambient capabilities that could not be read"
    )
    # A held set is said before an unread one.
    assert isolation._capabilities({**clear, "cap_eff_zero": False, "cap_prm_zero": None}) == (
        "effective capabilities"
    )


def test_the_worker_is_said_with_its_user_and_its_environment() -> None:
    assert isolation._worker_line({"uid": 1000, "platform_names_in_env": []}, CODE) == (
        "The worker process runs as user 1000; its environment holds none of the platform's "
        "own variables."
    )
    assert isolation._worker_line({"uid": 0, "platform_names_in_env": ["DATABASE_URL"]}, CODE) == (
        "The worker process runs as user 0; its environment holds the platform's own "
        "variables `DATABASE_URL`."
    )
    unread = {
        "uid": None,
        "unavailable": "not available on this platform",
        "platform_names_in_env": None,
    }
    assert isolation._worker_line(unread, CODE) == (
        "The worker process runs as a user that could not be read (not available on this "
        "platform); its environment could not be read."
    )


def test_a_read_in_the_worker_is_said_not_isolated_and_why() -> None:
    pack = {"where": IN_PROCESS, "source": "pack", "label": "Triage pack"}
    tail = (
        " read the sample in the worker process itself: not isolated, since it shares the "
        "worker's memory, environment, files and network."
    )
    assert isolation._in_process_line(pack, CODE) == "Triage pack (`pack`)" + tail
    assert isolation._in_process_line({**pack, "label": ""}, CODE) == (
        "The in-process source `pack`" + tail
    )


def test_a_started_process_with_no_measurement_is_said_untold() -> None:
    row = {
        "where": CHILD,
        "source": "mcp:analysis",
        "measured_by": "",
        "why_not_measured": NOT_MEASURED_CHILD,
    }
    assert isolation._child_line(row, CODE) == (
        "Tool server `analysis` (stdio, run on this machine) read the sample in a process the "
        "worker started; the run holds no measurement of the process it was started as, so its "
        "isolation cannot be told."
    )


def test_a_started_process_kept_on_every_count_is_said_check_by_check() -> None:
    row = {
        **KEPT,
        "attaches": 2,
        "uid": None,
        "needs_network": True,
        "why_not_measured": NOT_MEASURED_DISAGREE,
    }
    assert isolation._child_line(row, CODE) == (
        "Tool server `analysis` (stdio, run on this machine) read the sample. The process the "
        "worker started for it was measured at each of its 2 starts: it ran as a user that "
        "could not be read (none of its real, effective, saved or filesystem user ids is the "
        "worker's); in none of the worker's groups; with a process table of its own; a mount "
        "namespace of its own; a network of its own; no effective, permitted or ambient "
        "capabilities; no way to gain privileges; its environment held none of the platform's "
        "own variables. It had no descendant process when it was measured. So: isolated. Its "
        "block declares that it needs the network. Its processes were measured differently "
        "from one start to the next."
    )


def test_a_started_process_sharing_the_worker_is_said_check_by_check() -> None:
    row = {
        **KEPT,
        "uid": 1000,
        "same_uid_as_worker": True,
        "shares_group_with_worker": True,
        "own_pid_namespace": False,
        "own_mount_namespace": False,
        "own_net_namespace": False,
        "cap_eff_zero": False,
        "no_new_privs": False,
        "platform_names_in_env": ["JWT_SECRET_KEY"],
        "isolated": False,
        "isolated_by": "",
    }
    assert isolation._child_line(row, CODE) == (
        "Tool server `analysis` (stdio, run on this machine) read the sample. The process the "
        "worker started for it was measured at its start: it ran as user 1000 (one of its "
        "real, effective, saved or filesystem user ids is the worker's); in a group of the "
        "worker's; sharing the worker's process table; the worker's mount namespace; the "
        "worker's network; effective capabilities; no bar on gaining privileges; its "
        "environment held the platform's own variables `JWT_SECRET_KEY`. It had no descendant "
        "process when it was measured. So: not isolated."
    )


def test_a_started_process_read_on_no_count_is_said_unread_check_by_check() -> None:
    unread = dict.fromkeys(isolation.MEASURED_FIELDS)
    row = {
        **KEPT,
        **unread,
        "descendants_judged": False,
        "descendants_why": isolation.DESCENDANTS_UNRECORDED,
        "isolated": False,
        "isolated_by": "",
    }
    assert isolation._child_line(row, CODE) == (
        "Tool server `analysis` (stdio, run on this machine) read the sample. The process the "
        "worker started for it was measured at its start: it ran as a user that could not be "
        "read (its user ids could not all be read); in groups that could not all be read; its "
        "process table could not be compared; its mount namespace could not be compared; its "
        "network could not be compared; effective, permitted and ambient capabilities that "
        "could not be read; a privilege flag that could not be read; its environment could not "
        "be read. Its descendant processes were not judged (the run recorded no walk of the "
        "processes under it), so they cannot be shown to be kept from the worker. So: not "
        "isolated."
    )


def test_a_row_kept_by_a_declared_launcher_says_it_rests_on_the_declaration() -> None:
    row = {
        **KEPT,
        "launcher_depth": 1,
        "under_launcher": 1,
        "descendants": 1,
        "isolated_by": BY_DECLARATION,
    }
    line = isolation._child_line(row, CODE)
    assert line.endswith(
        f"{LAUNCHER_ONE} 1 process under the launcher was measured, and every process of the "
        "tree passed. So: isolated by its block's declaration."
    )


def test_the_tree_under_a_declared_launcher_is_said_by_what_was_measured_under_it() -> None:
    judged = {"descendants_judged": True, "under_launcher": 0, "descendants_failing": 0}
    assert isolation._launcher_sentence(
        {"descendants_judged": False, "descendants_why": "its tree was cut"}, 1
    ) == (
        f"{LAUNCHER_ONE} Its descendant processes were not judged (its tree was cut), so they "
        "cannot be shown to be kept from the worker."
    )
    assert isolation._launcher_sentence(judged, 1) == (
        f"{LAUNCHER_ONE} No process under the launcher was measured, so what read the sample "
        "cannot be shown to be kept from the worker."
    )
    assert isolation._launcher_sentence({**judged, "under_launcher": 1}, 1) == (
        f"{LAUNCHER_ONE} 1 process under the launcher was measured, and every process of the "
        "tree passed."
    )
    two = isolation._launcher_sentence({**judged, "under_launcher": 2, "descendants_failing": 1}, 2)
    assert two == (
        "Its block declares the top 2 levels of its tree a launcher that does not read the "
        "sample (the block's word, not measured), so the launcher is held only to carrying "
        "none of the platform's own variables, and every process under it to every check. "
        "2 processes under the launcher were measured, and 1 of the tree did not pass."
    )


def test_the_tree_under_a_started_process_is_said_by_what_was_judged() -> None:
    assert isolation._tree_sentence(
        {"descendants_judged": False, "descendants_why": "its tree was cut"}
    ) == (
        "Its descendant processes were not judged (its tree was cut), so they cannot be shown "
        "to be kept from the worker."
    )
    judged = {"descendants_judged": True, "descendants": 0, "descendants_failing": 0}
    assert isolation._tree_sentence(judged) == (
        "It had no descendant process when it was measured."
    )
    assert isolation._tree_sentence({**judged, "descendants": 1}) == (
        f"Its 1 descendant process was measured too, and every one passed. {WHICH}"
    )
    assert isolation._tree_sentence({**judged, "descendants": 3, "descendants_failing": 2}) == (
        f"Its 3 descendant processes were measured too, and 2 did not pass every check. {WHICH}"
    )


def test_a_server_reached_at_an_address_is_said_by_where_it_runs() -> None:
    near = {
        "where": LOCAL_SERVICE,
        "source": "mcp:near",
        "transport": "streamable-http",
        "host": "tools:8089",
        "why_not_measured": NOT_MEASURED_SERVICE,
    }
    assert isolation._service_line(near, CODE) == (
        "Tool server `near` (streamable-http) at `tools:8089` read the sample; it is a server "
        "reached at a local address, which this run does not measure, so not verified by this "
        "run."
    )
    far = {
        **near,
        "where": REMOTE_SERVICE,
        "source": "mcp:far",
        "host": "tools.example.org",
        "why_not_measured": NOT_MEASURED_REMOTE,
    }
    assert isolation._service_line(far, CODE) == (
        "Tool server `far` (streamable-http) at `tools.example.org` read the sample; it runs "
        "outside this machine, which this run cannot measure, so this run cannot tell what "
        "isolation it had."
    )
    unplaced = {
        "where": UNPLACED,
        "source": "provider:x",
        "why_not_measured": "the settings do not say where it ran",
    }
    assert isolation._service_line(unplaced, CODE) == (
        "The `x` provider's tool server (transport not recorded) read the sample; the settings "
        "do not say where it ran, so its isolation cannot be told."
    )


def test_the_part_heads_its_rows_with_what_holds_of_all_of_them() -> None:
    assert isolation_lines(None) == []
    assert isolation_lines({"isolated": False}) == []
    assert isolation_lines({"rows": [], "unsourced_reads": 0}) == [
        "This run recorded no read of the sample's bytes, so nothing is said of it."
    ]
    worker = {"uid": 1000, "platform_names_in_env": []}
    declared = [
        {**KEPT, "source": "mcp:a", "isolated_by": BY_DECLARATION},
        {**KEPT, "source": "mcp:b", "isolated_by": BY_DECLARATION},
        {**KEPT, "source": "mcp:c"},
    ]
    part = {"worker": worker, "rows": declared, "isolated": True, "isolated_by": BY_DECLARATION}
    lines = isolation_lines(part)
    assert lines[0] == (
        "Every source that read the sample's bytes was kept from the worker as measured, but "
        "for tool server `a`, tool server `b` that rests on its block's declaration of a "
        "launcher."
    )
    assert lines[1] == isolation._worker_line(worker, CODE)
    assert len(lines) == 2 + len(declared)
    measured = {"worker": worker, "rows": [KEPT], "isolated": True, "isolated_by": BY_MEASUREMENT}
    assert isolation_lines(measured)[0] == (
        "Every source that read the sample's bytes was measured as kept from the worker."
    )


def test_a_part_not_isolated_lists_every_reader_and_each_read_with_no_source() -> None:
    worker = {"uid": 1000, "platform_names_in_env": []}
    pack = {"where": IN_PROCESS, "source": "pack", "label": "Triage pack"}
    near = {
        "where": LOCAL_SERVICE,
        "source": "mcp:near",
        "transport": "streamable-http",
        "host": "",
        "why_not_measured": NOT_MEASURED_SERVICE,
    }
    part = {"worker": worker, "rows": [pack, KEPT, near], "unsourced_reads": 1, "isolated": False}
    assert isolation_lines(part) == [
        "Not every source that read the sample's bytes was kept from the worker; each is listed "
        "with what was measured.",
        "The worker process runs as user 1000; its environment holds none of the platform's "
        "own variables.",
        isolation._in_process_line(pack, CODE),
        isolation._child_line(KEPT, CODE),
        "Tool server `near` (streamable-http) read the sample; it is a server reached at a "
        "local address, which this run does not measure, so not verified by this run.",
        "1 call that read the sample recorded no source, so where it ran cannot be told.",
    ]
    # With no row, no worker line: only the reads with no source.
    assert isolation_lines({"worker": worker, "rows": [], "unsourced_reads": 2}) == [
        "Not every source that read the sample's bytes was kept from the worker; each is listed "
        "with what was measured.",
        "2 calls that read the sample recorded no source, so where they ran cannot be told.",
    ]


def test_the_report_heads_the_part_with_its_lead_sentence_inside_the_disclosure() -> None:
    from malspark.analysis.disclosure import disclosure_record
    from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from malspark.reporting.renderers.markdown import MarkdownRenderer

    reads = {
        "id": "ev_1",
        "tool": "pe_info",
        "args": {},
        "ok": True,
        "source": "pack",
        "facts": {"v": 1, "kind": "format_info", "arguments": {"path": "path"}},
    }
    record = disclosure_record({}, entries=[reads], worker={"uid": 1000})

    def rendered(held: dict[str, Any]) -> str:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            run_summary={"final_decision": "Malware", "disclosure": held},
        )
        return str(MarkdownRenderer().render(report))

    assert (
        "\n\n**Isolation:** where this run read the sample's bytes, and what kept each reader "
        "from the worker, as measured when each started; never assumed.\n\n- "
    ) in rendered(record)
    # A record stored before the part existed prints no lead sentence.
    old = {key: value for key, value in record.items() if key != "isolation"}
    assert "**Isolation:**" not in rendered(old)
